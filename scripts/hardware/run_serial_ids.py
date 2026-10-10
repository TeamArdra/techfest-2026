"""Headless, RECEIVE-ONLY AegisFlight monitor on a serial MAVLink link (onboard-deployment runner).

    .venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port COM5 --baud 115200 --out-dir run_001
    python3 scripts/hardware/run_serial_ids.py --port /dev/ttyAMA0 --baud 921600 --out-dir /var/lib/aegis/run_001

Wiring (all existing, unchanged components): ``SerialMavlinkTransport`` -> ``LiveMavlinkSource`` ->
``IDSPipeline`` -> ``EventStore`` (SQLite hash chain). Nothing here ever writes to the port: ``transport.send``
is never called, ``bytes_sent`` is recorded and the run FAILS (exit 3) if it is non-zero. A physical
deployment can additionally leave the monitor's TX pin unconnected, which makes receive-only a property of the
wiring and not just of this code.

What it does NOT do: it does not ask the flight controller for telemetry (that is a transmit). The controller
must already be configured to stream the six messages the extractor reads (see docs/ONBOARD_DEPLOYMENT.md);
otherwise the pipeline sees a link without GPS/attitude and reports it as a threat (measured on the physical
board: docs/HARDWARE_BENCH_PIXHAWK6X.md).

Defaults are deliberately conservative for ArduPilot: the ML detector is OFF (``--ml`` to enable) because the
Stage-1 model does not transfer (docs/ARDUPILOT_SITL.md). Stage-1 thresholds are used unchanged.

Outputs under ``--out-dir``: ``events.sqlite`` (hash-chained alerts), ``alerts.jsonl``, ``health.jsonl``
(one line per ``--health-interval``: transport/source counters, decision counts, process CPU/RSS) and
``summary.json`` (final). Stop with Ctrl-C / SIGTERM (clean shutdown, exit 0) or ``--seconds N``.
Exit codes: 0 ok (NOT a statement about link health: see ``link_ever_delivered_frames`` in summary.json),
2 bad arguments / cannot open the port with ``--no-reconnect`` / ``--out-dir`` already holds a previous run,
3 transmit attempted, 4 alert hash chain broken. An existing run is never overwritten.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from collections import Counter, deque
from datetime import UTC, datetime
from pathlib import Path

import psutil

from aegisflight.config import load_config
from aegisflight.logging import EventStore
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import LiveMavlinkSource
from aegisflight.sources.mavlink_serial import SerialMavlinkTransport


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="COM5, /dev/ttyAMA0, ... (socket://host:port needs --allow-url)")
    ap.add_argument("--baud", type=int, default=115200, help="must match the FC serial port; ignored by USB-CDC")
    ap.add_argument("--allow-url", action="store_true", help="allow a socket:// virtual port (tests/replay only)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--seconds", type=float, default=0.0, help="stop after this long (0 = until signalled)")
    ap.add_argument("--config-dir", default=None)
    ap.add_argument("--ml", action="store_true", help="enable the ML detector (Stage-1 model; NOT valid on ArduPilot)")
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--health-interval", type=float, default=10.0)
    ap.add_argument("--no-reconnect", action="store_true", help="fail instead of retrying an unopenable port")
    ap.add_argument("--reconnect-interval", type=float, default=1.0)
    a = ap.parse_args(argv)

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_config(a.config_dir)
    rate = float(cfg.simulation.get("sample_rate_hz", 10.0))
    model = a.model if a.ml and Path(a.model).exists() else None
    if a.ml and model is None:
        print("WARNING: --ml requested but the model file is missing: running without ML", file=sys.stderr)
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    db = out / "events.sqlite"
    if any((out / n).exists() for n in ("events.sqlite", "alerts.jsonl", "health.jsonl", "summary.json")):
        # never clobber a previous run's tamper-evident log (a restart loop must not erase the alerts before a crash)
        print(f"refusing to start: {out} already holds a previous run; use a fresh --out-dir", file=sys.stderr)
        return 2
    store = EventStore(db)
    run_id = "serial-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    store.start_run(run_id, label="serial-monitor", meta={"port": a.port, "ml": model is not None})
    try:
        tr = SerialMavlinkTransport(a.port, baudrate=a.baud, reconnect=not a.no_reconnect,
                                    reconnect_interval_s=a.reconnect_interval, allow_url=a.allow_url)
    except ValueError as exc:
        print(f"bad port argument: {exc}", file=sys.stderr)
        store.close()
        return 2
    try:
        tr.start()  # idempotent; with --no-reconnect an unopenable port raises here, before anything else runs
    except RuntimeError as exc:
        print(f"cannot open the port: {exc}", file=sys.stderr)
        tr.close()
        store.close()
        return 2
    src = LiveMavlinkSource(tr, sample_rate_hz=rate, origin="start")  # a dead-from-start link still ticks
    stop = threading.Event()

    def _stop(*_a: object) -> None:
        stop.set()
        src.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # not the main thread (tests)
            pass

    proc = psutil.Process()
    proc.cpu_percent(None)
    t_wall0, cpu0 = time.perf_counter(), sum(proc.cpu_times()[:2])
    decisions = alerts = threats = 0
    types: Counter[str] = Counter()
    lat: deque[float] = deque(maxlen=100_000)  # bounded: this runner may run for days; p99 is over the last 100k
    lat_sum = lat_max = 0.0
    rss_max = 0
    cpu_samples: list[float] = []
    next_health = time.monotonic() + a.health_interval
    health = open(out / "health.jsonl", "w", encoding="utf-8")  # noqa: SIM115 - closed in finally
    alerts_f = open(out / "alerts.jsonl", "w", encoding="utf-8")  # noqa: SIM115
    started = datetime.now(UTC).isoformat()
    rc = 0
    deadline = time.monotonic() + a.seconds if a.seconds > 0 else None
    try:
        for tick in src.stream():
            asmt = pipe.process_tick(tick)
            if asmt is not None:
                decisions += 1
                threats += bool(asmt.threat)
                lat.append(asmt.latency_ms)
                lat_sum += asmt.latency_ms
                lat_max = max(lat_max, asmt.latency_ms)
                if asmt.is_alert:
                    alerts += 1
                    types[asmt.attack_type.value] += 1
                    row = store.log_event(asmt, run_id)
                    alerts_f.write(json.dumps({"t": round(asmt.t, 3), "wall_utc": datetime.now(UTC).isoformat(),
                                               "type": asmt.attack_type.value, "score": round(asmt.threat_score, 3),
                                               "evidence": asmt.evidence, "event_id": row["id"], "hash": row["hash"],
                                               "detectors": asmt.contributing_detectors}) + "\n")
                    alerts_f.flush()
            now = time.monotonic()
            if now >= next_health:
                next_health = now + a.health_interval
                cpu_samples.append(proc.cpu_percent(None))
                rss_max = max(rss_max, proc.memory_info().rss)
                health.write(json.dumps({"wall_utc": datetime.now(UTC).isoformat(), "decisions": decisions,
                                         "alerts": alerts, "transport": tr.stats, "source": src.stats,
                                         "cpu_pct": cpu_samples[-1], "rss_mb": round(rss_max / 2**20, 1)},
                                        default=str) + "\n")
                health.flush()
            if stop.is_set() or (deadline is not None and now >= deadline):
                break
    finally:
        wall = time.perf_counter() - t_wall0
        cpu = sum(proc.cpu_times()[:2]) - cpu0
        t_stats, s_stats = tr.stats, src.stats
        rss_max = max(rss_max, proc.memory_info().rss)
        src.close()
        health.close()
        alerts_f.close()
        chain = store.verify_chain(run_id)
        store.close()
    if t_stats["bytes_sent"] != 0 or t_stats["write_errors"] != 0:
        print(f"FAIL: transmit attempted on a receive-only monitor (bytes_sent={t_stats['bytes_sent']}, "
              f"write_errors={t_stats['write_errors']})", file=sys.stderr)
        rc = 3
    elif not chain.ok:
        print(f"FAIL: alert hash chain is broken: {chain.detail}", file=sys.stderr)
        rc = 4
    ls = sorted(lat)
    summary = {"schema": "aegisflight.serial_monitor_run/1", "started_utc": started, "port": a.port, "baud": a.baud,
               "ml_enabled": model is not None, "config_dir": a.config_dir or "configs (Stage-1 default)",
               "wall_s": round(wall, 1), "cpu_s": round(cpu, 2),
               "cpu_pct_of_one_core_mean": round(100 * cpu / wall, 2) if wall else None,
               "rss_mb_max": round(rss_max / 2**20, 1), "decisions": decisions, "threat_decisions": threats,
               "alert_decisions": alerts, "alert_types": dict(types),
               "decision_latency_ms": {"mean": round(lat_sum / decisions, 4) if decisions else None,
                                       "p99_last_100k": round(ls[int(0.99 * (len(ls) - 1))], 4) if ls else None,
                                       "max": round(lat_max, 4) if decisions else None},
               "transport": t_stats, "source": s_stats,
               "link_ever_delivered_frames": t_stats["frames_received"] > 0,  # exit 0 does NOT mean a healthy link
               "passive_check": {"bytes_sent": t_stats["bytes_sent"], "write_errors": t_stats["write_errors"],
                                 "passed": t_stats["bytes_sent"] == 0 and t_stats["write_errors"] == 0},
               "hash_chain": {"ok": chain.ok, "length": chain.length}, "exit_code": rc}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("wall_s", "decisions", "alert_decisions", "alert_types",
                                              "passive_check", "hash_chain")}, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
