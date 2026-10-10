"""Run the UNCHANGED AegisFlight pipeline LIVE on an isolated ArduCopter SITL (Windows side).

    .venv/Scripts/python.exe scripts/ardupilot/run_ap_sitl_ids.py --name ap_benign_six_001 \
        --stream six --profile flight

What happens: ``wsl.exe`` starts ``ap_netns_run.sh`` (ArduCopter 4.7.1 SITL in a private network
namespace + a GCS-role collector). The only thing crossing the namespace boundary is the
collector's stdout -- length-prefixed MAVLink frames -- which this script reads through
``LengthPrefixedPipeTransport`` -> ``TapTransport`` -> ``LiveMavlinkSource`` -> ``IDSPipeline``
(Stage-1 detectors, fusion and hash-chain event store, all unchanged). No simulator port is ever
opened in the default network.

Environment tag: SITL (ArduCopter 4.7.1, ``--model +`` quad, Linux x86-64 in WSL2, wall-clock
1x). Claim class for a benign run: none -- false-alarm / coverage / cost reference, NOT attack
detection, and says nothing about real vehicles. With ``--attack`` (see ``ap_attack.py``) the
claim class is *link-level detection*: the modification happens on the downlink between the
simulator and the IDS; the vehicle's estimator and flight are NOT affected (the simulator never
sees it).

Outputs under ``artifacts/ardupilot/<name>/``: ``manifest.json`` (provenance, isolation proofs,
pipe-integrity check), ``summary.json`` (metrics), ``decisions.jsonl`` (every decision),
``alerts.jsonl`` (alerts with evidence), ``events.sqlite`` (hash-chained alert log; git-ignored),
copies of the WSL-side logs. Raw frames go to ``data/ardupilot/raw/<name>.clean.tlog`` (and
``.observed.tlog``); they are git-ignored, their SHA-256 is in the manifest.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import shlex
import statistics
import struct
import subprocess
import sys
import tarfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import psutil

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "sitl"))  # provenance helper

from provenance import collect, sha256_file  # noqa: E402

from aegisflight.config import load_config  # noqa: E402
from aegisflight.logging import EventStore  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.frame_pipe import LengthPrefixedPipeTransport  # noqa: E402
from aegisflight.sources.frame_tap import TapTransport  # noqa: E402
from aegisflight.sources.mavlink_live import LiveMavlinkSource  # noqa: E402

DISTRO = "Ubuntu-24.04"  # NEVER the default distro (Ubuntu-26.04 here): always explicit
WSL_LOGS = "/home/astryx/aegis_sitl_ap/logs"
PIPELINE_MESSAGES = ("HEARTBEAT", "SYS_STATUS", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "ATTITUDE", "VFR_HUD")
FETCH = ("preflight.txt", "postcheck.txt", "events.jsonl", "downlink.tlog", "arducopter.log",
         "ss_default_before.txt", "ss_default_after.txt", "monitor_events.jsonl")
FETCH_MAX_BYTES = 64 * 1024 * 1024
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
HARNESS = {"standard": "ap_netns_run.sh",  # collector configures streams on its own link
           "passive": "ap_netns_run_passive.sh"}  # FC streams via SR1_* params; monitor never transmits


def wsl_path(p: Path) -> str:
    d = p.resolve()
    return f"/mnt/{d.drive[0].lower()}/" + "/".join(d.parts[1:])


def wsl(*cmd: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(["wsl.exe", "-d", DISTRO, "--", *cmd], capture_output=True, timeout=timeout)


def fetch_wsl_files(run_dir: str, dest: Path) -> list[str]:
    """Copy the harness's logs out of WSL (tar over stdout; nothing is mounted or shared)."""
    got: list[str] = []
    cmd = f"cd {shlex.quote(run_dir)} && tar cf - {' '.join(FETCH)} 2>/dev/null"
    try:
        r = wsl("bash", "-c", cmd, timeout=120)
        if r.stdout:
            with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
                for m in tf.getmembers():
                    if m.name not in FETCH or not m.isreg() or m.size > FETCH_MAX_BYTES:
                        continue  # only the names we asked for, regular files, bounded size
                    f = tf.extractfile(m)
                    if f is not None:
                        (dest / m.name).write_bytes(f.read())
                        got.append(m.name)
    except (subprocess.TimeoutExpired, tarfile.TarError, OSError) as exc:
        print(f"WARNING: fetching the WSL-side logs failed: {exc!r}", file=sys.stderr)
    return got


def read_tlog(path: Path) -> list[tuple[int, bytes]]:
    data, out, i = path.read_bytes(), [], 0
    while i + 10 <= len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0]
        if data[i + 8] == 0xFD:
            n = 12 + data[i + 9] + (13 if data[i + 10] & 1 else 0)
        else:
            n = 8 + data[i + 9]
        out.append((ts, data[i + 8:i + 8 + n]))
        i += 8 + n
    return out


def pct(v: list[float], q: float) -> float | None:
    if not v:
        return None
    s = sorted(v)
    return round(s[min(len(s) - 1, round(q * (len(s) - 1)))], 4)


class ResourceSampler(threading.Thread):
    """Samples THIS (Windows IDS) process once a second. The WSL-side simulator is not included."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.proc = psutil.Process()
        self.stop_evt = threading.Event()
        self.cpu: list[float] = []
        self.rss: list[int] = []
        self.threads: list[int] = []

    def run(self) -> None:
        self.proc.cpu_percent(None)  # prime
        while not self.stop_evt.wait(1.0):
            self.cpu.append(self.proc.cpu_percent(None))
            self.rss.append(self.proc.memory_info().rss)
            self.threads.append(self.proc.num_threads())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True)
    ap.add_argument("--stream", choices=("six", "groups"), default="six")
    ap.add_argument("--profile", choices=("idle", "flight"), default="flight")
    ap.add_argument("--idle-s", type=float, default=60.0)
    ap.add_argument("--max-s", type=float, default=600.0, help="hard cap on the whole run")
    ap.add_argument("--config-dir", default=None, help="config profile dir (default: Stage-1 configs/)")
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--harness", choices=sorted(HARNESS), default="standard",
                    help="passive: the IDS link is a second serial port configured by SR1_* params, the monitor never transmits")
    ap.add_argument("--monitor-heartbeat", action="store_true",
                    help="passive harness only: the monitor sends a 1 Hz GCS HEARTBEAT (and nothing else) -- NOT receive-only")
    ap.add_argument("--no-ml", action="store_true", help="run without the ML detector (rules + physics only)")
    ap.add_argument("--out-dir", default="artifacts/ardupilot")
    ap.add_argument("--raw-dir", default="data/ardupilot/raw")
    ap.add_argument("--attack", default=None, help="attack hook spec from ap_attack.py (P2); default: none")
    a = ap.parse_args(argv)
    if not NAME_RE.fullmatch(a.name) or ".." in a.name:
        ap.error("--name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63} and not contain '..'")
    if a.monitor_heartbeat and a.harness != "passive":
        ap.error("--monitor-heartbeat needs --harness passive")

    out = REPO / a.out_dir / a.name
    raw = REPO / a.raw_dir
    out.mkdir(parents=True, exist_ok=True)
    raw.mkdir(parents=True, exist_ok=True)
    clean_tlog, obs_tlog = raw / f"{a.name}.clean.tlog", raw / f"{a.name}.observed.tlog"
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = f"{WSL_LOGS}/{a.name}_{ts}"

    hook = None
    attack_handle = None
    if a.attack:
        sys.path.insert(0, str(HERE))
        from ap_attack import build_attack  # noqa: PLC0415 - only when an attack is requested

        hook, attack_handle = build_attack(a.attack, out)

    cfg = load_config(a.config_dir)
    model = None if a.no_ml else (a.model if a.model and Path(a.model).exists() else None)
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    db = out / "events.sqlite"
    if db.exists():
        db.unlink()
    store = EventStore(db)
    run_id = a.name
    store.start_run(run_id, label="ardupilot-sitl", meta={"stream": a.stream, "profile": a.profile,
                                                         "attack": a.attack})

    mon_args = ["--send-heartbeat"] if a.monitor_heartbeat else []
    cmd = ["wsl.exe", "-d", DISTRO, "--", "bash", wsl_path(HERE / HARNESS[a.harness]), run_dir, *mon_args, "--",
           "--stream", a.stream, "--profile", a.profile, "--idle-s", str(a.idle_s)]
    print("launching:", " ".join(cmd), flush=True)
    stderr_log = out / "harness.stderr.log"
    errf = open(stderr_log, "wb")  # noqa: SIM115 - closed below
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, stdin=subprocess.DEVNULL, bufsize=0)

    def release_child() -> None:
        try:
            proc.wait(timeout=45)  # normal path: collector ends, harness cleans up and exits
        except subprocess.TimeoutExpired:
            proc.terminate()

    pipe_tr = LengthPrefixedPipeTransport(proc.stdout, on_close=release_child)
    tap = TapTransport(pipe_tr, clean_tlog=clean_tlog, observed_tlog=obs_tlog, down_hook=hook)
    rate_hz = float(cfg.simulation.get("sample_rate_hz", 10.0))
    src = LiveMavlinkSource(tap, sample_rate_hz=rate_hz, max_ticks=int(a.max_s * rate_hz))
    sampler = ResourceSampler()
    cpu0 = psutil.Process().cpu_times()
    t_wall0 = time.perf_counter()
    sampler.start()

    def watchdog() -> None:
        """Ends the run when the producer is dead or the wall-clock budget is spent -- independent of ticks,
        because LiveMavlinkSource emits none until a first frame arrives."""
        t_end = time.monotonic() + a.max_s + 30.0
        while not src._stop.is_set():
            time.sleep(0.5)
            dead = pipe_tr.eof or pipe_tr.last_error is not None or proc.poll() is not None
            quiet = tap.last_ns is None or time.monotonic_ns() - tap.last_ns > 1e9
            if time.monotonic() > t_end or (dead and quiet):
                src.stop()

    threading.Thread(target=watchdog, daemon=True, name="run-watchdog").start()

    decisions: list[dict] = []
    alerts: list[dict] = []
    msg_counts: Counter[str] = Counter()
    n_msgs = 0
    emit_lag_ms: list[float] = []
    dt = 1.0 / rate_hz
    started_utc = datetime.now(UTC).isoformat()
    try:
        for tick in src.stream():
            for m in tick.messages:
                msg_counts[m.msgname] += 1
            n_msgs += len(tick.messages)
            if tap.origin_ns is not None:
                close_ns = tap.origin_ns + int(tick.tick * dt * 1e9)
                emit_lag_ms.append((time.monotonic_ns() - close_ns) / 1e6)
            asmt = pipe.process_tick(tick)
            if asmt is not None:
                rec = {"t": round(asmt.t, 3), "wall_unix": round(time.time(), 3), "threat": bool(asmt.threat),
                       "alert": bool(asmt.is_alert), "type": asmt.attack_type.value,
                       "severity": asmt.severity.value, "score": round(asmt.threat_score, 4),
                       "latency_ms": round(asmt.latency_ms, 3),
                       "detector_scores": {k: round(v, 4) for k, v in asmt.detector_scores.items()},
                       "n_msgs": len(tick.messages)}
                decisions.append(rec)
                if asmt.is_alert:
                    row = store.log_event(asmt, run_id)
                    alerts.append({**rec, "event_id": row["id"], "hash": row["hash"],
                                   "evidence": asmt.evidence,
                                   "contributing_detectors": asmt.contributing_detectors})
            # link ended: the producer finished (EOF) and nothing has arrived for 0.5 s
            if tap.inner.eof and tap.last_ns is not None and time.monotonic_ns() - tap.last_ns > 5e8:
                break
    finally:
        wall_s = time.perf_counter() - t_wall0
        cpu1 = psutil.Process().cpu_times()
        sampler.stop_evt.set()
        src_stats = src.stats
        pipe_stats = pipe_tr.stats
        tap_stats = tap.tap_stats
        origin_ns = tap.origin_ns
        link_span_s = ((tap.last_ns - tap.origin_ns) / 1e9
                       if tap.last_ns is not None and tap.origin_ns is not None else 0.0)
        src.close()
        errf.close()
        sampler.join(timeout=2.0)

    rc = proc.returncode
    attack_meta = None
    if attack_handle is not None:
        result = attack_handle.finalize()
        win = None
        if result["gate_open_recv_ns"] is not None and origin_ns is not None:
            gate_t = (result["gate_open_recv_ns"] - origin_ns) / 1e9  # decision-time coordinates (s from 1st frame)
            p = attack_handle.meta["params"]
            win = {"gate_t_s": round(gate_t, 3), "onset_t_s": round(gate_t + p["onset_after_gate_s"], 3),
                   "end_t_s": round(gate_t + p["onset_after_gate_s"] + p["duration_s"], 3)}
        attack_meta = {**attack_handle.meta, "result": result, "window_decision_time": win}
    chain = store.verify_chain(run_id)
    store.close()
    fetched = fetch_wsl_files(run_dir, out)
    try:
        orphan = wsl("bash", "-c", "pgrep -a -x arducopter || echo none").stdout.decode().strip()
    except (subprocess.TimeoutExpired, OSError) as exc:
        orphan = f"UNKNOWN (orphan check failed: {exc!r})"

    # -- pipe integrity: the Windows clean tlog must equal the WSL-side tlog, frame for frame ---- #
    integrity: dict = {"checked": False}
    wsl_tlog = out / "downlink.tlog"
    if wsl_tlog.exists() and clean_tlog.exists():
        w, c = read_tlog(wsl_tlog), read_tlog(clean_tlog)
        n = min(len(w), len(c))
        same = sum(1 for i in range(n) if w[i][1] == c[i][1])
        off = [c[i][0] - w[i][0] for i in range(n)]
        integrity = {"checked": True, "wsl_frames": len(w), "windows_frames": len(c),
                     "identical_prefix_frames": same, "identical": len(w) == len(c) == same,
                     "clock_offset_us_median": int(statistics.median(off)) if off else None,
                     "clock_offset_us_spread": (max(off) - min(off)) if off else None}
    offset_s = (integrity.get("clock_offset_us_median") or 0) / 1e6

    # -- phases (collector events -> Windows clock) ------------------------------------------- #
    phases: list[tuple[float, str]] = []
    ev_path = out / "events.jsonl"
    if ev_path.exists():
        events = [json.loads(line) for line in ev_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        phases = [(e["t_unix"] + offset_s, e["name"]) for e in events if e["event"] == "phase"]
    for d in decisions:
        cur = "boot"
        for t_ph, name in phases:
            if d["wall_unix"] >= t_ph:
                cur = name
        # decisions after the last received frame measure the END of the run, not the link
        d["phase"] = "post_link" if d["t"] > link_span_s + 0.5 else cur
    phase_of = {d["wall_unix"]: d["phase"] for d in decisions}
    for al in alerts:
        al["phase"] = phase_of.get(al["wall_unix"])

    # -- metrics ------------------------------------------------------------------------------ #
    span = (decisions[-1]["t"] - decisions[0]["t"]) if len(decisions) > 1 else 0.0
    lat = [d["latency_ms"] for d in decisions]
    by_phase: dict[str, dict] = {}
    for d in decisions:
        p = by_phase.setdefault(d["phase"], {"decisions": 0, "threat": 0, "alerts": 0})
        p["decisions"] += 1
        p["threat"] += d["threat"]
        p["alerts"] += d["alert"]
    ticks = src_stats["ticks_emitted"]
    stream_s = link_span_s  # first to last received frame; excludes the trailing silent ticks
    in_link = [d for d in decisions if d["phase"] != "post_link"]
    coverage = {m: {"count": msg_counts.get(m, 0),
                    "rate_hz": round(msg_counts.get(m, 0) / stream_s, 3) if stream_s else None}
                for m in PIPELINE_MESSAGES}
    others = {k: {"count": v, "rate_hz": round(v / stream_s, 3) if stream_s else None}
              for k, v in sorted(msg_counts.items()) if k not in PIPELINE_MESSAGES}
    summary = {
        "schema": "aegisflight.ardupilot_sitl_run/1",
        "environment": "SITL (ArduCopter 4.7.1 in an isolated netns; pipe transport; wall-clock 1x)",
        "attack": a.attack or "NONE",
        "claim_class": ("link-level detection (downlink modified between simulator and IDS; estimator "
                        "and flight unaffected)" if a.attack else "none (benign false-alarm / cost reference)"),
        "harness": a.harness, "monitor_transmits_heartbeat": bool(a.monitor_heartbeat),
        "receive_only_monitor": a.harness == "passive" and not a.monitor_heartbeat,
        "stream_config": a.stream, "profile": a.profile, "started_utc": started_utc, "harness_exit_code": rc,
        "ticks": ticks, "link_span_s": round(stream_s, 1), "decisions_total": len(decisions),
        "decisions": len(in_link), "post_link_decisions": len(decisions) - len(in_link),
        "threat_decisions": sum(d["threat"] for d in in_link),
        "alert_decisions": sum(d["alert"] for d in in_link),
        "alert_decisions_post_link": sum(d["alert"] for d in decisions if d["phase"] == "post_link"),
        "false_alarm_rate_per_decision": (round(sum(d["alert"] for d in in_link) / len(in_link), 5)
                                          if in_link and not a.attack else None),
        "by_phase": by_phase, "alert_types": dict(Counter(al["type"] for al in alerts)),
        "message_coverage_pipeline": coverage, "other_messages": others,
        "aggregate_msg_rate_hz": round(n_msgs / stream_s, 2) if stream_s else None,
        "link_bytes_per_s": round(pipe_stats["bytes_received"] / stream_s, 1) if stream_s else None,
        "decision_latency_ms": {"mean": round(statistics.fmean(lat), 4) if lat else None, "p50": pct(lat, .5),
                                "p95": pct(lat, .95), "p99": pct(lat, .99), "max": round(max(lat), 4) if lat else None},
        "tick_close_to_emit_ms": {"p50": pct(emit_lag_ms, .5), "p95": pct(emit_lag_ms, .95),
                                  "p99": pct(emit_lag_ms, .99),
                                  "max": round(max(emit_lag_ms), 2) if emit_lag_ms else None},
        "resources_ids_process": {
            "cpu_pct_of_one_core_mean": round(statistics.fmean(sampler.cpu), 2) if sampler.cpu else None,
            "cpu_pct_of_one_core_max": round(max(sampler.cpu), 2) if sampler.cpu else None,
            "cpu_seconds_total": round((cpu1.user + cpu1.system) - (cpu0.user + cpu0.system), 2),
            "wall_seconds": round(wall_s, 1),
            "rss_mb_max": round(max(sampler.rss) / 2**20, 1) if sampler.rss else None,
            "threads_max": max(sampler.threads) if sampler.threads else None,
            "note": "Windows IDS process only (this script incl. pipeline, ML, SQLite); the WSL simulator is excluded",
        },
        "source_stats": src_stats, "pipe_stats": pipe_stats, "tap_stats": tap_stats,
        "pipe_integrity": integrity, "hash_chain": {"ok": chain.ok, "length": chain.length, "detail": chain.detail},
        "orphan_arducopter_after_run": orphan,
        "ml_enabled": model is not None, "config_dir": a.config_dir or "configs (Stage-1 default)",
        "decision_span_s": round(span, 1),
    }
    manifest = {
        "schema": "aegisflight.ardupilot_sitl_manifest/1", "name": a.name, "wsl_run_dir": run_dir, "distro": DISTRO,
        "command": [sys.executable, *sys.argv], "fetched_from_wsl": fetched,
        "clean_tlog": {"path": str(clean_tlog), "sha256": sha256_file(clean_tlog) if clean_tlog.exists() else None},
        "observed_tlog": {"path": str(obs_tlog), "sha256": sha256_file(obs_tlog) if obs_tlog.exists() else None},
        "attack": attack_meta, "origin_ns": origin_ns,
        "provenance": collect(model=a.model, configs=a.config_dir or "configs"),
    }
    for fn in ("preflight.txt", "postcheck.txt"):
        p = out / fn
        manifest[fn.split(".")[0]] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else None
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    (out / "decisions.jsonl").write_text("\n".join(json.dumps(d) for d in decisions) + "\n", encoding="utf-8")
    (out / "alerts.jsonl").write_text("\n".join(json.dumps(x, default=str) for x in alerts) + ("\n" if alerts else ""),
                                      encoding="utf-8")
    print(json.dumps({k: summary[k] for k in (
        "decisions", "alert_decisions", "by_phase", "aggregate_msg_rate_hz", "decision_latency_ms",
        "pipe_integrity", "hash_chain", "orphan_arducopter_after_run", "harness_exit_code")}, indent=2, default=str))
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
