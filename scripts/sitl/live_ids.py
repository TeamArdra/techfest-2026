"""Run the Stage-1 IDSPipeline LIVE on a PX4 SITL MAVLink/UDP link.

    .venv/Scripts/python.exe scripts/sitl/live_ids.py --port 18572 --seconds 150 --out artifacts/sitl/live_run_001

Environment: SITL, live UDP (no attack unless something else injects one; this
script never injects). The raw frames the IDS actually saw are teed to
``<out>.tlog`` (same format as record_flight.py) so any live decision can be
re-derived offline from identical bytes. One JSON line per decision goes to
``<out>.jsonl``; a summary to ``<out>.summary.json``.

It connects to PX4's GCS link as the GCS (sends the 1 Hz heartbeat PX4 needs) and
becomes that link's partner -- start a fresh SITL first.
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from provenance import collect, sha256_file

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport

MODEL = "models/isoforest.joblib"


def wsl_ip(distro: str = "Ubuntu-24.04") -> str:
    out = subprocess.run(["wsl", "-d", distro, "--", "hostname", "-I"], capture_output=True, text=True, timeout=30)
    return out.stdout.split()[0]


def split_frames(data: bytes) -> list[bytes]:
    """Split a datagram into whole MAVLink frames (v2 0xFD, v1 0xFE); drops trailing garbage."""
    out, i = [], 0
    while i < len(data):
        if data[i] == 0xFD and i + 12 <= len(data):
            flen = 12 + data[i + 1] + (13 if data[i + 2] & 1 else 0)
        elif data[i] == 0xFE and i + 8 <= len(data):
            flen = 8 + data[i + 1]
        else:
            break
        if i + flen > len(data):
            break
        out.append(data[i:i + flen])
        i += flen
    return out


class TeeTransport:
    """Wraps a transport; writes every polled frame to a tlog (unix-time microseconds)."""

    def __init__(self, inner, tlog_path: Path) -> None:
        self.inner = inner
        self.f = open(tlog_path, "wb")  # noqa: SIM115 - closed in close()
        # transport stamps with time.monotonic_ns; convert to unix for the tlog
        self._off = time.time() - time.monotonic()
        self.dropped_overflow = 0

    def poll(self):
        out = self.inner.poll()
        for recv_ns, data in out:
            ts = struct.pack(">Q", int((recv_ns / 1e9 + self._off) * 1e6))
            for frame in split_frames(data):  # tlog records are ONE frame each; a datagram may hold several
                self.f.write(ts + frame)
        self.dropped_overflow = getattr(self.inner, "dropped_overflow", 0)
        return out

    def close(self) -> None:
        self.inner.close()
        self.f.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=None, help="PX4 host (default: discovered WSL IP)")
    ap.add_argument("--port", type=int, default=18572)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-ml", action="store_true")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    cfg = load_config()
    model = None if a.no_ml or not Path(MODEL).exists() else MODEL
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    host = a.host or wsl_ip()
    udp = UdpMavlinkTransport(connect=(host, a.port), gcs_heartbeat=True)
    udp.start()
    transport = TeeTransport(udp, out.with_suffix(".tlog"))
    src = LiveMavlinkSource(transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))
    started = datetime.now(UTC).isoformat()
    n = threats = 0
    lat: list[float] = []
    classes: Counter = Counter()
    try:
        with open(out.with_suffix(".jsonl"), "w", encoding="utf-8") as jf:
            for tick in src.stream():
                asmt = pipe.process_tick(tick)
                if asmt is None:
                    continue
                n += 1
                threats += bool(asmt.threat)
                lat.append(asmt.latency_ms)
                classes[asmt.attack_type.value if asmt.threat else "BENIGN"] += 1
                jf.write(json.dumps({"t": round(asmt.t, 2), "wall_utc": datetime.now(UTC).isoformat(),
                                     "threat": bool(asmt.threat), "type": asmt.attack_type.value,
                                     "score": round(asmt.threat_score, 3), "latency_ms": round(asmt.latency_ms, 2),
                                     "n_msgs": len(tick.messages)}) + "\n")
    finally:
        stats = src.stats
        transport.close()
    lat_s = sorted(lat)
    summary = {
        "schema": "aegisflight.sitl_live_run/1", "environment": "SITL (live UDP)", "attack_status": "NONE (no injector)",
        "started_utc": started, "requested_seconds": a.seconds, "host": host, "port": a.port, "decisions": n, "threat_decisions": threats,
        "classes": dict(classes), "source_stats": stats, "ml_enabled": model is not None,
        "decision_latency_ms": {"mean": sum(lat) / len(lat) if lat else None,
                                "p95": lat_s[int(0.95 * (len(lat_s) - 1))] if lat_s else None},
    }
    summary["provenance"] = collect(tlog_sha256=sha256_file(out.with_suffix(".tlog")))
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
