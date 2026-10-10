"""Portable cost metric: CPU seconds the IDS needs per second of telemetry (run it on the TARGET machine).

    .venv/Scripts/python.exe scripts/ardupilot/measure_replay_cost.py data/ardupilot/raw/ap_benign_six_001.clean.tlog \
        --repeat 3 --json artifacts/ardupilot/replay_cost_<machine>.json

Replays a recorded capture through the unchanged pipeline as fast as it will go (no pacing) and reports
process CPU time per second of telemetry covered, for the ML-on and ML-off variants. A real-time
deployment needs the value to be well below 1.0 per core; the margin is how much headroom is left for
everything else on the machine. This measures the IDS pipeline only (frame parsing, features, three
detectors + fusion, optional ML) -- not the serial driver, not logging to disk, not the dashboard.

The number is only comparable across machines running the same Python/numpy/scikit-learn builds; the
JSON records them. A figure measured on a development laptop says nothing about a Raspberry Pi or a
Jetson until it is re-measured there with this same command.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import psutil

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from replay_ap_tlog import replay  # noqa: E402

from aegisflight.config import load_config  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tlog")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--json")
    a = ap.parse_args(argv)

    cfg = load_config(None)
    rate = float(cfg.simulation.get("sample_rate_hz", 10.0))
    proc = psutil.Process()
    out: dict = {"schema": "aegisflight.replay_cost/1", "utc": datetime.now(UTC).isoformat(),
                 "tlog": a.tlog, "machine": {"platform": platform.platform(), "processor": platform.processor(),
                                             "cpu_count_logical": os.cpu_count(), "python": platform.python_version()},
                 "variants": {}}
    for pkg in ("numpy", "scikit-learn", "pymavlink"):
        try:
            out["machine"][pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            out["machine"][pkg] = None
    for name, model in (("ml_off", None), ("ml_on", a.model if Path(a.model).exists() else None)):
        if name == "ml_on" and model is None:
            out["variants"][name] = {"skipped": "model file not found"}
            continue
        runs = []
        for _ in range(a.repeat):
            c0, w0 = time.process_time(), time.perf_counter()
            rows, _t0 = replay(Path(a.tlog), cfg, model, rate)
            cpu, wall = time.process_time() - c0, time.perf_counter() - w0
            covered = rows[-1]["t"] - rows[0]["t"] if len(rows) > 1 else 0.0
            runs.append({"decisions": len(rows), "telemetry_seconds": round(covered, 1), "cpu_s": round(cpu, 3),
                         "wall_s": round(wall, 3),
                         "cpu_s_per_telemetry_s": round(cpu / covered, 5) if covered else None,
                         "rss_mb": round(proc.memory_info().rss / 2**20, 1)})
        per = [r["cpu_s_per_telemetry_s"] for r in runs]
        out["variants"][name] = {"runs": runs, "median_cpu_s_per_telemetry_s": round(statistics.median(per), 5),
                                 "max_rss_mb": max(r["rss_mb"] for r in runs)}
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
