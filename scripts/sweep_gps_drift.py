#!/usr/bin/env python
"""Detection versus attack magnitude for gradual GPS drift (``SIM`` characterisation, ML off).

Runs the unchanged benchmark session runner once per (drift rate, seed) with ``gps_spoofing.mode = gradual_drift`` and the
Stage-1 ``configs/`` (nothing is tuned here), plus benign sessions on the same seeds. For every session it records whether an
attack-window decision was flagged and the time to first alert. Output: ``sweep.csv`` (one row per session),
``sweep_summary.csv`` (per rate: sessions, detected, Wilson 95 % interval, median time to first alert),
``detection_vs_magnitude.png`` and ``sweep_meta.json``.

What it is: a *characterisation* of where the current physics rules start to fire. The rate range was chosen after the
unit tests had already pinned the floor (``tests/unit/test_gps_scenarios_fused.py``), so it is **not** independent
validation, and the drift is velocity-inconsistent by construction (the simulator reports the true velocity), which is the
easy case. Slow velocity-consistent drift is a documented blind spot and is not swept here.

Usage: python scripts/sweep_gps_drift.py --out <dir> [--seeds 5] [--rates 0.5 1 2 3 4 5 6 8 12]
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aegisflight.benchmark.runner import run_session  # noqa: E402
from aegisflight.config import load_config  # noqa: E402
from make_submission_stats import wilson  # noqa: E402

SEED0 = 50_000  # distinct from the benchmark seeds (30,000+)


def _fp(res) -> int:
    return sum(1 for r in res.records if r.scored and not r.true_label.is_attack and r.pred_label.is_attack)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--rates", type=float, nargs="+", default=[0.5, 1, 2, 3, 4, 5, 6, 8, 12])
    ap.add_argument("--model", default=None, help="trained ML model (default: ML off, i.e. rules + physics only)")
    a = ap.parse_args()
    model = a.model
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base = load_config()
    rows = []
    for i in range(a.seeds):
        seed = SEED0 + i
        res = run_session(copy.deepcopy(base), "benign", seed=seed, model_path=model)
        rows.append({"rate_ms": 0.0, "seed": seed, "route": res.route, "detected": False, "ttd_s": None,
                     "false_positive_decisions": _fp(res)})
        for rate in a.rates:
            cfg = copy.deepcopy(base)
            cfg.attacks["gps_spoofing"].update({"mode": "gradual_drift", "drift_rate_ms": float(rate)})
            res = run_session(cfg, "gps_spoofing", seed=seed, model_path=model)
            rows.append({"rate_ms": float(rate), "seed": seed, "route": res.route,
                         "detected": res.time_to_detect_s is not None, "ttd_s": res.time_to_detect_s,
                         "false_positive_decisions": _fp(res)})
    df = pd.DataFrame(rows)
    df.to_csv(out / "sweep.csv", index=False)

    summ = []
    for rate, g in df[df["rate_ms"] > 0].groupby("rate_ms"):
        k, n = int(g["detected"].sum()), len(g)
        lo, hi = wilson(k, n)
        t = g["ttd_s"].dropna()
        summ.append({"rate_ms": rate, "sessions": n, "detected": k, "wilson95_lo": round(lo, 3),
                     "wilson95_hi": round(hi, 3), "median_ttd_s": None if t.empty else round(float(t.median()), 2),
                     "sessions_with_false_positive_decisions": int((g["false_positive_decisions"] > 0).sum())})
    sm = pd.DataFrame(summ)
    sm.to_csv(out / "sweep_summary.csv", index=False)
    benign = df[df["rate_ms"] == 0]
    benign_fp = int((benign["false_positive_decisions"] > 0).sum())

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 3.6))
    frac = sm["detected"] / sm["sessions"]
    ax.errorbar(sm["rate_ms"], frac, yerr=[frac - sm["wilson95_lo"], sm["wilson95_hi"] - frac], fmt="o-", capsize=3)
    ax.set_xlabel("injected drift rate (m/s), 30 s window")
    ax.set_ylabel("sessions detected (Wilson 95 %)")
    ax.set_ylim(-0.05, 1.05)
    ax.set_title(f"SIM, ML {'on' if model else 'off'}, n={a.seeds} sessions per rate; benign sessions with a FP: {benign_fp}/{len(benign)}", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "detection_vs_magnitude.png", dpi=130)

    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        head = None
    (out / "sweep_meta.json").write_text(json.dumps({
        "script": "scripts/sweep_gps_drift.py", "git_head": head, "environment": "SIM", "ml": model is not None,
        "model_sha256": hashlib.sha256(Path(model).read_bytes()).hexdigest() if model else None,
        "seeds": [SEED0 + i for i in range(a.seeds)], "rates_ms": a.rates,
        "configs_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path("configs").glob("*.yaml"))},
        "benign_sessions": len(benign), "benign_sessions_with_false_positive": benign_fp,
        "note": "characterisation after the floor was already pinned by unit tests; not independent validation; "
                "velocity-inconsistent drift only"}, indent=2) + "\n", encoding="utf-8")
    print(sm.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
