"""Feature-distribution shift: PX4 SITL calibration flights vs Stage-1 SIM benign.

    .venv/Scripts/python.exe scripts/sitl/calib_shift.py

SITL side: calibration flights benign_001..005 only (held-out never read here).
SIM side: ``aegisflight.external.realdata.sim_reference_ticks`` (the same generator the
Stage-1 external-validation reference uses; ``_vary_config`` sampling mirrors
``benchmark.dataset``), N flights with seeds 9001+i drawn exactly as
``scripts/external_validation.py::sim_reference`` does (rng 9000), run through the
unchanged ``FeatureExtractor``. Decisions before 5 s are dropped on both sides
(Stage-1 warm-up convention). Output: ``artifacts/sitl/calibration/feature_shift.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

from aegisflight.external import realdata  # noqa: E402
from aegisflight.features.extractor import ML_FEATURES, FeatureExtractor  # noqa: E402

N_SIM = 12
WARMUP_S = 5.0


def sim_rows(cfg) -> list[dict]:
    rng = np.random.default_rng(9000)
    routes = ("survey_box", "out_and_back", "perimeter")
    rows: list[dict] = []
    for i in range(N_SIM):
        seed, route = 9001 + i, routes[i % 3]
        speed, alt, noise = float(rng.uniform(9, 15)), float(rng.uniform(40, 80)), float(rng.uniform(0.8, 1.4))
        fe = FeatureExtractor(cmd_window_s=cfg.detector["protocol"].get("command_burst_window_s", 2.0))
        for t, msgs, _air in realdata.sim_reference_ticks(cfg, seed, route, speed, alt, noise):
            for m in msgs:
                fe.update(m)
            f = fe.extract(t)
            fe.clear_window_counts()
            if t >= WARMUP_S:
                rows.append({n: float(getattr(f, n)) for n in ML_FEATURES})
    return rows


def pct(v: np.ndarray) -> dict:
    return {"p50": float(np.percentile(v, 50)), "p95": float(np.percentile(v, 95)),
            "p99": float(np.percentile(v, 99)), "max": float(v.max()), "mean": float(v.mean()),
            "std": float(v.std())}


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    cfg = cc.cfg_for("default")
    sim = sim_rows(cfg)
    sitl = []
    for tl in cc.CALIB_FLIGHTS:
        assert int(Path(tl).stem.split("_")[1]) <= 5
        sitl += [r for r in cc.replay_rows(tl, cfg, None) if r["t"] >= WARMUP_S]
    try:
        from scipy.stats import ks_2samp
    except ImportError:  # pragma: no cover
        ks_2samp = None
    feats = {}
    for n in ML_FEATURES:
        a = np.array([r[n] for r in sim])
        b = np.array([r[n] for r in sitl])
        feats[n] = {"sim": pct(a), "sitl": pct(b),
                    "ks_statistic": float(ks_2samp(a, b).statistic) if ks_2samp else None}
    doc = {"schema": "aegisflight.sitl_feature_shift/1", "environment": "SIM vs SITL (replayed tlog)",
           "attack_status": "NONE", "n_sim_flights": N_SIM, "n_sim_decisions": len(sim),
           "n_sitl_decisions": len(sitl), "sitl_flights": list(cc.CALIB_FLIGHTS),
           "sim_source": "aegisflight.external.realdata.sim_reference_ticks, seeds 9001.., rng 9000 as "
                         "scripts/external_validation.py::sim_reference",
           "features": feats}
    out = cc.OUT_DIR / "feature_shift.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2))
    for n, v in feats.items():
        print(f"{n:24} sim p50/p95/max={v['sim']['p50']:.3f}/{v['sim']['p95']:.3f}/{v['sim']['max']:.3f}  "
              f"sitl={v['sitl']['p50']:.3f}/{v['sitl']['p95']:.3f}/{v['sitl']['max']:.3f}  KS={v['ks_statistic']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
