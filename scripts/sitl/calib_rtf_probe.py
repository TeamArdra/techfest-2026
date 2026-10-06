"""Analytic real-time-factor (host load) probe for the PX4-benign ML model and the rate rule.

    .venv/Scripts/python.exe scripts/sitl/calib_rtf_probe.py

Environment: SITL data, ANALYTIC COUNTERFACTUAL -- NOT a measurement. SITL time is not wall
time (RTF 0.87-0.90 in the calibration captures). To see how host-load dependent the PX4
model C and the rate rule are, each calibration decision's rate features are rescaled as if
the same flight had run at a different RTF:  ratio = RTF_target / RTF_flight,
``msg_rate_hz *= ratio`` and ``interarrival_jitter_ms /= ratio`` (all other features left
alone -- physical-time features do not change with RTF to first order, which is itself an
assumption). Calibration flights only. Output: ``artifacts/sitl/calibration/rtf_probe.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402
import joblib  # noqa: E402

from aegisflight.config import load_config  # noqa: E402
from aegisflight.detectors.anomaly import combined_anomaly_raw  # noqa: E402
from aegisflight.features.extractor import ML_FEATURES  # noqa: E402

TARGETS = (0.60, 0.70, 0.80, 0.90, 1.00, 1.25, 1.50, 2.00, 3.00)  # > 1.0: hypothetical faster-than-real-time OR a proportional rate flood


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    cfg = cc.cfg_for("px4_sitl")
    prot = cfg.detector["protocol"]
    spike = prot["nominal_msg_rate_hz"] * prot["msg_rate_spike_factor"]
    bundle = joblib.load(cc.resolve(cc.PX4_MODEL))
    thr, scale = bundle["score_thr"], bundle["score_scale"]
    ml_thr = float(load_config(cc.resolve(cc.PROFILE_DIR)).detector["anomaly"]["score_threshold"])
    der = json.loads((cc.OUT_DIR / "derivation.json").read_text())
    base_rows, rtf = [], []
    for tl in cc.CALIB_FLIGHTS:
        name = Path(tl).stem
        rows = [r for r in cc.replay_rows(tl, cc.cfg_for("default"), None) if r["t"] >= 5.0]
        base_rows += rows
        rtf += [der["flights"][name]["rtf"]] * len(rows)
    X = np.array([[r[n] for n in ML_FEATURES] for r in base_rows])
    rtf_a = np.array(rtf)
    i_rate, i_jit = ML_FEATURES.index("msg_rate_hz"), ML_FEATURES.index("interarrival_jitter_ms")
    out = {}
    for tgt in TARGETS:
        ratio = tgt / rtf_a
        Xs = X.copy()
        Xs[:, i_rate] *= ratio
        Xs[:, i_jit] /= ratio
        raw = combined_anomaly_raw(bundle, Xs)
        norm = 1.0 / (1.0 + np.exp(-(raw - thr) / scale))
        out[f"rtf_{tgt:.2f}"] = {"ml_C_alarm_rate": float((norm >= ml_thr).mean()),
                                 "rate_rule_spike_rate": float((Xs[:, i_rate] > spike).mean()),
                                 "median_msg_rate": float(np.median(Xs[:, i_rate]))}
        print(tgt, out[f"rtf_{tgt:.2f}"])
    doc = {"schema": "aegisflight.sitl_rtf_probe/1", "environment": "SITL data, analytic counterfactual",
           "attack_status": "NONE", "claim_class": "none", "n_decisions": len(X),
           "spike_threshold_msgs": spike, "targets": out,
           "caveat": "linear rescaling of two features; not a measurement at another RTF"}
    (cc.OUT_DIR / "rtf_probe.json").write_text(json.dumps(doc, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
