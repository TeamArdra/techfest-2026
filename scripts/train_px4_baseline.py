#!/usr/bin/env python
"""Train a SEPARATE PX4-SITL benign anomaly model (same ML_FEATURES, same bundle schema).

    .venv/Scripts/python.exe scripts/train_px4_baseline.py

Environment: SITL (replayed tlog), attack NONE. Output ``models/isoforest_px4.joblib``
(gitignored) + a sidecar JSON ``artifacts/sitl/calibration/isoforest_px4_training.json``
with the exact training file list, SHA-256s, seed and package versions.
``models/isoforest.joblib`` (Stage-1, simulator-trained) is NEVER read for writing.

Training data = the CALIBRATION flights benign_001..005 ONLY (the script refuses
held-out ids 006..010). ``ML_FEATURES`` order is untouched (frozen contract).

Same recipe as ``scripts/train_models.py``: StandardScaler + IsolationForest +
diagonal-Mahalanobis, combined by max of the two standardised signals, score
normalised by a benign-calibrated threshold/scale; first 5 s of each flight
excluded (the Stage-1 warm-up convention).

Difference forced by n = 5 flights: Stage-1 calibrates ``score_thr`` on a held-out
validation *split*; here it is calibrated on **leave-one-flight-out** out-of-fold
raw scores (each fold fits on 4 flights, scores the 5th, so no flight scores
itself), pooled: ``thr = mean + 3 sd``, ``scale = sd``. The shipped model is then
fit on all 5 flights. Scores of the calibration flights under the shipped model
are IN-SAMPLE (optimistic); the leave-one-flight-out numbers are the honest
within-calibration estimate; the held-out set is the real test.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent / "sitl"))
import calib_common as cc  # noqa: E402

from aegisflight.detectors.anomaly import combined_anomaly_raw  # noqa: E402
from aegisflight.features.extractor import ML_FEATURES  # noqa: E402

WARMUP_S = 5.0  # same as benchmark.dataset.collect_benign_dataset
ALARM_NORM = 0.62  # detector.yaml anomaly.score_threshold


def fit_bundle(X: np.ndarray, seed: int, n_estimators: int, contamination: float) -> dict:
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    model = IsolationForest(n_estimators=n_estimators, contamination=contamination,
                            random_state=seed, n_jobs=-1).fit(Xs)
    iso = -model.score_samples(Xs)
    maha = np.linalg.norm(Xs, axis=1)
    return {"model": model, "scaler": scaler, "feature_names": list(ML_FEATURES),
            "iso_mean": float(iso.mean()), "iso_std": float(iso.std() or 1e-3),
            "maha_mean": float(maha.mean()), "maha_std": float(maha.std() or 1e-3)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=cc.REPO / "models" / "isoforest_px4.joblib")
    ap.add_argument("--sidecar", type=Path, default=cc.OUT_DIR / "isoforest_px4_training.json")
    ap.add_argument("--seed", type=int, default=100)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    if a.out.resolve() == (cc.REPO / "models" / "isoforest.joblib").resolve():
        raise SystemExit("refusing to overwrite the Stage-1 model")

    cfg = cc.cfg_for("px4_sitl")
    acfg = cfg.detector["anomaly"]
    n_est, contamination = int(acfg.get("n_estimators", 200)), float(acfg.get("contamination", 0.02))

    X_by: dict[str, np.ndarray] = {}
    files = []
    for tl in cc.CALIB_FLIGHTS:
        name = Path(tl).stem
        assert int(name.split("_")[1]) <= 5, f"{name} is held-out"
        rows = cc.replay_rows(tl, cfg, None)
        X_by[name] = np.array([[r[n] for n in ML_FEATURES] for r in rows if r["t"] >= WARMUP_S])
        files.append({"tlog": tl, "sha256": cc.sha256(cc.resolve(tl)), "train_vectors": int(len(X_by[name]))})
        print(f"{name}: {len(X_by[name])} training vectors")

    # ---- leave-one-flight-out out-of-fold raw scores -> calibration of thr/scale ----
    oof_raw: dict[str, np.ndarray] = {}
    for held in X_by:
        Xtr = np.vstack([v for k, v in X_by.items() if k != held])
        fold = fit_bundle(Xtr, a.seed, n_est, contamination)
        oof_raw[held] = combined_anomaly_raw(fold, X_by[held])
    pooled = np.concatenate(list(oof_raw.values()))
    thr, scale = float(pooled.mean() + 3.0 * pooled.std()), float(max(pooled.std(), 1e-3))

    def alarm_rate(raw: np.ndarray) -> float:
        norm = 1.0 / (1.0 + np.exp(-(raw - thr) / scale))
        return float((norm >= ALARM_NORM).mean())

    lofo = {k: alarm_rate(v) for k, v in oof_raw.items()}

    # ---- shipped model: fit on all 5 flights ----
    Xall = np.vstack(list(X_by.values()))
    bundle = fit_bundle(Xall, a.seed, n_est, contamination)
    bundle["score_thr"], bundle["score_scale"] = thr, scale
    insample = {k: alarm_rate(combined_anomaly_raw(bundle, v)) for k, v in X_by.items()}
    bundle["metadata"] = {
        "created": datetime.now(UTC).isoformat(), "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__, "python_version": platform.python_version(),
        "seed": a.seed, "n_estimators": n_est, "contamination": contamination,
        "n_train_vectors": int(len(Xall)), "training": "PX4 SITL benign calibration flights 001..005",
        "train_files": [f["tlog"] for f in files], "calibration": "leave-one-flight-out OOF mean+3sd",
        "ml_features": list(ML_FEATURES),
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, a.out)

    sidecar = {
        "schema": "aegisflight.px4_baseline_training/1", "environment": "SITL (replayed tlog)",
        "attack_status": "NONE", "model_path": str(a.out.relative_to(cc.REPO)) if a.out.is_relative_to(cc.REPO) else str(a.out),
        "model_sha256": cc.sha256(a.out), "stage1_model_untouched_sha256": cc.sha256(cc.REPO / cc.STAGE1_MODEL),
        "training_files": files, "warmup_excluded_s": WARMUP_S, "seed": a.seed,
        "n_estimators": n_est, "contamination": contamination,
        "ml_features_order": list(ML_FEATURES),
        "score_thr": thr, "score_scale": scale,
        "alarm_norm_threshold": ALARM_NORM,
        "benign_alarm_rate_leave_one_flight_out": lofo,
        "benign_alarm_rate_in_sample_OPTIMISTIC": insample,
        "versions": {"sklearn": sklearn.__version__, "numpy": np.__version__,
                     "python": platform.python_version()},
        "caveat": "5 flights of one scripted route on one host; in-sample rates are optimistic; "
                  "rate features embed this host's real-time factor (~0.87-0.90).",
    }
    a.sidecar.parent.mkdir(parents=True, exist_ok=True)
    a.sidecar.write_text(json.dumps(sidecar, indent=2))
    print(f"saved {a.out}  sha256={sidecar['model_sha256'][:16]}...")
    print("LOFO alarm rate:", lofo)
    print("in-sample (optimistic):", insample)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
