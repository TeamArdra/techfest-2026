# AegisFlight — ML Pipeline

The ML layer is **one of four detectors** — a lightweight, benign-trained
anomaly detector that corroborates and extends the deterministic detectors. It
never replaces them; with no model present the system still runs (the detector
is a no-op).

```
collect benign sessions (varied) ──▶ ML feature vectors (11-dim)
        │ split BY SESSION (train/val/test)
        ▼
StandardScaler ──▶ IsolationForest        ┐
                    + Mahalanobis norm     ├─ ensemble = max(iso_z, maha_z)
        │ calibrate on validation          ┘
        ▼
save bundle (models/isoforest.joblib) ──▶ inference in AnomalyDetector
```

## Model
- **Type:** ensemble of `sklearn.ensemble.IsolationForest`
  (`n_estimators=200`; `contamination=0.02` is passed but only affects
  `predict()`/`decision_function()`, which AegisFlight does not use — decisions come from
  `score_samples()` + the calibration below) and a diagonal
  Mahalanobis/scaled-norm over the same `StandardScaler`. Combined by
  `max(iso_z, maha_z)` (see `detectors/anomaly.py:combined_anomaly_raw` — the
  identical function is used for both calibration and inference).
- **Why the ensemble:** Isolation Forest captures subtle multivariate anomalies
  but cannot extrapolate beyond its training range (blind to msg-rate floods,
  sequence gaps); the scaled-norm grows without bound for out-of-range values
  and covers that blind spot.
- **Features:** the 11-dim `ML_FEATURES` vector (`docs/FEATURES.md`).

## Training data (`benchmark/dataset.py`)
- **Benign only.** The model never sees an attack during training.
- **Varied** across sessions: route (survey/out-and-back/perimeter), cruise
  speed (9–15 m/s), cruise altitude (40–80 m), sensor-noise scale (0.8–1.4×),
  and seed.
- **Session-level split** (`split_by_session`): whole *flights* go to
  train/val/test (60/20/20). Rows from one flight are highly autocorrelated, so
  a random row split would leak — this avoids it.
- **Seeds are disjoint from the benchmark** (training kinematics/noise seeds 101–124;
  baseline benchmark noise seeds 1–6, kinematics seed fixed at 42). Evaluation flights
  are therefore different noise realisations of 3 fixed trajectories, not a broad set of
  unseen flights — see the extended benchmark v2 for per-session trajectory diversity.

## Calibration
The combined signal is standardised by benign *train* statistics
(`iso_mean/std`, `maha_mean/std`). The normalisation threshold is set on the
*validation* split (`score_thr = mean + 3σ`, `score_scale = σ`), and the benign
**test** alarm rate is reported as a leakage-free specificity check
(currently ≈0.2 %). Inference maps the combined signal through a logistic; the
detector triggers at `anomaly.score_threshold` (0.62).

## Saved bundle
`joblib` dict: `model`, `scaler`, `feature_names`, `iso_mean/std`,
`maha_mean/std`, `score_thr`, `score_scale`, and `metadata` (created timestamp,
`sklearn_version`, `python_version`, seed, n_sessions, contamination,
train/val/test session ids, benign_test_alarm_rate). Inference reconstructs the
exact feature schema from `feature_names`.

## Retraining
```
aegis train --sessions 24            # or: python scripts/train_models.py
```
Prints the split, benign test alarm rate, and per-attack sanity scores.
**Retrain whenever** you change `ML_FEATURES`, the simulator, or the noise
model. The `.joblib` is gitignored (regenerable); its metadata records the
environment it was trained in — verify `sklearn_version` compatibility before
trusting a stale model.

## Failure modes
- **No/incompatible model** → detector degrades to score 0 (logged as ML off).
- **Version skew** (different sklearn) → `joblib.load` may fail → same graceful
  no-op; retrain to fix.
- **Distribution shift** (new simulator settings) → higher benign alarm rate;
  retrain.

## Separate PX4-SITL model (not the Stage-1 model)
`scripts/train_px4_baseline.py` trains `models/isoforest_px4.joblib` (gitignored) from the five
PX4 SITL calibration flights with the **same** `ML_FEATURES` order and bundle schema; it never
touches `models/isoforest.joblib`. With only five flights, the score threshold/scale come from
leave-one-flight-out out-of-fold scores instead of a validation split, and in-sample scores are
optimistic. Sidecar (file list, SHA-256, sklearn version, seed):
`artifacts/sitl/calibration/isoforest_px4_training.json`. Details, limits and results:
`docs/CALIBRATION_PX4.md`.
