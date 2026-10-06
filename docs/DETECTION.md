# AegisFlight — Detection Methodology

Four independent detectors each emit a `DetectorResult` (a normalised `score`
∈ [0,1], a `triggered` flag, human-readable `evidence`, and `attack_votes`).
The `FusionEngine` combines them into one `ThreatAssessment`.

Three scores, three meanings:

| Term | Range | Meaning |
|---|---|---|
| **detector score** | 0–1 | one layer's confidence that *something* is wrong |
| **threat score** | 0–1 | fused, cross-layer threat level (noisy-OR, see below) |
| **confidence** | 0–1 | threat strength × attribution dominance — a *heuristic score, not a calibrated probability* |

---

## Detector A — Protocol / rule engine (`detectors/protocol.py`)

Stateless per-frame rules over MAVLink transport behaviour. Sub-scores (the
detector score is their max); each casts a vote for the attack it implies:

| Rule | Threshold (config `protocol.*`) | Votes |
|---|---|---|
| Message flood | `msg_rate ≥ max_msg_rate_hz` (400) → 1.0; `> spike_factor×nominal` (84) → ramp | DOS |
| Sequence gaps | `max_seq_gap > max_seq_gap` (30) | DOS if rate high, else MAVLINK_ANOMALY |
| Rogue telemetry source | sysid ∉ expected & not a command source | MAVLINK_ANOMALY |
| Heartbeat stale | `heartbeat_age > heartbeat_timeout_s` (3); the never-seen sentinel is ignored for `startup_grace_s` (0 = off) | DOS |
| GPS dropout | `gps_age > gps_dropout_s` (2) | DOS |
| Command provenance | command from sysid ∉ `expected_gcs_sysids`; sensitive cmd / burst | COMMAND_INJECTION |
| Signing | `require_signing` and unsigned present | MAVLINK_ANOMALY |

## Detector B — Cyber-physical consistency (`detectors/physics.py`)

Cross-checks physically-coupled channels an attacker can't falsify all at once:

| Check | Threshold (config `physics.*`) | Votes |
|---|---|---|
| Position residual (reported track vs velocity-implied) | `> gps_pos_residual_m` (12); hard `≥ 30` | GPS_SPOOFING |
| GPS altitude vs baro altitude | `> alt_consistency_m` (8) | TELEMETRY_MANIPULATION |
| GPS-velocity speed vs VFR groundspeed | `> gps_speed_consistency_ms` (5) | TELEMETRY_MANIPULATION |
| Altitude rate plausibility | `> alt_jump_ms` (25) | TELEMETRY_MANIPULATION |
| Acceleration plausibility | `> max_accel_ms2` (20) | GPS_SPOOFING |
| Battery voltage rise / collapse | `> battery_rise_v` (0.4) / `battery_drop_rate_v_s` (2) | TELEMETRY_MANIPULATION |
| Heading (attitude) vs course-over-ground | `> yaw_course_deg` (25; configurable) | TELEMETRY_MANIPULATION |

A **hysteresis** (`hysteresis_ticks`) damps soft triggers until they persist,
suppressing single-tick GPS-noise spikes; a hard position residual fires
immediately.

## Detector C — ML anomaly (`detectors/anomaly.py`)

Benign-trained **ensemble** over the 11-feature `ML_FEATURES` vector, combined
as `max(isolation-forest z, mahalanobis z)`:

- **Isolation Forest** — subtle *in-distribution* multivariate anomalies.
- **Diagonal Mahalanobis / scaled-norm** — the L2 norm of the standardised (z-score) vector,
  i.e. Mahalanobis distance with a *diagonal* covariance (feature correlations ignored) and
  ordinary mean/std (not a robust estimator).
  Isolation Forest cannot extrapolate past its training range, so it is blind to
  out-of-range spikes (msg-rate floods, sequence gaps); the scaled-norm covers
  that blind spot.

The normalised score is a logistic of the combined signal (calibrated so benign
validation stays low). Attribution uses the most-deviating standardised feature
(`FEATURE_ATTACK_MAP`). Trigger at `anomaly.score_threshold` (0.62). If no model
is present the detector is a no-op (score 0) so the rest of the system still
runs. See `docs/ML_PIPELINE.md`.

## Detector D — Firmware integrity (`detectors/integrity.py`)

Re-hashes firmware components against a SHA-256 manifest (**unsigned** in the PoC; signing is future work)
(`FirmwareVerifier`, throttled to every `recheck_every` decisions). An INVALID
verdict → score 1.0, vote FIRMWARE_INTEGRITY, with the exact mismatched
component(s) as evidence. This is genuine crypto, not a mock.

---

## Fusion (`fusion/engine.py`) {#fusion}

A plain weighted sum would cap a lone detector below the 0.45 threshold (a
firmware failure at weight 0.20 would never alert). Instead:

```
w'_i   = w_i / max_j(w_j)            # max-normalised config weights
threat = 1 - Π_i (1 - score_i · w'_i)   # noisy-OR
```

This keeps the config's *relative* trust (physics highest, ML lowest), lets a
single strong high-trust detector raise a threat, boosts the score when
detectors corroborate, and keeps a lone weak ML signal below threshold. Note: a lone ML
score ≥ 0.956 (0.45 / 0.47) *does* cross the threat threshold on its own, and on the
baseline benchmark every false positive is of this kind (compare the ML-off ablation,
`artifacts/benchmarks_ablation_no_ml/summary.md`).

- **Attribution:** `attack_type = argmax` of the weight-scaled vote sum across
  detectors; strong runners-up become `secondary_indicators`.
- **Severity:** bands (`WATCH` 0.30 / `SUSPICIOUS` 0.45 / `HIGH` 0.62 /
  `CRITICAL` 0.80).
- **Alerting:** an assessment becomes an *alert* (`is_alert`) when severity ≥
  `alert_threshold_severity` and it is outside the per-attack `cooldown_s`
  window; `clear_ticks` consecutive normal decisions clear the active state.

Every alert carries the concatenated evidence from all firing detectors — there
are no unexplained black-box alerts.

## Per-vehicle calibration (PX4 SITL)
Thresholds above are the **Stage-1 simulator** values and are the reference condition. A
separate, generated PX4-SITL profile (`configs/px4_sitl/detector.yaml`) and a separate
PX4-benign anomaly model (`models/isoforest_px4.joblib`) exist for false-alarm reduction on
that stack only; methodology, held-out evaluation and the cost side (what the loosened
rules may no longer catch) are in `docs/CALIBRATION_PX4.md`. It is not attack detection.
