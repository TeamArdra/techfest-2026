# PX4 SITL benign calibration (Stage 2, P3)

A per-vehicle **calibration profile** for the existing detector architecture, fitted on benign PX4 SITL flights, plus the
measured trade-off. Environment tag: **SITL** (PX4 `v1.18.0-rc1-27-gc239c63807`, a release candidate; Gazebo Harmonic
`8.15.0`, `gz_x500`, headless), replayed from recorded tlogs. Claim class: **none** - this is **false-alarm calibration**.
It is **not** attack detection and says nothing about real vehicles. No attack data exists yet (P2).

All tables below between `GEN` markers are spliced in by `scripts/sitl/calib_report.py` from the JSON files in
`artifacts/sitl/calibration/` (full report: `artifacts/sitl/calibration/summary.md`). Do not edit them by hand.
Stage-1 (`configs/detector.yaml`, `models/isoforest.joblib`) is untouched and remains the **reference condition (A)**.

## 1. Why a profile
P1 (`docs/PX4_SITL_INTEGRATION.md` section 6, `artifacts/sitl/P1_summary.md`) found that the Stage-1 detectors flag every
benign PX4 SITL decision. Stage-1 thresholds were set on the simulator (`configs/detector.yaml` header), so this is a
sim-to-stack transfer failure, not an attack result. The profile is a separate, named set of overrides
(`configs/px4_sitl/detector.yaml`); nothing in Stage-1 is overwritten.

## 2. Data split (the anti-tuning rule)
| set | flights | use |
|---|---|---|
| calibration | `data/sitl/raw/benign_001..005.tlog` | everything: profile derivation, PX4 model training, threshold stability checks |
| held-out | `data/sitl/raw/benign_006..010.tlog` | **evaluated once**, after the profile and model were frozen (SHA-256 recorded in `heldout_lock.json` *before* the run); never inspected earlier |

`scripts/sitl/calib_evaluate.py --set heldout` writes the lock and refuses to run again (single use). The profile was **not**
changed after the held-out result; the held-out set is **not burned** (`held_out_burned=false` in
`evaluation_heldout.json`). Calibration-set numbers are **in-sample** by construction and are reported separately from the
held-out numbers; never merge them. Both sets are the same scripted route on the same host (see limitations).

## 3. Mechanism (additive)
- `load_config("configs/px4_sitl")` deep-merges `configs/px4_sitl/detector.yaml` over the built-in defaults.
  `simulation.yaml` / `attacks.yaml` are absent on purpose: the loader falls back to built-in defaults (verified: only the
  simulator-only `message_rates` key differs; replay does not use it). The YAML is **generated** by
  `scripts/sitl/calib_derive.py`; every override is commented with the `derivation.json` entry that justifies it.
- Two **new optional detector keys**, default-preserving (unit-tested in `tests/unit/test_px4_profile.py`; Stage-1 behaviour
  is unchanged when absent):
  - `protocol.startup_grace_s` (default `0`): during the first N seconds after the first decision, the extractor's
    "never seen yet" sentinel (999 s before the first heartbeat / GPS message) is not a liveness fault. A heartbeat that
    **was** seen and then went stale is judged as before.
  - `physics.yaw_course_deg` (default `25.0`, the former hard-coded constant).
- ML: `models/isoforest_px4.joblib` (gitignored) is a **separate** model with the **same** `ML_FEATURES` order. The Stage-1
  model is never overwritten (its SHA-256 is recorded in the training sidecar).
- Replay: `scripts/sitl/replay_benign.py --adapter live --config-dir configs/px4_sitl --model models/isoforest_px4.joblib`
  (new options; defaults remain Stage-1). The A/B/C evaluation uses `scripts/sitl/calib_common.py`, which drives the unchanged
  `IDSPipeline` through the live header-first parser (`frame_ticks`), 10 Hz ticks, decisions at 5 Hz.

## 4. Derivation policy (one explicit margin, no per-threshold nudging)
`M = 1.25`. "Steady-state" = decisions after the cold-start decisions where no heartbeat / GPS message has been seen yet.
Let `x*` be the largest steady-state value of a feature over all calibration flights.

- A Stage-1 threshold `theta0` is changed **only if** `theta0 < M * x*`; the new value is `M * x*` rounded up to a coarse
  grid. A threshold already `>= M * x*` is left exactly as Stage-1. Thresholds are **never lowered** (no tightening without
  attack data).
- Message rate: SITL time is not wall time (per-flight RTF = `1 + boot_clock_vs_recv_drift_ppm/1e6`, from the P1 stats).
  Rates are normalised to RTF = 1 (`r_norm = rate / RTF_flight`). `nominal_msg_rate_hz = median(r_norm)`;
  spike threshold `= M * max(r_norm)`, expressed as `msg_rate_spike_factor = ceil_0.05(spike / nominal)`;
  `max_msg_rate_hz = nominal * (400/28)` (Stage-1 hard/nominal ratio kept; it only shapes the score ramp - the rule already
  fires at the spike threshold). Assumption: Gazebo lockstep caps RTF at 1 (sim speed factor unchanged).
- `expected_sysids` = vehicle sysids observed (excluding the default GCS ids).
- `startup_grace_s = ceil_0.2(M * max first-observed heartbeat/GPS time)`.
- Not derived from data (left as Stage-1): fusion weights/thresholds, ML score threshold, `max_seq_gap`, hysteresis, all
  physics thresholds with headroom, GNSS-loss rule, signing policy.

<!-- GEN:overrides -->
### Profile overrides and derivation (`derivation.json`, calibration flights only)

Margin M = 1.25. Rule: a Stage-1 threshold is raised to ceil(M x largest steady-state benign value) only if it is below that; otherwise left as Stage-1.

| key | Stage-1 | profile | calibration benign max (x*) | M x x* | changed |
|---|---|---|---|---|---|
| protocol.expected_sysids | [1] | [3] | observed [3] | - | yes |
| protocol.nominal_msg_rate_hz | 28.0 | 378.0 | median of rate/RTF = 378.0 (raw median 338) | - | yes |
| protocol.msg_rate_spike_factor | 3.0 | 1.4 | max rate/RTF = 411.7 (raw max 369) | 514.7 msg/s -> spike threshold 529 msg/s | yes |
| protocol.max_msg_rate_hz | 400.0 | 5400.0 | Stage-1 hard limit would fire at RTF=1 benign max | ratio 400/28 kept | yes |
| protocol.startup_grace_s (new key) | 0 | 1.4 | first heartbeat/GPS seen at t <= 1.0 s | 1.4 | yes |
| physics.gps_pos_residual_m | 12.0 | 12.0 | 2.430 (pos_residual_m) | 3.038 | no |
| physics.gps_pos_residual_hard_m | 30.0 | 30.0 | 2.430 (pos_residual_m) | 3.038 | no |
| physics.gps_speed_consistency_ms | 5.0 | 5.0 | 0.709 (gps_vfr_speed_diff_ms) | 0.887 | no |
| physics.alt_consistency_m | 8.0 | 8.0 | 0.700 (gps_baro_alt_diff_m) | 0.875 | no |
| physics.alt_jump_ms | 25.0 | 25.0 | 3.917 (alt_rate_ms) | 4.897 | no |
| physics.max_accel_ms2 | 20.0 | 20.0 | 3.729 (accel_ms2) | 4.661 | no |
| physics.battery_rise_v | 0.4 | 1.05 | 0.810 (battery_v_rise) | 1.013 | yes |
| physics.battery_drop_rate_v_s | 2.0 | 2.0 | 0.028 (battery_v_rate) | 0.035 | no |
| physics.yaw_course_deg | 25.0 | 110.0 | 85.233 (yaw_course_diff_deg) | 106.541 | yes |

Per-flight RTF used for normalisation (`1 + boot_clock_vs_recv_drift_ppm/1e6`): benign_001 0.900, benign_002 0.867, benign_003 0.899, benign_004 0.898, benign_005 0.898

<!-- /GEN:overrides -->

### Stability of the rules (leave-one-flight-out, calibration set only)
Deriving from 4 flights and testing on the 5th. This is within-calibration and the flights are not independent; it checks
that the derived numbers are stable, it is not a held-out result.

<!-- GEN:lofo -->
### Leave-one-flight-out check of the derivation rules (calibration set only; condition B)

| left-out flight | nominal | spike factor | other overrides | decisions | false alarms |
|---|---|---|---|---|---|
| benign_001 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 105.0} | 519 | 2 |
| benign_002 | 376.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 537 | 0 |
| benign_003 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 662 | 0 |
| benign_004 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 449 | 0 |
| benign_005 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 593 | 0 |

Pooled: 2 / 2760. within the calibration set; same route/host; not independent of the held-out question.

<!-- /GEN:lofo -->

## 5. ML detector
The Stage-1 model (trained on simulator benign) **saturates** on PX4 rate features (condition B2 below). Two options were
run and compared:
1. **ML off** (condition B): `AnomalyDetector(model_path=None)` is a no-op. Decision cost drops to the rule engines only.
2. **PX4-benign model** (condition C): `scripts/train_px4_baseline.py` - same recipe as `scripts/train_models.py`
   (StandardScaler + IsolationForest + diagonal Mahalanobis, max of the two standardised signals; first 5 s of each flight
   excluded; seed 100, 200 trees). With n = 5 flights a validation *split* is not possible, so `score_thr` / `score_scale`
   come from **leave-one-flight-out** out-of-fold raw scores (mean + 3 sd), then the shipped model is fitted on all five
   flights. Sidecar with the exact file list, hashes, versions: `artifacts/sitl/calibration/isoforest_px4_training.json`.

**Optimism.** A model trained on the same five flights it is then scored on is optimistic; the in-sample column below is shown
only to make that visible. The leave-one-flight-out column is the honest within-calibration estimate; the held-out run is
the real test. Even so, the five flights are one route on one host.

<!-- GEN:ml -->
### PX4-benign ML model (`models/isoforest_px4.joblib`, gitignored)

- sha256 `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c`; sklearn 1.9.1; seed 100; 200 trees; trained on 2635 decision vectors (t >= 5.0 s) from 5 calibration flights; Stage-1 model hash unchanged: `3fe74cddf3689e16...`
- score_thr 12.9939, score_scale 4.1710 (leave-one-flight-out out-of-fold mean + 3 sd)

| flight | alarm rate, leave-one-flight-out | alarm rate, shipped model IN-SAMPLE (optimistic) |
|---|---|---|
| benign_001 | 0.40% | 0.40% |
| benign_002 | 2.73% | 0.00% |
| benign_003 | 0.00% | 0.00% |
| benign_004 | 0.00% | 0.00% |
| benign_005 | 0.00% | 0.00% |

<!-- /GEN:ml -->

## 6. Results: A / B / B2 / C
A = Stage-1 default config + Stage-1 model. B = PX4 profile, ML off. B2 = PX4 profile + Stage-1 model (diagnostic: what a
profile user gets if they keep the simulator model). C = PX4 profile + PX4-benign model. All decisions are benign.
Source: `artifacts/sitl/calibration/evaluation_calib.json`, `evaluation_heldout.json`. Latency is the pipeline's own
`latency_ms` per decision measured on a shared Windows dev host - load-dependent, not a benchmark figure; it includes the
sklearn call when ML is on, which is why B is far cheaper than A/B2/C.

<!-- GEN:ab_calib -->
#### Calibration set (benign_001..005) - the data the profile and PX4 model were fitted on: IN-SAMPLE

Flights: benign_001, benign_002, benign_003, benign_004, benign_005 | held_out_burned=False

| cond | description | decisions | false-alarm decisions | FA rate | FA per flight | protocol trig | physics trig | ML trig | latency mean / p95 ms |
|---|---|---|---|---|---|---|---|---|---|
| A | Stage-1 default config + Stage-1 model | 2760 | 2760 | 100.00% | [519, 537, 662, 449, 593] | 100.00% | 4.89% | 96.56% | 13.60 / 18.04 |
| B | PX4 profile, ML off | 2760 | 2 | 0.07% | [2, 0, 0, 0, 0] | 0.07% | 0.00% | 0.00% | 0.26 / 0.44 |
| B2 | PX4 profile + Stage-1 model (diagnostic) | 2760 | 2665 | 96.56% | [500, 518, 643, 430, 574] | 0.07% | 0.00% | 96.56% | 13.19 / 17.24 |
| C | PX4 profile + PX4-benign model | 2760 | 2 | 0.07% | [2, 0, 0, 0, 0] | 0.07% | 0.00% | 0.07% | 13.17 / 17.43 |

Evidence strings present in false-alarm decisions (numbers masked as `#`), top 5 per condition:

- **A**: `message-rate spike: # msg/s > #×nominal (#)` x2745; `rogue telemetry source(s): sys#/comp#` x2658; `ML anomaly score # ≥ # (driver: msg_rate_hz, z=+#)` x2655; `heading/course mismatch #° (attitude inconsistent with track)` x133; `# command(s) from unexpected source sys#/comp#` x102
- **B**: `sequence gap # > #` x2
- **B2**: `ML anomaly score # ≥ # (driver: msg_rate_hz, z=+#)` x2655; `ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#)` x10; `sequence gap # > #` x2
- **C**: `sequence gap # > #` x2; `ML anomaly score # ≥ # (driver: max_seq_gap, z=+#)` x2

Detector combinations over their trigger on false-alarm decisions:

- **A**: {'protocol_rule': 95, 'ml_anomaly+protocol_rule': 2530, 'ml_anomaly+physics_consistency+protocol_rule': 135}
- **B**: {'protocol_rule': 2}
- **B2**: {'ml_anomaly': 2663, 'ml_anomaly+protocol_rule': 2}
- **C**: {'ml_anomaly+protocol_rule': 2}

Decisions touched by the known frozen-extractor gaps (condition-independent):

| gap | decisions | note |
|---|---|---|
| max_seq_gap > 30 (reorder read as 253-frame gap) | 2 | remains a false alarm under every PX4 condition |
| flight mode decoded `UNKNOWN` | 2760 of 2760 | no detector reads `flight_mode`; dashboard/telemetry only |
| cold start (no heartbeat/GPS seen yet, age sentinel 999 s) | 17 | stale-heartbeat evidence under A; absorbed by `startup_grace_s` in the profile |

<!-- /GEN:ab_calib -->

<!-- GEN:ab_heldout -->
#### Held-out set (benign_006..010) - never inspected before the profile was frozen; evaluated once

Flights: benign_006, benign_007, benign_008, benign_009, benign_010 | held_out_burned=False

| cond | description | decisions | false-alarm decisions | FA rate | FA per flight | protocol trig | physics trig | ML trig | latency mean / p95 ms |
|---|---|---|---|---|---|---|---|---|---|
| A | Stage-1 default config + Stage-1 model | 2805 | 2805 | 100.00% | [483, 736, 550, 631, 405] | 100.00% | 4.92% | 96.61% | 13.51 / 18.72 |
| B | PX4 profile, ML off | 2805 | 1 | 0.04% | [0, 0, 0, 0, 1] | 0.04% | 0.00% | 0.00% | 0.27 / 0.47 |
| B2 | PX4 profile + Stage-1 model (diagnostic) | 2805 | 2710 | 96.61% | [464, 717, 531, 612, 386] | 0.04% | 0.00% | 96.61% | 13.54 / 18.84 |
| C | PX4 profile + PX4-benign model | 2805 | 1 | 0.04% | [0, 0, 0, 0, 1] | 0.04% | 0.00% | 0.04% | 14.50 / 20.12 |

Evidence strings present in false-alarm decisions (numbers masked as `#`), top 5 per condition:

- **A**: `message-rate spike: # msg/s > #×nominal (#)` x2797; `ML anomaly score # ≥ # (driver: msg_rate_hz, z=+#)` x2710; `rogue telemetry source(s): sys#/comp#` x2706; `heading/course mismatch #° (attitude inconsistent with track)` x134; `# command(s) from unexpected source sys#/comp#` x99
- **B**: `sequence gap # > #` x1
- **B2**: `ML anomaly score # ≥ # (driver: msg_rate_hz, z=+#)` x2710; `sequence gap # > #` x1
- **C**: `sequence gap # > #` x1; `ML anomaly score # ≥ # (driver: max_seq_gap, z=+#)` x1

Detector combinations over their trigger on false-alarm decisions:

- **A**: {'protocol_rule': 95, 'ml_anomaly+protocol_rule': 2572, 'ml_anomaly+physics_consistency+protocol_rule': 138}
- **B**: {'protocol_rule': 1}
- **B2**: {'ml_anomaly': 2709, 'ml_anomaly+protocol_rule': 1}
- **C**: {'ml_anomaly+protocol_rule': 1}

Decisions touched by the known frozen-extractor gaps (condition-independent):

| gap | decisions | note |
|---|---|---|
| max_seq_gap > 30 (reorder read as 253-frame gap) | 1 | remains a false alarm under every PX4 condition |
| flight mode decoded `UNKNOWN` | 2805 of 2805 | no detector reads `flight_mode`; dashboard/telemetry only |
| cold start (no heartbeat/GPS seen yet, age sentinel 999 s) | 14 | stale-heartbeat evidence under A; absorbed by `startup_grace_s` in the profile |

Frozen inputs recorded in `heldout_lock.json` before the run (SHA-256):

- `profile_yaml_sha256`: `4f18f3f0220cecc71229c156ec2f23fc9b23eadb59357f2cde1e8baf6ec04660`
- `px4_model_sha256`: `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c`
- `stage1_model_sha256`: `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4`
- `stage1_detector_yaml_sha256`: `bc9a4d2618e5e5a0cdc251a35f22ad1cc928343894aa9a66c27ad28196f3cbfa`
- `derivation_json_sha256`: `acb392361f51a55bbede1608e2b9f866f118e93e50d01a8601a07336ac303fdf`

<!-- /GEN:ab_heldout -->

How to read this (no attack data is involved): the profile removes the false alarms that the evidence strings attribute to the
sysid / command-source / rate-baseline / heartbeat-cold-start / battery-recovery / heading-vs-course rules. The held-out set
shows that this carries over to five unseen flights of the same route. The **remaining** false alarms come from one
frozen-extractor defect (next section), identical under B and C.

## 7. Residual false alarms and frozen-extractor gaps (not fixed here; need approval)
These live in `features/extractor.py` (frozen: `ML_FEATURES` and the extractor are part of the contract), so they are
**quantified, not fixed**:

1. **Sequence reorder read as a 253-frame gap.** A backward sequence step is computed as `(seq - prev) % 256`, i.e. 253, so
   `max_seq_gap` and `loss_ratio` jump and the protocol sequence-gap rule (and the ML `max_seq_gap` feature) fire. In the
   pipeline path the per-decision `clear_window_counts()` resets `_seq_gap` every decision, so one reorder costs **one**
   decision here - the P1 note "sticky" holds only within one decision window. Counts are in the "decisions touched" table
   above (calibration and held-out). They are the **only** false alarms left under B and C.
2. **PX4 custom_mode reads as `UNKNOWN`** (ArduCopter `MODE_NAMES`). Every decision is affected, but **no detector reads
   `flight_mode`** (it only feeds the telemetry dict / dashboard), so it costs **zero** false alarms; it is an explainability
   defect.
3. **Cold start** (no heartbeat/GPS yet): handled in the profile by `startup_grace_s`.

Proposals (each needs your approval, a migration plan, retrain + re-benchmark, regression TP/FP/TN/FN = 6535/4/16826/65):
- Extractor: treat a large backward step as reorder, not loss (signed gap; ignore `gap > 128`). Expected to remove the residual
  false alarms; touches the Stage-1 reorder-stress scenario and the ML feature distribution, so it needs the full regression.
- Extractor/codec: stack-aware mode decode keyed on `HEARTBEAT.autopilot` (PX4 = 12); `sources.mavlink_live.decode_px4_mode`
  already implements the PX4 semantics. No detection effect.
- Extractor: add a **raw-sensor** cross-check (`GPS_RAW_INT` vs estimator output) as a `FeatureFrame` field (not in
  `ML_FEATURES`). On PX4 `GLOBAL_POSITION_INT` and `VFR_HUD` are both estimator outputs, so three physics cross-checks lose
  independence; the shift table shows their benign values are near zero (they are nearly the same quantity).

## 8. Feature shift: Stage-1 SIM benign vs PX4 SITL
SIM reference: `aegisflight.external.realdata.sim_reference_ticks`, 12 flights with the same sampler as
`scripts/external_validation.py::sim_reference`, through the unchanged `FeatureExtractor`; SITL side: calibration flights
only. `artifacts/sitl/calibration/feature_shift.json`.

<!-- GEN:shift -->
### Feature shift, Stage-1 SIM benign vs PX4 SITL calibration flights (decisions with t >= 5 s)

SIM: 12 flights / 6900 decisions (aegisflight.external.realdata.sim_reference_ticks, seeds 9001.., rng 9000 as scripts/external_validation.py::sim_reference). SITL: 2635 decisions.

| feature | SIM p50 / p95 / max | SITL p50 / p95 / max | KS |
|---|---|---|---|
| msg_rate_hz | 32.000 / 34.000 / 34.000 | 338.000 / 344.000 / 369.000 | 1.000 |
| interarrival_jitter_ms | 46.746 / 46.746 / 47.140 | 3.715 / 4.912 / 36.017 | 1.000 |
| max_seq_gap | 0.000 / 0.000 / 0.000 | 0.000 / 0.000 / 253.000 | 0.001 |
| pos_residual_m | 1.136 / 2.479 / 4.487 | 0.017 / 0.210 / 2.430 | 0.953 |
| gps_vfr_speed_diff_ms | 0.153 / 0.442 / 0.970 | 0.009 / 0.297 / 0.709 | 0.614 |
| gps_baro_alt_diff_m | 1.087 / 3.351 / 7.125 | 0.003 / 0.277 / 0.700 | 0.814 |
| alt_rate_ms | -0.202 / 10.825 / 28.363 | 0.000 / 1.812 / 3.917 | 0.396 |
| accel_ms2 | 1.599 / 7.490 / 11.071 | 0.000 / 2.059 / 3.729 | 0.679 |
| yaw_course_diff_deg | 0.260 / 2.085 / 16.109 | 0.000 / 25.732 / 85.233 | 0.247 |
| cmd_rate_hz | 0.000 / 0.000 / 0.000 | 0.000 / 0.000 / 3.000 | 0.039 |
| loss_ratio | 0.000 / 0.000 / 0.000 | 0.000 / 0.000 / 1.000 | 0.001 |

<!-- /GEN:shift -->

## 9. Host-load dependence (analytic counterfactual, not a measurement)
<!-- GEN:rtf -->
### Analytic rate-scaling probe (SITL data, COUNTERFACTUAL - not a measurement)

Calibration decisions (2635), `msg_rate_hz` x ratio and `interarrival_jitter_ms` / ratio, ratio = target / per-flight RTF. Targets <= 1.0 = the same flights as if the host ran at that real-time factor; targets > 1.0 = faster-than-real-time OR a proportional message-rate flood. Rate-rule spike threshold = 529 msg/s. linear rescaling of two features; not a measurement at another RTF.

| rate scale target | median msg/s | rate rule fires (share of decisions) | PX4 ML (model C) alarm share |
|---|---|---|---|
| 0.60 | 227 | 0.00% | 0.08% |
| 0.70 | 265 | 0.00% | 0.08% |
| 0.80 | 302 | 0.00% | 0.08% |
| 0.90 | 340 | 0.00% | 0.08% |
| 1.00 | 378 | 0.00% | 0.08% |
| 1.25 | 472 | 0.00% | 0.08% |
| 1.50 | 567 | 98.25% | 0.08% |
| 2.00 | 756 | 99.17% | 0.08% |
| 3.00 | 1134 | 99.58% | 42.28% |

<!-- /GEN:rtf -->

The probe shows that the PX4-benign model's rate sensitivity is **low**: it stays quiet across the whole benign RTF range and
only reacts at the largest scale, while the rate rule reacts well before. A plausible cause (not verified by ablation) is that
the leave-one-flight-out out-of-fold scores include the RTF-outlier flight (`benign_002`, the highest out-of-fold alarm rate in
the ML table), which widens the calibrated score threshold. The rate rule, not the ML model, is what reacts to a rate change. The ML model's contribution to attack detection on this stack is **not measured**.

## 10. Cost side: what the loosened rules may no longer catch
**Not measured on SITL** (no attack data; P2). Reasoning per changed value, plus an exploratory SIM check below.

| changed value | what it can no longer catch (risk) |
|---|---|
| `expected_sysids [3]` | a forged frame carrying sysid 3 / comp 1 passes both the rogue-source and command-source checks (the same property Stage-1 has for sysid 1); a SIM-style sysid-1 source would now be "rogue" |
| spike threshold ~ 1.4x nominal | message-rate floods smaller than the spike threshold (about 1.4x the RTF=1 benign rate) are invisible to the rate rule; the Stage-1 `dos`/`mavlink_anomaly:rate_spike` multipliers (5x-12x) are far above it |
| `max_msg_rate_hz` | none for detection (the rule already fires at the spike threshold); only the score ramp changes |
| `startup_grace_s` | a link that is dead from t = 0 is flagged about the grace length later; a heartbeat that stopped after being seen is unaffected |
| `battery_rise_v` | a spurious battery-voltage rise below the new value (Stage-1: 0.4 V/s) is invisible. The benign rise is the post-landing voltage recovery at `rel_alt` ~ 0; gating the rule on airborne state would be tighter but needs a code change |
| `yaw_course_deg` | the heading-vs-course rule is **effectively disabled** for this multirotor (benign max is far above the Stage-1 25 degrees). Frozen-attitude style telemetry manipulation is not caught by it; no other rule covers it |

Unchanged but potentially **too loose**: the SITL benign maxima for position residual, GPS/VFR speed, GPS/baro altitude, altitude
rate and acceleration (calibration table above) sit roughly an order of magnitude below the Stage-1 thresholds (e.g. SITL
GPS/baro max vs the Stage-1 8 m). Tightening them would raise sensitivity but cannot be justified without attack data, so it
was **not done**; propose revisiting after P2 using fresh attack sessions (not the held-out benign set).

<!-- GEN:sim -->
### EXPLORATORY SIM sanity check (cost side; environment SIM, NOT SITL, not the committed benchmark)

Seeds [42, 43], Stage-1 simulator model, Stage-1 default attack parameters. `profile_sysid1` = PX4 profile with expected_sysids forced to the SIM vehicle id [1], to isolate the threshold changes; `ML off` columns remove the Stage-1 simulator model so the RULE changes are visible. Cells are in-window decisions flagged / in-window decisions (all seeds pooled).

| attack:mode | default (ML on) | profile_sysid1 (ML on) | default, ML off | profile_sysid1, ML off |
|---|---|---|---|---|
| gps_spoofing:gradual_drift | 286/300 (95%) | 286/300 (95%) | 276/300 (92%) | 276/300 (92%) |
| gps_spoofing:sudden_offset | 30/300 (10%) | 30/300 (10%) | 29/300 (10%) | 29/300 (10%) |
| gps_spoofing:replay_freeze | 294/300 (98%) | 294/300 (98%) | 287/300 (96%) | 287/300 (96%) |
| mavlink_anomaly:rogue_sysid | 300/300 (100%) | 300/300 (100%) | 300/300 (100%) | 300/300 (100%) |
| mavlink_anomaly:rate_spike | 300/300 (100%) | 300/300 (100%) | 300/300 (100%) | 300/300 (100%) |
| mavlink_anomaly:seq_scramble | 299/300 (100%) | 299/300 (100%) | 295/300 (98%) | 295/300 (98%) |
| mavlink_anomaly:packet_loss | 298/300 (99%) | 298/300 (99%) | 32/300 (11%) | 32/300 (11%) |
| command_injection:rogue_command | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) |
| command_injection:mode_flip | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) |
| command_injection:arm_disarm_burst | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) |
| command_injection:gcs_replay | 0/200 (0%) | 0/200 (0%) | 0/200 (0%) | 0/200 (0%) |
| telemetry_manipulation:altitude_bias | 300/300 (100%) | 300/300 (100%) | 298/300 (99%) | 298/300 (99%) |
| telemetry_manipulation:speed_mismatch | 300/300 (100%) | 300/300 (100%) | 298/300 (99%) | 298/300 (99%) |
| telemetry_manipulation:battery_jump | 298/300 (99%) | 298/300 (99%) | 298/300 (99%) | 298/300 (99%) |
| telemetry_manipulation:frozen_attitude | 186/300 (62%) | 186/300 (62%) | 178/300 (59%) | 153/300 (51%) |
| dos:flood | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) | 200/200 (100%) |
| dos:blackout | 198/200 (99%) | 198/200 (99%) | 178/200 (89%) | 178/200 (89%) |
| dos:latency | 200/200 (100%) | 200/200 (100%) | 196/200 (98%) | 196/200 (98%) |
| dos:gnss_jamming | 192/200 (96%) | 192/200 (96%) | 192/200 (96%) | 192/200 (96%) |
| firmware_integrity:default | 892/900 (99%) | 892/900 (99%) | 892/900 (99%) | 892/900 (99%) |

Benign SIM sessions, scored decisions flagged: default 0/1150; profile_sysid1 0/1150; profile_raw 1150/1150; default_noml 0/1150; profile_sysid1_noml 0/1150

<!-- /GEN:sim -->

Reading the SIM table: with the same sessions, the only attack mode whose in-window detection differs between the default and the
profile thresholds is `telemetry_manipulation:frozen_attitude` with ML off (the heading-vs-course rule); with the Stage-1 ML on,
no row differs. The SIM attack strengths sit above both the old and the new rate thresholds, so this run **cannot** show the
cost of the rate loosening against weaker SITL floods - that remains unmeasured.

The SIM sanity run is **SIM**, exploratory, a handful of seeds, run with the profile's thresholds on the *simulator* (whose
vehicle id and message rates differ from PX4): it bounds the cost of the loosened values, it does not replace the committed
benchmark (`artifacts/benchmarks/`), and nothing was written there. Stage-1 regression under the default profile
(`artifacts/sitl/calibration/stage1_regression.json`):

<!-- GEN:regress -->
### Stage-1 regression under the default profile (SIM; `stage1_regression.json`)

| | TP | FP | TN | FN |
|---|---|---|---|---|
| committed `artifacts/benchmarks/summary.md` | 6535 | 4 | 16826 | 65 |
| after the detector change (scratch run) | 6535 | 4 | 16826 | 65 |

identical = **True**; command `aegis benchmark --out <scratch> --no-figures`; change under test: detectors/protocol.py startup_grace_s (default 0), detectors/physics.py yaw_course_deg (default 25.0).

<!-- /GEN:regress -->

## 11. Limitations (read before quoting any number)
- **n = 5 + 5 flights of one scripted route** on one airframe (`gz_x500`), one world, one host. Decisions within a flight are
  autocorrelated: ~2.7k decisions per set are not 2.7k independent samples; the Wilson intervals in the JSON are decision-level
  and optimistic. Rates quoted are decision rates, not flight-level rates.
- **Calibration-set results are in-sample.** The PX4 model scored on its own training flights is optimistic (section 5).
- **Host-load / RTF dependence.** SITL runs at RTF 0.87-0.90 here; rate features scale with it. The profile normalises to RTF = 1
  and assumes RTF <= 1; latency numbers vary with host load.
- **This is false-alarm reduction on SITL benign data only.** It says nothing about real vehicles, other airframes/stacks, radio
  links, or **attack detection**. Real-attack detection on PX4 is not claimed.
- The evidence is regenerable only with the local raw tlogs (git-ignored; SHA-256 in `derivation.json` and the manifests).
- The unfixed extractor defects (section 7) keep a small residual false-alarm rate until the proposals are approved.

## 13. Review against live P2/P4 attack-trial evidence (Stage-2, 2026-10; no change made)
Section 10 above flagged, *before any attack data existed*, which loosened thresholds carry a cost and
against which attack a tightened value would need to be justified. P2 and P4 (`docs/STAGE2_PROGRESS.md`,
`docs/VALIDATION_EVIDENCE.md`) now provide live SITL attack-trial data: GPS drift, rogue command injection,
downlink drop, downlink delay, uplink replay, naive and informed expected-GCS impersonation, and MAVLink-2
signing (n=10 each unless noted). This section checks that data against section 10's own list and
concludes **no calibration change is justified** — reasoned per item, not asserted.

- **None of the live P2/P4 attacks exercise the specific attack surfaces section 10 flagged.** `expected_sysids`
  (risk: a forgery claiming the *vehicle's own* sysid 3) was never tested — every P2 identity attack used a
  rogue sysid (66) or an expected-GCS sysid (255), neither of which touches this threshold's risk.
  `msg_rate_spike_factor` (~1.4x nominal; risk: a flood *below* that spike) was never tested — DELAY produced
  a spike at 1.9x-5.1x nominal (above the threshold, consistent with it, not evidence either way) and no P2
  attack floods below it. `battery_rise_v` and `yaw_course_deg` (risk: a battery/attitude manipulation) have
  **no corresponding live PX4 attack at all** in P2 — Stage-1's battery/attitude attacks were never ported to
  live SITL. Tightening any of these now, with no attack data that actually probes them, would be exactly
  the "tuning against results we do not have" the task rules against — so none are touched.
- **The one mechanism the new live data DOES exercise heavily, `max_seq_gap` (unchanged: 30, both Stage-1 and
  the PX4 profile), is a validated detector, not a residual false-alarm source to tighten.** It is the
  primary mechanism behind REPLAY-v2 (10/10), naive impersonation (10/10), and contributes to the signing
  rule's own staging — three independent, live-confirmed detections. The already-known frozen-extractor
  "253-frame reorder" false-alarm gap (section 7) did **not** reappear as a *new* problem in any P2/P4 batch;
  where it was seen (e.g. `test_mavlink_live_concurrency.py`, `p2d`/`p2l` pilots), it is the same
  pre-documented defect, not a new finding. Changing this threshold now would risk the exact attacks it is
  currently catching, for no offsetting evidence of being too loose. **Left exactly as-is.**
- **Live pre-onset false-alarm rates across every P2/P4 n=10 batch remain consistent with, not worse than,
  the existing calibration's own measured rate** (0.04-0.07% in section 6's calibration/held-out tables):
  GPS-drift 0/1404, post-fix injection 0 (clean), drop 0/1972, delay 1/1854, replay-v2 0/160, impersonation
  naive 1/2133 and informed 1/2139 (both single, isolated decisions, not investigated further at n=10), and
  P4 signing's pre-onset count is dominated by the one-time bootstrap transient (`P4_signing_summary.md`
  Limitations), not an ongoing rate. None of this argues the calibration is too loose OR too tight; it
  **reconfirms** the existing false-alarm characterization on a different (adversarial-session) sample.
- **`require_signing` must NOT be promoted into the committed `configs/px4_sitl/detector.yaml` profile.**
  This is a new, concrete, data-backed reason, not inertia: every committed calibration/held-out tlog
  (`benign_001..010`) and every existing recorded flight this profile is evaluated against is **unsigned by
  construction** (recorded before signing existed in this project). Setting `require_signing: true` as the
  profile default would make the pre-existing `signed_ratio < 1.0` rule fire on effectively 100% of
  decisions replayed from that data — a false-alarm regression, not an improvement, for every current and
  future use of this profile against unsigned telemetry. Signing enforcement stays exactly what P4 built it
  as: an explicit, per-deployment, opt-in policy (`cfg.detector["protocol"]["require_signing"] = True`, as
  the P4 trial driver sets it), never a default.

**Conclusion:** no threshold in `configs/px4_sitl/detector.yaml` is changed by this review. The held-out
numbers in section 6, the overrides in section 4, and the cost table in section 10 all stand unmodified.
This section exists so the question "was the live attack data checked against the calibration" has a
documented, reasoned answer, per the task that requested it, rather than silence.

## 14. Reproduce (calibration/held-out data must exist locally)
```bash
.venv/Scripts/python.exe scripts/sitl/calib_derive.py          # configs/px4_sitl/detector.yaml + derivation.json
.venv/Scripts/python.exe scripts/train_px4_baseline.py         # models/isoforest_px4.joblib + sidecar
.venv/Scripts/python.exe scripts/sitl/calib_evaluate.py --set calib
.venv/Scripts/python.exe scripts/sitl/calib_evaluate.py --set heldout   # single use (writes heldout_lock.json)
.venv/Scripts/python.exe scripts/sitl/calib_lofo.py
.venv/Scripts/python.exe scripts/sitl/calib_shift.py
.venv/Scripts/python.exe scripts/sitl/calib_rtf_probe.py
.venv/Scripts/python.exe scripts/sitl/calib_sim_sanity.py      # exploratory SIM
.venv/Scripts/python.exe scripts/sitl/calib_report.py          # summary.md + splices this document
```
Provenance: `derivation.json` (git commit, Python, numpy), `isoforest_px4_training.json` (model SHA-256, sklearn), and
`evaluation_*.json` (`frozen_inputs` hashes).
