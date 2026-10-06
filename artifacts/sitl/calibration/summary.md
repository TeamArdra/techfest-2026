# PX4 SITL benign calibration - summary (generated; do not edit)

Environment: **SITL** (replayed tlog; PX4 `v1.18.0-rc1-27-gc239c63807`, Gazebo Harmonic, `gz_x500`). Attack: **NONE**. Claim class: **none** - false-alarm calibration only. This is NOT attack detection and says nothing about real vehicles. Regenerate: see `docs/CALIBRATION_PX4.md`.

## 1. A / B / B2 / C

A = Stage-1 default config + Stage-1 model | B = PX4 profile, ML off | B2 = PX4 profile + Stage-1 model (diagnostic) | C = PX4 profile + PX4-benign model. Every decision is benign, so every threat flag is a false alarm.

### Calibration set (benign_001..005) - the data the profile and PX4 model were fitted on: IN-SAMPLE

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

### Held-out set (benign_006..010) - never inspected before the profile was frozen; evaluated once

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

## 2. Profile overrides and derivation (`derivation.json`, calibration flights only)

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

## 3. PX4-benign ML model (`models/isoforest_px4.joblib`, gitignored)

- sha256 `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c`; sklearn 1.9.1; seed 100; 200 trees; trained on 2635 decision vectors (t >= 5.0 s) from 5 calibration flights; Stage-1 model hash unchanged: `3fe74cddf3689e16...`
- score_thr 12.9939, score_scale 4.1710 (leave-one-flight-out out-of-fold mean + 3 sd)

| flight | alarm rate, leave-one-flight-out | alarm rate, shipped model IN-SAMPLE (optimistic) |
|---|---|---|
| benign_001 | 0.40% | 0.40% |
| benign_002 | 2.73% | 0.00% |
| benign_003 | 0.00% | 0.00% |
| benign_004 | 0.00% | 0.00% |
| benign_005 | 0.00% | 0.00% |

## 4. Leave-one-flight-out check of the derivation rules (calibration set only; condition B)

| left-out flight | nominal | spike factor | other overrides | decisions | false alarms |
|---|---|---|---|---|---|
| benign_001 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 105.0} | 519 | 2 |
| benign_002 | 376.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 537 | 0 |
| benign_003 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 662 | 0 |
| benign_004 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 449 | 0 |
| benign_005 | 379.0 | 1.4 | {'battery_rise_v': 1.05, 'yaw_course_deg': 110.0} | 593 | 0 |

Pooled: 2 / 2760. within the calibration set; same route/host; not independent of the held-out question.

## 5. Feature shift, Stage-1 SIM benign vs PX4 SITL calibration flights (decisions with t >= 5 s)

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

## 5b. Analytic rate-scaling probe (SITL data, COUNTERFACTUAL - not a measurement)

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

## 6. EXPLORATORY SIM sanity check (cost side; environment SIM, NOT SITL, not the committed benchmark)

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

## 6b. Stage-1 regression under the default profile (SIM; `stage1_regression.json`)

| | TP | FP | TN | FN |
|---|---|---|---|---|
| committed `artifacts/benchmarks/summary.md` | 6535 | 4 | 16826 | 65 |
| after the detector change (scratch run) | 6535 | 4 | 16826 | 65 |

identical = **True**; command `aegis benchmark --out <scratch> --no-figures`; change under test: detectors/protocol.py startup_grace_s (default 0), detectors/physics.py yaw_course_deg (default 25.0).

## 7. Not measured

- Attack detection on PX4 SITL or any real stack (no attack data exists; P2). The profile only moves the benign false-alarm rate.
- Real vehicles, other airframes, other worlds, other hosts/real-time factors (all data: one `gz_x500`, one scripted route, one host).
- Whether unchanged physics thresholds (which sit >= M x benign max, often ~10x above SITL benign) are too loose for attack sensitivity.
- Independence of decisions: ~2.7k decisions per set come from 5 flights of one route and are autocorrelated; decision-level rates and Wilson intervals are optimistic.
