# AegisFlight — Extended synthetic benchmark v2 (generated)

_116 sessions, model used: True, wall 222.7 s. Every session has its own trajectory seed, route, speed, altitude and noise scale; every implemented attack mode is exercised with randomised onset/duration. Production thresholds and model — nothing tuned on these results._

## Binary detection (decision level, benign + single-attack sessions)

| Scoring policy | Decisions | TP / FP / TN / FN | Accuracy | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|---|
| **Baseline benchmark** (artifacts/benchmarks, 5 s grace) | 23430 | 6535 / 4 / 16826 / 65 | 0.9971 | 0.9994 | 0.9902 | 0.0002 | 0.9947 |
| v2, 5 s grace (baseline policy) | 51073 | 9088 / 39 / 40813 / 1133 | 0.9771 | 0.9957 | 0.8891 | 0.0010 | 0.9394 |
| v2, **no grace** | 52900 | 9088 / 470 / 42209 / 1133 | 0.9697 | 0.9508 | 0.8891 | 0.0110 | 0.9190 |
| v2, 5 s grace, excl. firmware | 48773 | 7399 / 38 / 40213 / 1123 | 0.9762 | 0.9949 | 0.8682 | 0.0009 | 0.9273 |
| v2, no grace, excl. firmware | 50600 | 7399 / 469 / 41609 / 1123 | 0.9685 | 0.9404 | 0.8682 | 0.0111 | 0.9029 |
| v2, 5 s grace, excl. known-gap mode | 48870 | 9088 / 38 / 39102 / 642 | 0.9861 | 0.9958 | 0.9340 | 0.0010 | 0.9639 |

## Per attack mode (5 s grace)

| Mode | Sessions detected | Decision recall | Median / max time-to-detect (s) | Median post-attack alarm tail (s) | Attribution accuracy |
|---|---|---|---|---|---|
| `command_injection:arm_disarm_burst` | 4/4 | 98.82 % | 0.30 / 0.40 | 1.80 | 100.00 % |
| `command_injection:gcs_replay` ⚠ known gap | 0/4 | 0.00 % | — / — | 0.00 | — |
| `command_injection:mode_flip` | 4/4 | 99.57 % | 0.10 / 0.20 | 1.90 | 100.00 % |
| `command_injection:rogue_command` | 4/4 | 98.88 % | 0.20 / 0.40 | 1.60 | 100.00 % |
| `dos:blackout` | 4/4 | 99.58 % | 0.10 / 0.20 | 1.90 | 81.26 % |
| `dos:flood` | 4/4 | 100.00 % | 0.00 / 0.00 | 1.00 | 99.62 % |
| `dos:gnss_jamming` | 4/4 | 96.61 % | 0.80 / 0.80 | 0.00 | 100.00 % |
| `dos:latency` | 4/4 | 99.77 % | 0.00 / 0.00 | 1.20 | 3.61 % |
| `firmware_integrity:default` | 4/4 | 99.41 % | 0.50 / 0.80 | 0.00 | 100.00 % |
| `gps_spoofing:gradual_drift` | 4/4 | 94.64 % | 1.10 / 1.20 | 3.00 | 100.00 % |
| `gps_spoofing:replay_freeze` | 4/4 | 97.36 % | 0.50 / 0.80 | 3.00 | 100.00 % |
| `gps_spoofing:sudden_offset` | 4/4 | 12.63 % | 0.00 / 0.00 | 3.00 | 100.00 % |
| `mavlink_anomaly:packet_loss` | 4/4 | 98.98 % | 0.30 / 0.40 | 1.00 | 0.00 % |
| `mavlink_anomaly:rate_spike` | 4/4 | 100.00 % | 0.00 / 0.00 | 1.00 | 2.14 % |
| `mavlink_anomaly:rogue_sysid` | 4/4 | 100.00 % | 0.00 / 0.00 | 0.80 | 100.00 % |
| `mavlink_anomaly:seq_scramble` | 4/4 | 100.00 % | 0.00 / 0.00 | 0.00 | 98.29 % |
| `telemetry_manipulation:altitude_bias` | 4/4 | 100.00 % | 0.00 / 0.00 | 0.00 | 100.00 % |
| `telemetry_manipulation:battery_jump` | 4/4 | 98.55 % | 0.30 / 0.40 | 0.80 | 100.00 % |
| `telemetry_manipulation:frozen_attitude` | 4/4 | 69.08 % | 4.50 / 18.80 | 0.00 | 100.00 % |
| `telemetry_manipulation:speed_mismatch` | 4/4 | 100.00 % | 0.00 / 0.00 | 0.00 | 100.00 % |

## Benign sessions (false alarms)

| Condition | Sessions | Decisions | FP decisions | FPR | Sessions with ≥1 FP | FP classes |
|---|---|---|---|---|---|---|
| `benign` | 12 | 6900 | 4 | 0.06 % | 4 | `{"TELEMETRY_MANIPULATION": 4}` |
| `link_fifo_benign` | 6 | 3450 | 2114 | 61.28 % | 6 | `{"DOS": 2104, "TELEMETRY_MANIPULATION": 10}` |
| `link_reorder_benign` | 6 | 3450 | 3449 | 99.97 % | 6 | `{"MAVLINK_ANOMALY": 3328, "DOS": 121}` |

_Link stress conditions: `{"link_fifo_benign": {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": true}, "link_reorder_benign": {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": false}}`_

## Simultaneous attacks (multi-label ground truth)

| Combination | Sessions | In-window decisions | Binary recall | Primary ∈ truth | All active classes reported (both active) |
|---|---|---|---|---|---|
| `gps_spoofing+mavlink_anomaly` | 3 | 341 | 100.00 % | 100.00 % | 96.48 % |
| `gps_spoofing+command_injection` | 3 | 409 | 95.60 % | 84.60 % | 99.61 % |
| `dos+telemetry_manipulation` | 3 | 441 | 100.00 % | 98.87 % | 100.00 % |
| `telemetry_manipulation+firmware_integrity` | 3 | 1343 | 100.00 % | 100.00 % | 95.10 % |

_Prediction set for a decision = fused primary class ∪ `secondary_indicators`. The fusion emits one primary label; secondary indicators are ≥25 % of the primary vote._

Compute: mean 23.42 ms/decision (mean of session means), worst session p95 62.78 ms.
