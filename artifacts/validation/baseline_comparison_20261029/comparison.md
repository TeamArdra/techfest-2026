# AegisFlight vs simple-threshold baseline (SIM)

Same 23430 scored decisions for both systems (Stage-1 grid; `python scripts/baseline_comparison.py --out artifacts/validation/baseline_comparison_20261029`). Baseline rules: `configs/baseline_threshold.yaml` sha256 `c078b2fd11507b88…`.
AegisFlight counts equal `artifacts/benchmarks/results.json` (checked by the script).

| System | TP | FP | TN | FN | Recall | FPR | Precision |
|---|---|---|---|---|---|---|---|
| AegisFlight | 6535 | 4 | 16826 | 65 | 0.9902 | 0.0002 | 0.9994 |
| Threshold baseline | 996 | 1510 | 15320 | 5604 | 0.1509 | 0.0897 | 0.3974 |

## Per scenario
Decisions: attack rows TP/FN, benign row FP/TN. Sessions: sessions with at least one detected attack decision (benign row: at least one false-positive decision), Wilson 95 % on sessions.

| Scenario | Sessions | AegisFlight decisions | AegisFlight sessions | Baseline decisions | Baseline sessions |
|---|---|---|---|---|---|
| benign | 6 | FP 1 / TN 3449 | 1/6 [0.03, 0.56] | FP 279 / TN 3171 | 6/6 [0.61, 1.00] |
| gps_spoofing | 6 | 859 / 41 | 6/6 [0.61, 1.00] | 41 / 859 | 6/6 [0.61, 1.00] |
| mavlink_anomaly | 6 | 900 / 0 | 6/6 [0.61, 1.00] | 83 / 817 | 6/6 [0.61, 1.00] |
| command_injection | 6 | 600 / 0 | 6/6 [0.61, 1.00] | 29 / 571 | 6/6 [0.61, 1.00] |
| telemetry_manipulation | 6 | 900 / 0 | 6/6 [0.61, 1.00] | 41 / 859 | 6/6 [0.61, 1.00] |
| dos | 6 | 600 / 0 | 6/6 [0.61, 1.00] | 600 / 0 | 6/6 [0.61, 1.00] |
| firmware_integrity | 6 | 2676 / 24 | 6/6 [0.61, 1.00] | 202 / 2498 | 6/6 [0.61, 1.00] |

## Limitations

- `SIM` only; the attacks, the simulator, AegisFlight and this baseline are all team-written. Not an estimate of real-world performance.
- The baseline is deliberately minimal (single-value limits). It is not a model of ArduPilot or PX4 failsafes, which are configured per vehicle and were not run.
- Attack windows were designed against AegisFlight's checks; the baseline limits were fixed beforehand and not tuned to the attacks.
- 6 sessions per scenario: session intervals are wide. Decision-level counts are correlated within a session and carry no interval.
