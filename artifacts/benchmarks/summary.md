# AegisFlight — Benchmark Summary

_Generated from 23430 scored decisions across 6 seeds × 7 scenarios. Model used: False._

## Binary detection (attack vs benign)

| Metric | Value |
|---|---|
| Accuracy | 0.996 |
| Precision | 1.000 |
| Recall (TPR) | 0.986 |
| False-positive rate | 0.000 |
| F1 | 0.993 |
| TP / FP / TN / FN | 6504 / 0 / 16830 / 96 |

## Per-attack detection

| Attack | Precision | Recall | F1 | Support | Detection latency (s) |
|---|---|---|---|---|---|
| GPS_SPOOFING | 1.000 | 0.927 | 0.962 | 900 | 2.20 |
| MAVLINK_ANOMALY | 1.000 | 1.000 | 1.000 | 900 | 0.00 |
| COMMAND_INJECTION | 1.000 | 1.000 | 1.000 | 600 | 0.00 |
| TELEMETRY_MANIPULATION | 1.000 | 0.993 | 0.997 | 900 | 0.20 |
| DOS | 1.000 | 1.000 | 1.000 | 600 | 0.00 |
| FIRMWARE_INTEGRITY | 1.000 | 0.991 | 0.996 | 2700 | 0.80 |

## Latency, throughput & resources

| Metric | Value |
|---|---|
| Detection latency mean / p95 (s) | 0.533 / 2.250 |
| Compute latency mean / p95 (ms) | 0.103 / 0.322 |
| Throughput (messages/s) | 34101.2 |
| Mean distance / flight (m) | 1145.8 |
| CPU mean / max (%) | 99.65 / 99.9 |
| RSS mean / max (MB) | 62.9 / 64.56 |

_All figures produced by `python scripts/benchmark.py`; see `results.json`._