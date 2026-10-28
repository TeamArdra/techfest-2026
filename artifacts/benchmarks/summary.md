# AegisFlight — Benchmark Summary

_Generated from 23430 scored decisions across 6 seeds × 7 scenarios. Model used: True._

## Binary detection (attack vs benign)

| Metric | Value |
|---|---|
| Accuracy | 0.997 |
| Precision | 0.999 |
| Recall (TPR) | 0.990 |
| False-positive rate | 0.000 |
| F1 | 0.995 |
| TP / FP / TN / FN | 6535 / 4 / 16826 / 65 |

## Per-attack detection

| Attack | Precision | Recall | F1 | Support | Detection latency (s) |
|---|---|---|---|---|---|
| GPS_SPOOFING | 1.000 | 0.954 | 0.977 | 900 | 1.37 |
| MAVLINK_ANOMALY | 1.000 | 1.000 | 1.000 | 900 | 0.00 |
| COMMAND_INJECTION | 1.000 | 1.000 | 1.000 | 600 | 0.00 |
| TELEMETRY_MANIPULATION | 0.996 | 1.000 | 0.998 | 900 | 0.00 |
| DOS | 1.000 | 1.000 | 1.000 | 600 | 0.00 |
| FIRMWARE_INTEGRITY | 1.000 | 0.991 | 0.996 | 2700 | 0.80 |

## Latency, throughput & resources

| Metric | Value |
|---|---|
| Detection latency mean / p95 (s) | 0.361 / 1.400 |
| Compute latency mean / p95 (ms) | 17.746 / 23.634 |
| Throughput (messages/s) | 388.0 |
| Mean distance / flight (m) | 1145.8 |
| CPU mean / max (%) | 99.38 / 100.0 |
| RSS mean / max (MB) | 154.69 / 157.95 |

_All figures produced by `python scripts/benchmark.py`; see `results.json`._