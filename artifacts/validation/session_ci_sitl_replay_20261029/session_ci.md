# Session-level uncertainty for SITL trials and REPLAY flights (generated; do not edit)

Regenerate: `python scripts/make_session_ci_sitl_replay.py --out artifacts/validation/session_ci_sitl_replay_20261029`. Inputs: existing generated artifacts only (hashes in `session_ci.json`). Wilson 95 %; the unit is the trial / flight, never the decision.

## SITL attack trials (link-level detection on PX4 SITL; one fresh boot per trial)

| Source table | Section | Trials | Detected | Wilson 95 % | Not detected |
|---|---|---|---|---|---|
| `artifacts/sitl/P2_delay_summary.md` | P2 DELAY summary - live SITL trials (generated; do not edit) | 10 | 9 | [0.60, 0.98] | p2l_n10_trial_009 |
| `artifacts/sitl/P2_drop_summary.md` | P2 DROP summary - live SITL trials (generated; do not edit) | 10 | 10 | [0.72, 1.00] | - |
| `artifacts/sitl/P2_gcs_impersonation_summary.md` | Variant: informed (tracks real seq) | 10 | 0 | [0.00, 0.28] | p2g_inf_trial_001, p2g_inf_trial_002, p2g_inf_trial_003, p2g_inf_trial_004, p2g_inf_trial_005, p2g_inf_trial_006, p2g_inf_trial_007, p2g_inf_trial_008, p2g_inf_trial_009, p2g_inf_trial_010 |
| `artifacts/sitl/P2_gcs_impersonation_summary.md` | Variant: naive (own counter) | 10 | 10 | [0.72, 1.00] | - |
| `artifacts/sitl/P2_gnss_summary.md` | P2 GNSS-degradation summary - live SITL trials (generated; do not edit) | 10 | 10 | [0.72, 1.00] | - |
| `artifacts/sitl/P2_injection_summary.md` | POST-FIX batch (relay mirrors hook-added frames to all clients) | 10 | 10 | [0.72, 1.00] | - |
| `artifacts/sitl/P2_replay_v2_summary.md` | P2 REPLAY-v2 summary - live SITL trials (generated; do not edit) | 10 | 10 | [0.72, 1.00] | - |
| `artifacts/sitl/closure/final_delay_summary.md` | P2 DELAY summary - live SITL trials (generated; do not edit) | 3 | 3 | [0.44, 1.00] | - |
| `artifacts/sitl/closure/final_drift_summary.md` | P2 summary - first live attack trials on PX4 SITL (generated; do not edit) | 3 | 3 | [0.44, 1.00] | - |
| `artifacts/sitl/closure/final_drop_summary.md` | P2 DROP summary - live SITL trials (generated; do not edit) | 3 | 3 | [0.44, 1.00] | - |
| `artifacts/sitl/closure/final_gnss_summary.md` | P2 GNSS-degradation summary - live SITL trials (generated; do not edit) | 3 | 3 | [0.44, 1.00] | - |
| `artifacts/sitl/closure/final_injection_summary.md` | POST-FIX batch (relay mirrors hook-added frames to all clients) | 3 | 3 | [0.44, 1.00] | - |
| `artifacts/sitl/closure/final_replay_summary.md` | P2 REPLAY-v2 summary - live SITL trials (generated; do not edit) | 3 | 3 | [0.44, 1.00] | - |

Limits: all trials use one airframe, world, host and script family, so trials are not independent of that shared setup and the intervals are optimistic about generalisation. The vehicle is disarmed on the ground in most batches. Detection is link-level only. Tables whose column is not yes/no and batches marked superseded are skipped. Both the n=10 batches (`P2_*`) and the later n=3 closure batches (`final_*`) are listed; they are different runs, not pooled.

## REPLAY of real flight logs (false-alarm / fault evidence, not attack detection)

| Dataset | Metric | Flights | k | Wilson 95 % |
|---|---|---|---|---|
| PX4 Flight Review public logs, mapping px4_telemetry (`artifacts/external/px4_review_v2/per_flight.csv`) | flights with any physics-detector trigger | 24 | 16 | [0.47, 0.82] |
| PX4 Flight Review public logs, mapping px4_telemetry (`artifacts/external/px4_review_v2/per_flight.csv`) | flights with physics trigger on > 1 % of airborne ticks | 24 | 12 | [0.31, 0.69] |
| PX4 Flight Review public logs, mapping px4_telemetry (`artifacts/external/px4_review_v2/per_flight.csv`) | flights with ML navigation probe alarm on > 1 % of airborne ticks | 24 | 15 | [0.43, 0.79] |
| ALFA held-out dates, per-vehicle calibrated protocol rate, ML off (`artifacts/external/alfa_calibrated/results.json`) | flight logs with any fused threat decision (all labelled and unlabelled decisions) | 11 | 11 | [0.74, 1.00] |
| ALFA held-out dates, per-vehicle calibrated protocol rate, ML off (`artifacts/external/alfa_calibrated/results.json`) | flight logs with fused threat on > 1 % of decisions (all labelled and unlabelled decisions) | 11 | 2 | [0.05, 0.48] |

ALFA rows keep only logs with >= 500 decisions (excluded: 10 of 21 logs). Limits: flights are not randomly drawn from a population (PX4: seeded sample of public logs; ALFA: one airframe family, held-out dates). ALFA files can include several recordings of one flight (the source artifact dedups decisions, not files). No attack-detection claim and no real-world rate follows from these rows.
