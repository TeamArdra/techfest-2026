# P2 summary - first live attack trials on PX4 SITL (generated; do not edit)

Environment: **SITL**. Attack: downlink `GLOBAL_POSITION_INT` gradual drift (`docs/ATTACK_PROXY.md` Sec3). Claim class: **link-level detection (SITL) only** -- PX4 never receives a modified frame; this is not GPS spoofing of the vehicle and says nothing about signing.
Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p2_summary.py artifacts/sitl/p2_trial_001.manifest.json artifacts/sitl/p2_trial_003.manifest.json artifacts/sitl/p2_trial_004.manifest.json artifacts/sitl/p2_trial_005.manifest.json artifacts/sitl/p2_trial_006.manifest.json artifacts/sitl/p2_trial_007.manifest.json artifacts/sitl/p2_trial_008.manifest.json artifacts/sitl/p2_trial_009.manifest.json artifacts/sitl/p2_trial_010.manifest.json artifacts/sitl/p2_trial_011.manifest.json`.

**10/10 trials**: a `GPS_SPOOFING` decision fired at or after the attack window closed, with **0 false alarms** in any trial's pre-onset (benign) portion (1404 pre-onset decisions pooled).
Time-to-detection from attack end: n=10, mean=0.62s, median=0.56s, min=0.24s, max=1.11s

| trial | onset s | dur s | rate m/s | bearing | expected m | actual m | frames mod | pre-onset FA | detected | ttd-from-end s | other threat types |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2_trial_001 | 44.5 | 15.39 | 3.502 | 308.8 | 53.9 | 53.86 | 750 | 0 | yes | 0.9 | - |
| p2_trial_003 | 35.23 | 23.93 | 7.981 | 140.2 | 190.98 | 190.97 | 1198 | 0 | yes | 0.24 | - |
| p2_trial_004 | 27.51 | 21.42 | 5.957 | 237.9 | 127.59 | 127.48 | 1075 | 0 | yes | 0.67 | - |
| p2_trial_005 | 20.04 | 18.25 | 3.108 | 137.0 | 56.73 | 56.68 | 890 | 0 | yes | 1.11 | - |
| p2_trial_006 | 23.29 | 38.26 | 4.298 | 229.9 | 164.47 | 164.37 | 1884 | 0 | yes | 0.45 | - |
| p2_trial_007 | 33.48 | 30.02 | 4.383 | 85.5 | 131.57 | 131.56 | 1496 | 0 | yes | 0.5 | - |
| p2_trial_008 | 22.85 | 35.4 | 7.143 | 70.8 | 252.87 | 252.85 | 1745 | 0 | yes | 0.55 | - |
| p2_trial_009 | 26.69 | 35.33 | 3.739 | 354.2 | 132.1 | 132.05 | 1740 | 0 | yes | 0.38 | - |
| p2_trial_010 | 22.26 | 23.17 | 2.399 | 101.3 | 55.59 | 55.57 | 1141 | 0 | yes | 0.57 | ['DOS'] |
| p2_trial_011 | 23.8 | 28.4 | 9.341 | 353.3 | 265.25 | 265.08 | 1398 | 0 | yes | 0.81 | - |

## Limitations
- n reflects however many trials have completed when this was last regenerated; a small n (as called for by the design, >=10) is not a statistically powerful sample -- report counts, not a rate with confidence bounds.
- All trials share one scripted benign-flight-free attack window on one airframe/world/host; this is not independent of host load (see `docs/PX4_SITL_INTEGRATION.md` Sec2 on RTF variability).
- `pos_residual_m` is a running sum (see module docstring); time-to-detection-from-end conflates drift duration with detector latency less than time-to-detection-from-onset does, but neither is a clean 'alarm latency' figure independent of this attack's own duration parameter.
- No claim about PX4's own trajectory/estimator: the relay's uplink stays passthrough by construction.
- No comparison yet against the Stage-1 *simulated* `gps_spoofing` attack class recall (different injection point).
