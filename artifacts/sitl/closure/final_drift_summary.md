# P2 summary - first live attack trials on PX4 SITL (generated; do not edit)

Environment: **SITL**. Attack: downlink `GLOBAL_POSITION_INT` gradual drift (`docs/ATTACK_PROXY.md` Sec3). Claim class: **link-level detection (SITL) only** -- PX4 never receives a modified frame; this is not GPS spoofing of the vehicle and says nothing about signing.
Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p2_summary.py artifacts/sitl/p2_final_trial_*.manifest.json`.

**3/3 trials**: a `GPS_SPOOFING` decision fired at or after the attack window closed, with **0 false alarms** in any trial's pre-onset (benign) portion (538 pre-onset decisions pooled).
Time-to-detection from attack end: n=3, mean=1.00s, median=1.04s, min=0.90s, max=1.07s

| trial | onset s | dur s | rate m/s | bearing | expected m | actual m | frames mod | pre-onset FA | detected | ttd-from-end s | other threat types |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2_final_trial_001 | 44.5 | 15.39 | 3.502 | 308.8 | 53.9 | 53.84 | 769 | 0 | yes | 0.9 | - |
| p2_final_trial_002 | 35.23 | 23.93 | 7.981 | 140.2 | 190.98 | 190.96 | 1197 | 0 | yes | 1.04 | - |
| p2_final_trial_003 | 27.51 | 21.42 | 5.957 | 237.9 | 127.59 | 127.51 | 1071 | 0 | yes | 1.07 | - |

## Limitations
- n reflects however many trials have completed when this was last regenerated; a small n (as called for by the design, >=10) is not a statistically powerful sample -- report counts, not a rate with confidence bounds.
- All trials share one scripted benign-flight-free attack window on one airframe/world/host; this is not independent of host load (see `docs/PX4_SITL_INTEGRATION.md` Sec2 on RTF variability).
- `pos_residual_m` is a running sum (see module docstring); time-to-detection-from-end conflates drift duration with detector latency less than time-to-detection-from-onset does, but neither is a clean 'alarm latency' figure independent of this attack's own duration parameter.
- No claim about PX4's own trajectory/estimator: the relay's uplink stays passthrough by construction.
- No comparison yet against the Stage-1 *simulated* `gps_spoofing` attack class recall (different injection point).
