# P2 DROP summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: DROP (downlink GLOBAL_POSITION_INT + GPS_RAW_INT suppression). Claim class: **link-level detection** only (the vehicle is disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2dd_summary.py --attack drop <manifests> --out <this file>`.

- Trials: **10**; passing the integrity gates: **10** (`hook_errors == 0` and no frames left held).
- **Link-level detection (SITL): 10/10** integrity-passing trials (GPS-dropout evidence in the scoring window).
- Pre-onset false alarms (integrity-passing trials pooled): **0/1972** decisions.
- Time from onset to first detection: median 2.76 s, min 2.22 s, max 2.89 s (n=10).

| trial | idx | onset s | dur s | frames dropped | hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2d_n10_trial_001 | 0 | 44.18 | 10.98 | 585 | 0 | 585 | 0/221 | yes | 2.22 | 45 | DOS | GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s; GPS dropout 2.6s > 2.0s |
| p2d_n10_trial_002 | 1 | 36.48 | 9.19 | 494 | 0 | 494 | 0/183 | yes | 2.72 | 36 | DOS | GPS dropout 2.1s > 2.0s; GPS dropout 2.3s > 2.0s; GPS dropout 2.5s > 2.0s |
| p2d_n10_trial_003 | 2 | 35.62 | 11.32 | 609 | 0 | 609 | 0/179 | yes | 2.78 | 46 | DOS | GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s; GPS dropout 2.6s > 2.0s |
| p2d_n10_trial_004 | 3 | 43.51 | 11.95 | 646 | 0 | 646 | 0/218 | yes | 2.89 | 50 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |
| p2d_n10_trial_005 | 4 | 35.96 | 11.76 | 634 | 0 | 634 | 0/180 | yes | 2.84 | 48 | DOS | GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s; GPS dropout 2.6s > 2.0s |
| p2d_n10_trial_006 | 5 | 35.34 | 7.79 | 420 | 0 | 420 | 0/177 | yes | 2.86 | 29 | DOS | GPS dropout 2.1s > 2.0s; GPS dropout 2.3s > 2.0s; GPS dropout 2.5s > 2.0s |
| p2d_n10_trial_007 | 6 | 39.46 | 11.69 | 629 | 0 | 629 | 0/198 | yes | 2.74 | 49 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |
| p2d_n10_trial_008 | 7 | 43.33 | 11.71 | 632 | 0 | 632 | 0/217 | yes | 2.67 | 49 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |
| p2d_n10_trial_009 | 8 | 43.31 | 7.66 | 413 | 0 | 413 | 0/217 | yes | 2.49 | 29 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |
| p2d_n10_trial_010 | 9 | 36.2 | 7.53 | 400 | 0 | 400 | 0/182 | yes | 2.8 | 27 | DOS | GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s; GPS dropout 2.6s > 2.0s |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['e0b28d7']; `src`/`scripts`/`configs` dirty-path counts [5, 6] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 1.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped on, nothing about vehicle behaviour.
