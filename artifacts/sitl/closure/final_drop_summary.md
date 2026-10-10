# P2 DROP summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: DROP (downlink GLOBAL_POSITION_INT + GPS_RAW_INT suppression). Claim class: **link-level detection** only (the vehicle is disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2dd_summary.py --attack drop <manifests> --out <this file>`.

- Trials: **3**; passing the integrity gates: **3** (`hook_errors == 0` and no frames left held).
- **Link-level detection (SITL): 3/3** integrity-passing trials (GPS-dropout evidence in the scoring window).
- Pre-onset false alarms (integrity-passing trials pooled): **0/583** decisions.
- Time from onset to first detection: median 2.92 s, min 2.78 s, max 3.02 s (n=3).

| trial | idx | onset s | dur s | frames dropped | hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2d_final_trial_001 | 0 | 44.18 | 10.98 | 604 | 0 | 604 | 0/221 | yes | 3.02 | 45 | DOS | GPS dropout 2.1s > 2.0s; GPS dropout 2.3s > 2.0s; GPS dropout 2.5s > 2.0s |
| p2d_final_trial_002 | 1 | 36.48 | 9.19 | 505 | 0 | 505 | 0/183 | yes | 2.92 | 36 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |
| p2d_final_trial_003 | 2 | 35.62 | 11.32 | 623 | 0 | 623 | 0/179 | yes | 2.78 | 47 | DOS | GPS dropout 2.0s > 2.0s; GPS dropout 2.2s > 2.0s; GPS dropout 2.4s > 2.0s |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['eae85e6']; `src`/`scripts`/`configs` dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 0.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped on, nothing about vehicle behaviour.
