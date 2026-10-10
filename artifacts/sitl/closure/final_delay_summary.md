# P2 DELAY summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: DELAY (all unsigned downlink frames held a fixed delay, released in order). Claim class: **link-level detection** only (the vehicle is disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2dd_summary.py --attack delay <manifests> --out <this file>`.

- Trials: **3**; passing the integrity gates: **3** (`hook_errors == 0` and no frames left held).
- **Link-level detection (SITL): 3/3** integrity-passing trials (any threat decision in the scoring window).
- Pre-onset false alarms (integrity-passing trials pooled): **0/454** decisions.
- Time from onset to first detection: median 10.14 s, min 7.70 s, max 11.14 s (n=3).

| trial | idx | onset s | dur s | delay s | frames delayed | hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2l_final_trial_001 | 0 | 22.66 | 9.36 | 0.69 | 3515 | 0 | 0 | 0/114 | yes | 10.14 | 5 | DOS | message-rate spike: 639 msg/s > 1×nominal (529); message-rate spike: 640 msg/s > 1×nominal (529); message-rate spike: 640 msg/s > 1×nominal (529) |
| p2l_final_trial_002 | 1 | 43.66 | 10.67 | 0.429 | 3995 | 0 | 0 | 0/219 | yes | 11.14 | 5 | DOS | message-rate spike: 531 msg/s > 1×nominal (529); message-rate spike: 546 msg/s > 1×nominal (529); message-rate spike: 546 msg/s > 1×nominal (529) |
| p2l_final_trial_003 | 2 | 24.1 | 7.21 | 0.471 | 2697 | 0 | 0 | 0/121 | yes | 7.7 | 5 | DOS | message-rate spike: 546 msg/s > 1×nominal (529); message-rate spike: 558 msg/s > 1×nominal (529); message-rate spike: 559 msg/s > 1×nominal (529) |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['eae85e6']; `src`/`scripts`/`configs` dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 0.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped on, nothing about vehicle behaviour.
- The scoring window counts ANY threat decision; a decision need not be caused by the delay (see types/evidence per trial). Absence of detection is a legitimate, reported result: the delay changes arrival times, not content or sequence, so little detector signal is expected.
