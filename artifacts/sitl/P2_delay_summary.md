# P2 DELAY summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: DELAY (all unsigned downlink frames held a fixed delay, released in order). Claim class: **link-level detection** only (the vehicle is disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2dd_summary.py --attack delay <manifests> --out <this file>`.

- Trials: **10**; passing the integrity gates: **10** (`hook_errors == 0` and no frames left held).
- **Link-level detection (SITL): 9/10** integrity-passing trials (any threat decision in the scoring window).
- Pre-onset false alarms (integrity-passing trials pooled): **1/1854** decisions.
- Time from onset to first detection: median 10.83 s, min 7.70 s, max 12.48 s (n=9).

| trial | idx | onset s | dur s | delay s | frames delayed | hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2l_n10_trial_001 | 0 | 22.66 | 9.36 | 0.69 | 3424 | 0 | 0 | 0/114 | yes | 10.14 | 5 | DOS | message-rate spike: 627 msg/s > 1×nominal (529); message-rate spike: 613 msg/s > 1×nominal (529); message-rate spike: 613 msg/s > 1×nominal (529) |
| p2l_n10_trial_002 | 1 | 43.66 | 10.67 | 0.429 | 3908 | 0 | 0 | 1/219 | yes | 11.54 | 1 | DOS | message-rate spike: 531 msg/s > 1×nominal (529) |
| p2l_n10_trial_003 | 2 | 24.1 | 7.21 | 0.471 | 2641 | 0 | 0 | 0/121 | yes | 7.7 | 4 | DOS | message-rate spike: 552 msg/s > 1×nominal (529); message-rate spike: 534 msg/s > 1×nominal (529); message-rate spike: 530 msg/s > 1×nominal (529) |
| p2l_n10_trial_004 | 3 | 52.13 | 10.25 | 1.074 | 3722 | 0 | 0 | 0/261 | yes | 11.47 | 5 | DOS | message-rate spike: 763 msg/s > 1×nominal (529); message-rate spike: 767 msg/s > 1×nominal (529); message-rate spike: 769 msg/s > 1×nominal (529) |
| p2l_n10_trial_005 | 4 | 57.11 | 7.82 | 1.068 | 2845 | 0 | 0 | 0/286 | yes | 8.89 | 5 | DOS | message-rate spike: 684 msg/s > 1×nominal (529); message-rate spike: 768 msg/s > 1×nominal (529); message-rate spike: 770 msg/s > 1×nominal (529) |
| p2l_n10_trial_006 | 5 | 38.17 | 10.08 | 0.808 | 3712 | 0 | 0 | 0/191 | yes | 10.83 | 6 | DOS, MAVLINK_ANOMALY | sequence gap 254 > 30; ML anomaly score 0.87 ≥ 0.62 (driver: max_seq_gap, z=+36.4); message-rate spike: 659 msg/s > 1×nominal (529) |
| p2l_n10_trial_007 | 6 | 37.52 | 10.92 | 1.401 | 4014 | 0 | 0 | 0/188 | yes | 12.48 | 5 | DOS | message-rate spike: 839 msg/s > 1×nominal (529); message-rate spike: 824 msg/s > 1×nominal (529); message-rate spike: 833 msg/s > 1×nominal (529) |
| p2l_n10_trial_008 | 7 | 33.06 | 9.75 | 1.078 | 3513 | 0 | 0 | 0/166 | yes | 10.94 | 5 | DOS | message-rate spike: 748 msg/s > 1×nominal (529); message-rate spike: 747 msg/s > 1×nominal (529); message-rate spike: 748 msg/s > 1×nominal (529) |
| p2l_n10_trial_009 | 8 | 33.94 | 8.35 | 0.355 | 3036 | 0 | 0 | 0/170 | NO | None | 0 | - | - |
| p2l_n10_trial_010 | 9 | 27.57 | 7.54 | 1.197 | 2798 | 0 | 0 | 0/138 | yes | 8.83 | 5 | DOS | message-rate spike: 815 msg/s > 1×nominal (529); message-rate spike: 831 msg/s > 1×nominal (529); message-rate spike: 816 msg/s > 1×nominal (529) |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['e0b28d7']; `src`/`scripts`/`configs` dirty-path counts [6] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 0.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped on, nothing about vehicle behaviour.
- The scoring window counts ANY threat decision; a decision need not be caused by the delay (see types/evidence per trial). Absence of detection is a legitimate, reported result: the delay changes arrival times, not content or sequence, so little detector signal is expected.
