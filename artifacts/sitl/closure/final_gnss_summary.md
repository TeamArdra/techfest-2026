# P2 GNSS-degradation summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: `GPS_RAW_INT.fix_type`/`satellites_visible` rewritten below the protocol rule's thresholds for a window (position fields untouched). Claim class: **link-level detection** only (vehicle disarmed on the ground; PX4 is the sender and its estimator is unaffected; not real GNSS jamming, no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2n_summary.py <manifests> --out <this file>`.

- Trials: **3**; passing the integrity gates: **3**.
- **Link-level detection (SITL): 3/3** integrity-passing trials ('GNSS fix lost' evidence in [onset, onset+duration+5s]).
- Detector-saw-the-written-bytes check (evidence fix_type/satellites == drawn values): **3/3** detected trials.
- Pre-onset false alarms, any threat (integrity-passing trials pooled): **0/662** decisions; GNSS-rule-specific pre-onset evidence: **0**.
- Time from onset to first GNSS detection: median 1.87 s, min 1.87 s, max 1.94 s (n=3).

| trial | idx | onset s | dur s | fix_type | sats | frames modified | hook_errors | pre-onset FA | pre-onset GNSS ev. | detected | values match | latency s | GNSS-evidence decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2n_final_trial_001 | 0 | 50.86 | 33.47 | 1 | 2 | 167 | 0 | 0/255 | 0 | yes | yes | 1.94 | 163 | DOS | GNSS fix lost: fix_type=1, satellites=2 for 5 decisions; GNSS fix lost: fix_type=1, satellites=2 for 6 decisions |
| p2n_final_trial_002 | 1 | 40.73 | 33.01 | 0 | 3 | 165 | 0 | 0/204 | 0 | yes | yes | 1.87 | 161 | DOS | GNSS fix lost: fix_type=0, satellites=3 for 5 decisions; GNSS fix lost: fix_type=0, satellites=3 for 6 decisions |
| p2n_final_trial_003 | 2 | 40.53 | 18.91 | 1 | 0 | 95 | 0 | 0/203 | 0 | yes | yes | 1.87 | 91 | DOS | GNSS fix lost: fix_type=1, satellites=0 for 5 decisions; GNSS fix lost: fix_type=1, satellites=0 for 6 decisions |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['eae85e6']; `src`/`scripts`/`configs` dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 0.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- The attack writes values far below the rule's thresholds (fix_type 0-1, satellites 0-4 vs 3 / 5) by design: this is a positive control for the dedicated GNSS-fix-loss rule on live PX4 data, NOT a sensitivity measurement. A subtle degradation (e.g. fix_type 3 with 5 satellites, or a slow decline) was not tested.
- Detection is **link-level**: the IDS sees the degraded status the proxy put on its tap; it says nothing about how PX4 or a real receiver behaves under jamming.
