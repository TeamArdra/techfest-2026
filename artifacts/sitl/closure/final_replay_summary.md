# P2 REPLAY-v2 summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: byte-identical replay of a captured, unsigned COMMAND_LONG (force-disarm) from an EXPECTED GCS identity (sysid 255, in `expected_gcs_sysids`), 15-30s later. Three claims scored separately (see module docstring): harness delivery, command-path effect, link-level detection via the sequence-continuity mechanism (NOT identity/provenance). Regenerate: `scripts/sitl/make_p2r_v2_summary.py <manifests> --out <this file>`.

- Trials: **3**; passing the integrity gate: **3** (`hook_errors == 0`, attack saw frames).
- **Harness delivery**: original capture reached the IDS in **3/3**; the replay also reached it in **3/3**.
- **Command-path effect (SITL)**: both the original and replayed command ACCEPTED by PX4 in **3/3**.
- **Link-level detection (SITL), sequence-continuity mechanism**: `MAVLINK_ANOMALY` ("sequence gap") within 5s of the replay in **3/3**; any threat decision in that window: **3/3**.
- **Identity/provenance rule**: `COMMAND_INJECTION`-typed evidence across all trials: **0** (expected: 0 -- sysid 255 is an expected GCS identity, confirming the documented `command_injection:gcs_replay` gap holds for THIS rule; detection above comes from a different, orthogonal mechanism).
- Pre-replay false alarms (integrity-passing trials pooled): **0/48** decisions.
- Sequence-gap detection latency after the replay: 0.00s, 0.00s, 0.10s (n=3).

| trial | idx | delay s | capture delivered | replay delivered | orig ack | replay ack | seq-gap detected | latency s | any detected | identity evidence | pre-replay FA | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| p2r_final_trial_001 | 0 | 18.98 | yes | yes | MAV_RESULT_ACCEPTED | MAV_RESULT_ACCEPTED | yes | 0.0 | yes | 0 | 0/16 | sequence gap 235 > 30; ML anomaly score 0.84 ≥ 0.62 (driver: loss_ratio, z=+36.3) |
| p2r_final_trial_002 | 1 | 29.93 | yes | yes | MAV_RESULT_ACCEPTED | MAV_RESULT_ACCEPTED | yes | 0.0 | yes | 0 | 0/16 | sequence gap 224 > 30; ML anomaly score 0.83 ≥ 0.62 (driver: loss_ratio, z=+36.3); sequence gap 31 > 30 |
| p2r_final_trial_003 | 2 | 21.35 | yes | yes | MAV_RESULT_ACCEPTED | MAV_RESULT_ACCEPTED | yes | 0.1 | yes | 0 | 0/16 | sequence gap 233 > 30; ML anomaly score 0.84 ≥ 0.62 (driver: loss_ratio, z=+36.3) |

## Provenance
- PX4: ['v1.18.0-rc1-27-gc239c63807']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['eae85e6']; `src`/`scripts`/`configs` dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- The sequence-gap mechanism is analytically shown (see module docstring) to depend on the real GCS identity continuing to heartbeat between capture and replay, and on the replay delay staying well under ~225s at a 1Hz heartbeat given `max_seq_gap: 30` -- both hold for the full drawn range (15-30s) here, but this is NOT evidence about a replay performed after the real GCS has gone silent, or after a much longer delay.
- Detection here is **link-level** only: it says the IDS can see the stale sequence number on the link it is tapped on, nothing about vehicle behaviour or the estimator.
- This is a single command (force-disarm) replayed against an already-disarmed vehicle; not evidence about replaying a different command or one with in-flight consequence.
