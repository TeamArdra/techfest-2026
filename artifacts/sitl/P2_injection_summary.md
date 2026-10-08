# P2 command-injection summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: uplink rogue `COMMAND_LONG` force-disarm (sysid 66/compid 200), piggybacked on a real uplink frame, mirrored to the IDS tap. Regenerate: `scripts/sitl/make_p2i_summary.py artifacts/sitl/p2i_trial_*.manifest.json artifacts/sitl/p2i_fix_trial_*.manifest.json`.

Claims, never merged: **command-path effect** (PX4 acked the rogue command), **link-level detection** (IDS produced `COMMAND_INJECTION`-type evidence, "command(s) from unexpected source", at or after the injection), and **harness delivery** (each injected frame actually reached the IDS pipeline's input). A detector outcome only counts when the frame reached the IDS. The two batches below are different harness versions and are never pooled.

## POST-FIX batch (relay mirrors hook-added frames to all clients)

- **Command-path effect (SITL)**: PX4 accepted/acked the rogue command in **10/10** trials.
- **Link-level detection (SITL)**: the IDS produced command-injection evidence in **10/10** trials.
- **Harness delivery**: **37/37** injected frames reached the IDS pipeline input (carriers across all injections, sysid x count: 252x12, 254x25).
- Every injected frame reached the IDS, whichever client carried it.
- Provenance: aegisflight commit(s) e0b28d793c378f54f75b03be9a30bdda17ba4183; `src`/`scripts`/`configs` dirty in 10/10 manifests (dirty-path counts [3]): the uncommitted relay mirror fix and the trial/summary script edits themselves (the fix is not in the recorded commit; `tests/` and `docs/` are outside the provenance scope). Result is not a clean-commit reproduction until those paths are committed.

| trial | idx | onset s | injected | carried by (sysid) | reached IDS | acked | ack result | ttfa s | detected | latency s (from onset) | harness-artifact decisions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2i_fix_trial_001 | 0 | 36.95 | 2 | 252x2 | 2/2 | yes | MAV_RESULT_ACCEPTED | 0.0141689 | yes | 0.45 | 153 |
| p2i_fix_trial_002 | 1 | 55.55 | 6 | 252x2, 254x4 | 6/6 | yes | MAV_RESULT_ACCEPTED | 0.0139211 | yes | 0.85 | 198 |
| p2i_fix_trial_003 | 2 | 31.79 | 5 | 252x5 | 5/5 | yes | MAV_RESULT_ACCEPTED | 0.0131403 | yes | 0.41 | 180 |
| p2i_fix_trial_004 | 3 | 45.61 | 2 | 254x2 | 2/2 | yes | MAV_RESULT_ACCEPTED | 0.0369739 | yes | 0.59 | 185 |
| p2i_fix_trial_005 | 4 | 48.71 | 3 | 252x1, 254x2 | 3/3 | yes | MAV_RESULT_ACCEPTED | 0.0076799 | yes | 0.69 | 198 |
| p2i_fix_trial_006 | 5 | 54.88 | 4 | 254x4 | 4/4 | yes | MAV_RESULT_ACCEPTED | 0.0114811 | yes | 0.72 | 195 |
| p2i_fix_trial_007 | 6 | 50.39 | 3 | 254x3 | 3/3 | yes | MAV_RESULT_ACCEPTED | 0.0343814 | yes | 0.21 | 192 |
| p2i_fix_trial_008 | 7 | 55.81 | 4 | 252x1, 254x3 | 4/4 | yes | MAV_RESULT_ACCEPTED | 0.0110967 | yes | 0.79 | 186 |
| p2i_fix_trial_009 | 8 | 28.48 | 4 | 254x4 | 4/4 | yes | MAV_RESULT_ACCEPTED | 0.0222949 | yes | 0.92 | 175 |
| p2i_fix_trial_010 | 9 | 29.74 | 4 | 252x1, 254x3 | 4/4 | yes | MAV_RESULT_ACCEPTED | 0.0060308 | yes | 0.66 | 183 |

## PRE-FIX batch (superseded; harness defect, NOT a detector or transport result)

- Command-path effect (SITL): PX4 acked in **10/10** trials.
- Link-level detection: **5/10** trials - but in this harness version the relay did not mirror a hook-added frame to the uplink frame's own sender, and the IDS tap sends its own heartbeat; when that heartbeat carried the injection the IDS never received it. The carrier was not logged, so which injections were undeliverable cannot be reconstructed per injection.
- Of the 7 trials with the `ids_ingest.jsonl` tap, injected frames that reached the IDS input: **11/25**; trials with zero frames reaching the IDS cannot say anything about the detector. Trials detected despite zero frames reaching the ingest tap: none.
- Earlier drafts of this summary attributed the split to a timing/concurrency race in `UdpMavlinkTransport`. That hypothesis is disproven (see `docs/STAGE2_PROGRESS.md`, 2026-10-07 root-cause entry): the transport delivered every frame the relay mirrored to it.

| trial | idx | ingest tap | onset s | injected | reached IDS | acked | ack result | ttfa s | detected | latency s (from onset) | harness-artifact decisions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2i_trial_001 | 0 | no | 36.95 | 2 | not logged | yes | MAV_RESULT_ACCEPTED | 0.0073902 | NO | None | 100 |
| p2i_trial_002 | 0 | no | 36.95 | 2 | not logged | yes | MAV_RESULT_ACCEPTED | 0.0097603 | NO | None | 99 |
| p2i_trial_003 | 0 | no | 36.95 | 2 | not logged | yes | MAV_RESULT_ACCEPTED | 0.0106739 | NO | None | 190 |
| p2i_trial_004 | 0 | yes | 36.95 | 2 | 2/2 | yes | MAV_RESULT_ACCEPTED | 0.0093131 | yes | 0.25 | 198 |
| p2i_trial_005 | 1 | yes | 55.55 | 6 | 2/6 | yes | MAV_RESULT_ACCEPTED | 0.0182102 | yes | 7.05 | 150 |
| p2i_trial_006 | 2 | yes | 31.79 | 5 | 2/5 | yes | MAV_RESULT_ACCEPTED | 0.0133874 | yes | 4.61 | 172 |
| p2i_trial_007 | 3 | yes | 45.61 | 2 | 2/2 | yes | MAV_RESULT_ACCEPTED | 0.0079171 | yes | 0.79 | 173 |
| p2i_trial_008 | 4 | yes | 48.71 | 3 | 3/3 | yes | MAV_RESULT_ACCEPTED | 0.0108141 | yes | 0.69 | 148 |
| p2i_trial_009 | 5 | yes | 54.88 | 4 | 0/4 | yes | MAV_RESULT_ACCEPTED | 0.0144162 | NO | None | 163 |
| p2i_trial_010 | 6 | yes | 50.39 | 3 | 0/3 | yes | MAV_RESULT_ACCEPTED | 0.0145148 | NO | None | 165 |

## Known experimental artifact, not a false-alarm-rate result
TWO non-expected-GCS identities in this topology trigger the protocol rogue-telemetry-source rule: the inert "carrier" client (sysid 252/compid 193) and the benign flight-driver client (sysid 253/compid 192); both are outside the PX4 profile's `expected_sysids`/`expected_gcs_sysids`. The last column counts decisions citing either. It is a property of this harness (an uplink-mirroring harness needs non-IDS uplink clients), never a benign false-alarm measurement; do not merge it with `docs/CALIBRATION_PX4.md`.

## Limitations
- n=10 per batch, not a statistically powered sample; counts are reported, not a rate with confidence bounds.
- One airframe/world/host, one benign flight driver script, one seed family (2001 + trial_index).
- `acked` is independent of detection. Detection is link-level only: the IDS saw a mirrored copy of the frame on a bump-in-the-wire tap; this says nothing about estimator effects or physical flight deviation, and the mirrored-tap topology is a harness choice (a deployed IDS would need an actual uplink vantage point).
- The link is unsigned throughout (no claim about MAVLink signing); SITL only (no real hardware/RF).
