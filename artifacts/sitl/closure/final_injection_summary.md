# P2 command-injection summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: uplink rogue `COMMAND_LONG` force-disarm (sysid 66/compid 200), piggybacked on a real uplink frame, mirrored to the IDS tap. Regenerate: `scripts/sitl/make_p2i_summary.py artifacts/sitl/p2i_trial_*.manifest.json artifacts/sitl/p2i_fix_trial_*.manifest.json`.

Claims, never merged: **command-path effect** (PX4 acked the rogue command), **link-level detection** (IDS produced `COMMAND_INJECTION`-type evidence, "command(s) from unexpected source", at or after the injection), and **harness delivery** (each injected frame actually reached the IDS pipeline's input). A detector outcome only counts when the frame reached the IDS. The two batches below are different harness versions and are never pooled.

## POST-FIX batch (relay mirrors hook-added frames to all clients)

- **Command-path effect (SITL)**: PX4 accepted/acked the rogue command in **3/3** trials.
- **Link-level detection (SITL)**: the IDS produced command-injection evidence in **3/3** trials.
- **Harness delivery**: **13/13** injected frames reached the IDS pipeline input (carriers across all injections, sysid x count: 252x7, 254x6).
- Every injected frame reached the IDS, whichever client carried it.
- Provenance: aegisflight commit(s) eae85e6ecae4489a9fcd1e477af735f8780b8586; `src`/`scripts`/`configs` dirty in 0/3 manifests (dirty-path counts [0]): the uncommitted relay mirror fix and the trial/summary script edits themselves (the fix is not in the recorded commit; `tests/` and `docs/` are outside the provenance scope). Result is not a clean-commit reproduction until those paths are committed.

| trial | idx | onset s | injected | carried by (sysid) | reached IDS | acked | ack result | ttfa s | detected | latency s (from onset) | harness-artifact decisions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| p2i_final_trial_001 | 0 | 36.95 | 2 | 252x1, 254x1 | 2/2 | yes | MAV_RESULT_ACCEPTED | 0.0151909 | yes | 0.25 | 99 |
| p2i_final_trial_002 | 1 | 55.55 | 6 | 252x3, 254x3 | 6/6 | yes | MAV_RESULT_ACCEPTED | 0.0097169 | yes | 0.85 | 99 |
| p2i_final_trial_003 | 2 | 31.79 | 5 | 252x3, 254x2 | 5/5 | yes | MAV_RESULT_ACCEPTED | 0.015101 | yes | 0.61 | 98 |

## Known experimental artifact, not a false-alarm-rate result
TWO non-expected-GCS identities in this topology trigger the protocol rogue-telemetry-source rule: the inert "carrier" client (sysid 252/compid 193) and the benign flight-driver client (sysid 253/compid 192); both are outside the PX4 profile's `expected_sysids`/`expected_gcs_sysids`. The last column counts decisions citing either. It is a property of this harness (an uplink-mirroring harness needs non-IDS uplink clients), never a benign false-alarm measurement; do not merge it with `docs/CALIBRATION_PX4.md`.

## Limitations
- n=10 per batch, not a statistically powered sample; counts are reported, not a rate with confidence bounds.
- One airframe/world/host, one benign flight driver script, one seed family (2001 + trial_index).
- `acked` is independent of detection. Detection is link-level only: the IDS saw a mirrored copy of the frame on a bump-in-the-wire tap; this says nothing about estimator effects or physical flight deviation, and the mirrored-tap topology is a harness choice (a deployed IDS would need an actual uplink vantage point).
- The link is unsigned throughout (no claim about MAVLink signing); SITL only (no real hardware/RF).
