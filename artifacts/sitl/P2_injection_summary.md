# P2 command-injection summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: uplink rogue `COMMAND_LONG` force-disarm (sysid 66/compid 200), piggybacked on a real uplink frame, mirrored to the IDS tap.

Two independent claims (never merge these rows):
- **Command-path effect (SITL)**: PX4 accepted/acked the rogue command in **10/10** trials.
- **Link-level detection (SITL)**: the IDS produced `COMMAND_INJECTION`-type evidence ("command(s) from unexpected source") at or after the injection in **5/10** trials.

Detection is **not deterministic across identical draws**: trials sharing the exact same `(seed, trial_index)` draw produced different outcomes on different live runs (see table; `trial_index=0` was run 4 times total). Of the 7 trials run with the `ids_ingest.jsonl` diagnostic tap added, 5/7 detected; of the 3 trials run without it, 0/3 detected. This is consistent with -- but does not prove -- a timing/concurrency sensitivity in the live threaded UDP receive path (`sources/mavlink_live.py` `UdpMavlinkTransport`), the same open hypothesis raised before this batch; the parser, extractor, and detector logic were independently verified correct in isolation before this batch (see `docs/STAGE2_PROGRESS.md`) and are not implicated by this result.

**Known experimental artifact, not a false-alarm-rate result:** TWO non-expected-GCS identities in this topology trigger the same protocol rogue-telemetry-source rule -- the inert "carrier" client (sysid 252/compid 193) and the benign flight-driver client (sysid 253/compid 192); both are outside the PX4 profile's `expected_sysids`/`expected_gcs_sysids`, and once either's heartbeat is mirrored to the IDS, the rule correctly flags it on every decision that observes it (an earlier draft of this summary named only the carrier -- caught and corrected after `aegis-reviewer` traced the actual evidence strings and found the driver contributing an equal, independent share). This is a property of this specific experimental topology (an uplink-mirroring harness needs non-IDS uplink clients to mirror, and this one happens to have two outside the expected-identity lists), not a general benign false-alarm measurement -- it must never be merged with the `docs/CALIBRATION_PX4.md` false-alarm numbers, which use neither client.

| trial | idx | ingest tap | onset s | acked | ack result | ttfa s | detected | latency s (from onset) | carrier/driver-artifact decisions |
|---|---|---|---|---|---|---|---|---|---|
| p2i_trial_001 | 0 | no | 36.95 | yes | MAV_RESULT_ACCEPTED | 0.0073902 | NO | None | 100 |
| p2i_trial_002 | 0 | no | 36.95 | yes | MAV_RESULT_ACCEPTED | 0.0097603 | NO | None | 99 |
| p2i_trial_003 | 0 | no | 36.95 | yes | MAV_RESULT_ACCEPTED | 0.0106739 | NO | None | 190 |
| p2i_trial_004 | 0 | yes | 36.95 | yes | MAV_RESULT_ACCEPTED | 0.0093131 | yes | 0.25 | 198 |
| p2i_trial_005 | 1 | yes | 55.55 | yes | MAV_RESULT_ACCEPTED | 0.0182102 | yes | 7.05 | 150 |
| p2i_trial_006 | 2 | yes | 31.79 | yes | MAV_RESULT_ACCEPTED | 0.0133874 | yes | 4.61 | 172 |
| p2i_trial_007 | 3 | yes | 45.61 | yes | MAV_RESULT_ACCEPTED | 0.0079171 | yes | 0.79 | 173 |
| p2i_trial_008 | 4 | yes | 48.71 | yes | MAV_RESULT_ACCEPTED | 0.0108141 | yes | 0.69 | 148 |
| p2i_trial_009 | 5 | yes | 54.88 | yes | MAV_RESULT_ACCEPTED | 0.0144162 | NO | None | 163 |
| p2i_trial_010 | 6 | yes | 50.39 | yes | MAV_RESULT_ACCEPTED | 0.0145148 | NO | None | 165 |

## Limitations
- n=10, not a statistically powered sample; counts are reported, not a rate with confidence bounds.
- The split by "ingest tap present" is an observed correlation across two batches run at different times on one host, not a controlled A/B experiment (the only deliberate code change between batches was adding a read-only diagnostic log; host load, SITL boot timing, and Gazebo RTF were not held constant -- see `docs/PX4_SITL_INTEGRATION.md` Sec2).
- All trials: one airframe/world/host, one benign flight driver script, one seed family (2001 + trial_index).
- `acked=true` in every trial (independent of detection) reconfirms the command-path-effect result from the first trial; it is unrelated to whether the IDS flagged it.
- No claim about MAVLink signing (link is unsigned throughout) or about real hardware/RF.
