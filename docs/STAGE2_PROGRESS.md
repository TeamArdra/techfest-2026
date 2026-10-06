# Stage-2 progress record

Append-only log, newest last. Numbers are quoted only from generated artifacts (paths given).
Each entry: milestone / implementation / tests / experiments / results / limitations / next.

---

## 2026-10-06 - P0 baseline reconfirmed
- **State:** Stage-1 baseline reproduced earlier the same day (`.claude/CLAUDE.md`, "Known environment facts"):
  `pytest` 73 passed, ruff clean, benchmark TP/FP/TN/FN 6535/4/16826/65 (regenerated into a scratch dir, committed
  artifacts untouched). Not re-run for this entry; re-run at each milestone gate.
- PX4 tree (`/home/astryx/PX4-Autopilot`, `v1.18.0-rc1-27-gc239c63807`) clean (0 tracked modifications) after all WSL work.

## 2026-10-06 - P1 live PX4 SITL observation and ingestion  (env: SITL, attack: NONE)
**Implementation** (all additive; frozen Stage-1 files unchanged)
- `scripts/sitl/start_px4_sitl.sh` - isolated headless PX4+Gazebo (instance 2, own Gazebo partition, working dir outside the PX4 tree, env vars only).
- `scripts/sitl/record_flight.py` - benign GCS: arm, takeoff, square, land; raw tlog + manifest.
- `scripts/sitl/tlog_stats.py` - raw-header stream statistics (rates, jitter, seq loss vs reorder, clock drift, PX4 modes).
- `scripts/sitl/replay_benign.py` - unchanged Stage-1 pipeline over a tlog (`--adapter tlog|live`).
- `scripts/sitl/live_ids.py` - Stage-1 `IDSPipeline` live over UDP, teeing the exact bytes to a tlog.
- `scripts/sitl/make_p1_summary.py` - generates `artifacts/sitl/P1_summary.md`.
- `src/aegisflight/sources/mavlink_live.py` - `MavlinkFrameParser` (header-first), `UdpMavlinkTransport`,
  `LiveMavlinkSource`, `frame_ticks`, `decode_px4_mode` (built test-first by the `aegis-px4-mavlink` agent; verified by the lead).

**Tests:** `pytest` 103 passed (73 Stage-1 + 30 new in `tests/unit/test_mavlink_live.py`); `ruff check src tests scripts backend` clean.

**Experiments / results** (details: `artifacts/sitl/P1_summary.md`, `docs/PX4_SITL_INTEGRATION.md`)
- Real PX4 SITL MAVLink stream observed from Windows over WSL2 NAT UDP with **no machine-level networking change and no PX4 change**.
- 5 benign flights recorded (`data/sitl/raw/`, git-ignored; manifests alongside). Stream stats: `artifacts/sitl/benign_00N_stream_stats.json`.
- **Negative result:** the unchanged Stage-1 detectors flag every benign PX4 SITL decision (see `P1_summary.md`). Causes identified:
  rate baseline, expected sysid, command-source rule, sequence-reorder artifact, PX4 mode encoding, ML out-of-distribution.
  This is a sim-to-real calibration gap (Stage-1 config states it is not calibrated for real vehicles), not an attack result.
- Live UDP run vs offline replay of the same teed bytes agree (`live_run_001.*`).
- Findings with methodological consequences: PX4's UDP link locks to its first peer (fresh SITL boot per recording); SITL clock
  runs slow and load-dependent (record drift per capture); two GCS clients with identical ids alias via PX4 `-f` forwarding.

**Limitations:** one airframe/world/host; 5 flights; RTF observation was ad-hoc (not an artifact).
**Next:** independent review (`aegis-reviewer`), then P2 design (`aegis-security`) and proxy build.

## 2026-10-06 - P1 adversarial review and fixes  (aegis-reviewer; env: SITL)
Reviewer verdict: P1 evidence PARTIALLY SUPPORTED; 4 blocking items, all fixed or reworded:
1. *Provenance not regenerable* -> `.gitignore` now ignores only `data/sitl/raw/*.tlog` (manifests committable);
   `scripts/sitl/provenance.py` adds commit / dirty flag / package versions / model + config SHA-256 / command line /
   tlog SHA-256 to new manifests; older manifests were **backfilled** and are marked `backfilled: true` (they describe the
   repo at backfill time, not capture time). All P1 work is still uncommitted (HEAD `5c00948`), recorded as `dirty`.
2. *RTF "0.6-1.0" had no artifact* -> removed; mean RTF per capture is now derived from `boot_clock_vs_recv_drift_ppm`
   (0.867-0.900) in `P1_summary.md`.
3. *"live == offline" evidence was counts only* -> `scripts/sitl/compare_live_offline.py` writes per-decision equivalence
   (`artifacts/sitl/live_run_002_equivalence.json`); the contaminated `live_run_001` (255/190 aliasing) is superseded by a
   clean `live_run_002` with the driver on 254/191. Caveats stated: shared assembler (not independent), weak flag agreement
   in an all-alarm regime, the IDS is an active link partner, latency measured under host load.
4. *"seq lost 6" vs "no net loss"* -> `tlog_stats.py` now reports forward gaps, reorders, **net missing** and duplicates
   (net missing = 0, duplicates = 0 in all five flights).
Non-blocking review findings carried into hardening work (in progress): unknown-id frames are not CRC-verified; bind-mode
peer steering; byte-unbounded queue; loopback-only guard incomplete; per-datagram frame cap.
Decision (lead): P2 first attack approved as designed in `docs/ATTACK_PROXY.md` (downlink GLOBAL_POSITION_INT gradual
drift, claim ceiling = link-level detection on PX4 SITL). Detection scoring waits for P3 calibration; calibration uses
flights 001-005, held-out 006-010, and no attack data.

## 2026-10-06 - P2 proxy + first live attack built; P3 calibration run  (env: unit/loopback + SITL replay; attack: NONE yet injected live)
Three owners built in parallel against the frozen `proxy/hooks.py` interface (`FrameContext`/`FrameHook`); combined
gate after merge: **190 tests passed**, `ruff check src tests scripts backend` clean. Nothing committed; PX4 tree
untouched throughout.

**P2 - transport (`aegis-px4-mavlink`):** `src/aegisflight/proxy/transport.py` (`MavlinkRelay`, `make_udp_relay`,
header-first `split_frames`) relays PX4<->clients, fans downlink frames out to learned loopback clients (max 4, pinned
to first sender by default), sends the first GCS heartbeat before anything else starts (fails closed if PX4 never
answers), and runs `down_hook`/`up_hook` per frame with fail-open-to-original on a hook exception. Also hardened
`sources/mavlink_live.py` per the reviewer's non-blocking findings: loopback-only bind enforced, peer pinning, a byte
bound on the queue (8 MiB) alongside the count bound, a 64-frames-per-datagram cap, and header-sanity checks + an
`extra_crc` hook for message ids outside pymavlink's dialect (fuzz acceptance: ~1411/20000 forged datagrams accepted
before hardening, 0/20000 after, 8/200000 at the larger sample - residual is a known, documented gap, not CRC-verified).

**P2 - attack + ground truth (`aegis-security`):** `src/aegisflight/proxy/attacks_live.py` (`PositionDriftAttack`,
`draw_params`, disclosed `RANGES`) and `proxy/groundtruth.py` (`Manifest`, `FrameLogWriter`, `compute_actual_effect`,
`is_holdout`) implement the approved first attack: downlink `GLOBAL_POSITION_INT` lat/lon gradual drift, CRC
recomputed from the real dialect, signed/MAVLink1 frames always passed through untouched, fail-closed until the PX4
target is learned from a HEARTBEAT, deterministic given `(seed, trial_index)`. 45 new unit tests (byte-identical
pass-through outside the attack window, CRC validity, closed-form displacement vs an independent haversine check,
determinism, manifest/frame-log round-trips). Detector fields in the manifest are `init=False`/`None` - this module
cannot write a detection verdict even by mistake.

**P3 - PX4 calibration (`aegis-detection`):** benign-only (no attack data) calibration, split calibration
(`benign_001-005`) vs held-out (`benign_006-010`, run once, not iterated on). New `configs/px4_sitl/detector.yaml`
(additive profile; `configs/detector.yaml` unchanged) plus two small additive detector changes (`protocol.py`
`startup_grace_s`, `physics.py` `yaw_course_deg` now configurable) - both default-preserving, regression-checked.
Held-out false-alarm rate: **100% (2805/2805) on Stage-1 default -> 0.04% (1/2805) on the PX4 profile**, with or
without a PX4-trained isolation forest (`models/isoforest_px4.joblib`, gitignored, trained on the calibration flights
only - reported as optimistic, not held-out). The one remaining false alarm on held-out is the known sequence-reorder
extractor artifact (quantified, not fixed: 2/2760 calibration, 1/2805 held-out - this corrects the earlier P1 note that
called it "sticky"; `clear_window_counts()` resets it every decision). Stage-1 regression reconfirmed identical
(TP/FP/TN/FN 6535/4/16826/65, `artifacts/sitl/calibration/stage1_regression.json`). Cost side is reasoned, not
measured (no attack data exists yet): the loosened rate/battery/yaw thresholds have an estimated detection floor
(e.g. floods under ~1.4x benign rate would be invisible to the rate rule) - this must be re-examined once P2 attack
trials exist. Full numbers: `docs/CALIBRATION_PX4.md`, `artifacts/sitl/calibration/*.json`.

**Proposals awaiting lead/user decision (none applied):** (1) treat large backward sequence steps as reorder not loss
in the frozen extractor - would clear the last false alarm, needs retrain+regression; (2) decode flight mode by
`HEARTBEAT.autopilot` instead of assuming ArduCopter - no detection effect, explainability only; (3) a raw-sensor
cross-check feature outside `ML_FEATURES`; (4) revisit tightening physics thresholds once attack data exists.

**Next:** integrate the relay + attack hook end-to-end against live PX4 SITL (first real trials of the approved
attack), then extend to the remaining P2 attacks in order (injection, drop, replay, delay) per `docs/ATTACK_PROXY.md`.

## 2026-10-06 - P2 first live-attack trials against PX4 SITL  (env: SITL; attack: downlink GLOBAL_POSITION_INT gradual drift)
Built `scripts/sitl/run_p2_trial.py` wiring `MavlinkRelay` (upstream=PX4, downstream=loopback fan-out) with
`down_hook=PositionDriftAttack` and an `IDSPipeline` tapping the relay's downstream leg as an ordinary client.
Claim class: **link-level detection (SITL)** only - the relay's `up_hook` stays passthrough, so PX4 never receives a
modified frame; this is not GPS spoofing of the vehicle and says nothing about signing (link is unsigned).

**Harness bug caught before trusting the result:** the first attempt used `models/isoforest.joblib` (Stage-1 model)
with the `configs/px4_sitl` detector profile - exactly calibration condition **B2** (profile + Stage-1 model,
diagnostic-only), which the P3 report measured at ~96.6% benign false-alarm rate. The trial reproduced that almost
exactly (431/450 decisions flagged, 91-100% alarm rate *before* the attack window even started) - i.e. ML saturation,
not attack detection. Root cause confirmed by cross-referencing `docs/CALIBRATION_PX4.md`; fixed by requiring
`models/isoforest_px4.joblib` (condition C) whenever `--profile configs/px4_sitl` is used, and the script now refuses
the B2 cross-pairing by default. **A second bug** then surfaced: `groundtruth.FrameLogWriter` is correctly
append-only (its own contract), but the trial script did not clear stale output before a rerun, so the corrected
rerun's frame log briefly mixed two trials' evidence (`frames_counted` 1514 vs `frames_modified` 750). Fixed by making
the script refuse to run if any of its three output files already exist, rather than silently appending.

**Trial 001 (seed 1001, trial_index 0, clean rerun) result:** onset 44.50s, duration 15.39s, drift_rate 3.50 m/s,
bearing 309deg -> expected max displacement 53.90 m, measured (from the proxy's own frame log, not the detector)
53.86 m. 750/33121 downlink frames modified; 0 dropped/injected; 0 signed-skipped (link unsigned, as expected). IDS
(PX4-calibrated profile + PX4-trained ML): **448/450 decisions clean, exactly 2 flagged, both `GPS_SPOOFING`**, firing
at t=60.8s and t=61.0s - 0.9-1.1s *after* the attack window closed, not during it. Evidence: physics `pos_residual_m`
~29-30m > 12m threshold, agreed by the ML detector (z~+235). The lag is consistent with `pos_residual_m` being a
running dead-reckoning sum (`features/extractor.py _position_residual`), not an instantaneous feature - it crosses
threshold only once enough drift has accumulated, here near the end of a single 15.4s window.
10 independent trials (seed 1001, `trial_index` 0-9, fresh SITL boot each, per `docs/ATTACK_PROXY.md` Sec3's
randomisation plan: onset/duration/drift_rate/bearing each drawn uniformly from the disclosed ranges) were run.
`scripts/sitl/make_p2_summary.py` aggregates trial manifests into `artifacts/sitl/P2_summary.md` with no hand-typed
numbers; raw per-trial manifests: `artifacts/sitl/p2_trial_{001,003..011}.{manifest.json,frames.jsonl,ids_decisions.jsonl}`
(`p2_trial_002` was deleted, see below - indices are not contiguous by design, not an error).

**Result (artifacts/sitl/P2_summary.md): 10/10 trials detected (`GPS_SPOOFING`), 0 false alarms in any trial's
pre-onset portion (1404 pooled benign decisions). Time-to-first-detection measured from attack end: mean 0.62s,
median 0.56s, min 0.24s, max 1.11s** (measuring from attack *end* rather than *onset* because `pos_residual_m` is a
running dead-reckoning sum - see the first trial's analysis above; detection requires the accumulated drift to cross
the 12m physics threshold, which for these durations/rates happens near or after the window closes). Expected vs.
proxy-measured actual displacement agreed to within 0.03-0.06% in every trial checked (ground truth is self-consistent: measured
from the proxy's own frame log, never from the detector). n=10 is the design's floor, not a statistically powered
sample - reported as counts, not a rate with confidence intervals. **The working tree was dirty (8 uncommitted
paths, including the `detectors/physics.py`/`protocol.py` edits from the P3 entry above - the exact detectors
scoring these trials) during all ten; `full_provenance.working_tree_dirty`/`dirty_paths_count` in each manifest
records this per trial** - this is not a clean-commit reproducible result until those paths are committed.

**Unplanned finding, reported rather than hidden:** trial `p2_trial_010` additionally shows a `DOS`-labelled alarm
tail from t=54.2s to past t=60s (table's `other threat types` column), evidence strings `"heartbeat stale Ns > 3.0s"`
/ `"GPS dropout Ns > 2.0s"` growing monotonically - a **real PX4->IDS telemetry blackout** (the stream actually
stopped, not a feature-extraction artifact; `_RESID_WINDOW` is only 15 decisions / ~3s, too short to explain a 16s+
tail by itself), most likely caused by host load from other work running concurrently on this machine during that
trial. It is unrelated to the gradual-drift attack (content modification, not availability) and occurs ~9s *after*
that trial's correct `GPS_SPOOFING` detection, so it does not affect the measured time-to-detection; the detector
correctly flagged a second, incidental real fault. Documented as evidence that `SITL (live UDP)` timing-sensitive
results are host-load-dependent (consistent with `docs/PX4_SITL_INTEGRATION.md` Sec2 on RTF variability), not
papered over.

**Harness mistakes caught during the run, all self-corrected before trusting any evidence (reported in full since the
evidence-discipline rules require honesty about process, not just results):**
1. The first trial attempt used `models/isoforest.joblib` (Stage-1 ML) with the `configs/px4_sitl` detector profile -
  exactly calibration condition **B2** (profile + Stage-1 model, diagnostic-only, ~96.6% benign FA per
  `docs/CALIBRATION_PX4.md`). The run reproduced that almost exactly (431/450 decisions flagged, alarming *before*
  the attack window even started) - caught by cross-referencing the calibration report before trusting the result,
  not by the result looking reasonable. Fixed in `run_p2_trial.py`: the PX4-trained model is now required (and the B2
  cross-pairing refused by default) whenever `--profile configs/px4_sitl` is used.
2. The corrected rerun then hit a second bug: `groundtruth.FrameLogWriter` is correctly append-only (its own
  contract), but the trial script did not clear stale output before rerunning at the same `--out`, so the frame log
  briefly mixed two trials' evidence (`frames_counted` 1514 vs `frames_modified` 750). Fixed by making the script
  refuse to run if any of its three output files already exist, rather than silently appending or overwriting.
3. A batch-script indexing bug sent `trial_index=0` to a second trial named `p2_trial_002` - an exact duplicate of
  `p2_trial_001`'s draw. Caught by inspecting the manifest before trusting it; those three files were deleted and
  never entered `P2_summary.md`.
4. `TaskStop` on a batch's parent shell did not immediately kill the in-flight `run_p2_trial.py` child or the parent
  loop itself (it kept running with its already-parsed-into-memory script content, unaffected by a `sed` edit to the
  file on disk); rather than force-killing mid-trial and risking a torn file, in-flight files were left alone - `rm`
  on open files correctly failed with "resource busy" until each trial completed naturally. This produced valid
  trials 003-011 (`trial_index` 1-9) using the already-fixed `run_p2_trial.py` binary logic each fresh invocation
  re-read from disk; a second, deliberately-launched "remaining trials" batch correctly refused (via fix #2's guard)
  the instant it collided with the still-running zombie's output, rather than corrupting it. Net effect: the fixes
  held under an actual race condition, not just in the cases they were written for.
After all trials: `pytest` 190 passed, `ruff check src tests scripts backend` clean, PX4 tree confirmed clean
(`git status --porcelain --untracked-files=no` empty).

**Next:** extend to the remaining P2 attacks in order (injection, drop, replay, delay) per `docs/ATTACK_PROXY.md`,
or proceed to a broader P3 revisit (attack-driven threshold tightening, now that attack data exists) / P4 signing -
lead's call on sequencing, documented at the start of that work.

## 2026-10-06 - P2 second live attack: uplink command injection, built + first SITL trial  (env: SITL; attack: rogue COMMAND_LONG)
Delegated design+implementation to `aegis-security` (harness now proven, so design+build combined into one task).
Built `CommandInjectionAttack`/`draw_command_injection_params` (`src/aegisflight/proxy/attacks_live.py`) and
`compute_command_injection_effect` (`proxy/groundtruth.py`): uplink `MAV_CMD_COMPONENT_ARM_DISARM` (force-disarm)
injection impersonating rogue sysid/compid 66/200, piggybacked onto a real uplink frame (no timer-driven injection
exists in the frozen `hooks.py` interface - confirmed unnecessary, not added). Ack verified by watching
`COMMAND_ACK` on the downlink via the same hook instance installed as both `up_hook` and `down_hook`. 30 new tests,
**220 tests passed total**, `ruff` clean, no interface files touched (`hooks.py`/`transport.py` diff empty) -
verified independently before trusting the handback. Built `scripts/sitl/run_p2_injection_trial.py` (new trial
driver; the first attack's `run_p2_trial.py` only wires the modification attack).

**First real SITL trial (seed 2001, trial_index 0), with a benign flight driver flying concurrently via the
offboard link so the vehicle was actually armed and airborne:** PX4 **accepted** the rogue force-disarm -
`actual_effect: {frames_injected: 2, acked: true, first_ack_result: MAV_RESULT_ACCEPTED, time_to_first_ack_s:
0.0074}` - injected at t=36.9s, well after the driver armed (+5s) and reached altitude (+23s). The driver's own
flight completed only 1 of its 4 planned legs (`legs_reached: [true, false, false, false]`, `data/sitl/raw/
p2i_driver_001.json`) - suggestive of a real disruption, but **not independently confirmed by telemetry in this
trial** (no time-series altitude log was captured for this run) and not claimed as a measured physical deviation.
**Claim actually supported: command-path effect (SITL)** - an unauthenticated, rogue-identity command was accepted
and acted on by PX4 in ~7ms. This is the single highest-consequence result produced so far in Stage 2.

**Architectural finding caught before any detection claim was made (searched the full 500-decision run for ANY
command-related evidence string - found zero):** the relay's uplink path (`_handle_up` in `transport.py`) forwards
`up_hook` output only to `self.upstream.send()` (toward PX4) - it never mirrors uplink traffic to downstream
clients. **The IDS tap, as positioned in this experiment, cannot observe uplink frames from any client - not the
attack's injected frames, not even the benign driver's own commands.** This is not a detector failure (the protocol
detector's command-provenance rule, `protocol.py` lines ~127-146, is correctly written and would flag sysid 66 if it
ever saw the frame); it is a topology gap in how the IDS tap was wired for this specific experiment. Verified by
reading the relay's pump loop directly, not inferred. **No detection claim is made for this attack as a result** -
the question "would the IDS flag this live command injection" remains open pending a relay change (mirroring
observed-but-not-necessarily-modified uplink frames to downstream clients, analogous to a real bump-in-the-wire tap
that sees both directions of one physical link) - delegated to `aegis-px4-mavlink` as the next step, after which
this trial will be rerun to get the real answer. Downlink attacks (modification - already proven; drop, delay per
`docs/ATTACK_PROXY.md`'s attack-comparison table) are **not** affected by this gap, since the IDS already correctly
observes downlink traffic (proven by the first attack's clean 10/10 result).

**Next:** fix the relay's uplink visibility (additive, opt-in), rerun the injection trial to get a real detection
answer, then multiple independent trials once that's settled; drop/replay/delay remain next in order regardless.

## 2026-10-06 - P2 second attack: relay uplink mirroring built; detection question remains OPEN after 2 more reruns (env: SITL)
Delegated the mirroring fix to `aegis-px4-mavlink`: opt-in `MavlinkRelay(..., mirror_uplink_to_clients=False)` /
`make_udp_relay(..., mirror_uplink_to_clients=...)`, default off (regression-tested: the already-proven 10/10
downlink result is unaffected), new `RelayStats.mirrored_up` counter, 3 new tests. **223 tests passed total**,
`ruff` clean - verified independently.

**Rerun 1 (trial 002, mirroring on)**: `mirrored_up: 0`. Root cause (found before trusting the "fix didn't work"
reading): the IDS was the *only* relay client, and mirroring correctly excludes the sender of the carrier frame from
receiving its own echo - since the IDS's own uplink heartbeat was the only carrier available, it was always the
sender, so it always excluded itself. Not a bug in the fix; a gap in my trial topology.

**Rerun 2 (trial 003, added a separate inert "carrier" client, distinct sysid 252/193, solely to give the attack a
non-IDS uplink frame to piggyback on)**: `mirrored_up: 201` (confirmed firing: relay stats show `datagrams_up=200,
forwarded_up=202 [200 real + 2 injected], mirrored_up=201` [off-by-one is the very first carrier heartbeat, sent
before the IDS had registered as a client yet - benign startup-order artifact, not a bug]). The IDS's own
`source_stats` (`datagrams_received=36992, bad_frames=0, late_frames=0`) show it receiving substantially more
traffic than pure downlink alone would produce, consistent with the mirrored frames actually arriving and parsing
cleanly. **The ACK-based command-path-effect result is unchanged and reconfirmed** (`acked: true,
first_ack_result: MAV_RESULT_ACCEPTED, time_to_first_ack_s: 0.0107`).

**Yet the IDS still never flagged it - zero command-related evidence across the entire run, again.** Before writing
this off as "still broken" or asserting a cause, narrowed it with one cheap, no-SITL check:
`tests/unit/test_px4_profile.py::test_profile_vehicle_commands_legit_rogue_source_still_flagged` directly feeds
`ProtocolDetector.process()` a `FeatureFrame` with `commands_recent=[CommandEvent(sysid=42,...)]` and **proves the
detector logic itself is already correct** - it does flag an unexpected-source command when one appears in
`commands_recent`. So the gap is not the detector, not (per the relay/source stats above) the transport - it is
somewhere between "a mirrored COMMAND_LONG datagram arrives at the IDS's socket" and "`FeatureExtractor._commands`
contains the matching `CommandEvent` at decision time". Narrowed it further with two more cheap, no-SITL checks
(disposable inline scripts, not added as committed tests - the question is diagnostic, not a regression to guard):
1. `MavlinkFrameParser().parse(raw, ...)` on a byte-identical reconstruction of the injected frame (sysid 66,
   `MAV_CMD_COMPONENT_ARM_DISARM`) -> `FeatureExtractor.update()` -> `extract()`: **`commands_recent` populated
   correctly.** Parser and extractor both work exactly as needed, in isolation.
2. The same raw frame through `aegisflight.sources.mavlink_live.frame_ticks()` (the socket-free tick assembler):
   **the `COMMAND_LONG` envelope appears correctly in `tick.messages`.** Tick assembly also works correctly for
   this exact scenario, in isolation.

So parser, extractor, and tick-assembly are each individually proven correct for synthetic data that matches the
real scenario precisely. Combined with the live trial's own transport stats (`bad_frames: 0, late_frames: 0,
send_failures: 0`, `mirrored_up` growing steadily through the injection window), **every individually-testable link
in the chain checks out** - yet the live, end-to-end result is still zero command evidence. The remaining untested
surface is specifically the real threaded UDP receive path (`UdpMavlinkTransport`'s background thread + queue)
under genuine concurrent load (~340 msg/s downlink traffic sharing the same process as the 2 rare mirrored
command frames), which none of the serial, single-threaded synthetic checks above exercise. Stopping this thread of
live-SITL investigation here (three SITL cycles spent on it) rather than spending further live cycles chasing a
concurrency-specific hypothesis; the next step is a concurrency/threading-focused test of `UdpMavlinkTransport`
itself (inject one rare frame into a stream of high-rate frames on a real loopback socket, assert it is not lost or
misordered), which is still SITL-free.

**Honest summary of what this attack has and has not shown:**
- **Proven, solid:** command-path effect (SITL) - PX4 accepts and acts on a rogue, unauthenticated force-disarm in
  ~7-11ms, reproduced across 3 trials (seed 2001/trial_index 0 each time, same draw, same result).
- **Mechanically verified, working as designed:** the relay's opt-in uplink mirroring; the parser, extractor, and
  tick-assembly layers in isolation.
- **Open, not yet answered, precisely narrowed:** whether the current IDS would detect this specific live attack -
  not a logic bug (detector, parser, extractor, tick-assembly all individually verified correct), most likely a
  concurrency/timing issue specific to the live threaded transport under real load, unconfirmed. This is explicitly
  **not** claimed either way (neither "detected" nor "missed") - the evidence is insufficient to say, and the
  rules against overclaiming apply equally to claiming a negative result prematurely.

**Next:** a concurrency-focused `UdpMavlinkTransport` test (no SITL) before spending more live-SITL
cycles on it; independently, proceed to drop/replay/delay (downlink-direction attacks, unaffected by this open
question) using the proven first-attack pattern.

## 2026-10-07 - P2 command-injection: question resolved as non-deterministic (env: SITL); P1/P3/P2a committed
Picked up at the exact checkpoint above. First committed the three prior milestones that had accumulated
uncommitted across sessions (`pytest`/`ruff` re-verified clean before each): live PX4 SITL ingestion (P1,
commit `cbda253`), the PX4 calibration profile (P3, `7e7631b`), and the proxy + GPS-drift attack with its
10/10 evidence (P2a, `3fb8cb6`). No code was changed to commit these - the prior checkpoint's "Open" item
above was investigated fresh.

**Resolving the open question.** Built a SITL-free diagnostic (fake high-rate PX4 traffic over real loopback
UDP, the real `CommandInjectionAttack` hook, the real `MavlinkRelay`/`LiveMavlinkSource`/`IDSPipeline`, no
SITL) - detection worked immediately there, reconfirming the prior checkpoint's "parser/extractor/detector
individually correct" finding rather than contradicting it. Reran the live SITL injection trial with one
added, independent diagnostic: `ids_ingest.jsonl`, logging every non-vehicle-sysid message the IDS's
`LiveMavlinkSource` hands to the pipeline, written **before** the pipeline sees it (never touches detector
logic). Ran 10 live SITL trials total (seed 2001; `trial_index` 0-6; `trial_index=0`'s exact draw rerun
4 times to probe repeatability): **command-path effect reconfirmed in 10/10** (PX4 accepted/acked the rogue
force-disarm every time, `MAV_RESULT_ACCEPTED`, ~7-18ms) - **but link-level detection fired in only 5/10**,
including a split result on the *identical* `trial_index=0` draw run 4 separate times (3 misses, 1 hit).
Full table, exact evidence strings, and the aggregation code: `artifacts/sitl/P2_injection_summary.md`
(generated by new `scripts/sitl/make_p2i_summary.py` - no hand-typed numbers).

**Conclusion, stated at the honesty level the evidence supports:** this is not a permanent detector miss
(the previous checkpoint already proved detector/parser/extractor logic correct in isolation) and not a
permanent fix either (5/10 includes misses after the diagnostic tap was added) - it is intermittent across
otherwise-identical live trials, consistent with the prior checkpoint's own hypothesis of a timing/concurrency
sensitivity in the live threaded UDP receive path (`UdpMavlinkTransport`'s background thread + queue) under
real load, but **not proven** to that specific cause - the only controlled variable between the "mostly
failing" first batch (trials 001-003, 0/3) and the "mostly detecting" second batch (trials 004-010, 5/7) was
adding a read-only logging statement to the trial driver, which cannot plausibly change detection logic and
can only plausibly act through timing; host load and SITL boot conditions were not held constant between
batches (not a controlled A/B experiment - disclosed in the summary's Limitations). **No claim is made that
this is fixed.** A genuine root-cause fix (if one exists beyond timing variance) is deferred - flagged as
remaining work, not closed.

**Unrelated, pre-existing experimental artifact, caught before writing up the detection numbers:** every
trial's pre-onset "false alarms" count (37-102 per trial) is **not** a benign false-alarm-rate measurement -
the topology's inert "carrier" client (sysid 252/compid 193, needed so `mirror_uplink_to_clients` has a
non-IDS uplink sender to mirror from, per the prior checkpoint's own finding) sits outside the PX4 profile's
`expected_sysids`/`expected_gcs_sysids`, so the protocol detector's rogue-telemetry-source rule correctly
flags its mirrored heartbeat on nearly every decision that observes it. This is a property of this specific
experimental harness, disclosed in `P2_injection_summary.md`'s own section, and must not be merged with the
real `docs/CALIBRATION_PX4.md` false-alarm numbers (which use no such carrier).

**Honesty note on provenance:** all 10 trials ran with 8 dirty paths in the working tree (`full_provenance.
working_tree_dirty: true, dirty_paths_count: 8` in every manifest) - primarily `scripts/sitl/
run_p2_injection_trial.py` itself (the `ids_ingest` instrumentation) and this progress doc, both uncommitted
until after the trial batch finished. Committed immediately after (see below); not a clean-commit result
until that commit lands.

**Drop / delay / replay attacks (the three remaining P2 attacks, per `docs/ATTACK_PROXY.md`'s order).**
Delegated to `aegis-security`, test-first, against the frozen `proxy/hooks.py` interface:
`DropAttack` (suppresses `GLOBAL_POSITION_INT`/`GPS_RAW_INT` downlink for a window - link-level detection
ceiling), `DelayAttack` (holds all unsigned downlink frames for a fixed per-trial delay during a window,
byte-identical/order-preserving/no-loss, release is frame-driven since the hook cannot fire on a timer - link-
level detection ceiling, explicitly flagged as "may not be detected" given the jitter-floor caveat already in
`docs/ATTACK_PROXY.md`), `ReplayAttack` (captures one legitimate unsigned uplink `COMMAND_LONG`
(`MAV_CMD_SET_MESSAGE_INTERVAL`, harmless) and re-sends the byte-identical frame 15-30s later - the documented
`command_injection:gcs_replay` gap, live; **command-path-effect ceiling only, no detection claim** - under
`require_signing: false` a replay is wire-identical to the original, so no detector signal is expected by
design; this is reserved as the P4 signing before/after baseline). New module
`src/aegisflight/proxy/attacks_live_dos_replay.py`, 48 new unit tests (no SITL needed for these - all pass
against synthetic frames over real loopback sockets), additive `groundtruth.py` effect functions, new trial
drivers `run_p2_{drop,delay,replay}_trial.py` sharing a new `scripts/sitl/p2_trial_common.py` helper (the two
existing drivers untouched). Verified independently before trusting the handback: full suite 264 tests
collected / exit 0, `ruff check src tests scripts backend` clean, `git status` touched only the owner's paths,
nothing committed by the agent. Committed as `767774b`.

**One pilot live trial each** (n=1, not the design-floor n=10 - a smoke test, not a defensible result) was
started for drop/delay/replay against live PX4 SITL immediately after; see the next entry for results once
complete.

## 2026-10-07 - Drop/delay/replay: pilot (n=1 each) live SITL trials
One pilot trial each against live PX4 SITL (seeds 3001/4001/5001, `--seconds 100`). **n=1 - a smoke test of
the new attack hooks against a real PX4, not a defensible rate**; no randomised-trial batch was run (budget).
Raw evidence: `artifacts/sitl/p2{d,l,r}_trial_001.{manifest.json,frames.jsonl,ids_decisions.jsonl}`.

- **DROP** (suppress `GLOBAL_POSITION_INT`/`GPS_RAW_INT` downlink, onset 44.18s, duration 10.98s): proxy's own
  ground truth shows 574 frames dropped (522 `GLOBAL_POSITION_INT`, 52 `GPS_RAW_INT`), 0 skipped-signed (link
  unsigned). **Clean result:** 0 false alarms in the 44.18s pre-onset portion; first `DOS` alarm at t=47.0s
  ("GPS dropout 2.1s > 2.0s"), i.e. ~2.8s after onset, continuing every decision through the window (t=55.8s,
  "10.9s > 2.0s") - exactly the hypothesised protocol `gps_dropout` rule, exactly the expected claim ceiling
  (link-level detection, SITL; PX4 itself is the sender and is unaffected). First attempt at this trial failed
  twice with "PX4 never answered the relay's heartbeat within 15s" (an environmental SITL-boot-timing issue,
  not an attack-code bug: `run_p2_drop_trial.py`'s connect sequence is identical to the already-proven
  `run_p2_trial.py`'s); a manual SITL start with an explicit readiness check before the third attempt
  succeeded immediately - recorded as a flaky-boot note, not a defect.
- **DELAY** (hold all unsigned downlink frames, onset 22.66s, duration 9.36s, delay 0.69s): 3359 frames held
  and released, mean/min/max delay all 0.690s (single fixed delay per trial, as designed). `ids_threat_decisions:
  1/500` - consistent with the attack's own documented hypothesis ("may well not be detected" given the
  existing jitter-floor caveat in `docs/ATTACK_PROXY.md`); not investigated further given n=1. Relay stats show
  `hook_errors: 1` (one exception in ~36k hook calls, fail-open-to-original per the frozen `hooks.py` contract)
  and a 240-frame gap between `frames_down` and `forwarded_down` at process-exit time, consistent with the
  attack class's own documented limitation ("if the window ends on the very last downlink frame of a capture,
  any still-held frames are stranded") rather than a new defect - **not independently confirmed** (would need a
  dedicated SITL-free `UdpMavlinkTransport`-style test asserting the exact held-frame count reaches zero after
  the run ends; not built this session, flagged as remaining work).
- **REPLAY** (capture + replay an unsigned uplink `MAV_CMD_SET_MESSAGE_INTERVAL` from sysid 252/compid 193):
  **inconclusive by design choice, reported rather than hidden.** Both the original capture's `COMMAND_ACK` and
  the replay's `COMMAND_ACK` came back `MAV_RESULT_FAILED` (not `ACCEPTED`) - the chosen "harmless" command was
  rejected by PX4 identically both times, so this pilot does **not** demonstrate the intended "PX4 accepts a
  stale replayed frame" command-path-effect claim (unlike the force-disarm command used by the proven injection
  attack, `MAV_CMD_SET_MESSAGE_INTERVAL` targeting message id 244 may simply not be a command PX4 accepts from
  an unregistered stream in this configuraton - not investigated further). Separately, the capture identity
  (sysid 252/compid 193) is **not** a real/expected GCS identity (`expected_gcs_sysids: [255, 254]` in the PX4
  profile) - so the existing protocol rogue-source rule already flags *any* command from sysid 252 regardless
  of replay, which this pilot's 10 `COMMAND_INJECTION`-evidence decisions (all clustered at t=19.2-21.0s, i.e.
  at the *capture*, not the t=38.7s *replay*) are consistent with, not a replay-specific result. This means the
  pilot as configured does not yet test the documented `command_injection:gcs_replay` gap (an unsigned link's
  inability to distinguish a replayed *legitimate-GCS-identity* command from a fresh one) - that needs the
  capture identity to be a sysid already in `expected_gcs_sysids`, which was not done here. The trial also ran
  with no concurrent benign flight driver, so GPS telemetry genuinely went stale mid-run (`DOS`, "GPS dropout
  16.9s > 2.0s" and climbing) - a real fault, not an attack artifact, but it confounds reading anything from the
  decisions around t=38.7s. **Flagged as needing a redesigned pilot before this attack's result can be trusted
  either way**, not claimed as "replay goes undetected" or "replay is detected."

**Honesty note on provenance:** these three pilots and the drop/delay/replay commit above both exist now;
`git status --porcelain --untracked-files=no` against the PX4 tree confirmed clean after all SITL work above.

**Next (unchanged from the prior entry, re-stated for the next session):** (1) decide whether to spend further
live-SITL cycles on the command-injection non-determinism's root cause (a `UdpMavlinkTransport` concurrency
test, no SITL, is still the next diagnostic step, still not built); (2) redesign the replay pilot (real
expected-GCS capture identity, a command PX4 actually accepts, a concurrent benign driver) before trusting any
detection-or-not claim about it, then run it at the design-floor n; (3) a full n=10 batch for drop and delay,
analogous to the GPS-drift attack's P2_summary.md, once (1)/(2) are resourced; (4) P4 (MAVLink 2 signing)
scoping, now that PX4's signing mechanism has been read (read-only) in the PX4 tree: runtime `SETUP_SIGNING`
key exchange (`mavlink_sign_control.cpp`), a fixed per-build allowlist of message ids accepted unsigned
(`HEARTBEAT`, `RADIO_STATUS`, `ADSB_VEHICLE`, `COLLISION`), key persisted under the SITL instance's own storage
root - no PX4 source/build changes implied, only a live `SETUP_SIGNING` message and matching signing on the
proxy/IDS side. Not started.
