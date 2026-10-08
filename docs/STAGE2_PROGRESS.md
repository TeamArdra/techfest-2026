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
trial's pre-onset "false alarms" count (37-102 per trial) is **not** a benign false-alarm-rate measurement.
**Correction (caught by `aegis-reviewer`, not by the original write-up):** the first draft of this entry
blamed this solely on the inert "carrier" client (sysid 252/compid 193, needed so `mirror_uplink_to_clients`
has a non-IDS uplink sender to mirror from) - that client does sit outside the PX4 profile's
`expected_sysids`/`expected_gcs_sysids` and does trigger the protocol detector's rogue-telemetry-source rule
on its mirrored heartbeat, but it is not the only such source: the benign flight-driver client (sysid
253/compid 192, `data/sitl/raw/p2i_driver_*.json`, `"role": "GCS sysid=253 compid=192"`) is *also* outside
`expected_gcs_sysids: [255, 254]` and triggers the identical rule independently. In trial_005's pre-onset
portion the two contribute almost equally (49 decisions cite only sys252, 48 cite only sys253, 5 cite both);
`P2_injection_summary.md`'s "carrier-artifact decisions" column counts only the sys252 occurrences and so
understates the total taint by roughly 2x. Neither source affects the `COMMAND_INJECTION`-type evidence
(keyed to sys66/comp200, verified distinct) or the 5/10 / 10/10 headline numbers - this is a property of this
specific experimental topology (an uplink-mirroring harness needs non-IDS uplink clients, and this topology
happens to have two that are both outside the PX4 profile's expected-identity lists), not a general benign
false-alarm measurement, and must not be merged with the real `docs/CALIBRATION_PX4.md` false-alarm numbers
(which use neither client).

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
`src/aegisflight/proxy/attacks_live_dos_replay.py`, 46 new unit tests (the building agent's handback said 48;
`grep -c "^def test_"` on the file gives 46 - corrected by `aegis-reviewer`'s check; no SITL needed for these,
all pass against synthetic frames over real loopback sockets), additive `groundtruth.py` effect functions, new trial
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

## 2026-10-07 - P2 command-injection nondeterminism: root cause found, it is NOT the transport  (env: SITL artifacts + SIM-free loopback reproduction)
Bounded investigation (no SITL started, no live trials run, no `src/` change). Question asked: "can the real threaded
`UdpMavlinkTransport` reliably deliver a rare command frame inside a high-rate stream?"  Answer: **yes**, and the
concurrency hypothesis recorded in the entries above is **not supported**. The 5/10 detection split has a different,
deterministic mechanism in the **relay's uplink-mirror topology**.

**Proven (reproduced SITL-free with the real components; deterministic test committed):**
- `MavlinkRelay(mirror_uplink_to_clients=True)` mirrors an uplink frame - and everything the hook returns with it, including
  the attack's injected `COMMAND_LONG` - to every client **except the frame's sender** (`proxy/transport.py` `_handle_up`,
  `others = [a for a in self._clients if a != addr]`). `CommandInjectionAttack` piggybacks on **whichever** uplink frame comes
  next after its gap. The trial topology has two heartbeating uplink clients: the inert carrier (252/193) **and the IDS tap
  itself (254/191, `UdpMavlinkTransport(gcs_heartbeat=True)`)**. When the IDS's own heartbeat is the carrier, PX4 receives the
  injection (command-path effect unaffected) but the IDS is excluded from the mirror and never sees it. The trial script's
  comment (`run_p2_injection_trial.py` ~L120-126) assumed adding the carrier client removed this; it only made it ~50/50.
  Which client carries an injection depends on the 1 Hz heartbeat phase between the two loops, set by process start-up
  timing - hence run-to-run variation on identical `(seed, trial_index)` draws.
- Committed tests: `tests/unit/test_mavlink_live_concurrency.py` - (1) real threaded transport + `LiveMavlinkSource`, ~600 fps
  + 12 rare tagged commands, CPU-burning consumer: 12/12 delivered once, in order, no overflow/bad/late frames; (2) positive
  control: carrier = other client -> IDS receives the injection; (3) **strict xfail**: carrier = IDS -> IDS does not receive it
  (fails at exactly that assertion; PX4 does receive it); (4) real relay + real attack + two heartbeating clients over real
  sockets/threads: every injection not carried by the IDS reaches it exactly once, in order.
- Scratch experiment (SITL-free, real relay/attack/transports/`IDSPipeline` with the PX4 profile + PX4 model, fake PX4 at ~390
  fps, recording wrapper logging each injection's carrier sysid; **script not committed, numbers are not a generated artifact**,
  4 runs, hb 5 Hz, gap 0.3 s): injections carried by the IDS's heartbeat 155, received by IDS **0**; carried by the other
  client 139, received **139**; IDS command-source evidence appeared only in runs/ticks where frames were received. Per-run
  carrier split varied (26/44, 68/4, 24/58, 37/33) with heartbeat phase.
- Transport load limits (scratch, same caveat): consumer CPU alone (up to 85 ms per 100 ms tick) lost nothing. Adding 3
  GIL-hogging pure-Python threads in the IDS process starved the receive thread and ~93% of datagrams were dropped
  **silently** (`dropped_overflow` stays 0 - kernel-side drop). Not the live regime (all 10 live trials: `late_ticks: 0`; a
  hand reconciliation of IDS `datagrams_received` against relay `forwarded_down - down_no_client` + mirrored frames, done for
  trials 003/004/009/010 only, agreed to within ~5-8 frames of ~36k - too coarse to exclude a single lost frame), but it is
  an uncounted failure mode worth a counter.

**Consistent with, but NOT directly observed in, the 10 live trials** (the carrier of each live injection was not logged):
in every trial with a tap, each `sysid 66` frame the IDS saw coincides (<0.5 ms) with a carrier-252 heartbeat
(`artifacts/sitl/p2i_trial_00{4..8}.ids_ingest.jsonl`); trials 009/010 saw 0 of 4 / 3 injections
(`.frames.jsonl` vs `.ids_ingest.jsonl`); relay stats show `mirrored_up` firing in all of them and no bulk datagram loss.
The earlier "0/3 without tap vs 5/7 with tap" split is therefore most likely heartbeat-phase luck, not an effect of the tap
(not independently shown). A post-hoc attempt to attribute individual unseen injections in trials 005/006 to a carrier by
clock-offset anchoring was **ambiguous and is discarded** as evidence.

**Hypothesis, not proven:** that the missed live injections were all IDS-carried. It is the only mechanism found that
explains them and is shown to exist; confirming it on live data needs the carrier logged in a rerun.

**Consequence for claims:** the live "5/10 detected" is a harness-topology artefact, not a statement about the detector or
transport. It must not be reported as a detection rate, nor as a detector miss. `P2_injection_summary.md`,
`make_p2i_summary.py` (L98) and `VALIDATION_EVIDENCE.md` still state the disproven concurrency hypothesis - to be corrected by
the validation owner (generated artifact; not edited here).

**Proposed smallest fix (NOT applied; relay semantics change, needs approval):** in `_handle_up`'s mirror branch, mirror a hook-added
frame (`raw != fr.raw`) to all clients and keep sender-exclusion only for the original frame. Checked in a scratch
monkeypatch only: IDS receives the injection in both carrier cases, a sender never gets an echo of its own frame, original
frames still mirror to the others. (Note `fr` is a `_Frame`; compare against `fr.raw`.) Alternative with no relay change:
have the IDS tap register once and stop sending heartbeats. After either, remove the strict-xfail marker, then rerun the
injection trials (and log the carrier) before any detection claim.

Gate: `pytest` 272 passed + 1 xfailed (the xfail is the pinned gap above); `ruff check src tests scripts backend` clean;
PX4 tree not touched; nothing committed.

## 2026-10-07 - P2 command-injection: relay mirror fixed, live re-validation 10/10  (env: SITL; claim: link-level detection + command-path effect)
Approved follow-up to the root-cause entry above. **Fix (`src/aegisflight/proxy/transport.py`, `_handle_up`, opt-in
`mirror_uplink_to_clients` branch only):** a frame the hook created or modified (`raw != fr.raw`) is now mirrored to
**every** client, the carrier's sender included; an unmodified original is still mirrored to everyone **except** its
sender (no self-echo). Default-off behaviour is untouched. Tests: the strict xfail was removed and is now a passing
regression (`test_ids_sees_injected_frame_even_when_its_own_heartbeat_is_the_carrier`); added no-self-echo (both client
orderings) and hook-modified-frame tests; the live-chain test now asserts every injection reaches the IDS whichever
client carries it. One existing test (`test_proxy_transport.py::test_mirror_uplink_to_clients_when_enabled_excludes_sender`)
encoded the old semantics for the hook-added frame and was updated to the new contract (the sender still gets no echo of
its own original frame). `run_p2_injection_trial.py` now records the carrier sysid of every injection and the rogue seq per
ingest-tap line (additive manifest keys `injection_carriers`, `relay_mirror_semantics`); detector thresholds, model, profile
and attack parameter draws are unchanged.

**Re-validation (`artifacts/sitl/p2i_fix_trial_001..010`, generated summary `artifacts/sitl/P2_injection_summary.md`):** same
methodology as the pre-fix batch - seed 2001, `trial_index` 0-9, **fresh PX4 SITL boot per trial**, `configs/px4_sitl` + PX4-trained
model (`model_sha256` 3fe74cdd...), `--seconds 100`, benign driver 253/192, carrier 252/193, PX4
`v1.18.0-rc1-27-gc239c63807`. Results (all from the generated summary):
- **Command-path effect (SITL): PX4 acked the rogue force-disarm 10/10** (`MAV_RESULT_ACCEPTED`).
- **Link-level detection (SITL): command-injection evidence ("command(s) from unexpected source sys66/comp200") in 10/10 trials**,
  0 command evidence before onset in any trial, latency from onset 0.21-0.92 s.
- **Harness delivery: 37/37 injected frames reached the IDS pipeline input** (rogue seq 0..n-1 exactly once per trial,
  independently recounted from raw logs). Carriers: 25 on the IDS tap's own heartbeat (254) - exactly the case that was
  invisible before the fix - and 12 on the carrier client (252). Eight of ten trials contained at least one IDS-carried
  injection; all were delivered and detected.
This is the live confirmation of the root cause: the same seed family (`trial_index` 0-6 are identical draws to the pre-fix
batch; 7-9 are new draws) that gave 5/10 now gives 10/10 once the mirror delivers the frame. It is **not** a transport or detector change. Pre-fix batch retained as superseded evidence (it reached the ingest
tap with only 11/25 injected frames in the 7 trials that had one).

**Ceiling / limitations (kept next to the claim):** link-level on a mirrored bump-in-the-wire tap (a harness choice); the
attack uses a *rogue* sysid (66) outside the profile's expected identities, so this shows the protocol rule's source-identity
check works, not detection of an injection impersonating an expected GCS (255/254) or a replayed legitimate command
(`command_injection:gcs_replay`, P4); n=10 is the design floor, reported as counts; one airframe/world/host; unsigned
link; the carrier/driver rogue-source decisions are a harness artifact, not a false-alarm rate. Provenance: commit
`e0b28d7` with 3 dirty paths under `src`/`scripts` (the uncommitted relay fix + the two script edits) - not a clean-commit
reproduction until committed. Trial 010 had 26 late ticks (host load in the IDS consumer); its 4/4 injections still arrived
and were detected. PX4 tree verified clean (0 tracked modifications) after the batch; SITL stopped.

**Stale statements corrected:** `scripts/sitl/make_p2i_summary.py` (now computes delivery per injection and separates the
pre-/post-fix batches), `artifacts/sitl/P2_injection_summary.md` (regenerated), `docs/VALIDATION_EVIDENCE.md` (post-fix claim
row + superseded pre-fix row + roadmap item 7 + not-claimed list). Earlier entries in this log are left as written (append-only).

**Gate:** `pytest` 276 passed, 0 xfailed; `ruff check src tests scripts backend` clean; Stage-1 regression
(`aegis benchmark --out <scratch> --no-figures`) TP/FP/TN/FN **6535 / 4 / 16826 / 65**, identical to the committed baseline
(`artifacts/benchmarks/summary.md`; committed artifacts untouched). Nothing committed or pushed.

**Current Stage-2 checkpoint (superseded by the two entries below):** P0 done; P1 live ingestion done; P3 PX4 calibration done; P2: GPS-drift 10/10, command injection
10/10 (this entry), drop/delay/replay at pilot n=1 only. Open: n=10 batches for drop and delay; replay pilot needs redesign
(expected-GCS capture identity, a command PX4 accepts, concurrent driver); injection impersonating an expected GCS sysid;
counter for silent kernel-side datagram loss in `UdpMavlinkTransport`; then P4 signing (not started). Commits for P1/P3/P2a and
drop/delay/replay exist; this relay fix, tests, script/doc/artifact updates and the `p2i_fix_trial_*` evidence are uncommitted.

## 2026-10-08 - Drop/delay n=10 live SITL; DelayAttack backlog-flush bug fixed (env: SITL)
Continuing autonomously from the checkpoint above (relay-mirror fix for command injection already committed
`4a43ad9`). Ran full n=10 live SITL batches for the two remaining undersampled P2 attacks, fresh PX4 boot per
trial, seed 3001 (drop) / 4001 (delay), `--seconds 100`.

**DROP** (suppress `GLOBAL_POSITION_INT`/`GPS_RAW_INT` downlink): **10/10 detected** (`DOS`, "GPS dropout"),
**0 false alarms** in 1972 pooled pre-onset decisions, median latency 2.76s (min 2.22, max 2.89). Clean result,
matches the n=1 pilot's hypothesis exactly. `artifacts/sitl/P2_drop_summary.md` (generated by new
`scripts/sitl/make_p2dd_summary.py`), `artifacts/sitl/p2d_n10_trial_*`.

**DELAY** (hold every unsigned downlink frame a fixed per-trial delay, release in order): the first live
attempt at n=10 immediately exposed a real bug, not caught by the n=1 pilot or the 46 unit tests: when the
attack's onset window closes, the old code flushed **every** still-held frame in one hook-call return. At
PX4's ~340-380 msg/s the backlog at window-close is hundreds of frames; the relay's hook-output cap is 64
frames per call (`proxy/transport.py` `_MAX_HOOK_FRAMES`), so the relay rejected the oversized return and fell
back to forwarding only the original live frame — **every held frame in the backlog was silently dropped**,
never forwarded at all. (The n=1 pilot's `hook_errors: 1` and 240-frame `frames_down`/`forwarded_down` gap,
flagged then as "not independently confirmed", **was this bug** — now confirmed and fixed, not just
suspected.) **Fix** (`attacks_live_dos_replay.py::DelayAttack`): the end-of-window flush is removed; held
frames keep their natural per-frame release time, drained at most 63 per hook call (`_MAX_RELEASE_PER_CALL`),
with any live frame arriving while a backlog remains queued behind it to preserve order. Guarantee (tested):
every held frame is forwarded exactly once, byte-identical, in order, never dropped — now true under PX4-rate
backlogs, not only the light synthetic load the original 46 tests used. New tests added
(`test_proxy_attacks_live_dos_replay.py`); full re-check: 280 passed, `ruff` clean.

Re-ran delay at n=10 with the fix: **9/10 detected** — via a `DOS` "message-rate spike" (1.9x-5.1x nominal)
as the drained backlog arrives in a burst, 7.7-12.5s after onset — **not** the originally-hypothesised
per-frame-jitter mechanism (`docs/ATTACK_PROXY.md` Sec2's jitter-floor caveat was about the wrong signal; the
real signal is a rate spike from bursty release, which the fix's per-call cap makes gradual but still
detectable). The one miss (`p2l_n10_trial_009`) drew the smallest delay in the batch (0.355s) — too small a
backlog to produce a detectable burst, a legitimate negative result, not investigated further at n=10. 1
false alarm in 1854 pooled pre-onset decisions. `artifacts/sitl/P2_delay_summary.md`,
`artifacts/sitl/p2l_n10_trial_*`. Both summaries' scoring rules (GPS-dropout evidence for drop; any threat
decision in a bounded post-onset window for delay) were fixed before reading either n=10 batch's results.

**Gate:** 280 passed, `ruff check src tests scripts backend` clean; nothing run against the Stage-1 benchmark
yet this entry (deferred to the P2-consolidation entry below, which touches no detector code further).
Committed as `099b896`.

## 2026-10-08 - Replay-v2 (expected-GCS identity): redesigned, run at n=10, a genuine positive result via an unanticipated mechanism (env: SITL)
Picked up the explicitly-flagged redesign task: the original replay pilot captured from a non-GCS identity
(sysid 252) using a command PX4 rejected both times — neither tests the documented
`command_injection:gcs_replay` gap. Redesigned per the task brief: capture a legitimate, unsigned
`COMMAND_LONG` (the same proven-accepted force-disarm) from sysid 255/compid 190 — an **expected GCS
identity** (`expected_gcs_sysids: [255, 254]`) — then replay the byte-identical captured frame 15-30s later.
Driver already existed in skeleton form (`run_p2_replay_v2_trial.py`) from the prior session; two harness
bugs were found and fixed before trusting any result from it, both by a single n=1 diagnostic run against
live SITL before committing to a full batch (per the task's own instruction to fix the harness, not abandon
the experiment, when a diagnostic exposes one):

1. **IDS-tap-registration-order bug**: the original script sent the one legitimate capture command *before*
   creating the IDS's own tap connection, so the IDS could never see the original command (only the later
   replay) — an artifact of script ordering having nothing to do with detection. Fixed: the IDS tap now
   registers with the relay first.
2. **Independent per-client sequence counters**: the hand-rolled capture frame used a fixed `seq=0` via a
   throwaway encoder, unrelated to the capture client's own heartbeat sequence counter — an unrealistic
   topology (a real GCS has exactly one running sequence counter for everything it sends). Fixed: added
   `UdpMavlinkTransport.send_gcs_message()` (new, shares the transport's existing heartbeat seq counter and
   lock, tested in `test_mavlink_live.py`), and the capture now heartbeats for 3s first so its command carries
   a realistic mid-stream sequence number.

**The n=1 diagnostic after both fixes immediately showed something not designed for or anticipated**: a
`MAVLINK_ANOMALY` ("sequence gap 236 > 30") fired within 0.1s of the replay. Traced to its exact mechanism
before trusting it (not detector-tuning — nothing in `detectors/` or `configs/` was touched): the replayed
frame carries sysid 255's **old** MAVLink `seq` (byte-identical replay, by design), but the real GCS identity
has kept heartbeating in the meantime, so its *own* running counter has moved on. `FeatureExtractor`'s
per-source gap is `(seq - prev) % 256`; replaying an older seq while the real counter has advanced by `delta`
always computes to `256 - delta` (backward wraps to "almost all the way around" in mod-256 arithmetic) — at
this attack's 1Hz capture-client heartbeat and 15-30s replay-delay range, `delta` is ~15-30, giving a gap of
~225-240, always above `max_seq_gap: 30`. This is **not** the identity/provenance rule the attack's own
docstring says can never fire for an expected-GCS sysid (confirmed: it indeed never does, 0/10
`COMMAND_INJECTION` evidence below) — it is a different, pre-existing, unmodified Stage-1 rule
(sequence-continuity) picking this up by an orthogonal mechanism. Worked out analytically (not just observed)
*before* running the n=10 batch, so the scoring rule in the new `scripts/sitl/make_p2r_v2_summary.py` was
fixed ahead of reading that batch's results, per the task's rule against post-hoc tuning.

**n=10 result** (seed 5101, fresh SITL boot per trial; one boot timeout at `trial_index=1`, a known flaky-boot
environmental issue — retried once, succeeded): **10/10 harness delivery** (both capture and replay reached
the IDS pipeline), **10/10 command-path effect** (PX4 `MAV_RESULT_ACCEPTED` on both the original and the
replay), **10/10 link-level detection via the sequence-gap mechanism**, **0/10** identity-rule evidence
(confirms the documented gap holds for *that* rule exactly as written), **0** false alarms in 160 pooled
pre-replay decisions. Clean, deterministic, analytically explained result — not a lucky draw: the math above
holds for the entire drawn delay range, and all 10 independent draws (17.5-29.9s) confirm it.
`artifacts/sitl/P2_replay_v2_summary.md` (generated by `make_p2r_v2_summary.py`), `artifacts/sitl/p2r_v2_trial_*`.

**What this is and is not evidence for (stated at the honesty level the task requires):** this is real,
live, link-level detection of a real replay attack via a genuine (if serendipitous) existing mechanism — not
a fabricated or cherry-picked result. It is **not** a fix for the `command_injection:gcs_replay` gap in
general: the mechanism depends specifically on (a) the attack being a byte-identical replay (so it carries a
stale sequence number at all — a *fresh forgery* using the expected GCS identity would not), (b) the real GCS
identity continuing to heartbeat between capture and replay (so there is a "current" counter to fall behind),
and (c) the delay staying well under ~225s at 1Hz heartbeat given the current threshold. None of these were
tuned to produce the result — all three are properties of the already-fixed attack design and already-existing
unmodified detector config. The next, harder, and more representative question for the authentication gap —
a *fresh* forged command from the expected GCS identity, not a replay — is designed but not yet run (see
Stage-2 roadmap item 7 below).

New script: `scripts/sitl/run_trial_batch.sh` (reusable fresh-SITL-boot-per-trial runner for any P2 driver,
used for this batch and reusable for the next). Gate: 281 passed (one new test for
`send_gcs_message`), `ruff check src tests scripts backend` clean.

**Current Stage-2 checkpoint (superseded by the entry below):** P0/P1/P3 done. P2 live SITL: GPS-drift 10/10, command injection 10/10
(post relay-mirror fix), drop 10/10, delay 9/10, replay-v2 (expected-GCS identity) 10/10 via the
sequence-continuity mechanism (not identity). Open: a fresh-forgery expected-GCS-identity command (no replay,
no stale sequence) — the harder, more representative authentication-gap test; silent kernel-side datagram-loss
counter in `UdpMavlinkTransport`; then P4 MAVLink-2 signing (scoped, not started).

## 2026-10-08 - Expected-GCS impersonation (fresh forgery, not replay): the real authentication gap, confirmed live with a clean two-variant contrast (env: SITL)
The harder, more representative question flagged at the end of the replay-v2 entry: an attacker that *forges*
a `COMMAND_LONG` from scratch, stamped with the expected GCS identity (sysid 255/compid 190), rather than
replaying a captured one. A fresh forgery carries no stale sequence number by construction, so the
sequence-continuity mechanism that caught the replay (previous entry) is not guaranteed to catch this — the
central question this entry answers.

**Design** (two attacker strengths, run as separate n=10 batches, so the contrast is the evidence, not a
single number): added `seq_policy` to `CommandInjectionAttack` (`src/aegisflight/proxy/attacks_live.py`,
default `"own_counter"` — unchanged Stage-1-identical behaviour, opt-in only). `"own_counter"` (**naive**
attacker) keeps its own rogue MAVLink sequence counter from 0, same as the existing rogue-sysid-66 injection
attack, just pointed at sysid 255/190 instead. `"track_identity"` (**informed** attacker) passively reads the
*real* 255/190 heartbeat's running sequence number off the clear-text link (no signing on this link) and
stamps each forged command with exactly the next value that identity would send — modelling an attacker who
can read the link (the MITM position this proxy already assumes) continuing the real counter instead of
running a second, inconsistent one. Fails closed until one real frame from that identity has been observed
(`frames_skipped_no_identity_seq`). 9 new unit tests (`test_proxy_command_injection.py`): both policies'
seq behaviour, wraparound, carrier-independence, fail-closed, signed-frame exclusion, invalid-policy rejection.

New driver `run_p2_gcs_impersonation_trial.py`: topology has no rogue "carrier" client and no flight driver
(vehicle disarmed on the ground) — a scripted legitimate 255/190 GCS client plus the IDS tap (registered
first, learned from the replay-v2 harness fix), so there is no rogue-source harness noise to confound the
result. New generated summary `make_p2g_summary.py` scores, PER THE TASK'S OWN FRAMING, four questions
separately and never merges them: did the forged command reach PX4 and was it accepted (command-path
effect); did it reach the IDS (harness delivery); did the forgery actually achieve sequence continuity (an
attack-implementation check, not a detection result); did any rule fire, and specifically which one. All
hypotheses were written into each manifest's `expected_effect` and the scoring script's docstring before the
n=10 batches ran (one `track_identity` pilot trial was run first specifically to catch harness bugs before
committing to the full batch — none were found this time).

**Result (seed 6101, fresh SITL boot per trial, `--seconds 100`, 0 boot failures across 20 trials):**

| | command-path effect | harness delivery | seq continuity achieved | any detection | identity rule | seq-gap rule |
|---|---|---|---|---|---|---|
| **naive** (own_counter) | 10/10 ACCEPTED | 10/10 (33/33 frames) | 0/33 | **10/10** | 0/10 | **10/10** |
| **informed** (track_identity) | 10/10 ACCEPTED | 10/10 (33/33 frames) | 33/33 | **0/10** | 0/10 | 0/10 |

`artifacts/sitl/P2_gcs_impersonation_summary.md` (generated by `make_p2g_summary.py`), `artifacts/sitl/p2g_{inf,naive}_trial_*`.

**Reading this honestly, at the level the task demands:** both variants are an unauthenticated forged
force-disarm from an identity the profile trusts, and PX4 accepts it every time in both — the command-path
effect is identical and is not the interesting part. The identity/provenance rule never fires in either
variant, exactly as the SITL-free regression (`test_px4_profile.py`) already proved it cannot. The
*difference* is entirely in the sequence-continuity rule, and it is a clean, deterministic split: the naive
attacker's forged frames collide with the real GCS's own advancing counter (10/10, same mechanism, same
"256 - delta" wraparound arithmetic as the replay-v2 entry) and get caught; the informed attacker's forgery
is indistinguishable from the real counter by construction and gets **zero** detector signal across all 10
trials, all 33 forged frames, despite every one being accepted by PX4. **This is the real authentication gap
Stage-2 P4 is meant to close** — not "can an attacker inject a command" (already shown, rogue-sysid injection
and both GCS-impersonation variants all land it), but specifically "can an attacker impersonate a *trusted*
identity convincingly enough that no current signal distinguishes it from the real one" — yes, if the
attacker can read the link (which this proxy's MITM position already assumes), the current link only offers
sequence continuity as an incidental, non-cryptographic obstacle, and an attacker who can read traffic can
trivially defeat it. No detector code or threshold was changed to produce or avoid either result.

**What this is not evidence for:** no claim about a remote attacker who cannot observe the link (the informed
variant specifically assumes MITM read access, already the proxy's standing assumption, not a new one);
no vehicle-behaviour or estimator claim (ground vehicle, ACK-only observable); no claim that signing is the
*only* possible mitigation (a dedicated duplicate/replay-window check was not implemented or tested here).

**Gate:** 291 passed, `ruff check src tests scripts backend` clean. Stage-1 regression not re-run this entry
(the change is additive, opt-in attack-simulation code in `proxy/attacks_live.py` plus one new transport
method already regression-checked in the prior entry — neither touches `detectors/`, `features/`, `fusion/`,
or `pipeline.py`; the gate's own rule scopes the 9-minute benchmark re-run to detector/pipeline changes).

**Current Stage-2 checkpoint (superseded by the entry below):** P0/P1/P3 done. P2 live SITL fully populated: GPS-drift 10/10, command
injection 10/10, drop 10/10, delay 9/10, replay-v2 10/10 (sequence-continuity mechanism), GCS impersonation
naive 10/10 detected / informed 0/10 detected (this entry — the real, confirmed authentication gap). Next:
P4 MAVLink-2 signing, scoped (PX4 runtime `SETUP_SIGNING`, no PX4 build changes needed) but not started —
this entry's informed-attacker result is its "before" baseline.

## 2026-10-08 - P4 MAVLink-2 signing: scoped, an AegisFlight-side verification capability added, live "before/after" pilot closes the impersonation gap (env: SITL + SITL-free unit tests)
Per the task's own ordering ("first scope and understand... before implementing anything; prefer an
AegisFlight-side/integration-level implementation first"), scoping came before any code change.

**Scoping findings (read-only in both the PX4 tree and `pymavlink`; no PX4 source or build change):**
1. **A real, previously-undisclosed-as-such correctness gap in this codebase's own "signed" notion.**
   `MavlinkFrameParser`/the proxy's `FrameContext.signed` have always meant "the MAVLink-2 incompat
   *signing* bit is set" — the trailing 13-byte signature is parsed over and skipped, **never
   cryptographically checked against a key**. `require_signing: true` (`configs/detector.yaml`) would
   therefore only ever verify that every frame *claims* to be signed, not that any signature is valid — an
   attacker who sets the bit and appends 13 garbage bytes passes it completely. Confirmed by direct code
   reading, not by a bug report. `MessageEnvelope.signed` (frozen field) keeps this exact, existing meaning
   unchanged — no frozen-contract change was made or needed.
2. **PX4's own mechanism** (`src/modules/mavlink/mavlink_sign_control.{h,cpp}`, `mavlink_main.cpp`, read-only
   in the WSL tree): a live `SETUP_SIGNING` MAVLink2 command (32-byte secret + 8-byte initial timestamp) sets
   the link's key; **PX4 accepts the FIRST non-blank key unconditionally** (it does not need to already be
   signed — only a later *disable*, a blank key, must be signed with the current key) — a disclosed
   "trust-on-first-contact" bootstrap, not a hardened handshake, and not an AegisFlight choice. `SETUP_SIGNING`
   is **rejected while armed** (`mavlink_main.cpp`). The key persists to a file under the SITL instance's own
   isolated run directory (confirmed: `~/aegis_sitl/i2/mavlink/mavlink-signing-key.bin`, NOT inside the PX4
   tree — survives a PX4 restart within the same instance, found live, see pilot note below) and is reloaded
   at boot. Once initialized, **PX4 signs ALL of its own outgoing traffic**, not just what it is willing to
   accept unsigned from others (`_update_signing_state` sets `SIGN_OUTGOING` link-wide) — found live, not
   anticipated (see pilot note). Only `HEARTBEAT`, `RADIO_STATUS`, `ADSB_VEHICLE`, `COLLISION` are accepted
   unsigned once a key is active (`unsigned_messages[]`); `COMMAND_LONG` is not among them.
3. **`pymavlink` already implements the real algorithm** (`MAVLink.check_signature`/`sign_packet`:
   HMAC-SHA256 over the frame, truncated to 6 bytes, plus a per-stream monotonic-timestamp anti-replay
   check) and wires it into `decode()` automatically once `signing.secret_key` is set, raising on a bad or
   policy-violating signature — the primitive the implementation below uses directly rather than
   reimplementing.

**Implementation (additive; default behaviour unchanged for every existing caller without a key):**
- `MavlinkFrameParser(..., secret_key: bytes | None = None, unsigned_allowed_msgids=...)`: with a key, every
  claimed-signed frame is now REALLY verified via `pymavlink`'s own `decode()` signing path (not the bit
  alone); an unsigned frame for a message not on the allowlist is now also rejected, mirroring PX4's own
  policy. New `LiveStats.sig_valid`/`sig_invalid` counters (additive dataclass fields, not on the frozen
  `MessageEnvelope`). No key -> byte-for-byte unchanged behaviour, confirmed by the regression below.
- `UdpMavlinkTransport(..., sign_secret_key=None, sign_link_id=0, sign_initial_timestamp=0)` plus
  `enable_signing()` and `send_gcs_message` signing a frame when a key is configured, with a timestamp that
  strictly advances across the transport's whole lifetime (required for `pymavlink`'s own anti-replay check
  to accept it) — tested for correctness (timestamp advance, wrong-key rejection, allowlist, replay-rejection,
  bad key length) in `test_mavlink_live.py`, no SITL. New free function `send_setup_signing()` sends the
  bootstrap command unsigned (by construction, since no key exists yet on either side).
- 15 new unit tests; gate: 304 passed, `ruff check src tests scripts backend` clean; Stage-1 regression
  (`aegis benchmark --out <scratch> --no-figures`) **TP/FP/TN/FN 6535 / 4 / 16826 / 65, identical** to the
  committed baseline — confirms the change is inert without a key, as designed.

**Live pilot (n=1; a first attempt at a brand-new capability, same convention as every other new attack this
Stage-2 effort has built): does signing change the outcome of the informed-impersonation attack that
defeated every detection mechanism (0/10 detected, 10/10 ACCEPTED by PX4, prior entry)?**
1. First attempt: the attack's own passive target-learning (refuses to trust an unverified signed bit, by
   design) never learned PX4's identity once PX4's own downlink became signed (finding 2 above) ->
   `frames_injected` stayed 0 for the whole trial. Not a bug to hide — documented and bypassed by passing
   the already-known target identity explicitly (irrelevant to what this experiment measures: PX4's
   acceptance of an unsigned forged command, not the attack's own passive-learning mechanism).
2. Second attempt reused the same isolated SITL run directory; PX4 booted with signing **already** active
   from the first attempt's persisted key file (finding 2 above) — the outcome matched the hypothesis, but
   attribution to *that* trial's own handshake was ambiguous, so it is kept as a disclosed diagnostic
   (`artifacts/sitl/p4_sign_diag_persisted_key_001.*`), not the evidence trial.
3. Clean rerun, persisted key file removed first (confirmed by PX4's own log showing `MAVLink signing key
   accepted` exactly once, this run): **result** --
   - `SETUP_SIGNING` sent unsigned, bootstrap succeeded (PX4 log confirms).
   - The legitimate GCS's **signed** resend of the proven-accepted force-disarm: **ACCEPTED**
     (`MAV_RESULT_ACCEPTED`, confirmed signed on the wire) — signing does not break real operation.
   - The **exact same informed-impersonation attack** (sysid 255/190, correctly-tracked sequence,
     `CommandInjectionAttack(seq_policy="track_identity")`, unchanged from the prior entry's 10/10-ACCEPTED
     result) forged and delivered 2 unsigned `COMMAND_LONG` frames to PX4 (confirmed via the proxy's own
     frame log) -- **0/2 acknowledged**. No ack at all (not a rejection *result*, no response whatsoever),
     consistent with PX4's own mavlink library dropping an unsigned, non-allowlisted message before
     `handle_message` ever sees it.
   `artifacts/sitl/p4_sign_trial_001.*` (clean evidence trial), `artifacts/sitl/p4_sign_diag_persisted_key_001.*`
   (superseded diagnostic, kept per the project's "preserve negative/ambiguous results" rule).

**Reading this at the honesty level the task demands:** this is **one** live trial, not the n=10 design
floor the rest of P2 uses — a pilot, explicitly. It is a real, measured "before -> after" flip on the exact
attack that was previously undetected and unauthenticated (10/10 ACCEPTED, 0/10 detected -> 0/10 ACCEPTED),
using PX4's own, unmodified signing mechanism and an AegisFlight-side verification capability that changes
nothing without a key. **Not claimed:** a statistically powered rate (n=1); that signing is the only
mitigation needed (the naive-forgery / replay cases were already independently caught by the
sequence-continuity rule without signing); that this is secure against an attacker present *before* the
legitimate GCS's bootstrap `SETUP_SIGNING` (the disclosed trust-on-first-contact property is PX4's own, not
fixed here); that the IDS's own live pipeline is wired to a signed source in this trial (it is not -- this
pilot measures PX4's own acceptance, a command-path effect, not an IDS detection outcome); any production
key-management, rotation, or storage design (the key here is a fixed test value, not security-sensitive, and
is never logged or committed in a production sense -- it is written into this trial's own public manifest
for reproducibility of a test-only scenario, same convention as citing a test secret in code).

**Current Stage-2 checkpoint:** P0/P1/P3 done. P2 live SITL fully populated and consolidated. P4: scoped
(PX4 mechanism, pymavlink primitives, and this codebase's own prior signed-bit-only gap all documented);
an additive, default-off verification/signing capability added and unit-tested; one live pilot shows the
informed-impersonation gap closes (10/10 ACCEPTED -> 0/10 ACCEPTED) once signing is bootstrapped and active.
Next: an n=10 batch of this same pilot for a defensible rate; the IDS's own live IDSPipeline is not yet
wired to verify signatures itself (this pilot showed PX4's own rejection, not an IDS detection path) --
natural next step is a `require_signing`-aware detector rule using the new `sig_invalid` counter; then
Stage-2 step 5 (hardware/companion-computer integration assessment).

**Hardware-readiness assessment (bounded; no implementation, per the task's own caution against starting
this prematurely):** the existing `sources/mavlink_live.py` `FrameTransport` Protocol
(`poll() -> list[(recv_ns, datagram)]`, `close()`) is the only interface `LiveMavlinkSource` ->
`IDSPipeline` depends on; `UdpMavlinkTransport` is one implementation of it. A serial transport for a real
flight controller / companion-computer link (the next item in the Stage-2 roadmap, `PX4 SITL -> physical
flight controller -> MAVLink -> companion computer -> AegisFlight`) would only need to implement the same
two methods and could be unit-tested without hardware in hand (a pty-backed or loopback-serial double, the
same no-SITL-needed pattern already used throughout this session's unit tests) before ever touching a real
device. **No redesign is required**, confirming the architecture note in `.claude/CLAUDE.md`
("the existing source abstraction should remain reusable"). Not started: no hardware has been purchased or
assessed as needed yet — nothing in the current checkpoint requires it to make further progress; the next
concrete, hardware-free step would be exactly that serial-transport implementation, test-first, SITL-free.
