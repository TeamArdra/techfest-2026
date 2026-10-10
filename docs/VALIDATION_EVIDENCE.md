# What AegisFlight has evidence for — and what it does not

This page is the honesty check for the report and the demo. Quote numbers only from the
generated files it links (`artifacts/**/summary.md`, `artifacts/validation/validation_table.md`).

## 1. Real evidence (measured on real, public flight data)

| Claim we can make | Evidence |
|---|---|
| The IDS pipeline ingests **genuine recorded MAVLink telemetry** (ground-station `.tlog`, real radio link timing, sequence numbers, source ids) and runs end-to-end unchanged, via an adapter only | ALFA replay, `artifacts/external/alfa/summary.md` |
| With the **production (simulator-calibrated) configuration**, the IDS raises an alarm on essentially every decision of a real link — the simulated false-positive rate does **not** transfer | same file: fused threat rate on author-labelled benign periods; top evidence = message-rate spike + ML |
| Root causes are identified and measured: the real ArduPilot link runs at several times the simulator's configured nominal message rate, so the rate rule fires and the ML network features (rate, jitter) fall far outside the simulated training range | `real_link_stats_airborne` in the same file vs `configs/detector.yaml` and the model's scaler |
| After a **documented one-parameter per-vehicle calibration** (nominal message rate from calibration dates only, ML off, test on held-out dates) the real-link alarm rate is reported separately | `artifacts/external/alfa_calibrated/summary.md` |
| The **physics layer** is comparatively quiet on real fixed-wing telemetry, and its behaviour on real multirotors is measured under three explicit channel mappings | ALFA summary (physics column); `artifacts/external/px4_review_v2/summary.md` |
| On real PX4 and ArduPilot telemetry, `GLOBAL_POSITION_INT` and `VFR_HUD` are **both estimator outputs**, so three physics cross-checks lose independence; the heading-vs-course rule does not hold for multirotors; GPS/baro needs a baro offset correction | PX4 source (cited in `external/ulog_adapter.py`), E1 exceedance table |
| The selection of "real" public logs must be verified: the first protocol (rated logs) yielded **0 real flights** (HITL from one uploader), caught automatically by the `SYS_HITL` check | `artifacts/external/px4_review_v1/summary.md` |

**Not claimed:** real *attack* detection. No public real-attack MAVLink data was downloadable
in this session (the UAV Attack Dataset requires an IEEE account). Real data here measures
**false alarms and fault reactions only**. ALFA faults are physical, not cyber.

## 1b. PX4 SITL evidence (Stage 2, live software-in-the-loop — not real hardware, not public data)

Distinct from Section 1 (real public flight logs) and Section 2 (in-process simulation). Environment tag `SITL`
throughout. Full detail: `docs/PX4_SITL_INTEGRATION.md`, `docs/CALIBRATION_PX4.md`, `artifacts/sitl/P1_summary.md`,
`artifacts/sitl/P2_summary.md`, `artifacts/sitl/calibration/*.json`.

| Claim we can make | Evidence |
|---|---|
| Live MAVLink ingestion over UDP from a real PX4 SITL + Gazebo instance reproduces the offline replay of the identical bytes, per-decision | `artifacts/sitl/live_run_002_equivalence.json` |
| With the Stage-1 (simulator-calibrated) configuration, PX4 SITL benign flights false-alarm on **every** decision (same transfer failure as the real ArduPilot link in Section 1, different vehicle/transport) | `artifacts/sitl/P1_summary.md` |
| A documented, additive PX4-SITL calibration profile (held-out flights, never iterated on) reduces that to 1 false alarm in 2805 held-out decisions, with one quantified, un-fixed cause remaining (extractor sequence-reorder artifact) | `docs/CALIBRATION_PX4.md`, `artifacts/sitl/calibration/evaluation_heldout.json` |
| A live MAVLink-aware attack proxy (separate from the Stage-1 simulator attack system) modifying real downlink `GLOBAL_POSITION_INT` frames in transit is detected (`GPS_SPOOFING`) in 10/10 independent trials, 0 false alarms in 1404 pooled pre-attack decisions, with ground truth authored by the proxy itself (never from detector output) | `artifacts/sitl/P2_summary.md` |
| An unauthenticated, rogue-identity `COMMAND_LONG` (force-disarm) injected on the uplink is **accepted and acted on by PX4** (`MAV_RESULT_ACCEPTED`, ~7-18ms) in **10/10** live trials — **command-path effect (SITL)**, independent of whether the IDS flagged it | `artifacts/sitl/P2_injection_summary.md` |
| **Link-level detection (SITL), post-fix harness:** the IDS (PX4 profile + PX4-trained model) produced `COMMAND_INJECTION`-type evidence ("command(s) from unexpected source sys66/comp200") in **10/10** fresh-SITL trials; **37/37** injected frames reached the IDS pipeline input (carriers: 25 on the IDS tap's own heartbeat, 12 on the inert carrier client), ground truth = the proxy's own frame log + per-injection carrier log. Ceiling: a *rogue* sysid (66) outside the profile's expected identities is flagged by the protocol detector's source-identity rule; an injection impersonating an expected GCS sysid (255/254), or a replayed legitimate command (`command_injection:gcs_replay`), is **not** tested by this and is not claimed. The IDS saw a mirrored copy on a bump-in-the-wire tap (a harness choice). Uncommitted working tree at run time (recorded per manifest) | `artifacts/sitl/P2_injection_summary.md` (POST-FIX section), `artifacts/sitl/p2i_fix_trial_*` |
| **Superseded negative/partial result (pre-fix harness):** the earlier batch's 5/10 detection was a **harness defect**, not a detector, parser, extractor or transport result: the relay did not mirror a hook-added frame to the sender of the uplink frame it rode on, and the IDS tap sends its own heartbeat, so injections carried by it never reached the IDS (only 11/25 injected frames reached the ingest tap in the 7 trials that had one). The earlier "timing/concurrency sensitivity in the threaded UDP transport" hypothesis is **disproven** (transport delivered every mirrored frame; reproduced SITL-free in `tests/unit/test_mavlink_live_concurrency.py`) | `artifacts/sitl/P2_injection_summary.md` (PRE-FIX section), `docs/STAGE2_PROGRESS.md` 2026-10-07 root-cause entries |
| Downlink **drop** (suppress `GLOBAL_POSITION_INT`/`GPS_RAW_INT`): **10/10** live SITL trials detected (`DOS`, "GPS dropout"), 0 false alarms in 1972 pooled pre-onset decisions, median latency 2.76s | `artifacts/sitl/P2_drop_summary.md`, `artifacts/sitl/p2d_n10_trial_*` |
| Downlink **delay**-and-release (hold every unsigned frame a fixed delay, release in order): **9/10** detected — via a `DOS` message-rate spike as the backlog drains in a burst, **not** the originally hypothesised per-frame jitter mechanism (the one miss drew the smallest delay, 0.355s, too small a backlog to burst); 1 false alarm in 1854 pooled pre-onset decisions | `artifacts/sitl/P2_delay_summary.md`, `artifacts/sitl/p2l_n10_trial_*` |
| Uplink **replay** (byte-identical re-send of a legitimate, unsigned `COMMAND_LONG` captured from an **expected GCS identity**, sysid 255, 15-30s later): **10/10** harness delivery (both capture and replay reached the IDS), **10/10** command-path effect (PX4 `MAV_RESULT_ACCEPTED` both times), **10/10** link-level detection — but via an orthogonal **sequence-continuity** mechanism (`MAVLINK_ANOMALY`, "sequence gap"; the replayed frame's old MAVLink `seq` looks like a huge backward jump against the real GCS's own advancing counter), not the identity/provenance rule, which — confirmed by **0** `COMMAND_INJECTION`-type evidence across all 10 trials — cannot and does not fire for this sysid (the documented `command_injection:gcs_replay` gap, pinned SITL-free in `tests/unit/test_px4_profile.py`, holds exactly as documented). 0 false alarms in 160 pooled pre-replay decisions | `artifacts/sitl/P2_replay_v2_summary.md`, `artifacts/sitl/p2r_v2_trial_*` |
| **Superseded pilots (n=1, pre-redesign):** drop/delay pilots are superseded by the n=10 batches above; the original replay pilot was inconclusive by design (non-GCS capture identity, a command PX4 rejected both times) and is superseded by the redesigned v2 batch above | `artifacts/sitl/p2d_trial_001.manifest.json`, `artifacts/sitl/p2l_trial_001.manifest.json`, `artifacts/sitl/p2r_trial_001.manifest.json` |
| Expected-GCS **impersonation** (a fresh forged `COMMAND_LONG`, not a replay, stamped with sysid 255/compid 190): two attacker strengths contrasted, **10/10 command-path effect and 10/10 harness delivery in both**. **Naive** attacker (own sequence counter from 0): **10/10 detected** — same sequence-continuity mechanism as the replay row above. **Informed** attacker (passively reads the real 255/190 heartbeat's running sequence off the clear-text link and continues it, modelling an attacker who can already read the link — the MITM position this proxy assumes): **0/10 detected** — no rule fires, on any of the 33 forged frames across 10 trials. This is the confirmed authentication gap: an attacker who can read the link defeats the only mechanism (sequence continuity) that caught every other command-injection variant tried so far | `artifacts/sitl/P2_gcs_impersonation_summary.md`, `artifacts/sitl/p2g_{inf,naive}_trial_*` |
| **P4 MAVLink-2 signing, now at n=10: the informed-impersonation gap closes, and the IDS itself detects it.** A real, PX4-compatible `SETUP_SIGNING` bootstrap between the legitimate GCS and PX4, plus a NEW `require_signing`/`sig_invalid_count` detector rule (real HMAC-SHA256 verification via `pymavlink`'s own algorithm, not just the claimed-signed bit): **10/10** legitimate signed commands accepted; **10/10** unsigned forged commands rejected by PX4 (0 acks, command-path effect); **10/10** the IDS's verifying parser observed the forged bytes; **10/10** the new signing rule flagged it inside the attack window; pre-onset false alarms on the new rule are exactly 10/400 (one per trial, a characterized one-time signing-bootstrap transient, not ongoing noise). Supersedes the n=1 pilot (kept as prior evidence) | `artifacts/sitl/P4_signing_summary.md`, `artifacts/sitl/p4_sign_n10_trial_*`, `artifacts/sitl/p4_sign_trial_001.manifest.json` (superseded pilot) |
| Downlink **GNSS fix-quality degradation** (rewrite `GPS_RAW_INT.fix_type`/`satellites_visible` to 0-1 / 0-4 for a window; position fields untouched): **10/10** live SITL trials detected by the unchanged protocol GNSS-fix-loss rule (`DOS`, "GNSS fix lost"), **10/10** detector evidence equals the written values, 0/1940 pooled pre-onset decisions flagged (autocorrelated 5 Hz decisions from 10 disarmed, static-vehicle boots, i.e. effectively 0 of 10 trials; **not** an in-flight false-alarm rate), latency from onset median 1.23s (1.07-1.74s; includes the rule's own 5-decision persistence of ~1s and a small unrecorded IDS/relay clock-origin offset, so it is not detector speed). **Link-level detection (SITL), positive control only:** values are far below the rule's thresholds by design; PX4's estimator/flight are untouched (vehicle disarmed), no real receiver or RF; subtler degradation untested | `artifacts/sitl/P2_gnss_summary.md`, `artifacts/sitl/p2n_n10_trial_*` (n=1 pilot: `artifacts/sitl/p2n_pilot_trial_001.*`) |

**Not claimed:** PX4's own estimator/trajectory is affected (the proxy's uplink/downlink content stays byte-identical
by construction for drop/delay/replay, and the vehicle is disarmed on the ground for drop/delay/replay/impersonation/
signing/GNSS-degradation alike); a statistically powered detection rate (n=10 per variant is the design floor; the P4 signing pilot
is n=1 only); that the replay's or the naive impersonator's sequence-gap detection generalises past ~225s of delay
at 1Hz heartbeat, or to an attack performed after the real GCS identity has gone silent; that an attacker without
read access to the link could replicate the informed impersonation variant's seq-continuation (it is explicitly a
MITM-position result); that MAVLink-2 signing defends against an attacker present *before* the legitimate GCS's
bootstrap `SETUP_SIGNING` (PX4's own "trust-on-first-contact" property, not fixed here); that the IDS's own live
pipeline verifies signatures in the P4 pilot (it does not — the pilot measures PX4's own acceptance, a
command-path effect, not an IDS detection outcome); any production signing-key management, rotation, or storage
design; that GNSS-degradation detection holds for subtle degradation (only gross fix loss was tested), or for real receiver behaviour under jamming; a clean-commit result for the GPS-drift trials —
the working tree was **dirty** (8 uncommitted paths) during all ten of those trials, dirty again (8 paths) during
the pre-fix command-injection batch, dirty (3-4 paths) during the post-fix injection and drop/delay/replay-v2
batches; each manifest's `full_provenance.working_tree_dirty`/`dirty_paths_count` records this per trial. All
code for the above is now committed. GNSS-degradation batch: its manifests record commit `5ff674b` plus 5 dirty `src`/`scripts` paths (the attack, driver and summary code, committed afterwards in `6a6c0e2`; consistent by file timestamps, not hash-verified), and no Gazebo version is recorded in them.

## 1c. ArduPilot evidence (Stage 2, 2026-10-10): `SITL` + `BENCH` + `REPLAY` — not flight, not public data

New in this sprint; **separate from, and never merged with, Section 1b (PX4)**. Full detail: `docs/ARDUPILOT_SITL.md`,
`docs/HARDWARE_BENCH_PIXHAWK6X.md`, `docs/ONBOARD_DEPLOYMENT.md`, `artifacts/ardupilot/`, `artifacts/hardware/`.
`BENCH` = a physical flight controller on a desk, disarmed, no props, no airframe (not `HITL`, not `FIELD`).

| Env | Claim class | Claim we can make | Evidence |
|---|---|---|---|
| `BENCH` | none (stream description) | A **physical Pixhawk 6X** (ArduPilot, quadrotor, sysid 1, **MAVLink 1**, disarmed) read **passively over USB for 179 s** gave 198 frames — HEARTBEAT 1.006 Hz and TIMESYNC 0.10 Hz **only** — with 0 CRC/parser/garbage errors, 0 sequence loss, `bytes_sent = 0`. That is **1 of the 6 messages** the pipeline reads; replayed through the unchanged pipeline every one of the 896 decisions is a threat (missing GPS/attitude), so the board is not usable as-is. **Firmware version not determined; reconnect not measured on hardware; nothing was written to the board.** | `artifacts/hardware/pixhawk6x_passive_probe_001.json`, `…_pipeline_replay_{ml,noml}.json`, `docs/HARDWARE_BENCH_PIXHAWK6X.md` |
| `SITL` | none (ingestion) | The unchanged parser/pipeline ingests **ArduCopter 4.7.1** live (isolated network namespace; only a stdout pipe leaves it; isolation proved per run and re-checked after): 8 flights, 0 bad / 0 unverified frames, 0 late ticks, pipe byte-identical to the in-namespace log, hash chain intact, no leak/orphan. Both telemetry configurations deliver all six messages. | `artifacts/ardupilot/ap_*/manifest.json`, `summary.json` |
| `SITL` | none (benign reference) | With the **Stage-1 configuration, no ArduPilot profile**: ML detector on → **126 / 2,339** in-flight decisions are alerts (5.4 %); ML off → **0 / 2,329** over 5 flights (+ exactly 5 start-up alerts per flight before GPS lock). The Stage-1 ML model does **not** transfer to this ArduPilot-SITL pipe path (inter-arrival-jitter z up to +19, strongly negative after start-up; part of it may be path-induced) — the same family of result as PX4 and ALFA. ML was turned off because of this on these same flights, so 0/2,329 is selected-on-data. Not a false-alarm *rate*: 5 flights of one simple scripted trajectory. | `artifacts/ardupilot/BASELINE_SUMMARY.md` |
| `SITL` | **link-level detection** | One **pre-registered** scenario (downlink `GLOBAL_POSITION_INT` drift, 5 m/s east × 25 s, in-path between simulator and IDS, ML off): **3 of 3 `DETECTED`**, first `GPS_SPOOFING` alert 2.7–2.9 s after onset, `physics_consistency` only, paired clean control 0 alerts in the window, 0 pre-onset in-flight alerts, all validity gates passed; re-applying the spec to the clean tlog reproduces the observed tlog **byte for byte (3,660/3,660 frames, ×3)** and the live verdicts re-derive on 695–696/695–696 decisions. **Not** estimator compromise, **not** physical deviation (the simulator never receives a modified frame), **not** a rate (n=3). Post-registration edits (evaluator x2, orchestrator, transport hardening after review) are disclosed with hashes in the addendum; "pre-registered" means recorded and hashed with a self-written timestamp, not cryptographically signed. The attack rewrites only lat/lon (velocity truthful) so the physics check trips by construction; a velocity-consistent offset was not tested. | `docs/ARDUPILOT_SITL.md` §6, `artifacts/ardupilot/p2_position_drift_preregistration{,_addendum}.json`, `artifacts/ardupilot/ap_attack_drift_00{1,2,3}/{evaluation,reproducibility}.json` |
| `SITL` | none (deployment path) | A monitor that **never transmits** (`tx_frames 0`) on a second serial port whose streams are set by **persistent `MAV2_*` parameters** received all six messages (8,589 frames, 141 s) and the unchanged pipeline raised 0 in-flight alerts (0/476). **ArduCopter 4.7.1 has no `SRn_*` parameters** (they are `MAVn_*`); a first, wrong-named parameter file was a silent no-op and the first hypothesis (a GCS heartbeat is needed) was wrong — both disclosed. | `artifacts/ardupilot/ap_passive_monitor_params_001/`, `…/passive_monitor_param_readback/README.md` |
| `REPLAY` over a loopback **virtual** serial port | none (software path) | The real serial transport + receive-only runner on 3,442 ArduPilot SITL frames: 0 framing errors, `bytes_sent = 0`, clean shutdown, hash chain intact, CPU 0.57 % of a core (laptop). An 8.5 s simulated cable pull: the transport reconnected by itself (`reconnects = 1`); the detectors alerted during the outage (expected) **and produced a burst of false alerts at recovery** (sequence gap, heading mismatch, position residual). | `artifacts/ardupilot/serial_path_replay_001/` |

**Not claimed (ArduPilot):** that a flight controller with *no* GCS connected streams to a parameter-configured port (a GCS was active on SERIAL0 in that test); anything about a vehicle in the air, the physical board's firmware, estimator or flight behaviour; detection by the ML
detector on ArduPilot; detection of any attack other than the one scenario above; a detection or false-alarm *rate*; defence against replay/injection on
the physical link (the observed USB stream was MAVLink 1 with no signatures, so nothing in it could be authenticated); any figure measured on a companion computer. The SITL ran at a real-time factor of 0.917–0.923.

## 2. Simulation-only evidence

| Claim | Evidence | Caveat |
|---|---|---|
| Baseline fused-IDS accuracy / recall / FPR on 23,430 simulated decisions | `artifacts/benchmarks/summary.md` | 3 trajectories, default modes, 5 s grace |
| What the ML layer adds on the same grid | `artifacts/benchmarks_ablation_no_ml/summary.md` | ML is the only FP source in the baseline |
| Detection across **all 20 attack modes**, diverse trajectories, no-grace scoring, excl. firmware | `artifacts/benchmarks_extended/summary.md` | simulated link and attacker |
| Simultaneous attacks (4 combinations, multi-label truth) | same file, *Simultaneous attacks* | the fusion reports one primary + secondary indicators; full multi-label attribution is partial |
| GNSS jamming detection (new fix-loss rule) | same file, `dos:gnss_jamming` | scored as DOS; trivially observable in simulation |
| Benign link impairment stress (loss, delay, reordering) | same file, *Benign sessions* | synthetic impairment model |
| Firmware tamper detection | SHA-256 manifest compare | manifest is **unsigned** in the PoC |

## 3. Known gaps (reported, not hidden)

* `command_injection:gcs_replay` / expected-GCS impersonation — the protocol detector's
  **identity/provenance** rule cannot and does not distinguish any command carrying the
  legitimate GCS identity from a real one, replay or fresh forgery alike (no MAVLink-2
  signing); confirmed live, 0/10 in every live GCS-identity test run (Section 1b). A
  **different**, pre-existing rule (per-source sequence continuity) incidentally catches a
  byte-identical replay (10/10) and a *naive* fresh forgery that uses its own sequence
  counter (10/10) — but an **informed** forger that passively reads the real identity's
  running sequence off the clear-text link and continues it defeats this too: **0/10
  detected**, confirmed live across 10 trials / 33 forged, PX4-accepted frames. **Closed
  for this specific attack by P4 (pilot, n=1, Section 1b):** once MAVLink-2 signing is
  bootstrapped, PX4 itself stops accepting the (necessarily unsigned) forged command —
  10/10 ACCEPTED becomes 0/10 ACCEPTED — independent of any IDS detection rule. Not
  claimed: a statistically powered rate for the signing pilot, or defence against an
  attacker present before the legitimate GCS's own bootstrap handshake (PX4's own
  disclosed "trust-on-first-contact" property). It stays in the v2 benchmark as a
  known-gap row (the simulated benchmark has no signing model).
* **This codebase's own `signed` flag was presence-of-bit only, not cryptographically
  verified**, until this session's P4 scoping found it by reading the parser: the MAVLink-2
  signature's trailing bytes were parsed over and skipped, never checked against a secret.
  `require_signing: true` (unused by any current profile) would therefore have only ever
  checked "does every frame claim to be signed," not "is any signature valid" — fixed
  additively (`MavlinkFrameParser(secret_key=...)`, opt-in, `None` by default = unchanged
  behaviour, confirmed by an identical Stage-1 regression). `MessageEnvelope.signed` (a
  frozen field) keeps its original, existing meaning; the real verification lives in new,
  separate `LiveStats` counters instead.
* **ArduPilot (2026-10-10):** (a) the Stage-1 ML detector is unusable on ArduPilot SITL (§1c) and no ArduPilot-trained model exists; every ArduPilot result is rules + physics only.
  (b) After a transport outage the detectors emit a transient burst of false alerts at recovery (`sequence gap`, heading/course mismatch, position residual) — measured on a virtual serial port, not fixed.
  (c) The physical Pixhawk 6X, passively read, provides 1 of the 6 required messages and the observed USB stream was MAVLink 1 with no signatures; its firmware version is unknown.
  (d) Start-up alerts (5 per boot before GPS lock) are not suppressed; only the heartbeat/GPS sentinel part is coverable by the existing `startup_grace_s`.
  (e) Reconnect on a real USB/UART device is untested. (f) No measurement on a companion computer.
* `gps_spoofing:sudden_offset` — a constant, self-consistent offset is caught only at the
  jump (see v2 per-mode recall).
* Link-impairment stress shows the sequence/rate rules and ML network features are
  brittle to realistic loss and reordering.
* On PX4 SITL, a backward MAVLink sequence step (benign UDP reordering) is read by the frozen extractor as a
  253-frame loss, costing 1 benign decision in 2805 held-out — quantified, not fixed (needs a frozen-contract
  change + retrain; see `docs/CALIBRATION_PX4.md` proposal 1). PX4's flight mode decodes to `UNKNOWN` through the
  Stage-1 ArduCopter mode table — no detector reads it, so it costs 0 false alarms (explainability/dashboard gap only).

## 4. Future work (not implemented)

1. Real attack validation: UAV Attack Dataset (live HackRF spoofing/jamming on a Pixhawk 4);
   own SITL/HITL + SDR lab.
2. Per-vehicle baselining of transport features (automated, not hand-set) and retraining the
   ML layer on **real benign telemetry with network features** (ALFA-style `.tlog`s), with
   flight-level splits — only now scientifically justified because real tlogs exist.
3. Raw-sensor cross-checks for real vehicles: `GPS_RAW_INT` vs EKF position/velocity,
   `SCALED_PRESSURE` vs EKF altitude, with causal bias removal.
4. MAVLink-2 message signing (fixes command replay), signed firmware manifest (Ed25519).
5. A separate fault class (ALFA shows physical faults and attacks overlap in feature space).
6. A dedicated GPS_JAMMING class in the enum / dashboard.
7. (Done: the command-injection detection intermittency was traced to a relay-mirror topology defect, fixed and
   re-validated 10/10 post-fix; drop/delay n=10, the redesigned expected-GCS replay (v2) n=10, the
   expected-GCS fresh-forgery impersonation contrast (naive 10/10 detected, informed 0/10), and a P4
   MAVLink-2 signing pilot (n=1) closing the informed-impersonation gap are all done — see Section 1b.) Next:
   an n=10 batch of the signing pilot for a defensible rate; a `require_signing`-aware detector rule using
   the new `LiveStats.sig_invalid` counter, so the IDS's own live pipeline (not just PX4 itself) can flag an
   unsigned/invalid command once signing is the deployed policy; add a counter for silent kernel-side
   datagram loss when the receive thread is GIL-starved (`UdpMavlinkTransport` cannot see it today);
   re-tightening the PX4-SITL physics/rate thresholds now that real attack-trial data exists
   (`docs/CALIBRATION_PX4.md` proposal 4).

## 5. Overclaim audit (documentation language)

| Phrase | Where it was | Status |
|---|---|---|
| "signed firmware manifest" | `integrity/verifier.py`, `detectors/integrity.py`, `DETECTION.md`, `THREAT_MODEL.md`, `technical_proposal.md` | **fixed** → "SHA-256 manifest (unsigned in PoC)" |
| "Robust Mahalanobis" | `detectors/anomaly.py`, `DETECTION.md`, `ML_PIPELINE.md`, `technical_proposal.md` | **fixed** → "diagonal Mahalanobis (z-score norm)" |
| "99.7 % ML accuracy" | not found in docs | README now states explicitly it is the fused IDS on simulation |
| "evaluated on unseen flights" | `BENCHMARKING.md`, `ML_PIPELINE.md`, `harness.py`, `technical_proposal.md` | **fixed** → unseen *noise realisations* of 3 trajectories; v2 adds diversity |
| "keeps a lone weak ML signal below threshold" | `fusion/engine.py`, `DETECTION.md`, `technical_proposal.md` | **qualified**: a lone strong ML score crosses the threshold (source of baseline FPs) |
| "~9,000 msg/s / ~0.4 ms with ML off" | `BENCHMARKING.md` | **replaced** by the regenerated ablation (the `--no-model` flag did not disable ML before the fix) |
| "see scripts/tune_thresholds.py" | `configs/detector.yaml` | **fixed** — script never existed |
| "(bias-corrected)" GPS/baro | `configs/detector.yaml` | **fixed** — no correction is implemented |
| "benign residual ~4 m RMS" | `features/extractor.py` | **fixed** — replaced with a pointer to measured distributions |
| real-world deployment claims | `README.md`, `technical_proposal.md` | already scoped as future work; keep it that way |
