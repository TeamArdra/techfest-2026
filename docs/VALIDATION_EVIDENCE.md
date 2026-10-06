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
| The IDS's detection of that same live command injection is **intermittent**: `COMMAND_INJECTION` evidence fired in 5/10 trials, including a split 3-miss/1-hit result across 4 live runs of the *identical* attack draw — not a proven detector/parser/extractor bug (those were independently verified correct in isolation first), consistent with (not proven to be) timing/concurrency sensitivity in the live threaded UDP transport | `artifacts/sitl/P2_injection_summary.md`, `docs/STAGE2_PROGRESS.md` 2026-10-07 entry |
| Pilot (n=1) live trials of two more attacks: downlink GPS-channel **drop** is detected (`DOS`, "GPS dropout") ~2.8s after onset, 0 pre-onset false alarms; downlink **delay**-and-release (no frame loss, byte-identical, order-preserving) produces almost no detector signal (1/500 decisions), as the attack's own design hypothesised | `artifacts/sitl/p2d_trial_001.manifest.json`, `artifacts/sitl/p2l_trial_001.manifest.json` |
| A third pilot (uplink **replay** of a captured command) is **inconclusive by design and reported as such**: the chosen command was rejected by PX4 identically both as original and replay (no accept/reject asymmetry shown), and the capture used a non-GCS identity, so it does not yet test the documented `command_injection:gcs_replay` gap — needs redesign before any claim | `artifacts/sitl/p2r_trial_001.manifest.json`, `docs/STAGE2_PROGRESS.md` 2026-10-07 entry |

**Not claimed:** PX4's own estimator/trajectory is affected (the proxy's uplink stays unmodified by construction);
anything about real RF, hardware, or MAVLink signing (the SITL link is unsigned); a statistically powered detection
rate (n=10 is the design floor, reported as counts); that the IDS would reliably detect this live command injection
(5/10, see above — reported as an intermittent result, not a rate); a clean-commit result for the GPS-drift trials —
the working tree was **dirty** (8 uncommitted paths) during all ten of those trials, and dirty again (8 paths) during
the command-injection batch; each manifest's `full_provenance.working_tree_dirty`/`dirty_paths_count` records this
per trial. The GPS-drift/calibration/live-ingestion code itself is now committed (`cbda253`, `7e7631b`, `3fb8cb6`).

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

* `command_injection:gcs_replay` — a replayed command from the legitimate GCS identity is
  **not detected** (no MAVLink-2 signing). It stays in the v2 benchmark as a known-gap row.
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
7. A concurrency-focused test of `UdpMavlinkTransport` (no SITL needed) to pin down the command-injection
   detection intermittency (5/10, see Section 1b) to a specific cause, rather than the current "consistent
   with timing sensitivity, not proven" statement; re-tightening the PX4-SITL physics/rate thresholds now
   that real attack-trial data exists (`docs/CALIBRATION_PX4.md` proposal 4); MAVLink-2 signing on the SITL
   link (P4, scoped but not started — PX4 supports runtime `SETUP_SIGNING` key exchange and a fixed
   per-build unsigned-message allowlist, read-only from `mavlink_sign_control.cpp`, no PX4 build changes
   needed); drop/delay/replay attacks are implemented and unit-tested (`attacks_live_dos_replay.py`) with
   pilot (n=1) live-SITL trials in progress at the time of writing — see `docs/STAGE2_PROGRESS.md`.

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
