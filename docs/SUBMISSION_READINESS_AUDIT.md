# Stage-2 submission readiness audit

Audit of the AegisFlight Stage-2 report against the **official template** and the evidence in this repository.
Date 2026-10-29 · branch `docs/submission-readiness-20261029` (from `evidence/gps-hw-verify-20261029`, `HEAD` c849012) ·
the draft is `docs/stage2_report_draft.md` · claim classes and environment tags follow `docs/VALIDATION_EVIDENCE.md`
(`SIM` · `REPLAY` · `SITL` · `BENCH`; no `HITL` or `FIELD` evidence exists).

## 0. Bottom line

* The template expects **evidence from actual flight operation** and says simulated or generated results carry
  "limited weight". **The team has no flight data of its own and no attack run against a real vehicle.** The strongest
  real-world evidence is receive-only: four physical-board captures (bench, disarmed, stationary), public real flight logs
  replayed for false-alarm behaviour (ALFA, PX4 Flight Review), and SITL link-level detection. The report must say so
  plainly; it must not read as flight validation.
* Everything in the template's **11 sections** now has a home in the draft. Several mandatory deliverables are **missing or
  unverifiable** (section 7, P0): demonstration video, licence file, archive contents (raw captures are git-ignored),
  team/declaration fields, and a stated team target for each requirement row.
* Several documents in the repo contradicted the code or the artifacts (section 4). The worst were in the **risk register**
  (a mandatory deliverable): a detector rule that does not exist, and four "Approved" sign-offs with no review behind them.
  Those are corrected in this change.
* The known gap "poor GPS/estimator health is silent" is now addressed by a **narrow, passive, tested** change (section 6).
  It adds no alert and changes no detector or benchmark result.

## 0a. Hardware-free sprint status (2026-10-29, branch `sprint/hardware-free-20261029`)

Everything below was done without touching hardware: software tests, simulation, offline replay of the existing capture, a local dashboard. Nothing was sent to a
vehicle, no flight parameter or mode was touched, no attack was injected into a live link.

| Task | Status | What exists / what blocks it |
|---|---|---|
| Root `LICENSE` | **DONE** (holder line **human to confirm**) | MIT, consistent with `pyproject.toml`; "Team Ardra" taken from `authors` |
| Third-party notices | **PARTIAL** | `THIRD_PARTY_NOTICES.md`: Python and npm licences read from installed metadata / `package-lock.json`; second pass 2026-10-29: pyulog, uvloop, dev tools, PX4 / ArduPilot / Gazebo licence headers **verified** from metadata or licence files; 391 Rust crates **declared, not audited** (5 MPL-2.0); Tauri icon origin and ALFA source licence **unresolved**; licence texts not audited |
| Archive manifest | **DONE** (decisions **HUMAN**) | `docs/SUBMISSION_ARCHIVE_MANIFEST.md`; raw bench captures, model file and dataset inclusion need a team decision |
| Team ID, date, signature, final targets, AI-use verification, integrity declaration | **HUMAN ACTION REQUIRED** | placeholders left; `docs/SUBMISSION_ARCHIVE_MANIFEST.md` §4 lists exactly what is needed |
| Report audit and corrections | **DONE** (re-review recommended) | label-independence wording, gate wording, defense wording, platform coverage, saved-artifact references; see §4 (C14–C19) |
| Reproducible evidence for prose-only figures | **DONE for `SIM`; BLOCKED for SITL/hardware** | `artifacts/validation/submission_rerun_20261029/` (baseline 378/378, extended re-run, session-level Wilson intervals, per-class time to first alert, GPS drift sweep ML on/off, test-suite run). SITL batches need WSL/PX4/ArduPilot and were not regenerated; ALFA/PX4 replays need fetched logs and `pyulog` |
| Confidence intervals | **PARTIAL** | session level on `SIM` only (n = 4 per mode: wide); none for `SITL`, replay or hardware |
| Latency distribution / detection-vs-magnitude | **PARTIAL** | per-class min/median/max (no p95: < 20 sessions per class); magnitude sweep for GPS drift only; no latency-distribution plot |
| Baseline comparison (simple threshold / autopilot checks) | **PARTIAL (second pass)** | simple single-limit baseline done in `SIM` on the same 23,430 decisions: `artifacts/validation/baseline_comparison_20261029/` (baseline 996 / 1510 / 15320 / 5604; its FPs are one climb-rate rule). **Autopilot-check comparison still NOT DONE** (no failsafe output for attacked sessions) |
| Label-independence evidence | **DONE** | `tests/unit/test_label_independence.py` (behavioural + structural), `SIM`, five classes; firmware class excluded by design |
| Detector weaknesses: sudden offset, slow drift, `gcs_replay`, informed impersonation, PX4 drift | **REPRODUCED, no detector change; fixes BLOCKED** | see §6a: each is an information limit of unauthenticated telemetry (needs signing or an independent sensor), not a tuning problem; changing thresholds would be tuning to the test |
| Dashboard states and wording | **PARTIAL** | healthy / unhealthy / unknown / stale / null / older-backend cases unit-tested (11 frontend tests); real browser render of SIM and REPLAY checked and screenshotted; "usable fix", "(unauthenticated)" and "Replaying" wording added. No browser-driven component test library exists |
| Software-only demo script | **DONE (plan)** | `docs/DEMO_SCRIPT_SOFTWARE_ONLY.md`; **no video was recorded** (HUMAN ACTION) |
| Clean-machine reproducibility | **NOT DONE** | all checks ran in the existing environment |
| Healthy-estimator hardware capture, own flights, companion-computer measurement, attack on a real vehicle | **BLOCKED (hardware / flight)** | outside this sprint's scope by design |

## 1. Facts verified against the repository (the brief's leads)

| Lead in the brief | Verified value | Source |
|---|---|---|
| COM7 at 115200, 90 s, receive-only | window 2026-10-28T20:04:26Z–20:05:56Z, `wall_s` 90.0, `bytes_sent` 0, `write_errors` 0 | `artifacts/hardware/gps_hw_verify_20261029/live_capture/summary.json` |
| 5,130 MAVLink 1 frames, no gaps/CRC/garbage/disconnects | 5,130 frames, all `0xFE` (MAVLink 1), none signed; `seq_gap_events` 0; `crc_rejects` 0; `garbage_bytes` 0; `disconnects` 0 | `summary.json`, `live_capture/tlog_stats.json` |
| 3D fix in all 180 reports; 6–7 satellites; `eph` ~8 | `fix_type` 3 ×180; satellites min 6 / max 7; `eph` 7.99–8.58 (median 8.09) | `live_capture/gnss_summary.json` |
| GPS-healthy bit unset; no valid horizontal EKF solution | `SYS_STATUS` GPS present 180 / enabled 180 / **healthy 0**; EKF `flags` `0xa7` ×180, `pos_horiz_abs` 0, `const_pos_mode` 180 | `gnss_summary.json` |
| Drift 34.3 m while speed ≤ 0.02 m/s | max offset from first fix **34.306 m**; `GLOBAL_POSITION_INT` speed ≤ **0.02** m/s, `VFR_HUD` ≤ 0.026 m/s. **Nuance:** the receiver's own `GPS_RAW_INT.vel` reached 1.09 m/s (median 0.245) | `gnss_summary.json` |
| 451 decisions, 0 alerts live | 451 decisions, `alert_decisions` 0 | `summary.json` |
| Replay: 0 alerts gate on vs 4 false `GPS_SPOOFING` gate off | gate on: 450 decisions, 0 alerts; gate off: 450 decisions, 60 threat decisions, 4 `GPS_SPOOFING` ("position residual 12.0–15.2 m > 12 m") | `replay/live_capture_gate_{on,off}_noml.json`; the only config difference is `estimator_gate` (`diff` of `cfg_gate_off/detector.yaml` vs `configs/detector.yaml`) |
| All three bench captures lack a horizontal solution | 008: 125 reports, 009: 120, this one: 180, all `0xa7` | `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.10; `gnss_summary.json` |
| 883 passed, 3 skipped; frontend tests/build; Stage-2 verification | recorded in `docs/TESTING.md` and the bundle manifest; `pytest --collect-only` gives **886** on that tree, which equals 883 + 3 | `artifacts/hardware/gps_hw_verify_20261029/manifest.json` `checks` |
| `verify_stage2.py` is a demo | confirmed: hand-built inputs, `SIM` | `README.md` §2, `docs/TESTING.md` |
| Receive-only, no attack injected | `bytes_sent` 0; nothing injected; `manifest.json` `not_run` lists attacks as forbidden by scope | manifest |

**Template provenance.** `git show HEAD:"docs/Stage 2_…Report Template.pdf"` is a **23 KB plain-text file** saved with a `.pdf`
extension (not a PDF). The real 407 KB PDF (`%PDF-1.7`) is an **uncommitted working-tree modification** and was used for this
audit, text-extracted with `pdftotext -layout`. Its text matches the committed transcription's section list. It was not
touched. Decide whether to commit it (P0-5).

## 2. Official template: requirement checklist

IDs are the template's own section numbers. **Status:** ✅ complete · 🟡 partial · ❌ missing · ❓ cannot verify. "Draft" =
`docs/stage2_report_draft.md`. Weights are the template's.

| ID | Exact heading (weight) | Required content / format | Best existing source | Status |
|---|---|---|---|---|
| — | Team and Submission Information | table: Team ID, Team Name, Date of Submission, IDS Name / Version | `pyproject.toml` (name `aegisflight`, version `0.1.0`, author "Team Ardra") | ❌ Team ID, date: human fields |
| — | Submission note | archive must contain source, tests, flight logs and datasets, attack-injection scripts, ground-truth files, result files and the demonstration video; **a link alone is not sufficient** | repo | 🟡 video ❌; raw captures git-ignored; datasets fetched, not stored |
| 1 | Executive IDS Summary (5) | 17-row parameter table (value, unit, evidence/section) + top-3 readiness reasons + top-3 risks | Draft §1 | 🟡 rows without evidence say so |
| 2 | Stage 1 Baseline and Design Evolution (8) | 11-row Stage1/Stage2/Change?/Reason table | Draft §2 | ✅ |
| 2.1 | Stage 1 Claims Revisited | each Stage-1 claim: Demonstrated / Partly / Withdrawn + reason + evidence | Draft §2.1 (from `docs/technical_proposal.md`) | 🟡 the Stage-1 *report* itself is not in the repo; the proposal is used |
| 2.2 | Stage 1 Open Questions Addressed | question, how addressed, result, remaining uncertainty; **must state how "distance covered" is interpreted and what was measured** | Draft §2.2 | 🟡 Stage-1 evaluator questions not in repo; "distance covered" answered |
| 3 | Updated/implemented Requirements and Architecture (7) | 8-row requirement table (target, final team target, status) + architecture description + **system architecture figure** + how flight control is not interfered with | Draft §3; `docs/ARCHITECTURE.md`; `docs/diagrams/*.mmd` | 🟡 team targets undefined in the repo; Figure 3 rendered (`docs/figures/fig3_*.png`, second pass) |
| 4 | Integrated Methodology and Workflow (8) | **logic-flow diagram** + 7-row sub-domain table + how results from one stage changed another | Draft §4; `docs/diagrams/end-to-end-flow.mmd` | 🟡 Figure 4 rendered (`docs/figures/fig4_*.png`, second pass) |
| 5.1 | Methodology (§5 = 18) | 8 items: detectors per class, inputs read, thresholds & training, decision logic, latency design, baseline comparison, blind spots, limitations | Draft §5.1; `docs/DETECTION.md` | 🟡 simple-threshold baseline now reported (`SIM`, caveated); autopilot checks not compared |
| 5.2 | Attack Coverage and Test Matrix | per class: scenarios (count, magnitude incl. subtle), flight evidence, injection method + ground-truth source, detected/total | Draft §5.2 | 🟡 no flight evidence for any attack |
| 5.3 | Required Outputs | per-class + overall results **with counts and confidence intervals** on untuned data; detection vs magnitude; latency distribution (median, p95); baseline comparison; every miss explained; confidence statement; confusion matrix + latency/magnitude plots | Draft §5.3; `artifacts/benchmarks*/`, `artifacts/figures/` | 🟡 **no confidence intervals in SIM artifacts; no detection-vs-magnitude plot; no per-class p95** |
| 6.1 | Data Sources and Features | table: message/field, feature, detector, why, real-data evidence | Draft §6.1; `docs/FEATURES.md` | ✅ |
| 6.2 | Detection Capabilities and Robustness | 7 rows (six classes + malformed/truncated input): method, test evidence, result, limitation | Draft §6.2 | 🟡 no fuzzing campaign (claim withdrawn) |
| 6.3 | Traceability of Alerts | sample alerts → source messages/fields, detector + threshold, how a reviewer checks; **example figure** | Draft §6.3 | 🟡 text examples only |
| 7 | False-Alarm Behaviour and Alerting (8) | 9-row exposure table (**hours, km, flights, false alarms, rate/h, upper 95 % bound**, persistence, response policy) | Draft §7 | ❌ rate and bound **cannot be computed honestly** with this exposure |
| 7.1 | Benign-Condition Matrix | 6 conditions: source, duration, alerts, assessment | Draft §7.1 | 🟡 wind / aggressive manoeuvres: not tested |
| 7.2 | Alert Workflow and Integrity | stage / mechanism / behaviour / evidence + **alert timeline figure** + tamper-evidence + what happens if the IDS fails | Draft §7.2 | 🟡 timeline figure missing |
| 8 | Validation, Testing and Reproducibility (14) | 8.1 test setup (7 items incl. exact re-run commands); 8.2 results by category; 8.3 claims traceability; validation conclusion | Draft §8 | 🟡 clean-machine re-run not yet done |
| 9 | Compute, Integration, Usability and Reporting (8) | 6-row resource table **with where measured**; 9-row integration table; 3 usability rows; diagram + **operator screenshot** | Draft §9 | ❌ no target-hardware measurement, no screenshot, no video |
| 10 | Final Deployable Package (7) | 10-row package table (Submitted? / file); 8 readiness items; final readiness statement | Draft §10 | ❌ video, licence, third-party list |
| 11 | References, Data Traceability and Integrity (5) | references; 11.1 software/**AI tools**; 11.2 third-party code and datasets; 11.3 declaration + signature | Draft §11; `docs/REFERENCES.md` | 🟡 declaration must be signed by a human |

**Ambiguities, stated rather than guessed.** The PDF's table layout is damaged in text extraction (column headings wrap),
but every section, table and row label is recoverable. The template does not define "detection accuracy on data not used
for tuning", a latency target, a false-alarm target, or a benign "distance" definition; the draft states the definition used.

## 3. Evidence classification of the main claims

1. **Implemented and tested in software.** Pipeline, four detectors, noisy-OR fusion, SQLite SHA-256 hash chain, receive-only
   serial runner, estimator gate, MAVLink-2 signature verification rule, passive health observer. 902 tests collected
   (`tests/unit` 803, `tests/integration` 92, `tests/e2e` 2, `backend/tests` 5); last full run 883 passed / 3 skipped before
   this change (re-run result in section 10).
2. **Verified against recorded physical hardware (all receive-only, `BENCH`).** Link integrity and message-rate facts for
   Pixhawk 6X captures 007, 008, 009 and 2026-10-28 (the only hardware evidence); receiver and estimator state; false-alarm
   behaviour of the position-residual rule (3 captures, one vehicle, in-sample). **No attack, no flight.**
3. **Simulation or synthetic only.** All per-class detection rates (`artifacts/benchmarks*/`), telemetry-manipulation and
   firmware-integrity detection, the defense/mitigation layer, `verify_stage2.py`, the dashboard twin.
4. **Replay of real logs (not the team's flights).** ALFA (7.66 h, fixed-wing, physical faults, no cyber attacks) and PX4 Flight
   Review (2.18–2.36 airborne h, navigation probe only). False-alarm and transfer evidence, not attack detection.
5. **SITL (link-level unless stated).** PX4 `v1.18.0-rc1-27-gc239c63807` and ArduCopter 4.7.1; n = 3–10 per variant.
6. **Proposed or not implemented.** Companion-computer deployment and measurements, hardware fail-open, signed firmware
   manifest, inline prevention on a vehicle, healthy-estimator hardware validation, own-flight data.
7. **Unknown.** Firmware version of the physical board, GPS-health-bit cause, sky view, props/airframe state during captures,
   the two frames missing in the loopback replay.

## 4. Claims stronger than their evidence (and what was done)

| # | Claim (location) | Problem | Action in this change |
|---|---|---|---|
| C1 | RSK-07 "satellites_visible ≥ 12, `eph` < 100 triggers a spoofing alarm" (`RISK_REGISTER.md`) | no such rule; `min_gnss_fix_type`/`min_gnss_satellites` only drive the "GNSS fix lost" `DOS` rule | mitigation text rewritten to what exists |
| C2 | RSK-02 "read-only overlay root, append-only WAL with `fdatasync()`" | nothing in `src/` (grep `overlay\|fdatasync\|wal`: no hits) | marked design intent, not implemented |
| C3 | RSK-05 residual "Low (2×2)", drift "triggers in 2–5 s" | `docs/VALIDATION_EVIDENCE.md` §3: nothing below ~4 m/s, velocity-consistent drift undetected; CUSUM is off by default | residual raised, mitigation qualified |
| C4 | §5 sign-offs "Approved" for Security Lead, Avionics Lead, Systems Engineer, **Flight Test Pilot ("HUD usability & alert fatigue evaluation")** | no review, flight or usability evaluation exists | replaced by "Not signed" |
| C5 | `current_state.md` / `next_state.md`: "< 45 MB RSS", "< 18 % CPU on single Cortex-A53", "3.2 ms", "1.2 s recovery", "1.0 ms" | the draft's own withdrawal notice lists these as unsupported; measured host RSS is **60.7 MB** (live runner) and 154.7 MB (benchmark); nothing was measured on a Cortex-A53 | replaced with the measured host values |
| C6 | `current_state.md` "CUSUM … catching ultra-stealth micro-drift (0.15–0.30 m/s)" | `cusum_enabled` defaults to `False` and `configs/detector.yaml` has no `cusum` key; only the integrator class is unit-tested | qualified |
| C7 | `current_state.md` "150 ms fail-open watchdog … prevent pilot link severing" | in-process software flag (`hal/inline_bridge.py`), used only by `tests/unit/test_hal.py`; it cannot protect the link if the process dies | qualified |
| C8 | `DEMO_RUNBOOK.md` "satellite map", "within 360 ms", "0.0 m detour", "vehicle remains airborne" | `MapPanel.tsx` says "no tiles, not a geographic map"; the figures belong to the SIM twin and have no artifact | qualified |
| C9 | Stage-1 headline "FPR 0.0002, accuracy 0.997" | `SIM`; did not transfer to real or SITL links (100 % threat rate with production config on ALFA); the "nothing tuned" v2 benchmark has recall 0.889 and 1.1 % FPR with no grace | draft quotes both, tagged, with the no-grace FPR (0.0110), the link-stress rows (61.28 % / 99.97 %) and the artifact's 2026-09-24 date (reviewer pass fixed an earlier omission) |
| C10 | "Detects all six attack classes" | `SIM`: yes. `SITL`: telemetry manipulation and firmware integrity have no live harness; GPS drift on PX4 is detected **at release only**; `gcs_replay` and informed impersonation unsigned are open gaps | draft §5.2 per class |
| C11 | README title "Autonomous … Intrusion Detection **& Prevention** System" | body states prevention is "SIM model only; not measured" | **fixed in the hardware-free sprint** (README title, `DEMO_RUNBOOK.md` intro) |
| C12 | "0 alerts" on the 2026-10-28 capture | not evidence that coordinates were authentic: the gate hides < 30 m/fix forged-status walks (`docs/DETECTION.md`) | stated beside the result |
| C13 | `scripts/verify_stage2.py` "8/8 suites" | hand-built inputs | labelled demo |
| C14 | Draft §2.1 / §5.1: "no detector reads labels: `grep …` returns nothing" | the grep has one hit (a comment, `features/extractor.py:70`); and an import grep cannot prove behaviour | replaced by `tests/unit/test_label_independence.py` (identical decisions with ground truth scrubbed, five classes; plus an import check) and an honest scope statement |
| C15 | "gate removed 4 **false** alerts / 0 alerts" (draft §1, §6.2, §6.3, §7) | "false" rested on the vehicle's own velocity and the operator's statement, both unauthenticated; the gate was developed on this capture; 0 alerts is not evidence of detection | reworded to "judged non-attacks, not proven", in-sample, with the gate's adversarial cost |
| C16 | 899/902 test counts, "378 of 378", no-grace FP 463 vs 470 existed only in prose | not reproducible from a saved artifact | regenerated and saved (`artifacts/validation/submission_rerun_20261029/`); counts now 907 / 910 |
| C17 | Executive row "Detection accuracy on data not used for tuning" held `SIM` numbers | the simulator, attacks and detectors are the team's; template gives such data "limited weight" | row now states "design evidence only; not independent" |
| C18 | Dashboard header "valid fix yes" next to unauthenticated GPS; a replay shown as link "Live" | reads as verified truth / as a live link | now "GPS as reported (unauthenticated) … usable fix", stale-status note, "Replaying" |
| C19 | README title "Autonomous … Intrusion Detection & Prevention System"; runbook "8/8 suites in ~40 ms" | prevention is a SIM model; the suite measured 1,949.9 ms here | title and runbook corrected |

## 5. Technical completeness

| Topic | Adequately explained? | Where / gap |
|---|---|---|
| Architecture and data flow | Yes, but the committed figure is a Stage-1 simulation diagram | Draft §3 adds the live receive-only path; render before submitting |
| Threat model and attack scenarios | Yes | `docs/THREAT_MODEL.md`, `docs/ATTACKS.md` |
| Detection and fusion logic | Yes | `docs/DETECTION.md`; fusion weights/thresholds in `configs/detector.yaml` |
| Estimator-aware gating and its role | Yes, with its **adversarial cost** | the gate removes a documented false-alarm mechanism; the status report is unauthenticated, so it adds attacker capability (SIM) that only MAVLink-2 signing closes |
| Defense/mitigation and safety boundary | Needs the boundary stated first | live sources are **report-only**: `active-ips` is refused and no counter-frames are sent (`README.md`, `tests/unit/test_defense_safety.py`); prevention is a SIM model |
| Hardware topology / receive-only method | Yes | `docs/HARDWARE_BENCH_PIXHAWK6X.md`, bundle README; topology is **laptop ← telemetry radio**, not a companion UART |
| Quantitative metrics, baselines, false positives | **Partial** | `SIM` session CIs, `SITL`/`REPLAY` session-level CIs (`artifacts/validation/session_ci_sitl_replay_20261029/`) and a simple-threshold baseline now exist; no autopilot-checks baseline, no false-alarms-per-hour |
| Simulation vs hardware evidence | Yes when tags are kept | every row in the draft carries a tag |
| Limitations, risks, failure modes, future work | Yes | `docs/VALIDATION_EVIDENCE.md` §3–4, `RISK_REGISTER.md` (now corrected) |
| Reproducibility / demo instructions | Partial | commands exist; clean-machine re-run not done; the demo script describes a SIM twin |

## 6. Health-reporting gap: decision, design, tests

**Decision: address it with a narrow passive change, and also document the limits.** The gap was worse than "silent". On
2026-10-25 the dashboard header read "GPS report 3D_FIX · 7 sats · valid fix **yes**" for a vehicle whose own flags said it had no
horizontal solution (`docs/HARDWARE_BENCH_PIXHAWK6X.md`). The fix needs no detector, feature, model or frozen-contract change, so
the Stage-1 result cannot move.

**Design (as built).**
* `src/aegisflight/core/gps_health.py`: `GpsHealthObserver`, pure and status-only. Flags exactly two **vehicle-stated** conditions:
  `ekf_no_horizontal_solution` (fresh `EKF_STATUS_REPORT` with no horizontal-position bit, or `CONST_POS_MODE`) and
  `gps_sensor_unhealthy` (`SYS_STATUS` GPS present, health bit clear). Receiver `fix_type`/satellites/HDOP are passed through
  **unjudged** (no threshold invented). Unknown is `None`, never `False`; an `EKF_STATUS_REPORT` older than 2 s is unknown (only that field goes stale: `gps_healthy` and the receiver fields persist until replaced).
* `LinkMonitor` (`backend/engine.py`): six additive keys in the `/api/status` `link.gps` block. Existing keys unchanged.
* `scripts/hardware/run_serial_ids.py`: a `navigation_health` block in each `health.jsonl` line and in `summary.json`, a **sibling**
  of the pinned `telemetry_coverage` (whose key set a test fixes).
* Dashboard: `gpsNote()` in `frontend/src/lib/source.ts`, shown in the source bar in the warning colour beside "valid fix".
* **Not changed:** detectors, `FeatureFrame`, `ML_FEATURES`, fusion, the event schema, the hash chain, alerts. No new alert type.

**Tests (16 Python, 2 frontend).** `tests/unit/test_gps_health.py` (13): dialect constants pinned to pymavlink; agreement with
`ekf_has_horizontal_solution` for all 256 flag bytes; unknown-is-not-false; stale report; GPS-present gating; HDOP 65535; the
`LinkMonitor` block. `tests/unit/test_run_serial_ids.py` (+3): flagged stream, healthy stream, stream with no estimator messages.
`frontend/tests/source.test.ts` (+2).

**Evidence on real bytes** (`REPLAY` of `BENCH` over loopback; claim class none):
`artifacts/hardware/gps_hw_verify_20261029/replay/navigation_health_loopback/` — 453 decisions during the stream, **0 alerts**, both
conditions flagged on 452. Its one later alert is the silent tail of the 95 s window used for that run (disclosed in the bundle README). The API output is preserved in `replay/navigation_health_api/`.

**Remaining limits.** (1) The dashboard rendering is covered by a unit test of the wording and, since the hardware-free sprint, by one real-browser render of the REPLAY page
(`demo/screenshots/dashboard_REPLAY_bench_capture_gps_health_note.png`); there is still no automated render test (no render-test library in `frontend/`). The threat card on that page reads "NORMAL / nominal flight"
next to the unconfirmed-position note, which means only that no detector fired. (2) The `/api/status` block is live only on serial/UDP/replay sources. (3) The
flags are **vehicle-stated and unauthenticated**: a spoofer can report a clean fix and a forged status report; forged
`EKF_STATUS_REPORT` is already the documented cost of the gate. (4) No healthy-estimator capture exists, so the "quiet" branch is
tested only on synthetic frames.

## 6a. Detector weaknesses reproduced (hardware-free sprint)

Each weakness was reproduced before anything was considered; **no detector, threshold or config was changed** and no benchmark number moved (baseline 378/378 identical).
All `SIM` unless stated.

| Weakness | Reproduction (command, fixture, config) | Baseline outcome | Classification | Action |
|---|---|---|---|---|
| Sudden GPS offset: only the jump is visible | extended re-run `gps_spoofing:sudden_offset` (`extended_rerun/summary.md`); `pytest tests/unit/test_gps_scenarios_fused.py -k offset` | 4/4 sessions flagged, decision recall **12.63 %**, time to first alert 0.0 s; later decisions are indistinguishable from a consistent trajectory | information limit: a consistent offset carries no cross-sensor contradiction; pinned by tests | documented; fix needs an independent position source |
| Slow / velocity-consistent drift | `scripts/sweep_gps_drift.py` (ML off / on); `pytest … -k "slow or velocity_consistent"` | ML off: 0/10 at 0.5–3 m/s, 10/10 ≥ 4 m/s; ML on: 0/10 at 0.5–1 m/s, 10/10 ≥ 2 m/s with 1/10 benign sessions showing a false-positive decision; velocity-consistent drift undetected in both | detector limit **and** unavailable evidence (ML is off on live sources; no real drift data) | documented; lowering a threshold to flip this would be tuning to the test (not done) |
| `gcs_replay` | `run_session` with `command_injection.mode = gcs_replay`, seed 7; live console after 50 s; extended re-run | 0 of 100 attack decisions flagged with and without ML; 0 persisted alerts live; 0/4 sessions [0.00, 0.49] | information limit: the sender is the legitimate GCS identity; **needs MAVLink-2 signing** (PX4 SITL rejects an unsigned forgery, one command, n = 10) | documented; blocked on authenticated telemetry |
| Informed impersonation | `artifacts/sitl/P2_gcs_impersonation_summary.md` (SITL, original batch) | informed 0/10 detected; naive 10/10 | same | not re-run (needs WSL + PX4); cited |
| PX4 GPS drift detected at release only | `artifacts/sitl/P2_summary.md` (SITL, n = 10) | 10/10 at or after the window closed, 0 pre-onset alerts | PX4's position/velocity are estimator outputs, so the cross-check loses independence | not re-run; cited; evidence of a different kind (an independent raw sensor) is needed |
| Existing DoS / command-injection coverage | extended re-run; `artifacts/sitl/` | DoS 16/16 sessions [0.81, 1.00]; command injection 12/16 [0.51, 0.90] (the four misses are all `gcs_replay`) | fine on `SIM`; SITL n = 3–10 | none |
| Stage-1 regression parity | `aegis benchmark --out <scratch> --no-figures` + `scripts/compare_benchmark_runs.py` | 6535 / 4 / 16826 / 65; 378/378 cells | — | pass |

## 7. Gaps

### P0 — mandatory item missing, factual error, unsafe claim, or broken demonstration path
| # | Gap | Why P0 | Owner / action |
|---|---|---|---|
| P0-1 | **No demonstration video** ("screen recording of a real run"; the archive must contain it) | mandatory, §9 and §10 | human: record (plan, step 1) |
| P0-2 | ~~No `LICENSE` file; no third-party notices~~ | §10 "dependency list with licences", §11.2 | **added in the hardware-free sprint** (`LICENSE`, `THIRD_PARTY_NOTICES.md`); the copyright-holder line and the *unverified* rows in the notices are for the team to confirm |
| P0-3 | Risk-register fabricated sign-offs and non-existent mitigations (C1–C4) | integrity declaration; mandatory deliverable | **fixed here** |
| P0-4 | Stale numbers contradicting artifacts in `current_state.md` / `next_state.md` / `DEMO_RUNBOOK.md` (C5–C8) | factual error | **fixed here** |
| P0-5 | Raw hardware captures are git-ignored ("holds vehicle position") but the template wants flight logs and datasets in the archive; ALFA/PX4 logs are fetched, not stored | "a link alone is not sufficient" | team decision: include the captures (position privacy), or redacted copies + SHA-256 (the manifests record them); include the trained model `models/isoforest.joblib` (git-ignored; retraining may not reproduce it bit-for-bit); commit or replace the template PDF |
| P0-6 | Team ID, date, signature, integrity declaration, "final team target" per requirement | human-only | fill; do not pre-sign |
| P0-7 | AI-tool declaration (§11.1) | integrity | draft names Claude Code; the team must state what verification it performed |

### P1 — important evidence or explanation missing
| # | Gap | Action |
|---|---|---|
| P1-1 | **Confidence intervals: partly done** (`SIM`, session level, `extended_rerun/stats/`); none for SITL, replay or hardware | n = 4 per mode: the intervals are wide and say so |
| P1-2 | ~~No simple-threshold baseline~~ **done in the second pass** (`SIM` only, caveated); **autopilot-checks baseline still missing** (template §5.1, §5.3) | needs failsafe/EKF-check output on attacked sessions, which no artifact holds |
| P1-3 | **No false-alarms-per-hour with an upper bound** | exposure is too small: 90 s of hardware live; ALFA only ~0.64 h of author-labelled benign time (derived, draft §7). Do not report a rate |
| P1-4 | **No healthy-estimator hardware capture** | one receive-only capture with a valid horizontal solution (open sky; no arming, no writes) |
| P1-5 | **No own-flight data**, no attack on a real vehicle | cannot be fixed this week without a flight; stay explicit |
| P1-6 | Detection-vs-magnitude plot and per-class latency distribution | **partly done**: GPS-drift sweep + plot (ML off / on), per-class min/median/max; no distribution plot, no sweep for the other five classes |
| P1-7 | Architecture and workflow diagrams are Mermaid source, not rendered; ~~no operator screenshot~~ (two screenshots now tracked in `demo/screenshots/`) | diagrams **rendered in the second pass** (`docs/figures/`); nothing left except the video |
| P1-8 | Clean-machine re-run (the committee re-runs the tests) | fresh venv, `pip install -e ".[dev,external]"`; `pyulog` is **not installed** in this venv, so the PX4 ULog replays cannot be re-run here |
| P1-9 | Companion-computer resource figures: **none** | state "not measured"; do not carry over the withdrawn Pi figures |

### P2 — presentation
README title wording (C11); the `config_dir` label bug in `replay_ap_tlog.py` output (already disclosed); the two frames missing from
the loopback replay; consolidate the `docs/` status ledgers; `REPORT_ALIGNMENT.md` still maps the *Stage-1* sections.

## 8. What can and cannot be claimed

**Can be claimed today (each with its tag):**
* The unchanged pipeline ingests live MAVLink from PX4 SITL, ArduPilot SITL and a physical ArduPilot-family autopilot, receive-only
  (`SITL`, `BENCH`): 5,130 frames, 0 CRC/garbage/gap/disconnect, `bytes_sent` 0.
* Six attack classes are implemented and detected on the simulator with the reported per-mode results and listed gaps (`SIM`).
* `SITL` link-level detection (**original batches on earlier code with a dirty tree; final-code clean-tree re-runs are n = 3**, `VALIDATION_EVIDENCE.md` §1d):
  ArduPilot GPS drift 3/3 (+2.69 s), PX4 GPS drift 10/10 **at release only**, rogue-sysid command injection 10/10, drop 10/10, delay 9/10,
  replay 10/10 (via sequence continuity), GNSS degradation 10/10. With MAVLink-2 signing bootstrapped, an unsigned forged force-disarm on a
  *disarmed* PX4 SITL vehicle was rejected and flagged 10/10 (signing rule: 10/400 pre-onset false alarms; any rule 307/400); replay of a
  signed frame and other commands were not tested (`artifacts/sitl/`).
* Stage-1 thresholds **do not transfer** to real links; the failure, its cause and a per-vehicle calibration are documented (`REPLAY`).
* On one replayed stationary bench capture the estimator gate removes 4 `GPS_SPOOFING` alerts that the team judged to be non-attacks (stationary per the vehicle's own unauthenticated velocity and the operator); **in-sample**, one capture (`REPLAY`). This is not evidence that spoofing is detected, prevented or absent.
* Tamper-evident alert log (SHA-256 hash chain, unsigned); software-enforced receive-only operation on the serial path.
* The IDS now reports vehicle-stated GPS/estimator health without alerting (`REPLAY` of `BENCH`, claim class none).

**Must not be claimed yet:** detection of GPS spoofing or any attack on a real vehicle; that zero alerts means authentic GPS;
immunity to spoofing; "production-ready", "safe for autonomous flight", "deployed", "field-tested"; flight-trial readiness beyond a
*proposal* for receive-only trials; any prevention/mitigation effect on a vehicle; any figure on a Raspberry Pi/companion computer;
a false-alarm rate per hour; accuracy "on unseen flights"; fuzz-testing; tamper-proofing against an attacker who controls the host.

## 9. Final-week plan

1. **(P0) Record the demonstration video** (human, ~1 h): two clearly labelled segments — (a) `REPLAY` of the real 2026-10-28
   capture through `aegis serve --source replay`, header showing BENCH, the new health note and 0 alerts; (b) the `SIM` attack
   demo from `docs/DEMO_RUNBOOK.md`, labelled SIM. Not slides.
2. **(P0) Add `LICENSE` and `THIRD_PARTY_NOTICES`**; decide the archive contents for raw captures and the template PDF (P0-5).
3. **(P0) Fill team fields, choose and write the "final team target" column**, confirm §11.1, sign §11.3.
4. **(P1) Generate CIs and the detection-vs-magnitude/latency plots** from existing artifacts; render the two diagrams and one BENCH screenshot.
5. **(P1) Clean-machine re-run** of `pytest`, `ruff`, `aegis benchmark --out <scratch> --no-figures`; fill the draft's §8.2 from it.
6. **(P1, only if permitted and safe) One receive-only capture with a valid horizontal estimator solution** (open sky; no arming, no
   parameter writes) with `--tlog`, then replay with the gate on and off.
7. **(P2)** README title; consolidate the status ledgers.
8. Run `aegis-reviewer` over the final draft; freeze, tag the commit, copy it into the draft header.

## 10. Verification performed

All on 2026-10-29, Windows 11, CPython 3.13.15, from the repository root.

| Check | Command | Result |
|---|---|---|
| Full test suite | `.venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts= -q -rfE` | **899 passed, 3 skipped, 0 failed** (149.6 s); 902 collected = `tests/unit` 803, `integration` 92, `e2e` 2, `backend/tests` 5. The 3 skips are POSIX PTY tests |
| Lint | `ruff check src tests scripts backend` | All checks passed |
| Frontend | `npm --prefix frontend test` · `npm --prefix frontend run build` | 10 passed (8 existing + 2 new) · `tsc --noEmit` + `vite build` ok |
| Stage-1 regression | `aegis benchmark --out <scratch> --no-figures` | TP/FP/TN/FN **6535 / 4 / 16826 / 65**; 42 rows × 9 non-timing columns = **378 of 378 cells identical** to `artifacts/benchmarks/results.csv`; per-attack table identical; committed `artifacts/` untouched |
| Extended benchmark re-run (reviewer finding S2) | `scripts/benchmark_extended.py --out <scratch> --workers 6` | 5 s-grace rows identical to the committed 2026-09-24 artifact (9088 / 39 / 40813 / 1133); no-grace FP 463 vs 470 (FPR 0.0108 vs 0.0110); benign link-stress rows identical; only `dos:blackout` tail/attribution changed; committed artifact untouched |
| New feature on real bytes, through the live runner | `virtual_serial_replay.py` + `run_serial_ids.py` (bundle README) | 453 decisions during the stream, 0 alerts, both flags on 452; the one later alert is the silent tail of the 95 s window used for that run |
| New feature through the real API | `aegis serve --source replay --tlog … --replay-speed 10`, then `GET /api/status`, `/api/events` (saved: `replay/navigation_health_api/`) | `environment` REPLAY, 5,130 frames, `horizontal_solution` false, `gps_healthy` false, `quality_flags` both, 0 events |
| Referenced paths | script over every backticked path in the draft and this audit | 205 resolve directly; the 42 others are module-relative or bundle-relative shorthand, all resolved to a real file; none unresolved |
| Section order and weights | heading list vs the template | 11 sections + 2.1, 2.2, 5.1–5.3, 6.1–6.3, 7.1–7.2, 8.1–8.3, 9, 11.1–11.3 in the template's order; weights 5+8+7+8+18+12+8+14+8+7+5 = 100 |
| Numbers in the draft | spot-checked against each cited artifact | all agree; derived values are labelled (ALFA benign hours, rule-of-three bound) |

**A pre-existing flaky test, found and hardened.** `tests/unit/test_run_serial_ids.py::test_tlog_tees_the_clean_downlink_and_stays_receive_only`
failed in three consecutive runs on this tree. In isolation it passed 5 of 8 here and **4 of 8 on the unmodified `c849012` checkout**, so it is
independent of this change: the loopback `Device` streams on accept and the transport purges input at open (the latent race recorded in
`docs/GPS_WORKSTREAM_PROGRESS.md`). The assertion now tolerates up to 3 lost head frames and keeps the real invariant (the tee equals exactly the frames the
transport received, as one contiguous run). 14 of 14 isolated runs pass. It is a single hunk in the same file and commit as the new health tests, so it is easy to revert on its own.

**Reviewer pass (`aegis-reviewer`, read-only, 2026-10-29).** No fabricated numbers; re-derived hardware, ALFA, PX4-SITL, resource and code claims all
traced. It found one blocker and ten should-fix items, all verified and fixed in this change: the risk register's non-existent BOM/BEC (RSK-02, §3.2, §4
checklist) and over-strong RSK-05/06 text; the draft omitting the no-grace FPR (0.0110), the link-stress rows (61.28 % / 99.97 %) and the extended artifact's
2026-09-24 date (pre-Stage-2 code; since re-run into scratch on the submitted tree, see draft §5.3); ALFA/PX4 Flight Review hours mislabelled as benign exposure and the PX4 Flight Review trigger rates (5.51 % /
93.42 %, 48 % yaw-course) missing; original-versus-final-code SITL counts and dirty-tree provenance; "4 of 6 SITL classes" (now 3 direct + 1 indirect);
the signing result's scope (one command, disarmed vehicle, 10/400 and 307/400 pre-onset); "cannot disturb flight control" (now not claimed); causes of the
wander stated as undetermined; the API check now preserved (`replay/navigation_health_api/`); vacuous chain-OK at length 0; stale-state wording. Remaining
reviewer notes left as stated limits: the committed extended-benchmark artifact keeps its 2026-09-24 numbers (the scratch re-run is cited, not committed; regenerate
`artifacts/benchmarks_extended/` deliberately if the team wants it refreshed), tests that need git-ignored captures skip without them (an archive re-run will show more than 3 skips), and the `DEMO_RUNBOOK.md` title still
says "Prevention" (C11).

### Hardware-free sprint verification (2026-10-29, same machine, all new)

| Check | Command | Result |
|---|---|---|
| Full Python suite | `python -m pytest -p no:cacheprovider -o addopts= -q -rfE --junitxml=<scratch>` | **907 passed, 3 skipped, 0 failed**, 910 collected (unit 811, integration 92, e2e 2, backend 5), 155.3 s; the 3 skips are POSIX PTY tests (`artifacts/validation/submission_rerun_20261029/test_suite_run.json`) |
| Lint | `ruff check src tests scripts backend` | All checks passed (after one import-order fix in the new sweep script) |
| Frontend | `npm --prefix frontend test` · `npm --prefix frontend run build` | 11 passed · `tsc --noEmit` + `vite build` ok |
| Stage-1 regression | `aegis benchmark --out <scratch> --no-figures` + `scripts/compare_benchmark_runs.py` | 6535 / 4 / 16826 / 65, 378 of 378 non-timing cells equal |
| Stage-2 verification suites | `python scripts/verify_stage2.py` | 8 suites passed, 1,949.9 ms (`SIM`, hand-built inputs) |
| Extended benchmark | `scripts/benchmark_extended.py --workers 4` | 5 s-grace rows identical; no-grace FP 463 (committed 470); `sessions.csv` identical up to `detected` |
| Label independence | `pytest tests/unit/test_label_independence.py` | 8 passed |
| Live dashboard, browser | `aegis serve` (SIM) and `aegis serve --source replay` on the local capture, headless Chrome | SIM: attack injected, HIGH / GPS SPOOFING, hash chain OK; REPLAY: "Replaying", the unauthenticated-GPS line, the unconfirmed-position note, 0 persisted alerts, **0 coordinate-like numbers on the page**; screenshots in `demo/screenshots/` |

**Not done:** no clean-machine run; no
network fetch of external datasets, so the ALFA / PX4 replays were **cited, not regenerated** (`pyulog` is not installed in this venv); the SITL
batches need WSL/PX4 and were not re-run; nothing was sent to, written to or armed on the vehicle at any point; the template PDF and the
existing `stash@{0}` were not touched.

## 11. Second pass (2026-10-29, same branch)

Scope: baseline comparison, `SITL`/`REPLAY` session intervals, clean-environment run, rendered diagrams, licence audit, reviewer pass. No detector, threshold or config was changed; no hardware was touched; nothing was transmitted.

| Task | Status | Evidence |
|---|---|---|
| Simple-threshold baseline | **Done (`SIM`, caveated)**; autopilot-check baseline **blocked** (no failsafe output for attacked sessions) | `artifacts/validation/baseline_comparison_20261029/`; baseline defined in git (`9944a57`) before the run, run time not independently timestamped; all baseline FPs come from one climb-rate limit |
| `SITL` / `REPLAY` uncertainty | **Done from existing summaries**, trial / flight level | `artifacts/validation/session_ci_sitl_replay_20261029/session_ci.md`; no logs regenerated; one airframe, host and script family; n = 3 to 24 |
| Clean-environment reproducibility | **Done (clone + venv; no container)** | `artifacts/validation/clean_install_20261029/README.md`: 899 passed, 11 skipped, 0 failed; ruff clean; newer floor-pinned dependency versions resolved than on the host |
| Report diagrams | **Done** (Figures 3 and 4) | `docs/figures/` (`.mmd`, `.png`, `.svg`, README); rendered with mermaid-cli from a scratch install |
| Licence audit | **Partial** | `THIRD_PARTY_NOTICES.md` status summary: verified / declared-not-audited / unresolved |
| Reviewer pass | **Done** | invoked: `aegis-reviewer`, `aegis-security`; **not** invoked: `aegis-validation`, `aegis-detection`, `ecc:*` reviewers |

**Reviewer findings and disposition.**
- Fixed: report wording of the no-transmit claim (serial runner only; exit 3 detects, does not prevent; the `SITL` UDP transport does transmit); fail-open consequence of the forged-`EKF_STATUS_REPORT` gate stated next to the gate claim; baseline row now states FPR source, 6/6 benign sessions with a false alarm, same-author caveat and "defined in git before the run" instead of "pre-registered"; "disarmed in most batches" and "different runs, not pooled" added to the interval sentence; the PX4 physics-trigger rate (16/24 flights) stated as a limitation; ALFA negative result (3 of 25 fault events produced any threat) added to the report and `VALIDATION_EVIDENCE.md`; this audit's stale rows (baseline, diagrams, intervals, licences) and the archive manifest's figures row.
- Reviewer claim **not substantiated**: that committed `events.sqlite` files under `artifacts/hardware` may hold bench positions. `git ls-files` lists no `.sqlite` file; they are git-ignored.
- Open, for the team: (1) `commit [TBD at freeze]` and the test count: the draft's 907-passed run was on the uncommitted sprint tree; re-run on the frozen commit; the committed root `CLAUDE.md` still says 545 and `.claude/CLAUDE.md` 73 (not edited here). (2) About 167 tracked occurrences of `/home/astryx` and `D:\Ardra\...` paths (WSL username, team directory) in `artifacts/ardupilot/*`, `scripts/` and `THIRD_PARTY_NOTICES.md`; accept as pseudonymous or redact copies, not the evidence in place. (3) The template PDF in `docs/` is a 25-page Word export dated 2026-10-06 replacing a text file named `.pdf` in git; confirm it is the organisers' original or rename it; not committed here. (4) Build the archive from `git ls-files` / `git archive`, not a zip of the working tree (raw `.tlog` / `.rawbin` bench captures are git-ignored but present locally). (5) Tauri icon origin, ALFA source licence (manifest says CC BY 4.0; bundled README says CC0) and the `LICENSE` holder line remain unresolved. (6) `joblib` models are pickles: load only the checksummed file. (7) `make_session_ci_sitl_replay.py` reads `artifacts/` relative to the working directory: run from the repository root.
- Not covered by any agent: whether a forged status stream plus a velocity-consistent offset evades the remaining gated checks (hypothesis, untested); template PDF page content against the draft headings.

Checks run in this pass (host unless stated): `ruff check src tests scripts backend` clean; `pytest -p no:cacheprovider -q`: 907 passed, 3 skipped, 0 failed (counted from progress output); `python scripts/verify_stage2.py`: 8 of 8 suites passed (SIM, hand-built inputs); `npm test`: 11 passed; `npm run build`: ok; Stage-1 counts 6535 / 4 / 16826 / 65 reproduced by `scripts/baseline_comparison.py` (a full `aegis benchmark` re-run was not repeated: no source file changed since the earlier 378 of 378 comparison).
