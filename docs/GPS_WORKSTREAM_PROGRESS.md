# GPS workstream — progress log (interruption-safe)

Living status for the GPS workstream. It is updated after each milestone and before each long-running check.
Crash checkpoint (local, git-ignored): `.claude/checkpoints/2026-10-26-gps-iter2-crash-recovery.md`.
Plan: `docs/GPS_WORKSTREAM_PLAN.md`.

## Final-week hardware verification (2026-10-29), `main` a44dd9c: receive-only, nothing transmitted
Evidence: `artifacts/hardware/gps_hw_verify_20261029/` (README, `manifest.json`). Claim class none; live part `BENCH`-class, replay part `REPLAY`.
- **Live (physical vehicle, disarmed + stationary per telemetry):** COM7 (the only serial port; CP210x radio bridge), 115200,
  90 s, `run_serial_ids.py` with `--defense-mode passive --no-reconnect`. 5,130 frames, 0 loss/CRC/garbage/gaps,
  `bytes_sent` 0, **0 IDS alerts in 451 decisions**. The vehicle reported 3D fix with 6 to 7 satellites, `eph` ~8, GPS-healthy
  bit 0/180, EKF with **no horizontal solution** (`0xa7`), and position wander up to 34.3 m while stationary.
- **Offline (`REPLAY` of the same bytes):** gate on 0 alerts; gate off (Stage-1 rule) 4 false `GPS_SPOOFING`. Re-replay of 008/009
  matches the committed artifacts (modulo CRLF). One capture, in the gate's design setting: not an independent test.
- **Checks run (this session, Windows, Python 3.13.15):** focused GPS/serial/defense suites pass; **full pytest 883 passed, 3
  skipped, 0 failed**; `ruff check src tests scripts backend` clean; frontend `npm test` 8/8 and `npm run build` OK;
  `scripts/verify_stage2.py` exit 0 (8 suites, 17 PASS lines; a SIM demo, not validation evidence); Stage-1 regression
  `aegis benchmark --no-figures` TP/FP/TN/FN **6535 / 4 / 16826 / 65**, identical to `artifacts/benchmarks/summary.md`.
- **Code change:** optional `--tlog` on `run_serial_ids.py` (single consumer, via `TapTransport`), +2 tests. No `src/` or `configs/` change.
- **Findings:** (1) the IDS is silent when the receiver says 3D fix but the vehicle's own health flags say the position is not
  trustworthy: no coverage/health line exists for it (`docs/VALIDATION_EVIDENCE.md` Section 3). (2) No hardware capture has a
  healthy EKF, so the gate's un-gated branch is untested on hardware. (3) Not run: `aegis-reviewer` on these claims.
- **Next action:** one more receive-only capture of the same command with the vehicle under open sky until `EKF_STATUS_REPORT`
  shows `POS_HORIZ_ABS`, then replay it gate on vs off. Without it the demo can only show the degraded-estimator path.

## Integration session (2026-10-26 evening): teammate branch `origin/stage2-autonomous-defense`
Live status. Updated at each milestone.
- **Audit (verified).** `main` 90b9aa2 and `origin/main` 10e5b22 share **no common ancestor** (different root
  commits). On 2026-10-24 22:25 +0530, `filter-branch` rewrote all 62 `origin/main` commits to strip
  Co-Authored-By trailers. 56 of them carried a trailer; the other 6 were rewritten only because their parents
  changed. All 62 pairs have identical trees, author, date and subject; `origin/main` has 56 trailers and `main`
  has 0. `main` is those 62 rewritten commits plus 433f4b6 and 90b9aa2. The teammate branch (c96a109, 4 commits
  by Madhav Choudhary) forks from the *old* 10e5b22, so a plain `git merge` fails ("unrelated histories"), and
  `--allow-unrelated-histories` would pull back 62 duplicate commits, 56 of them trailer-bearing. For the same
  reason, pushing `main` would need a force-push over `origin/main`.
- **Protected (verified).** Local branch `safety/iter2-wip-2026-10-26` = c984c0f is the full working tree as of
  2026-10-26 22:39 +0530 (17 modified + 36 untracked files) on top of 90b9aa2. This log has changed since. Also `.claude/checkpoints/2026-10-26-pre-integration/`
  holds `tracked_wip.patch` (applies cleanly to HEAD), `untracked_wip.tar` (36/36 files), status, HEAD and
  `SHA256SUMS`. The `src`+`configs` diff sha256 is still `b4d434e3…7eaf`, the tree that was gated.
- **Plan.** An isolated worktree on branch `integration/stage2-defense-candidate` from 90b9aa2. Cherry-pick the 4
  teammate commits (authorship kept, no duplicated history). Apply the iteration-2 WIP on top, uncommitted.
  Resolve the overlaps; keep the committed Stage-1 baseline artifacts. Then validate and review. Nothing goes on
  `main` until the user reviews it.
- **Candidate built (verified).** Worktree `<scratchpad>/wt_integration`, branch
  `integration/stage2-defense-candidate`: 90b9aa2 → 5c59cdd, 539b79c, 804a28b, 51288ab (cherry-picks with `-x`).
  - Cherry-pick conflict: only `docs/TESTING.md`, resolved as the union.
  - Iteration-2 layer conflicts (staged, uncommitted): `extractor.py`, `physics.py`, `test_app_live_source.py` and
    `TESTING.md`, all resolved keeping both sides. `HANDOFF.md` overlapped too but auto-merged.
    `docs/.obsidian/workspace.json` (editor state) was left out. Resolved patch:
    `.claude/checkpoints/2026-10-26-pre-integration/candidate/`.
  - `ruff check src tests scripts backend` clean.
  - Tests, combined across two runs (not one run), both with `PYTHONPATH=<wt>/src`; without it, 4 collection
    errors:
    - Full suite: **844 passed, 8 skipped, 0 failed** (`runs/pytest_candidate_full.txt`). 5 of the skips are absent
      git-ignored tlogs: bench 007 ×4 and SITL `benign_001` ×1.
    - Re-running the two data-dependent files with those tlogs copied in: 90/90 passed (output not saved).
    - Implied total: 849 passed, 3 skipped (Windows PTY).
  - Model and tlogs were *copied* into the worktree's ignored paths (no junctions) and must be deleted with it.
- **Found while integrating:** the teammate's root `CLAUDE.md` adds an "Autonomous JIT Skills" rule that tells
  agents to run `npx -y agentic-awesome-skills …` and `rm -rf ~/.agents/skills/<id>` on their own
  (`docs/SKILLS_REGISTRY.md`). That is unvetted package execution by agents: a supply-chain risk. **Not followed.**
- **Stage-1 regression (SIM; scratch output only, `--no-figures`).** Comparator: `compare_results.py bench`.
  - The first candidate runs did not log the import path, so they are superseded. The re-runs (2026-10-26
    20:42–20:47Z, `runs/bench_candidate_r2_{model,nomodel}.log`) record `aegisflight` loaded from
    `wt_integration/src`.
  - Candidate staged `src`+`configs` diff sha256: `f92ab9f1…8a18`.
  - Candidate, ML on: **6535 / 4 / 16826 / 65**. 378/378 CSV cells identical to `artifacts/benchmarks`; the only
    JSON leaf that differs is `/config/python`.
  - Candidate, ML off: 378/378 CSV cells identical to `artifacts/benchmarks_ablation_no_ml`; the JSON again differs
    only in `/config/python`.
  - Clean main HEAD 90b9aa2 (`wt_head`, in session 7f9bdbfb's scratchpad), `--no-model`: **6504 / 0 / 16830 / 96**.
    378/378 identical to the teammate's `artifacts/benchmarks` and to the committed ablation.
  - **So the teammate's numbers are the ML-off ablation written over the ML-on baseline.**
    - The teammate's committed `results.json` itself records `model_used: false`.
    - Clean 90b9aa2 with `--no-model` reproduces it cell for cell (378/378), so the change is fully explained by
      the missing git-ignored model.
    - On this 6-seed SIM grid the teammate code changes no Stage-1 decision.
    - The harness drops ML without a warning when the model file is missing (`benchmark/harness.py:63-64`); the
      only trace is `model_used: false`.
  - In the candidate, the 7 baseline files (`artifacts/benchmarks*`) are restored to 90b9aa2, together with the 5
    docs the teammate deleted, and the JIT-skills line is removed from the root `CLAUDE.md`. Patch:
    `.claude/checkpoints/2026-10-26-pre-integration/candidate/integration_fixes.patch`.
- **HIGH safety finding (verified by the lead in code; worktree line numbers).**
  - `POST /api/defense/mode {"mode":"active-ips"}` (`backend/app.py:240-252`) has no `_sim_only` guard. The token
    is checked only when `AEGIS_API_TOKEN` is set, which it is not by default.
  - After that, on any non-SIM source (SIM has no transport), `LiveEngine` calls
    `feed.transport.send(counter_frames)` in two places: `backend/engine.py:575-579` (the tick loop) and
    `:411-415` (`POST /api/defense/override`). The frames include SET_MODE and a force-disarm (magic 21196,
    `mitigation/actuator.py`). For serial that is a real `ser.write` (`sources/mavlink_serial.py:618-626`).
  - `backend/sources.py:59-60` accepts `active-ips` for every source kind. `aegis serve --gcs-notify` attaches the
    live transport to the notifier (`engine.py:261-262`) and notifies in any mode.
  - This breaks the receive-only bench rule and the `backend/sources.py:13` "nothing here transmits" contract.
    **This blocks merging to `main`** until it is guarded.
- **ALFA on the candidate (`REPLAY`, claim class none; 17:24:28–17:36:56Z, alone; the log records the worktree's
  `src`).**
  - Compared with `artifacts/validation/estimator_gate_v2/alfa/after/`:
    - `alfa` (E2): 683 of the 684 compared leaves are identical. The only difference is `wall_time_s` (547.7 vs
      707.9 s), a run-time field the comparator does not exclude.
    - `alfa_calibrated` (E2b): 517/517 identical.
  - So the teammate layer changes no ALFA result in these two runs. Outputs are in scratch only
    (`runs/alfa_candidate*`); nothing was written to `artifacts/external/`.
- **Reviews received.**
  - **aegis-security: BLOCKERS.**
    - B1: the dashboard/API `active-ips` path transmits to a serial FC. Reproduced in-process with a fake
      transport: DO_SET_MODE from 1/191.
    - B2: `run_serial_ids.py --defense-mode active-ips` writes counter-frames to the port, and the exit-3 transmit
      guard is bypassed outside passive mode.
    - HIGH: `aegis serve --gcs-notify` writes STATUSTEXT to the FC link even in passive mode. In
      `run_serial_ids.py` the notifier sends UDP only, but to any host given on the command line (default
      127.0.0.1:14550), so it can send off the machine.
    - HIGH: force-disarm (magic 21196) fires when `armed` is unknown; "recovery" sends DO_SET_MODE AUTO; the IPS
      overrides a legitimate GCS RTL; the disarm "veto" only logs.
    - HIGH: the cadence guard flags one command against itself (Δt = 0).
    - HIGH: the `REDTEAM_AUDIT_STAGE2`/`RISK_REGISTER` claims contradict the code (`bytes_sent=0 VERIFIED`, a
      `process_telemetry()` that does not exist, a disarm veto, parameter attestation, 12 trace files that do not
      exist); `engine.py` hard-codes "Hardware verified: Cube/Pixhawk on TELEM1" in the UI.
    - MEDIUM: `mavlink/signing.py` duplicates P4 signing and accepts any timestamp on a new stream; the signing
      key literal sits in `scripts/verify_stage2.py`; the sanitizer and inline bridge are not wired in.
  - **ecc:security-reviewer:**
    - H1: live sources can transmit through the `/api/defense/*` endpoints.
    - H2: `--gcs-notify` writes to the FC link, and its host is unvalidated.
    - M1: the Origin check ignores port and scheme, so any `localhost:*` page can fire the no-body POSTs.
    - M2: the control plane is unauthenticated by default.
    - M3: `VITE_AEGIS_API_TOKEN` gets baked into the bundle.
    - M4: unvalidated `drift_rate_ms`/`mode` can kill the sim loop.
    - M5: signing replay window.
    - M6: unsigned commands spoofing sysid 1.
    - LOW: the Rust fastpath can panic on an out-of-bounds index; Tauri `csp: null`.
    - Bind address is loopback by default (OK).
  - **aegis-detection:**
    - The conflict resolution is correct and nothing is lost on either side.
    - CUSUM (default off) re-creates the bench false positives if enabled: 008 gives 11 and 009 gives 8
      GPS_SPOOFING alerts. It also adds SIM false positives. `PhysicsDetector.cusum` is dead state.
    - The HEARTBEAT type-6 filter does not touch SIM, bench or ALFA, but changes PX4/SITL mode and armed liveness
      (re-running SITL evidence may differ). The cadence-guard Δt = 0 bug is confirmed.
    - `GoldenFlightState` uses the ungated `pos_residual_m`.
  - **aegis-validation:**
    - The teammate's `artifacts/benchmarks*` equal the committed ML-off ablation. The extended run was reported
      reproduced for 34/116 sessions (an attributed review note; output not saved as evidence). Verdict:
      KEEP-BASELINE for all 7 files.
    - The README and report draft contain numbers with no artifact behind them (Pi CPU/RAM/power, 3.2 ms compute,
      82.4 km / 4.8 h, test counts 280+/650+/708/729+, a calibration path that does not exist, the prevention
      table).
    - `verify_stage2.py` is a demo with hard-coded expectations, not evidence.
    - Restore the 5 deleted docs.
  - **aegis-px4-mavlink:**
    - Framing, decoding, counting, timestamps and all defaults are unchanged.
    - 1a `--gcs-notify` transmits on the vehicle link (UDP sends are not counted in `bytes_sent`).
    - 1b `active-ips` is enabled through the API on live sources.
    - 1c `run_serial_ids` guard bypass.
    - **1d (new):** `_step_cyber_physical_twin` overwrites dashboard telemetry for non-SIM sources (checked on
      REPLAY):
      - on 008, alt 0.65 is shown against a real 185.14 in 487 updates (reproduced by aegis-reviewer);
      - groundspeed shows 12.0 and mode "AUTO" where the real value is absent;
      - `armed` is stale;
      - broadcasts are skipped while state ≠ NOMINAL: 137 of 625 ticks on 008 in the reviewer's re-run;
      - mitigation reaches `AUTO_MITIGATING` in passive mode on benign 008.
    - **HEARTBEAT A/B results** (reported by aegis-px4-mavlink; scripts at `<scratchpad>/review_px4/hb_ab*.py`,
      output not saved):
      - 0 verdict differences on bench 005–009, 32 AP SITL tlogs, PX4 benign, 24 PX4 live/p2i, and ALFA (194,628
        decisions, ML off);
      - internal `armed` and `heartbeat_age` change where type-6 heartbeats exist;
      - suggested filter: `autopilot != 8`.
    - Signing interop with the P4 parser: OK.
    - Rust is standalone.
    - **Signs off** the socket-test resolution and the open-time purge pin and doc.

**Verdict (lead, 2026-10-26):** the candidate passes every *regression* gate:
- tests: 844 passed, 8 skipped, 0 failed (the 5 data skips then pass);
- ruff clean;
- Stage-1 identical with ML on and with ML off;
- ALFA identical except `wall_time_s`;
- bench 008/009 iteration-2 replays summary-identical to the committed gate artifacts (37/37 and 11/11 leaves;
  aegis-reviewer re-run at `<scratchpad>/rev/replay_00{8,9}_cand.json`).

It is **not mergeable** to `main`, because of the safety blockers (security B1/B2, H1; px4 1a/1b/1c/1d) and the
evidence-integrity problems in the teammate's docs. **Not merged; nothing committed or pushed.**

**Next concrete action:** the user decides how to proceed:
1. Recommended: commit GPS iteration 2 on `main` first, without the teammate layer (scope already reviewed).
2. Ask the teammate, or authorise the lead, to make live actuation SIM-only:
   - `_sim_only` on `/api/defense/*`;
   - `SourceSpec` refuses non-passive modes for live kinds;
   - remove the `transport.send` loops and the notifier transport attachment;
   - limit `--gcs-notify-host` to loopback;
   - restore `run_serial_ids` receive-only;
   - make the twin SIM-only.
3. Remove or rewrite the unsupported claims (REDTEAM/RISK_REGISTER/README/report draft, hard-coded "Hardware
   verified").
4. Re-run this candidate gate.

## Blocker fixes on the candidate (2026-10-27), working tree of `wt_integration`, uncommitted
Smallest focused fixes; nothing in the GPS detector or the defense design was rewritten.
- **Live sources are receive-only.**
  - `SourceSpec` refuses `active-ips` for any non-SIM kind.
  - `LiveEngine.set_defense_mode("active-ips")` raises on live sources, and `/api/defense/mode` returns 409.
  - Both `feed.transport.send` loops are removed from `backend/engine.py`: counter-frames are reported, never
    transmitted.
- **`run_serial_ids.py` is receive-only again.**
  - `--defense-mode` is limited to passive/advisory, and the `tr.send` loop is gone.
  - The exit-3 `bytes_sent` check and the `passive_check` summary are unconditional again.
- **GCS notifications never use the vehicle link.**
  - The engine no longer attaches `feed.transport` to the notifier.
  - `GcsNotifier` refuses a non-loopback target and binds its socket to 127.0.0.1.
  - `SourceSpec`, the CLI and `run_serial_ids` refuse a non-loopback `--gcs-notify-host`.
- **Dashboard integrity.**
  - The cyber-physical twin runs, and the "compact telemetry" skip applies, only for SIM, so live and recorded
    telemetry is shown as received.
  - The hard-coded "Hardware verified: Cube/Pixhawk…" topology text is replaced.
  - The UI disables ACTIVE IPS when the source is not SIM.
- **Countermeasures.**
  - Disarm only when `armed is False`, and never with the 21196 force code (the default is now `force=False`).
  - No mode restore when the trusted mode is unknown (the AUTO fallback is removed).
  - `encode_set_mode` refuses unknown or PX4 mode names.
  - A mode change requested only by allow-listed GCS sysids is not countered.
  - The "VETO_DISARM" text now says "flagged (not blocked)".
- **Cadence guard** (`detectors/protocol.py`, default off, and `mitigation/submode_classifier.py`): each command is
  evaluated once, and Δt must be > 0.
- **API hardening.**
  - The control-plane Origin must be allow-listed or exactly same-origin; the old check compared the hostname only.
  - `/api/simulation/attack` validates `mode` and `drift_rate_ms`, returning 400.
- **Evidence and claims.**
  - Removed the signing-key literal in `verify_stage2.py` (now a per-run random key) and its "100% COMPLIANT /
    ready for submission" output.
  - README: artifact numbers (17.7/23.6 ms compute); the prevention table, DO-326A, "20 sub-modes", Rust/Tauri,
    test-count and MIT/LICENSE claims replaced.
  - Withdrawn with reasons, original text kept in commit 5c59cdd: `stage2_report_draft.md` and
    `REDTEAM_AUDIT_STAGE2.md`.
  - Corrected: `RISK_REGISTER.md` (12 invalid references remapped, unsupported mitigations rewritten),
    `current_state.md`, `SKILLS_REGISTRY.md` (human-installed only), `HANDOFF.md`, `TESTING.md` (Stage-1 regression
    back in the gate), `QUICKSTART`, `installation`, `DEMO_RUNBOOK`, `CODEBASE_MAP`, `docs/README.md`.
  - `evalPanels.tsx`: validation rows restored to the evidence-backed set (IEEE/mIDS/Pi/82.4 km/Rust rows removed).
- **Regression tests.**
  - New `tests/unit/test_defense_safety.py` (26 tests): 15 of its first 16 fail on the pre-fix tree; the one that
    passes is a case that was already correct.
  - New `test_replay_telemetry_is_shown_as_received_and_never_thinned`: fails pre-fix, 104 vs 200 broadcasts.
  - `test_cli_serve.py`: loopback and live `active-ips` refusals.
  - Frontend: `tsc --noEmit` 0 errors, `node --test` 8/8, and `vite build` OK (output in scratch, not
    `frontend/dist`).
- **Left as is (disclosed, default off or not wired):**
  - CUSUM is not estimator-gated, so `cusum_enabled` must stay false.
  - `GoldenFlightState` uses the ungated residual.
  - `mavlink/signing.py` duplicates P4 and has no new-stream timestamp window.
  - `InlineBridge`/`FrameSanitizer` are not wired.
  - HEARTBEAT `type != 6` filter (suggested `autopilot != 8`).
  - The Rust bounds check, Tauri CSP, unauthenticated control plane by default (now harmless for live sources),
    and `VITE_AEGIS_API_TOKEN`.

### Validation of the fixed candidate (2026-10-27)
Outputs are in scratch (`<scratchpad>/runs/`). Candidate `src`+`configs` diff vs HEAD sha256: `bde7d65e…7c20`.
- `ruff check src tests scripts backend`: clean (`runs/ruff_fixes.txt`).
- Full suite, one run with the git-ignored tlogs copied in: **881 passed, 3 skipped, 0 failed**. The 3 skips are
  the Windows PTY tests (`runs/pytest_fixes_full.txt`). This includes the 79 GPS tests, the socket/transport
  suites, the 26 new safety tests and the new replay-integrity test.
- **Stage-1 regression (SIM, ML on, `--no-figures`, 21:32–21:37Z; `aegisflight` loaded from `wt_integration/src`):**
  - **6535 / 4 / 16826 / 65**.
  - 378/378 CSV cells identical to `artifacts/benchmarks`; the only JSON difference is `/config/python`
    (`runs/bench_fixes_model_compare.txt`).
  - Committed `artifacts/benchmarks*` and `artifacts/figures` are untouched.
- **ALFA: not re-run.** The only detector change since the last identical ALFA run is the cadence guard in
  `detectors/protocol.py`. It is off by default (`cadence_guard_enabled` is in no `configs/` file), and ALFA does not
  use the backend or the mitigation code. Re-run it if the guard is ever enabled.
- **Next concrete action:** the user reviews the commit plan (in the final report of 2026-10-27). On approval, the
  commits are made on `integration/stage2-defense-candidate` only. No merge to `main`, no push.

## Next physical capture 010: prepared, NOT performed
No new GPS evidence exists beyond 008/009. This is a receive-only plan. Run it from the **main tree** with the
**main-tree scripts**. Never use the candidate's `run_serial_ids.py`: on the teammate branch it can transmit
(aegis-security B2).

**Preconditions, confirmed by the operator in writing before the port is opened:**
1. The board is disarmed, has no props and is on the desk. Nothing will be armed, flown, commanded, or
   reparametrised. No mode or mission changes, no injection.
2. The GNSS antenna has sky view (window or outdoors), as noted for 008/009.
3. No GCS or other process holds COM7. The probe fails fast (exit 2) if the port is busy.
4. No transmitter of any kind is used: no spoofing or jamming hardware.
5. `data/hardware/raw/telemetry_radio_010.{tlog,rawbin}` do not exist yet. The probe overwrites `--tlog` without
   asking; only `--raw` refuses. Both paths are git-ignored (checked: `.gitignore:62` and `:68`).
6. The operator records the start time, the antenna placement, and whether anything is moved or replugged
   (008 lost COM7 after the operator "moved things").

**Commands** (from `D:\Ardra\techfest-2026\aegisflight`, in **Git Bash**; in PowerShell set and clear
`$env:PYTHONPATH` instead of using the inline prefix):
- Before commands 3–4, record `git diff HEAD -- src configs | sha256sum`; expect `b4d434e3…`, or pin the tree to
  c984c0f.
- Command 3's JSON will carry the inaccurate label `"config_dir": "configs (Stage-1 default)"`
  (`replay_ap_tlog.py:121`).
- The `--tlog` file is created or emptied even if the open fails with exit 2.
```
.venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM7 --baud 115200 --duration 120 --json artifacts/hardware/telemetry_radio_probe_010.json --tlog data/hardware/raw/telemetry_radio_010.tlog --raw data/hardware/raw/telemetry_radio_010.rawbin
.venv/Scripts/python.exe scripts/hardware/gnss_tlog_summary.py data/hardware/raw/telemetry_radio_010.tlog --json artifacts/hardware/gnss_summary_010.json
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_010.tlog --no-ml --json <scratch>/replay_010_gate.json
PYTHONPATH=<clean 90b9aa2 worktree>/src .venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_010.tlog --no-ml --json <scratch>/replay_010_head.json
```

**Acceptance checks:**
- `passive_check.bytes_sent == 0` and `write_errors == 0` in the probe JSON.
- 0 CRC/header rejects, or every reject is explained.
- `EKF_STATUS_REPORT` is present (the EXTRA3 stream); otherwise the gate is inert and the capture only re-tests
  Stage-1 behaviour.
- Fix-type timeline and position wander are reported in metres only, never as coordinates.

**Pre-registered reading (out-of-sample for gate v2, which was developed on 008/009):**
- Compare `GPS_SPOOFING` alerts with the gate against HEAD.
- Report the DOS (GNSS fix lost) and TELEMETRY_MANIPULATION alerts separately.
- Do not tune any threshold to 010.

**Claim boundary:** `REPLAY` of `BENCH`, claim class none, n = 1 capture. It is false-alarm behaviour on a
stationary receiver, not spoofing detection.

**Keep out of git:** the tlog and rawbin (location-bearing). The probe, summary and replay JSONs carry no
coordinates; check before committing.

## Current objective (iteration 2 history; superseded by the sections above)
*2026-10-27: v2 is implemented and gated (see "Validation status" below). The v1 wording in this paragraph is historical.*
Iteration 2: an estimator-aware GPS position residual (`physics.estimator_gate`), meant to remove the
stationary-bench `GPS_SPOOFING` false positives. Resumed after a crash on 2026-10-25. **Status 2026-10-26: the
v1 gate (the uncommitted code from 2026-10-25) is NOT acceptable.** aegis-reviewer showed it weakens detection
(blocking B1–B6 below). It is being corrected as "v2". "Without weakening detection" is **not** established; it
is a goal.

## Last known-good commit
`90b9aa2` (main). Nothing from iteration 2 is committed. `main` vs `origin/main` diverge 64 / 62. Never push.

## Uncommitted changes (iteration 2) and why
| File | Why |
|---|---|
| `src/aegisflight/features/extractor.py` | reads `EKF_STATUS_REPORT.flags` (dialect constants); new optional `FeatureFrame` fields (`ekf_flags`, `ekf_age_s`, `nav_solution`, `pos_residual_nav_m`, `pos_step_max_m`); `ML_FEATURES` unchanged |
| `src/aegisflight/detectors/physics.py` | when the estimator has no horizontal solution, the residual is not spoofing evidence; a single-fix jump ≥ 30 m still alerts; a score-0 `navigation:` line |
| `src/aegisflight/fusion/engine.py` | score-0 diagnostics are listed after real findings (order only) |
| `configs/detector.yaml` | `physics.estimator_gate: true` |
| `tests/unit/test_gps_scenarios_fused.py` | benign cases 1–8, adversarial cases 9–17, 2 REPLAY-of-BENCH tests (008/009) |
| `docs/DETECTION.md`, `FEATURES.md`, `CONFIGURATION.md`, `HANDOFF.md`, `TESTING.md` | policy, fields, key, contract-extension note, tests |
| `artifacts/hardware/replay_gnss_00{8,9}_estimator_gate/` (untracked) | REPLAY-of-BENCH runs with the gate |

## Regression under investigation: `test_malformed_bytes_over_socket_are_rejected_without_events`
Status: **ROOT CAUSE FOUND (2026-10-26). Not caused by iteration 2.**
- Mechanism: pyserial's `socket://` `Serial.open()` ends with `reset_input_buffer()`, which `recv()`s and discards
  every byte already received. The test `Device` starts streaming as soon as TCP `accept()` returns. If the
  client thread is scheduled late (GIL contention during app start-up), the bytes sent at the start of the stream
  are purged before the framer exists to count them.
- Evidence (scratch probes, 2026-10-26):
  - the client socket `recv()`d all 8373 bytes, but the transport counted 7897;
  - the 476-byte difference was read by `protocol_socket.py:78 open → reset_input_buffer`;
  - in every failing run the first CRC-rejected sequence number is 7, not 1, so the first 0.1 s of the stream
    (6 valid + 6 corrupt frames) was purged;
  - the pre-crash failure (frames 126, crc 101) fits the same mechanism with a smaller purge: only the junk and the
    corrupt copy at t = 0.
- Not iteration 2: on clean HEAD (worktree `wt_head`) the test fails 3 of 10 runs; with iteration 2 it fails 5 of 9.
  Not distinguishable at n = 10.
- Not the framer: `MavlinkStreamFramer` counts 102 CRC rejects for the same stream under 200 random chunkings, as
  one blob, and byte by byte, in both trees.
- Ruled out: TCP loss (a plain socket client receives all 8373 bytes, even when lagging), `sendall` timeouts (a
  blocking send changes nothing), and the device's `recv` drain.
- Fix (DONE 2026-10-26): a test-harness defect. The harness streamed before the system under test had opened its
  port.
  - `tests/integration/test_app_live_source.py`: `Device(start=threading.Event())` holds the stream after the
    accept, and the new `start_when_port_open()` releases it once `/api/status` reports
    `link.transport.connected is True`. `connected` is set only after pyserial's `open()`, including its purge, has
    returned. This is synchronisation on observable state, not a sleep. The expected counts and every assertion
    are unchanged. The other 8 `Device(...)` call sites are unchanged (`start=None` is the old behaviour); none of
    them asserts exact head-of-stream counts.
  - `tests/unit/test_mavlink_serial.py`: new deterministic
    `test_virtual_port_bytes_that_arrive_before_open_returns_are_purged_uncounted` (KNOWN LIMITATION, pinned).
    It forces the race outcome: the purge runs only after the device's early frame is in the receive buffer.
    Mutation check: replacing the purge with a no-op makes it fail (the early frame is read first).
  - `docs/SERIAL_TRANSPORT.md`: "Open-time purge (uncounted)" paragraph. pyserial 3.5 purges on every backend:
    `socket://` recv-discard, Windows `PurgeComm`, POSIX `tcflush`. No product change.
- Results: the formerly failing test passed **12 of 12** after the fix (before: HEAD 3 of 10 failed, iteration 2
  5 of 9 failed). The new purge test passed 5 of 5 (~0.7 s each).
- Latent, not changed: `tests/unit/test_run_serial_ids.py` has its own `Device` that streams on accept and asserts
  `frames_received >= 20`. Its runner opens the port on the main thread right after connect, with no competing
  start-up. Measured **15 of 15 pass**. It is recorded here, not changed.

## Intermittent: `test_api_status_events_health_and_ws_shapes` (same race, most likely)
- It failed once (run 1 of the combined socket/transport suites, 2026-10-26). The assertion text was **not
  captured** (that command kept only the summary line), so the attribution below is the most likely cause, not a
  proven one.
- **Correction (2026-10-26).** An earlier version of this entry said the purge "cannot explain a missing
  HEARTBEAT". **That was wrong.** It assumed the purge always takes the whole t = 0 block (it did in all 7 purges
  observed under load: 190 bytes). A **partial** purge of the first 1–3 frames removes the t = 0 HEARTBEAT but
  leaves enough frames for `frames > 20` at t ≈ 0.8–0.9 s, before the next HEARTBEAT at t = 1.0. The test's
  HEARTBEAT presence assertion then fails.
  - aegis-validation forced this (scratch `probe/shapes_prefix_purge.py`), and the lead reproduced it: k = 1, 2, 3
    → FAIL on `('HEARTBEAT', …)`; k = 0 and k = 6 → PASS.
  - Partial purges occur naturally: the pre-crash failure (frames 126, crc 101) was one.
- So the real exposure is any assertion on the **head of the stream** (exact counts, or presence of a low-rate
  message such as the 1 Hz HEARTBEAT), not only exact counts. This test gets the same gate.
- Every later run uses `-rfE` so a recurrence is captured.

## Review findings (2026-10-26)
**ecc:python-reviewer**: no correctness bug in the extractor or physics logic; bit-identity holds when there is no
EKF report (extractor and physics). Findings:
1. **The gate does not cover the ML detector (MEDIUM-HIGH, verified independently).** The Isolation Forest still
   sees the ungated `pos_residual_m` (an `ML_FEATURES` member, frozen) and maps it to `GPS_SPOOFING`
   (`detectors/anomaly.py:40`). Scratch probe `ml_gate_probe.py` (SIM fixture from `test_gps_scenarios_fused.py`,
   300 decisions):

   | fixture | HEAD ML off | iter2 ML off | HEAD ML on | iter2 ML on |
   |---|---|---|---|---|
   | stationary wander + CONST_POS EKF | 230 threats / 15 alerts | **0 / 0** | 265 / 16 | **262 / 16** (all `ml_anomaly`) |
   | wander, no EKF message | 230 / 15 | 230 / 15 | 262 / 15 | 262 / 15 |
   | coherent east + solution | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

   Scope: ML is **off by default** for every non-SIM live source (`backend/sources.py:96-97`). It is also off by
   default in `run_serial_ids.py` ("NOT valid on ArduPilot") and in the bench replays (`--no-ml`). So the gate
   fixes the configuration that produced the bench false alerts. With ML opted in, the pre-existing ML
   non-transfer still flags wander. Action: scope the doc claims to "physics rule (default ML-off live
   configuration)", and pin the ML-on behaviour as a KNOWN LIMITATION test (skipped when the git-ignored model is
   absent). No ML change, since `ML_FEATURES` is frozen and a change would need a retrain decision.
2. **The fusion reordering changes Stage-1 evidence order (LOW-MEDIUM).** Moving every score-0 detector's evidence
   last also moves the protocol `coverage:` line after integrity/anomaly evidence when no EKF report exists. Only
   the order changes (not scores or verdicts), but the order is persisted and the CLI and demo show
   `evidence[:2]`/`[:3]`. Planned fix: move only score-0 **physics** evidence (the navigation note); then Stage-1
   order is exact when no EKF report exists.
3. LOW: `nav_solution` is the state at the last fix, not at `t` (comment). 4. LOW: a flapping unauthenticated
   EKF state restarts the segment window (name it under "falsified status" in DETECTION.md). 5. LOW: in
   no-solution, a fast vehicle with a slow `GLOBAL_POSITION_INT` (≥ 30 m per fix) would hard-alert (doc note).
   6. Nits: a comment on the `ardupilotmega` import (needed for the `EKF_*` constants, about 27 ms); type
   `cfg` in `_run`.

**aegis-validation** (harness fix): diagnosis SUPPORTED; fix SUPPORTED WITH CHANGES. Applied 2026-10-26:
- gated the shapes test;
- the purge pin now asserts the hook ran exactly once (it previously passed vacuously when no purge happened;
  re-checked with the reviewer's no-purge plugin, and it now fails);
- renamed `Device._run`'s local clock to `t0`;
- `start_when_port_open` checks the gate first;
- SERIAL_TRANSPORT wording: head of stream, and every reconnect.

It also confirmed that the gate still catches the regressions the test was written for: a late `open()` passes
gated and fails ungated (112 vs 126 frames), and with the CRC check turned off the gated test fails. Ownership note:
`test_mavlink_serial.py` and `SERIAL_TRANSPORT.md` are aegis-px4-mavlink's area; its sign-off is pending.

**aegis-reviewer** (estimator gate v1). SIM probes, synthetic envelopes, ML off, scratch `probes/`:
- **B1 NOT SUPPORTED: "adds no new attacker capability" is false.** Forging one field
  (`EKF_STATUS_REPORT.flags`, at least every 2 s) lets the reported position move up to 30 m per fix with no
  velocity, VFR or acceleration rewrite (P1: 10 → 0 alerts; P1b, a moving vehicle with its position frozen: 10 →
  0). The report is also injectable on links that never send it (PX4).
- **B2 NOT SUPPORTED: "stale status never silences" is false.** On going stale the window restarts and the
  change fix is skipped. A 500 m jump right after the reports are dropped for 2 s (nothing forged) is missed
  (P2b: 1 CRITICAL → 0). Sparse reports raise the drift floor from about 4 to about 7 m/s (P3b/c).
- **B3 NOT SUPPORTED: "a single-fix jump ≥ 30 m always alerts" is false.** The fix at a state change is skipped
  (P2: 1 CRITICAL → 0). Flag flipping hides a 10 m/s divergence completely (P3).
- B4: "without weakening detection" withdrawn (above).
- B5: Stage-1 benchmark (now IDENTICAL for v1) and ALFA must be cited before commit.
- B6: the 008/009 gate artifacts carry the hard-coded label `config_dir: "configs (Stage-1 default)"`
  (`replay_ap_tlog.py:121`) although the gate was on, and have no provenance. `VALIDATION_EVIDENCE.md` and
  `HARDWARE_BENCH` §6.10 still say "Not fixed".
- Supported: 008 GPS_SPOOFING 1 → 0 and 009 0 → 0 (REPLAY of BENCH, claim class none, n = 1 alert, in-sample).
  Root cause supported for that one 008 alert only. The 11 dashboard alerts saved no bytes or EKF flags, so
  whether the gate would clear them is unknown.

### v2 design (lead, 2026-10-26; implementation delegated to aegis-detection, the owner)
Constants reused only: `_LINK_GAP_S` (2 s), `gps_pos_residual_m` (12), `gps_pos_residual_hard_m` (30). No new
thresholds.
1. **Debounce.** A position fix is *gated* only if the latest EKF report is fresh (≤ 2 s) and says no horizontal
   solution, **and** the estimator has reported no-solution continuously for ≥ 2 s. The run resets on any
   solution report and on any gap of more than 2 s between reports. A single forged report, flag flipping, or
   stale or missing status never gates (closes P2, P3; P2b goes to rule 2).
2. **Not gated → the Stage-1 rule** on the same 15-fix window, leaving out only increments recorded at gated fixes,
   plus the one increment of the gated → ungated transition fix (so an estimator reset when the solution returns
   does not read as drift). No window restarts. **If no fix was ever gated, this equals `pos_residual_m`
   exactly.** That covers Stage-1 SIM, PX4, AP SITL, and ALFA as long as it never holds no-solution for 2 s.
3. **Jump check in every state.** A raw, unclamped single-fix step ≥ 30 m alerts `GPS_SPOOFING` (hard) if the
   fix is gated or is the gated → ungated transition fix. Elsewhere rule 2 already sees it (an increment clamped to
   30 m), so nothing changes when gating never happens.
4. **Gated → corroborated inconsistency.** The velocity-implied displacement |Σ v·dt| over the gated fixes in the
   window goes through the same 12 / 30 m thresholds. A pinned estimator reports v ≈ 0 (bench ≤ 0.108 m/s, about
   0.8 m over a 7.5 s window). A moving vehicle with forged flags and its position frozen (P1b) alerts.
5. **Inherent limit (KNOWN LIMITATION, disclosed).** Sustained forged no-solution plus zero velocity can still
   move the reported position by < 30 m per fix undetected (P1, P4). With no estimator solution and no velocity,
   that walk is indistinguishable from GNSS wander. (The bench dashboard session showed position *residuals* up
   to 42.4 m; that is the residual, not a measured wander amplitude. The session saved no bytes.)
6. Fusion: move only score-0 **physics** evidence last. Stage-1 evidence order is then exact.

### v2 implementation status (aegis-detection, 2026-10-26)
- **First pass done.** `src`+`configs` diff sha256 `f8758eeb…85f7`. Ruff clean; GPS + missing-telemetry +
  link-gap suites 143 passed; whole `tests/unit` 707 passed, 3 skipped. GPS test file grew from 50 to 75 tests:
  P1/P4/injection are KNOWN LIMITATION; P1b/P2/P2b/P3/P3b, the transition reset, the Stage-1 identity property
  and the fusion order are GENUINE; ML-on wander is a KNOWN LIMITATION. Mutation checks: disabling the debounce,
  the transition tag, rule 3 or rule 4 fails 8 / 3 / 4 / 3 tests. 008/009 replays are summary-identical to the
  v1 artifacts (008: GPS_SPOOFING 1 → 0 vs HEAD; 009 unchanged).
- Accepted deviations: the debounce is measured as the report span (≥ 2 s), so one report never gates; the
  navigation note prints `pos_residual_m`.
- **Changed after review (lead):** rule 4 as specified (|Σ v·dt|) also fired on *coherent* motion under a
  sustained no-solution status. Stage-1 is quiet there, so that was a new false-positive class. It is replaced by
  the velocity shortfall s = |V| − max(0, P·V̂) (V = Σ v·dt, P = Σ Δp over gated increments; 0 ≤ s ≤ |V|).
  Coherent motion → quiet, frozen or opposite position → alerts, wander → bounded by |V| ≈ 0.
- **Second pass done (final v2 tree): `src`+`configs` diff sha256 `aa2ed1d9…7f96`.** aegis-detection clamps the
  projection to [0, |V|]: s = |V| − min(|V|, max(0, P·V̂)). That keeps the reported value inside its bound and
  does not change detection. The field is `pos_vel_shortfall_gated_m`. The GPS test file has 78 tests (the
  coherent-under-no-solution case is now GENUINE quiet; new: position opposite to velocity → alerts; perpendicular
  or ahead-of-velocity offset → KNOWN LIMITATION). Bench 008/009 maximum shortfall is 0.11 m for both. Mutation:
  reverting rule 4 to |Σ v·dt| fails 6 tests, disabling it fails 3.
- **Lead re-verification on `aa2ed1d9…` (2026-10-26):** ruff clean; `ML_FEATURES` unchanged (names and order);
  **full suite 808 passed, 3 skipped, 0 failed** (`pytest -p no:cacheprovider -o addopts="" -q -rfE`).
- **ecc:python-reviewer on v2:** no correctness bug, and no Stage-1 change without EKF reports. Verified: tag and
  increment alignment, the exact-equality property, the debounce state machine, the shortfall bound, `reset()`, the
  harness gate, and test determinism. LOW items, queued for one final batch after the v2 ALFA run ends (`src/`
  must not change while it runs):
  1. **The gated branch skips the non-gated residual still in the window.** Forged no-solution reports could
     silence an already-alerting drift for up to 3 s. Fix: also run the Stage-1 thresholds on
     `pos_residual_nav_m` in the gated branch.
  2. The navigation note can sit among scored physics evidence (cosmetic; append it only when physics scored 0).
  3. A float edge on the 2.0 s debounce (conservative; optional 1e-9 tolerance).
  4. Nit: an early return when no EKF report was ever received, so "absent means untouched" is structural.
- **aegis-reviewer on v2 (SIM probes, synthetic, ML off; REPLAY of BENCH for 008/009):**
  - **B1–B4 CLOSED.** P1b 0 → 11 alerts; P1c (position against velocity) 0 → 11; P2, P2b and P3 equal Stage-1;
    P3b/c equal Stage-1 at every rate.
  - Remaining, disclosed and pinned as KNOWN LIMITATION: P1 (sustained forged status + zero velocity, 20 m/fix)
    0 alerts; P4 (split jump) 0; G (sideways) 1 alert, inside the debounce. 008: 0 alerts; 009: 0 alerts.
  - **B5 and B6 OPEN** (benchmark/ALFA results and evidence docs). Commit is also **blocked on the user's
    explicit confirmation of the frozen-contract extension.** The docs say "user-authorised", which the reviewer
    cannot verify from the repo. The user's 2026-10-25 brief said: "If EKF_STATUS_REPORT requires extending the
    frozen telemetry contract, treat that as an explicit, versioned interface change". The lead will ask the user
    to confirm.
  - Non-blocking doc fixes for the final batch:
    - the Rule-3 bullet is wrong (`pos_step_max_m` is the residual increment |Δp − v·dt|, not the raw
      displacement, so a coherent fast vehicle does not trigger it), and the "single-fix step" wording;
    - name the quiet 12–30 m transition step and the sensitivity dip after the solution returns under the
      forged-status limitation;
    - disclose that the gate needs EKF reports at least every 2 s (≥ 0.5 Hz), otherwise Stage-1 behaviour applies;
    - `nav_gated` can go stale if `GLOBAL_POSITION_INT` stops (cosmetic).

## Validation status (FINAL TREE `src`+`configs` sha256 `b4d434e3…7eaf` on HEAD `90b9aa2`, 2026-10-26)
| Stage | Result | Evidence |
|---|---|---|
| ruff `src tests scripts backend` | PASS | lead run |
| GPS tests (`tests/unit/test_gps_scenarios_fused.py`) | **79 passed**. By first docstring label: 59 GENUINE and 20 KNOWN LIMITATION; one test is mixed | aegis-reviewer re-ran it on the final tree |
| Formerly failing socket test, repeated | PASS 12/12 after the harness fix (before the fix: HEAD failed 3/10, iteration 2 failed 5/9) | this log, "Regression under investigation" |
| Full suite (`.venv/Scripts/python.exe -m pytest -p no:cacheprovider -o addopts="" -q -rfE`) | **809 passed, 3 skipped, 0 failed** (the 3 skips are POSIX PTY tests). Pre-crash: 778 / 1 failed / 3 skipped | lead run; `docs/TESTING.md` |
| Stage-1 regression (`SIM`) | **IDENTICAL**: TP/FP/TN/FN 6535 / 4 / 16826 / 65; 378/378 non-timing CSV cells identical; only `/config/python` differs among the JSON leaves | `artifacts/validation/estimator_gate_v2/stage1_regression/` |
| ALFA before/after (`REPLAY`, claim class none) | Outputs change only in `unlabelled`. ML on: GPS_SPOOFING 6 → 17 (explained below). ML off: 261 → 164. Threat rates unchanged | `artifacts/validation/estimator_gate_v2/alfa/` |
| Replay identity (`REPLAY`, ML off) | 44/44 byte-identical. **None of the 44 carries `EKF_STATUS_REPORT`**, so this only shows that links without estimator status are untouched | `artifacts/validation/estimator_gate_v2/replay_identity/` |
| Bench 008/009 (`REPLAY` of `BENCH`, claim class none, in-sample, n = 1 alert) | 008: GPS_SPOOFING alerts 1 → 0; 7 DOS + 1 TELEMETRY_MANIPULATION remain. 009: 0 → 0 | `artifacts/hardware/replay_gnss_00{8,9}_estimator_gate/` |
| Reviews | ecc:python-reviewer (v1, v2): no correctness bug. aegis-validation: harness fix SUPPORTED. aegis-reviewer: v1 NOT SUPPORTED (B1–B6); v2 closes B1–B4; final claims review closes B5/B6 with **no blocking issues**; non-blocking wording fixes applied 2026-10-26 | this log, "Review findings" |
| Frozen-contract extension | User confirmed on 2026-10-26: "Yes, confirm the extension" | `docs/HANDOFF.md` |

**ALFA ML-on GPS_SPOOFING 6 → 17, explained** (per decision; bundle `alfa/gps_spoofing_decisions/`):
- The increase is in two ground GPS-initialisation windows (2018-07-18 `flight4`, 2018-10-05 `flight1`). Each spans
  3.0 s or 3.6 s from first to last GPS_SPOOFING decision.
- **Inside those windows**, all 43 decisions are threats in both trees, and 24 labels change from DOS to
  GPS_SPOOFING: HEAD's clamped residual (27.0–31.5 m) falls just under the hard threshold and the fused label
  reverts to DOS, while v2's rule 3 keeps the raw ≈8117 km step hard for the window. HEAD's 8 GPS_SPOOFING rows are
  a subset of v2's 32 (raw counts before the script drops overlapping recordings; the aggregate shows a net 11).
- **Outside the windows,** only aggregate rates were compared: the `unlabelled` threat rate is equal to full
  precision, but there is no per-decision listing.
- For the ML-off change (GPS_SPOOFING 261 → 164, DOS +97, threat rate unchanged) the lead's **reading, not listed
  per decision,** is that gated ground decisions lose the GPS_SPOOFING label and stay threats through other rules.

## History of this resume (2026-10-26, condensed)
- Recovered the crashed session: the tree matched the pre-crash hash `e38107fa…`, and the crashed benchmark had
  produced nothing.
- Found and fixed the socket-test race (pyserial's open-time purge; a test-harness defect, not caused by
  iteration 2).
- The first v1 benchmark was identical, and the v1 ALFA run was done.
- aegis-reviewer showed that v1 weakened detection (B1–B4). v2 was designed by the lead and implemented by
  aegis-detection. The rule-4 metric changed from |Σ v·dt| to the velocity shortfall, because the former created
  a new false-positive class.
- The v2 benchmark and ALFA run were killed by the system for low memory (no output). The user chose to finish the
  batch first and then run one job at a time.
- Final batch: reviewer LOW items 2–4 applied, item 1 tried and dropped (see "Final batch" in "v2 implementation
  status"; disclosed in DETECTION.md).
- Final benchmark and ALFA run alone. Evidence bundle by aegis-validation. The lead made two probe copies
  repo-relative (no local paths) and refreshed the manifest.

## Next concrete action (iteration 2 only; for the overall state see the integration verdict at the top)
Await the user's approval of the proposed commit scope (lead's final report). **Do not commit or push without it.**

## Blockers (iteration 2 only; the teammate-branch integration IS blocked, see the top)
None. No hardware is needed.

Housekeeping: a read-only probe left an idle system-Python process (`C:\Program Files\Python314\python.exe`,
PID 6729, started 21:05). aegis-reviewer's attempt to end it was denied by the permission classifier; it is left
for the user.
