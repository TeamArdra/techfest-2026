# replay_gnss_009_estimator_gate: capture 009 replayed with the estimator gate v2

**Environment:** `REPLAY` of `BENCH` data. Capture 009 comes from the physical Pixhawk 6X: ArduCopter, disarmed, stationary
per the operator, GNSS receiver attached with 3D/DGPS throughout, telemetry radio on COM7 at 115200, 59.8 s of stream
(`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.10).
**Claim class:** none. This is false-alarm behaviour on one benign stream. It is **not** detection evidence: no attack
was made and the vehicle did not fly.
**In-sample:** the estimator gate (v1 and v2) was designed from captures 008/009. This replay is a design trace, not an
independent test.

## Provenance
- Code: `HEAD` `90b9aa247fdcda2f95d0096c1e0f486b9d030aed` **plus the uncommitted GPS iteration-2 working tree (gate v2,
  final batch)**. sha256 of `git diff HEAD -- src configs` (Git Bash):
  `b4d434e3dffed2ab646bb4d9aed963e0a4fb44e636353901b963a59d15967eaf`. Measured at 2026-10-26 13:17:22Z, right before the
  run, and again after it (13:17:24Z). Unchanged.
- Config: the working tree's `configs/` (no `--config-dir`). `configs/detector.yaml` sha256
  `be7876745a26e1a9de23acb1e079cab18165887df3ad8cd9800f67dae4e1f8be`. The only difference from `HEAD`'s
  (`88ec9ffb…aac3`) is `physics.estimator_gate: true` and its comment block.
- **Label caveat:** the JSON says `"config_dir": "configs (Stage-1 default)"`. That label is hard-coded by
  `scripts/ardupilot/replay_ap_tlog.py:121` whenever `--config-dir` is not given. **It is inaccurate here.** `configs/` in
  this tree is not the Stage-1 configuration, because `physics.estimator_gate` is `true`.
- ML: **off** (`--no-ml`; `"ml_enabled": false`). Integrity detector: no verifier.
- Python 3.13.15, pymavlink 2.4.50, numpy 2.5.3, scikit-learn 1.9.1 (installed but unused with ML off); Windows 11.
- Input: `data/hardware/raw/telemetry_radio_009.tlog` (local, git-ignored), sha256
  `e6926675305a8fbf592c76a152c57e30aa4c2e854a41b8b2ea0c5a14aafec867`, matching §6.10.
  - It holds 120 `EKF_STATUS_REPORT` frames, and every one reports no horizontal solution.
  - The longest continuous no-solution span is 59.49 s.
  - Source: `artifacts/validation/estimator_gate_v2/replay_identity/ekf_presence.json`.
- Path: in-process only (`tlog_stats.iter_raw_frames` → `sources.mavlink_live.frame_ticks` → `IDSPipeline.process_tick`).
- Output `replay_noml.json`: sha256 `5cecb057d9a95d7c9ade0a0e3910b3b67507a0b5f16cc7d222b2d3505a8b0ffc` (written on Windows,
  CRLF).

## Regenerate
```
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_009.tlog --no-ml --json artifacts/hardware/replay_gnss_009_estimator_gate/replay_noml.json
```

## Result, compared with HEAD
- 300 decisions, **0 threats, 0 alerts**: the same as HEAD.
- The output is **byte-identical** to the committed `artifacts/hardware/replay_gnss_009/replay_noml.json` (HEAD code,
  Stage-1 configs). The same holds for HEAD re-run on 2026-10-26 on a clean detached worktree of `90b9aa2`.
- HEAD already had 0 threats on 009, so "0 → 0" shows only that the gate **adds** nothing here. It does not show that the
  gate removes anything.
- The REPLAY-of-BENCH test `tests/unit/test_gps_scenarios_fused.py::test_bench_captures_raise_no_gps_spoofing_under_the_estimator_gate`
  pins the bench maxima for this capture: largest gated single-fix residual increment 0.70 m, largest rule-4 shortfall
  0.11 m. Both are far below the 12 / 30 m thresholds.
- **No coordinates.** The JSON holds counts only (no alerts, so no evidence lines). It has no latitude, longitude or
  other absolute coordinates.

## Limitations
- n = 1 capture of 60 s, in-sample. This is not a false-alarm rate.
- The 2026-10-25 dashboard session (11 `GPS_SPOOFING` alerts, after this capture) saved no input bytes and no EKF flags.
  Whether the gate would clear those alerts is **unknown**.
- The replay clock starts at the first recorded frame and uses the tlog's timestamps, not live arrival times.
- ML off. With ML on, the ML detector is not gated (SIM; `docs/DETECTION.md`).
- `EKF_STATUS_REPORT` is unauthenticated. Under forged or injected status the gate adds attacker capability (SIM;
  `docs/DETECTION.md`). Only MAVLink-2 signing closes that.
- The regression evidence for this tree is in `artifacts/validation/estimator_gate_v2/`.
