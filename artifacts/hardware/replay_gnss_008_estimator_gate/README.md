# replay_gnss_008_estimator_gate: capture 008 replayed with the estimator gate v2

**Environment:** `REPLAY` of `BENCH` data. Capture 008 comes from the physical Pixhawk 6X: ArduCopter, disarmed, stationary
per the operator, GNSS receiver attached, telemetry radio on COM7 at 115200, 62.3 s of stream
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
- Input: `data/hardware/raw/telemetry_radio_008.tlog` (local, git-ignored), sha256
  `c8774324a8d84b2e039b6065d77cdcee5e1682f269b1f2221535e978df95eb9b`, matching §6.10.
  - It holds 125 `EKF_STATUS_REPORT` frames, and every one reports no horizontal solution.
  - The longest continuous no-solution span is 62.0 s, so the gate's ≥ 2 s debounce is met.
  - Source: `artifacts/validation/estimator_gate_v2/replay_identity/ekf_presence.json`.
- Path: in-process only (`tlog_stats.iter_raw_frames` → `sources.mavlink_live.frame_ticks` → `IDSPipeline.process_tick`).
  No serial device, virtual port or socket is used.
- Output `replay_noml.json`: sha256 `7bb57d3416da4635bef65bb0596fa5b6cc9cd74ed5751241b0bd91a70e89c587` (written on Windows,
  CRLF).
  - It replaces the untracked v1 output of 2026-10-25, which was never committed.
  - It is byte-identical to the lead's scratch replay of the same final tree.

## Regenerate
```
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_008.tlog --no-ml --json artifacts/hardware/replay_gnss_008_estimator_gate/replay_noml.json
```
Output: `replay_noml.json`, the only generated file in this directory.

## Result, compared with HEAD
"Before" is the committed `artifacts/hardware/replay_gnss_008/replay_noml.json` (HEAD code, Stage-1 configs). On
2026-10-26 it was re-run on a clean detached worktree of `90b9aa2` (`PYTHONPATH=<wt_head>/src`, so the worktree's own
`configs/` was used). The re-run was **byte-identical** to the committed file (sha256 `be34b6a0…`).

| | HEAD (`replay_gnss_008`) | v2 (this directory) |
|---|---|---|
| decisions | 313 | 313 |
| threat decisions | 146 | 138 |
| alert decisions | 9 | 8 |
| alert types | `GPS_SPOOFING` 1, `DOS` 7, `TELEMETRY_MANIPULATION` 1 | `DOS` 7, `TELEMETRY_MANIPULATION` 1 |
| decisions with `physics_consistency` ≥ 0.5 | 12 | 1 |

- **`GPS_SPOOFING` 1 → 0.** That alert was the "position residual 12.1 m" alert at fix degradation (§6.10). HEAD's alert
  evidence holds "position residual 12.1 m" and "12.6 m" lines; v2's has none.
- **Unchanged in type and count:** the 7 `DOS` "GNSS fix lost" alerts (correct: a valid fix was seen and then degraded)
  and the 1 `TELEMETRY_MANIPULATION` alert (the AHRS altitude step, §6.10).
- **New evidence line.** 7 of the 8 alert decisions now also carry the score-0 line "navigation: estimator reports no
  horizontal position solution (EKF_STATUS_REPORT …". Physics adds it only when it scored 0; it changes no score.
- **No coordinates.** The JSON holds counts and the first 80 characters of evidence lines: distances, fix types,
  satellite counts and altitude values. It holds no latitude, longitude or other absolute coordinates.

## Limitations
- n = 1: one `GPS_SPOOFING` alert removed, on one 62 s capture of one board. This is a design trace (in-sample), not a
  false-alarm rate.
- The 11 `GPS_SPOOFING` alerts of the 2026-10-25 dashboard session saved no input bytes and no EKF flags. Whether the gate
  would clear them is **unknown**.
- The replay clock starts at the first recorded frame and uses the tlog's timestamps, not live arrival times.
- ML off. With ML on, the ML detector still sees the ungated `pos_residual_m` and can label the same wander
  `GPS_SPOOFING` (SIM; `docs/DETECTION.md`). ML is off by default for non-SIM sources.
- `EKF_STATUS_REPORT` is unauthenticated. Under forged or injected status the gate adds attacker capability (SIM; the
  limitations in `docs/DETECTION.md`, "Estimator-aware position residual"). Only MAVLink-2 signing closes that.
- The regression evidence for this tree (Stage-1 benchmark, ALFA before/after, the replay identity check) is in
  `artifacts/validation/estimator_gate_v2/`.
