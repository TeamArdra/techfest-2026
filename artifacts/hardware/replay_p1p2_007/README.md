# replay_p1p2_007 — capture 007 replayed through the P1/P2 working tree

**Environment:** `REPLAY` of `BENCH` data (capture 007: physical Pixhawk 6X, ArduCopter, disarmed,
indoor desk, no GPS fix, telemetry radio on COM7, 60 s; see `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.7).
**Claim class:** none. This describes a benign stream and the IDS's false-alarm behaviour on it.
It is **not** detection evidence: no attack was made and the vehicle did not fly.

## Provenance
- Code: `HEAD` `83f07c1782c7a19dcc2ec3e5f2261ee848cf5402` **plus the uncommitted P1/P2 working tree**.
  - sha256 of `git diff HEAD -- src configs`: `e03ab6c879680b09c3c982ac46245796eed278e81cd0f3b30c98610f2723aa9e`.
  - sha256 of `git diff HEAD` (whole tree): see the end of this file. The full-tree hash changed during this
    session because docs and `scripts/hardware/run_serial_ids.py` were edited; `src/` and `configs/` were not.
- Config: Stage-1 default `configs/` (no `--config-dir`). `configs/detector.yaml` sha256
  `88ec9ffbced4c898f226c91b421ae05b39d72049575ec5cc808fc9ceec0aaac3` (modified in the working tree:
  adds `protocol.require_global_position`, default false).
- ML: **off** (`--no-ml`). Integrity detector: no verifier.
- Python 3.13.15, pymavlink 2.4.50, numpy 2.5.3, scikit-learn 1.9.1; Windows 11.
- Input: `data/hardware/raw/telemetry_radio_007.tlog` (local, git-ignored), sha256
  `0a70133114f439aad8e7a45b7e86eb76127cda4efa0674891e8c228025d0e17a`. This matches the value in §6.7. The
  companion `.rawbin` sha256 `3420ff0c6c0b4b1e2d200fa00203241375e3710d274e09bff9c353f3e89a1c4d` matches
  `artifacts/hardware/telemetry_radio_probe_007.json`.
- Path: in-process only (`tlog_stats.iter_raw_frames` → `sources.mavlink_live.frame_ticks` →
  `IDSPipeline.process_tick`). No serial device, virtual port or socket is used.

## Regenerate
```
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_007.tlog --no-ml --json artifacts/hardware/replay_p1p2_007/replay_noml.json
```
Output: `replay_noml.json`, the only generated file in this directory.

## Not in `replay_noml.json`
`replay_ap_tlog.py` does not output `telemetry_coverage` or evidence families. The validation agent
measured them with a scratch script (not committed) that uses the same replay loop and the runner's
`_coverage()` fields:
- 1,620 frames, 300 decisions, 295 threat decisions, 15 alert decisions, all `DOS`.
- Evidence families: all 15 alerts and all 295 threats are "GNSS fix never acquired". There is no
  start-up "never received" line, no coverage line and no other family.
- telemetry_coverage at the end: heartbeat_seen true, global_position_seen true, gps_raw_seen true,
  decisions_without_global_position 0.

## Limitations
- n = 1: one 60 s benign bench stream, so this gives no false-alarm rate.
- The replay starts the clock at the first recorded frame, so it does not reproduce a live monitor that starts
  before any frame arrives (the P1 elapsed-time start-up path).
- Capture 007 is a separate session from the live IDS run `serial_ids_com7_001`. That run saved no input bytes,
  so it cannot be replayed byte for byte.
- The replay uses the tlog's microsecond timestamps, not live monotonic arrival times, so decisions can
  differ at tick boundaries from what a live run would produce.

## Whole-tree diff hash at time of writing
`git diff HEAD | sha256sum` = `afcd5bb7a85d30732fbfbbbaa1113c92f1d1323a03ac46cb2897387c03604633` (computed 2026-10-16 ~00:05 +0530, after the benchmark; `src/`+`configs/` diff hash unchanged across the run)

## Correction and provenance re-check, 2026-10-20 (appended; the numbers above are unchanged)
- **Correction: "no GPS fix" / indoor.** The capture does not show a receiver failing to get a fix indoors. It shows the board
  reporting **no GPS receiver**. `GPS_RAW_INT.fix_type` is 0 (`GPS_FIX_TYPE_NO_GPS`) in all 120 `GPS_RAW_INT` frames, with
  `satellites_visible` 0 and `eph`/`epv` 65535. The `SYS_STATUS` `MAV_SYS_STATUS_SENSOR_GPS` present/enabled/healthy bits are
  False in all 120 `SYS_STATUS` frames. Read from the input tlog with pymavlink, `ardupilotmega` dialect. Whether a GPS module
  was physically attached was not recorded. The 15 "GNSS fix never acquired" alerts therefore come from a board that reports
  no GPS. They are not evidence about GNSS reception.
- The `src`+`configs` diff hash recorded above (`e03ab6c8…a9e`) is **stale**: it describes the tree at the time of
  this replay. `src/aegisflight/detectors/protocol.py` was modified afterwards (file time 2026-10-16 00:16 +0530; content of
  that edit not recorded) and again on 2026-10-20 (aegis-detection: the coverage line is appended last in the protocol
  evidence; `detectors/physics.py` gates the GPS/VFR speed rule on `gps_seen`).
- Re-run on the 2026-10-20 tree: `HEAD` `83f07c1` + working tree, `git diff HEAD -- src configs | sha256sum` (Git Bash) =
  `708192a04883a7ad83a5918c81bf752c34e96744f2ff35ab498af81795aa0ad6`, taken immediately before the replay and unchanged
  after it. The regenerate command above, with `--json` pointed at a scratch directory, gives a `replay_noml.json` that is
  **byte-identical** to the one in this directory (sha256 `1cd58e58bba3eab7f471015ba30c19db65deca383943d16cb23191406d8a4aa6`).
- The scratch-only figures listed above (295 threats / 15 alerts, all "GNSS fix never acquired"; `telemetry_coverage` end
  values) were re-measured on the same tree with the same replay loop and reproduce exactly. Input tlog sha256 re-verified:
  `0a701331…e17a`.
