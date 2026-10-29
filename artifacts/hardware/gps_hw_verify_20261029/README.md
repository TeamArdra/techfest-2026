# gps_hw_verify_20261029: receive-only GPS verification on the powered-on vehicle

**Live part:** environment `BENCH`-class (a physical ArduPilot-family quadrotor, **disarmed and stationary per its own telemetry**;
the operator did not record whether props were off or where the vehicle sat). Not `SITL`, `HITL` or `FIELD`; no flight.
**Replay part:** environment `REPLAY` of the live capture (and of the 008/009 bench captures).
**Claim class: none.** This is a description of what the receiver and estimator reported, plus false-alarm behaviour on one
benign stream. It is **not** detection evidence: no attack was made, nothing was injected, the vehicle did not fly.

The live evidence and the replayed evidence are in separate directories and must not be merged into one headline number.

| Directory | What it is | Origin |
|---|---|---|
| `live_capture/` | one 90 s receive-only IDS run on COM7 + redacted stats of the same bytes | real hardware, this session |
| `replay/` | the **same bytes** replayed offline through the IDS, gate on vs gate off | REPLAY of the live capture |
| `manifest.json` | commands, inputs, hashes, versions, check results | assembled at the end of the session |

## Setup (what was physically connected)
- **Port:** `COM7`, Silicon Labs CP210x USB-to-UART bridge (`USB\VID_10C4&PID_EA60`). It was the **only** serial port enumerated
  (Windows PnP, `Win32_SerialPort`); nothing was opened speculatively. This is the laptop side of the telemetry-radio link used
  in the earlier COM7 captures (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6). Baud 115200 (the rate those captures established
  empirically; the radio's own configuration was not read).
- **Vehicle:** HEARTBEAT `type` 2 (QUADROTOR), `autopilot` 3 (ArduPilotMega), sysid/compid 1/1, `system_status` 3 (STANDBY),
  `base_mode` 81 (no `SAFETY_ARMED` bit, so **disarmed**). The board model is **not identifiable** from receive-only telemetry
  (no `AUTOPILOT_VERSION` was requested); it is not asserted here.
- **Receive-only enforcement:** `scripts/hardware/run_serial_ids.py` (source read before use; `--defense-mode passive`,
  `--no-reconnect`, ML off). `transport.send` is never called; the run fails with exit 3 if any byte is written.
  Result: `bytes_sent` 0, `write_errors` 0. Nothing else touched the port. No process was stopped.
- **Mitigation path:** `active-ips` is not an accepted choice of the runner, and counter-frames are never transmitted
  (pinned by `tests/unit/test_defense_safety.py::test_run_serial_ids_has_no_transmitting_mode`).
- **One code change was needed:** an optional `--tlog` flag on `run_serial_ids.py` (tees the clean received frames through the
  existing `TapTransport`, so there is still one consumer on the port). Tests:
  `tests/unit/test_run_serial_ids.py::test_tlog_tees_the_clean_downlink_and_stays_receive_only`,
  `::test_existing_tlog_is_never_overwritten`. The capture ran with this change in the working tree (not yet committed at capture time).
- **Raw tlog:** `data/hardware/raw/gps_hw_verify_20261029.tlog` (193,410 B, sha256 `c2e3459b15706479323da39813329ad1796948548b29f5d9df4ac55144d48e8f`).
  It holds the vehicle's position, so it is **local and git-ignored**. Nothing committed here contains an absolute coordinate.

## What was received (`live_capture/`)
Window 2026-10-28T20:04:26Z to 20:05:56Z (`summary.json`), 89.82 s of frames (`tlog_stats.json`).

- **5,130 frames, all MAVLink 1 (`0xFE`), none signed.** 0 bad frames, 0 CRC/header rejects, 0 garbage bytes, 0 disconnects,
  0 queue drops, 0 late ticks. Sequence numbers from 1/1 are contiguous: 0 gaps, 0 reorders, 0 duplicates (`tlog_stats.json`).
- Rates (`tlog_stats.json`): `HEARTBEAT` 1.0 Hz; `ATTITUDE`, `AHRS2`, `VFR_HUD` 4.0 Hz; and 2.0 Hz each for `GPS_RAW_INT`,
  `GLOBAL_POSITION_INT`, `EKF_STATUS_REPORT`, `SYS_STATUS`, `AHRS`, `VIBRATION`, `BATTERY_STATUS`, `RAW_IMU`, `SCALED_IMU2/3`,
  `SCALED_PRESSURE/2`, `RC_CHANNELS(_RAW)`, `SERVO_OUTPUT_RAW`, `NAV_CONTROLLER_OUTPUT`, `MISSION_CURRENT`, `POWER_STATUS`,
  `MEMINFO`, `SYSTEM_TIME`, `RANGEFINDER`, `TERRAIN_REPORT`. Stream-rate parameters were not touched.
- **Not received:** `GPS_STATUS` (per-satellite data) and `STATUSTEXT`. Neither is streamed on this link. `GPS_RAW_INT.h_acc`
  and the other extension fields are **unavailable**, because MAVLink 1 framing cannot carry them (`gnss_summary.json`: `h_acc_m: null`).
  Only `eph`/`epv` (HDOP/VDOP-style) are available.
- **IDS:** 451 decisions (`summary.json`), **0 alerts**; empty `alerts.jsonl`; hash chain `ok` with length 0
  (nothing to chain). Decision latency mean 0.349 ms, max 1.03 ms; CPU 2.8 % of one core. `health.jsonl`: 8 lines, every counter
  flat at zero for loss/garbage/disconnect.

## What the GNSS and estimator reported (`live_capture/gnss_summary.json`; positions only as metres from the first fix)
A 3D fix is **not** evidence that the coordinates are trustworthy, and the vehicle's own health flags agree:

| Observation | Value |
|---|---|
| `fix_type` | 3 (3D fix) in 180 of 180 reports |
| Satellites visible | min 6, median 7, max 7 |
| `eph` (HDOP-style) | 7.99 to 8.58 (median 8.09). Poor |
| `epv` | 2.31 to 2.33 |
| Reported speed (GPS `vel`, `GLOBAL_POSITION_INT`, `VFR_HUD`) | median 0.245 m/s (GPS `vel`), at most 0.02 m/s (position msg), at most 0.026 m/s (VFR) |
| Position offset from the first fix **while stationary** | median 11.7 m, **max 34.3 m** |
| Speed implied by successive position fixes | up to 3.05 m/s, against a reported speed of at most 0.02 m/s |
| `GPS_RAW_INT` vs `GLOBAL_POSITION_INT` horizontal disagreement | 0.0 m (same source) |
| `SYS_STATUS` GPS sensor present / enabled / **healthy** | 180 / 180 / **0** |
| `EKF_STATUS_REPORT.flags` | `0xa7` in 180 of 180: attitude, horizontal + vertical velocity, vertical position, **`CONST_POS_MODE`**. **No** `POS_HORIZ_ABS` or `POS_HORIZ_REL`; `GPS_GLITCHING` 0 |

Reading: a stationary, disarmed vehicle with a weak constellation. The receiver says 3D, the estimator has **no horizontal
position solution**, the GPS health bit is clear, and the reported position wanders tens of metres. The earlier bench captures
show the same estimator and health state (008: flags `0xa7` x125, healthy 0/125, max offset 21.6 m; 009: `0xa7` x120,
healthy 0/120, max offset 7.2 m; `artifacts/hardware/gnss_summary_00{8,9}.json`). Today's wander is the largest of the three.
Whether the sky view, the antenna or the receiver is the cause is **not established** by this capture.

## Replay of the same bytes (`replay/`, `REPLAY`, ML off)
`scripts/ardupilot/replay_ap_tlog.py` on the live tlog, in-process, unchanged pipeline.

| Config | Decisions | Threat decisions | Alert decisions | Alert evidence |
|---|---|---|---|---|
| `configs/` (committed; `physics.estimator_gate: true`) | 450 | 0 | 0 | none |
| `replay/cfg_gate_off/` (copy of `configs/`, only `estimator_gate: false`, i.e. the Stage-1 rule) | 450 | 60 | **4** `GPS_SPOOFING` | "position residual 12.0 to 15.2 m > 12 m (reported track diverges from velocity)" |

- Live run: 0 alerts in 451 decisions; replay gate-on: 0 in 450. They agree on the verdict (the one-decision difference is
  the tick boundary, as `replay_ap_tlog.py` documents).
- Reading: on a **real, benign, stationary** stream the Stage-1 rule raises 4 false `GPS_SPOOFING` alerts from receiver
  wander; the estimator-aware gate raises none. **Caveats:** one capture, one vehicle, ~90 s, the same setting the gate was
  designed from (008/009), so this is a design-consistent check and not an independent test. The gate's disclosed inherent
  limit stays: sustained forged no-solution status plus zero velocity can hide a walk below 30 m per fix
  (`docs/DETECTION.md`). Zero alerts here is therefore **not** evidence that these coordinates were authentic.
- Re-replay of the committed fixtures 008 and 009 on this tree is byte-identical to the committed
  `artifacts/hardware/replay_gnss_00{8,9}_estimator_gate/replay_noml.json` after normalising CRLF (determinism check).

## Regenerate
```
# live (needs the vehicle + radio on COM7; receive-only; refuses to overwrite)
.venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port COM7 --baud 115200 --out-dir artifacts/hardware/gps_hw_verify_20261029/live_capture --seconds 90 --health-interval 10 --no-reconnect --defense-mode passive --tlog data/hardware/raw/gps_hw_verify_20261029.tlog
# offline, from the local tlog
.venv/Scripts/python.exe scripts/sitl/tlog_stats.py data/hardware/raw/gps_hw_verify_20261029.tlog --json artifacts/hardware/gps_hw_verify_20261029/live_capture/tlog_stats.json
.venv/Scripts/python.exe scripts/hardware/gnss_tlog_summary.py data/hardware/raw/gps_hw_verify_20261029.tlog --json artifacts/hardware/gps_hw_verify_20261029/live_capture/gnss_summary.json
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/gps_hw_verify_20261029.tlog --no-ml --json artifacts/hardware/gps_hw_verify_20261029/replay/live_capture_gate_on_noml.json
.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/gps_hw_verify_20261029.tlog --no-ml --config-dir artifacts/hardware/gps_hw_verify_20261029/replay/cfg_gate_off --json artifacts/hardware/gps_hw_verify_20261029/replay/live_capture_gate_off_noml.json
```

## Not covered here
- **No healthy-estimator state was observed on hardware.** All three captures (008, 009, this one) have no horizontal solution.
  The un-gated Stage-1 branch of the gate has never run on a hardware stream with `POS_HORIZ_ABS` set.
- The replay JSONs print `"config_dir": "configs (Stage-1 default)"` for the gate-on run. That label is hard-coded by
  `replay_ap_tlog.py` and is inaccurate: `configs/` has `estimator_gate: true` (see the 009 README).
- No spoofing, jamming, injection or malformed-frame scenario was run against the vehicle; those are covered only by recorded
  fixtures and the unit/integration suites (see `docs/VALIDATION_EVIDENCE.md`).
