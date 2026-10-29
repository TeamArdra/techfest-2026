# navigation_health_loopback: the 2026-10-28 capture through the live runner, with the passive `navigation_health` block

**Environment:** `REPLAY` of `BENCH` data over a loopback TCP "virtual serial port". **Not hardware**: no baud rate, USB driver, radio
or DTR/RTS line is exercised, and nothing was sent to the vehicle (the feeder only reads a file).
**Claim class: none.** It shows that a new *passive* status block reports what the vehicle itself stated. It is not detection
evidence and not evidence that any position was authentic.

## What was run
The same bytes as `../../live_capture/` (`data/hardware/raw/gps_hw_verify_20261029.tlog`, local and git-ignored, sha256
`c2e3459b15706479323da39813329ad1796948548b29f5d9df4ac55144d48e8f`, 5,130 frames, 89.82 s), fed at original pace
(`--speed 1.0`) into the receive-only runner, which now writes `navigation_health`. Stage-1 `configs/`
(`configs/detector.yaml` sha256 `be787674…1f8be`, `estimator_gate: true`), ML off.

```
.venv/Scripts/python.exe scripts/hardware/virtual_serial_replay.py data/hardware/raw/gps_hw_verify_20261029.tlog --port 47321 --speed 1.0 --ready-file <ready>
.venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port socket://127.0.0.1:47321 --allow-url --baud 115200 --out-dir artifacts/hardware/gps_hw_verify_20261029/replay/navigation_health_loopback --seconds 95 --health-interval 10 --no-reconnect
```

## Provenance
- `HEAD` `c84901228c640429e17f9c2ea34035be95398463` (`evidence/gps-hw-verify-20261029`) **plus the uncommitted change this note
  documents**; `git diff HEAD -- src configs | sha256sum` = `fda0c762f6de3926a1179525a505b51bd624586e728b68df316289a6232eb61d`
  (the diff excludes the new untracked `core/gps_health.py`).
- sha256: `src/aegisflight/core/gps_health.py` `04f8651a…c403`, `src/aegisflight/backend/engine.py` `737d7ff8…648b9`,
  `scripts/hardware/run_serial_ids.py` `3289b8f8…5818`.
- Python 3.13.15, pymavlink 2.4.50, numpy 2.5.3, Windows 11. Run on 2026-10-28 UTC (wall clock in `health.jsonl`).
- `events.sqlite` is git-ignored (`*.sqlite`); it holds the one persisted alert (hash chain OK, length 1).

## Result (`summary.json`, `health.jsonl`)
- Runner exit 0, `bytes_sent` 0, `write_errors` 0, `passed` true. **5,128 frames received of the 5,130 the feeder sent**
  (`DONE sent=5130 skipped=0`; the two missing frames are not explained; the original live run received all 5,130).
- **Through the stream: 453 decisions, 0 alerts** (health line at 20:49:02 UTC). `navigation_health.flagged_decisions` at that line:
  `ekf_no_horizontal_solution` 452, `gps_sensor_unhealthy` 452. Every decision except the first one (made before the first
  `EKF_STATUS_REPORT` / `SYS_STATUS` arrived) carried both vehicle-stated conditions; `last` read `fix_type` 3, `satellites` 7,
  `hdop` 7.99, `ekf_flags` 0xa7 (167), `horizontal_solution` false, `gps_healthy` false.
- **Final summary (decisions 476, alert_decisions 1):** `ekf_no_horizontal_solution` 458, `gps_sensor_unhealthy` 475.
  The difference from the 453-decision line is the **silent tail**: the capture is 89.82 s long but the runner was run for 95 s.
  Only the EKF-derived flag goes stale after 2 s; `gps_sensor_unhealthy` (475) keeps counting on the last `SYS_STATUS` through the tail, so the
  more reliable figures are the 452-of-453 ones from the health line taken while the stream was still running.
- **The one alert is an artefact of that tail, not a detection:** `t` = 92.0 s, `DOS`, evidence "heartbeat stale 3.0s > 3.0s",
  "GPS dropout 2.5s > 2.0s" (plus the existing degraded-navigation line), after the feeder had stopped sending. The original live
  run (0 alerts in 451 decisions) did not have this tail.
- In the final `last` block `horizontal_solution` is `null` and `ekf_age_s` 5.3: the last `EKF_STATUS_REPORT` was older than the
  2 s staleness rule, so the state is reported as unknown rather than asserted forever. That is the designed behaviour.

## What this does and does not show
- Shows: on real bench bytes, the runner's new block states, without raising any alert, that the vehicle itself reported no
  horizontal position solution and an unhealthy GPS sensor on essentially every decision of a stream whose receiver said "3D fix".
- Does not show: that this vehicle's position was or was not authentic; behaviour on a *healthy* estimator (no hardware capture of
  one exists); anything about attacks; any hardware serial behaviour; the dashboard rendering (covered by unit tests only).
