# Onboard deployment — readiness assessment (Pixhawk 6X / ArduPilot, companion computer)

Date 2026-10-10. Evidence tags used below: `BENCH` (physical board on a desk, `docs/HARDWARE_BENCH_PIXHAWK6X.md`), `SITL`
(ArduCopter 4.7.1, `docs/ARDUPILOT_SITL.md`), `REPLAY` (recorded bytes), `VIRTUAL-SERIAL` (a recorded capture played over a
loopback socket into the real serial transport — a software path test, **not** a serial device). Nothing here is `FIELD`.

## 1. Verdict

**Not ready to deploy on the vehicle.** What is ready is a *receive-only monitor* whose software path has been exercised end to end on
real ArduPilot bytes, plus a concrete, SITL-verified recipe for feeding it. Eight things stand between that and a deployment; four of them need a decision or an
action from a person (§2). Nothing in this document claims detection on a real vehicle; the only attack evidence is one link-level scenario in SITL
(`docs/ARDUPILOT_SITL.md` §6).

## 2. Blockers (each with what unblocks it)

| # | Blocker | Evidence | Unblocks with |
|---|---|---|---|
| **B1** | **The board's firmware version is unknown**, and it decides the parameter *names*: ArduCopter 4.7.1 has **no `SRn_*`** parameters (read back from the simulator: absent; source: `// SR0 through SR6 was here`); they are `MAVn_*`. Older firmware uses `SRn_*`. | `artifacts/ardupilot/passive_monitor_param_readback/` | person reads the version in a GCS, or runs the probe with `--keep-trying` while replugging USB to catch the boot banner (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §4) |
| **B2** | **The physical FC does not stream what the IDS needs.** Passive USB capture: HEARTBEAT + TIMESYNC only, **1 of the 6 required messages**; the unchanged pipeline calls every decision a threat (896/896) because GPS/position/attitude never arrive. | `artifacts/hardware/pixhawk6x_passive_probe_001.json`, `…_pipeline_replay_*.json` | a person sets persistent stream parameters on the port the monitor will use (§4); nothing was written to the board in this sprint |
| **B3** | **Reconnect and framing on a real device are unmeasured.** Real USB unplug/replug, UART noise, baud mismatch, driver loss: untested. Only the loopback virtual port was exercised. | `docs/SERIAL_TRANSPORT.md` "Not done"; §6 below | bench replug test with the probe/runner (commands in §8) |
| **B4** | **The Stage-1 ML model could not be used on the ArduPilot-SITL pipe path** (ML-on in-flight alerts 126/2,339 vs 0/2,329 with it off; the ML-off figure is selected-on-data; part of the timing the model objected to may be path-induced). The only ArduPilot detection evidence is rules + physics on one SITL link-level scenario; per-vehicle ML retraining (Stage-2 step 4) is not done. | `artifacts/ardupilot/BASELINE_SUMMARY.md` | aegis-detection task: retrain on ArduPilot benign data, hold out flights, re-benchmark |
| **B5** | **Link loss produces alerts (by design); the physics false alerts at recovery were fixed 2026-10-10.** An 8.5 s outage (virtual port): 2 `DOS` alerts during it (expected — silence is indistinguishable from a dead link to the detectors). In run 001 recovery added `sequence gap 218 > 30`, heading/course mismatch 89° and position residual 29 m (one `TELEMETRY_MANIPULATION` and one `GPS_SPOOFING` false alert). Cause: the position residual integrated velocity across the whole gap and a fresh ATTITUDE was compared with an 8 s-old GPS velocity. Fix (commit `eae85e6`, `features/extractor.py`, `_LINK_GAP_S = 2.0`): skip both checks until GPS is fresh. Re-run 002 (same capture, same outage): recovery produces **one** `MAVLINK_ANOMALY` alert (`sequence gap 218`, a true observation — 218 frames were lost); the two physics alerts are gone. n = 1 outage; real USB/UART reconnect still unmeasured (B3). | `artifacts/ardupilot/serial_path_replay_00{1,2}/` | optional later: a hold-down on the sequence-gap alert keyed on `transport.reconnects` (not done; the alert is accurate) |
| **B6** | **No measurement on the target computer.** Cost figures are from one Windows laptop with the simulator excluded. | §6 | run `measure_replay_cost.py` on the target (command in §8) |
| **B7** | **Operational hardening is missing.** No service unit, no log rotation or disk cap (a dead link raises one `DOS` alert per 4 s ≈ 21,600/day), no watchdog, no slim install (the core install pulls FastAPI/uvicorn/matplotlib/pandas/scipy/scikit-learn). | `scripts/hardware/run_serial_ids.py` measured log growth, §5 | a deployment specialist task (none exists yet; the lead holds it) |
| **B8** | **Link authenticity cannot be established on this link as configured.** The observed USB stream was **MAVLink 1** with no signatures (198/198 frames in one passive 179 s capture; whether v1 is the port's protocol setting or a channel default was not established), so nothing in it could be verified; the known `gcs_replay`/injection gaps apply unmitigated. | `docs/HARDWARE_BENCH_PIXHAWK6X.md` §1 | enabling MAVLink 2 + signing is a vehicle-configuration and key-management decision (aegis-security), not something the monitor can do |

## 3. What is ready, and how well it is evidenced

| Capability | Evidence | Tag |
|---|---|---|
| Receive-only serial monitor (`run_serial_ids.py`): `transport.send` never called, `bytes_sent` recorded and enforced (exit 3 if non-zero), refuses pyserial URLs unless explicitly allowed | 4 unit tests; `bytes_sent = 0` in every run | unit, VIRTUAL-SERIAL, BENCH (probe) |
| Parser/framer on real ArduPilot: **0 CRC rejects, 0 garbage, 0 bad frames** on 198 BENCH frames (v1) and the 3,442-frame virtual-serial replay (both through the serial framer); the 3,660–8,589-frame SITL captures went through the pipe transport and the same parser, not the serial framer | `artifacts/hardware/…`, `artifacts/ardupilot/…` | BENCH, SITL |
| A **strictly receive-only** monitor on a parameter-configured port gets all six messages and the unchanged pipeline is quiet in flight | §4 | SITL |
| Startup, steady state, clean shutdown (`--seconds`; the signal path is untested), health counters, hash-chained alert log | `artifacts/ardupilot/serial_path_replay_001/` | VIRTUAL-SERIAL |
| Transport auto-reconnect after an outage (2 refused opens during the 8.5 s outage, then resumed by itself: `reconnects = 1`) | same | VIRTUAL-SERIAL |
| Latency/CPU/RSS | §6 | SITL, REPLAY |
| One link-level attack detected 3/3 and reproducible from recorded bytes | `docs/ARDUPILOT_SITL.md` §6 | SITL |

## 4. How to get telemetry to the monitor without the monitor transmitting

**Verified in SITL (`artifacts/ardupilot/ap_passive_monitor_params_001/`, `…/passive_monitor_param_readback/`):** SERIAL1 given `SERIAL1_PROTOCOL=2` and
`MAV2_EXT_STAT=2, MAV2_POSITION=5, MAV2_EXTRA1=10, MAV2_EXTRA2=5` (persistent defaults, read back from the simulator). A raw-socket client on SERIAL1 that
**never writes** (`tx_frames 0, tx_bytes 0`) received **8,589 frames in the 141 s flight with all six messages** (HEARTBEAT 0.95, SYS_STATUS 1.82,
GPS_RAW_INT 1.82, GLOBAL_POSITION_INT 4.53, ATTITUDE 9.07, VFR_HUD 4.53 Hz; 13 other message types; 60.9 Hz, 2.5 kB/s). Fed to the unchanged pipeline (ML off): 708 decisions, **5 start-up alerts and 0
in the 476 in-flight decisions**, hash chain intact, replay reproduces the live verdicts on 706/706, simulator ports never in the default namespace, run script hash equals the recorded one.
**The monitor sent no heartbeat of its own** -- but a full GCS (the flight driver on SERIAL0, sending a 1 Hz heartbeat and flying the vehicle) was connected for the whole run, so "an FC with *no* GCS at all streams on a `MAVn`-configured port" was **not** tested. (Two earlier runs used a parameter file with non-existent `SR1_*` names — a no-op — and are kept only as "default parameters give no streams, with or without a
heartbeat": `ap_passive_monitor_001`, `ap_passive_monitor_hb_001`. My first hypothesis, that ArduPilot withholds streams until it hears a GCS heartbeat, was wrong; the cause was the wrong parameter names.)

**Not verified:** on the physical board; on any firmware other than 4.7.1; which `MAVn` index belongs to which `SERIALx` on the board (in SITL with SERIAL0 and SERIAL1 both MAVLink,
`MAV2` was SERIAL1 — read the mapping back on the real board before relying on it); behaviour of a UART link (bandwidth, noise).

Recommended recipe (design, untested on hardware):
1. Read the firmware version (B1) and the current values of `SERIALx_PROTOCOL/BAUD` and the stream parameters; **save a parameter backup** with the GCS.
2. On a spare UART (e.g. a TELEM port): `SERIALx_PROTOCOL = 2` (MAVLink 2 — also what makes signing possible later, B8), `SERIALx_BAUD` ≥ 115 (115200; the 61 Hz groups stream is ≈ 2.5 kB/s ≈ 22 % of 115200 baud, 44 % of 57600),
   and the four stream-group parameters for **that port's** `MAVn` at 2 / 5 / 10 / 5 Hz. Reboot (the parameters are `RebootRequired`).
3. Wire **FC TX → monitor RX and ground only; leave the monitor's TX unconnected.** That makes "receive-only" a property of the wiring, not only of the code. (The FC then never hears the monitor; in SITL this was sufficient while another GCS was active on SERIAL0 -- an FC with no GCS at all was not tested.)
4. Rate budget: `nominal_msg_rate_hz` is 28, spike at ×3 = 84 Hz; this configuration measured 60.9 Hz. Enabling more stream groups can cross 84 Hz and trip the rate rule — add streams only with a re-measurement.
5. Group-level rates mean GPS_RAW_INT arrives at 2 Hz, not the 5 Hz of the Stage-1 simulator; no false alarm resulted in SITL (rule timeout 2 s, period 0.5 s).

If, instead, the monitor must request streams itself (`MAV_CMD_SET_MESSAGE_INTERVAL`, `REQUEST_DATA_STREAM`), that is a **transmit to the flight controller**, was not done on hardware, and
needs an explicit go-ahead; it was verified only on SITL (`six`/`groups` runs).

## 5. Requirements checklist

* **Dependencies.** Python ≥ 3.11 (tested 3.13.15 on Windows; the transport tests also ran on 3.12.3 in WSL), `pip install -e ".[serial]"` (pyserial ≥ 3.5; pymavlink 2.4.50, numpy 2.5.3, scikit-learn 1.9.1 were the tested versions). The core install also pulls the dashboard stack; there is no slim profile (B7). Install size and import time on the target were not measured.
* **Configuration.** `run_serial_ids.py --port <dev> --baud <FC baud> --out-dir <dir>`; Stage-1 `configs/` unchanged (`expected_sysids [1]` matches both the board and SITL); ML **off** (default; `--ml` exists and must not be used on ArduPilot); no `--allow-url` outside tests.
* **Telemetry interface.** §4. USB-CDC ignores baud; a UART must match `SERIALx_BAUD`.
* **Startup / shutdown.** Starts before the FC is present (the transport retries every `--reconnect-interval`; `--no-reconnect` fails with exit 2); a dead-from-start link still produces ticks and alerts. `--seconds N` stops cleanly (exit 0, summary written, hash chain verified; tested). The signal-driven stop (Ctrl-C / SIGTERM) is implemented but **not tested**, and SIGTERM is not a normal stop path on Windows. No systemd unit exists (B7). A unit would need `KillSignal=SIGTERM` and `Restart=on-failure`; untested.
* **Reconnect.** Transport-level reconnect worked in the virtual-port test; the pipeline-level consequences are B5. Port loss versus link loss are told apart only by `transport.connected/disconnects/last_error` in `health.jsonl`, not by the detectors.
* **Logging.** `events.sqlite` (hash-chained alerts; `aegis verify-log <db>` verifies), `alerts.jsonl` (≈ 301 B/alert), `health.jsonl` (≈ 1.15 kB per `--health-interval`; at the 10 s default ≈ 10 MB/day), `summary.json`. No rotation, no disk cap (B7). The hash chain detects edits, not deletion of the whole file.
* **Rollback.** The monitor has no effect on the vehicle (receive-only; TX unconnected). To roll back: stop the service, disconnect the RX wire, and restore the saved parameter backup (the stream parameters are the **only** change made to the vehicle). Nothing is flashed.

## 6. Cost — what was measured, and how to re-measure it where it matters

| Measure | Value | Where / tag |
|---|---|---|
| Pipeline CPU per second of telemetry, ML off | **0.00101 CPU-s/s** (median of 3, 138.8 s capture) | this laptop, REPLAY — `artifacts/ardupilot/replay_cost_dev_laptop_asus_tuf_f15.json` |
| …ML on | 0.0501 CPU-s/s (≈ 50× more) | same |
| RSS, ML off / ML on | ≈ 65 / ≈ 168 MB | same |
| Live runner, ML off, 160 s over the virtual serial port | CPU 0.57 % of one core (0.91 CPU-s), RSS 55.9 MB, decision latency mean 0.17 ms / p99 0.28 / max 0.70 ms | `artifacts/ardupilot/serial_path_replay_001/summary.json` |
| Live pipe path, ML off, 141 s | CPU 2.3 % mean / 6.2 % max, RSS 58.6 MB | `ap_passive_monitor_params_001` |

These do **not** transfer to a Raspberry Pi/Jetson-class computer; they only say the pipeline is ~three orders of magnitude below one core on a laptop-class CPU. The portable metric is CPU-seconds per
telemetry-second; run the same command on the target and compare it with 1.0 per core, with headroom for the OS, the serial driver and everything else on that computer.

## 7. Failure modes already observed (do not rediscover)
* A silent link → `DOS` alerts every 4 s (`cooldown_s`), indefinitely; with a 1 Hz heartbeat stream the first alert comes after 3 s (`heartbeat_timeout_s`).
* Start-up: 5 alerts per boot before GPS lock (sentinels `999 s`, no-fix GPS, first-sample battery/altitude values) — expect them; they are not attacks.
* A monitor that opens the port while a GCS holds it fails immediately (`PermissionError`) rather than sharing it — correct, and a reason to give the monitor its own port.
* Wrong parameter names are **silently ignored** by the simulator's defaults loader (it reported "Loaded defaults" either way): always read the values back.

## 8. Next actions, in order, with the exact commands
1. **(person)** Record the firmware version and the current stream/serial parameters; save a parameter backup. Alternatively, with the board's USB unplugged first:
   `.venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM5 --duration 120 --keep-trying --json artifacts/hardware/pixhawk6x_replug_001.json --tlog data/hardware/raw/pixhawk6x_replug_001.tlog`, then plug the USB in (boot banner may appear) and, for the reconnect measurement, pull it for ~10 s and plug it back.
2. **(person, props off, disarmed)** Apply §4 steps 2–3 on a spare UART; confirm the six messages with `pixhawk_passive_probe.py` (it needs a USB-serial adapter on that UART) before running the monitor.
3. `.venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port <port> --baud <baud> --out-dir runs/bench_001 --seconds 300` → `summary.json`; compare with `artifacts/ardupilot/BASELINE_SUMMARY.md`.
4. On the target computer: `.venv/Scripts/python.exe scripts/ardupilot/measure_replay_cost.py data/ardupilot/raw/ap_benign_six_001.clean.tlog --repeat 3 --json artifacts/ardupilot/replay_cost_<machine>.json` (copy the tlog over; it is git-ignored).
5. Decide B4 (retrain ML on ArduPilot) and B5 (post-reconnect hold-down) — both are aegis-detection scope and need re-benchmarking.
