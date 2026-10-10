# Physical Pixhawk 6X — passive telemetry validation (BENCH)

**Environment tag: `BENCH`** — a physical flight controller on a desk, USB-attached to the Windows
host, **disarmed, props removed, no airframe, no flight**. `BENCH` is not `SITL`, `HITL` or `FIELD`
and is not in the rule-file tag list; it is used here because none of those describes it.
**Claim class: none.** This is a description of what the board's telemetry stream looks like to a
receive-only monitor. It is not detection evidence and says nothing about a vehicle in the air.

Date: 2026-10-10. Code: AegisFlight `9a6cd0274cd0a15ed52278cce0bd7df5713bfb68` + the uncommitted
files of this sprint (`scripts/hardware/pixhawk_passive_probe.py`).

## 1. What was identified (read-only, nothing sent)

| Item | Value | How known |
|---|---|---|
| Board | **Pixhawk6X** | Windows USB descriptor `BusReportedDeviceDesc` (`USB\VID_1209&PID_5740`) |
| Firmware family | **ArduPilot** (`MAV_AUTOPILOT_ARDUPILOTMEGA`, id 3) | HEARTBEAT `autopilot` field; USB driver label "ArduPilot MAVLink" |
| Vehicle type | **Quadrotor** (`MAV_TYPE_QUADROTOR`, 2) → ArduCopter | HEARTBEAT `type` |
| System / component | sysid **1** / compid **1** | frame headers |
| State | `STANDBY`, **disarmed**, `custom_mode` 0 = `STABILIZE`, `base_mode` 81 | HEARTBEAT |
| MAVLink version in use | **1** (198 of 198 frames; no MAVLink-2, no signing) | frame magic byte `0xFE` |
| Serial interfaces | **COM5** = "ArduPilot MAVLink" (USB-CDC, the one used); **COM4** = "ArduPilot SLCAN" (CAN, **never opened**) | Windows PnP |
| Baud | not applicable (USB-CDC ignores it) | — |
| **Firmware version** | **NOT DETERMINED** | see §4 |

## 2. What was run

```
.venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM5 --duration 180 \
    --json artifacts/hardware/pixhawk6x_passive_probe_001.json \
    --tlog data/hardware/raw/pixhawk6x_passive_001.tlog        # tlog is git-ignored; sha256 below
```
The probe opens the port through the existing `SerialMavlinkTransport` + `MavlinkFrameParser`
(the production path) and **never writes**: `bytes_sent = 0`, `write_errors = 0` are recorded in
the artifact and checked by the script. No heartbeat, no stream request, no command, no parameter
read. COM4 was not touched. Opening the CDC port asserts the standard serial control lines (DTR/RTS) and sets the line coding; that is not MAVLink, but it is not electrically nothing. No other program held COM5 (a Mission-Planner/QGC-style GCS would
have: Windows serial ports are exclusive).

## 3. Results — `artifacts/hardware/pixhawk6x_passive_probe_001.json` (180 s, one capture)

| Measure | Result |
|---|---|
| Valid frames received | **198** in 179.0 s (1.11 Hz, 19.5 B/s, 3,492 B) |
| CRC failures / header rejects / unverifiable ids | **0 / 0 / 0** |
| Parser errors (`bad_frames`) / garbage bytes / resyncs / partial timeouts | **0 / 0 / 0 / 0** |
| Sequence loss (inferred from `seq`) | 0 (per source, per system, whole link) |
| Silences > 2.5 s | 0 (largest HEARTBEAT interval 1001.01 ms) |
| Driver-level loss | **not measurable** (no counter below `read()`; see `docs/SERIAL_TRANSPORT.md`) |
| Disconnects / reconnects / open failures / reader faults | 0 / 0 / 0 / 0 (nothing unplugged — see §4) |
| Time to first frame | 0.75 s after open |
| Concurrent open of the same port | the second probe failed immediately with `PermissionError(13, 'Access is denied.')` and a clear message — the fail-fast path works |

Message coverage (the whole stream, the receive side saw only these):

| Message | id | Rate | Used by the IDS pipeline |
|---|---|---|---|
| HEARTBEAT | 0 | 1.006 Hz (180) | yes |
| TIMESYNC | 111 | 0.101 Hz (18) | no |
| SYS_STATUS, GPS_RAW_INT, GLOBAL_POSITION_INT, ATTITUDE, VFR_HUD | 1, 24, 33, 30, 74 | **0 (never seen)** | **yes — the other five** |

**Coverage of the six messages the Stage-1 extractor reads: 1 of 6.** No STATUSTEXT, no
AUTOPILOT_VERSION appeared. ArduPilot sends nothing but HEARTBEAT/TIMESYNC on this port until a
ground station asks for streams; this was also what the earlier SITL smoke test showed
(`~/aegis_sitl_ap/logs/smoke_20261010T052549Z/observer.json`).

Raw capture: `data/hardware/raw/pixhawk6x_passive_001.tlog`, sha256
`1cd749655d055fec9d9d1a27a2b3ceddd846a00a860dd63e2be5380e58b98ec3` (local only; it can contain a
GPS position in other captures, so the pattern is git-ignored).

### The unchanged pipeline on this stream (REPLAY of the BENCH capture)
`artifacts/hardware/pixhawk6x_passive_pipeline_replay_{ml,noml}.json`: all **896 of 896** decisions
are flagged as threats and 45 are alerts, every one `DOS` from the protocol rule *"GPS dropout 999 s"*
(plus the ML detector, which scores ≈1.0 on the timing, z = −145). Meaning: **with Stage-1 settings
the IDS cannot be run on this link as it stands** — it requires GPS/position/attitude messages that
this port does not send. That is a missing-telemetry condition, not a detector fault, and not an
attack. It is reported because it is exactly what a naive "plug it in and listen" deployment
would show.

## 4. What is NOT established (reported, not hidden)

1. **Firmware version.** ArduPilot reports it only in AUTOPILOT_VERSION (needs a request =
   a command to the controller) and in the boot banner STATUSTEXT. The probe saw neither. The ArduCopter
   *SITL* build is 4.7.1 (`dbe79216`); that says nothing about this board's firmware.
   Ways to get it with no transmit from AegisFlight: (a) read it in Mission Planner/QGC (then close that
   program), or (b) run the probe with `--keep-trying` and **unplug/replug USB** so the board reboots
   while the probe listens — the boot banner may be captured (not guaranteed: it depends on whether ArduPilot
   queues boot text for a port that opens at enumeration).
2. **Reconnect on hardware.** The reconnect logic is covered by unit tests (`tests/unit/test_mavlink_serial.py`,
   `socket://` virtual port). It was **not** exercised against the real device: that needs a physical
   cable pull, and this shell is not elevated, so a host-side USB re-enumeration was also unavailable.
   Command for the person at the bench: run the probe with `--keep-trying --duration 120`, pull the USB cable
   for ~10 s, plug it back; the artifact will show `disconnects`/`reconnects`/`last_error`.
3. **Useful telemetry.** Anything beyond HEARTBEAT requires either a persistent FC parameter change
   (per-port stream rates -- `MAVn_*` in ArduCopter 4.7.1, `SRn_*` in older firmware -- and `SERIALn_PROTOCOL` on a spare UART — done once by a person in a GCS, no
   AegisFlight transmit) or the monitor transmitting a GCS heartbeat and stream requests. The sprint
   forbade sending to the physical controller, so neither was done. See `docs/ONBOARD_DEPLOYMENT.md`.
4. **Real flight, arming, vibration, GPS lock, RF/radio links, UART (non-USB) behaviour** — all untested.
5. **One capture, one board, 180 s, one USB host port/cable.** No variance, no long-duration or thermal data.

## 5. Safety record
No MAVLink was transmitted (`bytes_sent = 0` in every capture, including the 15 s smoke capture and
two 180 s captures; only the final 180 s capture -- the second, re-run after fixing a gap-report threshold bug in the
probe -- has a stored artifact, the others are console output). No arming, motor test, parameter write, calibration or flight. SLCAN/CAN interface untouched.
Only one process opened COM5 at a time (a deliberate second open failed, as designed).
