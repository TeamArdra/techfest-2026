# Physical Pixhawk 6X — passive telemetry validation (BENCH)

**Environment tag: `BENCH`** — a physical flight controller on a desk, USB-attached to the Windows
host (§1–§5; §6 reads it through the TELEM1 telemetry radio on COM7), **disarmed, props removed, no airframe, no flight**. `BENCH` is not `SITL`, `HITL` or `FIELD`
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
   *(Later, 2026-10-14: a person changed `SR1_*` in Mission Planner. With that change, all six messages arrive over the TELEM1 radio: §6.7.)*
4. **Real flight, arming, vibration, GPS lock, RF/radio links, UART (non-USB) behaviour** — all untested.
   *(Later, 2026-10-14: a TELEM1 telemetry-radio link on a laptop-side UART bridge (COM7) was captured and run through the IDS
   on the bench, §6.7 and §6.8. Flight, arming, vibration and GPS lock remain untested.)*
5. **One capture, one board, 180 s, one USB host port/cable.** No variance, no long-duration or thermal data.

## 5. Safety record
No MAVLink was transmitted (`bytes_sent = 0` in every capture, including the 15 s smoke capture and
two 180 s captures; only the final 180 s capture -- the second, re-run after fixing a gap-report threshold bug in the
probe -- has a stored artifact, the others are console output). No arming, motor test, parameter write, calibration or flight. SLCAN/CAN interface untouched.
Only one process opened COM5 at a time (a deliberate second open failed, as designed).

## 6. COM7 telemetry radio (TELEM1) — investigation checkpoint, 2026-10-14 (P2.3)

**Environment `BENCH`; claim class none.** *Update 2026-10-14: the symptom is resolved and the cause is partly established. After
the user set `SR1_*` and power-cycled the board, COM7 delivers all six pipeline messages: H2 is rejected and H1 is still
unproven (6.7). The first physical IDS run is recorded in 6.8. Sections 6.1–6.6 are kept as written at the checkpoint, when
the cause was not yet established. Unlike §1–§5 (USB, COM5), this section is about the TELEM1 telemetry radio, read on the
laptop's COM7.* Why the radio link delivers only
HEARTBEAT, and what is missing before it can feed the dashboard. For this checkpoint nothing was transmitted and no
serial port, parameter, radio setting or production code was touched: existing captures were analysed offline,
upstream ArduPilot / Mission Planner source was read, and hardware-free tests were run.

### 6.1 Confirmed facts
| # | Fact | Where |
|---|---|---|
| F1 | COM7 (laptop-side CP210x radio, 115200) captures 005 and 006, 60 s each: **60 frames (1,020 B), all HEARTBEAT, MAVLink 1**, sysid/compid 1/1 (ArduPilot, QUADROTOR, STANDBY, disarmed); 0 CRC/header rejects, 0 garbage bytes, `bytes_sent` 0 | `artifacts/hardware/telemetry_radio_probe_005.json`, `…_006.json` |
| F2 | In both, sequence numbers are contiguous (0 gaps) and the raw `read()` bytes equal the 60 heartbeat frames byte for byte: nothing else arrived | `scripts/sitl/tlog_stats.py` on `data/hardware/raw/telemetry_radio_00{5,6}.tlog`; `read_raw_records()` on `…_00{5,6}.rawbin` (local, git-ignored; sha256 in the JSONs) |
| F3 | The earlier COM7 capture at 57,600 baud: 964 B, **0 frames**, all garbage. At 115,200 the frames are byte-exact, so 115200 is the working rate of the laptop-side serial link (empirical; the radio's own configuration is unread) | `artifacts/hardware/telemetry_radio_probe_001.json` vs F1 |
| F4 | USB (COM5) passive captures: HEARTBEAT 1 Hz **+ TIMESYNC every 10 s**. COM7: **no TIMESYNC** | `artifacts/hardware/pixhawk6x_passive_probe_001.json`, `pixhawk6x_probe_001.json` vs F1 |
| F5 | Pixhawk 6X: SERIAL1 = UART7 = TELEM1 | ArduPilot `libraries/AP_HAL_ChibiOS/hwdef/Pixhawk6X/hwdef.dat` (`SERIAL_ORDER OTG1 UART7 …`); ardupilot.org Pixhawk 6X page |
| F6 | User-reported in Mission Planner (no artifact): MP on COM5 showed all six pipeline messages; `SERIAL1_PROTOCOL=1, SERIAL1_BAUD=115, BRD_SER1_RTSCTS=0, SERIAL1_OPTIONS=1024, SERIAL2_PROTOCOL=-1`; `SR1_EXT_STAT/POSITION/EXTRA1/EXTRA2/EXTRA3 = 2/2/4/4/2` read while MP was connected. **Over which link, and since which power-up, was not recorded** | user report |
| F7 | `SRn_*` exist at tag `Copter-4.6.3` and are absent at `Copter-4.7.1` (`// SR0 through SR6 was here`), so the board runs a pre-4.7 parameter layout; **exact firmware version unknown** | ArduPilot `ArduCopter/Parameters.cpp` at both tags |

Firmware behaviour, read in upstream source at tag `Copter-4.6.3` (S2, S4 and the defaults also checked identical at `Copter-4.5.7`):

* **S1** Every `SRn_*` defaults to 0, is `RebootRequired`, and is applied once at boot. HEARTBEAT (1 Hz) is sent regardless (`ArduCopter/GCS_Mavlink.cpp`; `GCS_Common.cpp` `initialise_message_intervals_from_streamrates`).
* **S2** A GCS `REQUEST_DATA_STREAM` changes the **receiving** link's `SRn_*` **in RAM only**; Copter never saves it (`libraries/GCS_MAVLink/GCS_Param.cpp`: "copter passes in save==false"; `persist_streamrates()` is false). With its default settings Mission Planner requests EXT_STAT 2 / POSITION 2 / EXTRA1 4 / EXTRA2 4 / EXTRA3 2 (also RAW_SENS 2, RC_CHAN 2) right after connecting and then about every 38 s (MissionPlanner `ExtLibs/ArduPilot/CurrentState.cs`, read 2026-10-14): exactly the F6 values.
* **S3** `SRn` belongs to the n-th serial port, in SERIAL order, whose protocol is MAVLink 1/2/HL (`AP_SerialManager::find_protocol_instance`, `GCS_MAVLINK::init`). With SERIAL0 (USB) on MAVLink, `SR1` = TELEM1.
* **S4** `SERIALx_OPTIONS` bit 10 ("Don't forward mavlink to/from"; moved to `MAVn_OPTIONS` in 4.7) marks the link *private*: no forwarding, no STATUSTEXT, **no TIMESYNC**. It does not stop `SRn` streams, and stream requests are refused only by bit 12 ("Ignore Streamrate"), which is not set. This explains F4 and supports that COM7 carries SERIAL1; it does **not** explain the missing messages.
* **S5** Each link has its own TX sequence counter (`GCS.h`, `_channel_status`). So F2 means the FC **sent nothing else on this link** during those minutes; the radio did not drop the other messages (assuming it forwards frames unmodified, which the byte-exact, CRC-valid frames indicate).
* **S6** GLOBAL_POSITION_INT is sent even with no valid position ("we send stale data"), and Copter's VFR_HUD altitude comes from the same AHRS location (`GCS_Common.cpp`).

### 6.2 Leading hypothesis (not proven)
**H1: no boot-time streams on TELEM1.** The stored `SR1_*` values are the default 0, so after power-up TELEM1 sends only
HEARTBEAT, and the F6 values were Mission Planner's own RAM-only request on that link (MP connected through the radio
during that power-up). Supported by F2+S5 (the sender emits nothing else), F4+S4 (COM7 is the private SERIAL1 link) and
S1/S2 (default 0, requests not saved, value pattern identical to MP's). **Not proven:** the stored `SR1_*` values have
never been read under conditions that rule out a RAM override, because F6 does not record the link or the power-up history.
**H2: mapping.** The stored `SR1_*` are non-zero but `SR1` is not the link feeding COM7 (the radio is on another port, or
the MAVLink ports are enumerated differently). F4+S4 make this less likely but do not exclude it.
**Ruled out by evidence:** the radio dropping or filtering messages (F2, S5); baud or framing errors on COM7 (F1, F3);
TELEM1 flow control (`BRD_SER1_RTSCTS=0`, and heartbeats flow).

### 6.3 Next diagnostic action (a person, read-only; separates H1 from H2)
Precondition: since the Pixhawk last powered up, no ground station has connected through COM7 (only the receive-only
probe). If that is not certain, a power cycle is needed first. That is a reboot, so it is a separate decision.
1. Make sure nothing holds COM7. Better: unplug the laptop-side radio so nothing can open it.
2. Mission Planner: select **COM5 explicitly (not AUTO)** and Connect. MP sends its usual heartbeat, parameter and
   stream requests **on the USB link only**. Per S2 and S4 they change only `SR0_*`, in RAM, are not saved, and cannot reach TELEM1.
3. Note the firmware version line (title bar or Messages tab).
4. Config → Full Parameter List → Refresh Params. Record by screenshot, or **Save** to a local file (never *Write Params*):
   `SERIAL0_PROTOCOL` … `SERIAL8_PROTOCOL`, `SERIAL1_OPTIONS`, all `SR1_*`, all `SR0_*`.
5. Disconnect.

Decision rule: `SR1_EXT_STAT, _POSITION, _EXTRA1, _EXTRA2` all 0, with SERIAL0 and SERIAL1 on MAVLink → **H1 confirmed**.
Non-zero with the precondition met → H1 rejected; work H2 from the `SERIALx_PROTOCOL` list. `SR0_*` showing MP's rates
confirms on the spot that the list shows RAM values. A 4.7+ version (no `SR*` parameters) → redo with `MAVn_*` (in 4.7.1
SITL, `MAV2` was SERIAL1: `artifacts/ardupilot/passive_monitor_param_readback/`).

**If H1 is confirmed, the smallest safe change (needs explicit authorisation):** save a parameter backup; set only
`SR1_EXT_STAT=2, SR1_POSITION=2, SR1_EXTRA1=4, SR1_EXTRA2=4` (SYS_STATUS + GPS_RAW_INT, GLOBAL_POSITION_INT, ATTITUDE and VFR_HUD,
at MP's own rates); reboot (RebootRequired). Rollback is restoring the backup. Verify with **one** receive-only COM7 probe capture
(60 s, `--tlog`, `--raw`). Pass: all six messages at ≥ 80 % of the set rates, contiguous sequence, 0 CRC rejects,
`bytes_sent` 0. Fail (still HEARTBEAT only) → H2.

### 6.4 Physical telemetry → IDS → dashboard: state and sequence
The path as inspected today:
```
COM7 -> SerialMavlinkTransport -> LiveMavlinkSource -> IDSPipeline -> EventStore + alerts/health/summary  (scripts/hardware/run_serial_ids.py, receive-only)
aegis serve -> LiveEngine -> SimulatedTelemetrySource only -> IDSPipeline -> in-memory alerts + WebSocket -> React ("Simulation")
```
Missing:
* **(a) Telemetry:** the other five messages do not arrive yet (6.2).
* **(b) Runner:** input bytes are not saved (no tlog; `sources/frame_tap.py` `TapTransport` already exists), there is no per-message coverage, only alerts are persisted (not decisions), and `summary.json` has no `BENCH` tag or provenance.
* **(c) Backend:** there is no source selection, `sim: true` is hard-coded, `/api/events` serves the simulator's in-memory deque rather than the runner's `events.sqlite`, and the attack endpoints are simulator-only. `LiveMavlinkSource.stream()` blocks, so it cannot run inline on the event loop.
* **(d) Frontend:** the header and footer hard-code "Simulation" / "does not connect to a real UAV", the `sim` flag is never read, there is no SITL/BENCH/REPLAY label, and the attack buttons are always enabled.

Proposed sequence (additive; SIM stays the default; only one process touches hardware):
1. The 6.3 diagnostic.
2. The authorised `SR1_*` change and its pass/fail capture.
3. Runner: tlog via `TapTransport`, coverage counts, a bounded `decisions.jsonl`, `environment: BENCH` and provenance (tests on `socket://`).
4. Backend: an opt-in `--follow <run-dir>` mode that reads the runner's files read-only, reports `source: BENCH` and `sim: false`, rejects attack calls, shows an error instead of falling back to SIM, and never opens a port.
5. Frontend: the label comes from the backend's `source`, a coverage/health panel is added, and attack controls appear only in SIM.
6. Decide P1–P3 (6.5) and implement them with regression tests and a Stage-1 benchmark regression.
7. An authorised live BENCH run (runner + dashboard, screen-recorded), then a REPLAY of the saved tlog through the runner (`scripts/hardware/virtual_serial_replay.py`) to reproduce the decisions.

Acceptance for the first live demo: real COM7 frames saved with hashes; six message types with measured rates;
UTC-anchored timestamps; coverage/health visible; every decision and alert persisted, with the hash chain verified (`aegis verify-log`);
the dashboard says BENCH; every bench alert explained; the replay reproduces the decisions.

### 6.5 Known detector-policy and evidence limitations
* By default, never-received GPS is still a CRITICAL `DOS` alert, although its evidence text says "never received … not a
  measured dropout" (**pending policy P1**). GPS_RAW_INT does not count as GPS presence (**P2**). See `tests/unit/test_missing_telemetry_fused.py`.
* A GNSS fix that was **never acquired** fires the same "GNSS fix lost" `DOS` rule as a lost fix (strict xfail; **P3**).
  *(Superseded 2026-10-15, P3.4: the evidence now reads "GNSS fix never acquired …" unless a valid fix was seen first; the
  xfail passes and is unmarked. The score, the `DOS` vote and the timing are unchanged; whether a never-acquired fix should score
  differently is still open.)*
  *Decision record: the user's P3.4 brief (2026-10-15) set the requirement (distinguishable cases, no false "lost" claim, no
  score/weight/threshold change); the exact wording and "valid fix seen since reset()" state were the implementer's choice
  (aegis-lead with aegis-detection), reviewed ACCEPT-WITH-FIXES in the aegis-reviewer P3.4 review and committed at the user's request (5a35143). Scoring is undecided.*
  Once the POSITION stream is on, GLOBAL_POSITION_INT arrives even without a fix (S6) and the never-received rule clears. On
  this indoor bench, with no fix expected, the GNSS rule should then alert about every 4 s (`cooldown_s`). This is
  predicted from the code and tests, not yet observed (*observed afterwards: 6.8*). An indoor bench with no fix is not attack evidence.
* The documented "never silently accepted" floor for never-seen GPS does not hold at the fused level (strict xfail).
* On ArduCopter the GPS-vs-baro altitude check compares two views of one AHRS altitude (S6), so physics silence on the
  bench says nothing about detector correctness.
* ML is off for ArduPilot, and the integrity detector reports `UNKNOWN` (no verifier). Nothing in this section is detection
  evidence. The COM7 captures are not yet in `docs/VALIDATION_EVIDENCE.md`, and this section has not had an `aegis-reviewer` pass.
  *(Superseded 2026-10-14: the §1c rows were added for 6.7 and 6.8, and those were reviewed.)*
* Hardware-free tests, 2026-10-14: `.venv/Scripts/python.exe -m pytest tests/unit/test_run_serial_ids.py tests/unit/test_missing_telemetry.py
  tests/unit/test_missing_telemetry_fused.py tests/unit/test_serial_raw_tap.py tests/unit/test_mavlink_serial.py
  tests/unit/test_mavlink_live.py backend/tests/test_api.py -p no:cacheprovider -o addopts="" -q` → **281 passed, 3 skipped**
  (Windows PTY), **2 xfailed**. *(After P3.4, 2026-10-15: the full suite gives 604 passed, 3 skipped, 1 xfailed; the P1 floor
  xfail remains.)*

### 6.6 Repository state and next task
At this checkpoint `HEAD` is `6b21d1f`. The working tree holds the earlier sprints' uncommitted work (7 modified tracked
files and 7 untracked: probe `--raw`, raw tap, missing-telemetry flags and tests, COM7 artifacts) plus this section; nothing
is staged or committed. **Next task: P2.4, the read-only Mission Planner inspection in 6.3 (done by a person, no writes).**
No parameter change and no code work before its result.

### 6.7 Stream-rate correction verified: capture 007 (2026-10-14)
**Environment `BENCH` (physical bench, "PHYSICAL_BENCH" in the Stage-2 brief); claim class none (stream description).**
**User actions, no artifact:** the user set `SR1_EXT_STAT=2, SR1_POSITION=2, SR1_EXTRA1=4, SR1_EXTRA2=4` in Mission Planner,
wrote and saved them, power-cycled the Pixhawk, and saw the new values after the reboot. The values stored *before* the change
were not recorded, and neither was the firmware version. AegisFlight wrote nothing to the board.
* **The 6.3 diagnostic (P2.4) was not done before the change.** That is why the earlier stored values are unknown.
* **Parameter backup:** whether the backup 6.3 asked for was saved is not recorded.
* **Mission Planner state:** MP was running on the laptop during capture 007 and the 6.8 run. It could not have held COM7,
  because both opens of COM7 succeeded and Windows lets only one process open a COM port. Whether it was connected over USB
  (COM5) is not recorded. Per S2/S4, a USB connection changes only `SR0_*` in RAM and does not reach TELEM1.
* **Probe label:** the probe-007 JSON's `environment` string says "…USB…". That text is hard-coded in the probe; this capture
  is the radio on COM7.

**Capture:** one 60 s receive-only probe capture on COM7, run at 2026-10-14T18:22:39Z, at commit `6b21d1f` plus the uncommitted
working tree (see 6.8, Provenance).
```
.venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM7 --baud 115200 --duration 60 --json artifacts/hardware/telemetry_radio_probe_007.json --tlog data/hardware/raw/telemetry_radio_007.tlog --raw data/hardware/raw/telemetry_radio_007.rawbin
```
| Message (id) | 005 / 006 count | 007 count | 007 rate (Hz) | Set rate |
|---|---|---|---|---|
| HEARTBEAT (0) | 60 / 60 | 60 | 1.004 | always 1 Hz |
| SYS_STATUS (1) | 0 | 120 | 2.008 | EXT_STAT 2 |
| GPS_RAW_INT (24) | 0 | 120 | 2.008 | EXT_STAT 2 |
| GLOBAL_POSITION_INT (33) | 0 | 120 | 2.008 | POSITION 2 |
| ATTITUDE (30) | 0 | 240 | 4.016 | EXTRA1 4 |
| VFR_HUD (74) | 0 | 240 | 4.016 | EXTRA2 4 |
| MISSION_CURRENT (42), NAV_CONTROLLER_OUTPUT (62), POWER_STATUS (125), MEMINFO (152) | 0 | 120 each | 2.008 each | same stream groups |
| AHRS2 (178) | 0 | 240 | 4.016 | same stream groups |

Totals: **1,620 frames, 46,020 B**, all MAVLink 1, one source (1/1, QUADROTOR, STANDBY, disarmed). 0 CRC rejects, 0 header
rejects, 0 garbage bytes, 0 sequence gaps, 0 silences over 2.5 s, `bytes_sent` 0, `write_errors` 0. As on COM7 before, there is
no TIMESYNC or STATUSTEXT (S4). **Independent checks:** `scripts/sitl/tlog_stats.py` on the tlog gives 1,620 frames, 0 bad,
sequence span 1,620, 0 lost. The data bytes in the `.rawbin` (2,759 records) equal the concatenated tlog frames (46,020 B) exactly.
sha256: rawbin `3420ff0c6c0b4b1e2d200fa00203241375e3710d274e09bff9c353f3e89a1c4d`,
tlog `0a70133114f439aad8e7a45b7e86eb76127cda4efa0674891e8c228025d0e17a` (both local and git-ignored).
Evidence: `artifacts/hardware/telemetry_radio_probe_007.json`.

**Against the 6.3 pass criterion:** all six messages are at or above the set rates, sequence numbers are contiguous, there
are 0 CRC rejects and `bytes_sent` is 0, so **PASS**.
* **H2 is rejected**, on the basis of the user's report that only these four `SR1_*` values were changed: `SR1_*` controls the
  link that reaches COM7.
  * The mix of message groups shows that the rates come from the stored values, not from a ground station's RAM request.
    In ArduCopter 4.6.3, `ArduCopter/GCS_Mavlink.cpp` (stream groups):
    * Present: AHRS2 (EXTRA1) and MISSION_CURRENT, NAV_CONTROLLER_OUTPUT, POWER_STATUS, MEMINFO (EXT_STAT).
    * Absent: the RAW_SENS, RC_CHAN and EXTRA3 groups, such as RAW_IMU, SCALED_PRESSURE, SERVO_OUTPUT_RAW, RC_CHANNELS,
      SYSTEM_TIME, EKF_STATUS_REPORT and VIBRATION. Mission Planner's request includes those groups (S2).
  * The board's exact firmware is unknown; 4.6.3 is the version whose source was read.
* **H1 is not proven:** that the earlier stored values were 0 is consistent with this result, but because the pre-change
  values were not recorded it remains unproven. There is one supporting sign. F6 showed `SR1_EXTRA3 = 2` while MP was connected,
  yet no EXTRA3 message arrives now. So F6 showed RAM values rather than stored ones, assuming `SR1_EXTRA3` was not changed
  (user report).

### 6.8 First physical telemetry through the IDS: `serial_ids_com7_001` (2026-10-14)
**Environment `BENCH` (PHYSICAL_BENCH).** This shows that **real telemetry from the physical board is ingested, the detectors and
fusion run on it, and the events are persisted to a verifiable log**. **It is not evidence of attack detection**: no attack
was made, the vehicle did not fly, and it was disarmed and stationary on an indoor desk with no GPS fix. The alerts below are
the current detectors' behaviour on that bench, not attacks.

**Run:** one run, 60 s, started 2026-10-14T18:29:45Z, about 7 minutes after capture 007. The same board, radio and power-up
is an operator statement; there is no artifact for it.
Defaults were used: Stage-1 `configs/` and ML off. The detector configuration was unchanged.
```
.venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port COM7 --baud 115200 --out-dir artifacts/hardware/serial_ids_com7_001 --seconds 60 --no-reconnect
```
Exit code 0. Outputs are in `artifacts/hardware/serial_ids_com7_001/`: `summary.json`, `alerts.jsonl`, `health.jsonl` (5 records,
every 10 s) and `events.sqlite` (git-ignored, sha256 `8c24eba15247025b1bf5400344b04897b12874dffbe106226aeb23734dcae590`).

**Provenance:**
* Code: `HEAD` `6b21d1f` **plus uncommitted working-tree changes** in `src/aegisflight/{detectors/protocol.py, features/extractor.py,
  sources/mavlink_serial.py}` and `scripts/hardware/pixhawk_passive_probe.py`.
  * The sha256 of `git diff HEAD -- src scripts` is `8e95360e7c8674c4bbf4f81b1c2f6a7972f86c432af955084c16a90d92ee7d4a`. It was
    recorded *after* the run, and was unchanged at review, so it does not prove the code state at run time.
  * The diff shows LF endings; two of these files have CRLF in the working copy.
  * The uncommitted `protocol.py` / `extractor.py` changes produce alert #1's "never received" evidence text.
  * **No Stage-1 benchmark regression was run on this working tree.**
* Environment: Python 3.13.15, pymavlink 2.4.50, pyserial 3.5, Windows 11. These come from the probe-007 provenance (same
  venv); the runner records none of them, and the psutil version is not recorded.
* Config: `configs/detector.yaml` sha256 `bc9a4d2618e5e5a0cdc251a35f22ad1cc928343894aa9a66c27ad28196f3cbfa`, unmodified. No model was loaded.
* What `summary.json` itself lacks: a git commit and an environment tag (gap 6.4(b)).

| Check | Result (`summary.json`, `health.jsonl`) |
|---|---|
| Source identity | `port` COM7, `baud` 115200. 1,620 frames from 1/1. Not SIM and not SITL. |
| Framing | 46,026 B received, **1,620 frames**, 0 CRC rejects, 0 header rejects. **6 garbage bytes and 1 resync**, already present at the first 10 s health record and unchanged afterwards. This is consistent with the port opening mid-frame, but not proven. 0 disconnects, 0 dropped, 0 late ticks. |
| Message mix | **Not counted by the runner.** The frame total equals capture 007's, so the mix is very likely the same, but this run's per-message rates are not measured. |
| Pipeline | 601 ticks at 10 Hz produced **301 decisions** at 5 Hz. Decision latency: mean 0.1667 ms, p99 0.3759 ms, max 0.7105 ms. CPU 1.28 % of one core (laptop), RSS 55.5 MB. |
| Fusion | **297 of 301 decisions were threats**; 16 were alert decisions, all `DOS`. Only alerts are persisted, so the individual non-alert decisions (including the 4 non-threats) are not recorded (gap 6.4(b)). |
| Persistence | `events.sqlite` holds 16 events, ids 1–16, each with evidence, per-detector scores and a telemetry snapshot. `aegis verify-log` reports "chain: OK", and the runner's own check agrees (length 16). |
| Transmit | `bytes_sent` 0, `write_errors` 0. From the code: the runner and `LiveMavlinkSource` only `start()`, `poll()`, read `stats` and `close()` the transport. `send()` is never called, and the runner exits 3 if either counter is non-zero. |

**The alerts.** Every alert comes from `protocol_rule` alone. The other three detectors scored 0.0, and integrity is `UNKNOWN`.
* **#1, t = 0.0 s: start-up false alert.** The evidence reads "heartbeat stale (never received …) > 3.0s" and "GPS dropout:
  never received (no GLOBAL_POSITION_INT …) > 2.0s".
  * Cause: the first decision is made before any frame arrives, and `startup_grace_s` defaults to 0, which is Stage-1 behaviour.
  * The "> 3.0s" is the configured timeout, not a measured wait.
  * Score: protocol 1.0, fused **0.8824**, CRITICAL.
  * This is a monitor-start artefact (pending policy P1), not a link failure and not an attack.
* **#2 to #16, t = 1.4 s and then every 4.0–4.2 s: recurring no-fix alerts.** The evidence reads "GNSS fix lost: fix_type=0,
  satellites=0 for N decisions", with N running from 5 to 286 and never resetting.
  * Rule: fix type below 3 or fewer than 5 satellites for at least 5 consecutive decisions (`configs/detector.yaml`
    `min_gnss_fix_type`, `min_gnss_satellites`, `gnss_loss_ticks`).
  * Score: protocol 0.7. The fusion is a noisy-OR with max-normalised weights, and protocol's weight is 0.30 / 0.34 = 0.882,
    so the fused score is **0.6176**. That is SUSPICIOUS: above the 0.45 threat line and only 0.0024 below the 0.62 HIGH line,
    so a small weight change would make these alerts HIGH.
  * Spacing: the 4 s gaps are `cooldown_s`.
  * The persisted telemetry snapshot reads `satellites 0, lat/lon 0.0, battery_voltage 0.0, flight_mode STABILIZE, armed false`.
* **No GPS fix is not the same as missing GPS telemetry.** GPS telemetry arrived. After t = 0 there is no "never received"
  or GPS-dropout evidence, and the rule reports `fix_type` and `satellites` values, which only exist once GPS_RAW_INT has
  arrived. What is missing is the fix itself, as expected indoors. The rule still calls a fix that was never acquired "lost";
  this is policy P3 (6.5), now observed on hardware rather than only predicted. *(Wording since P3.4, 2026-10-15: a re-run on
  the current code would read "GNSS fix never acquired …" with the same score and timing; the alerts above are the historical
  output of the earlier code and are left as recorded.)*
* **Timestamps.** Decision time `t` counts from when the source's `stream()` began (`origin="start"`), on the host's monotonic
  clock. That is a few ms after `started_utc`; the `runs.started` row in the database (18:29:44.91Z) is earlier still.
  * In `events.sqlite`, `wall_time` is within 6.7 ms of `started_utc + t` across the 16 events.
  * In `alerts.jsonl`, `wall_utc` is within 11.2 ms, because it is stamped after the database insert
    (`run_serial_ids.py`). The flight controller's own timestamps
  (`time_boot_ms`) do not drive decision timing.

**Limitations of this run:**
* There is one run of 60 s (n = 1), so this gives no false-alarm rate.
* No attack was made, the vehicle did not fly, and it was disarmed and stationary.
* Message rates were not counted independently during the IDS run.
* The runner does not save its input bytes, so it cannot be replayed byte for byte. Capture 007 is a separate session.
* Opening COM7 with pyserial on Windows asserts DTR and RTS (flow control off). Any effect on the CP210x adapter or the radio
  was not measured, and the zero transmit counters do not rule it out.
* The firmware version was not recorded.
* ML is off, and the integrity detector is `UNKNOWN`.
* Whether a ground station was connected over USB during the run is not recorded (6.7).
* On this indoor bench, 297 of 301 decisions were threats. By inference these are almost all from the GNSS rule: the first
  decision or two came from the never-received rules, and non-alert decisions are not persisted. A judge-facing demo
  therefore needs the P1/P3 policy decisions first.
