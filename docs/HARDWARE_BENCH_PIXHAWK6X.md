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

*Re-audited 2026-10-16 (read-only, source inspection; nothing run against the dashboard):* (c) and (d) are unchanged.
`backend/engine.py` builds only `SimulatedTelemetrySource`; `/health` and `/` return a hard-coded `"sim": True`; `/api/events`
reads the engine's own store (default `artifacts/aegisflight_live.sqlite`), never a runner's `events.sqlite`; the frontend lists
"Live UDP / serial MAVLink source" under *planned*. **The dashboard is simulation-only: physical telemetry and the runner's persisted
events are not surfaced in it, and no source label distinguishes SIM / SITL / BENCH.** For (b), the runner now writes
`telemetry_coverage` (heartbeat / GLOBAL_POSITION_INT / GPS_RAW_INT ever seen, decisions without position) to `summary.json` and
every `health.jsonl` line (tested on `socket://`, not on hardware); tlog saving, `decisions.jsonl` and a `BENCH` tag are still
missing. Smallest next task for the operator interface: step 4 below (read-only `--follow <run-dir>` backend mode with a
`source` field), then step 5. Not attempted here: it spans backend + frontend and is a new feature, not a narrow fix.*

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
  *(Decided 2026-10-15, user decision "Coverage, not attack"; implemented, not yet committed; Stage-1 regression: §6.9. **P1:** with the
  new default `protocol.require_global_position: false`, a link that has never delivered GLOBAL_POSITION_INT is a coverage
  condition -- protocol score 0, no vote, not a threat or alert -- reported in every assessment as "coverage: GLOBAL_POSITION_INT
  never received (...)"; `true` restores the DOS outcome and the `never_seen_gps_*` knobs. A never-received heartbeat / required
  position stream is now judged on elapsed monitoring time, so the monitor-start alert at t=0 no longer occurs; no heartbeat for
  > 3 s since monitoring began is still a DOS alert. Loss after a stream was seen is unchanged. **P2:** GPS_RAW_INT presence is
  reported (`FeatureFrame.gps_raw_seen`, named in the coverage line) but is still not position presence and does not satisfy
  `require_global_position`. The 0.5 never-seen floor guarantees detector-level evidence, not a fused alert. P3 scoring stays
  open. No live bench re-run against this change; offline REPLAY of captures 005/007: `artifacts/hardware/replay_p1p2_{005,007}/`
  and §6.9.)*
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
  *(Correction 2026-10-20: capture 007 shows `fix_type` 0 = `GPS_FIX_TYPE_NO_GPS` ("No GPS connected"), not 1 = `NO_FIX`; see
  §6.9. The board reported **no GPS receiver**, so "no fix indoors" is an unverified explanation. The rule treats 0 and 1 alike.)*
* The documented "never silently accepted" floor for never-seen GPS does not hold at the fused level (strict xfail).
  *(Superseded 2026-10-15/16, P1: the docs now say the floor guarantees detector-level evidence, not a fused alert; the xfail
  is replaced by `test_floor_guarantees_detector_level_evidence_not_a_fused_alert`.)*
* On ArduCopter the GPS-vs-baro altitude check compares two views of one AHRS altitude (S6), so physics silence on the
  bench says nothing about detector correctness.
* ML is off for ArduPilot, and the integrity detector reports `UNKNOWN` (no verifier). Nothing in this section is detection
  evidence. The COM7 captures are not yet in `docs/VALIDATION_EVIDENCE.md`, and this section has not had an `aegis-reviewer` pass.
  *(Superseded 2026-10-14: the §1c rows were added for 6.7 and 6.8, and those were reviewed.)*
* Hardware-free tests, 2026-10-14: `.venv/Scripts/python.exe -m pytest tests/unit/test_run_serial_ids.py tests/unit/test_missing_telemetry.py
  tests/unit/test_missing_telemetry_fused.py tests/unit/test_serial_raw_tap.py tests/unit/test_mavlink_serial.py
  tests/unit/test_mavlink_live.py backend/tests/test_api.py -p no:cacheprovider -o addopts="" -q` → **281 passed, 3 skipped**
  (Windows PTY), **2 xfailed**. *(After P3.4, 2026-10-15: the full suite gives 604 passed, 3 skipped, 1 xfailed; the P1 floor
  xfail remains.)* *(After P1/P2, 2026-10-16, uncommitted tree: 663 passed, 3 skipped, 0 xfailed.)* *(2026-10-20, closure
  sprint tree: 688 passed, 3 skipped, 0 xfailed; §6.9.)*

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
    *(P1 decided 2026-10-15, §6.5: never-received streams are now judged on elapsed monitoring time, so the current code would
    not raise this t = 0 alert; the alert above is the historical artifact's.)*
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
  arrived. What is missing is the fix itself, as expected indoors *(correction 2026-10-20: the capture-007 GPS_RAW_INT frames
  report `fix_type` 0 = `GPS_FIX_TYPE_NO_GPS` and the SYS_STATUS GPS sensor bits are clear, i.e. the board reported no GPS
  receiver, not a receiver without a fix; "as expected indoors" is unverified. This run saved no input bytes; its snapshot,
  `fix_type=0, satellites=0`, is consistent. See §6.9)*. The rule still calls a fix that was never acquired "lost";
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
  therefore needs the P1/P3 policy decisions first. *(2026-10-16: P1/P2 were decided 2026-10-15 (§6.5); P3 wording is fixed, P3 scoring is
  still open, so an indoor no-fix bench still alerts every ~4 s on "GNSS fix never acquired".)* *(2026-10-20: on this board
  the condition is "no GPS receiver reported" (`fix_type` 0), which the GNSS rule does not distinguish from "no fix"; §6.9.)*

### 6.9 Telemetry closure sprint (2026-10-20): GNSS fact, status, supervised validation procedure
**Environment of everything in this section: offline only.** No serial port was opened, the board was not touched, and no
parameter or radio setting was read or changed.

**GNSS fact from capture 007 (offline, `data/hardware/raw/telemetry_radio_007.tlog`, sha256 `0a701331…e17a`; pymavlink
one-off, cross-checked by two agents):** all 120 `GPS_RAW_INT` frames have `fix_type` 0, which is MAVLink `GPS_FIX_TYPE_NO_GPS`
("No GPS connected"; `NO_FIX`, "GPS is connected", is 1). They also have `satellites_visible` 0, `eph` 65535 and
`time_usec` 0. All 120 `GLOBAL_POSITION_INT` frames have lat = lon = 0. All 120 `SYS_STATUS` frames have the GPS sensor bit
clear in *present*, *enabled* and *health*. **So the board reported no GPS receiver.** Earlier text calling this "no fix
indoors" was an unverified explanation; it is corrected where it appears. Whether a GNSS module was attached or configured
(`GPS_TYPE`) was not recorded. Two consequences:
* `gps_seen` = True on this link means the position *message* arrives, not that a position exists (S6).
* The GNSS rule treats `fix_type` 0 and 1 alike, so the "GNSS fix never acquired" alerts in replay 007 come from a missing
  receiver. The receiver was not jammed or unable to see the sky.

**Sprint changes (uncommitted, on `83f07c1` + the P1/P2 tree):**
* `detectors/physics.py`: the GPS/VFR speed rule is skipped when `GLOBAL_POSITION_INT` was never received
  (`gps_seen is False`). Before this, a moving vehicle on a position-less link raised `TELEMETRY_MANIPULATION`, which
  contradicted "Coverage, not attack".
* `detectors/protocol.py`: the coverage line is now the last protocol evidence item, so it never heads another rule's
  alert.
* Docs and comments corrected; tests added (`docs/DETECTION.md`, `docs/THREAT_MODEL.md`, `docs/VALIDATION_EVIDENCE.md`).
* Runner: docstring corrected, and `telemetry_coverage` is now also printed on the console.

No threshold, config default or fusion weight changed. The one behaviour change is the speed-rule gate, which
removes that rule's `TELEMETRY_MANIPULATION` vote/score only when `gps_seen` is False.

**Fresh results, 2026-10-20** (`SIM` / `REPLAY`; scratch outputs, not committed; `src`+`configs` diff sha256 `708192a0…0ad6`):
* Full suite `pytest -p no:cacheprovider`: **688 passed, 3 skipped (Windows PTY), 0 failed, 0 xfailed**.
* `ruff check src tests scripts backend`: clean (scratch log `ruff_20261020.txt`; re-run by aegis-reviewer).
* Reference hashes for this tree: `git diff HEAD -- src configs | sha256sum` = `708192a0…0ad6` (used throughout this
  section), and `git diff HEAD -- src configs scripts | sha256sum` = `cd109aae…71f6` (the step-5 recipe below).
* Stage-1 `aegis benchmark --out <scratch> --no-figures`: **6535 / 4 / 16826 / 65**, non-timing `results.csv` identical.
* Replays 005/007 (`replay_ap_tlog.py --no-ml`): byte-identical to `artifacts/hardware/replay_p1p2_{005,007}/replay_noml.json`.
* The speed gate changes 0 of 194,628 ALFA replay decisions.
* Loopback dry run of the runner: below.

**Verdicts (lead):**
* Telemetry core: **READY FOR SUPERVISED PHYSICAL VALIDATION**, not `PHYSICALLY CLOSED`. The procedure below has not been
  run on this tree.
* Operator-facing live telemetry: **NOT INTEGRATED**. The dashboard is simulation-only (§6.4, re-checked 2026-10-20:
  `src/aegisflight/backend/engine.py` builds only `SimulatedTelemetrySource`; `/health`, `/` and `/api/status` hard-code `"sim": True`;
  `/api/events` returns the engine's in-memory alert deque).
* GNSS never-acquired scoring (P3): **open, user decision**.

**Supervised physical validation: procedure for a person at the bench (not run; Claude must not run it).**
*What it can establish:* that the current tree's start-up and coverage behaviour holds on the physical COM7 link. That
covers four things: no "never received" alert in the first 3 s when monitoring starts at port open; `telemetry_coverage` in
`summary.json` / `health.jsonl` matching the messages that arrive; receive-only (`bytes_sent` 0); and a byte-exact input
capture for offline replay. *What it cannot establish:* GPS fix behaviour (needs a connected GNSS receiver with sky view),
attack detection (no attack is made), a false-alarm rate (n = 1), or anything about flight.
*Duration:* 60 s per step. That matches every earlier COM7 capture and run (005–007, `serial_ids_com7_001`); it is not a
statistical choice.

0. **Setup.** Use the same physical arrangement as §6.7/§6.8: Pixhawk 6X disarmed, no propellers, telemetry radio on TELEM1,
   laptop-side radio on USB. Do not change any parameter or radio setting, and do not use Mission Planner *Write Params*.
   **During steps 3, 4 and 7, no ground station may be connected on any port, USB included.** A connected GCS transmits to
   the board, ArduPilot may forward its traffic onto TELEM1 (not verified on this board), and a GCS HEARTBEAT would count as
   heartbeat presence (presence is not source-checked), confounding the coverage result. Record the UTC time, how the board
   is powered, and whether a GNSS module is physically attached (look; do not infer). The firmware version may be read
   in a GCS over USB **before step 3 or after step 4** (read-only; then disconnect the GCS).
1. **Identify the port without opening it.** In PowerShell: `Get-PnpDevice -Class Ports -PresentOnly | Format-Table
   FriendlyName, InstanceId` lists devices from the OS without opening them. The laptop-side radio was a "Silicon Labs
   CP210x" on COM7; use whatever COM number it shows now. The board's own USB port is a different device (COM5 before): do
   not open it. If the CP210x is absent or ambiguous, stop.
2. **Baud.** Use `--baud 115200`. Its provenance is empirical, not a read configuration. At 115200, captures 005–007 were
   CRC-valid and byte-exact with 0 garbage bytes; at 57600, capture 001 got 964 B of garbage and 0 frames. The radio's own
   serial setting has never been read, and `SERIAL1_BAUD=115` is a user report (F6). Step 3 re-checks the rate: frames > 0,
   0 CRC rejects and ≈ 0 garbage bytes confirm it. If not, stop. Do not sweep baud rates and do not reconfigure the radio.
3. **Receive-only capture (input for replay).** Check that the three paths do not exist (`Test-Path`). `--tlog` and `--json`
   overwrite without asking (`pixhawk_passive_probe.py` opens `--tlog` with `"wb"`); only `--raw` refuses.
   ```
   .venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM7 --baud 115200 --duration 60 --json artifacts/hardware/telemetry_radio_probe_008.json --tlog data/hardware/raw/telemetry_radio_008.tlog --raw data/hardware/raw/telemetry_radio_008.rawbin
   ```
   Pass: `bytes_sent` 0, frames > 0, 0 CRC rejects, and the same six pipeline messages as 007 at similar rates (§6.7 table).
4. **IDS run on the current tree.** The output directory must not exist; the runner refuses to reuse a run's files.
   ```
   .venv/Scripts/python.exe scripts/hardware/run_serial_ids.py --port COM7 --baud 115200 --out-dir artifacts/hardware/serial_ids_com7_002 --seconds 60 --no-reconnect
   ```
   `--no-reconnect` matters: without it, a busy or unopenable port does not fail. It produces "heartbeat never received"
   alerts after 3.2 s instead. The console prints `telemetry_coverage`, `passive_check` and `hash_chain`.
   Then run `.venv/Scripts/aegis.exe verify-log artifacts/hardware/serial_ids_com7_002/events.sqlite`.
5. **Record the code state.** In Git Bash: `git rev-parse HEAD`, `git diff HEAD -- src configs | sha256sum` and
   `git diff HEAD -- src configs scripts | sha256sum`. For this sprint's tree they are `83f07c1`, `708192a0…0ad6` and
   `cd109aae…71f6`; any difference means a different tree was tested.
   Hash each new input file with `Get-FileHash -Algorithm SHA256` (the tlog and rawbin are git-ignored).
6. **Offline replay of step 3 (no hardware).**
   `.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_008.tlog --no-ml --json <scratch>/replay_008.json`
   Its GNSS evidence text names `fix_type` (0 = no receiver reported, 1 = receiver without fix).
7. *Optional, only if comfortable:* power the board off by normal power removal, keep the laptop-side radio plugged in, and
   run step 4 with a new `--out-dir` (`serial_ids_com7_003`) and `--seconds 10`. This shows a never-received heartbeat on
   hardware. Expected from the code, tests and the loopback dry run below: no alert before t = 3.0 s, then "heartbeat
   stale (never received …)" `DOS` from the first decision after 3.0 s (t = 3.2 s, then 7.2 s; dry run: 51 decisions, 35
   threats, 2 alerts). The coverage line is on each saved alert; non-alert decisions are not saved. Expect
   `decisions_without_global_position` = `decisions` and `link_ever_delivered_frames` false.

**Expected, step 4.** These are predictions from the code and from replay 007, not results. Exit 0;
`passive_check.passed` true; `hash_chain.ok` true; 0 CRC rejects (a few garbage bytes and 1 resync at port open, as in
run 001, are tolerable); about 300 decisions (run 001 had 301). `telemetry_coverage` shows
`heartbeat_seen`, `global_position_seen` and `gps_raw_seen` all true. `decisions_without_global_position` counts the
decisions before the first `GLOBAL_POSITION_INT` frame, about the first frame's arrival time / 0.2 s: 0 if frames flow at
port open, a few if they start later. `alerts.jsonl` has **no** "never received" alert in the first 3 s. If `GPS_RAW_INT`
again reports `fix_type` 0, there are "GNSS fix never acquired" `DOS` alerts, the first about 1 s after the first
`GPS_RAW_INT` and then every 4.0–4.2 s (`cooldown_s`). Replay 007 had 15 in 60 s, first at t = 1 s; run 001 started at
t = 1.4 s. These are expected false alarms under the open P3 policy, not attacks.

**Loopback dry run of steps 4 and 7 (2026-10-20, aegis-px4-mavlink).** Environment: `REPLAY` of `BENCH` captures 005/007
through the live serial runner (`origin="start"`), over `socket://127.0.0.1` (`--allow-url`). Not hardware: no baud,
driver, UART or DTR/RTS. Not detection evidence. Outputs, tools and regeneration notes are in
`artifacts/hardware/loopback_dryrun_20261020/` (untracked; `README.md`). Code: this sprint's tree (`src`+`configs` diff
sha256 `708192a0…0ad6`).

| Run | Result |
|---|---|
| 007 via `virtual_serial_replay.py` | 301 decisions, 296 threats; 15 `DOS` "GNSS fix never acquired" alerts at t = 1.0 + 4k s, the same as replay 007 |
| 007, first frame delayed to +1.5 s after connect (`tools/delayed_replay.py`) | 301 decisions, 289 threats; 15 alerts, first at t = 2.4 s; no "never received" alert; `decisions_without_global_position` 8 |
| 005 (HEARTBEAT only), immediate and delayed | 0 alerts each; coverage T/F/F, 301 of 301 decisions without position |
| no frames, 10 s | 51 decisions, 35 threats; 2 alerts at t = 3.2 and 7.2 s, "heartbeat stale (never received …)" |

In every run: exit 0, `passive_check.passed` true, `aegis verify-log` chain OK, and `telemetry_coverage` printed on the
console. In the 005 run `disconnects` was 1 because the replay tool closes its socket at ~59.5 s, before the 60 s deadline.
That is the tool, not the code, so keep `--seconds` below the capture span in any loopback dry run. This dry run
exercises the "monitor starts before the first frame" path that the in-process replays cannot. It still does **not**
replace the physical run.

**Stop conditions:**
* exit 3, or `bytes_sent` / `write_errors` > 0;
* exit 4, or `hash_chain.ok` false, or `aegis verify-log` not OK (keep the files untouched for inspection);
* exit 2 because the port could not be opened (close the other program; do not retry in a loop);
* frames 0, or CRC rejects / garbage bytes still growing after the first seconds (baud/wiring; do not sweep or reconfigure);
* the USB device disappears or `disconnects` > 0;
* the board arms, changes mode or behaves in any way the operator does not expect (unplug the laptop-side radio; do not
  interpret LEDs or tones);
* any alert other than the one expected for that step. In step 4 that is only "GNSS fix never acquired" `DOS`. In step 7
  it is only "heartbeat stale (never received …)" `DOS`, and only after t = 3.0 s.

If you see an unexpected source id, record it; do not conclude an attack. The presence rules accept any sysid. A radio that
injects `RADIO_STATUS` (often sysid 51) would raise a rogue-source `MAVLINK_ANOMALY`. None was seen in 005–007, which had no
GCS on the link.
In every case, keep the output directory and the console text.

**Side effect not measured:** opening the port with pyserial asserts DTR and RTS. `mavlink_serial.py` sets only
`rtscts`/`xonxoff` False, and no option holds the lines low. The effect on the CP210x or radio is unmeasured; zero transmit
counters do not rule it out. Earlier opens (005–007, run 001) showed no observed problem, which is not proof.

**Preserve:** `artifacts/hardware/telemetry_radio_probe_008.json`; `data/hardware/raw/telemetry_radio_008.{tlog,rawbin}`
(git-ignored; keep, with their sha256); `artifacts/hardware/serial_ids_com7_002/` (and `_003/`) including the git-ignored
`events.sqlite`; the console output; the step-0 notes.
**Verdicts it can give:** *telemetry-ingestion PASS* when steps 3–4 meet the pass and expected rows above. It is **not** a GPS
validation (no receiver reported, or no sky view) and **not** attack detection. The `PHYSICALLY CLOSED` verdict for telemetry
core requires this pass on the tree it ran (record the hash).

### 6.10 GNSS receiver connected: GPS connectivity sprint (2026-10-25)
**Environment `BENCH`; claim class none.** This section describes the receiver's reports and the IDS's behaviour on them. No attack
was made, nothing was injected into the board, and the vehicle was disarmed and stationary. It is **not** GPS spoofing
detection evidence. The §6.9 procedure was followed, with these deviations:
* Capture 008 hit two §6.9 stop conditions: the port was busy, then the device disappeared. The session resumed after the
  operator re-plugged the radio, and 009 is the clean capture.
* The §6.9 step-4 expectations ("GNSS fix never acquired" alerts) assumed no receiver, so they do not apply here.

**Setup and provenance.**
* *Operator statement (no artifact):* a GNSS receiver is connected, and Mission Planner showed a 3D fix.
* *Board:* ArduPilot (`autopilot` 3), QUADROTOR, sysid/compid 1/1, MAVLink 1, unsigned, STANDBY, disarmed, `custom_mode` 0.
  **The firmware version was not determined:** no `AUTOPILOT_VERSION` or `STATUSTEXT` arrived, and requesting one would need a
  transmit.
* *Port:* the only serial device Windows listed was the CP210x radio on **COM7** (`Get-PnpDevice -Class Ports -PresentOnly`).
  The board's own USB port (COM5 before) was not enumerated. The baud was **115200** (§6.9 step 2), confirmed by 0 CRC rejects.
* *Code:* `HEAD` `75dc7a6` for every hardware run below, with `src` and `configs` unchanged and the tracked scripts unmodified.
  `git diff HEAD -- src configs | sha256sum` gives `e3b0c442…b855`, the hash of an empty diff. Python 3.13.15, pymavlink 2.4.50, pyserial 3.5, Windows 11 (probe provenance).
  Stage-1 `configs/`, ML off.
* *Mission Planner held COM7 at first:* at 16:55:05Z the probe could not open COM7 (`PermissionError(13)`, exit 2, nothing sent).
  The operator then disconnected Mission Planner, which stayed running but unconnected.
  * Because Mission Planner had been connected over COM7 during this power-up, its RAM-only stream request (S2) very likely still
    applied.
  * The stream now also carries the RAW_SENS, RC_CHAN and EXTRA3 groups (`EKF_STATUS_REPORT`, `SYSTEM_TIME`, `RC_CHANNELS`,
    `VIBRATION` …), at about 57 frames/s against 27 in capture 007. So **these rates are probably not the stored `SR1_*`
    alone** (compare §6.7).
  * That inference assumes the stored values have not changed since capture 007; they were not re-read.
  * 008 and 009 are from one boot (the host-minus-`time_boot_ms` offset is identical), so no reboot cleared a RAM request
    between them.

| Run (UTC) | Command (all receive-only) | Result |
|---|---|---|
| Capture **008**, 16:56:12Z, 90 s requested | `pixhawk_passive_probe.py --port COM7 --baud 115200 --duration 90 --json artifacts/hardware/telemetry_radio_probe_008.json --tlog …/telemetry_radio_008.tlog --raw …/telemetry_radio_008.rawbin` | **62.3 s** of stream, then COM7 **vanished from Windows** (1 disconnect, 27 open failures). The operator then re-plugged it and reports having "moved things" (unspecified). 3,562 frames, 105,804 B; 0 CRC/header rejects, 0 garbage bytes, 0 sequence gaps (also per `scripts/sitl/tlog_stats.py`); `bytes_sent` 0. sha256: tlog `c8774324…eb9b`, rawbin `d545485b…597f` (both git-ignored) |
| IDS run **`serial_ids_com7_002`**, 17:10:12Z, 60 s | §6.9 step 4 command with `--out-dir artifacts/hardware/serial_ids_com7_002` | Exit 0. 3,420 frames, 0 CRC rejects, 0 garbage, 0 disconnects. **301 decisions, 0 threats, 0 alerts.** `telemetry_coverage`: all three seen, `decisions_without_global_position` 1. `bytes_sent` 0. `aegis verify-log`: chain OK (0 events). Latency mean 0.30 ms, p99 0.62 ms; CPU 2.21 % of one core; RSS 55.4 MB. `events.sqlite` sha256 `0a9ce9c7…1162` (git-ignored). The runner saves no input bytes, so the GNSS state during this run is **not recorded**; capture 009 followed it |
| Capture **009**, 17:15:13Z, 60 s | as 008 with `--duration 60` and `_009` paths | 59.8 s, 3,418 frames, 0 errors, 0 gaps, `bytes_sent` 0. sha256: tlog `e6926675…c867`, rawbin `1144070b…bed2` (git-ignored) |
| Dashboard backend, 17:17:00Z, about 125 s | `aegis serve --source serial --serial-port COM7 --baud 115200 --no-reconnect --port 8766 --db <scratch>` (binds 127.0.0.1) | See "Dashboard" below. 7,117 frames, 211,394 B, 0 CRC rejects, 33 garbage bytes (all at port open), 0 disconnects, `bytes_sent` 0. *Session record (console and API output); there is no committed artifact. Only the event store survives, git-ignored.* |

**GNSS state** (`scripts/hardware/gnss_tlog_summary.py` → `artifacts/hardware/gnss_summary_00{8,9}.json`; positions only as metres
from the first fix):

| | 008 (62 s) | 009 (60 s) |
|---|---|---|
| `GPS_RAW_INT.fix_type` | 3D 61, DGPS 16, 2D 36, NO_FIX 12 (of 125) | 3D 33, DGPS 87 (of 120) |
| Valid per the GNSS rule (fix ≥ 3 and ≥ 5 satellites) | 68/125: the first ~34 s, then 3D with 4 satellites → 2D with 3 → NO_FIX with 0 | 120/120 |
| Satellites / HDOP (median) | 0–7 (5) / 3.57–99.99 (5.54) | 6–7 (6) / 2.8–4.9 (4.9) |
| Raw position offset from the first fix, max / altitude range | 21.6 m / 40.3 m | 7.2 m / 8.0 m |
| `GPS_RAW_INT.vel` max | 3.24 m/s | 0.41 m/s |
| `GLOBAL_POSITION_INT` vx/vy speed max vs speed implied by its successive positions | 0.108 vs **17.75** m/s | 0.02 vs 1.41 m/s |
| `GPS_RAW_INT` vs `GLOBAL_POSITION_INT` horizontal | median 0 m (max 15.3 m) | 0 m in every pair |
| `SYS_STATUS` GPS present / enabled / healthy | 125 / 125 / **0** | 120 / 120 / **0** |
| `EKF_STATUS_REPORT.flags` | `0xa7` in all: constant-position mode, **no absolute horizontal position** | same |
| `time_usec` / `time_boot_ms` | non-zero and monotonic; no `lat = lon = 0` | same |

What this shows, and what it does not:
* **A receiver is now attached and reported.** In capture 007 the board reported none (`fix_type` 0, GPS sensor bits clear; §6.9).
* **A 3D fix is confirmed, but not as a steady state.** 009 held 3D/DGPS throughout. 008 lost it after ~34 s; the cause was not
  recorded. COM7 vanished at ~62 s, and the operator later reported re-plugging it and moving things, at an unspecified time. In pymavlink 2.4.50, `GPS_FIX_TYPE` 0 means NO_GPS, 1 NO_FIX, 2 2D, 3 3D and 4 DGPS.
* **GPS messages reach the laptop fresh:** `GPS_RAW_INT` arrives about every 0.5 s on the host clock (max 0.52 s), and
  `time_usec` increases.
* **The EKF was not using GPS for horizontal position.**
  * The GPS health bit was 0, and the EKF flags (`0xa7`) show constant-position mode with neither absolute nor relative
    horizontal position.
  * Why was not established. It is consistent with the weak geometry (HDOP ~5), but no parameter or pre-arm message was read.
  * On this board `GLOBAL_POSITION_INT` repeats the receiver's position while the fix is valid (in 008 the two were up to
    15.3 m apart after the fix degraded), while its velocity is the EKF's zero.
  * So the two messages are **not independent position sources**, and position and velocity are **not one coherent navigation
    solution**.
* **A 3D fix, the satellite count or the DOP says nothing about whether the coordinates are authentic.**

**IDS behaviour on this receiver** (Stage-1 configs, ML off, unchanged code):
* *Replay 008* (`artifacts/hardware/replay_gnss_008/replay_noml.json`): 313 decisions, 146 threats, **9 alerts**.
  * 7 `DOS` "GNSS fix lost …". This is correct: a valid fix was seen and then degraded. The streak never reset because the fix
    did not return.
  * 1 `GPS_SPOOFING`, "position residual 12.1 m" at 33.4 s, as the fix degraded.
  * 1 `TELEMETRY_MANIPULATION` at 43.8 s: "GPS/baro altitude mismatch 19.2 m" and "implausible altitude rate −96.0 m/s".
    * The autopilot's own altitude stepped −19.2 m. `VFR_HUD` showed the step at 43.72 s and `GLOBAL_POSITION_INT` at 44.01 s.
    * The mismatch is the 0.29 s skew between two views of one AHRS altitude (S6), not two independent sensors.
    * The rate alert is that altitude itself stepping 19.2 m within one 0.2 s decision.
  * The alert and step times come from an offline tlog analysis; they are not stored in `replay_noml.json`.
* *Replay 009* (`artifacts/hardware/replay_gnss_009/replay_noml.json`): 300 decisions, **0 threats, 0 alerts**. This agrees with
  the live run `serial_ids_com7_002` (0 alerts), a separate session about 4 min earlier.
* *Dashboard session:* **11 `GPS_SPOOFING` alerts** in the first ~56 s (3 CRITICAL, 1 HIGH, 7 SUSPICIOUS), none afterwards.
  * They fired at t = 12.2 … 52.8 s with "position residual" 12.8–42.4 m.
  * The stored alert snapshots show 5–6 satellites, but `fix_type` is not stored per alert.
  * `/api/status`, sampled once, showed 3D, 5 satellites and `valid_fix: true`. Whether the fix stayed valid at every alert is
    not recorded.
* **Finding: position-residual false alarms on a stationary board (operator statement) with a reported-valid but weak fix.**
  * The rule assumes that position and velocity come from one coherent navigation solution, and it is not gated on GNSS
    quality.
  * Here the position is raw GNSS wander and the velocity is the EKF's zero, so the wander reads as a track diverging from
    its velocity.
  * The code behaves as specified: the rule's assumption simply does not hold in ArduCopter's constant-position mode.
  * It was **not changed.** A GNSS-quality gate is a detector-policy decision, and a spoofer can report good DOP.
  * The mechanism is illustrated by a synthetic fixture whose amplitude was chosen, not fitted to the bench data:
    `tests/unit/test_gps_scenarios_fused.py::test_stationary_gnss_wander_with_a_valid_fix_raises_false_gps_spoofing_alerts`.

**Dashboard** (the live session above; read through the API and the rendered page text, with no screenshot so no map position
was captured):
* `/health` reports `sim: false, environment: BENCH`.
* `/api/status` reports `source.kind: serial` on COM7/115200, `physical: true`, link `live`, per-message counts and ages, and a
  `gps` block (`fix_type` 3 `3D_FIX`, 5 satellites, `valid_fix: true`, `gps_raw_age_s` 0.0, `position_age_s` 0.1,
  `position_zero: false`).
* `POST /api/simulation/attack` and `/start` return **HTTP 409**, "simulation-only; the source is BENCH (read-only)".
* The page title reads "(BENCH)". The header shows "GPS report · 7 sats · valid fix", and the panels are labelled "bench
  telemetry · not flight data".
* The incident history lists the same **11** events as `/api/events` and the event store. `aegis verify-log` on the store gives
  11 events, chain OK.
* The store is kept locally, git-ignored because its telemetry snapshots hold the position, at
  `artifacts/hardware/serve_bench_com7_001/events.sqlite` (sha256 `df379f88…87b8`).
* `aegis serve` saves no input bytes, so this session cannot be replayed.
* The "distance covered" panel showed 196 m for a board that, per the operator, never moved; that number is GNSS wander.

**Receive-only:**
* `bytes_sent` 0 and `write_errors` 0 in every capture, the IDS run and the dashboard session.
* On the serial path, `send()` exists only on the transport and is never called. The other `send` callers are SITL/UDP-only:
  the UDP transport's heartbeat and signing helpers in `sources/mavlink_live.py`, and the MITM proxy in `proxy/transport.py`.
  None is reachable from the serial path.
* The DTR/RTS side effect at port open is still unmeasured (§6.9).

**Not established:**
* the firmware version;
* which stream rates come from stored `SR1_*` and which from Mission Planner's RAM request;
* what the operator changed during 008, and why COM7 disappeared;
* why the GPS health bit was 0;
* the sky view;
* any false-alarm *rate* (a few minutes of one board);
* anything about attack detection. Synthetic GPS scenarios are SIM evidence: `docs/VALIDATION_EVIDENCE.md` §2.

**Regression for this change set** (no `src`/`configs` change; tests, one offline script and docs only; scratch outputs, not
committed):
* `pytest -p no:cacheprovider` on the final tree: **746 passed, 3 skipped (Windows PTY), 0 failed**. This includes the 17 tests
  in `test_gps_scenarios_fused.py`.
* `ruff check src tests scripts backend`: clean.
* `aegis benchmark --out <scratch> --no-figures`: TP/FP/TN/FN **6535 / 4 / 16826 / 65**, model used. All 42 rows × 9
  non-timing columns of `results.csv` and the per-attack table are identical to `artifacts/benchmarks/`.
* Replays 005/007 are byte-identical to `artifacts/hardware/replay_p1p2_00{5,7}/replay_noml.json`.
* ALFA was not re-run: there is no detector or feature change.

**Regenerate** (offline, from the git-ignored tlogs):
`.venv/Scripts/python.exe scripts/hardware/gnss_tlog_summary.py data/hardware/raw/telemetry_radio_00N.tlog --json artifacts/hardware/gnss_summary_00N.json`
and `.venv/Scripts/python.exe -W ignore scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/telemetry_radio_00N.tlog --no-ml --json artifacts/hardware/replay_gnss_00N/replay_noml.json`.

**Update 2026-10-26: estimator gate v2 (GPS iteration 2).** This is an addition. The 2026-10-25 text above, including
"It was **not changed**", describes the code at `75dc7a6` and stays as written.
* **What changed.** The position-residual rule now reads ArduPilot's `EKF_STATUS_REPORT.flags`
  (`physics.estimator_gate: true`).
  * A `GLOBAL_POSITION_INT` fix is *gated* when fresh reports have said "no horizontal solution" for at least 2 s. A
    gated fix's position-vs-velocity residual is not used as spoofing evidence.
  * Movement the velocity implies but the position does not show, and a single residual step of 30 m or more, still
    alert.
  * Without any `EKF_STATUS_REPORT`, the Stage-1 rule is unchanged.
  * Design and limitations: `docs/DETECTION.md`, "Estimator-aware position residual".
  * Status: uncommitted on `90b9aa2`, `src`+`configs` diff sha256 `b4d434e3…7eaf`. Reading the report extends a frozen
    contract; the user confirmed this on 2026-10-26 (`docs/HANDOFF.md`).
* **What the bench captures show** (`REPLAY` of `BENCH`; claim class none; ML off; **in-sample**, because the gate was
  designed from these two captures):
  * Both captures report no horizontal solution in every `EKF_STATUS_REPORT`: 125 and 120 reports, matching the `0xa7`
    flags above.
  * *Replay 008* (`artifacts/hardware/replay_gnss_008_estimator_gate/`): **`GPS_SPOOFING` 1 → 0**. The 7 `DOS` "GNSS
    fix lost" alerts and the 1 `TELEMETRY_MANIPULATION` altitude-step alert remain: 9 → 8 alerts, 146 → 138 threats, of
    313 decisions. 7 of the 8 alert decisions also carry a score-0 "navigation: estimator reports no horizontal position
    solution …" line.
  * *Replay 009* (`artifacts/hardware/replay_gnss_009_estimator_gate/`): 0 threats, as before. The output is
    byte-identical to `replay_gnss_009/replay_noml.json`.
  * Both READMEs give the provenance. One caveat applies to both: the JSON label `config_dir: "configs (Stage-1
    default)"` is hard-coded by the replay script and is inaccurate for this tree.
* **What it does not show.**
  * Whether the gate would clear the dashboard session's 11 `GPS_SPOOFING` alerts. That session saved no input bytes
    and no EKF flags, so this is **unknown**.
  * Any false-alarm *rate*. n = 1 alert was removed, on the design data.
  * Behaviour on links that send no `EKF_STATUS_REPORT`, or send it at under 0.5 Hz. The Stage-1 rule, and so this
    false alarm, apply there.
  * The first 2 s of a no-solution period: the debounce leaves them to the Stage-1 rule.
  * ML-on behaviour. The ML detector is not gated, and with ML on it still flags wander through `ml_anomaly` (SIM).
  * Anything about attacks. `EKF_STATUS_REPORT` is unauthenticated, so an in-path attacker who forges or injects it gains
    the capabilities listed in `docs/DETECTION.md` (SIM evidence only). Only MAVLink-2 signing closes that.
* **Regression on the same tree:** `artifacts/validation/estimator_gate_v2/README.md`.
  * Stage-1 benchmark identical (6535 / 4 / 16826 / 65).
  * ALFA changes only in the unlabelled category: physics trigger rate and attack-type labels change, threat rates do
    not.
  * 44 of 44 earlier replays (none containing `EKF_STATUS_REPORT`) byte-identical, including 005/007.
  * Full test suite: 809 passed, 3 skipped (lead, 2026-10-26).
