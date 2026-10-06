# PX4 SITL integration (Stage 2, P1)

What was observed on a **real PX4 SITL MAVLink stream**, how the live source consumes it,
and what is *not* yet handled. Environment tag for everything here: **SITL**
(PX4 `v1.18.0-rc1-27-gc239c63807`, a release candidate - not a stable tag; Gazebo Harmonic `8.15.0`,
model `gz_x500`, headless). All numbers are in `artifacts/sitl/P1_summary.md` and the JSON beside it
(regenerate: `scripts/sitl/make_p1_summary.py`). Commands: `docs/STAGE2_RUNBOOK.md`.

## 1. Endpoints and link behaviour (read from PX4 source + observed)
| Link | PX4 local UDP | PX4 remote | Mode | Notes |
|---|---|---|---|---|
| GCS | `18570 + instance` | `14550` | normal | streams telemetry to the learned partner |
| Offboard / API | `14580 + instance` | `14540 + instance` | onboard | command path |
| Payload / gimbal | `14280` / `13030` (+instance) | | onboard / gimbal | not used |

- A UDP link **locks to the first datagram sender (IP and source port) once either 3 s have passed since the link
  started or the default partner is localhost, and never re-learns** (`src/modules/mavlink/mavlink_receiver.cpp`
  ~L3809-3830; `_src_addr_initialized` is only ever assigned `true`; the `-t`/`-c` options pre-initialise it). A
  host-initiated "hello" is the least invasive way in; **restart SITL after any probe**. Whether `PX4_NET_INTERFACE`
  unset means no broadcast lives in the rc scripts (`px4-rc.mavlink`), not in the module; we did not need it.
- WSL2 NAT works in both directions for UDP (Windows -> WSL IP and back). The WSL IP is discovered with
  `wsl -d Ubuntu-24.04 -- hostname -I`, never hard-coded. No `.wslconfig` / mirrored-networking change was required.
- Arming needs a GCS heartbeat (`Preflight Fail: No connection to the GCS` otherwise): the live transport and the
  recorder both send a 1 Hz GCS heartbeat.
- `-f` forwarding: a GCS heartbeat sent on the offboard link is **forwarded** onto the GCS link. Two clients that share
  sysid/compid 255/190 therefore alias each other; the flight driver takes `--sysid` to use a distinct id.

## 2. Stream identity and rates (artifacts/sitl/benign_00N_stream_stats.json)
- Vehicle sysid `3` (instance+1), compid `1`; HEARTBEAT `type=2` (quadrotor), `autopilot=12` (PX4), MAVLink 2
  (`0xFD`), **unsigned**. A rare MAVLink 1 frame can appear only as forwarded traffic from another client.
- GCS link carries ~35 message types at ~326-338 frames/s (`frames/s` column in `P1_summary.md`): seven streams at ~45 Hz in wall time (nominally 50 Hz in PX4 time; 43 Hz in the slowest capture)
  (GLOBAL_POSITION_INT, ATTITUDE, ATTITUDE_QUATERNION, LOCAL_POSITION_NED, POSITION_TARGET_LOCAL_NED,
  ATTITUDE_TARGET, SERVO_OUTPUT_RAW), GPS_RAW_INT / VFR_HUD at ~4.5 / ~3.6 Hz, and ~1 Hz housekeeping
  (HEARTBEAT, SYS_STATUS, ...). The Stage-1 simulator emits six message types at far lower rates.
- Several ids are outside pymavlink's `common` dialect (8, 290, 291, 380, 410, 411, 514, ...). They are parsed by
  header and kept as `MSG_<id>` envelopes with empty `fields`.
- **SITL time is not wall time.** Per-capture `boot_clock_vs_recv_drift_ppm` (time_boot_ms vs receive clock) shows the
  vehicle clock running ~10-13% slow; nominal 50 Hz streams arrive at ~45 Hz. Gazebo's real-time factor was observed
  differing per capture. **Mean RTF over each capture = 1 + `boot_clock_vs_recv_drift_ppm`/1e6** (0.87-0.90 in the five
  P1 captures; four at 0.898-0.900, benign_002 an outlier at 0.867) - `artifacts/sitl/P1_summary.md`. Ad-hoc `gz topic`
  samples showed the instantaneous factor varying with host load but are not an artifact and are not quoted as a result.
  **Any rate-based feature scales with host load**; record the drift with every capture and never compare absolute
  rates across hosts unqualified.
- Sequence numbers are per link. Over 5 benign flights **net missing = 0 and duplicates = 0** (unique sequence numbers
  equal the span, `seq_net_missing` in the stats JSON); one flight had two brief out-of-order events (depth 2), which
  also produce the "forward gaps" column. These are single-host loopback-like WSL2 conditions, not a radio link. The Stage-1 extractor reads a backward step as a 253-frame gap (see section 6).

## 3. PX4 flight-mode semantics (do not treat as ArduCopter)
`HEARTBEAT.custom_mode = (main_mode << 16) | (sub_mode << 24)` (`px4_custom_mode.h`).
Main: 1 MANUAL, 2 ALTCTL, 3 POSCTL, **4 AUTO**, 5 ACRO, 6 OFFBOARD, 7 STABILIZED, 8 RATTITUDE.
AUTO sub: 1 READY, 2 TAKEOFF, **3 LOITER (hold)**, 4 MISSION, 5 RTL, 6 LAND, ...
`aegisflight.sources.mavlink_live.decode_px4_mode` implements this. The frozen Stage-1 codec/extractor
(`MODE_NAMES`) still maps ArduCopter integers, so PX4 modes are labelled `UNKNOWN` by the unchanged extractor - a
known gap, not hidden (section 6). Observed benign sequence: AUTO/LOITER -> AUTO/TAKEOFF -> AUTO/LOITER -> AUTO/LAND
-> AUTO/LOITER (`mode_transitions` in each stats JSON).

## 4. Live source (`src/aegisflight/sources/mavlink_live.py`)
Additive module; `SimulatedTelemetrySource`, the tlog adapter and the benchmark path are untouched.
- `MavlinkFrameParser` - **header-first** decode: sysid/compid/seq/msgid/signed/length come from the raw header
  (v1 and v2); fields only when the id is in pymavlink's `all` dialect; never raises; bad frames are counted.
- `UdpMavlinkTransport` - `connect=(host,port)` (GCS role, heartbeat) or `bind=(host,port)` (loopback by default,
  wildcard refused unless `allow_wildcard=True`); receive thread -> bounded queue; 4 MiB SO_RCVBUF; counters.
- `LiveMavlinkSource.stream()` - **clock-driven** ticks (`TelemetryTick` unchanged); `frame_ticks()` is the same
  assembler fed from any iterable (used by tests and offline replay).

### Tick semantics
| Aspect | Behaviour |
|---|---|
| Tick duration | `dt = 1/sample_rate_hz` (10 Hz -> 0.1 s); pipeline decides every 2nd tick (5 Hz), unchanged |
| Accumulation | tick *k* (`t = k*dt`) carries every frame received in `((k-1)dt, k*dt]`; integer-microsecond maths, a frame exactly on a boundary belongs to the tick that closes there (same as `tlog_ticks`) |
| Origin | `first_frame` (default; reproduces `segments()+tlog_ticks`) or `start` (dead link still ticks) |
| Silence | ticks keep being emitted with empty `messages` (a dropped/DoS link must still be visible) |
| Slow consumer | missed ticks are emitted back-to-back, never skipped; counted in `late_ticks` |
| Late / out-of-order | frame arriving after its tick closed goes to the next open tick (`late_frames`); arrival order and sequence numbers are preserved untouched |
| Missing / dropped | not synthesised; they appear as absent frames / sequence gaps for the extractor |
| Ground truth | live ticks carry **no** truth (`label=BENIGN` default); only an explicit `label_fn` can set one |

## 5. Validation of the path (SITL, benign, attack NONE)
- Unit tests: `tests/unit/test_mavlink_live.py` (synthetic frames; no PX4 needed).
- Live UDP against PX4 SITL: `scripts/sitl/live_ids.py` -> `artifacts/sitl/live_run_002.*`; the raw frames the IDS saw
  were teed to a tlog and re-run offline; `scripts/sitl/compare_live_offline.py` writes a **per-decision** comparison
  (`live_run_002_equivalence.json`). It shows the clock-driven loop + tee reproduce the offline assembly; it is **not** an
  independent decode check (shared assembler/parser), and agreement on the threat flag is weak while every decision is an
  alarm. The IDS is an *active* link partner (it sends the GCS heartbeat), not a passive tap. An earlier run
  (`live_run_001`) was contaminated by an aliased 255/190 driver and is superseded.
- Live decision latency in that run was measured while other jobs shared the host; it is load-dependent and is **not**
  a benchmark figure (Stage-1 latency numbers come from `aegis benchmark`).

## 6. Known gaps carried to P3 (calibration) - evidence, not excuses
Unchanged Stage-1 detectors flag **every** benign PX4 SITL decision (see `P1_summary.md`). Causes **consistent with**
the evidence strings in `benign_replay_stage1_default_liveparser.json` (attribution from strings, **not an ablation**;
other strings also occur, e.g. "heartbeat stale" and "battery voltage rose"):
1. Message-rate baseline: the configured `nominal_msg_rate_hz: 28` (`configs/detector.yaml`, a configured constant, not a
   measured simulator rate) vs ~338 msg/s observed = ~12x; spike factor 3.
2. Expected vehicle sysid is 1; PX4 SITL is 3 -> "rogue telemetry source".
3. Command-source rule: PX4 itself emits `COMMAND_LONG` toward the GCS and is flagged as an unexpected source.
4. Sequence reorder -> 253-gap artifact (`max_seq_gap`, `loss_ratio`), and `max_seq_gap` is sticky.
5. PX4 modes read as `UNKNOWN` (Stage-1 `MODE_NAMES`).
6. ML anomaly saturates (out of training distribution on rate features).
7. Physics detector triggers on a small fraction of benign decisions (investigate per-feature in P3).
None of this is an attack result and none of it changes Stage-1 SIM results.

## 7. Not done / not claimed
- No attack of any kind has been injected yet (P2). No claim of PX4 attack detection.
- No MAVLink signing (P4); `signed` is the header flag only.
- Single airframe (`gz_x500`), single world, single host; host-load dependent timing. 5 flights of one scripted route
  (autocorrelated decisions): not 2760 independent samples.
- Unknown-id frames (not in pymavlink's dialect) cannot be CRC-verified; they are link statistics only (hardening in progress).
- Evidence is regenerable only with the local raw tlogs (git-ignored, SHA-256 in each manifest's `provenance`); manifests
  from before the provenance step are marked `backfilled` (describe the repo at backfill time, not capture time).
