# Serial MAVLink transport (Stage 2, hardware path step 7 - software only)

`aegisflight.sources.mavlink_serial.SerialMavlinkTransport` is a second implementation of the
existing `FrameTransport` seam (`poll()` / `close()`), beside `UdpMavlinkTransport`. It lets
`LiveMavlinkSource` -> `IDSPipeline` read MAVLink from a serial port instead of a UDP socket.
Nothing downstream changed: no detector, feature, fusion, pipeline, threshold, config or frozen
contract was touched.

**Status: unit-tested on virtual serial endpoints, plus (2026-10-10) one physical contact:** a
passive, receive-only read of a **Pixhawk 6X over USB-CDC (Windows COM5)** for 15 s and 180 s: 198
valid MAVLink-1 frames, 0 CRC/header/garbage errors, `bytes_sent = 0`, and a deliberate second open
of the same port failed fast with `PermissionError`
(`docs/HARDWARE_BENCH_PIXHAWK6X.md`, `artifacts/hardware/pixhawk6x_passive_probe_001.json`). It has
**not** been connected to a UART or a telemetry radio, its reconnect has not been exercised against
the real device, and the board streamed only HEARTBEAT/TIMESYNC (1 of the 6 messages the IDS reads),
so this adds a framing/transport observation, not a detection claim. ArduPilot SITL bytes were also
run through it over a loopback virtual port with a headless runner (`scripts/hardware/run_serial_ids.py`,
`artifacts/ardupilot/serial_path_replay_001/`).

## Usage
```python
from aegisflight.sources import LiveMavlinkSource, SerialMavlinkTransport

tr = SerialMavlinkTransport("COM5", baudrate=57600)      # or "/dev/ttyACM0"
src = LiveMavlinkSource(tr, sample_rate_hz=10.0)          # unchanged class
for tick in src.stream():                                 # same TelemetryTick contract
    ...                                                   # -> IDSPipeline.process_tick
print(tr.stats)                                           # transport health (see below)
```
Install the optional dependency with `pip install -e ".[serial]"` (`pyserial>=3.5`, pure Python,
no transitive dependencies; also part of `[dev]`). It is imported lazily: the core install and
every other module work without it.

**Port strings and pyserial URLs.** `port` is a device name. Anything containing `://` is a
pyserial URL and is refused with `ValueError` unless `allow_url=True`, and then only
`socket://` passes (`ALLOWED_URL_SCHEMES == {"socket"}`): a raw TCP client that sends nothing on
connect (a test checks this), so it stays passive. Everything else is always refused,
including `rfc2217://` (it sends Telnet option negotiation, i.e. baud/data-bit commands, to the
peer on open, which contradicts passive observation), `spy://` (writes a file), `alt://`,
`hwgrep://`, `loop://`, `file://` and unknown schemes. A plain device name is opened with
`serial.Serial` directly, so no URL handler can be imported for it. This matters if the port
ever comes from configuration. (With an injected `serial_factory` the port string is only a
label and is not checked.) The `socket://` tests pass `allow_url=True`. `max_read_bytes` must be
<= 65,536 (`MAX_READ_BYTES_LIMIT`; the default is 4,096, and a read never needs more than the
driver has buffered), which also bounds the framer's buffer.

The IDS is **passive** here: no GCS heartbeat is sent. `send(bytes)` writes raw bytes (for a
future relay upstream); heartbeats, signing and command helpers are not implemented. A flight
controller that needs a GCS heartbeat to stream (as PX4 SITL did) is not served by this class
alone.

## Framing (`MavlinkStreamFramer`)
A serial port is an unframed byte stream, so the transport recovers frames itself and queues
**one whole frame per item** (`(stamp_ns, frame_bytes)`), which `MavlinkFrameParser` then
decodes unchanged.
- Handles partial frames (waits), several frames per read, MAVLink 1 and 2, and signed frames
  (13-byte signature counted in the length).
- A magic byte (`0xFD`/`0xFE`) only *proposes* a frame. It is accepted only when complete and its
  X.25 CRC verifies against pymavlink's `crc_extra` (same dialect the parser uses). On failure ONE
  byte is dropped and scanning resumes, so real frames inside a false candidate are recovered.
- **Ids whose CRC cannot be verified are refused by default.** An id outside pymavlink's `all`
  dialect has no `crc_extra`, so the framer cannot tell a genuine frame from a corrupted one: a
  single bit flip in the message-id field of an ordinary frame yields exactly such an id, with a
  plausible header and a garbage payload (and a stray/inserted byte shifts the header so a
  phantom `sysid`/`compid` can reach the rogue-source logic). So such candidates are rejected
  (`unverifiable_rejects`, ids tallied in `unverifiable_ids`) and the scan resumes one byte on.
  - `extra_crc={msgid: crc_extra}` makes an id verifiable; it is then CRC-checked like a dialect
    id. Supply values taken from the definitions the flight controller was built with. Pass the
    same dict to `LiveMavlinkSource(..., extra_crc=...)` (additive, default `None`; also on
    `frame_ticks`) so the parser CRC-verifies those frames too instead of counting them as
    header-sanity-only `unverified_frames`.
  - `aegisflight.sources.mavlink_live.PX4_SITL_EXTRA_CRC` holds the seven values for the ids PX4
    SITL sends that pymavlink's dialect lacks. **Verified for PX4 `v1.18.0-rc1-27-gc239c63807`
    only** (the build recorded in `data/sitl/raw/benign_001.json`), from two local, authoritative
    sources that agree on all seven: (a) the `MAVLINK_MESSAGE_CRCS` tables in that build's
    generated headers, `build/px4_sitl_default/mavlink/{common,development}/*.h`; (b) `crc_extra`
    computed by pymavlink's `mavparse` from the PX4 tree's own XML,
    `src/modules/mavlink/mavlink/message_definitions/v1.0/` (mavlink submodule `f9cb1f9e`). Both
    were read-only. 8 `LINK_NODE_STATUS` = 117, 290 `ESC_INFO` = 251, 291 `ESC_STATUS` = 10,
    380 `TIME_ESTIMATE_TO_TARGET` = 232, 410 `EVENT` = 160, 411 `CURRENT_EVENT_SEQUENCE` = 106
    (all `common`); 514 `ESTIMATOR_SENSOR_FUSION_STATUS` = 197 (`development` dialect, which
    upstream may change). As a consistency check only, not as the source, all 413 such frames in
    the capture verify under these values. They are **not applied by default** and were **not
    verified against ArduPilot** (the physical Pixhawk 6X runs ArduPilot; its dialect and message
    set must be checked against its own definitions before reusing them).
  - `accept_unverified_ids=True` is an opt-in compatibility mode: header plausibility only (v2,
    compat 0, sysid and compid non-zero, msgid <= 0xFFFF; v1 never). **It verifies nothing**:
    a corrupted id on any frame survives as a plausible frame with a garbage payload
    (`unverified_accepted` counts these), and about 1 in 65k stray magic bytes can swallow real
    frames (estimated from the field widths, not measured). Off by default.
  - There is deliberately no search over the 256 possible `crc_extra` values: against a 16-bit
    CRC a match is a coincidence about 1 time in 65,536 per guess, not proof of integrity.
  - **Effect on real PX4 traffic (REPLAY of a SITL capture; framing and features only, no
    detection claim, no hardware):** all numbers are in
    `artifacts/sitl/serial_framer_replay_benign_001.json` (regenerate: `python
    scripts/sitl/serial_framer_replay.py data/sitl/raw/benign_001.tlog --json
    artifacts/sitl/serial_framer_replay_benign_001.json`; the tlog is local and git-ignored, its
    SHA-256 is recorded). The capture holds 35,067 frames, 413 with the seven out-of-dialect ids.
    - *Default policy:* emits exactly the 34,654 other frames, identical bytes in identical order
      (list equality against the capture, not a count), each re-verified with the reference CRC,
      `unverified_accepted == 0`. The 413 refused frames match the capture per id (8:93, 290:93,
      291:93, 380:46, 410:10, 411:31, 514:47); **433** unverifiable candidates were counted, of
      which 413 are those genuine frames and **20 are false candidates** met while rescanning
      inside them, plus 105 `crc_rejects` and ~17 kB `garbage_bytes` that are all false (the
      capture is uncorrupted). So on such a link `crc_rejects`/`garbage_bytes` are not pure
      link-quality indicators.
    - *Consequence for features (unchanged `IDSPipeline`, `configs/px4_sitl` profile,
      `models/isoforest_px4.joblib`, original per-frame timestamps kept):* the dropped frames
      punch holes in the per-source sequence numbers. 98 of 104 one-second windows (158 of 519
      decisions) show a sequence gap, against 2 of 104 (2 of 519) for the full capture; mean
      `loss_ratio` 0.0136 vs 0.0039. The ML score moved on 481 of 519 decisions by a mean
      absolute 5.5e-4 (max 3.1e-3); no ML-trigger crossing and no threat flag changed in this
      one benign capture. That is a measurement on one capture, not a statement about other flights, attacks or
      other models.
    - *With `PX4_SITL_EXTRA_CRC` (framer and parser):* all 35,067 frames, exactly the capture
      (bytes and order), zero unverifiable/crc/header rejects, and features and ML scores
      **identical** to the full-capture baseline (zero difference on every decision).
    - Not modelled: serial read-completion timestamps (frames keep their original capture
      stamps), baud-rate effects, and any real serial link. A replay does not show
      physical-hardware compatibility or detector correctness on a live link.
- A candidate that never completes (link idle for `partial_timeout_s`, default 1 s) is broken by
  dropping its first byte and rescanning (`partial_timeouts`).
- **CPU work is bounded, not real-time guaranteed.** Every failed candidate drops exactly one
  byte, so at most one candidate is evaluated per input byte, and one costs at most 265 CRC steps
  (v2 header + 255 payload bytes): a hard cap of 265 steps per input byte, counted in
  `crc_bytes_checked`. A candidate must have a CRC-verifiable id to reach the CRC at all, so
  out-of-dialect candidates cost 0 CRC steps (a test asserts this) and the random-garbage test
  asserts no more than 1 step per input byte. The CRC is table-driven (bit-identical to
  `mavlink_live._x25`, checked by a test). The densest shape found is a stream of all `0xFE`: a
  v1 candidate with a 254-byte payload starts at every byte and costs about **258 steps per
  input byte** (257.7 measured; a test asserts it lies in `(240, 265]`), which is why the cap is
  stated as 265. Sparser crafted streams cost less, e.g. a known id with a 255-byte payload
  restarting every 6 (v1) or 10 (v2) bytes costs about 43 and 26 steps per byte; those are
  illustrative, not worst cases. The tests assert counted CRC work, never wall-clock time;
  nothing here is a real-time or latency guarantee.
- **Scan cost is linear in the buffer.** The position of the next `0xFD`/`0xFE` is cached while
  the buffer is scanned, so each kind is searched for at most once per stretch of buffer. Before
  this, a buffer such as the repeating `00 FD 00 02` (a header-rejected `FD` after every garbage
  byte, no `0xFE` anywhere) rescanned to the end of the buffer for each garbage run: for one
  64 KiB read, `find()` examined 536,969,204 bytes (8,194x the buffer, 16,383 end-of-buffer
  misses) at `2297e14` against 114,682 (1.7x, 1 miss) now (one-off scratch comparison running
  the test's counting wrapper against `git show 2297e14:...`; not a committed artifact). A test
  counts exactly that
  (a work counter wrapped around `find()`, not a clock) and checks the pattern really takes the
  repeated-search branch. A large single read of valid mixed v1/v2/signed frames with a split
  tail is also tested.
- Memory: after any call fewer than 280 bytes are retained; garbage is discarded, never stored.
  The output queue is bounded by count (`queue_size`) and bytes (`max_queue_bytes`); overflow
  drops the newest frame and is counted.

## Timestamps
The stamp is `clock_ns()` (default `time.monotonic_ns`, the same clock `LiveMavlinkSource` uses)
read right after the `read()` that **resolved** the frame returned, i.e. the read after which the
framer could first emit it. Normally that is the read that delivered the frame's last byte, but a
valid frame queued behind a still-incomplete false candidate is held until that candidate
resolves (more bytes arrive, or the stale-partial flush fires), so it can be stamped later than
its last byte arrived: by up to the time to receive the false candidate's remaining bytes (at
most 280) or `partial_timeout_s`. A test pins this behaviour. The stamp is host-side time, not
wire time: it includes baud-rate serialisation of the frame, driver/USB buffering and read
latency. Frames resolved by one `read()` share one stamp, so burst spacing inside a read is lost
(`max_frames_per_read` shows how many). Per-byte-offset stamping was not implemented. Rate- and
jitter-based features computed from these stamps are therefore not comparable to SITL/UDP
numbers, and the PX4 SITL calibration profile should not be assumed to transfer (see
`docs/CALIBRATION_PX4.md`).

## Health counters (`transport.stats`)
All are measured at this transport. **None measures loss below the driver** (UART FIFO overruns,
USB drops, radio loss before `read()` returned the bytes); there is deliberately no such counter.

| Counter | Meaning |
|---|---|
| `bytes_received`, `reads` | bytes / `read()` calls that returned data |
| `frames_received` (`datagrams_received`) | whole frames produced (name kept for UDP parity) |
| `garbage_bytes`, `resync_events` | bytes discarded for any reason while hunting a frame start (includes the bytes of refused candidates, not only line noise); garbage runs |
| `header_rejects` | candidates refused on the header alone (unknown incompat flags) |
| `crc_rejects` | complete candidates of a CRC-verifiable id (dialect or `extra_crc`) whose CRC did not match: a corrupted frame or a false magic byte |
| `unverifiable_rejects` | complete candidates whose id has no `crc_extra`, refused. Either a genuine out-of-dialect message or a corrupted id field; the framer cannot tell which |
| `unverifiable_ids` (`unverifiable_id_overflow`) | msgid -> count for those candidates (at most 64 distinct ids tracked; the rest only counted) |
| `unverified_accepted` | frames accepted with NO CRC check (`accept_unverified_ids=True` only; 0 otherwise) |
| `crc_bytes_checked` | CRC steps spent confirming candidates: a work measure, not an error count |
| `partial_timeouts` | stalled candidates broken after the idle timeout |
| `reader_faults`, `reader_running` | unexpected exceptions in the reader loop (software, not link); whether the reader thread is alive |
| `dropped_overflow(_bytes)`, `queue_high_water`, `max_poll_gap_s` | same meaning as the UDP transport |
| `max_frames_per_read` | largest burst completed by one read |
| `connected`, `disconnects`, `reconnects`, `open_failures`, `last_error` | port state |
| `discarded_on_disconnect_bytes` | partial-frame bytes thrown away at a disconnect |
| `bytes_sent`, `write_errors` | `send()` accounting |

## Reconnect and shutdown
- `start()`: with `reconnect=True` (default) an unopenable port is retried every
  `reconnect_interval_s`, so the IDS may start before the controller is plugged in; with
  `reconnect=False` it raises `RuntimeError`.
- Any `read()` failure (cable pulled, `socket://` peer closed, device reset) closes the port,
  discards the partial frame, counts a disconnect and reopens.
- While disconnected `poll()` returns nothing, so `LiveMavlinkSource` emits empty ticks and the
  detectors see **silence** (heartbeat-stale / dropout evidence). They cannot tell host-side port
  loss from link loss; read `connected` / `disconnects` / `last_error` for that.
- An unexpected exception inside the reader (for example a framing bug) is a software fault, not
  a link event, but it takes the same path: the port is closed, `connected` goes False,
  `reader_faults` and `disconnects` are bumped (`disconnects` counts every port close, faults
  included), the cause is recorded in `last_error` ("reader fault: ..."), the partial frame is
  discarded and the normal reconnect policy applies (retry every `reconnect_interval_s`, or stay
  down with `reconnect=False`, where the thread ends and `reader_running` is False). A
  persistent fault therefore repeats at most once per reconnect interval; it cannot spin. If the
  fault handler itself fails, the thread ends, the port is closed in a `finally`, and
  `last_error` says "unrecoverable". Shutdown stays prompt and idempotent in every case.
- `reconnect_interval_s`, `partial_timeout_s` and `read_timeout_s` must be finite and > 0
  (`ValueError` otherwise).
- `close()` is idempotent, stops the reader within one read timeout (also while waiting to
  reconnect), closes the port and drains the queue. `start()` after `close()` is a no-op.

## Tests (`tests/unit/test_mavlink_serial.py`)
- Pure framer tests: fragmentation, bursts, v1/v2/signed, garbage, false magic bytes, CRC and
  flag failures, unknown ids (refused by default, `extra_crc`, opt-in mode), random chunking
  invariance, fuzz with a memory bound, hand-off to the unchanged parser.
- Corruption regressions: every single-bit flip of the 24 message-id bits of a v2 frame (and of
  the 8 v1 bits), a byte inserted at every offset inside a frame (values 0x00/0x01/0xFD/0xFE/0xFF),
  nine malformed candidate headers, and a seeded bit-flip/insert/delete campaign. Each checks that
  nothing is emitted that was not sent, that the neighbouring frames survive, and (via the
  unchanged `MavlinkFrameParser`) that no phantom `(sysid, compid)` appears. The campaign is
  seeded and therefore a regression test, not a proof (a 16-bit CRC still admits ~1 false accept
  in 65k corrupted known-id candidates).
- Work bounds: table CRC bit-identical to `_x25`; the all-`0xFE` stream and dense v1/v2 streams
  stay under the 265-steps-per-byte cap; out-of-dialect candidates cost 0 CRC steps; bounded
  diagnostics; the alternating `00 FD 00 02` buffer is scanned in linear work (find-call counter).
- The seven PX4 ids: one genuine frame per id (real bytes from the benign capture) is refused by
  default and accepted with `PX4_SITL_EXTRA_CRC`; every single-bit flip of each of those frames
  (all header, payload and CRC bits) is rejected while the following frame survives; a wrong
  `crc_extra` is rejected; `extra_crc` never overrides a dialect id; the dict passes through
  `frame_ticks`, the parser and `LiveMavlinkSource` (parser stops counting them as
  `unverified_frames` and CRC-verifies them).
- Transport tests over a scripted fake port: stamps (including the held-behind-a-false-candidate
  case), counters, stale partial, overflow and byte budget, open failure, reconnect cycles,
  `reconnect=False`, prompt shutdown, `send()`, argument validation, the pyserial URL policy, and
  reader-thread faults (a `framer.feed()` that raises, with and without reconnect, repeated
  faults, and a failing fault handler).
- `LiveMavlinkSource` driven end to end over the transport.
- Real pyserial over a `socket://` virtual port (loopback TCP server playing the device): works
  on every OS, including Windows.
- Real pyserial over a PTY pair: POSIX only, **skipped on Windows** (no `pty` module). A
  Windows-only run therefore does not exercise a termios tty. After the latest changes the file
  was run again on Linux (WSL Ubuntu-24.04, Python 3.12.3, pyserial 3.5) through a throwaway
  harness that stubbed only the heavy `aegisflight.sources.stream` import: the 3 PTY tests
  passed, and so did 157 of the file's 160 tests (the 3 failures are the tests that build a
  real `TelemetryTick` - the `LiveMavlinkSource` and `frame_ticks` ones - which the harness
  stubs out; they pass on Windows). That harness is not committed, so this result is a one-off
  observation, not something CI reproduces. To repeat it natively:
  `pytest tests/unit/test_mavlink_serial.py` on any Linux/macOS checkout with `.[dev]` installed
  (not done here: the repo is deliberately not installed inside WSL).

## Not done / not claimed
- Hardware coverage is **one passive USB-CDC contact on one board** (Windows): real UART baud
  rates, flow control, port permissions (`dialout` on Linux), the write path, USB re-enumeration
  and the reconnect path against a real device are unverified.
- The verified `PX4_SITL_EXTRA_CRC` table covers PX4 SITL `v1.18.0-rc1-27-gc239c63807` only and
  is off by default. For other firmware, ids outside pymavlink's dialect have no verified values
  here; with the default policy those frames are refused (about 1.2% of the PX4 SITL capture),
  which punches sequence gaps into the per-source counters (98 of 104 one-second windows in the
  replay above). **Observed for ArduPilot (not a guarantee):** every id seen was inside pymavlink's
  `all` dialect (0 `unverifiable_rejects` in 198 BENCH frames; 0 `unverified_frames` in 8 ArduCopter 4.7.1
  SITL captures), so the PX4 table is not needed there; a different message set could differ. Derive the
  values from the firmware's own definitions, or recalibrate on a capture taken through the same path,
  before relying on sequence-gap/loss features over serial for any id outside the dialect.
- The feature effect was measured on one benign SITL capture through the replay path with the
  original timestamps; serial read-completion stamps, real baud rates and other models/flights
  were not measured.
- No per-byte-offset timestamps (see Timestamps); no kernel/driver loss counter.
- No `aegis` CLI sub-command, config key or dashboard wiring; use the Python API or the standalone receive-only runner
  `scripts/hardware/run_serial_ids.py` (untested on a real device beyond the passive probe; see `docs/ONBOARD_DEPLOYMENT.md`).
- No auto-baud, no MAVLink-router integration, no serial proxy/relay upstream.
- No calibration for a real link's message rates; no attack was run over serial.
