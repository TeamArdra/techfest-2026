# Serial MAVLink transport (Stage 2, hardware path step 7 - software only)

`aegisflight.sources.mavlink_serial.SerialMavlinkTransport` is a second implementation of the
existing `FrameTransport` seam (`poll()` / `close()`), beside `UdpMavlinkTransport`. It lets
`LiveMavlinkSource` -> `IDSPipeline` read MAVLink from a serial port instead of a UDP socket.
Nothing downstream changed: no detector, feature, fusion, pipeline, threshold, config or frozen
contract was touched.

**Status: unit-tested on virtual serial endpoints. It has never been connected to a physical
flight controller, a USB-CDC device, a UART or a telemetry radio.** No evidence run was made with
it, so it adds no validation claim; it removes a software prerequisite for one.

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
pyserial URL and is refused with `ValueError` unless `allow_url=True`, and then only the schemes
in `ALLOWED_URL_SCHEMES` (`socket`, `rfc2217`) pass; `spy://` (which writes a file), `alt://`,
`hwgrep://`, `loop://`, `file://` and unknown schemes are always refused. A plain device name is
opened with `serial.Serial` directly, so no URL handler can be imported for it. This matters if
the port ever comes from configuration. (With an injected `serial_factory` the port string is
only a label and is not checked.) The `socket://` tests pass `allow_url=True`.

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
    id. Supply values taken from the definitions the flight controller was built with.
  - `accept_unverified_ids=True` is an opt-in compatibility mode: header plausibility only (v2,
    compat 0, sysid and compid non-zero, msgid <= 0xFFFF; v1 never). **It verifies nothing**:
    a corrupted id on any frame survives as a plausible frame with a garbage payload
    (`unverified_accepted` counts these), and about 1 in 65k stray magic bytes can swallow real
    frames (estimated from the field widths, not measured). Off by default.
  - There is deliberately no search over the 256 possible `crc_extra` values: against a 16-bit
    CRC a match is a coincidence about 1 time in 65,536 per guess, not proof of integrity.
  - **Cost on real PX4 traffic (REPLAY of a SITL capture, framing only; no detection claim):**
    in `artifacts/sitl/serial_framer_replay_benign_001.json` (regenerate:
    `python scripts/sitl/serial_framer_replay.py data/sitl/raw/benign_001.tlog --json
    artifacts/sitl/serial_framer_replay_benign_001.json`; the tlog itself is local and
    git-ignored) the capture holds 35,067 frames, 413 of them with ids outside the dialect (8,
    290, 291, 380, 410, 411, 514). The default policy emits exactly the other 34,654;
    `accept_unverified_ids=True` emits all 35,067. The refused frames are not invalid, only
    unverifiable here. Their `crc_extra` could not be derived from the XML bundled with pymavlink
    (those ids are absent), so no verified `extra_crc` table is shipped; take the values from the
    definitions the flight controller was built with. Rescanning inside the refused frames also
    produced 105 `crc_rejects` and ~17 kB of `garbage_bytes` in that file, so on such a link
    those two counters are not pure link-quality indicators.
- A candidate that never completes (link idle for `partial_timeout_s`, default 1 s) is broken by
  dropping its first byte and rescanning (`partial_timeouts`).
- **CPU work is bounded, not real-time guaranteed.** Every failed candidate drops exactly one
  byte, so at most one candidate is evaluated per input byte, and one costs at most 265 CRC steps
  (v2 header + 255 payload bytes): a hard cap of 265 steps per input byte, counted in
  `crc_bytes_checked`. A candidate must have a CRC-verifiable id to reach the CRC at all, so
  out-of-dialect candidates cost 0 CRC steps (a test asserts this) and the random-garbage test
  asserts no more than 1 step per input byte. The CRC is table-driven (bit-identical to
  `mavlink_live._x25`, checked by a test). The worst shapes tried, a known id with a 255-byte
  payload restarting every 6 (v1) or 10 (v2) bytes, cost about 43 and 26 steps per byte
  (deterministic counters, asserted as `> 20` / `> 15` so the tests really are adversarial). The
  tests assert counted work, not wall-clock time; there is no real-time guarantee.
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
- Work bounds: table CRC bit-identical to `_x25`; dense adversarial v1/v2 streams stay under the
  265-steps-per-byte cap; out-of-dialect candidates cost 0 CRC steps; bounded diagnostics.
- Transport tests over a scripted fake port: stamps (including the held-behind-a-false-candidate
  case), counters, stale partial, overflow and byte budget, open failure, reconnect cycles,
  `reconnect=False`, prompt shutdown, `send()`, argument validation, the pyserial URL policy, and
  reader-thread faults (a `framer.feed()` that raises, with and without reconnect, repeated
  faults, and a failing fault handler).
- `LiveMavlinkSource` driven end to end over the transport.
- Real pyserial over a `socket://` virtual port (loopback TCP server playing the device): works
  on every OS, including Windows.
- Real pyserial over a PTY pair: POSIX only, **skipped on Windows** (no `pty` module). A
  Windows-only run therefore does not exercise a termios tty. After the M1/M2/L1 hardening the
  file was run again on Linux (WSL Ubuntu-24.04, Python 3.12.3, pyserial 3.5) through a
  throwaway harness that stubbed only the heavy `aegisflight.sources.stream` import: the 3 PTY
  tests passed, and so did 134 of the file's 135 tests (the one failure is the
  `LiveMavlinkSource` test, which needs the real `TelemetryTick` the harness stubs out; it
  passes on Windows). That harness is not committed, so this result is a one-off observation,
  not something CI reproduces. To repeat it natively:
  `pytest tests/unit/test_mavlink_serial.py` on any Linux/macOS checkout with `.[dev]` installed
  (not done here: the repo is deliberately not installed inside WSL).

## Not done / not claimed
- Never run against hardware: real baud rates, USB-CDC enumeration, COM-port naming, flow
  control, port permissions (`dialout` on Linux) and the write path against a real device are
  unverified.
- No verified `extra_crc` table for the ids PX4 sends outside pymavlink's dialect; with the
  default policy those frames (about 1.2% of the SITL capture above) are not presented, so
  message-rate features derived from this transport undercount them. Decide per link.
- No per-byte-offset timestamps (see Timestamps); no kernel/driver loss counter.
- No CLI entry point, config key or dashboard wiring; use the Python API.
- No auto-baud, no MAVLink-router integration, no serial proxy/relay upstream.
- No calibration for a real link's message rates; no attack was run over serial.
