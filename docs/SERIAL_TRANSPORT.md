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

tr = SerialMavlinkTransport("COM5", baudrate=57600)      # or "/dev/ttyACM0", or a pyserial URL
src = LiveMavlinkSource(tr, sample_rate_hz=10.0)          # unchanged class
for tick in src.stream():                                 # same TelemetryTick contract
    ...                                                   # -> IDSPipeline.process_tick
print(tr.stats)                                           # transport health (see below)
```
Install the optional dependency with `pip install -e ".[serial]"` (`pyserial>=3.5`, pure Python,
no transitive dependencies; also part of `[dev]`). It is imported lazily: the core install and
every other module work without it.

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
- Ids outside the dialect cannot be CRC-checked; they are accepted on header plausibility only
  (v2, compat 0, sysid and compid non-zero, msgid <= 0xFFFF) unless `extra_crc={msgid: crc_extra}`
  is supplied. **Residual hazard:** about 1 in 65k stray magic bytes can still produce a false
  unknown-id frame that swallows the real frames inside it (estimated from the field widths, not
  measured).
- A candidate that never completes (link idle for `partial_timeout_s`, default 1 s) is broken by
  dropping its first byte and rescanning (`partial_timeouts`).
- Memory: after any call fewer than 280 bytes are retained; garbage is discarded, never stored.
  The output queue is bounded by count (`queue_size`) and bytes (`max_queue_bytes`); overflow
  drops the newest frame and is counted.

## Timestamps
The stamp is `clock_ns()` (default `time.monotonic_ns`, the same clock `LiveMavlinkSource` uses)
read right after the `read()` that completed the frame returned. It is host-side time, not wire
time: it includes baud-rate serialisation of the frame, driver/USB buffering and read latency.
Frames completed by one `read()` share one stamp, so burst spacing inside a read is lost
(`max_frames_per_read` shows how many). A frame completed by a stale-partial flush is stamped at
the flush. Rate- and jitter-based features computed from these stamps are therefore not
comparable to SITL/UDP numbers, and the PX4 SITL calibration profile should not be assumed to
transfer (see `docs/CALIBRATION_PX4.md`).

## Health counters (`transport.stats`)
All are measured at this transport. **None measures loss below the driver** (UART FIFO overruns,
USB drops, radio loss before `read()` returned the bytes); there is deliberately no such counter.

| Counter | Meaning |
|---|---|
| `bytes_received`, `reads` | bytes / `read()` calls that returned data |
| `frames_received` (`datagrams_received`) | whole frames produced (name kept for UDP parity) |
| `garbage_bytes`, `resync_events` | bytes discarded while hunting a frame start; garbage runs |
| `crc_rejects` | complete candidates that failed CRC/plausibility |
| `partial_timeouts` | stalled candidates broken after the idle timeout |
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
- `close()` is idempotent, stops the reader within one read timeout (also while waiting to
  reconnect), closes the port and drains the queue. `start()` after `close()` is a no-op.

## Tests (`tests/unit/test_mavlink_serial.py`)
- Pure framer tests: fragmentation, bursts, v1/v2/signed, garbage, false magic bytes, CRC and
  flag failures, unknown ids, `extra_crc`, random chunking invariance, fuzz with a memory bound,
  hand-off to the unchanged parser.
- Transport tests over a scripted fake port: stamps, counters, stale partial, overflow and byte
  budget, open failure, reconnect cycles, `reconnect=False`, prompt shutdown, `send()`.
- `LiveMavlinkSource` driven end to end over the transport.
- Real pyserial over a `socket://` virtual port (loopback TCP server playing the device): works
  on every OS, including Windows.
- Real pyserial over a PTY pair: POSIX only, **skipped on Windows** (no `pty` module). A
  Windows-only run therefore does not exercise a termios tty. The 3 PTY tests were run once on
  Linux (WSL Ubuntu-24.04, Python 3.12.3, pyserial 3.5) through a throwaway harness that stubbed
  only the heavy `aegisflight.sources.stream` import: 3 passed. That harness is not committed,
  so this result is a one-off observation, not something CI reproduces. To repeat it natively:
  `pytest tests/unit/test_mavlink_serial.py` on any Linux/macOS checkout with `.[dev]` installed
  (not done here: the repo is deliberately not installed inside WSL).

## Not done / not claimed
- Never run against hardware: real baud rates, USB-CDC enumeration, COM-port naming, flow
  control, port permissions (`dialout` on Linux) and the write path against a real device are
  unverified.
- No CLI entry point, config key or dashboard wiring; use the Python API.
- No auto-baud, no MAVLink-router integration, no serial proxy/relay upstream.
- No calibration for a real link's message rates; no attack was run over serial.
