"""Serial MAVLink transport for ``LiveMavlinkSource`` (Stage-2 hardware path, step 7).

:class:`SerialMavlinkTransport` is a second implementation of the existing
:class:`~aegisflight.sources.mavlink_live.FrameTransport` seam (``poll()`` / ``close()``),
next to :class:`~aegisflight.sources.mavlink_live.UdpMavlinkTransport`. Nothing downstream
changes: ``LiveMavlinkSource`` -> ``IDSPipeline`` consume ``(recv_ns, bytes)`` pairs exactly as
before. Status: unit-tested with virtual serial endpoints only. It has **never been run
against a physical flight controller** (see ``docs/SERIAL_TRANSPORT.md``).

What differs from UDP
---------------------
UDP delivers whole datagrams; a serial port delivers an unframed byte stream. Frame
boundaries therefore have to be recovered here, by :class:`MavlinkStreamFramer`:

* **Header-first, then CRC-confirmed.** A magic byte (``0xFD`` / ``0xFE``) only *proposes* a
  frame. The length comes from the header (signature included), and a candidate is accepted
  only if it is complete AND its X.25 CRC verifies (``crc_extra`` from pymavlink's dialect,
  the same one :class:`MavlinkFrameParser` uses). If it fails, ONE byte is dropped and the scan
  restarts, so real frames hiding inside a false candidate are recovered instead of being
  swallowed. Ids outside the dialect have no known ``crc_extra``; they are accepted on header
  plausibility alone (MAVLink 2, compat flags 0, sysid/compid != 0, msgid <= 0xFFFF), the
  parser's "unverified" trust level with a stricter filter. Residual hazard (~1 in 65k per
  stray magic byte): a false unknown-id candidate can still swallow the real frames inside it.
  Pass ``extra_crc`` to make an id verifiable.
* **One queue item per frame.** ``poll()`` returns ``(stamp_ns, one_whole_frame)``, so the
  parser sees clean frames and every frame has its own stamp.

Timestamps (what the number does and does not mean)
---------------------------------------------------
The stamp is ``clock_ns()`` read immediately after the ``read()`` that **completed** the frame
returned. It is host-side, not wire time. It includes the baud-rate serialisation time of the
frame, OS/USB driver buffering, and read latency. Frames completed by one ``read()`` share one
stamp, so a burst's inter-frame spacing is lost (``max_frames_per_read`` shows how bad it
got). A frame finished later by a stale-partial flush (see below) is stamped at the flush.
Rate/jitter features computed from these stamps therefore differ from UDP/SITL and need
per-link calibration.

Counters and what they are NOT
------------------------------
Every counter is measured at this transport: bytes read from the driver, bytes discarded while
resynchronising, candidate frames rejected, frames emitted, queue overflow. **Nothing here
measures loss below the driver** -- bytes dropped by the UART FIFO, USB stack or radio before
``read()`` ever returned them are invisible (the serial analogue of UDP's kernel drops). A
corrupted frame shows up as ``crc_rejects`` / ``garbage_bytes`` only if its bytes arrived at all.

Reconnect
---------
An exception from ``read()`` (USB unplug, ``socket://`` peer closed, device reset) closes the
port, discards any partial frame, bumps ``disconnects`` and (default) retries every
``reconnect_interval_s``. While disconnected ``poll()`` returns nothing, so the IDS sees
**silence** -- indistinguishable *to the detectors* from a dead link. Read ``connected`` /
``disconnects`` / ``last_error`` to tell host-side port loss from link loss.

Passive by default: no GCS heartbeat is sent. ``send()`` exists for a future relay upstream;
heartbeats and signing are deliberately not implemented here.
"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from .mavlink_live import (
    _CRC,
    _INCOMPAT_SIGNED,
    _SIGNATURE,
    _V1_HEADER,
    _V1_MAGIC,
    _V2_HEADER,
    _V2_MAGIC,
    _load_dialect,
    _x25,
)

#: Largest possible MAVLink frame: v2 header(10) + payload(255) + CRC(2) + signature(13).
MAX_FRAME_BYTES = _V2_HEADER + 255 + _CRC + _SIGNATURE  # 280


class SerialLike(Protocol):
    """The slice of ``serial.Serial`` this transport uses (so tests can substitute a fake)."""

    @property
    def in_waiting(self) -> int: ...

    def read(self, size: int = 1) -> bytes: ...

    def write(self, data: bytes) -> int | None: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# stream framer (pure; no serial, no threads)
# --------------------------------------------------------------------------- #


class MavlinkStreamFramer:
    """Incremental byte stream -> whole, CRC-confirmed MAVLink frames.

    Pure and single-threaded: ``feed(data)`` returns the frames completed by ``data``;
    ``flush_stale()`` breaks a stalled false candidate. It never raises on wire data. Memory is
    bounded: after any call the retained bytes are < :data:`MAX_FRAME_BYTES` (garbage is
    discarded, never stored).
    """

    def __init__(self, *, extra_crc: dict[int, int] | None = None) -> None:
        self._map = _load_dialect().mavlink_map
        self._extra_crc = {k: v & 0xFF for k, v in (extra_crc or {}).items() if k not in self._map}
        self._buf = bytearray()
        self._in_garbage = False
        # counters
        self.bytes_in = 0
        self.frames_out = 0
        self.garbage_bytes = 0  # bytes discarded while hunting for a frame start
        self.resync_events = 0  # good -> garbage transitions (one per run, not per byte)
        self.crc_rejects = 0  # complete candidates whose CRC (or sanity) failed
        self.partial_timeouts = 0  # stalled candidates broken by flush_stale()

    @property
    def pending_bytes(self) -> int:
        return len(self._buf)

    def reset(self) -> int:
        """Discard any partial frame (e.g. after a disconnect). Returns bytes dropped."""
        n = len(self._buf)
        self._buf.clear()
        self._in_garbage = False
        return n

    def feed(self, data: bytes) -> list[bytes]:
        if data:
            self.bytes_in += len(data)
            self._buf += data
        return self._scan()

    def flush_stale(self) -> list[bytes]:
        """Call when the link has been quiet: the pending bytes are not going to complete.

        Drops the first pending byte (a magic byte that proposed a frame which never
        arrived) and rescans what follows, which may hold real frames the false candidate was
        blocking. A no-op when nothing is pending.
        """
        if not self._buf:
            return []
        self.partial_timeouts += 1
        self._drop(1)
        return self._scan()

    # -- internals ---------------------------------------------------------- #

    def _drop(self, n: int) -> None:
        if n <= 0:
            return
        if not self._in_garbage:
            self._in_garbage = True
            self.resync_events += 1
        self.garbage_bytes += n
        del self._buf[:n]

    def _scan(self) -> list[bytes]:
        out: list[bytes] = []
        buf = self._buf
        while buf:
            magic = buf[0]
            if magic == _V2_MAGIC:
                if len(buf) < _V2_HEADER:
                    break  # header incomplete: wait
                if buf[2] & ~_INCOMPAT_SIGNED & 0xFF:  # unknown incompat flags: spec says drop
                    self._drop(1)
                    continue
                total = (_V2_HEADER + buf[1] + _CRC
                         + (_SIGNATURE if buf[2] & _INCOMPAT_SIGNED else 0))
            elif magic == _V1_MAGIC:
                if len(buf) < _V1_HEADER:
                    break
                total = _V1_HEADER + buf[1] + _CRC
            else:  # not a frame start: skip the whole run up to the next magic byte
                cut = [p for p in (buf.find(_V2_MAGIC, 1), buf.find(_V1_MAGIC, 1)) if p > 0]
                self._drop(min(cut) if cut else len(buf))
                continue
            if len(buf) < total:
                break  # body incomplete: wait (bounded: total <= MAX_FRAME_BYTES)
            frame = bytes(buf[:total])
            if self._valid(frame):
                del buf[:total]
                self._in_garbage = False
                self.frames_out += 1
                out.append(frame)
            else:  # false magic (or corrupted frame): drop ONE byte, rescan the rest
                self.crc_rejects += 1
                self._drop(1)
        return out

    def _valid(self, frame: bytes) -> bool:
        v2 = frame[0] == _V2_MAGIC
        hdr = _V2_HEADER if v2 else _V1_HEADER
        if v2:
            msgid = frame[7] | frame[8] << 8 | frame[9] << 16
            sysid, compid, compat = frame[5], frame[6], frame[3]
        else:
            msgid, sysid, compid, compat = frame[5], frame[3], frame[4], 0
        cls = self._map.get(msgid)
        extra = getattr(cls, "crc_extra", None) if cls is not None else self._extra_crc.get(msgid)
        if extra is None:
            # Unknown id: the CRC cannot be verified, so only header plausibility stands between
            # a stray magic byte and a swallowed run of real frames. Deliberately stricter than
            # MavlinkFrameParser's own check (v2, compat 0, sysid != 0): also compid != 0 and
            # msgid <= 0xFFFF (no assigned MAVLink id is larger), which makes a false accept
            # ~1 in 65k per stray magic byte instead of ~1 in 256.
            return v2 and sysid != 0 and compid != 0 and compat == 0 and msgid <= 0xFFFF
        body_end = hdr + frame[1]
        want = int.from_bytes(frame[body_end : body_end + _CRC], "little")
        return _x25(bytes([extra]), _x25(frame[1:body_end])) == want


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #


def _default_factory(port: str, baudrate: int, read_timeout_s: float,
                     write_timeout_s: float) -> Callable[[], SerialLike]:
    def make() -> SerialLike:
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - exercised only without pyserial
            raise RuntimeError(
                "SerialMavlinkTransport needs pyserial: pip install 'aegisflight[serial]'") from exc
        # serial_for_url accepts device names (COM5, /dev/ttyACM0) and pyserial URLs
        # (socket://host:port, loop://) -- the former is hardware, the latter is how the tests
        # get a virtual port.
        return serial.serial_for_url(port, baudrate=baudrate, timeout=read_timeout_s,
                                     write_timeout=write_timeout_s, rtscts=False, xonxoff=False)

    return make


class SerialMavlinkTransport:
    """Reader thread + bounded queue over a serial port; ``FrameTransport`` compatible.

    ``port``: device name or pyserial URL. ``baudrate``: ignored by USB-CDC links, essential for
    UART/telemetry-radio links (it must match the flight controller's serial-port setting).
    ``serial_factory`` replaces port opening (tests).

    The queue is bounded by item count (``queue_size``) AND bytes (``max_queue_bytes``);
    overflow drops the NEWEST frame and is counted in ``dropped_overflow`` /
    ``dropped_overflow_bytes`` (same semantics as ``UdpMavlinkTransport``).
    """

    def __init__(
        self,
        port: str,
        *,
        baudrate: int = 57600,
        read_timeout_s: float = 0.05,
        write_timeout_s: float = 1.0,
        partial_timeout_s: float = 1.0,
        max_read_bytes: int = 4096,
        queue_size: int = 16384,
        max_queue_bytes: int = 8 * 1024 * 1024,
        reconnect: bool = True,
        reconnect_interval_s: float = 1.0,
        extra_crc: dict[int, int] | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        serial_factory: Callable[[], SerialLike] | None = None,
    ) -> None:
        if baudrate < 1:
            raise ValueError("baudrate must be >= 1")
        if read_timeout_s <= 0:
            raise ValueError("read_timeout_s must be > 0 (a blocking read could not be stopped)")
        if max_read_bytes < 1 or max_queue_bytes < 1 or queue_size < 1:
            raise ValueError("max_read_bytes, queue_size and max_queue_bytes must be >= 1")
        self.port = port
        self.baudrate = baudrate
        self._factory = serial_factory or _default_factory(port, baudrate, read_timeout_s,
                                                           write_timeout_s)
        self._partial_timeout_ns = int(partial_timeout_s * 1e9)
        self._max_read = max_read_bytes
        self._reconnect = reconnect
        self._reconnect_interval_s = reconnect_interval_s
        self._clock_ns = clock_ns
        self._framer = MavlinkStreamFramer(extra_crc=extra_crc)
        self._q: queue.Queue[tuple[int, bytes]] = queue.Queue(maxsize=queue_size)
        self._max_bytes = max_queue_bytes
        self._queued_bytes = 0
        self._bytes_lock = threading.Lock()
        self._io_lock = threading.Lock()  # guards the _ser swap and writes
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._ser: SerialLike | None = None
        self._last_rx_ns: int | None = None
        self._last_poll_end_ns: int | None = None
        # health counters (all measured HERE; none measure loss below the driver)
        self.connected = False
        self.reads = 0
        self.bytes_received = 0
        self.datagrams_received = 0  # frames queued-or-dropped; name kept for UDP parity
        self.max_frames_per_read = 0
        self.dropped_overflow = 0
        self.dropped_overflow_bytes = 0
        self.queue_high_water = 0
        self.max_poll_gap_s = 0.0
        self.disconnects = 0
        self.reconnects = 0
        self.open_failures = 0
        self.discarded_on_disconnect_bytes = 0
        self.bytes_sent = 0
        self.write_errors = 0
        self.last_error: str | None = None

    # -- framer counters, exposed under this transport ------------------------ #

    @property
    def garbage_bytes(self) -> int:
        return self._framer.garbage_bytes

    @property
    def resync_events(self) -> int:
        return self._framer.resync_events

    @property
    def crc_rejects(self) -> int:
        return self._framer.crc_rejects

    @property
    def partial_timeouts(self) -> int:
        return self._framer.partial_timeouts

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "connected": self.connected, "reads": self.reads,
            "bytes_received": self.bytes_received, "frames_received": self.datagrams_received,
            "garbage_bytes": self.garbage_bytes, "resync_events": self.resync_events,
            "crc_rejects": self.crc_rejects, "partial_timeouts": self.partial_timeouts,
            "dropped_overflow": self.dropped_overflow,
            "dropped_overflow_bytes": self.dropped_overflow_bytes,
            "queue_high_water": self.queue_high_water, "max_poll_gap_s": self.max_poll_gap_s,
            "max_frames_per_read": self.max_frames_per_read, "disconnects": self.disconnects,
            "reconnects": self.reconnects, "open_failures": self.open_failures,
            "discarded_on_disconnect_bytes": self.discarded_on_disconnect_bytes,
            "bytes_sent": self.bytes_sent, "write_errors": self.write_errors,
            "last_error": self.last_error,
        }

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> None:
        """Open the port and start the reader. Idempotent.

        With ``reconnect=False`` an unopenable port raises here. With ``reconnect=True`` it is
        recorded (``open_failures`` / ``last_error``) and retried by the reader thread, so the IDS
        can be started before the flight controller is plugged in.
        """
        if self._thread is not None or self._closed:
            return
        if not self._try_open(initial=True) and not self._reconnect:
            raise RuntimeError(f"cannot open serial port {self.port!r}: {self.last_error}")
        self._thread = threading.Thread(target=self._rx_loop, name="mavlink-serial-rx",
                                        daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        with self._io_lock:
            self._close_port()
        self.poll()  # drain and release the byte budget

    def __enter__(self) -> SerialMavlinkTransport:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- consumer side -------------------------------------------------------- #

    def poll(self) -> list[tuple[int, bytes]]:
        now_ns = self._clock_ns()
        if self._last_poll_end_ns is not None:
            gap_s = (now_ns - self._last_poll_end_ns) / 1e9
            if gap_s > self.max_poll_gap_s:
                self.max_poll_gap_s = gap_s
        out: list[tuple[int, bytes]] = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        if out:
            with self._bytes_lock:
                self._queued_bytes -= sum(len(d) for _, d in out)
        self._last_poll_end_ns = self._clock_ns()
        return out

    def send(self, data: bytes) -> bool:
        """Write raw bytes to the port. False if disconnected/closed or the write failed."""
        with self._io_lock:
            ser = self._ser
            if ser is None or self._closed:
                return False
            try:
                ser.write(data)
            except Exception as exc:  # noqa: BLE001 - serial/OS errors; the rx loop owns reconnect
                self.write_errors += 1
                self.last_error = repr(exc)
                return False
            self.bytes_sent += len(data)
            return True

    # -- reader thread -------------------------------------------------------- #

    def _close_port(self) -> None:
        ser, self._ser = self._ser, None
        self.connected = False
        if ser is not None:
            try:
                ser.close()
            except Exception:  # noqa: BLE001 - closing a dead port may itself fail
                pass

    def _try_open(self, *, initial: bool = False) -> bool:
        try:
            ser = self._factory()
        except Exception as exc:  # noqa: BLE001 - SerialException, OSError, ValueError, ...
            self.open_failures += 1
            self.last_error = repr(exc)
            return False
        with self._io_lock:
            if self._closed:
                try:
                    ser.close()
                except Exception:  # noqa: BLE001
                    pass
                return False
            self._ser = ser
            self.connected = True
            self._last_rx_ns = None
        if not initial:
            self.reconnects += 1
        return True

    def _on_disconnect(self, exc: BaseException) -> None:
        self.last_error = repr(exc)
        self.disconnects += 1
        with self._io_lock:
            self._close_port()
        self.discarded_on_disconnect_bytes += self._framer.reset()

    def _emit(self, frames: list[bytes], stamp_ns: int) -> None:
        if len(frames) > self.max_frames_per_read:
            self.max_frames_per_read = len(frames)
        for fr in frames:
            self.datagrams_received += 1
            self._enqueue(stamp_ns, fr)

    def _enqueue(self, stamp: int, data: bytes) -> None:
        with self._bytes_lock:
            if self._queued_bytes + len(data) <= self._max_bytes:
                try:
                    self._q.put_nowait((stamp, data))
                    self._queued_bytes += len(data)
                    qsize = self._q.qsize()
                    if qsize > self.queue_high_water:
                        self.queue_high_water = qsize
                    return
                except queue.Full:
                    pass
            self.dropped_overflow += 1
            self.dropped_overflow_bytes += len(data)

    def _rx_loop(self) -> None:
        while not self._stop.is_set():
            ser = self._ser
            if ser is None:
                if not self._reconnect:
                    return
                if self._stop.wait(self._reconnect_interval_s):
                    return
                self._try_open()
                continue
            try:
                data = ser.read(max(1, min(ser.in_waiting, self._max_read)))
            except Exception as exc:  # noqa: BLE001 - port vanished / peer closed / driver error
                if self._stop.is_set():
                    return
                self._on_disconnect(exc)
                continue
            stamp = self._clock_ns()
            if data:
                self.reads += 1
                self.bytes_received += len(data)
                self._last_rx_ns = stamp
                self._emit(self._framer.feed(data), stamp)
            elif (self._framer.pending_bytes and self._last_rx_ns is not None
                  and stamp - self._last_rx_ns >= self._partial_timeout_ns):
                self._last_rx_ns = stamp  # re-arm: at most one drop per timeout interval
                self._emit(self._framer.flush_stale(), stamp)
