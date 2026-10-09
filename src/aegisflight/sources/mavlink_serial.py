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

* **Ids whose CRC cannot be verified are REFUSED by default.** An id outside the dialect has no
  known ``crc_extra``, so nothing separates a genuine frame from a corrupted one: a single
  bit flip in the message-id field of any ordinary frame produces exactly such an id, with a
  plausible header and a garbage payload. Supply ``extra_crc={msgid: crc_extra}`` to make an id
  verifiable (it is then CRC-checked like a dialect id). ``accept_unverified_ids=True`` is an
  opt-in compatibility mode that accepts them on header plausibility alone; it provides NO
  integrity (see ``docs/SERIAL_TRANSPORT.md``). There is deliberately no search over the 256
  possible ``crc_extra`` values: a match would be a 1-in-65536 coincidence per guess, not proof.
* **One queue item per frame.** ``poll()`` returns ``(stamp_ns, one_whole_frame)``, so the
  parser sees clean frames and every frame has its own stamp.

Timestamps (what the number does and does not mean)
---------------------------------------------------
The stamp is ``clock_ns()`` read immediately after the ``read()`` that **resolved** the frame
returned -- the read after which the framer could first emit it. That is normally the read that
delivered its last byte, but not always: a frame sitting behind a still-incomplete false
candidate is held until that candidate resolves (more bytes arrive, or the stale-partial flush
fires), so it can be stamped later than its last byte arrived -- by up to the time to receive
the false candidate's remaining bytes (<= 280) or ``partial_timeout_s``. The stamp is host-side,
not wire time: it includes baud-rate serialisation, OS/USB driver buffering and read latency.
Frames resolved by one ``read()`` share one stamp, so a burst's inter-frame spacing is lost
(``max_frames_per_read`` shows how bad it got). A frame resolved by a stale-partial flush is
stamped at the flush. Rate/jitter features computed from these stamps therefore differ from
UDP/SITL and need per-link calibration.

Counters and what they are NOT
------------------------------
Every counter is measured at this transport: bytes read from the driver, bytes discarded while
resynchronising, candidates refused (by header, by failed CRC, or because their id is
unverifiable -- three separate counters), frames emitted, queue overflow. **Nothing here
measures loss below the driver** -- bytes dropped by the UART FIFO, USB stack or radio before
``read()`` ever returned them are invisible (the serial analogue of UDP's kernel drops). A
corrupted frame shows up as ``crc_rejects`` / ``garbage_bytes`` only if its bytes arrived at all.

Reconnect
---------
An exception from ``read()`` (USB unplug, ``socket://`` peer closed, device reset) closes the
port, discards any partial frame, bumps ``disconnects`` and (default) retries every
``reconnect_interval_s``. While disconnected ``poll()`` returns nothing, so the IDS sees
**silence** -- indistinguishable *to the detectors* from a dead link. Read ``connected`` /
``disconnects`` / ``last_error`` to tell host-side port loss from link loss. An unexpected
exception inside the reader (a framing bug, not a link event) takes the same path: port closed,
``connected`` False, ``reader_faults`` bumped, cause in ``last_error``; ``reader_running`` says
whether the thread is still alive.

Passive by default: no GCS heartbeat is sent. ``send()`` exists for a future relay upstream;
heartbeats and signing are deliberately not implemented here.
"""

from __future__ import annotations

import math
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
)

#: Largest possible MAVLink frame: v2 header(10) + payload(255) + CRC(2) + signature(13).
MAX_FRAME_BYTES = _V2_HEADER + 255 + _CRC + _SIGNATURE  # 280

#: Distinct unverifiable message ids remembered for diagnostics (bounded: wire data must not
#: be able to grow this dict). Further distinct ids are only counted in ``unverifiable_id_overflow``.
MAX_TRACKED_UNVERIFIABLE_IDS = 64

#: pyserial URL schemes this transport will open, and only with ``allow_url=True``. Everything
#: else (``spy://`` writes a file, ``alt://`` can wrap it, ``hwgrep://``, ``cp2110://``, ...)
#: is refused: the port string may come from configuration.
ALLOWED_URL_SCHEMES = frozenset({"socket", "rfc2217"})


def _build_x25_table() -> tuple[int, ...]:
    # Same arithmetic as mavlink_live._x25, folded into one lookup per input byte.
    table = []
    for x in range(256):
        t = (x ^ (x << 4)) & 0xFF
        table.append(((t << 8) ^ (t << 3) ^ (t >> 4)) & 0xFFFF)
    return tuple(table)


_X25_TABLE = _build_x25_table()


def _crc_x25(data: bytes | bytearray, crc: int = 0xFFFF) -> int:
    """MAVLink X.25 / MCRF4XX CRC, table-driven. Bit-identical to ``mavlink_live._x25``
    (a test compares them); roughly 2-3x faster in pure Python, no new dependency."""
    table = _X25_TABLE
    for b in data:
        crc = (crc >> 8) ^ table[(b ^ crc) & 0xFF]
    return crc


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

    Acceptance policy for a complete candidate (``extra_crc`` ids behave like dialect ids):

    * id has a ``crc_extra`` (dialect or ``extra_crc``) -> accepted iff the CRC verifies;
    * id has none (CRC unverifiable) -> **refused**, unless ``accept_unverified_ids=True``, in
      which case it is accepted on header plausibility alone (MAVLink 2, compat flags 0, sysid
      and compid != 0, msgid <= 0xFFFF). That mode verifies nothing: a bit flip in the id of
      a good frame becomes an accepted frame with a garbage payload.

    Work bound: every failed candidate drops exactly one byte, so candidates evaluated <=
    bytes fed, and each costs at most 265 CRC steps (v2 header 10 + payload 255; the 9 header
    bytes after the magic, the payload and the ``crc_extra`` byte) -- a hard cap of 265 CRC
    steps per input byte, measured in ``crc_bytes_checked``. Typical garbage costs
    far less (a candidate needs a known id to reach the CRC at all); a crafted stream
    approaches the cap only if its false candidates overlap densely. This is a work bound,
    not a real-time guarantee.
    """

    def __init__(self, *, extra_crc: dict[int, int] | None = None,
                 accept_unverified_ids: bool = False) -> None:
        self._map = _load_dialect().mavlink_map
        self._extra_crc = {k: v & 0xFF for k, v in (extra_crc or {}).items() if k not in self._map}
        self._accept_unverified = accept_unverified_ids
        self._buf = bytearray()
        self._in_garbage = False
        # counters (each says exactly what it counts; see docs/SERIAL_TRANSPORT.md)
        self.bytes_in = 0
        self.frames_out = 0
        self.garbage_bytes = 0  # bytes discarded for any reason while hunting a frame start
        self.resync_events = 0  # good -> garbage transitions (one per run, not per byte)
        self.header_rejects = 0  # candidates refused on the header alone (unknown incompat flags)
        self.crc_rejects = 0  # complete candidates of a VERIFIABLE id whose CRC did not match
        self.unverifiable_rejects = 0  # complete candidates whose id has no crc_extra, refused
        self.unverified_accepted = 0  # frames accepted with NO CRC check (opt-in mode only)
        self.crc_bytes_checked = 0  # CRC steps spent confirming candidates (work measure)
        self.partial_timeouts = 0  # stalled candidates broken by flush_stale()
        # msgid -> times seen as an unverifiable candidate. An entry is EITHER a genuine
        # out-of-dialect message OR a corrupted id field; the framer cannot tell which.
        self.unverifiable_ids: dict[int, int] = {}
        self.unverifiable_id_overflow = 0  # unverifiable candidates whose id was not tracked

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
        self._discard(1)
        del self._buf[:1]
        return self._scan()

    # -- internals ---------------------------------------------------------- #

    def _discard(self, n: int) -> None:
        """Account for ``n`` bytes thrown away (the caller removes them from the buffer)."""
        if n <= 0:
            return
        if not self._in_garbage:
            self._in_garbage = True
            self.resync_events += 1
        self.garbage_bytes += n

    def _scan(self) -> list[bytes]:
        out: list[bytes] = []
        buf = self._buf
        n = len(buf)
        pos = 0  # candidates are examined in place; the consumed prefix is cut once, at the end
        while pos < n:
            magic = buf[pos]
            if magic == _V2_MAGIC:
                if n - pos < _V2_HEADER:
                    break  # header incomplete: wait
                if buf[pos + 2] & ~_INCOMPAT_SIGNED & 0xFF:  # unknown incompat flags: spec says drop
                    self.header_rejects += 1
                    self._discard(1)
                    pos += 1
                    continue
                total = (_V2_HEADER + buf[pos + 1] + _CRC
                         + (_SIGNATURE if buf[pos + 2] & _INCOMPAT_SIGNED else 0))
            elif magic == _V1_MAGIC:
                if n - pos < _V1_HEADER:
                    break
                total = _V1_HEADER + buf[pos + 1] + _CRC
            else:  # not a frame start: skip the whole run up to the next magic byte
                cut = [p for p in (buf.find(_V2_MAGIC, pos + 1), buf.find(_V1_MAGIC, pos + 1))
                       if p > 0]
                end = min(cut) if cut else n
                self._discard(end - pos)
                pos = end
                continue
            if n - pos < total:
                break  # body incomplete: wait (bounded: total <= MAX_FRAME_BYTES)
            if self._accept(buf, pos, total):
                out.append(bytes(buf[pos : pos + total]))
                pos += total
                self._in_garbage = False
                self.frames_out += 1
            else:  # false magic (or corrupted frame): drop ONE byte, rescan the rest
                self._discard(1)
                pos += 1
        del buf[:pos]
        return out

    def _accept(self, buf: bytearray, pos: int, total: int) -> bool:
        """Verdict on the complete candidate at ``buf[pos:pos+total]``; updates the counters."""
        v2 = buf[pos] == _V2_MAGIC
        if v2:
            hdr = _V2_HEADER
            msgid = buf[pos + 7] | buf[pos + 8] << 8 | buf[pos + 9] << 16
            sysid, compid, compat = buf[pos + 5], buf[pos + 6], buf[pos + 3]
        else:
            hdr = _V1_HEADER
            msgid, sysid, compid, compat = buf[pos + 5], buf[pos + 3], buf[pos + 4], 0
        cls = self._map.get(msgid)
        extra = getattr(cls, "crc_extra", None) if cls is not None else self._extra_crc.get(msgid)
        if extra is None:
            return self._accept_unverifiable(msgid, v2, sysid, compid, compat)
        body_end = pos + hdr + buf[pos + 1]
        want = buf[body_end] | buf[body_end + 1] << 8
        self.crc_bytes_checked += body_end - pos  # (len + header-1) bytes + the crc_extra byte
        if _crc_x25(bytes((extra,)), _crc_x25(buf[pos + 1 : body_end])) == want:
            return True
        self.crc_rejects += 1
        return False

    def _accept_unverifiable(self, msgid: int, v2: bool, sysid: int, compid: int,
                             compat: int) -> bool:
        if msgid in self.unverifiable_ids:
            self.unverifiable_ids[msgid] += 1
        elif len(self.unverifiable_ids) < MAX_TRACKED_UNVERIFIABLE_IDS:
            self.unverifiable_ids[msgid] = 1
        else:
            self.unverifiable_id_overflow += 1
        # Opt-in only. Header plausibility is NOT a check of integrity: it is stricter than
        # MavlinkFrameParser's own sanity (also compid != 0 and msgid <= 0xFFFF) purely to
        # reduce, not remove, false accepts. Every v1 id is in the dialect, so v1 never passes.
        if (self._accept_unverified and v2 and sysid != 0 and compid != 0 and compat == 0
                and msgid <= 0xFFFF):
            self.unverified_accepted += 1
            return True
        self.unverifiable_rejects += 1
        return False


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #


def _check_port(port: str, allow_url: bool) -> None:
    """Refuse port strings that would hand control to a pyserial URL handler.

    ``serial_for_url`` treats anything containing ``://`` as a handler selector and imports
    ``serial.urlhandler.protocol_<scheme>``; ``spy://`` among them writes a file. The port
    string may come from configuration, so URLs are off unless ``allow_url=True`` and then only
    the schemes in :data:`ALLOWED_URL_SCHEMES` pass. Plain device names (``COM5``,
    ``/dev/ttyACM0``) are always fine.
    """
    if not isinstance(port, str) or not port or "\x00" in port:
        raise ValueError("port must be a non-empty device name string")
    if "://" not in port:
        return
    scheme = port.split("://", 1)[0].lower()
    if not allow_url:
        raise ValueError(
            f"port {port!r} is a pyserial URL; pass allow_url=True to open URLs "
            f"(allowed schemes: {sorted(ALLOWED_URL_SCHEMES)})")
    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError(f"pyserial URL scheme {scheme!r} is not allowed "
                         f"(allowed: {sorted(ALLOWED_URL_SCHEMES)})")


def _positive_finite(name: str, value: float) -> None:
    if not (isinstance(value, (int, float)) and math.isfinite(value) and value > 0):
        raise ValueError(f"{name} must be a finite number > 0, got {value!r}")


def _default_factory(port: str, baudrate: int, read_timeout_s: float,
                     write_timeout_s: float) -> Callable[[], SerialLike]:
    def make() -> SerialLike:
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - exercised only without pyserial
            raise RuntimeError(
                "SerialMavlinkTransport needs pyserial: pip install 'aegisflight[serial]'") from exc
        opts = {"baudrate": baudrate, "timeout": read_timeout_s,
                "write_timeout": write_timeout_s, "rtscts": False, "xonxoff": False}
        # A plain device name goes straight to serial.Serial, so no URL handler can ever be
        # imported for it. Only a port already validated by _check_port(allow_url=True) reaches
        # serial_for_url (that is how the tests get a socket:// virtual port).
        if "://" in port:
            return serial.serial_for_url(port, **opts)
        return serial.Serial(port, **opts)

    return make


class SerialMavlinkTransport:
    """Reader thread + bounded queue over a serial port; ``FrameTransport`` compatible.

    ``port``: a device name (``COM5``, ``/dev/ttyACM0``). A pyserial URL is refused unless
    ``allow_url=True`` and its scheme is in :data:`ALLOWED_URL_SCHEMES`. ``baudrate``: ignored
    by USB-CDC links, essential for UART/telemetry-radio links (it must match the flight
    controller's serial-port setting). ``serial_factory`` replaces port opening (tests; the
    port string is then only a label and is not validated).

    ``extra_crc`` / ``accept_unverified_ids``: how ids outside the dialect are treated; see
    :class:`MavlinkStreamFramer`. By default such frames are refused.

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
        accept_unverified_ids: bool = False,
        allow_url: bool = False,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        serial_factory: Callable[[], SerialLike] | None = None,
    ) -> None:
        if baudrate < 1:
            raise ValueError("baudrate must be >= 1")
        _positive_finite("read_timeout_s", read_timeout_s)  # a blocking read could not be stopped
        _positive_finite("partial_timeout_s", partial_timeout_s)
        _positive_finite("reconnect_interval_s", reconnect_interval_s)
        if max_read_bytes < 1 or max_queue_bytes < 1 or queue_size < 1:
            raise ValueError("max_read_bytes, queue_size and max_queue_bytes must be >= 1")
        if serial_factory is None:
            _check_port(port, allow_url)
        self.port = port
        self.baudrate = baudrate
        self._factory = serial_factory or _default_factory(port, baudrate, read_timeout_s,
                                                           write_timeout_s)
        self._partial_timeout_ns = int(partial_timeout_s * 1e9)
        self._max_read = max_read_bytes
        self._reconnect = reconnect
        self._reconnect_interval_s = reconnect_interval_s
        self._clock_ns = clock_ns
        self._framer = MavlinkStreamFramer(extra_crc=extra_crc,
                                           accept_unverified_ids=accept_unverified_ids)
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
        self.disconnects = 0  # port closes: read failures AND reader faults (a subset, below)
        self.reader_faults = 0  # unexpected exceptions in the reader loop (software, not link)
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
    def header_rejects(self) -> int:
        return self._framer.header_rejects

    @property
    def unverifiable_rejects(self) -> int:
        return self._framer.unverifiable_rejects

    @property
    def unverified_accepted(self) -> int:
        return self._framer.unverified_accepted

    @property
    def crc_bytes_checked(self) -> int:
        return self._framer.crc_bytes_checked

    @property
    def unverifiable_ids(self) -> dict[int, int]:
        return dict(self._framer.unverifiable_ids)

    @property
    def partial_timeouts(self) -> int:
        return self._framer.partial_timeouts

    @property
    def reader_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "connected": self.connected, "reader_running": self.reader_running,
            "reads": self.reads,
            "bytes_received": self.bytes_received, "frames_received": self.datagrams_received,
            "garbage_bytes": self.garbage_bytes, "resync_events": self.resync_events,
            "header_rejects": self.header_rejects, "crc_rejects": self.crc_rejects,
            "unverifiable_rejects": self.unverifiable_rejects,
            "unverified_accepted": self.unverified_accepted,
            "unverifiable_ids": self.unverifiable_ids,
            "unverifiable_id_overflow": self._framer.unverifiable_id_overflow,
            "crc_bytes_checked": self.crc_bytes_checked,
            "partial_timeouts": self.partial_timeouts, "reader_faults": self.reader_faults,
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

    def _on_fault(self, exc: BaseException) -> None:
        """An unexpected exception in the reader (framer, queue, ...): a software fault, not a
        link event. The port is closed, so ``connected`` goes False and ``last_error`` says
        why; the normal reconnect policy then applies (retry, or stay down with
        ``reconnect=False``). Counted in ``reader_faults`` and, like any port close, in
        ``disconnects``."""
        self.reader_faults += 1
        self._on_disconnect(RuntimeError(f"reader fault: {exc!r}"))

    def _rx_loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    if not self._rx_step():
                        return
                except Exception as exc:  # noqa: BLE001 - must never kill the thread silently
                    if self._stop.is_set():
                        return
                    try:
                        self._on_fault(exc)
                    except Exception as exc2:  # noqa: BLE001 - even the handler failed: give up loudly
                        self.last_error = f"reader fault (unrecoverable): {exc2!r} after {exc!r}"
                        return
        finally:
            # Whatever ended the thread (stop, reconnect=False, unrecoverable fault), the
            # transport must not go on reporting itself connected.
            with self._io_lock:
                self._close_port()

    def _rx_step(self) -> bool:
        """One reader iteration; False ends the thread. Exceptions from the framing/queue
        code propagate to ``_rx_loop``'s fault handler (read failures are handled here)."""
        ser = self._ser
        if ser is None:
            if not self._reconnect:
                return False
            if self._stop.wait(self._reconnect_interval_s):
                return False
            self._try_open()
            return True
        try:
            data = ser.read(max(1, min(ser.in_waiting, self._max_read)))
        except Exception as exc:  # noqa: BLE001 - port vanished / peer closed / driver error
            if self._stop.is_set():
                return False
            self._on_disconnect(exc)
            return True
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
        return True
