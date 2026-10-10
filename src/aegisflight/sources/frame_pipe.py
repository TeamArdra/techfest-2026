"""Length-prefixed frame pipe -> ``FrameTransport`` (Stage-2, ArduPilot SITL path).

A third implementation of the existing ``FrameTransport`` seam (``poll()`` / ``close()``), beside
``UdpMavlinkTransport`` and ``SerialMavlinkTransport``. It reads MAVLink frames from any binary
stream -- in practice the stdout of a ``wsl.exe`` child whose MAVLink endpoint lives in an
isolated network namespace -- so the simulator's ports never have to be exposed to the default
network: the pipe is the only thing that crosses the boundary, and it is receive-only (this class
never writes to the child).

Wire format (one record per MAVLink frame, produced by ``scripts/ardupilot/ap_gcs_pipe.py``)::

    >H length (8..280)  |  that many bytes: ONE complete MAVLink 1/2 frame

There is no resynchronisation: the producer is our own script, so a record whose length is out of
range or whose first byte is not a MAVLink magic means the stream is corrupt and the reader
stops (``last_error`` says why) instead of guessing. End of stream sets ``eof``. Frames are
stamped ``clock_ns()`` (default ``time.monotonic_ns``, the clock ``LiveMavlinkSource`` uses) when
the reader thread got them, so the stamp includes the pipe and ``wsl.exe`` relay delay; it is not
the time the simulator emitted the frame.

The pipe carries bytes, not guarantees: nothing here verifies frame CRCs (the unchanged
``MavlinkFrameParser`` downstream does, per known id).
"""

from __future__ import annotations

import queue
import struct
import threading
import time
from collections.abc import Callable
from typing import BinaryIO, Protocol

#: Largest possible MAVLink frame: v2 header(10) + payload(255) + CRC(2) + signature(13).
MAX_FRAME_BYTES = 280
MIN_FRAME_BYTES = 8  # v1: header 6 + CRC 2 (empty payload)
_V2_MIN = 12  # v2: header 10 + CRC 2 (empty payload)
_LEN = struct.Struct(">H")


class ByteStream(Protocol):
    def read(self, n: int, /) -> bytes: ...


def pack_record(frame: bytes) -> bytes:
    """Encode one frame as a pipe record (used by producers and tests)."""
    if not (MIN_FRAME_BYTES <= len(frame) <= MAX_FRAME_BYTES):
        raise ValueError(f"frame length {len(frame)} outside [{MIN_FRAME_BYTES}, {MAX_FRAME_BYTES}]")
    if frame[0] not in (0xFD, 0xFE):
        raise ValueError("frame does not start with a MAVLink magic byte")
    return _LEN.pack(len(frame)) + frame


def _read_exact(stream: ByteStream, n: int) -> bytes | None:
    """Exactly ``n`` bytes; ``None`` at a clean end of stream (nothing read); ``EOFError`` if the stream
    ended part-way through (a torn record is an error, not a clean EOF)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            if not buf:
                return None
            raise EOFError(f"truncated record: got {len(buf)} of {n} bytes")
        buf += chunk
    return bytes(buf)


class LengthPrefixedPipeTransport:
    """Reader thread + bounded queue over a binary stream; ``FrameTransport`` compatible.

    ``stream``: any object with ``read(n)`` that blocks until data or EOF (``Popen.stdout``,
    ``os.fdopen`` of a pipe, ``io.BytesIO`` in tests). It must be UNBUFFERED (``bufsize=0`` /
    ``buffering=0``): closing a buffered reader that the reader thread is blocked on would itself block.
    ``on_close``: called once from ``close()`` to release the producer (e.g. terminate the child
    process); the stream is closed too.
    """

    def __init__(self, stream: BinaryIO | ByteStream, *, queue_size: int = 16384,
                 max_queue_bytes: int = 8 * 1024 * 1024,
                 clock_ns: Callable[[], int] = time.monotonic_ns,
                 on_close: Callable[[], None] | None = None) -> None:
        if queue_size < 1 or max_queue_bytes < 1:
            raise ValueError("queue_size and max_queue_bytes must be >= 1")
        self._stream = stream
        self._clock_ns = clock_ns
        self._on_close = on_close
        self._q: queue.Queue[tuple[int, bytes]] = queue.Queue(maxsize=queue_size)
        self._max_bytes = max_queue_bytes
        self._queued_bytes = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._last_poll_end_ns: int | None = None
        # health counters (all measured HERE)
        self.frames_received = 0
        self.bytes_received = 0
        self.dropped_overflow = 0
        self.dropped_overflow_bytes = 0
        self.queue_high_water = 0
        self.max_poll_gap_s = 0.0
        self.eof = False
        self.last_error: str | None = None

    @property
    def stats(self) -> dict[str, object]:
        return {"frames_received": self.frames_received, "bytes_received": self.bytes_received,
                "dropped_overflow": self.dropped_overflow,
                "dropped_overflow_bytes": self.dropped_overflow_bytes,
                "queue_high_water": self.queue_high_water, "max_poll_gap_s": self.max_poll_gap_s,
                "eof": self.eof, "reader_running": self.reader_running, "last_error": self.last_error}

    @property
    def reader_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None or self._closed:
            return
        self._thread = threading.Thread(target=self._rx_loop, name="frame-pipe-rx", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._on_close is not None:
            try:
                self._on_close()
            except Exception as exc:  # noqa: BLE001 - releasing the producer must not raise
                self.last_error = self.last_error or f"on_close failed: {exc!r}"
        try:
            closer = getattr(self._stream, "close", None)
            if callable(closer):
                closer()
        except Exception:  # noqa: BLE001 - closing a dead pipe may itself fail
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self.poll()  # drain and release the byte budget

    def __enter__(self) -> LengthPrefixedPipeTransport:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

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
            with self._lock:
                self._queued_bytes -= sum(len(d) for _, d in out)
        self._last_poll_end_ns = self._clock_ns()
        return out

    # -- reader ----------------------------------------------------------------- #

    def _rx_loop(self) -> None:
        try:
            while not self._closed:
                head = _read_exact(self._stream, _LEN.size)
                if head is None:
                    self.eof = True
                    return
                (n,) = _LEN.unpack(head)
                if not (MIN_FRAME_BYTES <= n <= MAX_FRAME_BYTES):
                    self.last_error = (f"corrupt pipe: record length {n} outside "
                                       f"[{MIN_FRAME_BYTES}, {MAX_FRAME_BYTES}]")
                    return
                frame = _read_exact(self._stream, n)
                if frame is None:
                    self.last_error = f"truncated final record ({n} bytes expected)"
                    self.eof = True  # error recorded BEFORE eof so a reader that sees eof also sees why
                    return
                if frame[0] not in (0xFD, 0xFE):
                    self.last_error = f"corrupt pipe: record starts with 0x{frame[0]:02x}, not a MAVLink magic"
                    return
                if n < (_V2_MIN if frame[0] == 0xFD else MIN_FRAME_BYTES):
                    self.last_error = f"corrupt pipe: {n}-byte record is shorter than its MAVLink header"
                    return
                stamp = self._clock_ns()
                self.frames_received += 1
                self.bytes_received += n
                self._enqueue(stamp, frame)
        except EOFError as exc:  # stream ended inside a record
            if not self._closed:
                self.last_error = str(exc)
                self.eof = True
        except Exception as exc:  # noqa: BLE001 - a closed/broken pipe ends the reader, loudly
            if not self._closed:
                self.last_error = f"reader stopped: {exc!r}"

    def _enqueue(self, stamp: int, data: bytes) -> None:
        with self._lock:
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
