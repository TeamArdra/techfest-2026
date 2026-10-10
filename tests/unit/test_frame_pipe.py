"""Unit tests for ``LengthPrefixedPipeTransport`` (ArduPilot-SITL pipe path). No SITL, no WSL, no sockets."""

from __future__ import annotations

import io
import os
import threading
import time

import pytest
from pymavlink.dialects.v20 import common as mav

from aegisflight.sources import LengthPrefixedPipeTransport, LiveMavlinkSource
from aegisflight.sources.frame_pipe import MAX_FRAME_BYTES, pack_record


def _enc() -> mav.MAVLink:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    m.robust_parsing = True
    return m


def heartbeat(seq: int = 0, *, v1: bool = False) -> bytes:
    m = _enc()
    m.seq = seq
    msg = m.heartbeat_encode(2, 3, 81, 0, 3, 3)
    return bytes(msg.pack(m, force_mavlink1=v1))


def attitude(seq: int = 0) -> bytes:
    m = _enc()
    m.seq = seq
    return bytes(m.attitude_encode(1000, 0.1, 0.2, 0.3, 0.0, 0.0, 0.0).pack(m))


def drain(tr: LengthPrefixedPipeTransport, want: int, timeout: float = 3.0) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    end = time.monotonic() + timeout
    while len(out) < want and time.monotonic() < end:
        out += tr.poll()
        time.sleep(0.005)
    return out


class Trickle:
    """A stream that returns at most ``n`` bytes per read (partial reads, like a real pipe)."""

    def __init__(self, data: bytes, n: int = 3) -> None:
        self._b = io.BytesIO(data)
        self._n = n

    def read(self, size: int) -> bytes:
        return self._b.read(min(size, self._n))


def test_pack_record_validates():
    assert pack_record(heartbeat())[:2] == len(heartbeat()).to_bytes(2, "big")
    with pytest.raises(ValueError):
        pack_record(b"\xfd\x00")  # too short
    with pytest.raises(ValueError):
        pack_record(b"\x00" * 20)  # no MAVLink magic
    with pytest.raises(ValueError):
        pack_record(b"\xfd" + b"\x00" * MAX_FRAME_BYTES)  # too long


def test_frames_round_trip_in_order_even_with_trickled_reads():
    frames = [heartbeat(0), attitude(1), heartbeat(2, v1=True), attitude(3)]
    data = b"".join(pack_record(f) for f in frames)
    with LengthPrefixedPipeTransport(Trickle(data, n=3)) as tr:
        got = drain(tr, len(frames))
        assert [f for _, f in got] == frames
        stamps = [s for s, _ in got]
        assert stamps == sorted(stamps)
        assert tr.frames_received == 4 and tr.bytes_received == sum(map(len, frames))
    assert tr.eof and tr.last_error is None


def test_clean_eof_is_flagged_not_an_error():
    with LengthPrefixedPipeTransport(io.BytesIO(pack_record(heartbeat()))) as tr:
        drain(tr, 1)
        deadline = time.monotonic() + 2
        while not tr.eof and time.monotonic() < deadline:
            time.sleep(0.005)
        assert tr.eof and tr.last_error is None and not tr.reader_running


def test_truncated_final_record_is_reported():
    full = pack_record(heartbeat())
    with LengthPrefixedPipeTransport(io.BytesIO(full + full[:-4])) as tr:
        got = drain(tr, 1)
        deadline = time.monotonic() + 2
        while tr.last_error is None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert len(got) == 1
        assert tr.eof and "truncated" in (tr.last_error or "")


@pytest.mark.parametrize("bad", [b"\x00\x02ab", b"\x01\xff" + b"\xfd" * 300, b"\x00\x10" + b"\x55" * 16])
def test_corrupt_records_stop_the_reader_without_emitting(bad):
    with LengthPrefixedPipeTransport(io.BytesIO(bad)) as tr:
        deadline = time.monotonic() + 2
        while tr.last_error is None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert tr.poll() == []
        assert "corrupt pipe" in (tr.last_error or "")


def test_overflow_drops_newest_and_counts():
    frames = [heartbeat(i) for i in range(10)]
    data = b"".join(pack_record(f) for f in frames)
    tr = LengthPrefixedPipeTransport(io.BytesIO(data), queue_size=4)
    tr.start()
    deadline = time.monotonic() + 2
    while not tr.eof and time.monotonic() < deadline:
        time.sleep(0.005)
    got = tr.poll()
    tr.close()
    assert [f for _, f in got] == frames[:4]  # the NEWEST are dropped
    assert tr.dropped_overflow == 6 and tr.dropped_overflow_bytes == sum(map(len, frames[4:]))
    assert tr.queue_high_water == 4


def test_byte_budget_bounds_the_queue():
    f = heartbeat()
    tr = LengthPrefixedPipeTransport(io.BytesIO(pack_record(f) * 5), max_queue_bytes=len(f) * 2)
    tr.start()
    deadline = time.monotonic() + 2
    while not tr.eof and time.monotonic() < deadline:
        time.sleep(0.005)
    assert len(tr.poll()) == 2 and tr.dropped_overflow == 3
    tr.close()


def test_close_is_idempotent_calls_on_close_once_and_unblocks_a_waiting_reader():
    r, w = os.pipe()
    closed: list[int] = []
    reader = os.fdopen(r, "rb", buffering=0)
    tr = LengthPrefixedPipeTransport(reader, on_close=lambda: (closed.append(1), os.close(w)))
    tr.start()
    time.sleep(0.05)
    assert tr.reader_running  # blocked in read(): no data yet
    t0 = time.monotonic()
    tr.close()
    tr.close()
    assert time.monotonic() - t0 < 2.5
    assert closed == [1] and not tr.reader_running


def test_on_close_failure_does_not_raise():
    def boom() -> None:
        raise RuntimeError("child already gone")

    tr = LengthPrefixedPipeTransport(io.BytesIO(b""), on_close=boom)
    tr.start()
    tr.close()
    assert "on_close failed" in (tr.last_error or "")


def test_poll_after_close_is_empty_and_start_after_close_is_a_noop():
    tr = LengthPrefixedPipeTransport(io.BytesIO(pack_record(heartbeat())))
    tr.close()
    tr.start()
    assert tr.poll() == [] and not tr.reader_running


def test_rejects_bad_limits():
    with pytest.raises(ValueError):
        LengthPrefixedPipeTransport(io.BytesIO(b""), queue_size=0)
    with pytest.raises(ValueError):
        LengthPrefixedPipeTransport(io.BytesIO(b""), max_queue_bytes=0)


def test_feeds_the_unchanged_live_source_end_to_end():
    """Real frames through the pipe -> LiveMavlinkSource -> ticks carrying decoded envelopes."""
    names: list[str] = []
    r, w = os.pipe()
    tr = LengthPrefixedPipeTransport(os.fdopen(r, "rb", buffering=0))

    def producer() -> None:
        for i in range(20):
            os.write(w, pack_record(heartbeat(i)) + pack_record(attitude(i)))
            time.sleep(0.02)
        os.close(w)

    th = threading.Thread(target=producer)
    th.start()
    src = LiveMavlinkSource(tr, sample_rate_hz=20.0, max_ticks=15)
    try:
        for tick in src.stream():
            names += [m.msgname for m in tick.messages]
    finally:
        src.close()
        th.join()
    assert "HEARTBEAT" in names and "ATTITUDE" in names
    assert src.stats["bad_frames"] == 0


def test_v2_record_shorter_than_its_header_is_corrupt_not_forwarded():
    short_v2 = b"\xfd" + b"\x00" * 8  # 9 bytes: passes the 8..280 and magic checks, but a v2 header is 10 + CRC 2
    with LengthPrefixedPipeTransport(io.BytesIO(len(short_v2).to_bytes(2, "big") + short_v2)) as tr:
        deadline = time.monotonic() + 2
        while tr.last_error is None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert tr.poll() == [] and "shorter than its MAVLink header" in (tr.last_error or "")


def test_torn_length_header_is_an_error_not_a_clean_eof():
    with LengthPrefixedPipeTransport(io.BytesIO(pack_record(heartbeat()) + b"\x00")) as tr:  # 1 byte of a 2-byte length
        deadline = time.monotonic() + 2
        while not tr.eof and time.monotonic() < deadline:
            time.sleep(0.005)
        assert tr.eof and "truncated" in (tr.last_error or "")
