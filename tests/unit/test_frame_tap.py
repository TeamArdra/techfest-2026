"""Unit tests for ``TapTransport`` (tee + optional FrameHook). No SITL, no WSL, no sockets."""

from __future__ import annotations

import struct

from pymavlink.dialects.v20 import common as mav

from aegisflight.proxy.hooks import FrameContext
from aegisflight.sources.frame_tap import TapTransport, frame_header


def _frame(seq: int, *, v1: bool = False) -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    m.seq = seq
    return bytes(m.heartbeat_encode(2, 3, 81, 0, 3, 3).pack(m, force_mavlink1=v1))


class Fake:
    """A scripted inner transport with the counters LiveMavlinkSource reads."""

    dropped_overflow = 7

    def __init__(self, frames: list[bytes]) -> None:
        self._items = [(1_000_000_000 + i * 1_000_000, f) for i, f in enumerate(frames)]
        self.started = self.closed = False

    def start(self) -> None:
        self.started = True

    def poll(self):
        out, self._items = self._items, []
        return out

    def close(self) -> None:
        self.closed = True


def _read_tlog(path) -> list[tuple[int, bytes]]:
    data, out, i = path.read_bytes(), [], 0
    while i < len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0]
        n = (12 + data[i + 9] + (13 if data[i + 10] & 1 else 0)) if data[i + 8] == 0xFD else 8 + data[i + 9]
        out.append((ts, data[i + 8:i + 8 + n]))
        i += 8 + n
    return out


def test_frame_header_v2_and_v1():
    assert frame_header(_frame(7)) == (1, 1, 7, 0, False)
    assert frame_header(_frame(9, v1=True)) == (1, 1, 9, 0, False)


def test_passthrough_is_byte_identical_ordered_and_tees_both_logs(tmp_path):
    frames = [_frame(i) for i in range(5)] + [_frame(5, v1=True)]
    inner = Fake(frames)
    tap = TapTransport(inner, clean_tlog=tmp_path / "c.tlog", observed_tlog=tmp_path / "o.tlog")
    tap.start()
    got = tap.poll()
    tap.close()
    assert inner.started and inner.closed
    assert [f for _, f in got] == frames
    assert [s for s, _ in got] == [s for s, _ in Fake(frames)._items]  # stamps preserved
    clean, obs = _read_tlog(tmp_path / "c.tlog"), _read_tlog(tmp_path / "o.tlog")
    assert [f for _, f in clean] == frames and [f for _, f in obs] == frames
    assert tap.frames_in == tap.frames_out == 6 and tap.hook_errors == 0 and tap.origin_ns == 1_000_000_000
    assert clean[0][0] > 1.6e15  # unix microseconds, not a monotonic stamp


def test_hook_can_modify_drop_and_duplicate_and_logs_diverge(tmp_path):
    frames = [_frame(i) for i in range(4)]

    def hook(ctx: FrameContext) -> list[bytes]:
        assert ctx.direction == "down" and ctx.sysid == 1 and ctx.msgid == 0
        if ctx.seq == 0:
            return [ctx.raw[:-1] + bytes([ctx.raw[-1] ^ 0xFF])]  # modify
        if ctx.seq == 1:
            return []  # drop
        if ctx.seq == 2:
            return [ctx.raw, ctx.raw]  # duplicate
        return [ctx.raw]

    tap = TapTransport(Fake(frames), clean_tlog=tmp_path / "c.tlog", observed_tlog=tmp_path / "o.tlog",
                       down_hook=hook)
    got = tap.poll()
    tap.close()
    assert len(got) == 4 and tap.frames_in == 4 and tap.frames_out == 4
    assert got[0][1] != frames[0] and got[1][1] == frames[2] and got[2][1] == frames[2]
    assert [f for _, f in _read_tlog(tmp_path / "c.tlog")] == frames  # clean is never rewritten
    assert [f for _, f in _read_tlog(tmp_path / "o.tlog")] == [f for _, f in got]


def test_hook_failure_fails_open_and_is_counted():
    frames = [_frame(i) for i in range(3)]

    def boom(ctx: FrameContext) -> list[bytes]:
        if ctx.seq == 1:
            raise RuntimeError("bad attack code")
        return [ctx.raw]

    tap = TapTransport(Fake(frames), down_hook=boom)
    assert [f for _, f in tap.poll()] == frames
    assert tap.hook_errors == 1 and "bad attack code" in (tap.first_hook_error or "")


def test_hook_returning_wrong_type_fails_open_and_is_counted():
    frames = [_frame(0)]
    tap = TapTransport(Fake(frames), down_hook=lambda ctx: ctx.raw)  # type: ignore[arg-type,return-value]
    assert [f for _, f in tap.poll()] == frames
    assert tap.hook_errors == 1 and "expected list[bytes]" in (tap.first_hook_error or "")


def test_counters_of_the_inner_transport_are_delegated():
    tap = TapTransport(Fake([]))
    assert tap.dropped_overflow == 7
    assert tap.tap_stats == {"frames_in": 0, "frames_out": 0, "hook_errors": 0, "first_hook_error": None}


def test_close_is_idempotent(tmp_path):
    inner = Fake([])
    tap = TapTransport(inner, clean_tlog=tmp_path / "c.tlog")
    tap.close()
    tap.close()
    assert inner.closed


def test_short_frame_with_a_hook_fails_open_instead_of_raising():
    short = b"\xfd" + b"\x00" * 8  # a torn v2 frame: frame_header would raise IndexError

    class Inner(Fake):
        def __init__(self) -> None:
            super().__init__([])
            self._items = [(1, short)]

    tap = TapTransport(Inner(), down_hook=lambda ctx: [ctx.raw])
    assert [f for _, f in tap.poll()] == [short]
    assert tap.hook_errors == 1 and "IndexError" in (tap.first_hook_error or "")


def test_tlogs_are_closed_even_if_the_inner_close_raises(tmp_path):
    class Boom(Fake):
        def close(self) -> None:
            raise RuntimeError("inner close failed")

    tap = TapTransport(Boom([]), clean_tlog=tmp_path / "c.tlog")
    try:
        tap.close()
    except RuntimeError:
        pass
    assert tap._clean.closed
