"""Serial MAVLink transport: stream framer, reader thread, reconnect, virtual-port tests.

No hardware and no PX4. Three layers:

* ``MavlinkStreamFramer`` is pure -- tested directly (partial frames, bursts, garbage,
  false magic bytes, CRC failures, bounded memory, chunking invariance).
* ``SerialMavlinkTransport`` with a scripted fake port (``serial_factory``) -- deterministic
  disconnect / reconnect / stale-partial / overflow / shutdown behaviour.
* REAL pyserial over a virtual port: ``socket://`` (a loopback TCP server standing in for a
  serial device; works on every OS, including this Windows host) and, on POSIX only, a real
  PTY pair. The PTY tests are skipped on Windows -- ``pty`` does not exist there -- so on a
  Windows-only run the PTY code path is NOT exercised; ``socket://`` covers the same
  transport code through pyserial's real ``Serial`` API, but not a termios tty.
"""

from __future__ import annotations

import itertools
import os
import random
import socket
import sys
import threading
import time

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.sources.mavlink_live import LiveMavlinkSource, MavlinkFrameParser, _x25
from aegisflight.sources.mavlink_serial import (
    MAX_FRAME_BYTES,
    MavlinkStreamFramer,
    SerialMavlinkTransport,
)

pytest.importorskip("serial", reason="pyserial not installed (pip install 'aegisflight[serial]')")

# --------------------------------------------------------------------------- #
# frame builders
# --------------------------------------------------------------------------- #


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, 12, 0x80, 0, 4).pack(m))


def att(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


def gpi(seq: int = 0, sysid: int = 3) -> bytes:
    m = _mk(sysid, 1, seq)
    return bytes(m.global_position_int_encode(1000, 473977418, 85455940, 488000, 12000,
                                              10, -20, 30, 9000).pack(m))


def v1_hb(seq: int = 0) -> bytes:
    m = _mk(2, 5, seq, dialect=mav1)
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def signed_hb(seq: int = 0) -> bytes:
    m = _mk(3, 1, seq)
    m.signing.secret_key = bytes(32)
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1000
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def raw_v2(msgid: int, payload: bytes = b"\x01\x02\x03", seq: int = 0, sysid: int = 3,
           crc_extra: int | None = None) -> bytes:
    """Hand-built MAVLink 2 frame; CRC valid only if ``crc_extra`` is given."""
    head = bytes([0xFD, len(payload), 0, 0, seq, sysid, 1]) + msgid.to_bytes(3, "little")
    body = head + payload
    if crc_extra is None:
        return body + b"\xaa\xbb"
    return body + _x25(bytes([crc_extra]), _x25(body[1:])).to_bytes(2, "little")


def frame_stream(n: int) -> list[bytes]:
    makers = (hb, att, gpi)
    return [makers[i % 3](i % 256) for i in range(n)]


def unknown_v1_id() -> int:
    from aegisflight.sources.mavlink_live import _load_dialect

    known = _load_dialect().mavlink_map
    return next(i for i in range(256) if i not in known)


# --------------------------------------------------------------------------- #
# MavlinkStreamFramer
# --------------------------------------------------------------------------- #


def test_framer_whole_frame_roundtrip():
    f = MavlinkStreamFramer()
    fr = hb(5)
    assert f.feed(fr) == [fr]
    assert (f.frames_out, f.garbage_bytes, f.crc_rejects, f.pending_bytes) == (1, 0, 0, 0)


def test_framer_partial_frame_waits_then_completes_byte_by_byte():
    f = MavlinkStreamFramer()
    fr = gpi(9)
    got: list[bytes] = []
    for i, b in enumerate(fr):
        out = f.feed(bytes([b]))
        if i < len(fr) - 1:
            assert out == [] and f.pending_bytes == i + 1
        got += out
    assert got == [fr] and f.pending_bytes == 0 and f.garbage_bytes == 0


def test_framer_multiple_mixed_frames_in_one_read():
    frames = [hb(0), v1_hb(1), signed_hb(2), att(3), gpi(4)]
    assert len(frames[2]) == len(hb()) + 13  # signed: 13-byte signature counted in the length
    f = MavlinkStreamFramer()
    assert f.feed(b"".join(frames)) == frames
    assert f.pending_bytes == 0 and f.crc_rejects == 0 and f.garbage_bytes == 0


def test_framer_garbage_prefix_and_between_frames_resyncs_and_counts():
    a, b = hb(1), att(2)
    f = MavlinkStreamFramer()
    out = f.feed(b"\x01\x02\x03" + a + b"\x00" * 5 + b)
    assert out == [a, b]
    assert f.garbage_bytes == 8
    assert f.resync_events == 2  # one per garbage RUN, not per byte
    assert f.crc_rejects == 0


def test_framer_false_magic_does_not_swallow_following_frames():
    """A stray 0xFD claiming a 200-byte payload must not eat the real frames behind it."""
    real = [att(i) for i in range(8)]  # 8 * 40 bytes > the 212-byte false candidate
    f = MavlinkStreamFramer()
    out = f.feed(bytes([0xFD, 200, 0, 0]) + b"".join(real))
    assert out == real
    assert f.crc_rejects >= 1 and f.garbage_bytes >= 4


def test_framer_stale_false_candidate_is_broken_by_flush():
    real = [hb(0), hb(1)]
    f = MavlinkStreamFramer()
    assert f.feed(bytes([0xFD, 200, 0, 0]) + b"".join(real)) == []  # still waiting for 212 bytes
    assert f.pending_bytes > 0
    assert f.flush_stale() == real
    assert f.partial_timeouts == 1 and f.pending_bytes == 0
    assert f.flush_stale() == [] and f.partial_timeouts == 1  # nothing pending: no-op


def test_framer_corrupt_crc_frame_dropped_next_frame_recovered():
    bad = bytearray(hb(1))
    bad[-1] ^= 0xFF
    good = att(2)
    f = MavlinkStreamFramer()
    assert f.feed(bytes(bad) + good) == [good]
    assert f.crc_rejects == 1


def test_framer_unknown_incompat_flags_dropped():
    bad = bytearray(hb(1))
    bad[2] = 0x02  # unknown incompat flag
    good = hb(2)
    f = MavlinkStreamFramer()
    assert f.feed(bytes(bad) + good) == [good]


def test_framer_unknown_ids_header_sanity_only():
    f = MavlinkStreamFramer()
    ok = raw_v2(60001)  # v2, sysid 3: accepted on header sanity (CRC not verifiable)
    assert f.feed(ok) == [ok]
    assert f.feed(raw_v2(60001, sysid=0)) == []  # sysid 0 refused
    v1 = bytes([0xFE, 3, 0, 3, 1, unknown_v1_id()]) + b"\x01\x02\x03" + b"\xaa\xbb"
    assert f.feed(v1) == []  # every v1 id is in the dialect: an unknown one is garbage
    assert f.feed(raw_v2(0x030000)) == []  # id above 0xFFFF: implausible, never a real message
    bad_compid = bytearray(raw_v2(60001))
    bad_compid[6] = 0
    assert f.feed(bytes(bad_compid)) == []
    bad_compat = bytearray(raw_v2(60001))
    bad_compat[3] = 1
    assert f.feed(bytes(bad_compat)) == []


def test_framer_extra_crc_makes_unknown_id_verifiable():
    f = MavlinkStreamFramer(extra_crc={60001: 77})
    good = raw_v2(60001, crc_extra=77)
    assert f.feed(good) == [good]
    assert f.feed(raw_v2(60001, crc_extra=78)) == []  # wrong crc_extra: rejected
    assert f.crc_rejects >= 1


def test_framer_chunking_invariance_random_splits():
    rng = random.Random(7)
    frames = frame_stream(60)
    stream = b"".join(frames[:20]) + b"\x13\x37" + b"".join(frames[20:])
    whole = MavlinkStreamFramer().feed(stream)
    assert whole == frames
    for _ in range(30):
        f, out, i = MavlinkStreamFramer(), [], 0
        while i < len(stream):
            n = rng.randint(1, 97)
            out += f.feed(stream[i : i + n])
            i += n
        assert out == frames and f.pending_bytes == 0


def test_framer_fuzz_never_raises_and_memory_stays_bounded():
    rng = random.Random(1234)
    magic_heavy = bytes([0xFD, 0xFE, 0xFD, 0xFD, 0xFF, 0x00, 0x01, 0xC8])
    f = MavlinkStreamFramer()
    for _ in range(400):
        chunk = bytes(rng.choice(magic_heavy) if rng.random() < 0.6 else rng.randrange(256)
                      for _ in range(rng.randint(0, 600)))
        f.feed(chunk)
        assert f.pending_bytes < MAX_FRAME_BYTES
    f.flush_stale()
    assert f.pending_bytes < MAX_FRAME_BYTES


def test_framer_reset_drops_partial_and_reports_size():
    f = MavlinkStreamFramer()
    f.feed(hb(0)[:7])
    assert f.pending_bytes == 7
    assert f.reset() == 7 and f.pending_bytes == 0
    fr = hb(1)
    assert f.feed(fr) == [fr]


def test_framer_output_is_clean_input_for_the_existing_parser():
    frames = frame_stream(30)
    f = MavlinkStreamFramer()
    out = f.feed(b"\x00\x01" + b"".join(frames[:15]) + b"\xfd\xc8\x00" + b"".join(frames[15:]))
    assert out == frames
    p = MavlinkFrameParser()
    envs = [e for fr in out for e in p.parse(fr, 0.0)]
    assert len(envs) == 30 and p.stats.bad_frames == 0
    assert [e.seq for e in envs] == [i % 256 for i in range(30)]


# --------------------------------------------------------------------------- #
# transport helpers
# --------------------------------------------------------------------------- #


def wait_for(pred, timeout: float = 5.0, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def collect(tr: SerialMavlinkTransport, n: int, timeout: float = 5.0) -> list[tuple[int, bytes]]:
    got: list[tuple[int, bytes]] = []
    wait_for(lambda: (got.extend(tr.poll()), len(got) >= n)[1], timeout, f"{n} frames")
    return got


class FakePort:
    """Scripted serial port. Script items: bytes (one read returns them), None (timeout),
    or an Exception (raised by read). An empty script behaves like an idle line (timeouts)."""

    def __init__(self, script: list | None = None) -> None:
        self.script = list(script or [])
        self.lock = threading.Lock()
        self.closed = False
        self.written: list[bytes] = []
        self.fail_write: Exception | None = None

    def push(self, *items) -> None:
        with self.lock:
            self.script.extend(items)

    @property
    def in_waiting(self) -> int:
        with self.lock:
            return len(self.script[0]) if self.script and isinstance(self.script[0], bytes) else 0

    def read(self, size: int = 1) -> bytes:
        with self.lock:
            item = self.script.pop(0) if self.script else None
        if isinstance(item, BaseException):
            raise item
        if item is None:
            time.sleep(0.002)
            return b""
        if len(item) > size:
            with self.lock:
                self.script.insert(0, item[size:])
            return item[:size]
        return item

    def write(self, data: bytes) -> int:
        if self.fail_write is not None:
            raise self.fail_write
        self.written.append(data)
        return len(data)

    def close(self) -> None:
        self.closed = True


def make_tr(ports: list, **kw) -> tuple[SerialMavlinkTransport, list[int]]:
    """Transport whose factory hands out ``ports`` in order (an Exception item = open fails)."""
    calls = [0]
    it = iter(ports)
    lock = threading.Lock()

    def factory():
        with lock:
            calls[0] += 1
            item = next(it, OSError("no more ports"))
        if isinstance(item, BaseException):
            raise item
        return item

    kw.setdefault("reconnect_interval_s", 0.01)
    return SerialMavlinkTransport("FAKE", serial_factory=factory, **kw), calls


# --------------------------------------------------------------------------- #
# transport: framing, stamps, counters
# --------------------------------------------------------------------------- #


def test_transport_delivers_whole_frames_from_fragments_and_bursts():
    frames = frame_stream(9)
    blob = b"".join(frames)
    port = FakePort([blob[:5], blob[5:61], blob[61:62], blob[62:]])
    tr, _ = make_tr([port])
    with tr:
        got = collect(tr, 9)
    assert [d for _, d in got] == frames
    assert tr.datagrams_received == 9 and tr.bytes_received == len(blob)
    assert tr.reads >= 4 and tr.garbage_bytes == 0 and tr.crc_rejects == 0


def test_transport_stamps_are_per_completing_read_and_monotonic():
    a, b, c = hb(0), att(1), gpi(2)
    ticker = itertools.count(1_000_000, 1_000_000)
    port = FakePort([a + b, c[:10], c[10:]])  # a,b complete in read 1; c in read 3
    tr, _ = make_tr([port], clock_ns=lambda: next(ticker))
    with tr:
        got = collect(tr, 3)
    stamps = [s for s, _ in got]
    assert stamps[0] == stamps[1]  # same read -> same stamp (burst spacing is NOT recoverable)
    assert stamps[2] > stamps[1]  # completed by a later read -> later stamp
    assert tr.max_frames_per_read == 2


def test_transport_garbage_is_counted_and_resynced():
    a, b = hb(1), att(2)
    port = FakePort([b"\x00\x01\x02" + a, b"\xaa" * 7 + b])
    tr, _ = make_tr([port])
    with tr:
        got = collect(tr, 2)
    assert [d for _, d in got] == [a, b]
    assert tr.garbage_bytes == 10 and tr.resync_events == 2


def test_transport_stale_partial_is_flushed_after_timeout():
    real = [hb(0), hb(1)]
    port = FakePort([bytes([0xFD, 200, 0, 0]) + b"".join(real)])  # false 212-byte candidate, then idle
    tr, _ = make_tr([port], partial_timeout_s=0.05)
    with tr:
        got = collect(tr, 2)
    assert [d for _, d in got] == real
    assert tr.partial_timeouts == 1


def test_transport_bounded_queue_counts_overflow_and_releases_byte_budget():
    frames = frame_stream(20)
    port = FakePort([b"".join(frames)])
    tr, _ = make_tr([port], queue_size=5)
    with tr:
        wait_for(lambda: tr.datagrams_received == 20, what="20 frames read")
        assert tr.dropped_overflow == 15 and tr.queue_high_water == 5
        assert tr.dropped_overflow_bytes == sum(len(f) for f in frames[5:])
        got = tr.poll()
    assert [d for _, d in got] == frames[:5]  # the NEWEST frames are the ones dropped
    assert tr._queued_bytes == 0

    port2 = FakePort([b"".join(frames)])
    tr2, _ = make_tr([port2], max_queue_bytes=100)
    with tr2:
        wait_for(lambda: tr2.datagrams_received == 20, what="20 frames read")
        kept = tr2.poll()
    assert sum(len(d) for _, d in kept) <= 100 and tr2.dropped_overflow == 20 - len(kept)
    assert tr2._queued_bytes == 0


def test_transport_stats_dict_is_complete_and_honest_about_scope():
    tr, _ = make_tr([FakePort([hb(0)])])
    with tr:
        collect(tr, 1)
    s = tr.stats
    for key in ("connected", "bytes_received", "garbage_bytes", "resync_events", "crc_rejects",
                "partial_timeouts", "dropped_overflow", "queue_high_water", "max_poll_gap_s",
                "disconnects", "reconnects", "open_failures", "last_error"):
        assert key in s
    assert not any("kernel" in k or "os_drop" in k or "lost" in k for k in s)  # no pretend loss counter


# --------------------------------------------------------------------------- #
# transport: open failure, disconnect, reconnect, shutdown
# --------------------------------------------------------------------------- #


def test_transport_disconnect_discards_partial_and_reconnects():
    first, second = hb(1), att(2)
    p1 = FakePort([first, gpi(3)[:15], OSError("device unplugged")])
    p2 = FakePort([second])
    tr, calls = make_tr([p1, p2])
    with tr:
        got = collect(tr, 2)
        assert [d for _, d in got] == [first, second]  # the cut-off gpi(3) is NOT glued to anything
        wait_for(lambda: tr.connected, what="reconnected")
    assert tr.disconnects == 1 and tr.reconnects == 1 and calls[0] == 2
    assert tr.discarded_on_disconnect_bytes == 15
    assert "device unplugged" in (tr.last_error or "")
    assert p1.closed and p2.closed


def test_transport_start_with_missing_port_retries_until_it_appears():
    fr = hb(4)
    tr, calls = make_tr([OSError("no such device"), OSError("still no"), FakePort([fr])])
    tr.start()  # reconnect=True: does not raise
    try:
        got = collect(tr, 1)
        assert [d for _, d in got] == [fr]
        assert tr.open_failures == 2 and tr.connected
    finally:
        tr.close()


def test_transport_reconnect_disabled_fails_fast_and_stays_down():
    tr, calls = make_tr([OSError("nope")], reconnect=False)
    with pytest.raises(RuntimeError, match="cannot open serial port"):
        tr.start()
    tr.close()

    p = FakePort([hb(0), OSError("gone")])
    tr2, calls2 = make_tr([p], reconnect=False)
    with tr2:
        collect(tr2, 1)
        wait_for(lambda: tr2.disconnects == 1, what="disconnect")
        time.sleep(0.1)
        assert not tr2.connected and calls2[0] == 1  # never reopened
        assert tr2._thread is not None and not tr2._thread.is_alive()


def test_transport_survives_repeated_disconnect_cycles():
    ports = [FakePort([hb(i), OSError(f"drop {i}")]) for i in range(4)] + [FakePort([att(9)])]
    tr, _ = make_tr(ports)
    with tr:
        got = collect(tr, 5)
    assert len(got) == 5 and tr.disconnects == 4 and tr.reconnects == 4


def test_transport_close_is_prompt_idempotent_and_releases_the_port():
    port = FakePort()  # idle line
    tr, _ = make_tr([port])
    tr.start()
    thread = tr._thread
    t0 = time.monotonic()
    tr.close()
    tr.close()
    assert time.monotonic() - t0 < 1.5
    assert port.closed and thread is not None and not thread.is_alive()
    assert tr.poll() == [] and tr.send(b"x") is False
    tr.start()  # start after close is a no-op, not a resurrection
    assert tr._thread is thread


def test_transport_close_interrupts_a_long_reconnect_wait():
    tr, _ = make_tr([OSError("down")], reconnect_interval_s=60.0)
    tr.start()
    time.sleep(0.05)
    t0 = time.monotonic()
    tr.close()
    assert time.monotonic() - t0 < 1.5


def test_transport_send_writes_and_reports_failures():
    port = FakePort()
    tr, _ = make_tr([port])
    with tr:
        assert tr.send(b"\xfd\x00") is True
        assert port.written == [b"\xfd\x00"] and tr.bytes_sent == 2
        port.fail_write = OSError("write failed")
        assert tr.send(b"zz") is False and tr.write_errors == 1
    assert tr.send(b"late") is False


def test_transport_rejects_bad_arguments():
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", baudrate=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", read_timeout_s=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", queue_size=0)
    with pytest.raises(ValueError):
        SerialMavlinkTransport("x", max_queue_bytes=0)


def test_transport_poll_gap_tracks_consumer_stalls():
    tr, _ = make_tr([FakePort()])
    with tr:
        tr.poll()
        time.sleep(0.12)
        tr.poll()
    assert tr.max_poll_gap_s >= 0.1


# --------------------------------------------------------------------------- #
# integration with the unchanged LiveMavlinkSource
# --------------------------------------------------------------------------- #


def test_live_source_runs_unchanged_over_the_serial_transport():
    frames = [hb(0), att(1), gpi(2)] * 5
    port = FakePort([b"".join(frames)])
    tr, _ = make_tr([port])
    src = LiveMavlinkSource(tr, sample_rate_hz=10.0, max_ticks=4)
    try:
        ticks = list(src.stream())
    finally:
        src.close()
    names = [m.msgname for t in ticks for m in t.messages]
    assert names.count("HEARTBEAT") == 5 and names.count("ATTITUDE") == 5
    assert names.count("GLOBAL_POSITION_INT") == 5
    st = src.stats
    assert st["bad_frames"] == 0 and st["dropped_overflow"] == 0 and "queue_high_water" in st


# --------------------------------------------------------------------------- #
# REAL pyserial over a virtual port: socket:// (portable)
# --------------------------------------------------------------------------- #


class VirtualPortServer:
    """Loopback TCP server that plays the 'device' end of a ``socket://`` serial port."""

    def __init__(self) -> None:
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.srv.settimeout(0.05)
        self.port = self.srv.getsockname()[1]
        self.conn: socket.socket | None = None
        self.received = bytearray()
        self.accepted = 0
        self._stop = threading.Event()
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    @property
    def url(self) -> str:
        return f"socket://127.0.0.1:{self.port}"

    def _run(self) -> None:
        while not self._stop.is_set():
            if self.conn is None:
                try:
                    self.conn, _ = self.srv.accept()
                    self.conn.settimeout(0.02)
                    self.accepted += 1
                except OSError:
                    continue
            try:
                data = self.conn.recv(4096)
                if data:
                    self.received += data
                else:
                    self.conn = None
            except TimeoutError:
                pass
            except OSError:
                self.conn = None

    def wait_connected(self) -> None:
        wait_for(lambda: self.conn is not None, what="client connected")

    def send(self, data: bytes, chunk: int | None = None, delay: float = 0.0) -> None:
        self.wait_connected()
        assert self.conn is not None
        if chunk is None:
            self.conn.sendall(data)
            return
        for i in range(0, len(data), chunk):
            self.conn.sendall(data[i : i + chunk])
            time.sleep(delay)

    def drop_client(self) -> None:
        self.wait_connected()
        c, self.conn = self.conn, None
        assert c is not None
        c.close()

    def close(self) -> None:
        self._stop.set()
        self._th.join(timeout=2)
        for s in (self.conn, self.srv):
            if s is not None:
                s.close()


@pytest.fixture
def vport():
    s = VirtualPortServer()
    yield s
    s.close()


def test_virtual_port_fragmented_stream_is_reassembled(vport):
    frames = frame_stream(12)
    tr = SerialMavlinkTransport(vport.url, reconnect_interval_s=0.02)
    with tr:
        vport.send(b"".join(frames), chunk=7, delay=0.001)
        got = collect(tr, 12, timeout=10)
    assert [d for _, d in got] == frames
    assert tr.garbage_bytes == 0 and tr.crc_rejects == 0 and tr.reads > 12


def test_virtual_port_garbage_burst_and_resync(vport):
    a, b, c = hb(1), att(2), gpi(3)
    tr = SerialMavlinkTransport(vport.url)
    with tr:
        vport.send(b"\x00\x11\x22" + a + bytes([0xFD, 120, 0, 0]) + b + c + b"\xee\xee" + a)
        got = collect(tr, 4, timeout=10)
    assert [d for _, d in got] == [a, b, c, a]
    assert tr.resync_events >= 2 and tr.garbage_bytes >= 9


def test_virtual_port_peer_close_then_reconnect(vport):
    a, b = hb(1), att(2)
    tr = SerialMavlinkTransport(vport.url, reconnect_interval_s=0.05)
    with tr:
        vport.send(a)
        collect(tr, 1)
        vport.send(gpi(5)[:9])  # leave a partial frame on the wire
        wait_for(lambda: tr.bytes_received >= len(a) + 9, what="partial received")
        vport.drop_client()
        wait_for(lambda: tr.disconnects >= 1, what="disconnect noticed")
        wait_for(lambda: tr.connected and vport.accepted >= 2, what="reconnect")
        vport.send(b)
        got = collect(tr, 1)
    assert got[0][1] == b  # the cut-off gpi never leaks into the new session
    assert tr.reconnects >= 1 and tr.discarded_on_disconnect_bytes == 9


def test_virtual_port_send_reaches_the_device(vport):
    tr = SerialMavlinkTransport(vport.url)
    with tr:
        vport.wait_connected()
        assert tr.send(b"hello-fc")
        wait_for(lambda: bytes(vport.received) == b"hello-fc", what="device received write")


def test_virtual_port_unreachable_with_reconnect_disabled_raises():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here now
    tr = SerialMavlinkTransport(f"socket://127.0.0.1:{port}", reconnect=False)
    with pytest.raises(RuntimeError, match="cannot open serial port"):
        tr.start()
    tr.close()


# --------------------------------------------------------------------------- #
# REAL pyserial over a PTY pair (POSIX only; skipped on Windows)
# --------------------------------------------------------------------------- #

posix_pty = pytest.mark.skipif(sys.platform == "win32",
                               reason="PTY pairs do not exist on Windows; socket:// tests cover "
                                      "the same transport paths there")


@pytest.fixture
def pty_pair():
    import pty
    import tty

    master, slave = pty.openpty()
    tty.setraw(slave)
    name = os.ttyname(slave)
    yield master, slave, name
    for fd in (master, slave):
        try:
            os.close(fd)
        except OSError:
            pass


@posix_pty
def test_pty_fragments_bursts_and_garbage(pty_pair):
    master, _slave, name = pty_pair
    frames = frame_stream(10)
    blob = b"\x00\x01" + b"".join(frames[:5]) + b"\xfd\xc8\x00" + b"".join(frames[5:])
    tr = SerialMavlinkTransport(name, baudrate=115200)
    with tr:
        for i in range(0, len(blob), 11):
            os.write(master, blob[i : i + 11])
            time.sleep(0.002)
        got = collect(tr, 10, timeout=10)
    assert [d for _, d in got] == frames
    assert tr.resync_events >= 2


def _read_ready(fd: int) -> bytes:
    import select

    r, _, _ = select.select([fd], [], [], 0.05)
    return os.read(fd, 64) if r else b""


@posix_pty
def test_pty_send_reaches_the_other_end(pty_pair):
    master, _slave, name = pty_pair
    tr = SerialMavlinkTransport(name)
    with tr:
        assert tr.send(b"ping")
        wait_for(lambda: _read_ready(master) == b"ping", what="master received write")


@posix_pty
def test_pty_device_disappearing_is_a_disconnect_not_a_crash(pty_pair):
    master, slave, name = pty_pair
    a = hb(1)
    tr = SerialMavlinkTransport(name, reconnect=False)
    with tr:
        os.write(master, a)
        collect(tr, 1)
        os.close(master)  # the 'USB cable' is pulled
        os.close(slave)
        wait_for(lambda: tr.disconnects >= 1, what="disconnect noticed")
        assert not tr.connected and tr.last_error
