"""Live MAVLink source: header-first frame decode, tick bucketing, UDP transport.

Everything here runs without PX4. Frames are synthetic (built with pymavlink's
dialects or hand-assembled), time is injected (fake clock / fake sleep), and the
UDP tests use loopback sockets on ephemeral ports. One optional test replays the
recorded PX4 SITL capture ``data/sitl/raw/benign_001.tlog`` (skipped if absent).
"""

from __future__ import annotations

import random
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope
from aegisflight.external.tlog_adapter import tlog_ticks
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.sources.mavlink_live import (
    LiveMavlinkSource,
    LiveStats,
    MavlinkFrameParser,
    UdpMavlinkTransport,
    _loopback_only,
    _x25,
    decode_px4_mode,
    frame_ticks,
    send_setup_signing,
)

REPO = Path(__file__).resolve().parents[2]
TLOG = REPO / "data" / "sitl" / "raw" / "benign_001.tlog"

# --------------------------------------------------------------------------- #
# synthetic frame builders
# --------------------------------------------------------------------------- #


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb(seq: int = 0, sysid: int = 3, compid: int = 1, custom_mode: int = 0) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, 12, 0x80, custom_mode, 4).pack(m))


def gpi(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(
        m.global_position_int_encode(1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000)
        .pack(m)
    )


def att(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


def raw_v2(msgid: int, payload: bytes = b"\x01\x02\x03", seq: int = 0, sysid: int = 3,
           compid: int = 1, signed: bool = False) -> bytes:
    """Hand-built MAVLink 2 frame (CRC is not verifiable for ids we do not know)."""
    inc = 1 if signed else 0
    head = bytes([0xFD, len(payload), inc, 0, seq, sysid, compid]) + msgid.to_bytes(3, "little")
    frame = head + payload + b"\xaa\xbb"
    if signed:
        frame += bytes(range(13))
    return frame


def signed_hb(seq: int = 0) -> bytes:
    m = _mk(3, 1, seq)
    m.signing.secret_key = bytes(32)
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1000
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def v1_hb(seq: int = 0, sysid: int = 2, compid: int = 5) -> bytes:
    m = _mk(sysid, compid, seq, dialect=mav1)
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


# --------------------------------------------------------------------------- #
# header-first decode
# --------------------------------------------------------------------------- #


def test_known_messages_decode_fields_and_header():
    p = MavlinkFrameParser()
    out = p.parse(hb(7, custom_mode=0x040000) + gpi(8) + att(9), 1.5)
    assert [e.msgname for e in out] == ["HEARTBEAT", "GLOBAL_POSITION_INT", "ATTITUDE"]
    assert [e.seq for e in out] == [7, 8, 9]
    assert {(e.sysid, e.compid) for e in out} == {(3, 1)}
    assert all(e.recv_time == 1.5 and not e.signed for e in out)
    assert out[0].fields["custom_mode"] == 0x040000  # raw, not translated
    assert out[1].fields["lat"] == 473977418
    assert out[0].msgid == 0 and out[1].msgid == 33 and out[2].msgid == 30
    assert out[0].byte_len == len(hb())
    assert p.stats.frames_received == 3 and p.stats.bad_frames == 0


def test_unknown_msgid_is_header_decoded_not_source_zero():
    p = MavlinkFrameParser()
    (e,) = p.parse(raw_v2(290, seq=41), 0.0)
    assert (e.sysid, e.compid) == (3, 1)  # NOT 0/0 like pymavlink's UNKNOWN_n
    assert e.msgid == 290 and e.msgname == "MSG_290" and e.fields == {}
    assert e.seq == 41 and e.byte_len == 10 + 3 + 2
    (e2,) = p.parse(raw_v2(0x1FFFF, payload=b""), 0.0)  # 3-byte msgid fully used
    assert e2.msgid == 0x1FFFF and e2.msgname == "MSG_131071"


def test_mavlink1_frame():
    p = MavlinkFrameParser()
    f = v1_hb(seq=9, sysid=2, compid=5)
    assert f[0] == 0xFE
    (e,) = p.parse(f, 0.0)
    assert (e.sysid, e.compid, e.seq, e.msgname, e.signed) == (2, 5, 9, "HEARTBEAT", False)
    assert e.byte_len == len(f)


def test_signed_flag_and_total_length():
    p = MavlinkFrameParser()
    sf = signed_hb(seq=4)
    assert sf[2] & 1 and len(sf) == 10 + 9 + 2 + 13
    # signed frame sandwiched between unsigned ones: framing must stay aligned
    out = p.parse(hb(3) + sf + hb(5), 0.0)
    assert [e.seq for e in out] == [3, 4, 5]
    assert [e.signed for e in out] == [False, True, False]
    assert out[1].msgname == "HEARTBEAT" and out[1].byte_len == len(sf)
    # dummy signature on an unknown id
    (u,) = p.parse(raw_v2(411, signed=True), 0.0)
    assert u.signed and u.byte_len == 10 + 3 + 2 + 13


def test_multi_frame_datagram_and_order():
    p = MavlinkFrameParser()
    frames = [hb(1), raw_v2(380, seq=2), att(3), v1_hb(4), gpi(5)]
    out = p.parse(b"".join(frames), 2.0)
    assert [e.seq for e in out] == [1, 2, 3, 4, 5]
    assert p.stats.datagrams_received == 1 and p.stats.frames_received == 5


def test_truncated_and_garbage_datagrams_never_raise():
    p = MavlinkFrameParser()
    good = hb(1)
    assert p.parse(good[:-3], 0.0) == []  # truncated tail
    assert p.stats.bad_frames == 1
    assert p.parse(good[:5], 0.0) == []  # truncated header
    assert p.stats.bad_frames == 2
    out = p.parse(good + good[:-1], 0.0)  # good then truncated
    assert len(out) == 1 and p.stats.bad_frames == 3
    out = p.parse(b"\x00\x01\x02" + good, 0.0)  # leading junk resyncs on the magic
    assert len(out) == 1 and p.stats.bad_frames == 4
    assert p.parse(b"", 0.0) == []
    assert p.parse(b"\xfd", 0.0) == [] and p.stats.bad_frames == 5


def test_bad_crc_on_known_message_is_bad_frame():
    p = MavlinkFrameParser()
    f = bytearray(hb(1))
    f[-1] ^= 0xFF
    assert p.parse(bytes(f), 0.0) == []
    assert p.stats.bad_frames == 1
    # the next valid frame still parses
    assert len(p.parse(hb(2), 0.0)) == 1


def test_random_garbage_fuzz_never_raises():
    rng = random.Random(1234)
    p = MavlinkFrameParser()
    base = hb(1) + raw_v2(290) + gpi(2)
    for _ in range(400):
        n = rng.randrange(0, 80)
        junk = bytes(rng.randrange(256) for _ in range(n))
        mutated = bytearray(base)
        for _ in range(rng.randrange(0, 6)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        p.parse(junk, 0.0)
        p.parse(bytes(mutated), 0.0)
        p.parse(base[: rng.randrange(len(base))], 0.0)


def test_px4_mode_decode():
    assert decode_px4_mode(0x010000) == "MANUAL"
    assert decode_px4_mode(0x030000) == "POSCTL"
    assert decode_px4_mode(0x040000 | (2 << 24)) == "AUTO/TAKEOFF"
    assert decode_px4_mode((4 << 16) | (3 << 24)) == "AUTO/LOITER"
    assert decode_px4_mode((4 << 16) | (6 << 24)) == "AUTO/LAND"
    assert decode_px4_mode(6 << 16) == "OFFBOARD"
    assert decode_px4_mode(99 << 16) == "MAIN_99"
    assert decode_px4_mode((4 << 16) | (77 << 24)) == "AUTO/77"


# --------------------------------------------------------------------------- #
# tick semantics, data-driven (iterable of (recv_time, frame))
# --------------------------------------------------------------------------- #


def _seqs(tick) -> list[int]:
    return [m.seq for m in tick.messages]


def test_bucket_boundaries_half_open_on_left():
    frames = [(0.05, hb(1)), (0.10, hb(2)), (0.15, hb(3))]
    ticks = list(frame_ticks(frames, 10.0, origin_s=0.0))
    assert [t.tick for t in ticks] == [0, 1, 2]
    assert _seqs(ticks[0]) == []
    assert _seqs(ticks[1]) == [1, 2]  # 0.10 belongs to tick 1 ((0, 0.1]), not tick 2
    assert _seqs(ticks[2]) == [3]
    assert ticks[1].t == pytest.approx(0.1) and ticks[2].t == pytest.approx(0.2)


def test_default_origin_is_first_frame_arrival():
    base = 1_700_000_000.123456
    frames = [(base, hb(1)), (base + 0.05, hb(2)), (base + 0.1, hb(3))]
    ticks = list(frame_ticks(frames, 10.0))
    assert _seqs(ticks[0]) == [1]  # first frame is at rel 0 -> tick 0
    assert _seqs(ticks[1]) == [2, 3]
    rel = [m.recv_time for t in ticks for m in t.messages]
    assert rel == pytest.approx([0.0, 0.05, 0.1], abs=1e-9)  # rebased to the first frame


def test_gap_in_data_yields_empty_ticks():
    frames = [(0.0, hb(1)), (1.05, hb(2))]
    ticks = list(frame_ticks(frames, 10.0))
    assert [t.tick for t in ticks] == list(range(12))
    assert [len(t.messages) for t in ticks] == [1] + [0] * 10 + [1]


def test_out_of_order_seq_duplicates_and_arrival_order_preserved():
    frames = [(0.01, hb(10)), (0.02, hb(12)), (0.03, hb(11)), (0.04, hb(11)), (0.05, hb(13))]
    (tick0, tick1) = list(frame_ticks(frames, 10.0, origin_s=0.0))[:2]
    assert _seqs(tick0) == []
    assert _seqs(tick1) == [10, 12, 11, 11, 13]


def test_unknown_labels_default_to_benign_and_ground_truth_untouched():
    t = next(iter(frame_ticks([(0.0, hb(1))], 10.0)))
    assert t.label == AttackType.BENIGN and t.truth_state is None and t.labels == frozenset()
    t2 = next(iter(frame_ticks([(0.0, hb(1))], 10.0, label_fn=lambda _t: AttackType.GPS_SPOOFING)))
    assert t2.label == AttackType.GPS_SPOOFING


def test_equivalent_to_tlog_ticks_on_same_timestamps():
    rng = random.Random(7)
    stamps: list[int] = []
    t_us = 0
    while len(stamps) < 400:
        t_us += rng.randrange(1, 40_000)
        if t_us % 100_000:
            stamps.append(t_us)
    frames = [(us / 1e6, hb(i % 256)) for i, us in enumerate(stamps)]
    envs = [
        MessageEnvelope(us / 1e6, 3, 1, 0, "HEARTBEAT", i % 256, False, 21)
        for i, us in enumerate(stamps)
    ]
    ours = list(frame_ticks(frames, 10.0, origin_s=0.0))
    ref = list(tlog_ticks(envs, 10.0))
    assert [t.tick for t in ours] == [t.tick for t in ref]
    assert [t.t for t in ours] == [t.t for t in ref]
    assert [_seqs(t) for t in ours] == [_seqs(t) for t in ref]


# --------------------------------------------------------------------------- #
# tick semantics, clock-driven (fake clock + fake sleep, no real time)
# --------------------------------------------------------------------------- #


class FakeClock:
    def __init__(self, start_s: float = 0.0) -> None:
        self.ns = round(start_s * 1e9)
        self.sleeps = 0

    def __call__(self) -> int:
        return self.ns

    def sleep(self, s: float) -> None:
        self.sleeps += 1
        assert s > 0
        self.ns += round(s * 1e9)


class ScriptedTransport:
    """Frames become visible at ``visible_ns`` and carry their own receive stamp."""

    def __init__(self, clock: FakeClock, script) -> None:
        self.clock = clock
        # entries: (stamp_s, frame) or (stamp_s, frame, visible_s)
        self.pending = [
            (round(e[0] * 1e9), e[1], round((e[2] if len(e) > 2 else e[0]) * 1e9)) for e in script
        ]
        self.dropped_overflow = 0
        self.started = False

    def start(self) -> None:
        self.started = True

    def poll(self):
        now = self.clock.ns
        ready = [(s, d) for s, d, v in self.pending if v <= now]
        self.pending = [e for e in self.pending if e[2] > now]
        return ready

    def close(self) -> None:
        pass


def _live(script, clock=None, **kw):
    clock = clock or FakeClock()
    tr = ScriptedTransport(clock, script)
    src = LiveMavlinkSource(tr, clock_ns=clock, sleep=clock.sleep, **kw)
    return src, clock, tr


def test_silent_gap_emits_empty_ticks_from_the_clock():
    # first frame at 0.05 s (origin), next at 1.15 s -> 10 empty ticks in between
    src, clock, tr = _live([(0.05, hb(1)), (1.15, hb(2))], max_ticks=12)
    emitted_at: list[int] = []
    ticks = []
    for t in src.stream():
        ticks.append(t)
        emitted_at.append(clock.ns)
    assert tr.started
    assert [t.tick for t in ticks] == list(range(12))
    assert [len(t.messages) for t in ticks] == [1] + [0] * 10 + [1]
    # an empty tick k is emitted BEFORE the later frame exists: at origin+k*dt (+settle), not
    # when the next packet shows up
    origin = round(0.05 * 1e9)
    for k in range(1, 11):
        rel = (emitted_at[k] - origin) / 1e9
        assert k * 0.1 <= rel < (k + 1) * 0.1, (k, rel)
    assert src.stats["ticks_emitted"] == 12 and src.stats["late_ticks"] == 0
    assert src.stats["frames_received"] == 2


def test_clock_driven_uses_no_real_sleep():
    t0 = time.perf_counter()
    src, _clock, _ = _live([(0.0, hb(1))], max_ticks=100)  # 10 s of link time
    assert len(list(src.stream())) == 100
    assert time.perf_counter() - t0 < 2.0


def test_origin_start_emits_ticks_before_first_frame():
    src, clock, _ = _live([], clock=FakeClock(5.0), origin="start", max_ticks=5)
    ticks = list(src.stream())
    assert [t.tick for t in ticks] == [0, 1, 2, 3, 4]
    assert all(t.messages == [] for t in ticks)
    assert ticks[4].t == pytest.approx(0.4)


def test_origin_first_frame_waits_for_link():
    clock = FakeClock()
    src, _, _ = _live([(2.0, hb(1))], clock=clock, max_ticks=1)
    (tick,) = list(src.stream())
    assert tick.tick == 0 and _seqs(tick) == [1]
    assert clock.ns >= 2_000_000_000  # nothing was emitted before the link came up


def test_slow_consumer_gets_every_tick_and_late_ticks_counted():
    src, clock, _ = _live([(0.05, hb(1)), (0.15, hb(2)), (0.55, hb(3))], max_ticks=8)
    gen = src.stream()
    first = next(gen)
    assert first.tick == 0 and src.stats["late_ticks"] == 0
    clock.ns += round(0.5e9)  # consumer stalls for 0.5 s of link time
    rest = [next(gen) for _ in range(7)]
    all_ticks = [first, *rest]
    assert [t.tick for t in all_ticks] == list(range(8))  # nothing skipped
    assert [_seqs(t) for t in all_ticks][1] == [2]  # bucketed by ARRIVAL, not delivery
    assert _seqs(all_ticks[5]) == [3]
    assert src.stats["late_ticks"] == 4  # ticks 1..4 were emitted after their own period
    assert src.stats["ticks_emitted"] == 8


def test_frame_visible_after_its_tick_closed_is_not_lost():
    # stamped inside tick 1 (rel 0.095) but only handed to us at rel 0.25
    src, _, _ = _live([(0.0, hb(1)), (0.095, hb(2), 0.25)], max_ticks=5)
    ticks = list(src.stream())
    assert [t.tick for t in ticks] == [0, 1, 2, 3, 4]
    assert _seqs(ticks[1]) == []
    carrying = [t.tick for t in ticks if _seqs(t) == [2]]
    assert carrying and carrying[0] > 1
    assert src.stats["late_frames"] == 1
    assert src.stats["frames_received"] == 2
    # recv_time keeps the true arrival (0.095), it is not rewritten
    assert ticks[carrying[0]].messages[0].recv_time == pytest.approx(0.095)


def test_stop_ends_the_stream():
    clock = FakeClock()
    tr = ScriptedTransport(clock, [])
    holder: dict = {}

    def sleep(s: float) -> None:
        clock.sleep(s)
        if clock.ns > 3e9:
            holder["src"].stop()

    src = LiveMavlinkSource(tr, clock_ns=clock, sleep=sleep)
    holder["src"] = src
    assert list(src.stream()) == []  # no link ever came up, still terminates on stop()


def test_pipeline_cadence_with_extractor_is_fixed_during_silence():
    # a silent link must still advance the extractor clock (DoS visibility)
    src, _, _ = _live([(0.0, hb(1)), (0.0, gpi(2))], max_ticks=30)
    fx = FeatureExtractor()
    rates = []
    for tk in src.stream():
        for m in tk.messages:
            fx.update(m)
        rates.append(fx.extract(tk.t).msg_rate_hz)
    assert rates[0] > 0 and rates[-1] == 0.0
    assert src.stats["ticks_emitted"] == 30


# --------------------------------------------------------------------------- #
# UDP transport (loopback only)
# --------------------------------------------------------------------------- #


@pytest.fixture
def udp_ok():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.close()
    except OSError:
        pytest.skip("UDP loopback sockets unavailable")


def _wait(pred, timeout=2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


def test_bind_refuses_wildcard_by_default(udp_ok):
    for host in ("0.0.0.0", ""):
        with pytest.raises(ValueError):
            UdpMavlinkTransport(bind=(host, 0))


def test_bind_default_host_is_loopback_and_requires_exactly_one_mode(udp_ok):
    with UdpMavlinkTransport(bind=(None, 0)) as tr:
        assert tr.local_address[0] == "127.0.0.1"
    with pytest.raises(ValueError):
        UdpMavlinkTransport()
    with pytest.raises(ValueError):
        UdpMavlinkTransport(bind=("127.0.0.1", 0), connect=("127.0.0.1", 9))


def test_loopback_end_to_end_into_ticks(udp_ok):
    n_datagrams = 20
    with UdpMavlinkTransport(bind=("127.0.0.1", 0)) as tr:
        port = tr.local_address[1]

        def send() -> None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(n_datagrams):
                # 2 frames per datagram on even i, one unknown-id frame on odd i
                data = hb(i) + gpi(i) if i % 2 == 0 else raw_v2(290, seq=i)
                s.sendto(data, ("127.0.0.1", port))
                time.sleep(0.01)
            s.close()

        src = LiveMavlinkSource(tr, max_ticks=8)
        th = threading.Thread(target=send)
        t0 = time.monotonic()
        th.start()
        ticks = list(src.stream())
        th.join()
        assert time.monotonic() - t0 < 3.0
        assert [t.tick for t in ticks] == list(range(8))
        msgs = [m for t in ticks for m in t.messages]
        assert len(msgs) == 10 * 2 + 10
        assert {(m.sysid, m.compid) for m in msgs} == {(3, 1)}
        assert [m.seq for m in msgs if m.msgname == "HEARTBEAT"] == list(range(0, 20, 2))
        st = src.stats
        assert st["frames_received"] == 30 and st["bad_frames"] == 0
        assert st["datagrams_received"] == n_datagrams and st["dropped_overflow"] == 0
        assert st["ticks_emitted"] == 8
        # receive timestamps are non-decreasing in arrival order
        rts = [m.recv_time for m in msgs]
        assert rts == sorted(rts)


def test_connect_mode_sends_gcs_heartbeat_and_receives_replies(udp_ok):
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2.0)
    try:
        with UdpMavlinkTransport(connect=("127.0.0.1", peer.getsockname()[1])) as tr:
            data, addr = peer.recvfrom(2048)  # PX4 learns our address from this
            (hbm,) = MavlinkFrameParser().parse(data, 0.0)
            assert hbm.msgname == "HEARTBEAT" and (hbm.sysid, hbm.compid) == (255, 190)
            assert hbm.fields["type"] == mav2.MAV_TYPE_GCS
            peer.sendto(hb(5), addr)
            assert _wait(lambda: tr.datagrams_received >= 1)
            (item,) = tr.poll()
            assert item[1] == hb(5) and isinstance(item[0], int)
            # heartbeats keep advancing their own sequence
            tr.send_heartbeat()
            data2, _ = peer.recvfrom(2048)
            (hb2,) = MavlinkFrameParser().parse(data2, 0.0)
            assert hb2.seq == (hbm.seq + 1) % 256
    finally:
        peer.close()


def test_send_gcs_message_shares_the_heartbeat_sequence_counter(udp_ok):
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2.0)
    try:
        with UdpMavlinkTransport(connect=("127.0.0.1", peer.getsockname()[1]),
                                 gcs_heartbeat=False, gcs_sysid=255, gcs_compid=190) as tr:
            tr.send_heartbeat()
            tr.send_heartbeat()
            ok, seq = tr.send_gcs_message(lambda m: m.command_long_encode(
                1, 1, mav2.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 21196, 0, 0, 0, 0, 0))
            assert ok and seq == 2
            tr.send_heartbeat()
            frames = [MavlinkFrameParser().parse(peer.recvfrom(2048)[0], 0.0)[0] for _ in range(4)]
            assert [f.seq for f in frames] == [0, 1, 2, 3]
            assert [f.msgname for f in frames] == ["HEARTBEAT", "HEARTBEAT", "COMMAND_LONG", "HEARTBEAT"]
            assert all((f.sysid, f.compid) == (255, 190) for f in frames)
    finally:
        peer.close()


def test_bounded_queue_counts_overflow(udp_ok):
    with UdpMavlinkTransport(bind=("127.0.0.1", 0), queue_size=2) as tr:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(12):
            s.sendto(hb(i), tr.local_address)
        s.close()
        assert _wait(lambda: tr.datagrams_received + tr.dropped_overflow >= 12)
        assert tr.dropped_overflow >= 1
        assert len(tr.poll()) <= 2


def test_close_is_clean_and_idempotent(udp_ok):
    tr = UdpMavlinkTransport(bind=("127.0.0.1", 0))
    tr.start()
    threads = list(tr._threads)
    assert threads and all(t.is_alive() for t in threads)
    tr.close()
    tr.close()
    assert not any(t.is_alive() for t in threads)
    assert tr.poll() == []


# --------------------------------------------------------------------------- #
# offline replay of the recorded PX4 SITL capture
# --------------------------------------------------------------------------- #


def _tlog_frames(path: Path):
    data = path.read_bytes()
    i = 0
    while i + 20 <= len(data):
        ts = struct.unpack(">Q", data[i : i + 8])[0]
        f = i + 8
        assert data[f] == 0xFD
        flen = 12 + data[f + 1] + (13 if data[f + 2] & 1 else 0)
        yield ts / 1e6, data[f : f + flen]
        i = f + flen


@pytest.mark.skipif(not TLOG.exists(), reason="SITL capture data/sitl/raw/benign_001.tlog absent")
def test_replay_of_real_px4_capture_has_clean_source_accounting():
    frames = list(_tlog_frames(TLOG))
    assert len(frames) == 35067  # frames recorded in benign_001.json

    stats = LiveStats()
    fx = FeatureExtractor()
    seen: list[MessageEnvelope] = []
    ticks = 0
    sources: set[tuple[int, int]] = set()
    names_unknown = 0
    gaps: list[int] = []
    for tk in frame_ticks(frames, 10.0, stats=stats):
        ticks += 1
        for m in tk.messages:
            fx.update(m)
            seen.append(m)
            sources.add((m.sysid, m.compid))
            names_unknown += m.msgname.startswith("MSG_")
        gaps.append(fx.extract(tk.t).max_seq_gap)
        if tk.tick % 2 == 1:
            fx.clear_window_counts()

    assert len(seen) == len(frames)  # every frame became exactly one envelope
    assert stats.frames_received == 35067 and stats.bad_frames == 0
    assert all(m.sysid != 0 for m in seen)
    assert sources == {(3, 1)}  # no phantom 'rogue source 0/0'
    assert not any(m.signed for m in seen)
    # Any non-zero max_seq_gap must be explained by real arrival-order discontinuities of the
    # single source (UDP reordering / loss), not by UNKNOWN_n frames collapsing into source 0/0.
    prev = None
    breaks = backward = 0
    for m in seen:
        if prev is not None and (m.seq - prev) % 256 != 1:
            breaks += 1
            backward += (m.seq - prev) % 256 >= 128
        prev = m.seq
    assert sum(1 for g in gaps if g) <= breaks
    if max(gaps) == 253:  # == (seq - prev) % 256 - 1 for a depth-2 reorder
        assert backward > 0
    assert names_unknown > 0  # ids outside pymavlink's dialect are kept, header-decoded
    assert all(m.fields == {} for m in seen if m.msgname.startswith("MSG_"))
    # recv_time is rebased to the first frame and arrival-ordered up to link reordering
    assert seen[0].recv_time == 0.0 and seen[-1].recv_time == pytest.approx(103.7, abs=0.2)
    assert ticks == 1038 and stats.late_ticks == 0
    modes = {decode_px4_mode(m.fields["custom_mode"]) for m in seen if m.msgname == "HEARTBEAT"
             and m.fields["type"] != mav2.MAV_TYPE_GCS}
    assert "AUTO/TAKEOFF" in modes or "AUTO/MISSION" in modes or "AUTO/LOITER" in modes


# --------------------------------------------------------------------------- #
# hardening (independent adversarial review): bind policy, peer pinning, bounds,
# unknown-id sanity
# --------------------------------------------------------------------------- #


def _crc_frame_v2(msgid: int, extra: int, payload: bytes = b"\x01\x02\x03", seq: int = 0,
                  sysid: int = 3, compid: int = 1) -> bytes:
    head = bytes([0xFD, len(payload), 0, 0, seq, sysid, compid]) + msgid.to_bytes(3, "little")
    crc = _x25(bytes([extra]), _x25(head[1:] + payload))
    return head + payload + crc.to_bytes(2, "little")


def test_x25_helper_matches_pymavlink_crc():
    f = hb(3)  # HEARTBEAT crc_extra is 50
    assert int.from_bytes(f[-2:], "little") == _x25(bytes([50]), _x25(f[1:-2]))


def test_loopback_policy_accepts_only_loopback_unless_allowed():
    for ok in (None, "127.0.0.1", "127.5.5.5", "::1", "localhost", "LocalHost"):
        assert _loopback_only(ok, False)
    assert _loopback_only(None, False) == "127.0.0.1"
    assert _loopback_only("localhost", False) == "127.0.0.1"
    for bad in ("", "0.0.0.0", "::", "192.168.1.5", "172.29.64.1", "10.0.0.1", "example.com",
                "::ffff:192.168.1.5"):
        with pytest.raises(ValueError):
            _loopback_only(bad, False)
        assert _loopback_only(bad, True) == bad  # explicit opt-in only


def test_bind_to_non_loopback_is_refused_before_touching_the_os(udp_ok):
    with pytest.raises(ValueError):
        UdpMavlinkTransport(bind=("192.0.2.1", 0))
    with pytest.raises(ValueError):
        UdpMavlinkTransport(bind=("172.29.64.1", 0))


def test_connect_target_is_not_restricted(udp_ok):
    # connect= is how we reach the WSL NAT address; a UDP connect() sends nothing
    try:
        tr = UdpMavlinkTransport(connect=("192.0.2.1", 14550), gcs_heartbeat=False)
    except OSError:
        pytest.skip("no route to a non-loopback address on this host")
    tr.close()


def _udp_client() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.3)
    return s


def test_bind_mode_pins_peer_to_first_sender(udp_ok):
    first, second = _udp_client(), _udp_client()
    try:
        with UdpMavlinkTransport(bind=("127.0.0.1", 0)) as tr:
            first.sendto(hb(1), tr.local_address)
            assert _wait(lambda: tr.peer_address == first.getsockname())
            second.sendto(hb(2), tr.local_address)  # must not steal the peer
            assert _wait(lambda: tr.dropped_foreign == 1)
            assert tr.peer_address == first.getsockname()
            assert tr.send(b"reply")
            assert first.recvfrom(64)[0] == b"reply"
            with pytest.raises(TimeoutError):
                second.recvfrom(64)  # nothing reflected to the second sender
            assert [d for _, d in tr.poll()] == [hb(1)]  # foreign datagram not delivered
    finally:
        first.close()
        second.close()


def test_bind_mode_can_follow_last_sender_when_unpinned(udp_ok):
    first, second = _udp_client(), _udp_client()
    try:
        with UdpMavlinkTransport(bind=("127.0.0.1", 0), pin_peer=False) as tr:
            first.sendto(hb(1), tr.local_address)
            assert _wait(lambda: tr.datagrams_received >= 1)
            second.sendto(hb(2), tr.local_address)
            assert _wait(lambda: tr.peer_address == second.getsockname())
            assert tr.send(b"x") and second.recvfrom(64)[0] == b"x"
            assert tr.dropped_foreign == 0 and len(tr.poll()) == 2
    finally:
        first.close()
        second.close()


def test_queue_is_bounded_by_bytes_not_only_datagram_count(udp_ok):
    pad = hb(0) + bytes(980)  # ~1000 B datagram (trailing zeros are junk -> bad frames, fine)
    with UdpMavlinkTransport(bind=("127.0.0.1", 0), queue_size=1000, max_queue_bytes=3000) as tr:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(10):
            s.sendto(pad, tr.local_address)
        assert _wait(lambda: tr.datagrams_received >= 10)
        kept = tr.poll()
        assert 1 <= len(kept) <= 3 and sum(len(d) for _, d in kept) <= 3000
        assert tr.dropped_overflow == 10 - len(kept)
        assert tr.dropped_overflow_bytes == tr.dropped_overflow * len(pad)
        s.sendto(pad, tr.local_address)  # bytes were released by poll(): accepted again
        assert _wait(lambda: tr.datagrams_received >= 11)
        assert len(tr.poll()) == 1
        s.close()


def test_one_datagram_cannot_expand_into_thousands_of_envelopes():
    tiny = raw_v2(290, payload=b"")  # 12-byte frame
    big = tiny * 5000  # 60 000-byte datagram: 5000 envelopes before the cap
    p = MavlinkFrameParser()
    assert len(p.parse(big, 0.0)) == 64  # documented default
    assert p.stats.frames_received == 64 and p.stats.bad_frames == 1  # remainder counted
    p2 = MavlinkFrameParser(max_frames_per_datagram=3)
    assert len(p2.parse(tiny * 3, 0.0)) == 3 and p2.stats.bad_frames == 0  # exactly at the cap
    assert len(p2.parse(tiny * 4, 0.0)) == 3 and p2.stats.bad_frames == 1
    p3 = MavlinkFrameParser()
    assert len(p3.parse(hb(1) * 64, 0.0)) == 64 and p3.stats.bad_frames == 0


def test_unknown_id_header_sanity():
    p = MavlinkFrameParser()
    ok = raw_v2(290)
    assert len(p.parse(ok, 0.0)) == 1 and p.stats.unverified_frames == 1
    bad_compat = bytearray(ok)
    bad_compat[3] = 1  # compat flags must be 0 for frames we cannot CRC-check
    assert p.parse(bytes(bad_compat), 0.0) == []
    assert p.parse(raw_v2(290, sysid=0), 0.0) == []  # sysid 0 is never a valid source
    assert p.stats.bad_frames == 2
    # unknown ids cannot be v1 (pymavlink knows every v1 id); v1 unknown id is refused
    v1_unknown = bytes([0xFE, 1, 0, 3, 1, 251, 9]) + b"\x00\x00"
    assert MavlinkFrameParser().parse(v1_unknown, 0.0) == []
    # known ids keep their existing behaviour (CRC-checked, header otherwise unrestricted)
    assert len(MavlinkFrameParser().parse(hb(1, sysid=0), 0.0)) == 1


def test_extra_crc_verifies_unknown_ids():
    p = MavlinkFrameParser(extra_crc={290: 119})
    good = _crc_frame_v2(290, 119)
    assert len(p.parse(good, 0.0)) == 1 and p.stats.unverified_frames == 0  # verified
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    assert p.parse(bytes(bad), 0.0) == [] and p.stats.bad_frames == 1
    assert len(p.parse(raw_v2(411), 0.0)) == 1  # ids not in the table stay 'unverified'
    assert p.stats.unverified_frames == 1
    # extra_crc never overrides ids the dialect already knows
    assert len(MavlinkFrameParser(extra_crc={0: 1}).parse(hb(1), 0.0)) == 1


def _fuzz_stats(seed: int = 2024, n: int = 20000) -> LiveStats:
    rng = random.Random(seed)
    p = MavlinkFrameParser()
    for _ in range(n):
        d = bytearray(rng.randbytes(rng.randrange(0, 300)))
        for _ in range(rng.randrange(0, 4)):  # sprinkle magic bytes so framing is attempted
            if d:
                d[rng.randrange(len(d))] = rng.choice((0xFD, 0xFE))
        p.parse(bytes(d), 0.0)
    return p.stats


# Before hardening this exact fuzz (seed 2024, 20 000 datagrams, ~3.0 MB) was accepted as
# 1411 'valid' frames, nearly all unknown-id frames that bypass CRC.
_FUZZ_ACCEPTED_BEFORE = 1411
_FUZZ_ACCEPTED_MEASURED = 0  # measured after the fix (deterministic for this seed; 200k datagrams: 8)


def test_fuzz_acceptance_drops_sharply_for_unknown_ids():
    st = _fuzz_stats()
    assert st.frames_received <= _FUZZ_ACCEPTED_MEASURED
    assert st.frames_received * 20 < _FUZZ_ACCEPTED_BEFORE
    assert st.unverified_frames <= st.frames_received


# --------------------------------------------------------------------------- #
# MavlinkFrameParser: optional cryptographic signature verification (P4 scoping)
# --------------------------------------------------------------------------- #

_SECRET = bytes(range(32))  # arbitrary 32-byte MAVLink-2 signing key, deterministic for tests
_GPI_MSGID = 33  # GLOBAL_POSITION_INT


def _signed_raw(encode_fn, key: bytes = _SECRET, *, seq: int = 0, sysid: int = 255, compid: int = 190,
               timestamp: int = 1000, link_id: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    m.signing.secret_key = key
    m.signing.sign_outgoing = True
    m.signing.link_id = link_id
    m.signing.timestamp = timestamp
    return bytes(encode_fn(m).pack(m))


def test_parser_without_key_leaves_signed_bit_only_behaviour_unchanged():
    raw = _signed_raw(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4))
    stats = LiveStats()
    (msg,) = MavlinkFrameParser(stats).parse(raw, 0.0)
    assert msg.signed is True
    assert stats.sig_valid == 0 and stats.sig_invalid == 0  # no key configured -> not checked


def test_parser_with_key_accepts_a_correctly_signed_frame():
    raw = _signed_raw(lambda m: m.global_position_int_encode(
        1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000))
    stats = LiveStats()
    (msg,) = MavlinkFrameParser(stats, secret_key=_SECRET).parse(raw, 0.0)
    assert msg.signed is True and msg.msgname == "GLOBAL_POSITION_INT"
    assert stats.sig_valid == 1 and stats.sig_invalid == 0 and stats.bad_frames == 0


def test_parser_with_key_rejects_wrong_key():
    raw = _signed_raw(lambda m: m.global_position_int_encode(
        1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000), key=_SECRET)
    stats = LiveStats()
    wrong_key = bytes(range(1, 33))
    out = MavlinkFrameParser(stats, secret_key=wrong_key).parse(raw, 0.0)
    assert out == []  # dropped, not emitted
    assert stats.sig_invalid == 1 and stats.sig_valid == 0 and stats.bad_frames == 1


def test_parser_with_key_rejects_an_unsigned_frame_for_a_message_not_on_the_allowlist():
    raw = gpi()  # unsigned GLOBAL_POSITION_INT, not in PX4_UNSIGNED_ALLOWED_MSGIDS
    stats = LiveStats()
    out = MavlinkFrameParser(stats, secret_key=_SECRET).parse(raw, 0.0)
    assert out == []
    # rejected by the signing policy (not allowlisted unsigned) -- counted the same as a bad signature
    assert stats.bad_frames == 1 and stats.sig_valid == 0 and stats.sig_invalid == 1


def test_parser_with_key_still_accepts_an_unsigned_heartbeat_matching_px4s_own_allowlist():
    raw = hb()  # unsigned HEARTBEAT
    stats = LiveStats()
    (msg,) = MavlinkFrameParser(stats, secret_key=_SECRET).parse(raw, 0.0)
    assert msg.msgname == "HEARTBEAT" and msg.signed is False
    assert stats.bad_frames == 0 and stats.sig_valid == 0  # allowlisted: never checked, never counted


def test_parser_with_key_rejects_a_replayed_old_timestamp():
    key = _SECRET
    raw1 = _signed_raw(lambda m: m.global_position_int_encode(
        1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000), key=key, seq=0, timestamp=5000)
    raw2 = _signed_raw(lambda m: m.global_position_int_encode(
        1001, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000), key=key, seq=1, timestamp=4000)
    stats = LiveStats()
    parser = MavlinkFrameParser(stats, secret_key=key)
    assert len(parser.parse(raw1, 0.0)) == 1
    out2 = parser.parse(raw2, 0.0)  # same stream, OLDER timestamp -> pymavlink's own anti-replay check
    assert out2 == []
    assert stats.sig_invalid == 1 and stats.sig_valid == 1


def test_parser_rejects_a_bad_secret_key_length():
    with pytest.raises(ValueError):
        MavlinkFrameParser(secret_key=b"too short")


# --------------------------------------------------------------------------- #
# UdpMavlinkTransport: outgoing signing + SETUP_SIGNING bootstrap (P4 scoping)
# --------------------------------------------------------------------------- #


def test_send_gcs_message_unsigned_by_default_even_with_send_gcs_message():
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2.0)
    try:
        with UdpMavlinkTransport(connect=("127.0.0.1", peer.getsockname()[1]), gcs_heartbeat=False) as tr:
            tr.send_gcs_message(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4))
            raw, _ = peer.recvfrom(2048)
            assert not (raw[2] & 0x01)  # incompat signed bit clear: unchanged default behaviour
    finally:
        peer.close()


def test_enable_signing_makes_subsequent_sends_verifiable_and_advances_timestamp():
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2.0)
    try:
        with UdpMavlinkTransport(connect=("127.0.0.1", peer.getsockname()[1]), gcs_heartbeat=False,
                                 gcs_sysid=255, gcs_compid=190) as tr:
            tr.send_gcs_message(lambda m: m.heartbeat_encode(  # unsigned, before enable_signing
                mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4))
            raw0, _ = peer.recvfrom(2048)
            assert not (raw0[2] & 0x01)

            tr.enable_signing(_SECRET, initial_timestamp=1000)
            tr.send_gcs_message(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4))
            tr.send_gcs_message(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4))
            raw1, _ = peer.recvfrom(2048)
            raw2, _ = peer.recvfrom(2048)
            assert raw1[2] & 0x01 and raw2[2] & 0x01

            stats = LiveStats()
            parser = MavlinkFrameParser(stats, secret_key=_SECRET)
            assert len(parser.parse(raw1, 0.0)) == 1
            assert len(parser.parse(raw2, 0.0)) == 1  # strictly advancing timestamp -> both verify
            assert stats.sig_valid == 2 and stats.sig_invalid == 0
    finally:
        peer.close()


def test_send_setup_signing_goes_out_unsigned_and_carries_the_key():
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2.0)
    try:
        with UdpMavlinkTransport(connect=("127.0.0.1", peer.getsockname()[1]), gcs_heartbeat=False) as tr:
            sent, seq = send_setup_signing(tr, target_sysid=1, target_compid=1, secret_key=_SECRET,
                                           initial_timestamp=4242)
            assert sent and seq == 0
            raw, _ = peer.recvfrom(2048)
            assert not (raw[2] & 0x01)  # unsigned: no key exists on either side yet
            msg = mav2.MAVLink(None).decode(bytearray(raw))
            assert msg.get_type() == "SETUP_SIGNING"
            assert bytes(msg.secret_key) == _SECRET and msg.initial_timestamp == 4242
    finally:
        peer.close()


def test_enable_signing_rejects_a_bad_key_length():
    with UdpMavlinkTransport(bind=("127.0.0.1", 0)) as tr:
        with pytest.raises(ValueError):
            tr.enable_signing(b"too short")


def test_constructor_rejects_a_bad_sign_secret_key_length():
    with pytest.raises(ValueError):
        UdpMavlinkTransport(bind=("127.0.0.1", 0), sign_secret_key=b"too short")


# --------------------------------------------------------------------------- #
# P4: TelemetryTick.sig_invalid plumbing through frame_ticks()/LiveMavlinkSource
# --------------------------------------------------------------------------- #


def test_frame_ticks_sig_invalid_zero_without_a_key():
    raw = _signed_raw(lambda m: m.global_position_int_encode(
        1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000), key=_SECRET)
    ticks = list(frame_ticks([(0.0, raw)], sample_rate_hz=10.0))
    assert all(t.sig_invalid == 0 for t in ticks)  # no key: bit-only, unchanged behaviour


def test_frame_ticks_sig_invalid_counts_a_bad_signature_in_its_tick():
    good = _signed_raw(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4),
                       key=_SECRET, seq=0, timestamp=1000)
    bad = _signed_raw(lambda m: m.global_position_int_encode(
        1000, 473977418, 85455940, 488000, 12000, 10, -20, 30, 9000),
        key=bytes(range(1, 33)), seq=1, timestamp=1001)  # wrong key -> invalid
    ticks = list(frame_ticks([(0.0, good), (0.5, bad)], sample_rate_hz=10.0, secret_key=_SECRET))
    assert sum(t.sig_invalid for t in ticks) == 1
    assert sum(len(t.messages) for t in ticks) == 1  # the bad frame never becomes an envelope


def test_frame_ticks_sig_invalid_zero_when_everything_verifies():
    raw = _signed_raw(lambda m: m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4),
                      key=_SECRET)
    ticks = list(frame_ticks([(0.0, raw)], sample_rate_hz=10.0, secret_key=_SECRET))
    assert sum(t.sig_invalid for t in ticks) == 0
    assert sum(len(t.messages) for t in ticks) == 1


# --------------------------------------------------------------------------- #
# Transport health proxies (NOT a kernel-drop count -- Phase 2 observability)
# --------------------------------------------------------------------------- #


def test_queue_high_water_tracks_the_largest_backlog_seen():
    with UdpMavlinkTransport(bind=("127.0.0.1", 0), queue_size=16) as tr:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(5):
            s.sendto(hb(i), tr.local_address)
        s.close()
        assert _wait(lambda: tr.datagrams_received >= 5)
        assert tr.queue_high_water == 5  # nothing drained yet -> backlog grew to 5
        tr.poll()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.sendto(hb(5), tr.local_address)
        s2.close()
        assert _wait(lambda: tr.datagrams_received >= 6)
        assert tr.queue_high_water == 5  # draining then adding 1 does not raise the high-water mark


def test_queue_high_water_zero_when_nothing_ever_arrives():
    with UdpMavlinkTransport(bind=("127.0.0.1", 0)) as tr:
        assert tr.queue_high_water == 0


def test_max_poll_gap_s_grows_only_between_poll_calls_not_before_the_first():
    clock = FakeClock(0.0)
    with UdpMavlinkTransport(bind=("127.0.0.1", 0), clock_ns=clock) as tr:
        tr.poll()  # first call: no prior poll to measure a gap against
        assert tr.max_poll_gap_s == 0.0
        clock.ns += round(0.25 * 1e9)
        tr.poll()
        assert tr.max_poll_gap_s == pytest.approx(0.25, abs=1e-6)
        clock.ns += round(0.05 * 1e9)  # a smaller gap afterwards must not shrink the high-water mark
        tr.poll()
        assert tr.max_poll_gap_s == pytest.approx(0.25, abs=1e-6)


def test_stats_surface_on_live_mavlink_source():
    clock = FakeClock(0.0)
    tr = ScriptedTransport(clock, [])
    tr.queue_high_water = 7
    tr.max_poll_gap_s = 0.42
    src = LiveMavlinkSource(tr, sample_rate_hz=10.0, clock_ns=clock, sleep=clock.sleep, max_ticks=0)
    d = src.stats
    assert d["queue_high_water"] == 7 and d["max_poll_gap_s"] == pytest.approx(0.42)
