"""MAVLink relay (proxy transport): framing, hooks, fan-out, start ordering, loopback e2e.

All unit tests drive ``MavlinkRelay.pump_once`` with fake links (no sockets, no threads, a
fake clock). One loopback integration test uses real UDP sockets on ephemeral ports.
"""

from __future__ import annotations

import logging
import socket
import time

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import (
    MavlinkRelay,
    UdpDownstream,
    main,
    make_udp_relay,
    split_frames,
)
from aegisflight.sources.mavlink_live import MavlinkFrameParser

# --------------------------------------------------------------------------- #
# frame builders
# --------------------------------------------------------------------------- #


def _mk(sysid=1, compid=1, seq=0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb(seq=0, sysid=1, compid=1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(2, 12, 0, 0, 4).pack(m))


def gpi(seq=0, sysid=1, compid=1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.global_position_int_encode(1000, 473977418, 85455940, 488000, 12000,
                                              10, -20, 30, 9000).pack(m))


def v1_hb(seq=0, sysid=2, compid=5) -> bytes:
    m = _mk(sysid, compid, seq, dialect=mav1)
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


def signed_hb(seq=0) -> bytes:
    m = _mk(1, 1, seq)
    m.signing.secret_key = bytes(32)
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1000
    return bytes(m.heartbeat_encode(1, 12, 0, 0, 4).pack(m))


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #

CLIENT_A = ("127.0.0.1", 50001)
CLIENT_B = ("127.0.0.1", 50002)


class FakeUp:
    def __init__(self, events=None, hb_ok=True):
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []
        self.events = events if events is not None else []
        self.hb_ok = hb_ok
        self.dropped_overflow = 0
        self.closed = 0

    def start(self):
        self.events.append("up.start")

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data):
        self.sent.append(data)
        return True

    def send_heartbeat(self):
        self.events.append("up.heartbeat")
        return self.hb_ok

    def close(self):
        self.closed += 1


class FakeDown:
    def __init__(self, events=None):
        self.inbox: list[tuple[int, tuple, bytes]] = []
        self.sent: list[tuple[bytes, tuple]] = []
        self.events = events if events is not None else []
        self.dropped_overflow = 0
        self.closed = 0

    def start(self):
        self.events.append("down.start")

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def sendto(self, data, addr):
        self.sent.append((data, addr))
        return True

    def close(self):
        self.closed += 1

    def to(self, addr):
        return [d for d, a in self.sent if a == addr]


class Clock:
    def __init__(self):
        self.ns = 0

    def __call__(self):
        return self.ns

    def sleep(self, s):
        self.ns += round(s * 1e9)


def relay(up=None, down=None, clock=None, **kw):
    up, down, clock = up or FakeUp(), down or FakeDown(), clock or Clock()
    r = MavlinkRelay(up, down, clock_ns=clock, sleep=clock.sleep, **kw)
    return r, up, down, clock


# --------------------------------------------------------------------------- #
# framing
# --------------------------------------------------------------------------- #


def test_split_frames_header_fields_v1_v2_signed():
    f1, f2, f3, f4 = hb(7, 3, 4), v1_hb(9, 2, 5), signed_hb(11), gpi(13)
    frames, bad = split_frames(f1 + f2 + f3 + f4)
    assert bad == 0
    assert [f.raw for f in frames] == [f1, f2, f3, f4]  # byte-identical slices
    assert [(f.sysid, f.compid, f.seq, f.msgid, f.signed) for f in frames] == [
        (3, 4, 7, 0, False), (2, 5, 9, 0, False), (1, 1, 11, 0, True), (1, 1, 13, 33, False)]
    assert len(f3) == 10 + 9 + 2 + 13  # the 13-byte signature stays inside the frame


def test_split_frames_garbage_truncation_and_cap_never_raise():
    good = hb(1)
    assert split_frames(b"") == ([], 0)
    assert split_frames(good[:-2])[1] == 1 and split_frames(good[:-2])[0] == []
    frames, bad = split_frames(b"\x00\x01\x02" + good + good[:5])
    assert [f.raw for f in frames] == [good] and bad == 2  # junk run + truncated tail
    bad_incompat = bytearray(good)
    bad_incompat[2] = 0x02  # unknown incompat flag -> unframeable
    assert split_frames(bytes(bad_incompat) + good)[0][0].raw == good
    many = hb(0) * 100
    frames, bad = split_frames(many, max_frames=10)
    assert len(frames) == 10 and bad == 1


# --------------------------------------------------------------------------- #
# pass-through: byte-identical, ordered, fan-out
# --------------------------------------------------------------------------- #


def test_passthrough_downlink_is_byte_identical_ordered_and_fans_out():
    r, up, down, _ = relay()
    for a in (CLIENT_A, CLIENT_B):  # learn both clients
        down.inbox.append((1, a, hb(0, 254, 190)))
    r.pump_once()
    datagrams = [hb(1) + gpi(2) + v1_hb(3), signed_hb(4), gpi(5)]
    up.inbox = [(10 + i, d) for i, d in enumerate(datagrams)]
    r.pump_once()
    expected = [hb(1), gpi(2), v1_hb(3), signed_hb(4), gpi(5)]  # one datagram per frame
    assert down.to(CLIENT_A) == expected and down.to(CLIENT_B) == expected
    st = r.stats
    assert st["frames_down"] == 5 and st["forwarded_down"] == 5 and st["clients"] == 2
    assert st["dropped_by_hook"] == st["hook_errors"] == st["bad_segments"] == 0
    assert up.sent == [hb(0, 254, 190)] * 2  # the client heartbeats went upstream


def test_passthrough_uplink_goes_upstream_in_order():
    r, up, down, _ = relay()
    down.inbox = [(1, CLIENT_A, hb(1, 255, 190) + gpi(2, 255, 190)), (2, CLIENT_B, hb(3, 254, 1))]
    r.pump_once()
    assert up.sent == [hb(1, 255, 190), gpi(2, 255, 190), hb(3, 254, 1)]
    assert r.stats["frames_up"] == 3 and r.stats["forwarded_up"] == 3
    assert down.sent == []  # uplink frames are never echoed to clients


def test_mirror_uplink_default_off_two_clients_no_mirroring_regression():
    """Locks in the proven, reviewed behaviour: with no opt-in, uplink traffic from one
    client is NEVER mirrored to another, so the existing downlink-attack evidence stays
    byte-for-byte reproducible."""
    r, up, down, _ = relay()
    assert r.mirror_uplink_to_clients is False  # explicit default
    down.inbox = [(1, CLIENT_A, hb(0, 255, 190)), (2, CLIENT_B, hb(1, 254, 1))]
    r.pump_once()  # learn both clients
    down.inbox = [(3, CLIENT_A, gpi(2, 255, 190))]
    r.pump_once()
    assert down.to(CLIENT_B) == [] and down.to(CLIENT_A) == []  # no mirroring either way
    assert r.stats["mirrored_up"] == 0
    assert up.sent[-1] == gpi(2, 255, 190)


def test_mirror_uplink_to_clients_when_enabled_excludes_sender():
    """A downstream IDS tap only sees PX4's own downlink by default; this is the opt-in
    that makes it also see uplink traffic (including anything an up_hook injects), as a
    real single-link bump-in-the-wire tap would -- but never an echo of a client's own
    frame back to itself."""

    def up_hook(ctx):
        return [ctx.raw, hb(99, 7, 7)]  # simulate an up_hook injecting a rogue frame

    r, up, down, _ = relay(up_hook=up_hook)  # register clients with mirroring still off
    down.inbox = [(1, CLIENT_A, hb(0, 255, 190)), (2, CLIENT_B, hb(1, 254, 1))]
    r.pump_once()
    r.mirror_uplink_to_clients = True  # flip it on, as a live trial would

    down.inbox = [(3, CLIENT_A, gpi(2, 255, 190))]
    r.pump_once()
    assert up.sent[-2:] == [gpi(2, 255, 190), hb(99, 7, 7)]  # upstream still gets both
    assert down.to(CLIENT_B) == [gpi(2, 255, 190), hb(99, 7, 7)]  # the OTHER client sees both
    assert down.to(CLIENT_A) == []  # the sender gets no echo of its own uplink
    assert r.stats["mirrored_up"] == 2


def test_bad_bytes_are_dropped_and_counted_not_forwarded():
    r, up, down, _ = relay()
    down.inbox = [(1, CLIENT_A, hb(1))]
    r.pump_once()
    up.inbox = [(5, b"\x00\x01" + hb(2) + hb(3)[:4])]
    r.pump_once()
    assert down.to(CLIENT_A) == [hb(2)] and r.stats["bad_segments"] == 2


# --------------------------------------------------------------------------- #
# hooks
# --------------------------------------------------------------------------- #


def test_hook_sees_context_and_can_modify_drop_and_inject():
    seen: list[FrameContext] = []

    def down_hook(ctx):
        seen.append(ctx)
        if ctx.msgid == 33:
            return [ctx.raw[:-2] + b"\x00\x00"]  # modify
        if ctx.seq == 3:
            return []  # drop
        if ctx.seq == 5:
            return [ctx.raw, hb(99), hb(100)]  # original + two injected
        return [ctx.raw]

    r, up, down, _ = relay(down_hook=down_hook)
    down.inbox = [(1, CLIENT_A, hb(0))]
    r.pump_once()
    up.inbox = [(777, hb(2, sysid=7, compid=9) + hb(3) + hb(5) + gpi(6))]
    r.pump_once()
    out = down.to(CLIENT_A)
    assert out == [hb(2, 7, 9), hb(5), hb(99), hb(100), gpi(6)[:-2] + b"\x00\x00"]
    ctx = seen[0]
    assert (ctx.direction, ctx.recv_ns, ctx.sysid, ctx.compid, ctx.seq, ctx.msgid, ctx.signed) == (
        "down", 777, 7, 9, 2, 0, False)
    assert ctx.raw == hb(2, 7, 9)
    st = r.stats
    assert st["dropped_by_hook"] == 1 and st["frames_down"] == 4
    assert st["forwarded_down"] == 5  # hb2, hb5, hb99, hb100, gpi6


def test_up_hook_gets_direction_up_and_signed_flag():
    seen: list[FrameContext] = []
    r, up, down, _ = relay(up_hook=lambda c: (seen.append(c), [c.raw])[1])
    down.inbox = [(42, CLIENT_A, signed_hb(8))]
    r.pump_once()
    assert seen[0].direction == "up" and seen[0].signed and seen[0].recv_ns == 42
    assert up.sent == [signed_hb(8)]


def test_hook_exception_forwards_original_counts_and_logs_once(caplog):
    def boom(ctx):
        raise RuntimeError("attack bug")

    r, up, down, _ = relay(down_hook=boom)
    down.inbox = [(1, CLIENT_A, hb(0))]
    r.pump_once()
    with caplog.at_level(logging.ERROR, logger="aegisflight.proxy.transport"):
        up.inbox = [(2, hb(1) + hb(2) + hb(3))]
        r.pump_once()
    assert down.to(CLIENT_A) == [hb(1), hb(2), hb(3)]  # original frames, relay still alive
    assert r.stats["hook_errors"] == 3
    assert len([rec for rec in caplog.records if "hook failed" in rec.getMessage()]) == 1


@pytest.mark.parametrize("bad", [None, b"raw", [hb(1), "str"], [b""], [hb(1)] * 65, 5])
def test_hook_returning_garbage_is_an_error_not_a_crash(bad):
    r, up, down, _ = relay(down_hook=lambda ctx: bad)
    down.inbox = [(1, CLIENT_A, hb(0))]
    r.pump_once()
    up.inbox = [(2, hb(1))]
    r.pump_once()
    assert down.to(CLIENT_A) == [hb(1)] and r.stats["hook_errors"] == 1


# --------------------------------------------------------------------------- #
# clients
# --------------------------------------------------------------------------- #


def test_clients_are_bounded_loopback_only_and_junk_cannot_register():
    r, up, down, clock = relay(max_clients=2, client_timeout_s=10.0)
    down.inbox = [
        (1, ("10.1.2.3", 5000), hb(1)),  # non-loopback source
        (1, ("127.0.0.1", 6000), b"\x00\x01\x02"),  # junk takes no slot
        (1, ("127.0.0.1", 6001), hb(1)),
        (1, ("127.0.0.2", 6002), hb(2)),
        (1, ("127.0.0.1", 6003), hb(3)),  # table full
    ]
    r.pump_once()
    st = r.stats
    assert st["clients"] == 2 and st["clients_seen"] == 2 and st["rejected_clients"] == 2
    assert up.sent == [hb(1), hb(2)]  # rejected clients' frames are NOT forwarded either
    clock.ns += 11 * 10**9  # both go idle: a newcomer evicts them
    down.inbox = [(2, ("127.0.0.1", 6003), hb(4))]
    r.pump_once()
    assert r.client_addresses == [("127.0.0.1", 6003)] and up.sent[-1] == hb(4)


def test_downlink_with_no_client_is_counted_not_sent():
    r, up, down, _ = relay()
    up.inbox = [(1, hb(1) + hb(2))]
    r.pump_once()
    st = r.stats
    assert down.sent == [] and st["down_no_client"] == 2 and st["frames_down"] == 2
    assert r.upstream_alive  # we did hear PX4


# --------------------------------------------------------------------------- #
# lifecycle / ordering
# --------------------------------------------------------------------------- #


def test_start_sends_first_heartbeat_before_anything_else_starts():
    events: list[str] = []
    r, _up, _down, _ = relay(FakeUp(events), FakeDown(events))
    r.start()
    try:
        assert events[:3] == ["up.heartbeat", "up.start", "down.start"]
        assert r.first_heartbeat_sent
        assert r.start() is r and events.count("up.start") == 1  # idempotent
    finally:
        r.close()


def test_start_fails_closed_if_first_heartbeat_cannot_be_sent():
    events: list[str] = []
    r, _up, _down, _ = relay(FakeUp(events, hb_ok=False), FakeDown(events))
    with pytest.raises(RuntimeError):
        r.start()
    assert events == ["up.heartbeat"]  # nothing else was started
    r.close()


def test_wait_upstream_alive_true_after_px4_frame_false_on_timeout():
    r, up, _down, clock = relay()
    assert r.wait_upstream_alive(0.5) is False
    assert clock.ns >= 0.5e9  # waited on the injected clock, no real time
    up.inbox = [(1, b"\x00\x01")]  # junk is not 'alive'
    r.pump_once()
    assert not r.upstream_alive
    up.inbox = [(2, hb(1))]
    r.pump_once()
    assert r.wait_upstream_alive(0.5) is True


def test_close_is_idempotent_and_threads_are_daemons():
    r, up, down, _ = relay()
    r.start()
    th = r._thread
    assert th is not None and th.daemon and th.is_alive()
    r.close()
    r.close()
    assert not th.is_alive() and up.closed == 1 and down.closed == 1
    with pytest.raises(RuntimeError):
        r.start()


def test_pump_survives_a_leg_that_raises():
    class Flaky(FakeUp):
        n = 0

        def poll(self):
            self.n += 1
            if self.n == 1:
                raise OSError("transient")
            return super().poll()

    up = Flaky()
    r = MavlinkRelay(up, FakeDown(), idle_sleep_s=0.001)
    r.start()
    try:
        deadline = time.monotonic() + 2
        while r.stats["pump_errors"] < 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert r.stats["pump_errors"] == 1 and r._thread.is_alive()
    finally:
        r.close()


# --------------------------------------------------------------------------- #
# real sockets (loopback): fake PX4 <-> relay <-> two clients
# --------------------------------------------------------------------------- #


@pytest.fixture
def udp_ok():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.close()
    except OSError:
        pytest.skip("UDP loopback sockets unavailable")


def _sock(timeout=1.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(timeout)
    return s


def _wait(pred, timeout=2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


def test_downstream_refuses_non_loopback_bind(udp_ok):
    with pytest.raises(ValueError):
        UdpDownstream(("0.0.0.0", 0))
    with pytest.raises(ValueError):
        UdpDownstream(("192.0.2.1", 0))
    with pytest.raises(ValueError):
        make_udp_relay("127.0.0.1", 9, 0, listen_host="0.0.0.0")


def test_loopback_end_to_end_px4_relay_two_clients(udp_ok):
    px4, c_ids, c_drv = _sock(), _sock(), _sock()
    t0 = time.monotonic()
    r = make_udp_relay("127.0.0.1", px4.getsockname()[1], 0)
    parser = MavlinkFrameParser()
    try:
        r.start()
        # (1) the very first datagram PX4 sees is the proxy's own GCS heartbeat
        first, proxy_addr = px4.recvfrom(2048)
        (e,) = parser.parse(first, 0.0)
        assert e.msgname == "HEARTBEAT" and (e.sysid, e.compid) == (255, 190)
        listen = r.downstream.local_address
        assert listen[0] == "127.0.0.1"

        # (2) clients announce themselves with distinct sysids; PX4 receives them from the
        # SAME source address it locked to
        c_ids.sendto(hb(1, 255, 191), listen)
        c_drv.sendto(hb(2, 254, 1), listen)
        got: list[bytes] = []
        while len(got) < 2:
            data, addr = px4.recvfrom(2048)
            assert addr == proxy_addr
            if data[5] != 255 or data[6] != 190:  # skip the proxy's periodic heartbeat
                got.append(data)
        assert sorted(got) == sorted([hb(1, 255, 191), hb(2, 254, 1)])
        assert _wait(lambda: r.stats["clients"] == 2)

        # (3) PX4 -> proxy: 3 frames in one datagram + a signed one; both clients get every
        # frame, byte-identical, in order
        frames = [hb(10), gpi(11), v1_hb(12), signed_hb(13)]
        px4.sendto(frames[0] + frames[1] + frames[2], proxy_addr)
        px4.sendto(frames[3], proxy_addr)
        assert r.wait_upstream_alive(1.0)
        for c in (c_ids, c_drv):
            assert [c.recvfrom(2048)[0] for _ in frames] == frames

        # (4) client -> PX4 frame goes upstream untouched
        c_drv.sendto(gpi(20, 254, 1), listen)
        while True:
            data, _ = px4.recvfrom(2048)
            if data[5] == 254:
                break
        assert data == gpi(20, 254, 1)
        st = r.stats
        assert st["frames_down"] == 4 and st["forwarded_down"] == 4
        assert st["hook_errors"] == st["dropped_by_hook"] == st["bad_segments"] == 0
    finally:
        r.close()
        r.close()
        for s in (px4, c_ids, c_drv):
            s.close()
    assert time.monotonic() - t0 < 3.0


def test_loopback_mirror_uplink_to_other_client_when_enabled(udp_ok):
    """Real-socket variant of the mirroring test: a bump-in-the-wire IDS tap (c_ids) sees
    the other client's (c_drv's) uplink traffic once mirroring is opted in, PX4 still gets
    it unchanged, and c_drv never gets an echo of its own frame."""
    px4, c_ids, c_drv = _sock(), _sock(), _sock()
    r = make_udp_relay("127.0.0.1", px4.getsockname()[1], 0, mirror_uplink_to_clients=True)
    try:
        r.start()
        px4.recvfrom(2048)  # the proxy's first GCS heartbeat
        listen = r.downstream.local_address
        c_ids.sendto(hb(1, 255, 191), listen)
        c_drv.sendto(hb(2, 254, 1), listen)
        seen: set[tuple[int, int]] = set()
        while len(seen) < 2:
            data, _ = px4.recvfrom(2048)
            if (data[5], data[6]) != (255, 190):  # skip the proxy's periodic heartbeat
                seen.add((data[5], data[6]))
        assert _wait(lambda: r.stats["clients"] == 2)

        c_drv.sendto(gpi(20, 254, 1), listen)
        while True:
            data, _ = px4.recvfrom(2048)
            if data[5] == 254:
                break
        assert data == gpi(20, 254, 1)  # PX4 still gets it unchanged
        # with mirroring on throughout, c_ids may also have already received a mirrored
        # copy of c_drv's own registration heartbeat (9-byte payload); skip past that to
        # find the gpi frame (28-byte payload) we actually care about
        while True:
            mirrored, _ = c_ids.recvfrom(2048)
            if mirrored[1] == len(gpi(0)) - 12:
                break
        assert mirrored == gpi(20, 254, 1)  # the OTHER client sees it mirrored
        c_drv.settimeout(0.2)
        with pytest.raises(socket.timeout):
            c_drv.recvfrom(2048)  # no echo of its own uplink frame
        assert r.stats["mirrored_up"] == 2  # the registration heartbeat + the gpi frame
    finally:
        r.close()
        for s in (px4, c_ids, c_drv):
            s.close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_requires_explicit_host_and_ports():
    with pytest.raises(SystemExit):
        main(["--px4-port", "14550", "--listen-port", "14551"])  # no --px4-host
    with pytest.raises(SystemExit):
        main(["--px4-host", "127.0.0.1", "--listen-port", "14551"])


def test_cli_runs_passthrough_and_reports_no_px4(udp_ok, capsys):
    px4 = _sock()
    try:
        rc = main(["--px4-host", "127.0.0.1", "--px4-port", str(px4.getsockname()[1]),
                   "--listen-port", "0", "--seconds", "0.2", "--alive-timeout", "0.1"])
    finally:
        px4.close()
    assert rc == 2  # fake PX4 never answered: reported, not hidden
    out = capsys.readouterr().out
    assert "no MAVLink from PX4" in out and '"frames_down": 0' in out
