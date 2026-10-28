"""Inline IPS (Topology B): policy rules and the bridge, on SYNTHETIC frames and fake transports.

Nothing here opens a port, talks to an autopilot or measures a vehicle. The frames are real MAVLink 2
bytes from pymavlink; the transports are in-memory lists.
"""

from __future__ import annotations

import struct

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mitigation.inline_policy import (
    FORCE_MAGIC,
    MAV_CMD_COMPONENT_ARM_DISARM,
    MAV_CMD_DO_SET_MODE,
    InlinePolicy,
)
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.types import DefenseMode
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames
from aegisflight.sources.mavlink_live import frame_ticks


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def _enc(sysid: int, compid: int = 1) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.robust_parsing = True
    return m


def command_long(sysid: int, command: int, p1: float = 0.0, p2: float = 0.0, comp: int = 190) -> bytes:
    m = _enc(sysid, comp)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, p2, 0, 0, 0, 0, 0).pack(m))


def set_mode(sysid: int) -> bytes:
    m = _enc(sysid, 190)
    return bytes(m.set_mode_encode(1, 1, 4).pack(m))


def rc_override(sysid: int) -> bytes:
    m = _enc(sysid, 190)
    return bytes(m.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m))


def heartbeat(sysid: int = 1, armed: bool = True) -> bytes:
    m = _enc(sysid, 1)
    base = 0x80 if armed else 0
    return bytes(m.heartbeat_encode(2, 3, base, 4, 4).pack(m))


def gpi(sysid: int = 1, lat: float = 19.0, lon: float = 72.9, rel_alt_m: float = 30.0, vx: float = 5.0) -> bytes:
    m = _enc(sysid, 1)
    return bytes(m.global_position_int_encode(1000, int(lat * 1e7), int(lon * 1e7), int((rel_alt_m + 10) * 1000),
                                              int(rel_alt_m * 1000), int(vx * 100), 0, 0, 0).pack(m))


def ctx(raw: bytes, direction: str, recv_ns: int = 1_000_000_000) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction=direction, raw=fr.raw, recv_ns=recv_ns, sysid=fr.sysid,  # type: ignore[arg-type]
                        compid=fr.compid, seq=fr.seq, msgid=fr.msgid, signed=fr.signed)


@pytest.fixture
def policy():
    clock = Clock()
    p = InlinePolicy(FrameSanitizer(), clock=clock)
    p.clock = clock  # type: ignore[attr-defined]
    p.set_enforce(True)
    return p


def up(p: InlinePolicy, raw: bytes) -> list[bytes]:
    return p.up(ctx(raw, "up"))


def down(p: InlinePolicy, raw: bytes) -> list[bytes]:
    return p.down(ctx(raw, "down"))


# --------------------------------------------------------------------------- #
# static uplink rules
# --------------------------------------------------------------------------- #

def test_enforcement_off_forwards_everything_byte_identically():
    p = InlinePolicy(FrameSanitizer(), clock=Clock())
    for raw in (command_long(66, MAV_CMD_DO_SET_MODE, 1, 4), set_mode(66), rc_override(66)):
        assert up(p, raw) == [raw]


def test_untrusted_control_traffic_is_dropped_but_the_pilot_is_not(policy):
    for build in (lambda s: set_mode(s), lambda s: rc_override(s), lambda s: command_long(s, MAV_CMD_DO_SET_MODE, 1, 4)):
        assert up(policy, build(66)) == []          # rogue sysid
        raw = build(255)
        assert up(policy, raw) == [raw]              # the real GCS passes
    assert policy.dropped_untrusted_control == 3


def test_non_sensitive_traffic_from_other_sysids_passes(policy):
    raw = heartbeat(77)
    assert up(policy, raw) == [raw]


def test_plain_disarm_in_flight_is_dropped_for_everyone_but_a_forced_kill_from_the_pilot_passes(policy):
    down(policy, heartbeat(armed=True))
    down(policy, gpi(rel_alt_m=30.0))
    assert policy.in_flight
    plain = command_long(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, 0.0)
    assert up(policy, plain) == []
    kill = command_long(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, FORCE_MAGIC)
    assert up(policy, kill) == [kill]                # emergency kill switch is never blocked
    assert up(policy, command_long(66, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, FORCE_MAGIC)) == []  # attacker's forced kill


def test_disarm_on_the_ground_passes(policy):
    down(policy, heartbeat(armed=False))
    down(policy, gpi(rel_alt_m=0.0, vx=0.0))
    assert not policy.in_flight
    raw = command_long(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, 0.0)
    assert up(policy, raw) == [raw]


def test_identical_sensitive_command_burst_is_dropped_once_per_window(policy):
    raw = command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)
    assert up(policy, raw) == [raw]
    assert up(policy, raw) == []                     # same payload inside cadence_s
    assert up(policy, command_long(255, MAV_CMD_DO_SET_MODE, 1, 5)) != []  # a different command is a different intent
    policy.clock.t += 0.2                            # type: ignore[attr-defined]
    assert up(policy, raw) == [raw]
    assert policy.dropped_burst == 1


# --------------------------------------------------------------------------- #
# dynamic downlink rules and the stale-analyser fallback
# --------------------------------------------------------------------------- #

def test_quarantine_applies_only_while_fresh_and_never_to_protected_sysids(policy):
    san = policy.sanitizer
    san.configure(active=True, quarantined_sysids={42, 1, 255})
    rogue, vehicle = heartbeat(42), heartbeat(1)
    # not touched yet: transparent
    assert down(policy, rogue) == [rogue]
    policy.touch()
    assert down(policy, rogue) == []
    assert down(policy, vehicle) == [vehicle]        # the vehicle is protected even if listed
    assert up(policy, heartbeat(255)) == [heartbeat(255)]
    policy.clock.t += policy.dynamic_ttl_s + 0.1     # type: ignore[attr-defined]
    assert down(policy, rogue) == [rogue]            # analyser went quiet -> transparent, not stale


def test_gps_rewrite_keeps_a_valid_frame_and_leaves_signed_frames_alone(policy):
    policy.sanitizer.configure(active=True, sanitize_gps=True, lat_offset_deg=0.001, lon_offset_deg=-0.002)
    policy.touch()
    raw = gpi(lat=19.001, lon=72.898)
    (out,) = down(policy, raw)
    assert out != raw and len(out) == 40  # a zero-trimmed frame is re-emitted at its full 28-byte payload
    msg = mav2.MAVLink(None).parse_char(out)
    assert msg is not None and abs(msg.lat / 1e7 - 19.000) < 1e-6 and abs(msg.lon / 1e7 - 72.900) < 1e-6  # CRC valid
    assert policy.rewritten == 1
    signed = bytearray(raw)
    signed[2] |= 1
    signed += bytes(13)
    c = ctx(bytes(signed), "down")
    assert policy.down(c) == [c.raw]                 # a rewrite would break the MAC, so it is left alone


def test_a_rule_that_raises_forwards_the_original(policy, monkeypatch):
    monkeypatch.setattr(policy, "_command_rule", lambda *a, **k: 1 / 0)
    raw = command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)
    assert up(policy, raw) == [raw] and policy.hook_errors == 1


# --------------------------------------------------------------------------- #
# the bridge
# --------------------------------------------------------------------------- #

class FakeLink:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def feed(self, *frames: bytes, stamp: int = 1_000_000_000) -> None:
        self.inbox.extend((stamp, f) for f in frames)

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


def make_bridge(mode: str):
    fc, gcs = FakeLink(), FakeLink()
    return InlineIpsBridge(fc, gcs, mode=mode), fc, gcs


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_non_active_postures_forward_every_frame_byte_identically(mode):
    b, fc, gcs = make_bridge(mode)
    down_frames = [heartbeat(), gpi(), heartbeat(42)]
    up_frames = [command_long(66, MAV_CMD_DO_SET_MODE, 1, 4), set_mode(66), rc_override(66)]
    fc.feed(*down_frames)
    gcs.feed(*up_frames)
    b.pump_once()
    assert gcs.sent == down_frames and fc.sent == up_frames
    assert b.dropped_up == 0 and b.dropped_down == 0


def test_active_ips_drops_hostile_uplink_before_the_flight_controller_and_the_tap_still_sees_it():
    b, fc, gcs = make_bridge("active-ips")
    pilot = command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)
    hostile = [command_long(66, MAV_CMD_DO_SET_MODE, 1, 9), set_mode(66), rc_override(66)]
    gcs.feed(*hostile, pilot)
    b.pump_once()
    assert fc.sent == [pilot]
    assert b.dropped_up == 3
    seen = [f.raw for _, d in b.tap.poll() for f in split_frames(d)[0]]
    assert seen == [*hostile, pilot]                 # detectors get the originals


def test_benign_traffic_is_never_dropped_in_active_ips():
    b, fc, gcs = make_bridge("active-ips")
    down_frames = [heartbeat(), gpi(), gpi(rel_alt_m=31.0)] * 20
    up_frames = [heartbeat(255), command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)]
    fc.feed(*down_frames)
    gcs.feed(*up_frames)
    b.pump_once()
    assert gcs.sent == down_frames
    assert fc.sent == up_frames
    assert b.dropped_up == b.dropped_down == 0 and b.send_failures == 0


def test_analyser_keeps_policy_fresh_and_a_mode_change_clears_enforcement():
    b, fc, gcs = make_bridge("active-ips")
    frames = [(i * 0.1, f) for i in range(40) for f in (heartbeat(), gpi())]
    for tick in frame_ticks(frames, sample_rate_hz=10.0):
        b.analyse_tick(tick)
    assert b.decisions > 0 and b.policy.dynamic_fresh
    assert fc.sent == []                             # clean flight: no counter-frames
    b.set_mode(DefenseMode.PASSIVE)
    assert b.policy.enforce is False
    raw = set_mode(66)
    gcs.feed(raw)
    b.pump_once()
    assert fc.sent == [raw]                          # back in IDS mode nothing is filtered


def test_status_reports_per_frame_latency():
    b, fc, gcs = make_bridge("active-ips")
    fc.feed(*[gpi() for _ in range(50)])
    b.pump_once()
    st = b.status()
    assert st["latency_us"]["samples"] == 50 and st["latency_us"]["p95"] is not None
    assert st["frames"]["forwarded_down"] == 50 and st["policy"]["enforce"] is True


def test_unframeable_bytes_are_not_forwarded_as_frames():
    b, fc, gcs = make_bridge("active-ips")
    fc.feed(b"\x00\x01\x02garbage")
    assert b.pump_once() == 0 and gcs.sent == []


def test_hook_exception_in_the_bridge_still_forwards(monkeypatch):
    b, fc, gcs = make_bridge("active-ips")
    monkeypatch.setattr(b.policy, "down", lambda c: 1 / 0)
    raw = gpi()
    fc.feed(raw)
    b.pump_once()
    assert gcs.sent == [raw] and b.policy.hook_errors == 1


def test_payload_layout_assumptions():
    # COMMAND_LONG: command id at payload offset 28 (the rules depend on it)
    raw = command_long(255, MAV_CMD_COMPONENT_ARM_DISARM, 0.0, FORCE_MAGIC)
    payload = raw[10:10 + raw[1]] + bytes(40)
    assert struct.unpack_from("<H", payload, 28)[0] == MAV_CMD_COMPONENT_ARM_DISARM
    assert struct.unpack_from("<2f", payload, 0)[1] == FORCE_MAGIC


# --------------------------------------------------------------------------- #
# real transports over loopback sockets (pyserial socket:// virtual ports)
# --------------------------------------------------------------------------- #

def test_bridge_over_real_serial_transports_filters_hostile_uplink_and_passes_the_rest():
    import socket
    import threading
    import time

    from aegisflight.sources.mavlink_serial import SerialMavlinkTransport

    def listener():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s

    fc_srv, gcs_srv = listener(), listener()
    conns: dict[str, socket.socket] = {}

    def accept(name, srv):
        conns[name], _ = srv.accept()

    for name, srv in (("fc", fc_srv), ("gcs", gcs_srv)):
        threading.Thread(target=accept, args=(name, srv), daemon=True).start()
    fc = SerialMavlinkTransport(f"socket://127.0.0.1:{fc_srv.getsockname()[1]}", allow_url=True,
                                accept_unverified_ids=True)
    gcs = SerialMavlinkTransport(f"socket://127.0.0.1:{gcs_srv.getsockname()[1]}", allow_url=True,
                                 accept_unverified_ids=True)
    bridge = InlineIpsBridge(fc, gcs, mode="active-ips")
    fc.start()
    gcs.start()
    bridge.start()
    try:
        deadline = time.monotonic() + 5
        while len(conns) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(conns) == 2
        down_frames = [heartbeat(), gpi(), heartbeat()]
        pilot = command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)
        hostile = command_long(66, MAV_CMD_DO_SET_MODE, 1, 9)
        conns["fc"].sendall(b"".join(down_frames))
        conns["gcs"].sendall(hostile + pilot)

        def read_all(sock, want, timeout=5.0):
            sock.settimeout(0.2)
            buf = b""
            end = time.monotonic() + timeout
            while len(buf) < want and time.monotonic() < end:
                try:
                    buf += sock.recv(4096)
                except TimeoutError:
                    pass
            return buf

        got_gcs = read_all(conns["gcs"], sum(map(len, down_frames)))
        got_fc = read_all(conns["fc"], len(pilot))
        time.sleep(0.3)  # any wrongly forwarded hostile frame would have arrived by now
        conns["fc"].settimeout(0.2)
        with __import__("contextlib").suppress(TimeoutError):
            got_fc += conns["fc"].recv(4096)
        assert got_gcs == b"".join(down_frames)
        assert got_fc == pilot                       # the hostile command never reached the flight controller
        assert bridge.dropped_up == 1 and bridge.status()["latency_us"]["samples"] >= 5
    finally:
        bridge.close()
        for c in conns.values():
            c.close()
        fc_srv.close()
        gcs_srv.close()
