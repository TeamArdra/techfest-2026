"""Concurrency + topology regression tests for the live command-injection path (no SITL).

Why this file exists (docs/STAGE2_PROGRESS.md, 2026-10-07 "command-injection nondeterminism"):
live SITL trials showed PX4 accepting the rogue COMMAND_LONG 10/10 but the IDS seeing it in only 5/10.
The leading hypothesis was a race in the threaded ``UdpMavlinkTransport``. These tests separate the two
candidate causes:

* transport reliability -- a rare frame inside a high-rate stream survives the real receive thread, queue
  and tick assembly (first test; passes), and
* relay mirror topology -- ``MavlinkRelay(mirror_uplink_to_clients=True)`` used to fan an uplink frame out to
  every client EXCEPT its sender, and the attack piggybacks on whichever uplink frame comes next. When that
  frame was the IDS tap's own heartbeat, the injected frame was never mirrored to the IDS (the root cause of
  the 5/10 split). Fixed: a frame the hook created/modified is mirrored to ALL clients; an unmodified
  original still goes to everyone except its sender (no self-echo). These tests pin both halves.

All sockets are loopback on ephemeral ports; no PX4 and no Gazebo.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest
from pymavlink.dialects.v20 import common as mav

from aegisflight.proxy.attacks_live import CommandInjectionAttack, CommandInjectionParams
from aegisflight.proxy.transport import MavlinkRelay, make_udp_relay
from aegisflight.sources.mavlink_live import (
    LiveMavlinkSource,
    MavlinkFrameParser,
    UdpMavlinkTransport,
)

ROGUE_SYSID = 66


@pytest.fixture
def udp_ok():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.close()
    except OSError:
        pytest.skip("UDP loopback sockets unavailable")


def _px4_heartbeat(seq: int = 0) -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    m.seq = seq
    return bytes(m.heartbeat_encode(mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_PX4, 0, 0,
                                    mav.MAV_STATE_ACTIVE).pack(m))


def _px4_gpi(m: mav.MAVLink) -> bytes:
    m.seq = (m.seq + 1) % 256
    return bytes(m.global_position_int_encode(1000, 473977418, 85455940, 488000, 12000, 10, -20, 30,
                                              9000).pack(m))


def _gcs_heartbeat(sysid: int, compid: int, seq: int = 0) -> bytes:
    m = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(m.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0,
                                    mav.MAV_STATE_ACTIVE).pack(m))


def _rogue_command(seq: int) -> bytes:
    m = mav.MAVLink(None, srcSystem=ROGUE_SYSID, srcComponent=200)
    m.seq = seq
    return bytes(mav.MAVLink_command_long_message(1, 1, 400, 0, 0, 21196, 0, 0, 0, 0, 0).pack(m))


# --------------------------------------------------------------------------- #
# 1. transport reliability: rare frame in a high-rate stream, real threads
# --------------------------------------------------------------------------- #


def test_threaded_transport_delivers_every_rare_command_in_high_rate_stream(udp_ok):
    """Real ``UdpMavlinkTransport`` rx thread + queue + ``LiveMavlinkSource`` ticks, a consumer that burns
    CPU every tick (stand-in for the pipeline), ~600 frames/s of PX4-like traffic and 12 rare tagged
    ``COMMAND_LONG``s (unique seq each). Every command must arrive exactly once, in order."""
    n_cmds, cmd_period_s = 12, 0.25
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind(("127.0.0.1", 0))
    tr = UdpMavlinkTransport(connect=sender.getsockname(), gcs_heartbeat=True, heartbeat_hz=2.0)
    src = LiveMavlinkSource(tr, sample_rate_hz=10.0, max_ticks=45)
    dst = tr.local_address
    done = threading.Event()

    def blast() -> None:
        px4 = mav.MAVLink(None, srcSystem=1, srcComponent=1)
        t0 = time.perf_counter()
        sent = 0
        per_batch = 6 / 600.0
        next_batch = t0
        while not done.is_set() and sent < n_cmds:
            now = time.perf_counter()
            if now < next_batch:
                time.sleep(min(0.001, next_batch - now))
                continue
            next_batch += per_batch
            for _ in range(6):
                sender.sendto(_px4_gpi(px4), dst)
            if now - t0 >= 0.3 + sent * cmd_period_s:
                sender.sendto(_rogue_command(sent), dst)
                sent += 1
        while not done.is_set():  # keep the stream flowing until the consumer is finished
            sender.sendto(_px4_gpi(px4), dst)
            time.sleep(0.002)

    th = threading.Thread(target=blast, daemon=True)
    th.start()
    got: list[int] = []
    try:
        for tick in src.stream():
            end = time.perf_counter() + 0.02  # 20 ms of CPU per 100 ms tick
            while time.perf_counter() < end:
                pass
            got += [m.seq for m in tick.messages
                    if m.msgname == "COMMAND_LONG" and m.sysid == ROGUE_SYSID]
    finally:
        done.set()
        th.join(timeout=3)
        stats = src.stats
        dropped = tr.dropped_overflow
        tr.close()
        sender.close()
    assert got == list(range(n_cmds)), got  # all present, exactly once, in send order
    assert dropped == 0 and stats["bad_frames"] == 0 and stats["late_frames"] == 0, stats


# --------------------------------------------------------------------------- #
# 2/3. relay mirror topology (deterministic, fake links, REAL attack hook)
# --------------------------------------------------------------------------- #

IDS = ("127.0.0.1", 50001)  # the IDS tap (a relay client that also sends its own heartbeat)
OTHER = ("127.0.0.1", 50002)  # an inert second uplink client ("carrier")


class _Up:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []
        self.dropped_overflow = 0

    def start(self) -> None: ...

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def send_heartbeat(self) -> bool:
        return True

    def close(self) -> None: ...


class _Down:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, tuple, bytes]] = []
        self.sent: list[tuple[bytes, tuple]] = []
        self.dropped_overflow = 0

    def start(self) -> None: ...

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def sendto(self, data: bytes, addr) -> bool:
        self.sent.append((data, addr))
        return True

    def close(self) -> None: ...

    def to(self, addr) -> list[bytes]:
        return [d for d, a in self.sent if a == addr]


def _relay_with_attack():
    params = CommandInjectionParams(trial_seed=0, trial_index=0, onset_s=0.0, burst_count=1,
                                    inter_injection_gap_s=0.0)
    attack = CommandInjectionAttack(params, warmup_s=0.0)
    up, down = _Up(), _Down()
    clock = [0]

    def tick() -> int:
        clock[0] += 1_000_000
        return clock[0]

    r = MavlinkRelay(up, down, up_hook=attack, down_hook=attack, mirror_uplink_to_clients=True,
                     clock_ns=lambda: clock[0], sleep=lambda s: None)
    # both clients register with a heartbeat BEFORE the PX4 target is learned (so nothing is injected yet)
    down.inbox += [(tick(), IDS, _gcs_heartbeat(254, 191)), (tick(), OTHER, _gcs_heartbeat(252, 193))]
    r.pump_once()
    up.inbox.append((tick(), _px4_heartbeat()))  # attack learns the PX4 target from this downlink heartbeat
    r.pump_once()
    return r, up, down, tick


def _rogue_in(frames: list[bytes]) -> list[bytes]:
    parser = MavlinkFrameParser()
    return [f for f in frames
            if any(e.sysid == ROGUE_SYSID and e.msgname == "COMMAND_LONG" for e in parser.parse(f, 0.0))]


def test_injected_frame_is_mirrored_to_the_ids_when_another_client_carries_it():
    """Positive control: injection rides on OTHER's heartbeat -> the IDS (a non-sender) receives it."""
    r, up, down, tick = _relay_with_attack()
    down.inbox.append((tick(), OTHER, _gcs_heartbeat(252, 193, seq=1)))
    r.pump_once()
    assert r.stats["mirrored_up"] >= 1
    assert len(_rogue_in(down.to(IDS))) == 1
    assert len(_rogue_in(up.sent)) == 1  # and PX4 got the injection


def test_ids_sees_injected_frame_even_when_its_own_heartbeat_is_the_carrier():
    """Regression for the 5/10 live detection split: the injection rides on the IDS tap's OWN heartbeat.
    PX4 gets it, and (since the mirror fix) so does the IDS -- the sender is excluded only from the echo of
    its own ORIGINAL frame, not from a frame the hook added."""
    r, up, down, tick = _relay_with_attack()
    down.inbox.append((tick(), IDS, _gcs_heartbeat(254, 191, seq=1)))
    r.pump_once()
    assert len(_rogue_in(up.sent)) == 1
    assert len(_rogue_in(down.to(IDS))) == 1
    assert len(_rogue_in(down.to(OTHER))) == 1  # every client sees the single injection exactly once


@pytest.mark.parametrize("carrier, other", [(IDS, OTHER), (OTHER, IDS)])
def test_sender_never_gets_an_echo_of_its_own_original_frame(carrier, other):
    """The fix must not create self-echoes: the carrier's original heartbeat goes to the other client only."""
    r, up, down, tick = _relay_with_attack()
    hb = _gcs_heartbeat(254 if carrier == IDS else 252, 191 if carrier == IDS else 193, seq=7)
    down.inbox.append((tick(), carrier, hb))
    r.pump_once()
    assert down.to(carrier).count(hb) == 0
    assert down.to(other).count(hb) == 1
    assert up.sent.count(hb) == 1  # PX4 still gets the original, unchanged


def test_hook_modified_uplink_frame_is_mirrored_to_all_clients_and_original_is_not():
    """A hook that REWRITES the carrier frame: the modified bytes (what PX4 receives) go to every client; the
    unmodified original is never seen by anyone. Counted once in ``mirrored_up``."""
    original = _gcs_heartbeat(252, 193, seq=3)
    modified = _gcs_heartbeat(252, 193, seq=4)

    def rewrite(ctx):
        return [modified] if ctx.raw == original else [ctx.raw]

    up, down = _Up(), _Down()
    r = MavlinkRelay(up, down, up_hook=rewrite, mirror_uplink_to_clients=True,
                     clock_ns=lambda: 1, sleep=lambda s: None)
    down.inbox += [(1, IDS, _gcs_heartbeat(254, 191)), (2, OTHER, _gcs_heartbeat(252, 193))]
    r.pump_once()
    before = r.stats["mirrored_up"]
    down.inbox.append((3, OTHER, original))
    r.pump_once()
    assert up.sent.count(modified) == 1 and up.sent.count(original) == 0
    assert down.to(IDS).count(modified) == 1 and down.to(OTHER).count(modified) == 1
    assert down.to(IDS).count(original) == 0 and down.to(OTHER).count(original) == 0
    assert r.stats["mirrored_up"] - before == 1


# --------------------------------------------------------------------------- #
# 4. real threads + real sockets, whole live chain (fake PX4 thread), ground-truth carrier recorded
# --------------------------------------------------------------------------- #


class _RecordingHook:
    """Wraps the real attack; records the carrier sysid of every injection. Changes no behaviour."""

    def __init__(self, attack: CommandInjectionAttack) -> None:
        self.attack = attack
        self.carriers: list[int] = []

    def __call__(self, ctx):
        out = self.attack(ctx)
        if ctx.direction == "up" and len(out) == 2:
            self.carriers.append(ctx.raw[5])  # MAVLink 2 header byte 5 = sysid of the carrier
        return out


def test_live_chain_every_injection_reaches_the_ids_exactly_once_whoever_carries_it(udp_ok):
    """Fake PX4 thread <-> real relay (real attack, mirroring on) <-> carrier client (252) + IDS client (254),
    both heartbeating at 20 Hz so either may carry any injection -> real ``LiveMavlinkSource``. Every injection
    (seq == injection index) must reach the IDS exactly once, in order, regardless of which client carried it."""
    px4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    px4.bind(("127.0.0.1", 0))
    px4.settimeout(0.002)
    stop = threading.Event()

    def fake_px4() -> None:
        m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
        peer = None
        last_hb = 0.0
        t_next = time.perf_counter()
        while not stop.is_set():
            try:
                _, peer = px4.recvfrom(2048)
            except OSError:
                pass
            if peer is None:
                continue
            now = time.perf_counter()
            if now - last_hb >= 0.2:
                last_hb = now
                px4.sendto(_px4_heartbeat(), peer)
            if now >= t_next:
                t_next += 0.01
                for _ in range(4):
                    px4.sendto(_px4_gpi(m), peer)

    pth = threading.Thread(target=fake_px4, daemon=True)
    pth.start()
    params = CommandInjectionParams(trial_seed=0, trial_index=0, onset_s=0.5, burst_count=40,
                                    inter_injection_gap_s=0.1)
    hook = _RecordingHook(CommandInjectionAttack(params, warmup_s=0.5))
    relay = make_udp_relay("127.0.0.1", px4.getsockname()[1], 0, up_hook=hook, down_hook=hook,
                           mirror_uplink_to_clients=True)
    carrier = ids_tr = None
    try:
        relay.start()
        assert relay.wait_upstream_alive(timeout=5.0)
        port = relay.downstream.local_address[1]
        ids_tr = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True, heartbeat_hz=20.0,
                                     gcs_sysid=254, gcs_compid=191)
        carrier = UdpMavlinkTransport(connect=("127.0.0.1", port), gcs_heartbeat=True, heartbeat_hz=20.0,
                                      gcs_sysid=252, gcs_compid=193)
        ids_tr.start()
        time.sleep(0.05)
        carrier.start()
        src = LiveMavlinkSource(ids_tr, sample_rate_hz=10.0, max_ticks=45)
        seen: list[int] = []
        for tick in src.stream():
            seen += [m.seq for m in tick.messages
                     if m.msgname == "COMMAND_LONG" and m.sysid == ROGUE_SYSID]
        stats = src.stats
    finally:
        for t in (ids_tr, carrier):
            if t is not None:
                t.close()
        relay.close()
        stop.set()
        pth.join(timeout=2)
        px4.close()
    assert len(hook.carriers) >= 10, f"inconclusive: only {len(hook.carriers)} injections happened"
    # injections can still be in flight at the very end of the stream: ignore the last 2
    must_see = set(range(len(hook.carriers) - 2))
    assert must_see <= set(seen), sorted(must_see - set(seen))
    assert len(seen) == len(set(seen)), "duplicate delivery"
    assert seen == sorted(seen), "out-of-order delivery"
    assert stats["bad_frames"] == 0 and stats["dropped_overflow"] == 0, stats
