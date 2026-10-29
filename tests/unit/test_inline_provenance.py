"""Unsigned-link provenance (sequence-counter tracker + replay set) on SYNTHETIC pymavlink frames."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.mitigation.inline_policy import MAV_CMD_NAV_LAND, InlinePolicy, SeqProvenance
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames


class Clock:
    t = 100.0

    def __call__(self) -> float:
        return self.t


def _ctx(raw: bytes) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction="up", raw=fr.raw, recv_ns=1, sysid=fr.sysid,  # type: ignore[arg-type]
                        compid=fr.compid, seq=fr.seq, msgid=fr.msgid, signed=fr.signed)


def _m(sysid: int, seq: int) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    m.robust_parsing = True
    m.seq = seq
    return m


def hb(sysid: int, seq: int) -> bytes:
    m = _m(sysid, seq)
    return bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))


def land(sysid: int, seq: int, p1: float = 0.0) -> bytes:
    m = _m(sysid, seq)
    return bytes(m.command_long_encode(1, 1, MAV_CMD_NAV_LAND, 0, p1, 0, 0, 0, 0, 0, 0).pack(m))


@pytest.fixture
def pol():
    p = InlinePolicy(FrameSanitizer(), clock=Clock())
    p.set_enforce(True)
    return p


def feed(p: InlinePolicy, seqs, sysid: int = 255) -> None:
    for s in seqs:
        p.up(_ctx(hb(sysid, s)))


def arm(p: InlinePolicy, armed: bool = True) -> None:
    p.armed = armed
    p.rel_alt_m = 30.0 if armed else 0.0
    p.groundspeed_ms = 5.0 if armed else 0.0


def test_forged_land_with_own_counter_dropped_in_flight(pol):
    feed(pol, range(10, 15))
    arm(pol)
    assert pol.up(_ctx(land(255, 200))) == []
    assert pol.dropped_provenance == 1
    assert pol.stats()["provenance_known_sources"] == 1


def test_forged_land_on_ground_passes_but_is_suspect(pol):
    feed(pol, range(10, 15))
    raw = land(255, 200)
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.suspect_provenance == 1 and pol.dropped_provenance == 0


def test_genuine_command_with_radio_loss_gap_passes(pol):
    feed(pol, range(10, 15))
    arm(pol)
    raw = land(255, 19)  # +5
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.dropped_provenance == 0 and pol.suspect_provenance == 0


def test_unknown_counter_passes(pol):
    feed(pol, [10, 11])
    arm(pol)
    raw = land(255, 200)
    assert pol.up(_ctx(raw)) == [raw]


def test_gcs_restart_resyncs_after_three_frames(pol):
    feed(pol, range(100, 106))
    arm(pol)
    pol._clock.t += 3.0  # the old stream is gone (restart), so the quiet period has passed
    assert pol.up(_ctx(land(255, 0))) == []
    pol.up(_ctx(hb(255, 1)))
    pol.up(_ctx(hb(255, 2)))  # third mutually consistent frame resyncs
    assert pol.resyncs == 1
    raw = land(255, 3)
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.stats()["resyncs"] == 1


def test_forged_frame_does_not_move_last_seq(pol):
    feed(pol, range(10, 15))
    arm(pol)
    pol.up(_ctx(land(255, 200)))
    t = pol._seq[(255, 190)]
    assert t.last == 14
    raw = land(255, 15)
    assert pol.up(_ctx(raw)) == [raw]


def test_byte_identical_replay_dropped(pol):
    feed(pol, range(10, 15))
    raw = land(255, 15)
    assert pol.up(_ctx(raw)) == [raw]
    pol._clock.t += 1.0  # type: ignore[attr-defined]
    assert pol.up(_ctx(raw)) == []
    assert pol.dropped_replay_unsigned == 1


def test_same_command_with_new_seq_passes(pol):
    feed(pol, range(10, 15))
    first, second = land(255, 15), land(255, 16)
    assert pol.up(_ctx(first)) == [first]
    pol._clock.t += 1.0  # type: ignore[attr-defined]
    assert pol.up(_ctx(second)) == [second]


def test_signing_key_bypasses_tracker():
    p = InlinePolicy(FrameSanitizer(), clock=Clock(), signing_key=bytes(range(32)))
    p.set_enforce(True)
    feed(p, range(10, 15))
    assert p.stats()["provenance_known_sources"] == 0
    assert p.up(_ctx(land(255, 15))) == []  # unsigned: the signature rules decide
    assert p.dropped_provenance == 0 and p.dropped_unsigned == 1


def test_enforce_off_is_byte_identical():
    p = InlinePolicy(FrameSanitizer(), clock=Clock())
    feed(p, range(10, 15))
    for raw in (land(255, 200), land(255, 200)):
        assert p.up(_ctx(raw)) == [raw]
    assert p.stats()["provenance_known_sources"] == 0


def test_provenance_off_option():
    p = InlinePolicy(FrameSanitizer(), clock=Clock(), provenance=False)
    p.set_enforce(True)
    feed(p, range(10, 15))
    arm(p)
    raw = land(255, 200)
    assert p.up(_ctx(raw)) == [raw]


def test_seq_provenance_wraparound_and_duplicate():
    t = SeqProvenance(16)
    for s in (250, 251, 252):
        t.observe(s)
    assert t.observe(2) == "consistent"      # wraps, +6
    assert t.observe(2) == "inconsistent"    # duplicate


def test_forger_consecutive_counter_next_to_live_pilot_cannot_take_over(pol):
    """SITL finding: a forger sending 3+ consecutive own-counter frames next to a live pilot must not resync."""
    feed(pol, range(100, 106))
    arm(pol)
    for i in range(6):                                 # forger: its own consecutive counter 0..5
        assert pol.up(_ctx(land(255, i))) == []
        pol._clock.t += 0.3
        if i % 3 == 2:
            feed(pol, [106 + i // 3])                  # the live pilot keeps sending its own frames
    assert pol.resyncs == 0
    raw = land(255, 108)                               # the genuine pilot is not locked out
    assert pol.up(_ctx(raw)) == [raw]


def test_seq_provenance_quiet_period_gates_resync():
    t = SeqProvenance(16, quiet_s=2.0)
    for i, s in enumerate((10, 11, 12)):
        t.observe(s, float(i))
    assert [t.observe(s, 3.0 + 0.1 * k) for k, s in enumerate((200, 201, 202))] == ["inconsistent"] * 3
    assert t.resyncs == 0
    assert t.observe(203, 5.0) == "consistent" and t.resyncs == 1


# -- wrap-around replay (count-bounded replay memory) --------------------------------------------------------- #

def _set_mode(sysid: int, seq: int, mode: int | None = None) -> bytes:
    m = _m(sysid, seq)
    return bytes(m.command_long_encode(1, 1, 176, 0, 1, seq if mode is None else mode, 0, 0, 0, 0, 0).pack(m))


def _disarm(sysid: int, seq: int, magic: float = 0.0) -> bytes:
    m = _m(sysid, seq)
    return bytes(m.command_long_encode(1, 1, 400, 0, 0.0, magic, 0, 0, 0, 0, 0).pack(m))


def test_replay_after_counter_wrap_is_dropped_by_filter_not_provenance(pol):
    feed(pol, range(10, 15))
    cap = _set_mode(255, 15)
    assert pol.up(_ctx(cap)) == [cap]
    pol._clock.t += 3600.0  # no time limit any more
    feed(pol, [s % 256 for s in range(16, 16 + 255)])  # 255 fillers: the counter is back just below 15 (seq 14)
    assert pol.up(_ctx(cap)) == []
    assert pol.dropped_replay_unsigned == 1 and pol.dropped_provenance == 0


def test_replay_filter_applies_even_when_source_counter_unknown(pol):
    raw = _set_mode(255, 40)
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.up(_ctx(raw)) == []


def test_replay_memory_is_count_bounded():
    p = InlinePolicy(FrameSanitizer(), clock=Clock(), replay_memory=4)
    p.set_enforce(True)
    first = _set_mode(255, 1)
    p.up(_ctx(first))
    for s in range(2, 7):
        p.up(_ctx(_set_mode(255, s)))
    assert len(p._seen) == 4
    assert p.up(_ctx(first)) == [first]  # evicted by count only


def test_repeated_legit_command_with_new_seq_passes_after_wrap(pol):
    feed(pol, range(10, 15))
    for s in (15, 16, 17):
        raw = _set_mode(255, s)
        assert pol.up(_ctx(raw)) == [raw]


# -- contested source (two transmitters) --------------------------------------------------------------------- #

def _contest(p: InlinePolicy) -> None:
    feed(p, range(10, 15))
    p.up(_ctx(hb(255, 15)))
    p.up(_ctx(_set_mode(255, 15)))  # same seq, different payload, same instant


def test_same_seq_different_payload_marks_contested_and_alarms_once(pol):
    _contest(pol)
    assert pol.contested_events == 1 and pol.is_contested(255)
    assert pol.take_alarms() == [255]
    pol._clock.t += 1.0
    feed(pol, [16])
    pol.up(_ctx(_set_mode(255, 16)))  # a second event inside the alarm interval: counted, not re-alarmed
    assert pol.contested_events == 2 and pol.take_alarms() == []
    assert pol.stats()["contested_sources"] == 1 and pol.contested_alarms == 1
    pol._clock.t += 11.0  # past the alarm interval and still inside the hold: next event alarms again
    feed(pol, [17])
    pol.up(_ctx(_set_mode(255, 17)))
    assert pol.take_alarms() == [255]


def test_contested_expires_after_hold(pol):
    _contest(pol)
    pol._clock.t += 61.0
    assert not pol.is_contested(255)


def test_same_seq_same_payload_is_not_contested(pol):
    feed(pol, range(10, 15))
    pol.up(_ctx(hb(255, 15)))
    pol.up(_ctx(hb(255, 15)))
    assert pol.contested_events == 0


def test_alert_mode_never_drops_contested(pol):
    _contest(pol)
    arm(pol)
    raw = _set_mode(255, 16)
    assert pol.up(_ctx(raw)) == [raw] and pol.dropped_contested == 0


def test_drop_sensitive_drops_in_flight_only():
    p = InlinePolicy(FrameSanitizer(), clock=Clock(), contested_policy="drop-sensitive")
    p.set_enforce(True)
    _contest(p)
    raw = _set_mode(255, 16)
    assert p.up(_ctx(raw)) == [raw]  # on the ground: not dropped
    arm(p)
    assert p.up(_ctx(_set_mode(255, 17, mode=9))) == []
    assert p.dropped_contested == 1
    hbf = hb(255, 18)
    assert p.up(_ctx(hbf)) == [hbf]  # non-sensitive traffic still flows


def test_drop_sensitive_never_drops_forced_disarm():
    p = InlinePolicy(FrameSanitizer(), clock=Clock(), contested_policy="drop-sensitive")
    p.set_enforce(True)
    _contest(p)
    arm(p)
    forced = _disarm(255, 16, magic=21196.0)
    assert p.up(_ctx(forced)) == [forced]
    assert p.up(_ctx(_disarm(255, 17))) == []


def test_bad_contested_policy_rejected():
    with pytest.raises(ValueError):
        InlinePolicy(FrameSanitizer(), contested_policy="kill")
