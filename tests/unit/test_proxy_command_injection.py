"""Unit tests for ``aegisflight.proxy.attacks_live.CommandInjectionAttack`` and
``draw_command_injection_params`` -- docs/ATTACK_PROXY.md (second live attack, uplink
COMMAND_LONG injection). Synthetic MAVLink 2/1 frames built with pymavlink's dialects; no
sockets, no PX4, no transport module involved."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.proxy.attacks_live import (
    COMMAND_INJECTION_RANGES,
    DEFAULT_COMMAND,
    DEFAULT_COMMAND_PARAMS,
    DEFAULT_ROGUE_COMPID,
    DEFAULT_ROGUE_SYSID,
    CommandInjectionAttack,
    CommandInjectionParams,
    draw_command_injection_params,
)
from aegisflight.proxy.groundtruth import (
    FrameLogWriter,
    compute_command_injection_effect,
    read_frame_log,
)
from aegisflight.proxy.hooks import FrameContext

# onset=5s, burst_count=3, inter_injection_gap_s=1.0
PARAMS = CommandInjectionParams(
    trial_seed=1, trial_index=0, onset_s=5.0, burst_count=3, inter_injection_gap_s=1.0
)


def _fresh_attack(**kw) -> CommandInjectionAttack:
    return CommandInjectionAttack(PARAMS, warmup_s=0.0, **kw)


def _mk(sysid: int, compid: int, seq: int, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def hb_raw(seq: int = 0, sysid: int = 3, compid: int = 1, autopilot: int = 12) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, autopilot, 0x80, 0, 4).pack(m))


def gcs_hb_raw(seq: int = 0, sysid: int = 255, compid: int = 190, dialect=mav2,
               signed: bool = False) -> bytes:
    """A real client's (legitimate GCS) periodic uplink heartbeat -- the piggyback carrier."""
    m = _mk(sysid, compid, seq, dialect)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4).pack(m))


def ack_raw(command: int = DEFAULT_COMMAND, result: int = mav2.MAV_RESULT_ACCEPTED, seq: int = 0,
            sysid: int = 3, compid: int = 1, signed: bool = False) -> bytes:
    m = _mk(sysid, compid, seq)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(m.command_ack_encode(command, result).pack(m))


def ctx_for(raw: bytes, direction: str = "up", recv_ns: int = 0) -> FrameContext:
    """Parse header fields straight off the bytes -- what the real transport supplies."""
    if raw[0] == 0xFD:
        incompat = raw[2]
        seq, sysid, compid = raw[4], raw[5], raw[6]
        msgid = raw[7] | (raw[8] << 8) | (raw[9] << 16)
        signed = bool(incompat & 0x01)
    else:
        seq, sysid, compid, msgid = raw[2], raw[3], raw[4], raw[5]
        signed = False
    return FrameContext(
        direction=direction, raw=raw, recv_ns=recv_ns, sysid=sysid, compid=compid, seq=seq,
        msgid=msgid, signed=signed,
    )


def decode(raw: bytes):
    return mav2.MAVLink(None).decode(bytearray(raw))


def _learn(a: CommandInjectionAttack, recv_ns: int = 0) -> None:
    """Learn the PX4 target from a downlink HEARTBEAT *and* establish the uplink elapsed-time
    baseline (``_first_client_recv_ns``) via a priming uplink frame -- both at ``recv_ns``
    (default 0), separate from the timed call(s) a test makes afterwards. Mirrors
    ``PositionDriftAttack``'s test convention of a dedicated baseline-establishing call before
    the timed assertions (its own ``_learn`` + the ``test_configured_target_skips_heartbeat_
    learning`` two-call pattern)."""
    a(ctx_for(hb_raw(), "down", recv_ns=recv_ns))
    a(ctx_for(gcs_hb_raw(seq=0), "up", recv_ns=recv_ns))


# --------------------------------------------------------------------------- #
# pass-through: real frames are never dropped/modified; fail-closed before learning
# --------------------------------------------------------------------------- #


def test_real_uplink_frame_always_passed_through_unchanged_before_learning():
    a = _fresh_attack()
    raw = gcs_hb_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_injected == 0


def test_real_uplink_frame_byte_identical_even_when_injecting():
    a = _fresh_attack()
    _learn(a)
    raw = gcs_hb_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))  # elapsed 8s >= onset 5s
    assert out[0] == raw  # the real frame is untouched, always first
    assert len(out) == 2
    assert a.frames_injected == 1


def test_before_onset_no_injection():
    a = _fresh_attack()
    _learn(a)
    raw = gcs_hb_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=2_000_000_000))  # elapsed 2s < onset 5s
    assert out == [raw]
    assert a.frames_injected == 0


def test_downlink_frames_never_modified():
    a = _fresh_attack()
    _learn(a)
    raw = hb_raw(seq=5)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]


# --------------------------------------------------------------------------- #
# target learning (same convention as PositionDriftAttack)
# --------------------------------------------------------------------------- #


def test_target_learned_from_px4_heartbeat_only():
    a = _fresh_attack()
    a(ctx_for(hb_raw(sysid=4, compid=1, autopilot=3), "down", recv_ns=0))  # not PX4 (12)
    a(ctx_for(gcs_hb_raw(seq=0), "up", recv_ns=0))  # prime the uplink baseline regardless
    raw = gcs_hb_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out == [raw] and a.frames_injected == 0  # fail closed: not learned

    a(ctx_for(hb_raw(sysid=3, compid=1, autopilot=12), "down", recv_ns=0))
    out2 = a(ctx_for(gcs_hb_raw(seq=2), "up", recv_ns=16_000_000_000))  # elapsed 16s, now learned
    assert len(out2) == 2
    assert a.frames_injected == 1


def test_configured_target_skips_heartbeat_learning():
    a = CommandInjectionAttack(PARAMS, warmup_s=0.0, target_sysid=3, target_compid=1)
    # first uplink frame establishes the elapsed-time baseline (elapsed 0 -> before onset)
    first = gcs_hb_raw(seq=0)
    out0 = a(ctx_for(first, "up", recv_ns=0))
    assert out0 == [first] and a.frames_injected == 0
    raw = gcs_hb_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))  # no heartbeat ever seen; elapsed 8s
    assert len(out) == 2
    injected = decode(out[1])
    assert (injected.target_system, injected.target_component) == (3, 1)


def test_partial_target_configuration_rejected():
    with pytest.raises(ValueError):
        CommandInjectionAttack(PARAMS, target_sysid=3, target_compid=None)
    with pytest.raises(ValueError):
        CommandInjectionAttack(PARAMS, target_sysid=None, target_compid=1)


def test_command_params_wrong_length_rejected():
    with pytest.raises(ValueError):
        CommandInjectionAttack(PARAMS, command_params=(0.0, 1.0))


# --------------------------------------------------------------------------- #
# the injected frame itself: validity, identity, command
# --------------------------------------------------------------------------- #


def test_injected_frame_parses_cleanly_with_rogue_identity_and_command():
    a = _fresh_attack()
    _learn(a)
    out = a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    assert len(out) == 2
    injected = decode(out[1])
    assert injected.get_type() == "COMMAND_LONG"
    assert injected.get_srcSystem() == DEFAULT_ROGUE_SYSID
    assert injected.get_srcComponent() == DEFAULT_ROGUE_COMPID
    assert injected.command == DEFAULT_COMMAND
    assert injected.target_system == 3  # learned PX4 sysid
    assert injected.target_component == 1  # learned PX4 compid
    assert injected.param1 == pytest.approx(DEFAULT_COMMAND_PARAMS[0])
    assert injected.param2 == pytest.approx(DEFAULT_COMMAND_PARAMS[1])


def test_injected_frame_rogue_seq_increments_independently_of_carrier_seq():
    a = _fresh_attack()
    _learn(a)
    out1 = a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    out2 = a(ctx_for(gcs_hb_raw(seq=77), "up", recv_ns=9_500_000_000))  # gap 1.5s >= 1.0s
    seq1 = decode(out1[1]).get_seq()
    seq2 = decode(out2[1]).get_seq()
    assert (seq1, seq2) == (0, 1)


def test_configurable_rogue_identity_and_command():
    a = CommandInjectionAttack(
        PARAMS, warmup_s=0.0, rogue_sysid=200, rogue_compid=17,
        command=mav2.MAV_CMD_DO_SET_MODE, command_params=(1.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0),
    )
    _learn(a)
    out = a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    injected = decode(out[1])
    assert injected.get_srcSystem() == 200
    assert injected.get_srcComponent() == 17
    assert injected.command == mav2.MAV_CMD_DO_SET_MODE


# --------------------------------------------------------------------------- #
# burst count / gap timing
# --------------------------------------------------------------------------- #


def test_burst_count_caps_total_injections():
    a = _fresh_attack()  # burst_count=3, gap=1.0s
    _learn(a)
    times_ns = [8_000_000_000, 9_200_000_000, 10_500_000_000, 11_800_000_000, 13_000_000_000]
    injected_counts = []
    for i, t in enumerate(times_ns, start=1):
        out = a(ctx_for(gcs_hb_raw(seq=i), "up", recv_ns=t))
        injected_counts.append(len(out) - 1)
    assert sum(injected_counts) == 3
    assert a.frames_injected == 3


def test_inter_injection_gap_enforced():
    a = _fresh_attack()  # gap=1.0s
    _learn(a)
    out1 = a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    assert len(out1) == 2
    out2 = a(ctx_for(gcs_hb_raw(seq=2), "up", recv_ns=8_500_000_000))  # only 0.5s later
    assert len(out2) == 1  # gap not satisfied -> no second injection yet
    out3 = a(ctx_for(gcs_hb_raw(seq=3), "up", recv_ns=9_200_000_000))  # 1.2s after first
    assert len(out3) == 2


# --------------------------------------------------------------------------- #
# signed frames and MAVLink 1
# --------------------------------------------------------------------------- #


def test_signed_carrier_frame_is_never_used_to_piggyback():
    a = _fresh_attack()
    _learn(a)
    raw = gcs_hb_raw(seq=1, signed=True)
    ctx = ctx_for(raw, "up", recv_ns=8_000_000_000)
    assert ctx.signed
    out = a(ctx)
    assert out == [raw]
    assert a.frames_injected == 0
    assert a.frames_skipped_signed == 1


def test_mavlink1_carrier_frame_still_gets_injection_appended():
    # Unlike PositionDriftAttack (which must decode the frame it rewrites and therefore
    # requires a v2 target), this attack never decodes the carrier -- only header fields the
    # transport already parsed -- so a v1 carrier is a valid piggyback host.
    a = _fresh_attack()
    _learn(a)
    raw = gcs_hb_raw(seq=1, dialect=mav1)
    assert raw[0] == 0xFE
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out[0] == raw
    assert len(out) == 2
    injected = decode(out[1])
    assert injected.get_type() == "COMMAND_LONG"


def test_truncated_garbage_carrier_never_raises():
    a = _fresh_attack()
    _learn(a)
    raw = gcs_hb_raw(seq=1)[:10]
    ctx = FrameContext(direction="up", raw=raw, recv_ns=8_000_000_000, sysid=255, compid=190,
                        seq=1, msgid=0, signed=False)
    out = a(ctx)  # must not raise
    assert raw in out


# --------------------------------------------------------------------------- #
# ack-watching (down_hook)
# --------------------------------------------------------------------------- #


def test_ack_observed_and_logged_when_command_matches(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))  # injects
        a(ctx_for(ack_raw(command=DEFAULT_COMMAND, result=mav2.MAV_RESULT_ACCEPTED), "down",
                  recv_ns=8_050_000_000))

    entries = read_frame_log(path)
    actions = [e.action for e in entries]
    assert "injected" in actions
    assert "observed_ack" in actions
    ack_entry = next(e for e in entries if e.action == "observed_ack")
    assert ack_entry.field_deltas["result"] == mav2.MAV_RESULT_ACCEPTED
    assert ack_entry.field_deltas["command"] == DEFAULT_COMMAND


def test_ack_with_different_command_id_not_attributed(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))  # injects DISARM (400)
        a(ctx_for(ack_raw(command=mav2.MAV_CMD_DO_SET_MODE, result=mav2.MAV_RESULT_ACCEPTED),
                  "down", recv_ns=8_050_000_000))

    entries = read_frame_log(path)
    assert all(e.action != "observed_ack" for e in entries)


def test_ack_before_any_injection_ignored(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(ack_raw(command=DEFAULT_COMMAND), "down", recv_ns=1_000_000_000))

    entries = read_frame_log(path)
    assert entries == []


def test_signed_ack_frame_not_recognised():
    a = _fresh_attack()
    _learn(a)
    a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    out = a(ctx_for(ack_raw(signed=True), "down", recv_ns=8_050_000_000))
    assert len(out) == 1  # passthrough; no exception, no observed_ack side effect visible here


def test_mavlink1_ack_not_recognised():
    a = _fresh_attack()
    _learn(a)
    a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
    m1 = mav1.MAVLink(None, srcSystem=3, srcComponent=1)
    m1.seq = 0
    v1raw = bytes(m1.command_ack_encode(DEFAULT_COMMAND, mav2.MAV_RESULT_ACCEPTED).pack(m1))
    out = a(ctx_for(v1raw, "down", recv_ns=8_050_000_000))
    assert out == [v1raw]


# --------------------------------------------------------------------------- #
# determinism
# --------------------------------------------------------------------------- #


def test_deterministic_given_same_params_and_frame_sequence():
    def run() -> list[bytes]:
        a = _fresh_attack()
        _learn(a)
        outs: list[bytes] = []
        for i, recv_ns in enumerate([8_000_000_000, 9_500_000_000, 11_000_000_000], start=1):
            out = a(ctx_for(gcs_hb_raw(seq=i), "up", recv_ns=recv_ns))
            outs.extend(out)
        return outs

    assert run() == run()


# --------------------------------------------------------------------------- #
# draw_command_injection_params: ranges, determinism, independence
# --------------------------------------------------------------------------- #


def test_draw_params_within_ranges():
    for seed in (1, 2, 3, 100, 20261006):
        p = draw_command_injection_params(seed)
        assert COMMAND_INJECTION_RANGES["onset_s"][0] <= p.onset_s < COMMAND_INJECTION_RANGES["onset_s"][1]
        lo, hi = COMMAND_INJECTION_RANGES["burst_count"]
        assert round(lo) <= p.burst_count <= round(hi)
        gap_lo, gap_hi = COMMAND_INJECTION_RANGES["inter_injection_gap_s"]
        assert gap_lo <= p.inter_injection_gap_s < gap_hi
        assert p.trial_seed == seed


def test_draw_params_trial_seed_is_seed_plus_trial_index():
    p = draw_command_injection_params(100, trial_index=3)
    assert p.trial_seed == 103
    assert p.trial_index == 3


def test_draw_params_deterministic_repeat():
    assert draw_command_injection_params(42, 3) == draw_command_injection_params(42, 3)


def test_draw_params_differs_across_seeds():
    p1 = draw_command_injection_params(1)
    p2 = draw_command_injection_params(2)
    assert (p1.onset_s, p1.burst_count, p1.inter_injection_gap_s) != (
        p2.onset_s, p2.burst_count, p2.inter_injection_gap_s,
    )


# --------------------------------------------------------------------------- #
# frame-log / manifest round-trip via compute_command_injection_effect
# --------------------------------------------------------------------------- #


def test_compute_command_injection_effect_no_ack(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))

    result = compute_command_injection_effect(path)
    assert result["frames_injected"] == 1
    assert result["acked"] is False
    assert result["ack_count"] == 0
    assert result["first_ack_result"] is None
    assert result["time_to_first_ack_s"] is None


def test_compute_command_injection_effect_with_ack_latency(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
        a(ctx_for(ack_raw(result=mav2.MAV_RESULT_ACCEPTED), "down", recv_ns=8_300_000_000))

    result = compute_command_injection_effect(path)
    assert result["frames_injected"] == 1
    assert result["acked"] is True
    assert result["ack_count"] == 1
    assert result["first_ack_result"] == mav2.MAV_RESULT_ACCEPTED
    assert result["first_ack_result_name"] == "MAV_RESULT_ACCEPTED"
    assert result["time_to_first_ack_s"] == pytest.approx(0.3, rel=1e-3)


def test_frame_log_round_trip_preserves_action_values(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = CommandInjectionAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        a(ctx_for(gcs_hb_raw(seq=1), "up", recv_ns=8_000_000_000))
        a(ctx_for(ack_raw(), "down", recv_ns=8_300_000_000))
    entries = read_frame_log(path)
    assert {e.action for e in entries} == {"injected", "observed_ack"}


def test_detector_fields_never_touched_by_this_module():
    a = _fresh_attack()
    assert not hasattr(a, "detector_decision")
    assert not hasattr(a, "time_to_detection_s")


# --------------------------------------------------------------------------- #
# seq_policy: impersonating an identity that is really transmitting (expected GCS 255/190)
# --------------------------------------------------------------------------- #


def _impersonator(**kw) -> CommandInjectionAttack:
    return CommandInjectionAttack(PARAMS, warmup_s=0.0, rogue_sysid=255, rogue_compid=190, **kw)


def test_default_seq_policy_impersonating_gcs_still_uses_own_counter_from_zero():
    a = _impersonator()
    _learn(a)
    out = a(ctx_for(gcs_hb_raw(seq=17), "up", recv_ns=8_000_000_000))
    inj = decode(out[1])
    assert (inj.get_srcSystem(), inj.get_srcComponent()) == (255, 190)
    assert inj.get_seq() == 0  # unchanged default behaviour: independent of the real 255/190 counter


def test_track_identity_continues_the_impersonated_identitys_real_counter():
    a = _impersonator(seq_policy="track_identity")
    _learn(a)  # primes with a 255/190 frame, seq 0
    out1 = a(ctx_for(gcs_hb_raw(seq=17), "up", recv_ns=8_000_000_000))
    assert decode(out1[1]).get_seq() == 18
    # the real identity advances; the next forgery continues from ITS counter, not from the previous forgery
    a(ctx_for(gcs_hb_raw(seq=18), "up", recv_ns=8_400_000_000))
    out2 = a(ctx_for(gcs_hb_raw(seq=19), "up", recv_ns=9_500_000_000))
    assert decode(out2[1]).get_seq() == 20


def test_track_identity_carrier_from_another_client_still_continues_the_identitys_counter():
    a = _impersonator(seq_policy="track_identity")
    _learn(a)
    a(ctx_for(gcs_hb_raw(seq=40), "up", recv_ns=7_000_000_000))  # identity frame (also not due yet -> no inject? onset 5s)
    other = a(ctx_for(gcs_hb_raw(seq=3, sysid=254, compid=191), "up", recv_ns=9_000_000_000))
    forged = [decode(r) for r in other[1:]]
    assert forged and forged[0].get_seq() == 42  # 40 was the last 255/190 frame seen; 41 was used at 7s


def test_track_identity_burst_without_new_identity_frames_increments():
    a = _impersonator(seq_policy="track_identity")
    _learn(a)
    a(ctx_for(gcs_hb_raw(seq=9, sysid=252, compid=193), "up", recv_ns=1_000_000_000))  # not the identity
    out1 = a(ctx_for(gcs_hb_raw(seq=5, sysid=252, compid=193), "up", recv_ns=8_000_000_000))
    out2 = a(ctx_for(gcs_hb_raw(seq=6, sysid=252, compid=193), "up", recv_ns=9_500_000_000))
    assert [decode(out1[1]).get_seq(), decode(out2[1]).get_seq()] == [1, 2]  # _learn's 255/190 frame had seq 0


def test_track_identity_seq_wraps_modulo_256():
    a = _impersonator(seq_policy="track_identity")
    _learn(a)
    out = a(ctx_for(gcs_hb_raw(seq=255), "up", recv_ns=8_000_000_000))
    assert decode(out[1]).get_seq() == 0


def test_track_identity_fails_closed_until_the_identity_has_been_seen():
    a = _impersonator(seq_policy="track_identity")
    a(ctx_for(hb_raw(), "down", recv_ns=0))  # learn the PX4 target only
    a(ctx_for(gcs_hb_raw(seq=4, sysid=252, compid=193), "up", recv_ns=0))  # sets the elapsed baseline
    out = a(ctx_for(gcs_hb_raw(seq=5, sysid=252, compid=193), "up", recv_ns=8_000_000_000))
    assert len(out) == 1  # nothing to continue -> nothing injected
    assert a.frames_skipped_no_identity_seq == 1 and a.frames_injected == 0
    out = a(ctx_for(gcs_hb_raw(seq=7), "up", recv_ns=8_500_000_000))  # now 255/190 speaks: its own frame carries it
    assert len(out) == 2 and decode(out[1]).get_seq() == 8


def test_track_identity_ignores_a_signed_identity_frame_for_learning():
    a = _impersonator(seq_policy="track_identity")
    a(ctx_for(hb_raw(), "down", recv_ns=0))
    out = a(ctx_for(gcs_hb_raw(seq=30, signed=True), "up", recv_ns=8_000_000_000))
    assert len(out) == 1  # signed: not learned from, and never used as a carrier


def test_unknown_seq_policy_rejected():
    with pytest.raises(ValueError):
        CommandInjectionAttack(PARAMS, seq_policy="bogus")  # type: ignore[arg-type]
