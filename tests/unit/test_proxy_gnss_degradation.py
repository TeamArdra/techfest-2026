"""Unit tests for ``aegisflight.proxy.attacks_live.GnssDegradationAttack`` and
``draw_gnss_degradation_params`` / ``compute_gnss_degradation_effect``. Synthetic MAVLink
frames built with pymavlink dialects; no sockets, no PX4."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import DEFAULT_DETECTOR
from aegisflight.detectors import ProtocolDetector
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.proxy.attacks_live import (
    GNSS_DEGRADATION_RANGES,
    GnssDegradationAttack,
    GnssDegradationParams,
    draw_gnss_degradation_params,
)
from aegisflight.proxy.groundtruth import (
    FrameLogWriter,
    compute_gnss_degradation_effect,
    read_frame_log,
)
from aegisflight.proxy.hooks import FrameContext
from aegisflight.sources.mavlink_live import MavlinkFrameParser

# onset=5, duration=10 -> window [5, 15); degrade to fix_type=1, 3 satellites
PARAMS = GnssDegradationParams(
    trial_seed=1, trial_index=0, onset_s=5.0, duration_s=10.0, fix_type=1, satellites_visible=3
)

LAT, LON, ALT = 473977418, 85455940, 488000


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def gps_raw(
    seq: int = 0, sysid: int = 3, compid: int = 1, fix_type: int = 3, sats: int = 10,
    dialect=mav2, signed: bool = False,
) -> bytes:
    m = _mk(sysid, compid, seq, dialect)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(
        m.gps_raw_int_encode(123456, fix_type, LAT, LON, ALT, 121, 200, 450, 9000, sats).pack(m)
    )


def gpi_raw(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.global_position_int_encode(1000, LAT, LON, ALT, 12000, 10, -20, 30, 9000).pack(m))


def hb_raw(seq: int = 0, sysid: int = 3, compid: int = 1, autopilot: int = 12) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, autopilot, 0x80, 0, 4).pack(m))


def ctx_for(raw: bytes, direction: str = "down", recv_ns: int = 0) -> FrameContext:
    if raw[0] == 0xFD:
        seq, sysid, compid = raw[4], raw[5], raw[6]
        msgid = raw[7] | (raw[8] << 8) | (raw[9] << 16)
        signed = bool(raw[2] & 0x01)
    else:
        seq, sysid, compid, msgid = raw[2], raw[3], raw[4], raw[5]
        signed = False
    return FrameContext(
        direction=direction, raw=raw, recv_ns=recv_ns, sysid=sysid, compid=compid, seq=seq,
        msgid=msgid, signed=signed,
    )


def decode(raw: bytes):
    return mav2.MAVLink(None).decode(bytearray(raw))


def _attack(**kw) -> GnssDegradationAttack:
    return GnssDegradationAttack(PARAMS, warmup_s=0.0, **kw)


def _learn(a: GnssDegradationAttack, recv_ns: int = 0) -> None:
    a(ctx_for(hb_raw(), "down", recv_ns=recv_ns))


# --------------------------------------------------------------------------- #
# pass-through: direction, identity, msgid, window
# --------------------------------------------------------------------------- #


def test_fail_closed_before_target_learned():
    a = _attack()
    raw = gps_raw(seq=1)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert a.frames_modified == 0


def test_up_direction_always_passthrough():
    a = _attack()
    _learn(a)
    raw = gps_raw(seq=1)
    assert a(ctx_for(raw, "up", recv_ns=6_000_000_000)) == [raw]
    assert a.frames_modified == 0


def test_other_message_ids_passthrough_byte_identical_inside_window():
    a = _attack()
    _learn(a)
    raw = gpi_raw(seq=1)  # GLOBAL_POSITION_INT must NOT be touched by this attack
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert a.frames_modified == 0


def test_other_source_passthrough():
    a = _attack()
    _learn(a)
    raw = gps_raw(seq=1, sysid=9, compid=2)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert a.frames_modified == 0


def test_before_onset_and_after_window_passthrough():
    a = _attack()
    _learn(a, recv_ns=0)
    early, late = gps_raw(seq=1), gps_raw(seq=2)
    assert a(ctx_for(early, "down", recv_ns=4_900_000_000)) == [early]
    assert a(ctx_for(late, "down", recv_ns=15_000_000_000)) == [late]  # window is half-open [5, 15)
    assert a.frames_modified == 0


def test_warmup_floor_delays_window_open():
    a = GnssDegradationAttack(PARAMS, warmup_s=8.0)
    _learn(a, recv_ns=0)
    raw = gps_raw(seq=1)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]  # in window, but < warmup
    (after,) = a(ctx_for(gps_raw(seq=2), "down", recv_ns=9_000_000_000))
    assert decode(after).fix_type == PARAMS.fix_type  # actually degraded, not merely a different seq
    assert a.frames_modified == 1


def test_extension_fields_and_length_unchanged_with_nonzero_extensions():
    # GPS_RAW_INT has MAVLink-2 extension fields (alt_ellipsoid, h_acc, v_acc, vel_acc, hdg_acc, yaw);
    # a rewrite must not zero or drop them. Build a frame with every extension nonzero.
    m = _mk(3, 1, 5)
    orig = bytes(m.gps_raw_int_encode(
        123456, 3, LAT, LON, ALT, 121, 200, 450, 9000, 10,
        alt_ellipsoid=490000, h_acc=1500, v_acc=2500, vel_acc=300, hdg_acc=4000, yaw=18000,
    ).pack(m))
    a = _attack()
    _learn(a)
    (new,) = a(ctx_for(orig, "down", recv_ns=6_000_000_000))
    o, n = decode(orig), decode(new)
    assert len(new) == len(orig)
    for field in ("alt_ellipsoid", "h_acc", "v_acc", "vel_acc", "hdg_acc", "yaw"):
        assert getattr(o, field) != 0 and getattr(n, field) == getattr(o, field), field
    assert (n.fix_type, n.satellites_visible) == (PARAMS.fix_type, PARAMS.satellites_visible)


def test_already_degraded_input_is_still_rewritten_and_logged_as_modified():
    a = _attack()
    _learn(a)
    (new,) = a(ctx_for(gps_raw(seq=1, fix_type=PARAMS.fix_type, sats=PARAMS.satellites_visible),
                       "down", recv_ns=6_000_000_000))
    assert (decode(new).fix_type, decode(new).satellites_visible) == (PARAMS.fix_type, PARAMS.satellites_visible)
    assert a.frames_modified == 1


def test_target_learned_from_px4_heartbeat_only():
    a = _attack()
    a(ctx_for(hb_raw(autopilot=3), "down"))  # ArduPilot, not PX4
    assert a._target_sysid is None
    a(ctx_for(hb_raw(autopilot=12), "down"))
    assert (a._target_sysid, a._target_compid) == (3, 1)


def test_partial_target_configuration_rejected():
    with pytest.raises(ValueError):
        GnssDegradationAttack(PARAMS, target_sysid=1)


# --------------------------------------------------------------------------- #
# the modification itself
# --------------------------------------------------------------------------- #


def test_modifies_only_fix_type_and_satellites():
    a = _attack()
    _learn(a)
    orig = gps_raw(seq=7)
    (new,) = a(ctx_for(orig, "down", recv_ns=6_000_000_000))
    o, n = decode(orig), decode(new)  # decode() also validates the recomputed CRC
    assert (n.fix_type, n.satellites_visible) == (PARAMS.fix_type, PARAMS.satellites_visible)
    assert (o.fix_type, o.satellites_visible) == (3, 10)
    for field in ("time_usec", "lat", "lon", "alt", "eph", "epv", "vel", "cog"):
        assert getattr(n, field) == getattr(o, field), field
    assert a.frames_modified == 1


def test_header_unchanged_and_crc_valid():
    a = _attack()
    _learn(a)
    orig = gps_raw(seq=42, sysid=3, compid=1)
    (new,) = a(ctx_for(orig, "down", recv_ns=6_000_000_000))
    assert new != orig
    assert (new[5], new[6], new[4]) == (3, 1, 42)  # sysid, compid, seq
    assert new[7:10] == orig[7:10]  # msgid
    decode(new)  # raises on a bad CRC


def test_every_frame_in_window_is_modified():
    a = _attack()
    _learn(a)
    for i, t in enumerate([5.0, 7.0, 9.5, 14.9], start=1):
        (new,) = a(ctx_for(gps_raw(seq=i), "down", recv_ns=int(t * 1e9)))
        assert decode(new).fix_type == PARAMS.fix_type
    assert a.frames_modified == 4


def test_signed_frame_never_modified_and_counted():
    a = _attack()
    _learn(a)
    raw = gps_raw(seq=1, signed=True)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert (a.frames_skipped_signed, a.frames_modified) == (1, 0)


def test_mavlink1_frame_passes_through():
    a = _attack()
    _learn(a)
    raw = gps_raw(seq=1, dialect=mav1)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert a.frames_modified == 0


def test_corrupt_payload_never_raises_and_passes_through():
    a = _attack()
    _learn(a)
    bad = bytearray(gps_raw(seq=1))
    bad[-1] ^= 0xFF  # corrupt the CRC
    assert a(ctx_for(bytes(bad), "down", recv_ns=6_000_000_000)) == [bytes(bad)]
    trunc = gps_raw(seq=2)[:12]
    assert a(ctx_for(trunc, "down", recv_ns=6_100_000_000)) == [trunc]
    assert a.frames_modified == 0


def test_deterministic_given_same_params_and_frame_sequence():
    outs = []
    for _ in range(2):
        a = _attack()
        _learn(a)
        outs.append([a(ctx_for(gps_raw(seq=i), "down", recv_ns=int(t * 1e9)))
                     for i, t in enumerate([1.0, 6.0, 10.0, 20.0], start=1)])
    assert outs[0] == outs[1]


def test_no_drops_or_injections():
    a = _attack()
    _learn(a)
    a(ctx_for(gps_raw(seq=1), "down", recv_ns=6_000_000_000))
    assert (a.frames_dropped, a.frames_injected) == (0, 0)


# --------------------------------------------------------------------------- #
# parameter draw
# --------------------------------------------------------------------------- #


def test_draw_within_disclosed_ranges():
    for idx in range(50):
        p = draw_gnss_degradation_params(100, idx)
        for name in ("onset_s", "duration_s"):
            lo, hi = GNSS_DEGRADATION_RANGES[name]
            assert lo <= getattr(p, name) <= hi
        # degraded values are strictly sub-threshold for the protocol rule (3 / 5)
        assert p.fix_type in (0, 1) and p.fix_type < 3
        assert 0 <= p.satellites_visible <= 4 and p.satellites_visible < 5


def test_draw_seed_plus_index_and_deterministic():
    assert draw_gnss_degradation_params(7, 3).trial_seed == 10
    assert draw_gnss_degradation_params(7, 3) == draw_gnss_degradation_params(7, 3)
    assert draw_gnss_degradation_params(7, 3) != draw_gnss_degradation_params(7, 4)
    a, b = draw_gnss_degradation_params(7, 3), draw_gnss_degradation_params(10, 0)
    assert (a.onset_s, a.duration_s, a.fix_type, a.satellites_visible) == (
        b.onset_s, b.duration_s, b.fix_type, b.satellites_visible)


# --------------------------------------------------------------------------- #
# ground truth: frame log + compute_gnss_degradation_effect
# --------------------------------------------------------------------------- #


def test_frame_log_and_effect_roundtrip(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = _attack(frame_log=log)
        _learn(a)
        a(ctx_for(gps_raw(seq=1, fix_type=3, sats=10), "down", recv_ns=6_000_000_000))
        a(ctx_for(gps_raw(seq=2, fix_type=3, sats=10), "down", recv_ns=8_000_000_000))
        a(ctx_for(gps_raw(seq=3, signed=True), "down", recv_ns=9_000_000_000))
        a(ctx_for(gpi_raw(seq=4), "down", recv_ns=9_500_000_000))  # untouched message: not logged

    entries = read_frame_log(path)
    assert [e.action for e in entries] == ["modified", "modified", "forwarded"]
    assert all(e.msgid == 24 for e in entries)
    eff = compute_gnss_degradation_effect(path)
    assert eff["frames_modified"] == 2
    # deltas are derived from the log, independent of the manifest's drawn params
    assert eff["fix_type_deltas_written"] == [PARAMS.fix_type - 3]
    assert eff["satellites_visible_deltas_written"] == [PARAMS.satellites_visible - 10]
    assert eff["first_modified_recv_ns"] == 6_000_000_000
    assert eff["last_modified_recv_ns"] == 8_000_000_000


def test_effect_with_no_modified_frames(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path):
        pass
    eff = compute_gnss_degradation_effect(path)
    assert eff["frames_modified"] == 0 and eff["first_modified_recv_ns"] is None


def test_attack_exposes_no_detector_fields():
    a = _attack()
    assert not hasattr(a, "detector_decision")
    assert not hasattr(a, "time_to_detection_s")


# --------------------------------------------------------------------------- #
# SITL-free coupling: attack output -> real parser -> real extractor -> unchanged
# ProtocolDetector GNSS rule (the rule is NOT tuned for this; defaults only)
# --------------------------------------------------------------------------- #


def _run_chain(raws: list[bytes]):
    parser, ex = MavlinkFrameParser(), FeatureExtractor()
    det = ProtocolDetector(DEFAULT_DETECTOR["protocol"])
    results = []
    for i, raw in enumerate(raws):
        t = 100.0 + i * 0.2
        for env in parser.parse(raw, t):
            ex.update(env)
        results.append(det.process(ex.extract(t)))
    return results


def test_degraded_frames_trip_unchanged_protocol_gnss_rule():
    a = _attack()
    _learn(a)
    n = DEFAULT_DETECTOR["protocol"]["gnss_loss_ticks"] + 2
    degraded = [a(ctx_for(gps_raw(seq=i), "down", recv_ns=6_000_000_000 + i))[0] for i in range(n)]
    assert all(decode(r).fix_type == PARAMS.fix_type for r in degraded)
    results = _run_chain(degraded)
    assert any("GNSS fix lost" in e for e in results[-1].evidence)
    assert results[-1].attack_votes.get("DOS", 0.0) > 0.0


def test_unmodified_healthy_frames_do_not_trip_gnss_rule():
    healthy = [gps_raw(seq=i) for i in range(12)]
    results = _run_chain(healthy)
    assert not any("GNSS fix lost" in e for r in results for e in r.evidence)


# --------------------------------------------------------------------------- #
# frames_modify_failed: swallowed modify failures are counted, never raised
# --------------------------------------------------------------------------- #


def test_modify_failed_counter_increments_on_undecodable_in_window_frame():
    a = _attack()
    _learn(a)
    bad = bytearray(gps_raw(seq=1))
    bad[-1] ^= 0xFF  # corrupt CRC -> decode raises inside _modify
    assert a(ctx_for(bytes(bad), "down", recv_ns=6_000_000_000)) == [bytes(bad)]  # original passed through
    trunc = gps_raw(seq=2)[:12]
    assert a(ctx_for(trunc, "down", recv_ns=6_100_000_000)) == [trunc]
    assert a.frames_modify_failed == 2
    assert a.frames_modified == 0


def test_modify_failed_counter_increments_when_rewrite_raises(monkeypatch):
    a = _attack()
    _learn(a)

    def boom(_ctx):
        raise RuntimeError("pack failure")

    monkeypatch.setattr(a, "_modify", boom)
    raw = gps_raw(seq=1)
    assert a(ctx_for(raw, "down", recv_ns=6_000_000_000)) == [raw]
    assert (a.frames_modify_failed, a.frames_modified) == (1, 0)


def test_modify_failed_counter_stays_zero_on_validated_normal_path():
    a = _attack()
    _learn(a)
    for i, t in enumerate([1.0, 5.0, 7.0, 9.5, 14.9, 20.0], start=1):  # before / inside / after window
        a(ctx_for(gps_raw(seq=i), "down", recv_ns=int(t * 1e9)))
    a(ctx_for(gps_raw(seq=9, signed=True), "down", recv_ns=8_000_000_000))  # signed: skipped, not failed
    a(ctx_for(gps_raw(seq=10, dialect=mav1), "down", recv_ns=8_000_000_000))  # MAVLink 1: not our wire format
    a(ctx_for(gpi_raw(seq=11), "down", recv_ns=8_000_000_000))  # other message
    assert a.frames_modified == 4
    assert a.frames_modify_failed == 0


def test_modify_failed_not_counted_outside_window_or_for_non_target_frames():
    a = _attack()
    _learn(a)
    bad = bytearray(gps_raw(seq=1))
    bad[-1] ^= 0xFF
    a(ctx_for(bytes(bad), "down", recv_ns=1_000_000_000))  # before onset: never attempted
    a(ctx_for(bytes(bad), "down", recv_ns=20_000_000_000))  # after window: never attempted
    a(ctx_for(bytes(bad), "up", recv_ns=6_000_000_000))  # wrong direction
    assert a.frames_modify_failed == 0
