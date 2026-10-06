"""Unit tests for ``aegisflight.proxy.attacks_live.PositionDriftAttack`` and
``draw_params`` -- docs/ATTACK_PROXY.md §3. Synthetic MAVLink 2/1 frames built
with pymavlink's dialects; no sockets, no PX4, no transport module involved."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.geo import haversine_m
from aegisflight.proxy.attacks_live import (
    RANGES,
    PositionDriftAttack,
    PositionDriftParams,
    draw_params,
)
from aegisflight.proxy.groundtruth import FrameLogWriter, compute_actual_effect, read_frame_log
from aegisflight.proxy.hooks import FrameContext

LAT0 = 473977418  # 47.3977418 deg * 1e7
LON0 = 85455940  # 8.5455940 deg * 1e7

# onset=5, duration=10 -> window [5, 15); drift_rate=6 m/s due east (bearing 90)
PARAMS = PositionDriftParams(
    trial_seed=1, trial_index=0, onset_s=5.0, duration_s=10.0, drift_rate_ms=6.0, bearing_deg=90.0
)


def _fresh_attack(**kw) -> PositionDriftAttack:
    return PositionDriftAttack(PARAMS, warmup_s=0.0, **kw)


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, dialect=mav2):
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return m


def gpi_raw(
    seq: int = 0,
    sysid: int = 3,
    compid: int = 1,
    lat: int = LAT0,
    lon: int = LON0,
    time_boot_ms: int = 1000,
    alt: int = 488000,
    relative_alt: int = 12000,
    vx: int = 10,
    vy: int = -20,
    vz: int = 30,
    hdg: int = 9000,
    dialect=mav2,
    signed: bool = False,
) -> bytes:
    m = _mk(sysid, compid, seq, dialect)
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return bytes(
        m.global_position_int_encode(
            time_boot_ms, lat, lon, alt, relative_alt, vx, vy, vz, hdg
        ).pack(m)
    )


def att_raw(seq: int = 0, sysid: int = 3, compid: int = 1) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.attitude_encode(1000, 0.1, -0.2, 1.5, 0.0, 0.0, 0.0).pack(m))


def hb_raw(seq: int = 0, sysid: int = 3, compid: int = 1, autopilot: int = 12) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, autopilot, 0x80, 0, 4).pack(m))


def ctx_for(raw: bytes, direction: str = "down", recv_ns: int = 0) -> FrameContext:
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


def _learn(a: PositionDriftAttack, recv_ns: int = 0) -> None:
    a(ctx_for(hb_raw(), "down", recv_ns=recv_ns))


# --------------------------------------------------------------------------- #
# pass-through: direction, target identity, msgid, window
# --------------------------------------------------------------------------- #


def test_fail_closed_before_target_learned():
    a = _fresh_attack()
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


def test_up_direction_always_passthrough():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "up", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


def test_non_target_msgid_passthrough():
    a = _fresh_attack()
    _learn(a)
    raw = att_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


def test_other_source_passthrough():
    a = _fresh_attack()
    _learn(a)  # target learned as (3, 1)
    raw = gpi_raw(seq=1, sysid=9, compid=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


def test_before_onset_passthrough():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=2_000_000_000))  # elapsed 2s < onset 5s
    assert out == [raw]
    assert a.frames_modified == 0


def test_after_duration_passthrough():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1)
    out = a(ctx_for(raw, "down", recv_ns=16_000_000_000))  # elapsed 16s >= onset+duration 15s
    assert out == [raw]
    assert a.frames_modified == 0


def test_warmup_floor_delays_but_window_still_opens():
    # onset=2, duration=20 -> naive window [2, 22); warmup=10 raises the floor to [10, 22)
    params = PositionDriftParams(
        trial_seed=1, trial_index=0, onset_s=2.0, duration_s=20.0, drift_rate_ms=6.0,
        bearing_deg=90.0,
    )
    a = PositionDriftAttack(params, warmup_s=10.0)
    _learn(a)
    early = gpi_raw(seq=1)
    out_early = a(ctx_for(early, "down", recv_ns=5_000_000_000))  # elapsed 5s: onset passed, warmup not
    assert out_early == [early] and a.frames_modified == 0
    later = gpi_raw(seq=2)
    out_later = a(ctx_for(later, "down", recv_ns=15_000_000_000))  # elapsed 15s: inside [10, 22)
    assert out_later != [later]
    assert a.frames_modified == 1


# --------------------------------------------------------------------------- #
# target learning
# --------------------------------------------------------------------------- #


def test_target_learned_from_px4_heartbeat_only():
    a = _fresh_attack()
    # a non-PX4 autopilot heartbeat must not set the target
    a(ctx_for(hb_raw(sysid=4, compid=1, autopilot=3), "down", recv_ns=0))  # autopilot=3 != PX4(12)
    raw = gpi_raw(seq=1, sysid=4, compid=1)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw] and a.frames_modified == 0  # still not learned -> fail closed

    a(ctx_for(hb_raw(sysid=3, compid=1, autopilot=12), "down", recv_ns=0))
    raw2 = gpi_raw(seq=2, sysid=3, compid=1)
    out2 = a(ctx_for(raw2, "down", recv_ns=8_000_000_000))
    assert out2 != [raw2]  # now learned and in-window -> modified
    assert a.frames_modified == 1


def test_configured_target_skips_heartbeat_learning():
    a = PositionDriftAttack(PARAMS, warmup_s=0.0, target_sysid=5, target_compid=2)
    # first target frame establishes the elapsed-time baseline (elapsed 0 -> before onset)
    first = gpi_raw(seq=0, sysid=5, compid=2)
    out0 = a(ctx_for(first, "down", recv_ns=0))
    assert out0 == [first] and a.frames_modified == 0
    raw = gpi_raw(seq=1, sysid=5, compid=2)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))  # no heartbeat ever seen; elapsed 8s
    assert out != [raw]
    assert a.frames_modified == 1


def test_partial_target_configuration_rejected():
    with pytest.raises(ValueError):
        PositionDriftAttack(PARAMS, target_sysid=5, target_compid=None)
    with pytest.raises(ValueError):
        PositionDriftAttack(PARAMS, target_sysid=None, target_compid=2)


# --------------------------------------------------------------------------- #
# the modification itself: CRC validity, field isolation, closed-form displacement
# --------------------------------------------------------------------------- #


def test_modified_frame_parses_cleanly_and_only_lat_lon_changed():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=7, time_boot_ms=1234, alt=5000, relative_alt=100, vx=1, vy=2, vz=3, hdg=45)
    (out,) = a(ctx_for(raw, "down", recv_ns=8_000_000_000))  # elapsed 8s, inside [5, 15)
    orig = decode(raw)
    mod = decode(out)  # raises MAVError on a bad CRC -- this must not raise
    assert mod.get_type() == "GLOBAL_POSITION_INT"
    assert mod.get_srcSystem() == orig.get_srcSystem() == 3
    assert mod.get_srcComponent() == orig.get_srcComponent() == 1
    assert mod.get_seq() == orig.get_seq() == 7
    assert (mod.lat, mod.lon) != (orig.lat, orig.lon)
    for f in ("time_boot_ms", "alt", "relative_alt", "vx", "vy", "vz", "hdg"):
        assert getattr(mod, f) == getattr(orig, f), f
    assert a.frames_modified == 1


def test_sysid_compid_seq_msgid_byte_level_header_unchanged():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=42)
    (out,) = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out[0] == raw[0] == 0xFD  # magic
    assert out[4] == raw[4] == 42  # seq
    assert out[5] == raw[5] == 3  # sysid
    assert out[6] == raw[6] == 1  # compid
    assert out[7:10] == raw[7:10]  # msgid (3 bytes)
    assert out[2] == raw[2]  # incompat flags (unsigned -> 0 either way)
    assert out[3] == raw[3]  # compat flags


def test_closed_form_displacement_matches_independent_haversine():
    a = _fresh_attack()
    _learn(a)
    elapsed_since_onset = 3.0
    recv_ns = int((PARAMS.onset_s + elapsed_since_onset) * 1e9)
    raw = gpi_raw(seq=1)
    (out,) = a(ctx_for(raw, "down", recv_ns=recv_ns))
    orig, mod = decode(raw), decode(out)
    dist_m = haversine_m(orig.lat / 1e7, orig.lon / 1e7, mod.lat / 1e7, mod.lon / 1e7)
    expected_m = PARAMS.drift_rate_ms * elapsed_since_onset
    assert dist_m == pytest.approx(expected_m, rel=1e-3)
    # bearing 90 deg (due east): latitude is untouched, longitude increases
    assert mod.lat == orig.lat
    assert mod.lon > orig.lon


def test_displacement_grows_monotonically_within_window():
    a = _fresh_attack()
    _learn(a)
    dists = []
    for i, t_s in enumerate([5.5, 8.0, 11.0, 14.9], start=1):
        raw = gpi_raw(seq=i)
        (out,) = a(ctx_for(raw, "down", recv_ns=int(t_s * 1e9)))
        orig, mod = decode(raw), decode(out)
        dists.append(haversine_m(orig.lat / 1e7, orig.lon / 1e7, mod.lat / 1e7, mod.lon / 1e7))
    assert dists == sorted(dists)
    assert dists[0] > 0.0


def test_trailing_zero_payload_truncation_is_handled():
    a = _fresh_attack()
    _learn(a)
    # alt/relative_alt/vx/vy/vz/hdg all zero -> MAVLink2 strips those trailing bytes
    raw = gpi_raw(seq=1, alt=0, relative_alt=0, vx=0, vy=0, vz=0, hdg=0)
    assert len(raw) < 10 + 28 + 2  # shorter than the full fixed-size payload: truncation occurred
    (out,) = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    orig, mod = decode(raw), decode(out)
    assert (mod.lat, mod.lon) != (orig.lat, orig.lon)
    assert mod.hdg == 0 and mod.vx == 0 and mod.vy == 0 and mod.vz == 0
    assert mod.alt == 0 and mod.relative_alt == 0
    assert a.frames_modified == 1


def test_corrupt_crc_never_raises_and_passes_through():
    a = _fresh_attack()
    _learn(a)
    raw = bytearray(gpi_raw(seq=1))
    raw[-1] ^= 0xFF  # corrupt CRC -- header-level msgid/sysid/compid still readable
    raw = bytes(raw)
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


def test_truncated_garbage_never_raises():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1)[:15]  # too short to be a valid frame at all
    ctx = FrameContext(direction="down", raw=raw, recv_ns=8_000_000_000, sysid=3, compid=1,
                        seq=1, msgid=33, signed=False)
    out = a(ctx)  # must not raise
    assert out == [raw]
    assert a.frames_modified == 0


# --------------------------------------------------------------------------- #
# signed frames and MAVLink 1
# --------------------------------------------------------------------------- #


def test_signed_frame_is_never_modified_and_counted():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1, signed=True)
    ctx = ctx_for(raw, "down", recv_ns=8_000_000_000)
    assert ctx.signed
    out = a(ctx)
    assert out == [raw]
    assert a.frames_modified == 0
    assert a.frames_skipped_signed == 1


def test_mavlink1_frame_passes_through():
    a = _fresh_attack()
    _learn(a)
    raw = gpi_raw(seq=1, dialect=mav1)
    assert raw[0] == 0xFE
    out = a(ctx_for(raw, "down", recv_ns=8_000_000_000))
    assert out == [raw]
    assert a.frames_modified == 0


# --------------------------------------------------------------------------- #
# determinism
# --------------------------------------------------------------------------- #


def test_deterministic_given_same_params_and_frame_sequence():
    def run() -> list[bytes]:
        a = _fresh_attack()
        _learn(a)
        outs = []
        for i, recv_ns in enumerate([6_000_000_000, 9_000_000_000, 12_000_000_000], start=1):
            outs.append(a(ctx_for(gpi_raw(seq=i), "down", recv_ns=recv_ns))[0])
        return outs

    assert run() == run()


# --------------------------------------------------------------------------- #
# draw_params: ranges, determinism, independence across seeds/trials
# --------------------------------------------------------------------------- #


def test_draw_params_within_ranges():
    for seed in (1, 2, 3, 100, 20261006):
        p = draw_params(seed)
        assert RANGES["onset_s"][0] <= p.onset_s < RANGES["onset_s"][1]
        assert RANGES["duration_s"][0] <= p.duration_s < RANGES["duration_s"][1]
        assert RANGES["drift_rate_ms"][0] <= p.drift_rate_ms < RANGES["drift_rate_ms"][1]
        assert RANGES["bearing_deg"][0] <= p.bearing_deg < RANGES["bearing_deg"][1]
        assert p.trial_seed == seed  # trial_index defaults to 0


def test_draw_params_trial_seed_is_seed_plus_trial_index():
    p = draw_params(100, trial_index=3)
    assert p.trial_seed == 103
    assert p.trial_index == 3


def test_draw_params_deterministic_repeat():
    assert draw_params(42, 3) == draw_params(42, 3)


def test_draw_params_differs_across_seeds_and_trial_index():
    p1 = draw_params(1)
    p2 = draw_params(2)
    assert (p1.onset_s, p1.duration_s, p1.drift_rate_ms, p1.bearing_deg) != (
        p2.onset_s, p2.duration_s, p2.drift_rate_ms, p2.bearing_deg,
    )
    p3 = draw_params(1, trial_index=1)
    assert p3.trial_seed == 2
    assert (p3.onset_s, p3.duration_s, p3.drift_rate_ms, p3.bearing_deg) != (
        p1.onset_s, p1.duration_s, p1.drift_rate_ms, p1.bearing_deg,
    )


# --------------------------------------------------------------------------- #
# integration with groundtruth (frame log + compute_actual_effect); detector
# fields are never touched by this attack / log path
# --------------------------------------------------------------------------- #


def test_frame_log_entries_for_modified_and_signed_frames(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as log:
        a = PositionDriftAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a, recv_ns=0)
        a(ctx_for(gpi_raw(seq=1, signed=True), "down", recv_ns=6_000_000_000))
        a(ctx_for(gpi_raw(seq=2), "down", recv_ns=7_000_000_000))
        a(ctx_for(att_raw(seq=3), "down", recv_ns=7_500_000_000))  # non-target msg: not logged

    entries = read_frame_log(path)
    actions = [e.action for e in entries]
    assert actions.count("modified") == 1
    assert actions.count("forwarded") == 1  # the signed GLOBAL_POSITION_INT
    assert len(entries) == 2  # the pass-through ATTITIDE frame is not logged (not "touched")

    mod_entry = next(e for e in entries if e.action == "modified")
    assert (mod_entry.msgid, mod_entry.sysid, mod_entry.compid, mod_entry.mavlink_seq) == (33, 3, 1, 2)
    assert set(mod_entry.field_deltas) == {"lat_1e7deg", "lon_1e7deg"}
    assert mod_entry.crc_recomputed is True
    assert mod_entry.proxy_recv_time_utc.endswith("Z")


def test_end_to_end_compute_actual_effect_matches_applied_displacement(tmp_path):
    path = tmp_path / "frames.jsonl"
    ref_lat_deg = LAT0 / 1e7
    last_elapsed_since_onset = None
    with FrameLogWriter(path) as log:
        a = PositionDriftAttack(PARAMS, warmup_s=0.0, frame_log=log)
        _learn(a)
        for i, t_s in enumerate([6.0, 8.0, 10.0, 12.0, 14.0], start=1):
            a(ctx_for(gpi_raw(seq=i), "down", recv_ns=int(t_s * 1e9)))
            last_elapsed_since_onset = t_s - PARAMS.onset_s

    result = compute_actual_effect(path, ref_lat_deg=ref_lat_deg)
    expected_max_m = PARAMS.drift_rate_ms * last_elapsed_since_onset
    assert result["frames_counted"] == 5
    assert result["max_lat_lon_delta_m"] == pytest.approx(expected_max_m, rel=1e-2)


def test_detector_fields_never_touched_by_this_module():
    # PositionDriftAttack / FrameLogEntry have no notion of a detector decision at all --
    # nothing to assert on the attack object itself beyond: the type doesn't expose one.
    a = _fresh_attack()
    assert not hasattr(a, "detector_decision")
    assert not hasattr(a, "time_to_detection_s")
