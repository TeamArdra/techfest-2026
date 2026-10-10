"""Unit tests for the ArduPilot P2 attack wrapper (``scripts/ardupilot/ap_attack.py``). No SITL, no WSL."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "ardupilot"))

from ap_attack import AirborneGatedDrift, build_attack, parse_spec, relative_alt_m  # noqa: E402

from aegisflight.proxy.attacks_live import PositionDriftParams  # noqa: E402
from aegisflight.proxy.hooks import FrameContext  # noqa: E402
from aegisflight.sources.frame_tap import frame_header  # noqa: E402

LAT0, LON0 = -353632610, 1491652300  # 1e7 deg


def gpi(seq: int, rel_alt_mm: int, *, lat=LAT0, lon=LON0, vx=0, vy=0, sysid=1, compid=1, v1=False) -> bytes:
    m = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    msg = m.global_position_int_encode(seq * 200, lat, lon, 584000 + rel_alt_mm, rel_alt_mm, vx, vy, 0, 35300)
    return bytes(msg.pack(m, force_mavlink1=v1))


def ctx(raw: bytes, t_s: float, direction="down") -> FrameContext:
    sysid, compid, seq, msgid, signed = frame_header(raw)
    return FrameContext(direction, raw, int(t_s * 1e9), sysid, compid, seq, msgid, signed)


def decode(raw: bytes):
    d = mav.MAVLink(None)
    d.robust_parsing = True
    return d.decode(bytearray(raw))


def hook(onset=5.0, duration=10.0, rate=5.0, bearing=90.0, airborne=12.0) -> AirborneGatedDrift:
    return AirborneGatedDrift(PositionDriftParams(0, 0, onset, duration, rate, bearing), airborne_m=airborne)


def test_relative_alt_parse_including_truncated_payload():
    assert relative_alt_m(gpi(0, 12345)) == pytest.approx(12.345)
    assert relative_alt_m(gpi(0, 0)) == 0.0  # MAVLink-2 zero truncation shortens the payload
    assert relative_alt_m(gpi(0, 5000, v1=True)) is None  # v1 is not this wrapper's wire format


def test_gate_closed_below_threshold_everything_is_byte_identical():
    h = hook()
    for i in range(50):
        raw = gpi(i, 11_900)  # 11.9 m < 12 m
        assert h(ctx(raw, i * 0.2)) == [raw]
    assert h.gate_open_recv_ns is None and h.inner.frames_modified == 0 and h.frames_before_gate == 50


def test_gate_opens_at_first_airborne_frame_then_waits_onset_then_drifts_east_at_rate():
    h = hook(onset=5.0, duration=10.0, rate=5.0, bearing=90.0)
    t_gate = 100.0
    out0 = h(ctx(gpi(0, 12_500), t_gate))  # gate opens on this very frame
    assert h.gate_open_recv_ns == int(t_gate * 1e9) and h.gate_relative_alt_m == pytest.approx(12.5)
    assert out0 == [gpi(0, 12_500)]  # onset not reached: still untouched
    assert h(ctx(gpi(1, 12_500), t_gate + 4.9)) == [gpi(1, 12_500)]
    # 7 s after the gate = 2 s after onset -> 10 m east
    raw = gpi(2, 12_500)
    (mod,) = h(ctx(raw, t_gate + 7.0))
    d0, d1 = decode(raw), decode(mod)
    assert d1.lon != d0.lon
    east_m = (d1.lon - d0.lon) / 1e7 * 111_320.0 * math.cos(math.radians(d0.lat / 1e7))
    north_m = (d1.lat - d0.lat) / 1e7 * 111_320.0
    assert east_m == pytest.approx(10.0, abs=0.3) and abs(north_m) < 0.3
    # velocity, altitude, relative altitude and heading stay truthful
    for f in ("vx", "vy", "vz", "alt", "relative_alt", "hdg", "time_boot_ms"):
        assert getattr(d1, f) == getattr(d0, f)
    # CRC is valid (decode would have raised) and the frame keeps its identity
    assert frame_header(mod) == frame_header(raw)


def test_window_closes_after_duration():
    h = hook(onset=2.0, duration=3.0)
    h(ctx(gpi(0, 20_000), 0.0))  # gate
    assert h(ctx(gpi(1, 20_000), 1.9)) == [gpi(1, 20_000)]
    assert h(ctx(gpi(2, 20_000), 2.5)) != [gpi(2, 20_000)]
    assert h(ctx(gpi(3, 20_000), 5.1)) == [gpi(3, 20_000)]
    assert h.inner.frames_modified == 1


def test_only_the_target_vehicles_position_frames_are_touched():
    h = hook(onset=0.0, duration=100.0)
    h(ctx(gpi(0, 20_000), 0.0))  # open the gate
    other = gpi(1, 20_000, sysid=7, compid=1)
    assert h(ctx(other, 1.0)) == [other]  # another system id
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    hb = bytes(m.heartbeat_encode(2, 3, 81, 0, 3, 3).pack(m))
    assert h(ctx(hb, 1.0)) == [hb]  # another message id
    up = gpi(2, 20_000)
    assert h(ctx(up, 1.0, direction="up")) == [up]  # uplink is never modified
    # onset=0: the gate-opening frame itself is the only "modified" one (zero displacement at elapsed 0)
    assert h.inner.frames_modified == 1


def test_v1_frames_pass_through_unmodified():
    h = hook(onset=0.0, duration=100.0)
    h(ctx(gpi(0, 20_000), 0.0))
    v1 = gpi(1, 20_000, v1=True)
    assert h(ctx(v1, 1.0)) == [v1]


def test_target_is_explicit_not_learned_from_an_autopilot_id():
    h = AirborneGatedDrift(PositionDriftParams(0, 0, 0, 100, 5, 0), target=(9, 1), airborne_m=1.0)
    raw = gpi(0, 20_000)  # sysid 1 is NOT the target
    assert h(ctx(raw, 0.0)) == [raw] and h.gate_open_recv_ns is None


def test_parse_spec_validation():
    assert parse_spec("position_drift:onset=5,duration=25,rate=5,bearing=90,airborne_m=12") == {
        "onset": 5.0, "duration": 25.0, "rate": 5.0, "bearing": 90.0, "airborne_m": 12.0}
    for bad in ("gps_replay:onset=1", "position_drift:onset=5,duration=25,rate=5",
                "position_drift:onset=5,duration=25,rate=5,bearing=90,bogus=1"):
        with pytest.raises(ValueError):
            parse_spec(bad)


def test_build_attack_writes_ground_truth_and_reports_realised_effect(tmp_path):
    h, handle = build_attack("position_drift:onset=1,duration=4,rate=5,bearing=90,airborne_m=12", tmp_path)
    for i in range(60):  # 12 s of 5 Hz frames; gate opens on frame 0 (20 m)
        h(ctx(gpi(i, 20_000), i * 0.2))
    res = handle.finalize()
    assert res["gate_opened"] and res["frames_skipped_signed"] == 0
    # onset 1 s, duration 4 s, 5 Hz -> frames at t = 1.0 .. 4.8 s are modified (20 frames)
    assert res["frames_modified"] == 20
    eff = res["actual_effect"]
    assert eff["frames_counted"] == res["frames_modified"]
    assert eff["max_lat_lon_delta_m"] == pytest.approx(5.0 * 3.8, abs=0.5)  # rate x (last frame - onset)
    assert handle.meta["claim_class"].startswith("link-level detection")
