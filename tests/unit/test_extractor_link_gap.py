"""Link-gap handling in FeatureExtractor: a transport outage must not read as a physics anomaly.

Regression for the serial-reconnect false-alert burst (docs/SERIAL_TRANSPORT.md,
artifacts/ardupilot/serial_path_replay_001): after an 8.5 s cable pull the constant-velocity
position residual spanned the whole gap (29 m) and a fresh ATTITUDE was compared with a stale GPS
velocity (89 deg heading/course mismatch). No SITL, no sockets: synthetic MessageEnvelopes.
"""

from __future__ import annotations

import math

from aegisflight.core.geo import EARTH_RADIUS_M
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import FeatureExtractor

LAT0, LON0 = -35.363261, 149.165230
M_PER_DEG = math.radians(1.0) * EARTH_RADIUS_M


def _env(t: float, name: str, **fields) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=0,
                           signed=False, byte_len=20, fields=fields)


def _gpi(t: float, north_m: float, east_m: float, vn: float, ve: float) -> MessageEnvelope:
    lat = LAT0 + north_m / M_PER_DEG
    lon = LON0 + east_m / (M_PER_DEG * math.cos(math.radians(LAT0)))
    return _env(t, "GLOBAL_POSITION_INT", lat=int(lat * 1e7), lon=int(lon * 1e7), alt=600000,
                relative_alt=15000, vx=int(vn * 100), vy=int(ve * 100), vz=0, hdg=0)


def _att(t: float, yaw_deg: float) -> MessageEnvelope:
    return _env(t, "ATTITUDE", roll=0.0, pitch=0.0, yaw=math.radians(yaw_deg), rollspeed=0.0,
                pitchspeed=0.0, yawspeed=0.0)


def _fly_east(ext: FeatureExtractor, t0: float, t1: float) -> float:
    """5 Hz GPS + 10 Hz ATTITUDE flying east at 5 m/s, yaw 90 deg; returns the east position at t1."""
    t = t0
    while t < t1 - 1e-9:
        ext.update(_att(t, 90.0))
        ext.update(_att(t + 0.1, 90.0))
        ext.update(_gpi(t, 0.0, 5.0 * (t - t0), 0.0, 5.0))
        t += 0.2
    return 5.0 * (t1 - t0)


def test_position_residual_does_not_span_a_link_outage():
    ext = FeatureExtractor()
    e = _fly_east(ext, 0.0, 20.0)
    ext.extract(20.0)
    # 8.5 s outage; the vehicle turned north meanwhile (a legitimate manoeuvre, not an attack).
    t = 28.5
    ext.update(_gpi(t, 40.0, e + 25.0, 5.0, 0.0))
    assert ext.extract(t).pos_residual_m < 3.0


def test_yaw_course_ignores_a_stale_gps_velocity():
    ext = FeatureExtractor()
    _fly_east(ext, 0.0, 20.0)
    # After the outage the first message back is ATTITUDE (10 Hz vs 5 Hz GPS): yaw now north,
    # but the last GPS velocity (east, 8.5 s old) is stale.
    ext.update(_att(28.5, 0.0))
    frame = ext.extract(28.5)
    assert frame.gps_age_s > 8.0
    assert frame.yaw_course_diff_deg == 0.0


def test_genuine_drift_without_a_gap_is_still_caught():
    """Guard: the fix must not blunt the position-residual check on a gap-free stream."""
    ext = FeatureExtractor()
    t, e = 0.0, 0.0
    while t < 10.0:
        e += 5.0 * 0.2 + 1.0  # reported east position runs 1 m per fix ahead of the truthful velocity
        ext.update(_att(t, 90.0))
        ext.update(_gpi(t, 0.0, e, 0.0, 5.0))
        t += 0.2
    assert ext.extract(t).pos_residual_m > 12.0


def test_frozen_attitude_with_fresh_gps_is_still_caught():
    ext = FeatureExtractor()
    for k in range(20):
        t = k * 0.2
        ext.update(_att(t, 0.0))  # attitude frozen north while the track is east
        ext.update(_gpi(t, 0.0, 5.0 * t, 0.0, 5.0))
    assert ext.extract(3.8).yaw_course_diff_deg > 45.0
