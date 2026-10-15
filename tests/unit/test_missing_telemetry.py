"""Missing-telemetry semantics: "never received" vs "received then lost" vs "stale".

Background: on a physical Pixhawk 6X the passive USB stream carried HEARTBEAT (+TIMESYNC) only.
The unchanged pipeline reported every decision as a DOS threat, "GPS dropout 999.0s > 2.0s" --
a never-seen sentinel presented as a measured dropout. These tests pin, with synthetic
MessageEnvelopes (no hardware, no sockets):

* the default score / attack vote for each case is unchanged (Stage-1 behaviour);
* the evidence now says which case it is (``never received`` vs a measured age);
* a loss after valid data keeps alerting exactly as before, including after > 999 s;
* ``startup_grace_s`` honours only the never-seen sentinel and ends at a defined time;
* the additive ``never_seen_gps_*`` keys re-attribute / cap only the never-seen GPS case.
"""

from __future__ import annotations

import math

import pytest

from aegisflight.config import DEFAULT_DETECTOR
from aegisflight.core.enums import AttackType
from aegisflight.core.geo import EARTH_RADIUS_M
from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot
from aegisflight.detectors import PhysicsDetector, ProtocolDetector
from aegisflight.features.extractor import ML_FEATURES, FeatureExtractor, FeatureFrame

LAT0, LON0 = -35.363261, 149.165230
M_PER_DEG = math.radians(1.0) * EARTH_RADIUS_M
DECISION_DT = 0.2  # 5 Hz decisions


def _env(t: float, name: str, **fields) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=0,
                           signed=False, byte_len=20, fields=fields)


def _hb(t: float) -> MessageEnvelope:
    return _env(t, "HEARTBEAT", base_mode=0, custom_mode=0)


def _gpi(t: float, north_m: float = 0.0, east_m: float = 0.0, vn: float = 0.0,
         ve: float = 0.0) -> MessageEnvelope:
    lat = LAT0 + north_m / M_PER_DEG
    lon = LON0 + east_m / (M_PER_DEG * math.cos(math.radians(LAT0)))
    return _env(t, "GLOBAL_POSITION_INT", lat=int(lat * 1e7), lon=int(lon * 1e7), alt=600000,
                relative_alt=15000, vx=int(vn * 100), vy=int(ve * 100), vz=0, hdg=0)


def _att(t: float) -> MessageEnvelope:
    return _env(t, "ATTITUDE", roll=0.0, pitch=0.0, yaw=0.0, rollspeed=0.0, pitchspeed=0.0,
                yawspeed=0.0)


def _every(t: float, period: float) -> bool:
    k = t / period
    return abs(k - round(k)) < 1e-6


def _proto(**over) -> ProtocolDetector:
    return ProtocolDetector({**DEFAULT_DETECTOR["protocol"], **over})


def _run(messages_at, seconds: float = 20.0, **over):
    """Feed ``messages_at(t)`` into extractor + protocol detector at 5 Hz; return (t, frame, result)."""
    ext, det = FeatureExtractor(), _proto(**over)
    out = []
    for k in range(int(round(seconds / DECISION_DT)) + 1):
        t = round(k * DECISION_DT, 6)
        for m in messages_at(t):
            ext.update(m)
        frame = ext.extract(t)
        out.append((t, frame, det.process(frame)))
    return out


def _at(rows, t):
    return next(r for r in rows if abs(r[0] - t) < 1e-6)


def _hb_only(t):
    return [_hb(t)] if _every(t, 1.0) else []


def _hb_att_no_position(t):
    return _hb_only(t) + [_att(t)]


# ---- (a) never received ------------------------------------------------------------------- #

def test_heartbeat_only_stream_default_outcome_unchanged_but_evidence_is_honest():
    rows = _run(_hb_only)
    for _t, frame, res in rows:
        assert frame.heartbeat_seen is True and frame.gps_seen is False
        # Stage-1 outcome preserved: DOS, saturated score, triggered
        assert res.score == 1.0 and res.triggered
        assert res.attack_votes == {AttackType.DOS: 1.0}
        # ...but it no longer claims a 999 s measured dropout
        assert len(res.evidence) == 1
        ev = res.evidence[0]
        assert ev.startswith("GPS dropout: never received")
        assert "999" not in ev and "not a measured dropout" in ev


def test_heartbeat_plus_attitude_without_position_is_the_same_never_received_case():
    rows = _run(_hb_att_no_position)
    _, frame, res = _at(rows, 10.0)
    assert frame.snapshot.yaw is not None and frame.gps_seen is False
    assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}
    assert res.evidence[0].startswith("GPS dropout: never received")
    # physics-facing features stay at the neutral 0 (the physics detector is blind, not alarmed)
    assert frame.pos_residual_m == 0.0 and frame.yaw_course_diff_deg == 0.0
    assert frame.gps_vfr_speed_diff_ms == 0.0 and frame.gps_baro_alt_diff_m == 0.0
    phys = PhysicsDetector(DEFAULT_DETECTOR["physics"]).process(frame)
    assert phys.score == 0.0 and phys.evidence == []


def test_no_heartbeat_at_all_is_still_a_dos_style_liveness_fault():
    rows = _run(lambda t: [])
    _, frame, res = _at(rows, 5.0)
    assert frame.heartbeat_seen is False and frame.gps_seen is False
    assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}
    assert any(e.startswith("heartbeat stale (never received") for e in res.evidence)
    assert any(e.startswith("GPS dropout: never received") for e in res.evidence)


# ---- startup grace: only the never-seen sentinel, bounded ---------------------------------- #

def test_startup_grace_covers_only_never_seen_and_expires():
    rows = _run(_hb_only, seconds=5.0, startup_grace_s=1.4)
    for t in (0.0, 0.2, 1.0, 1.2):
        _, _, res = _at(rows, t)
        assert res.score == 0.0 and res.evidence == [] and res.attack_votes == {}
    for t in (1.4, 1.6, 3.0, 5.0):  # after the window, absence IS reported (not silently accepted)
        _, _, res = _at(rows, t)
        assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}
        assert res.evidence[0].startswith("GPS dropout: never received")


def test_startup_grace_does_not_shield_a_loss_after_valid_data():
    # GPS seen at t=0, then silent; the grace window (3 s) is still open when the age crosses 2 s
    def msgs(t):
        return _hb_only(t) + ([_gpi(t)] if t == 0.0 else [])

    rows = _run(msgs, seconds=5.0, startup_grace_s=3.0)
    _, _, early = _at(rows, 2.0)
    assert early.score == 0.0  # age 2.0 is not > 2.0
    _, _, res = _at(rows, 2.4)  # inside grace (2.4 < 3.0) yet judged on the measured age
    assert res.score == 0.5 and res.attack_votes == {AttackType.DOS: 0.5}
    assert res.evidence == ["GPS dropout 2.4s > 2.0s"]


def test_gps_arriving_during_grace_clears_the_condition():
    def msgs(t):
        return _hb_only(t) + ([_gpi(t)] if t >= 0.6 else [])

    rows = _run(msgs, seconds=5.0, startup_grace_s=1.4)
    for t in (0.0, 0.4, 2.0, 5.0):
        assert _at(rows, t)[2].evidence == []


# ---- (b) received then lost ---------------------------------------------------------------- #

def test_gps_lost_after_valid_data_alerts_exactly_as_before():
    lost_at = 6.0

    def msgs(t):
        return _hb_only(t) + [_att(t)] + ([_gpi(t)] if t < lost_at else [])

    rows = _run(msgs)
    assert _at(rows, 7.8)[2].evidence == []  # age 1.8 s: below threshold
    _, frame, res = _at(rows, 8.2)  # last GPS at t=5.8 -> age 2.4 s
    assert frame.gps_seen is True
    assert res.score == 0.5 and res.triggered and res.attack_votes == {AttackType.DOS: 0.5}
    assert res.evidence == ["GPS dropout 2.4s > 2.0s"]
    _, _, late = _at(rows, 19.8)  # age 14.0 s: ramp saturated
    assert late.score == 1.0 and late.attack_votes == {AttackType.DOS: 1.0}
    assert late.evidence == ["GPS dropout 14.0s > 2.0s"]


def test_loss_longer_than_the_never_seen_sentinel_is_not_mislabelled_never_received():
    ext, det = FeatureExtractor(), _proto(startup_grace_s=1.0)
    ext.update(_hb(0.0))
    ext.update(_gpi(0.0))
    ext.update(_hb(1500.0))  # heartbeat alive; GPS silent for 1500 s (> the 999 s sentinel)
    frame = ext.extract(1500.0)
    assert frame.gps_seen is True and frame.gps_age_s == 1500.0
    res = det.process(frame)
    assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}
    assert res.evidence == ["GPS dropout 1500.0s > 2.0s"]


def test_heartbeat_lost_after_valid_data_keeps_measured_age_evidence():
    def msgs(t):
        return ([_hb(t)] if _every(t, 1.0) and t < 5.0 else []) + [_gpi(t)]

    rows = _run(msgs)
    _, frame, res = _at(rows, 8.2)  # last heartbeat t=4 -> age 4.2 s > 3 s
    assert frame.heartbeat_seen is True
    assert res.score == pytest.approx(0.6) and res.attack_votes == {AttackType.DOS: pytest.approx(0.6)}
    assert res.evidence == ["heartbeat stale 4.2s > 3.0s"]


# ---- (c) stale / intermittent, below threshold ---------------------------------------------- #

def test_intermittent_gps_and_heartbeat_below_thresholds_are_not_flagged():
    def msgs(t):  # GPS every 1.6 s (< 2 s), heartbeat every 2.8 s (< 3 s); both on the 0.2 s grid
        return ([_gpi(t)] if _every(t, 1.6) else []) + ([_hb(t)] if _every(t, 2.8) else [])

    rows = _run(msgs)
    for t, _, res in rows:
        assert res.score == 0.0, t
        assert res.evidence == [] and res.attack_votes == {}


# ---- (d) genuine anomalies with available evidence ------------------------------------------ #

def test_in_flight_gps_dropout_alerts_then_clears_when_gps_returns():
    def msgs(t):
        return _hb_only(t) + [_att(t)] + ([] if 12.0 <= t < 16.0 else [_gpi(t)])

    rows = _run(msgs)
    assert _at(rows, 11.8)[2].score == 0.0
    _, _, res = _at(rows, 14.0)  # last GPS 11.8 -> 2.2 s
    assert res.score == 0.5 and res.attack_votes == {AttackType.DOS: 0.5}
    assert res.evidence == ["GPS dropout 2.2s > 2.0s"]
    assert _at(rows, 16.2)[2].score == 0.0


def test_gps_spoofing_evidence_is_still_detected_when_position_is_present():
    ext = FeatureExtractor()
    phys = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    east, flagged = 0.0, False
    for k in range(60):
        t = k * DECISION_DT
        east += 5.0 * DECISION_DT + 1.0  # reported track runs ahead of the truthful velocity
        ext.update(_hb(t))
        ext.update(_att(t))
        ext.update(_gpi(t, 0.0, east, 0.0, 5.0))
        res = phys.process(ext.extract(t))
        flagged = flagged or AttackType.GPS_SPOOFING in res.attack_votes
    assert flagged


# ---- additive never-seen GPS knobs ---------------------------------------------------------- #

def test_never_seen_gps_knobs_reattribute_and_cap_only_the_never_seen_case():
    rows = _run(_hb_only, seconds=5.0, never_seen_gps_vote="MAVLINK_ANOMALY",
                never_seen_gps_max_score=0.5)
    _, _, res = _at(rows, 3.0)
    assert res.score == 0.5 and res.triggered  # still reported, not silenced
    assert res.attack_votes == {AttackType.MAVLINK_ANOMALY: 0.5}
    assert res.evidence[0].startswith("GPS dropout: never received")

    # a loss after valid data is untouched by the same knobs
    def lost(t):
        return _hb_only(t) + ([_gpi(t)] if t < 1.0 else [])

    _, _, res2 = _at(_run(lost, seconds=20.0, never_seen_gps_vote="MAVLINK_ANOMALY",
                          never_seen_gps_max_score=0.5), 19.8)
    assert res2.score == 1.0 and res2.attack_votes == {AttackType.DOS: 1.0}


def test_never_seen_gps_cap_is_floored_so_the_condition_cannot_be_silenced():
    det = _proto(never_seen_gps_max_score=0.0)
    assert det.never_seen_gps_max == 0.5
    frame = FeatureFrame(t=1.0, snapshot=TelemetrySnapshot(t=1.0), heartbeat_age_s=0.5,
                         gps_age_s=999.0, gps_seen=False, sources={(1, 1): 5}, n_sources=1)
    res = det.process(frame)
    assert res.triggered and res.score == 0.5


def test_defaults_keep_stage1_never_seen_policy():
    det = _proto()
    assert det.never_seen_gps_vote is AttackType.DOS
    assert det.never_seen_gps_max == 1.0
    assert det.startup_grace_s == 0.0


def test_hand_built_frame_without_flags_falls_back_to_the_sentinel():
    det = _proto()
    sentinel = FeatureFrame(t=1.0, snapshot=TelemetrySnapshot(t=1.0), heartbeat_age_s=0.5,
                            gps_age_s=999.0, sources={(1, 1): 5}, n_sources=1)
    assert sentinel.gps_seen is None
    res = det.process(sentinel)
    assert res.score == 1.0 and res.evidence[0].startswith("GPS dropout: never received")
    measured = FeatureFrame(t=1.0, snapshot=TelemetrySnapshot(t=1.0), heartbeat_age_s=0.5,
                            gps_age_s=5.0, sources={(1, 1): 5}, n_sources=1)
    assert det.process(measured).evidence == ["GPS dropout 5.0s > 2.0s"]


def test_extractor_seen_flags_clear_on_reset():
    ext = FeatureExtractor()
    ext.update(_hb(0.0))
    ext.update(_gpi(0.0))
    f = ext.extract(1.0)
    assert f.heartbeat_seen is True and f.gps_seen is True
    ext.reset()
    f = ext.extract(1.0)
    assert f.heartbeat_seen is False and f.gps_seen is False
    assert f.gps_age_s == 999.0 and f.heartbeat_age_s == 999.0
    assert "heartbeat_seen" not in ML_FEATURES and "gps_seen" not in ML_FEATURES
