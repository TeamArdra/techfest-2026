"""Missing-telemetry semantics: "never received" vs "received then lost" vs "stale".

Background: on a physical Pixhawk 6X the passive USB stream carried HEARTBEAT (+TIMESYNC) only.
The unchanged pipeline reported every decision as a DOS threat, "GPS dropout 999.0s > 2.0s" --
a never-seen sentinel presented as a measured dropout. These tests pin, with synthetic
MessageEnvelopes (no hardware, no sockets):

* the evidence says which case it is (``never received`` vs a measured age);
* a loss after valid data keeps alerting exactly as before, including after > 999 s;
* DECIDED (user decision 2026-10-15, "Coverage, not attack"): with the default
  ``protocol.require_global_position: false`` a never-received GLOBAL_POSITION_INT is a reported
  coverage condition (score 0, no vote, a ``coverage: ...`` evidence line), not a threat;
  ``require_global_position: true`` restores the DOS outcome and the ``never_seen_gps_*`` knobs;
* DECIDED (same date): a NEVER-received heartbeat / required position stream is judged on elapsed
  monitoring time, so the first decision does not fire merely because nothing has arrived yet;
* ``startup_grace_s`` (an optional key, default 0) honours only the never-seen case, combines with
  the elapsed-time gate as a maximum (the later of the two decides), and ends at a defined time.
"""

from __future__ import annotations

import math

import pytest

from aegisflight.config import DEFAULT_DETECTOR
from aegisflight.core.enums import AttackType
from aegisflight.core.geo import EARTH_RADIUS_M
from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot
from aegisflight.detectors import PhysicsDetector, ProtocolDetector
from aegisflight.features.extractor import ML_FEATURES, CommandEvent, FeatureExtractor, FeatureFrame

COVERAGE = "coverage: GLOBAL_POSITION_INT never received"
HB_TIMEOUT = DEFAULT_DETECTOR["protocol"]["heartbeat_timeout_s"]
GPS_DROPOUT = DEFAULT_DETECTOR["protocol"]["gps_dropout_s"]

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


def _vfr(t: float, groundspeed: float) -> MessageEnvelope:
    return _env(t, "VFR_HUD", groundspeed=groundspeed, heading=90, throttle=50, alt=600.0, climb=0.0)


# ---- (a) never received ------------------------------------------------------------------- #

def test_heartbeat_only_stream_default_is_a_coverage_condition_not_a_threat():
    """DECIDED P1 (user decision 2026-10-15, "Coverage, not attack"). Was: DOS 1.0 every decision."""
    rows = _run(_hb_only)
    for _t, frame, res in rows:
        assert frame.heartbeat_seen is True and frame.gps_seen is False
        assert frame.gps_raw_seen is False
        assert res.score == 0.0 and not res.triggered and res.attack_votes == {}
        assert len(res.evidence) == 1
        ev = res.evidence[0]
        assert ev.startswith(COVERAGE) and "GPS_RAW_INT never received" in ev
        assert "GPS dropout" not in ev and "lost" not in ev and "999" not in ev
        assert "inactive" in ev and "not attack evidence" in ev


def test_heartbeat_only_stream_with_require_global_position_reproduces_the_old_dos_outcome():
    """DECIDED P1 opt-in: today's outcome, after the elapsed-time startup gate (``gps_dropout_s``)."""
    rows = _run(_hb_only, require_global_position=True)
    for t, _frame, res in rows:
        if t <= GPS_DROPOUT:
            assert res.score == 0.0 and res.evidence == [] and res.attack_votes == {}, t
            continue
        assert res.score == 1.0 and res.triggered and res.attack_votes == {AttackType.DOS: 1.0}
        assert len(res.evidence) == 1
        ev = res.evidence[0]
        assert ev.startswith("GPS dropout: never received")
        assert "999" not in ev and "not a measured dropout" in ev and COVERAGE not in ev


def test_heartbeat_plus_attitude_without_position_is_the_same_never_received_case():
    rows = _run(_hb_att_no_position)
    _, frame, res = _at(rows, 10.0)
    assert frame.snapshot.yaw is not None and frame.gps_seen is False
    assert res.score == 0.0 and res.attack_votes == {}  # DECIDED P1: coverage, not attack
    assert res.evidence[0].startswith(COVERAGE)
    # physics-facing features stay at the neutral 0 (the physics detector is blind, not alarmed)
    assert frame.pos_residual_m == 0.0 and frame.yaw_course_diff_deg == 0.0
    assert frame.gps_vfr_speed_diff_ms == 0.0 and frame.gps_baro_alt_diff_m == 0.0
    phys = PhysicsDetector(DEFAULT_DETECTOR["physics"]).process(frame)
    assert phys.score == 0.0 and phys.evidence == []


def test_no_heartbeat_at_all_is_still_a_dos_style_liveness_fault():
    rows = _run(lambda t: [])
    _, frame, res = _at(rows, 5.0)
    assert frame.heartbeat_seen is False and frame.gps_seen is False
    assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}  # heartbeat only
    assert any(e.startswith("heartbeat stale (never received") for e in res.evidence)
    assert any(e.startswith(COVERAGE) for e in res.evidence)  # DECIDED P1: position is coverage
    assert not any(e.startswith("GPS dropout") for e in res.evidence)


def test_never_received_heartbeat_is_judged_on_elapsed_monitoring_time():
    """DECIDED (e): t=0 is quiet; "no heartbeat for > heartbeat_timeout_s since monitoring began"
    still fires (heartbeat stays DOS by default: it is MAVLink-mandatory)."""
    rows = _run(lambda t: [], seconds=6.0)
    for t, _, res in rows:
        hb = [e for e in res.evidence if e.startswith("heartbeat stale")]
        if t <= HB_TIMEOUT:
            assert hb == [] and res.score == 0.0 and res.attack_votes == {}, t
        else:
            assert hb and res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}, t
    first = next(t for t, _, r in rows if r.score > 0)
    assert first == pytest.approx(HB_TIMEOUT + DECISION_DT)


def test_elapsed_gate_starts_at_the_first_decision_not_at_t0_of_the_clock():
    ext, det = FeatureExtractor(), _proto()
    res = [det.process(ext.extract(t)) for t in (100.0, 102.0, 103.0, 103.2)]
    assert [r.score for r in res] == [0.0, 0.0, 0.0, 1.0]


def test_heartbeat_arriving_before_the_timeout_never_fires():
    rows = _run(lambda t: [_hb(t)] if t >= 2.0 and _every(t, 1.0) else [], seconds=8.0)
    assert all(not any(e.startswith("heartbeat") for e in r.evidence) for _t, _, r in rows)


# ---- startup grace: only the never-seen sentinel, bounded ---------------------------------- #

@pytest.mark.parametrize(("grace", "first_fire"), [(1.4, 2.2), (3.0, 3.0)])
def test_startup_grace_covers_only_never_seen_and_expires(grace, first_fire):
    # require_global_position: the never-seen position stream is a fault in this profile. The
    # elapsed gate (> gps_dropout_s) and the grace combine as a maximum, not a sum: the later of
    # the two decides when the fault may first fire.
    rows = _run(_hb_only, seconds=5.0, startup_grace_s=grace, require_global_position=True)
    for t, _, res in rows:
        if t < first_fire - 1e-9:
            assert res.score == 0.0 and res.evidence == [] and res.attack_votes == {}, t
        else:  # after the window, absence IS reported (not silently accepted)
            assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}, t
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

    rows = _run(msgs, seconds=5.0, startup_grace_s=1.4, require_global_position=True)
    for t in (0.0, 0.4, 2.0, 5.0):
        assert _at(rows, t)[2].evidence == []
    default = _run(msgs, seconds=5.0, startup_grace_s=1.4)  # coverage line only until it arrives
    assert all(r.score == 0.0 for _t, _, r in default)
    assert _at(default, 0.4)[2].evidence[0].startswith(COVERAGE)
    assert _at(default, 0.6)[2].evidence == [] and _at(default, 5.0)[2].evidence == []


# ---- (b) received then lost ---------------------------------------------------------------- #

@pytest.mark.parametrize("require", [False, True])
def test_gps_lost_after_valid_data_alerts_exactly_as_before(require):
    lost_at = 6.0

    def msgs(t):
        return _hb_only(t) + [_att(t)] + ([_gpi(t)] if t < lost_at else [])

    rows = _run(msgs, require_global_position=require)
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


# ---- physics: the GPS/VFR speed check needs a position stream (P1 follow-up, 2026-10-20) ------ #

SPEED_EV = "GPS/VFR speed mismatch"


def _speed_frame(t: float, gps_seen: bool | None) -> FeatureFrame:
    # VFR groundspeed 10 m/s and no GPS velocity: the extractor's speed difference is then 10 m/s
    return FeatureFrame(t=t, snapshot=TelemetrySnapshot(t=t), gps_vfr_speed_diff_ms=10.0,
                        gps_seen=gps_seen)


def test_speed_check_is_inactive_when_position_was_never_received():
    """Never-received GLOBAL_POSITION_INT has no GPS velocity to compare: no evidence, no vote."""
    phys = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    for k in range(5):  # well past the soft-trigger hysteresis
        res = phys.process(_speed_frame(k * DECISION_DT, gps_seen=False))
        assert res.score == 0.0 and res.attack_votes == {} and res.evidence == []
        assert res.signals["gps_vfr_speed_diff_ms"] == 10.0  # the signal is still recorded


@pytest.mark.parametrize("gps_seen", [None, True])
def test_speed_check_fires_as_before_when_position_seen_or_unknown(gps_seen):
    """``True`` (extractor, position received) and ``None`` (hand-built frame) keep the Stage-1 rule."""
    phys = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    res = [phys.process(_speed_frame(k * DECISION_DT, gps_seen=gps_seen)) for k in range(3)]
    for r in res:
        assert r.attack_votes == {AttackType.TELEMETRY_MANIPULATION: 0.5}
        assert r.evidence == [f"{SPEED_EV} 10.0 m/s > 5 m/s"]
    assert res[0].score == pytest.approx(0.5 * 0.35)  # first soft tick damped by hysteresis
    assert res[-1].score == 0.5 and res[-1].triggered


def test_moving_vehicle_without_position_keeps_the_ml_feature_but_physics_is_silent():
    """HEARTBEAT + ATTITUDE + VFR_HUD at 10 m/s, no GLOBAL_POSITION_INT. The ML feature
    ``gps_vfr_speed_diff_ms`` is unchanged (ML_FEATURES is frozen: it still equals the VFR
    groundspeed); only the physics RULE on it is gated."""
    ext, phys = FeatureExtractor(), PhysicsDetector(DEFAULT_DETECTOR["physics"])
    for k in range(25):
        t = round(k * DECISION_DT, 6)
        for m in _hb_att_no_position(t) + [_vfr(t, 10.0)]:
            ext.update(m)
        frame = ext.extract(t)
        res = phys.process(frame)
        assert frame.gps_seen is False
        assert frame.gps_vfr_speed_diff_ms == pytest.approx(10.0)
        assert frame.to_vector()[ML_FEATURES.index("gps_vfr_speed_diff_ms")] == pytest.approx(10.0)
        assert res.score == 0.0 and res.evidence == [] and res.attack_votes == {}


# ---- coverage line placement ------------------------------------------------------------------ #

def test_coverage_line_is_the_last_protocol_evidence_item():
    """The score-0 coverage line comes after every rule's evidence (command provenance, signing), so
    it is never the headline of an alert raised by another rule; it adds no vote."""
    det = _proto(require_signing=True)
    cmd = CommandEvent(recv_time=1.0, sysid=77, compid=1, command=400)  # ARM_DISARM, unexpected source
    frame = FeatureFrame(t=1.0, snapshot=TelemetrySnapshot(t=1.0), heartbeat_age_s=0.5,
                         gps_age_s=999.0, sources={(1, 1): 5}, n_sources=1, commands_recent=[cmd],
                         signed_ratio=0.0, heartbeat_seen=True, gps_seen=False, gps_raw_seen=False)
    res = det.process(frame)
    i_cmd = next(i for i, e in enumerate(res.evidence) if "unexpected source" in e)
    i_sig = next(i for i, e in enumerate(res.evidence) if e.startswith("unsigned messages"))
    assert i_cmd < i_sig < len(res.evidence) - 1
    assert res.evidence[-1].startswith(COVERAGE)
    assert sum(e.startswith(COVERAGE) for e in res.evidence) == 1
    assert res.attack_votes == {AttackType.COMMAND_INJECTION: 0.9, AttackType.MAVLINK_ANOMALY: 0.5}


# ---- additive never-seen GPS knobs ---------------------------------------------------------- #

def test_never_seen_gps_knobs_reattribute_and_cap_only_the_never_seen_case():
    rows = _run(_hb_only, seconds=5.0, never_seen_gps_vote="MAVLINK_ANOMALY",
                never_seen_gps_max_score=0.5, require_global_position=True)
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


def _never_gps_frame(t: float, **kw) -> FeatureFrame:
    return FeatureFrame(t=t, snapshot=TelemetrySnapshot(t=t), heartbeat_age_s=0.5,
                        gps_age_s=999.0, sources={(1, 1): 5}, n_sources=1, **kw)


def test_never_seen_gps_cap_is_floored_so_the_detector_still_reports_it():
    # the floor guarantees DETECTOR-level evidence + score 0.5, not a fused alert
    det = _proto(never_seen_gps_max_score=0.0, require_global_position=True)
    assert det.never_seen_gps_max == 0.5
    det.process(_never_gps_frame(0.0, gps_seen=False))  # first decision: elapsed 0
    res = det.process(_never_gps_frame(3.0, gps_seen=False))
    assert res.triggered and res.score == 0.5
    assert res.evidence[0].startswith("GPS dropout: never received")


def test_never_seen_gps_knobs_are_inert_without_require_global_position():
    det = _proto(never_seen_gps_vote="MAVLINK_ANOMALY", never_seen_gps_max_score=0.6)
    det.process(_never_gps_frame(0.0, gps_seen=False))
    res = det.process(_never_gps_frame(3.0, gps_seen=False))
    assert res.score == 0.0 and res.attack_votes == {} and res.evidence[0].startswith(COVERAGE)


def test_defaults_keep_stage1_never_seen_policy():
    det = _proto()
    assert det.never_seen_gps_vote is AttackType.DOS
    assert det.never_seen_gps_max == 1.0
    assert det.startup_grace_s == 0.0
    assert det.require_global_position is False  # DECIDED P1 default (2026-10-15)


def test_hand_built_frame_without_flags_falls_back_to_the_sentinel():
    det = _proto()
    sentinel = _never_gps_frame(1.0)
    assert sentinel.gps_seen is None and sentinel.gps_raw_seen is None
    res = det.process(sentinel)
    assert res.score == 0.0 and res.evidence[0].startswith(COVERAGE)
    assert "GPS_RAW_INT presence unknown" in res.evidence[0]
    measured = FeatureFrame(t=1.0, snapshot=TelemetrySnapshot(t=1.0), heartbeat_age_s=0.5,
                            gps_age_s=5.0, sources={(1, 1): 5}, n_sources=1)
    assert det.process(measured).evidence == ["GPS dropout 5.0s > 2.0s"]
    req = _proto(require_global_position=True)
    req.process(_never_gps_frame(0.0))
    res = req.process(_never_gps_frame(3.0))
    assert res.score == 1.0 and res.evidence[0].startswith("GPS dropout: never received")


# ---- DECIDED P2: GPS presence matrix (user decision 2026-10-15, "Coverage, not attack") ------ #

def _presence(raw: bool, gpi: bool, **over):
    def msgs(t):
        return _hb_only(t) + ([_gpi(t)] if gpi else []) + ([_raw(t, 3, 10)] if raw else [])
    return _run(msgs, seconds=5.0, **over)


@pytest.mark.parametrize(("raw", "raw_text"), [
    (True, "GPS_RAW_INT present"),
    (False, "GPS_RAW_INT never received"),
])
def test_presence_without_global_position_is_coverage_only(raw, raw_text):
    for _t, frame, res in _presence(raw, False):
        assert frame.gps_seen is False and frame.gps_raw_seen is raw
        assert res.score == 0.0 and res.attack_votes == {} and not res.triggered
        assert len(res.evidence) == 1 and res.evidence[0].startswith(COVERAGE)
        assert raw_text in res.evidence[0]
        assert "GPS dropout" not in res.evidence[0] and "lost" not in res.evidence[0]


@pytest.mark.parametrize("raw", [True, False])
def test_presence_with_global_position_is_quiet(raw):
    for _t, frame, res in _presence(raw, True):
        assert frame.gps_seen is True and frame.gps_raw_seen is raw
        assert res.score == 0.0 and res.evidence == [] and res.attack_votes == {}


def test_gps_raw_int_does_not_satisfy_a_declared_position_requirement():
    rows = _presence(True, False, require_global_position=True)
    _, frame, res = _at(rows, 3.0)
    assert frame.gps_raw_seen is True and frame.gps_seen is False
    assert res.score == 1.0 and res.attack_votes == {AttackType.DOS: 1.0}
    assert res.evidence[0].startswith("GPS dropout: never received")


# ---- GNSS fix: never acquired vs lost after a valid fix (P3 wording) ------------------------ #

GNSS_TICKS = DEFAULT_DETECTOR["protocol"]["gnss_loss_ticks"]


def _raw(t: float, fix: int, sats: int) -> MessageEnvelope:
    return _env(t, "GPS_RAW_INT", fix_type=fix, satellites_visible=sats, eph=100)


def _gnss_ev(res) -> list[str]:
    return [e for e in res.evidence if e.startswith("GNSS fix")]


def _fix_stream(fix_at):
    """Heartbeat + 5 Hz position (liveness quiet) + GPS_RAW_INT whose (fix, sats) is ``fix_at(t)``."""
    def msgs(t):
        return _hb_only(t) + [_gpi(t), _raw(t, *fix_at(t))]
    return msgs


def test_gnss_fix_never_acquired_says_so_and_never_claims_a_loss():
    rows = _run(_fix_stream(lambda t: (0, 0)), seconds=5.0)
    _, _, res = rows[GNSS_TICKS - 1]  # the rule's first firing decision
    assert res.score == pytest.approx(0.7) and res.attack_votes == {AttackType.DOS: 0.7}
    assert res.signals["gnss_bad_ticks"] == float(GNSS_TICKS)
    assert _gnss_ev(res) == [f"GNSS fix never acquired: fix_type=0, satellites=0 for {GNSS_TICKS} "
                             "decisions (no valid fix since monitoring began)"]
    for _t, _, r in rows:
        assert not any("lost" in e for e in r.evidence)


def test_gnss_fix_lost_after_valid_fix_keeps_exact_wording_score_and_timing():
    rows = _run(_fix_stream(lambda t: (3, 10) if t < 2.0 else (0, 0)), seconds=5.0)
    fired = [(t, r) for t, _, r in rows if _gnss_ev(r)]
    t0, res = fired[0]
    assert t0 == pytest.approx(2.0 + (GNSS_TICKS - 1) * DECISION_DT)
    assert res.score == pytest.approx(0.7) and res.attack_votes == {AttackType.DOS: 0.7}
    assert _gnss_ev(res) == [f"GNSS fix lost: fix_type=0, satellites=0 for {GNSS_TICKS} decisions"]


def test_gnss_fix_healthy_throughout_has_no_gnss_evidence():
    for _t, _, res in _run(_fix_stream(lambda t: (3, 10)), seconds=5.0):
        assert _gnss_ev(res) == [] and res.signals["gnss_bad_ticks"] == 0.0


def test_gnss_fix_reacquired_after_never_then_lost_says_lost():
    def fix_at(t):
        if t < 2.0:
            return (0, 0)  # never acquired (fires "never acquired")
        return (3, 10) if t < 4.0 else (1, 3)  # valid fix, then lost

    rows = _run(_fix_stream(fix_at), seconds=7.0)
    assert any(_gnss_ev(r) and "never acquired" in _gnss_ev(r)[0] for t, _, r in rows if t < 2.0)
    late = [r for t, _, r in rows if t >= 4.0 and _gnss_ev(r)]
    assert late and all(_gnss_ev(r)[0].startswith("GNSS fix lost: fix_type=1, satellites=3") for r in late)


@pytest.mark.parametrize("near_miss", [(3, 4), (2, 10)])  # sats-only short / fix-only short
def test_gnss_near_miss_fix_does_not_count_as_ever_valid(near_miss):
    # "valid" needs BOTH fix_type >= 3 AND satellites >= 5: a half-good fix is never acquired
    rows = _run(_fix_stream(lambda t: near_miss if t < 2.0 else (0, 0)), seconds=4.0)
    fired = [_gnss_ev(r) for t, _, r in rows if t >= 2.0 and _gnss_ev(r)]
    assert fired and all(ev[0].startswith("GNSS fix never acquired") for ev in fired)
    assert not any("lost" in e for _t, _, r in rows for e in r.evidence)


def test_gnss_absent_fix_fields_do_not_count_as_ever_valid():
    # no GPS_RAW_INT at all (snapshot fix/sats None) for 2 s, then a bad fix: never acquired
    def msgs(t):
        return _hb_only(t) + [_gpi(t)] + ([_raw(t, 0, 0)] if t >= 2.0 else [])

    rows = _run(msgs, seconds=4.0)
    assert all(_t >= 2.0 or r.signals["gnss_bad_ticks"] == 0.0 for _t, _, r in rows)
    fired = [_gnss_ev(r) for t, _, r in rows if _gnss_ev(r)]
    assert fired and all(ev[0].startswith("GNSS fix never acquired") for ev in fired)


def test_gnss_valid_fix_memory_clears_on_reset():
    ext, det = FeatureExtractor(), _proto()
    for k in range(3):  # a valid fix is observed
        t = k * DECISION_DT
        ext.update(_raw(t, 3, 10))
        det.process(ext.extract(t))
    det.reset()
    ext.reset()
    res = None
    for k in range(GNSS_TICKS):
        t = k * DECISION_DT
        ext.update(_hb(t))
        ext.update(_gpi(t))
        ext.update(_raw(t, 0, 0))
        res = det.process(ext.extract(t))
    assert res is not None and _gnss_ev(res)
    assert _gnss_ev(res)[0].startswith("GNSS fix never acquired")


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


def test_extractor_gps_raw_seen_flag_sets_and_clears_on_reset():
    ext = FeatureExtractor()
    assert ext.extract(0.0).gps_raw_seen is False
    ext.update(_raw(0.0, 3, 10))
    f = ext.extract(1.0)
    assert f.gps_raw_seen is True and f.gps_seen is False  # raw fix is not position presence
    ext.reset()
    assert ext.extract(1.0).gps_raw_seen is False
    assert "gps_raw_seen" not in ML_FEATURES
