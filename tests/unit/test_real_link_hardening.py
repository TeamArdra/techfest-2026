"""Real-link false-alarm and safe-actuation regressions (SYNTHETIC hand-built frames, nothing opens a port)."""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode, MitigationState

_PROTO = load_config().detector["protocol"]
_PHYS = load_config().detector["physics"]


def _snap(t: float, mode: str | None = "LOITER") -> TelemetrySnapshot:
    return TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=True, battery_remaining=90.0)


def _frame(t: float, rate: float = 10.0, mode: str | None = "LOITER", **kw) -> FeatureFrame:
    return FeatureFrame(t=t, snapshot=_snap(t, mode), gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        heartbeat_age_s=0.1, gps_age_s=0.1, msg_rate_hz=rate, **kw)


def _asmt(t: float, attack: AttackType) -> ThreatAssessment:
    return ThreatAssessment(t=t, wall_time=t, threat=True, threat_score=0.9, severity=Severity.CRITICAL,
                            attack_type=attack, confidence=0.9, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=None, latency_ms=1.0, is_alert=True)


def _run(det: ProtocolDetector, rates: list[float], t0: float = 0.0, dt: float = 0.2):
    return [det.process(_frame(t0 + i * dt, r)) for i, r in enumerate(rates)]


# ---- 1. rate baseline ----
def test_baseline_learned_then_no_alarm_but_burst_alarms():
    det = ProtocolDetector({**_PROTO, "auto_rate_baseline": True, "rate_learn_s": 20.0})
    learn = _run(det, [140.0] * 105)  # 21 s
    assert all(r.score == 0.0 for r in learn)
    assert any("learning link message-rate baseline" in e for e in learn[1].evidence)
    steady = _run(det, [145.0] * 20, t0=21.0)
    assert all(r.score == 0.0 for r in steady)
    burst = det.process(_frame(30.0, 600.0))
    assert burst.triggered and burst.attack_votes.get(AttackType.DOS, 0.0) >= 0.6


def test_flood_during_learning_is_rejected():
    det = ProtocolDetector({**_PROTO, "auto_rate_baseline": True})
    rates = [30.0] * 50 + [900.0] * 55
    _run(det, rates)
    after = det.process(_frame(21.0, 900.0))
    assert after.triggered
    assert any("learning rejected" in e for e in after.evidence)
    assert det.max_rate == _PROTO["max_msg_rate_hz"]


def test_disabled_by_default_keeps_stage1_behaviour():
    det = ProtocolDetector(dict(_PROTO))
    assert det.auto_rate_baseline is False
    r = det.process(_frame(0.0, 140.0))
    assert r.triggered and any("message-rate spike" in e for e in r.evidence)
    assert not any("learning" in e for e in r.evidence)


# ---- 2. yaw/course ----
def test_yaw_course_switch():
    kw = {"yaw_course_diff_deg": 120.0}
    on = PhysicsDetector(dict(_PHYS))
    off = PhysicsDetector({**_PHYS, "yaw_course_enabled": False})
    for i in range(3):
        a = on.process(_frame(i * 0.2, **kw))
        b = off.process(_frame(i * 0.2, **kw))
    assert any("heading/course" in e for e in a.evidence) and a.score > 0
    assert not any("heading/course" in e for e in b.evidence) and b.score == 0.0


# ---- 3. restore frame ----
def _step_flip(mode_now: str | None):
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    for i in range(5):
        c.step(_frame(i * 0.2, mode="LOITER"), _benign(i * 0.2))
    sent = []
    for i in range(5, 15):
        t = i * 0.2
        sent += c.step(_frame(t, mode=mode_now), _asmt(t, AttackType.COMMAND_INJECTION)).counter_frames
    return sent


def _benign(t: float) -> ThreatAssessment:
    return ThreatAssessment(t=t, wall_time=t, threat=False, threat_score=0.0, severity=Severity.NORMAL,
                            attack_type=AttackType.BENIGN, confidence=0.0, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=None, latency_ms=1.0, is_alert=False)


def test_no_restore_when_mode_unchanged_but_restore_when_changed():
    assert _step_flip("LOITER") == []
    assert _step_flip("STABILIZE") != []


# ---- 4. no ALT_HOLD / rate limit from rate or telemetry alarms ----
def test_no_alt_hold_from_dos_or_telemetry_episode_and_rate_limit_needs_three_ticks():
    for attack in (AttackType.DOS, AttackType.TELEMETRY_MANIPULATION, AttackType.MAVLINK_ANOMALY):
        c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
        for i in range(5):
            c.step(_frame(i * 0.2), _benign(i * 0.2))
        sent = []
        for i in range(5, 200):
            t = i * 0.2
            sent += c.step(_frame(t, rate=700.0), _asmt(t, attack)).counter_frames
        assert c.state == MitigationState.SAFE_HOLD
        assert not any(k == "SET_MODE_ALT_HOLD" for k in c._last_cmd_t), attack
        assert not sent or attack == AttackType.DOS  # nothing but (possibly) non-mode frames
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    flags = []
    for i in range(4):
        t = i * 0.2
        c.step(_frame(t, rate=700.0), _asmt(t, AttackType.DOS))
        flags.append(c.sanitizer.rate_limit_active)
    assert flags[:2] == [False, False] and flags[-1] is True
