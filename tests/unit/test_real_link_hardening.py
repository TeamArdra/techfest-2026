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


def test_baseline_relearned_after_a_gcs_connects_late_and_a_hard_flood_still_alarms():
    """SITL finding: a monitor started before the GCS asked for its streams learned ~5 msg/s, then 140 msg/s alarmed all flight."""
    det = ProtocolDetector({**_PROTO, "auto_rate_baseline": True, "rate_learn_s": 20.0, "rate_relearn_s": 30.0})
    _run(det, [5.0] * 105)                                   # 21 s of heartbeat-only traffic, learned ~28 floor
    plateau = _run(det, [140.0] * 200, t0=21.0)              # streams requested: 40 s plateau
    assert any(r.triggered for r in plateau[:50])            # alarms while it is still unexplained...
    assert all(r.score == 0.0 for r in plateau[-20:])        # ...and stops after the plateau is adopted
    assert any("re-learned" in e for r in plateau[-20:] for e in r.evidence) or det.nominal_rate >= 130.0
    flood = det.process(_frame(70.0, _PROTO["max_msg_rate_hz"] + 50.0))
    assert flood.triggered and flood.attack_votes.get(AttackType.DOS, 0.0) == 1.0   # the hard limit is never relaxed


def test_unstable_burst_is_not_adopted_as_the_new_normal():
    det = ProtocolDetector({**_PROTO, "auto_rate_baseline": True, "rate_learn_s": 20.0, "rate_relearn_s": 30.0})
    _run(det, [5.0] * 105)
    wobble = _run(det, [100.0, 300.0] * 100, t0=21.0)        # 100..300 msg/s: max > 2 x min
    assert det.nominal_rate < 100.0 and any(r.triggered for r in wobble[-20:])


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


def test_auto_baseline_is_really_enabled_for_live_sources_and_not_for_sim(tmp_path):
    """SITL finding: the key defaulted to an explicit False, so setdefault never enabled it on a live link."""
    from aegisflight.backend.engine import LiveEngine
    from aegisflight.backend.sources import SourceSpec
    from aegisflight.hal.inline_ips import InlineIpsBridge

    sim = LiveEngine(spec=SourceSpec(), db_path=str(tmp_path / "s.sqlite"))
    live = LiveEngine(spec=SourceSpec(kind="serial", port="COM7"), db_path=str(tmp_path / "l.sqlite"))
    try:
        assert sim.pipeline.protocol.auto_rate_baseline is False
        assert live.pipeline.protocol.auto_rate_baseline is True
    finally:
        sim.store.close()
        live.store.close()

    class _Link:
        def poll(self):
            return []

        def send(self, d):
            return True

        def close(self):
            pass

    b = InlineIpsBridge(_Link(), _Link(), mode="passive")
    assert b.pipeline.protocol.auto_rate_baseline is True
    forced = load_config()
    forced.detector["protocol"]["auto_rate_baseline"] = False
    assert InlineIpsBridge(_Link(), _Link(), cfg=forced, mode="passive").pipeline.protocol.auto_rate_baseline is False
