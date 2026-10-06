"""PX4-SITL calibration profile: additive detector keys keep Stage-1 behaviour by default."""

from __future__ import annotations

from pathlib import Path

import yaml

from aegisflight.config import DEFAULT_DETECTOR, load_config
from aegisflight.core.types import TelemetrySnapshot
from aegisflight.detectors import PhysicsDetector, ProtocolDetector
from aegisflight.features.extractor import CommandEvent, FeatureFrame

REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / "configs" / "px4_sitl"


def _frame(t: float = 1.0, **kw) -> FeatureFrame:
    base = {"heartbeat_age_s": 0.5, "gps_age_s": 0.0, "sources": {(1, 1): 10}, "n_sources": 1}
    base.update(kw)
    return FeatureFrame(t=t, snapshot=TelemetrySnapshot(t=t), **base)


def _proto(**over) -> ProtocolDetector:
    return ProtocolDetector({**DEFAULT_DETECTOR["protocol"], **over})


def test_startup_grace_default_keeps_stage1_behaviour():
    det = _proto()
    assert det.startup_grace_s == 0.0
    r = det.process(_frame(t=0.0, heartbeat_age_s=999.0, gps_age_s=999.0))
    assert any("heartbeat stale" in e for e in r.evidence)
    assert any("GPS dropout" in e for e in r.evidence)


def test_startup_grace_suppresses_only_never_seen_sentinel():
    det = _proto(startup_grace_s=1.4)
    r0 = det.process(_frame(t=0.0, heartbeat_age_s=999.0, gps_age_s=999.0))
    assert not r0.evidence  # never seen yet, still inside the grace window
    # a heartbeat that WAS seen and then went stale is judged as before, even inside the grace
    r1 = det.process(_frame(t=0.4, heartbeat_age_s=5.0))
    assert any("heartbeat stale" in e for e in r1.evidence)
    # after the grace the sentinel is a real fault
    r2 = det.process(_frame(t=1.6, heartbeat_age_s=999.0, gps_age_s=999.0))
    assert any("heartbeat stale" in e for e in r2.evidence)
    assert any("GPS dropout" in e for e in r2.evidence)


def test_startup_grace_restarts_after_reset():
    det = _proto(startup_grace_s=1.0)
    det.process(_frame(t=100.0))
    det.reset()
    r = det.process(_frame(t=200.0, heartbeat_age_s=999.0))
    assert not r.evidence


def test_yaw_course_default_is_stage1_25_and_configurable():
    assert PhysicsDetector(DEFAULT_DETECTOR["physics"]).yaw_course_deg == 25.0
    for deg, fires in ((25.0, True), (110.0, False)):
        det = PhysicsDetector({**DEFAULT_DETECTOR["physics"], "yaw_course_deg": deg})
        res = [det.process(_frame(yaw_course_diff_deg=40.0)) for _ in range(3)]
        assert any("heading/course" in e for r in res for e in r.evidence) is fires


def test_profile_overrides_only_and_stage1_defaults_untouched():
    stage1 = load_config().detector
    assert stage1["protocol"]["expected_sysids"] == [1]
    assert stage1["protocol"]["nominal_msg_rate_hz"] == 28.0
    prof = load_config(PROFILE).detector
    assert prof["protocol"]["expected_sysids"] == [3]
    assert prof["protocol"]["nominal_msg_rate_hz"] > 28.0
    raw = yaml.safe_load((PROFILE / "detector.yaml").read_text(encoding="utf-8"))
    additive = {"startup_grace_s", "yaw_course_deg"}  # new optional keys with Stage-1-identical defaults
    for section, keys in raw.items():
        for k in keys:
            assert k in DEFAULT_DETECTOR[section] or k in additive, (section, k)
    # fusion / anomaly / decision cadence are not overridden by the profile
    assert prof["fusion"] == stage1["fusion"] and prof["anomaly"] == stage1["anomaly"]
    assert prof["decision_rate_hz"] == stage1["decision_rate_hz"]


def test_profile_vehicle_commands_legit_rogue_source_still_flagged():
    det = ProtocolDetector(load_config(PROFILE).detector["protocol"])
    own = CommandEvent(1.0, 3, 1, 400)  # the vehicle's own autopilot component
    rogue = CommandEvent(1.0, 42, 1, 400)
    ok = det.process(_frame(sources={(3, 1): 10}, n_sources=1, commands_recent=[own]))
    assert not ok.evidence
    rogue_tm = det.process(_frame(sources={(3, 1): 10, (42, 1): 5}, n_sources=2))
    assert any("rogue telemetry" in e for e in rogue_tm.evidence)
    rogue_cmd = det.process(_frame(sources={(3, 1): 10}, n_sources=1, commands_recent=[rogue]))
    assert any("unexpected source" in e for e in rogue_cmd.evidence)
