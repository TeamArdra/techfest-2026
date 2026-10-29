"""GPS response ladder of the ACTIVE_IPS controller (software only). SYNTHETIC frames, nothing opens a port."""

from __future__ import annotations

import pytest

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import CommandEvent, FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import AttackSubMode, DefenseMode

FORBIDDEN = {"AUTO", "RTL", "LOITER", "GUIDED", "POSHOLD", "LAND", "SMART_RTL"}


def _frame(t, mode="AUTO", armed=True, resid=0.0, cmds=None):
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=armed, battery_remaining=90.0)
    return FeatureFrame(t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=10.0, pos_residual_m=resid, commands_recent=cmds or [])


def _asmt(t, attack):
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(t=t, wall_time=t, threat=threat, threat_score=0.9 if threat else 0.0,
                            severity=Severity.CRITICAL if threat else Severity.NORMAL, attack_type=attack,
                            confidence=0.9 if threat else 0.0, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=IntegrityStatus.VALID,
                            latency_ms=1.0, is_alert=threat)


class Rig:
    def __init__(self, mode=DefenseMode.ACTIVE_IPS, sub=AttackSubMode.GPS_GRADUAL_DRIFT, secondary=None):
        self.c = MitigationController(mode=mode)
        self.c.set_capabilities(ekf_secondary=secondary)
        self.sent: list[str] = []
        self.sub = sub
        a = self.c.actuator
        a.encode_set_mode = lambda m, *x, **k: (self.sent.append(m), b"M:" + m.encode())[1]
        a.encode_ekf_source_switch = lambda source_set=1, *x, **k: (self.sent.append(f"EKF{source_set}"), b"E")[1]
        a.encode_statustext = lambda text, *x, **k: (self.sent.append("TEXT"), b"T")[1]
        self.c.classifier.classify = lambda f, s: self.sub
        self.t = 100.0

    def tick(self, attack=AttackType.GPS_SPOOFING, **kw):
        act = self.c.step(_frame(self.t, **kw), _asmt(self.t, attack))
        self.t = round(self.t + 0.2, 6)
        return act

    def run(self, secs, **kw):
        for _ in range(int(round(secs / 0.2))):
            self.tick(**kw)


def test_no_switch_without_capability():
    r = Rig(secondary=None)
    r.run(10)
    assert "EKF2" not in r.sent
    assert r.c.ekf_secondary_available is False


def test_alt_hold_within_3s_without_secondary():
    r = Rig()
    r.run(3.6)
    assert r.sent.count("ALT_HOLD") == 1
    assert "TEXT" in r.sent
    r.run(10)
    assert r.sent.count("ALT_HOLD") == 1


def test_jamming_also_escalates():
    r = Rig(sub=AttackSubMode.DOS_GNSS_JAMMING)
    r.run(4)
    assert "ALT_HOLD" in r.sent and "EKF2" not in r.sent


def test_secondary_switch_then_fallback():
    r = Rig(secondary=True)
    r.run(1.0)
    assert r.sent.count("EKF2") == 1 and "ALT_HOLD" not in r.sent
    r.run(5.0, resid=30.0)
    assert r.sent.count("ALT_HOLD") == 1


def test_no_alt_hold_if_mode_not_position_dependent_or_disarmed():
    r = Rig()
    r.run(5, mode="STABILIZE")
    assert "ALT_HOLD" not in r.sent
    r2 = Rig()
    r2.run(5, armed=False)
    assert "ALT_HOLD" not in r2.sent


def test_never_forbidden_mode_during_episode():
    r = Rig(secondary=True)
    r.run(40)
    assert not (set(r.sent) & FORBIDDEN)


def test_pilot_override_cancels_ladder():
    r = Rig()
    r.run(1.0)
    cmd = CommandEvent(recv_time=r.t, sysid=255, compid=190, command=176)
    r.c.classifier.allowed_sysids.add(255)
    r.tick(cmds=[cmd])
    r.run(8)
    assert "ALT_HOLD" not in r.sent
    assert any(a["tag"] == "GPS_PILOT_OVERRIDE" for a in r.c.action_history)


def test_rogue_mode_command_does_not_cancel():
    r = Rig()
    r.run(1.0)
    r.c.classifier.allowed_sysids.add(255)
    r.tick(cmds=[CommandEvent(recv_time=r.t, sysid=77, compid=1, command=176)])
    r.run(4)
    assert "ALT_HOLD" in r.sent


def test_gps_recovery_does_not_restore_auto():
    r = Rig(secondary=True)
    r.c.golden.trusted_mode = "AUTO"
    r.run(2)
    r.sent.clear()
    r.run(6, attack=AttackType.BENIGN, mode="ALT_HOLD", resid=2.0)
    assert "AUTO" not in r.sent
    assert r.sent.count("EKF1") == 1
    assert any(a["tag"] == "GPS_RECOVERED" for a in r.c.action_history)


def test_gps_recovery_waits_for_residual():
    r = Rig()
    r.run(2)
    r.run(8, attack=AttackType.BENIGN, resid=20.0)
    assert r.c.state.value != "NOMINAL"
    r.run(1, attack=AttackType.BENIGN, resid=1.0)
    assert r.c.state.value == "NOMINAL"


def test_command_injection_recovery_still_restores_mode():
    r = Rig(sub=AttackSubMode.CMD_ROGUE_SOURCE)
    for _ in range(10):
        r.tick(attack=AttackType.BENIGN)  # anchor trusted mode AUTO
    r.run(1, attack=AttackType.COMMAND_INJECTION, mode="STABILIZE")
    r.sent.clear()
    r.run(6, attack=AttackType.BENIGN, mode="AUTO")
    assert "AUTO" in r.sent


@pytest.mark.parametrize("mode", [DefenseMode.PASSIVE, DefenseMode.ADVISORY])
def test_passive_advisory_send_no_control_frame(mode):
    r = Rig(mode=mode, secondary=True)
    r.run(10)
    assert not (set(r.sent) - {"TEXT"})
    assert not any(x in r.sent for x in ("EKF2", "ALT_HOLD"))


def test_plain_set_mode_from_the_pilot_cancels_the_ladder_end_to_end():
    """The legacy SET_MODE message, as the extractor now records it (command 176), stands the ladder down."""
    from aegisflight.core.types import MessageEnvelope
    from aegisflight.features.extractor import FeatureExtractor

    ex = FeatureExtractor()
    ex.update(MessageEnvelope(recv_time=1.0, sysid=255, compid=190, msgid=11, msgname="SET_MODE", seq=0, signed=False,
                              byte_len=14, fields={"target_system": 1, "base_mode": 1, "custom_mode": 5}))
    cmd = ex.extract(1.1).commands_recent[0]
    r = Rig()
    r.run(1.0)
    r.c.classifier.allowed_sysids.add(255)
    r.tick(cmds=[CommandEvent(recv_time=r.t, sysid=cmd.sysid, compid=cmd.compid, command=cmd.command)])
    r.run(8)
    assert "ALT_HOLD" not in r.sent
