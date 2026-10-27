"""Safety regressions for the Stage-2 defense layer (integration review 2026-10-27).

Pins the fixes for the review blockers: live sources are receive-only (no counter-command, no
STATUSTEXT on the vehicle link), countermeasures never guess (no force-disarm, no unknown or
default mode, no override of the pilot's own mode change), and the command-cadence guard
evaluates each command once. All inputs are SYNTHETIC hand-built frames; nothing opens a port.
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegisflight.backend import app as app_module
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import CommandEvent, FeatureFrame
from aegisflight.mavlink.gcs_notifier import GcsNotifier, is_loopback_host
from aegisflight.mitigation.actuator import MavlinkActuator
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.submode_classifier import AttackSubModeClassifier
from aegisflight.mitigation.types import AttackSubMode, DefenseMode

MAV_CMD_DO_SET_MODE = 176
MAV_CMD_COMPONENT_ARM_DISARM = 400
RUN_SERIAL_IDS = Path(__file__).resolve().parents[2] / "scripts" / "hardware" / "run_serial_ids.py"


def _snap(t: float, *, armed: bool | None = True, mode: str | None = "AUTO", gs: float = 5.0) -> TelemetrySnapshot:
    return TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=gs, vz=0.0,
                             groundspeed=gs, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=armed, battery_remaining=90.0)


def _frame(snap: TelemetrySnapshot, commands: list[CommandEvent] | None = None) -> FeatureFrame:
    return FeatureFrame(t=snap.t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=10.0, commands_recent=commands or [])


def _asmt(t: float, attack: AttackType = AttackType.BENIGN, *, evidence: list[str] | None = None,
          integrity: IntegrityStatus = IntegrityStatus.VALID) -> ThreatAssessment:
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(t=t, wall_time=t, threat=threat, threat_score=0.9 if threat else 0.0,
                            severity=Severity.CRITICAL if threat else Severity.NORMAL, attack_type=attack,
                            confidence=0.9 if threat else 0.0, evidence=evidence or [], detector_scores={},
                            contributing_detectors=[], integrity_status=integrity, latency_ms=1.0, is_alert=threat)


def _command_long(frame: bytes) -> tuple[int, tuple[float, ...]]:
    """(command id, params 1..7) of an unsigned MAVLink-2 COMMAND_LONG frame (zero-padded if trimmed)."""
    payload = frame[10:10 + frame[1]] + bytes(33)
    return struct.unpack_from("<H", payload, 28)[0], struct.unpack_from("<7f", payload, 0)


class _RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True


# --------------------------------------------------------------------------- #
# 1. live sources are receive-only
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("spec", [{"kind": "serial", "port": "COM7"}, {"kind": "udp", "udp_port": 14550}])
def test_source_spec_refuses_active_ips_for_live_kinds(spec):
    with pytest.raises(ValueError, match="simulation-only"):
        SourceSpec(defense_mode="active-ips", **spec)
    assert SourceSpec(defense_mode="advisory", **spec).defense_mode == "advisory"  # report-only modes stay allowed


def test_source_spec_refuses_a_non_loopback_gcs_notify_host():
    with pytest.raises(ValueError, match="loopback"):
        SourceSpec(gcs_notify=True, gcs_notify_host="192.168.1.100")
    assert SourceSpec(gcs_notify=True, gcs_notify_host="127.0.0.1").gcs_notify_host == "127.0.0.1"


def test_live_engine_never_transmits_counter_frames(tmp_path, monkeypatch):
    """Even with ACTIVE_IPS forced on a live engine (bypassing every guard), an override's counter frames are
    reported, never written to the vehicle link."""
    engine = LiveEngine(spec=SourceSpec(kind="serial", port="COM7"), db_path=str(tmp_path / "e.sqlite"))
    try:
        with pytest.raises(ValueError, match="simulation-only"):
            engine.set_defense_mode("active-ips")
        tr = _RecordingTransport()
        monkeypatch.setattr(engine, "feed", type("Feed", (), {"transport": tr})())
        engine.mitigation.set_mode("active-ips")  # simulate a bypass of the public guards
        engine.defense_override("safe_hold")
        assert engine._last_mitigation_action.counter_frames, "safe_hold should still PRODUCE a counter frame"
        assert tr.sent == []
    finally:
        engine.store.close()


def test_api_refuses_active_ips_on_a_live_source_with_409(tmp_path, monkeypatch):
    engine = LiveEngine(spec=SourceSpec(kind="serial", port="COM7"), db_path=str(tmp_path / "e.sqlite"))
    monkeypatch.setattr(app_module, "engine", engine)
    try:
        client = TestClient(app_module.app)  # not entered as a context: no lifespan, the port is never opened
        r = client.post("/api/defense/mode", json={"mode": "active-ips"})
        assert r.status_code == 409 and "simulation-only" in r.json()["error"]
        assert engine.mitigation.mode == DefenseMode.PASSIVE
        assert client.post("/api/defense/mode", json={"mode": "advisory"}).status_code == 200
    finally:
        engine.store.close()


def test_gcs_notifier_is_loopback_only():
    assert is_loopback_host("127.0.0.1") and is_loopback_host("localhost") and is_loopback_host("::1")
    assert not is_loopback_host("0.0.0.0") and not is_loopback_host("192.168.1.100")
    assert not is_loopback_host("gcs.example")  # names are not resolved
    with pytest.raises(ValueError, match="loopback"):
        GcsNotifier(udp_target=("192.168.1.100", 14550))
    n = GcsNotifier(udp_target=("127.0.0.1", 14550))
    try:
        assert n._sock is not None and n._sock.getsockname()[0] == "127.0.0.1"
    finally:
        n.close()


def test_run_serial_ids_has_no_transmitting_mode(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("run_serial_ids_safety", RUN_SERIAL_IDS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with pytest.raises(SystemExit) as e:  # argparse: 'active-ips' is not a choice
        mod.main(["--port", "socket://127.0.0.1:1", "--out-dir", str(tmp_path), "--defense-mode", "active-ips"])
    assert e.value.code == 2
    rc = mod.main(["--port", "socket://127.0.0.1:1", "--out-dir", str(tmp_path / "x"), "--gcs-notify",
                   "--gcs-notify-host", "192.168.1.100"])
    assert rc == 2 and "loopback" in capsys.readouterr().err
    assert ".send(" not in RUN_SERIAL_IDS.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 2. countermeasures never guess
# --------------------------------------------------------------------------- #

def test_encode_set_mode_refuses_unknown_modes():
    act = MavlinkActuator()
    assert act.knows_mode("ALT_HOLD") and not act.knows_mode("AUTO/LOITER") and not act.knows_mode(None)
    with pytest.raises(ValueError):
        act.encode_set_mode("AUTO/LOITER")  # a PX4 name must not become ArduCopter AUTO (3)


def test_disarm_is_never_forced_by_default():
    cmd, params = _command_long(MavlinkActuator().encode_prearm_disarm())
    assert cmd == MAV_CMD_COMPONENT_ARM_DISARM and params[0] == 0.0 and params[1] == 0.0


@pytest.mark.parametrize("armed, expect_frame", [(None, False), (True, False), (False, True)])
def test_firmware_alert_disarms_only_a_vehicle_known_to_be_disarmed(armed, expect_frame):
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    act = ctrl.step(_frame(_snap(1.0, armed=armed, gs=0.0)),
                    _asmt(1.0, AttackType.FIRMWARE_INTEGRITY, integrity=IntegrityStatus.INVALID))
    disarms = [f for f in act.counter_frames if _command_long(f)[0] == MAV_CMD_COMPONENT_ARM_DISARM]
    assert bool(disarms) is expect_frame
    assert all(_command_long(f)[1][1] == 0.0 for f in disarms)  # never the 21196 force code


def test_recovery_never_sends_a_default_mode():
    """Unknown trusted mode -> no SET_MODE on recovery (the old fallback sent AUTO, which starts a mission)."""
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    t = 1.0
    ctrl.step(_frame(_snap(t, mode=None)), _asmt(t, AttackType.DOS, evidence=["flood"]))
    sent: list[bytes] = []
    for _ in range(200):
        t += 0.2
        sent += ctrl.step(_frame(_snap(t, mode=None)), _asmt(t)).counter_frames
    assert not any(_command_long(f)[0] == MAV_CMD_DO_SET_MODE for f in sent)


def _first_injection_step(sender: int) -> list[bytes]:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.step(_frame(_snap(1.0, mode="AUTO")), _asmt(1.0))
    assert ctrl.golden.trusted_mode == "AUTO"
    cmds = [CommandEvent(2.0, sender, 190, MAV_CMD_DO_SET_MODE, (1.0, 6.0))]
    act = ctrl.step(_frame(_snap(2.0, mode="RTL"), cmds),
                    _asmt(2.0, AttackType.COMMAND_INJECTION, evidence=[f"mode change from sysid {sender}"]))
    return act.counter_frames


def test_pilot_mode_change_from_the_gcs_is_not_countered():
    assert not any(_command_long(f)[0] == MAV_CMD_DO_SET_MODE for f in _first_injection_step(255))
    # the same change requested by an unknown sender is still countered
    assert any(_command_long(f)[0] == MAV_CMD_DO_SET_MODE for f in _first_injection_step(99))


# --------------------------------------------------------------------------- #
# 3. command-cadence guard: one command is evaluated once
# --------------------------------------------------------------------------- #

def _cadence_frames(cmds: list[CommandEvent], t_end: float) -> list[FeatureFrame]:
    """5 Hz decisions with a 2 s commands_recent window, as the extractor builds them."""
    out, t = [], cmds[0].recv_time
    while t <= t_end:
        out.append(_frame(_snap(t), [c for c in cmds if t - 2.0 <= c.recv_time <= t]))
        t = round(t + 0.2, 6)
    return out


ONE = [CommandEvent(10.0, 255, 190, MAV_CMD_DO_SET_MODE, (1.0, 3.0))]
TWO = ONE + [CommandEvent(10.5, 255, 190, MAV_CMD_DO_SET_MODE, (1.0, 3.0))]


def test_protocol_cadence_guard_flags_a_real_duplicate_but_not_one_command_against_itself():
    det = ProtocolDetector({"cadence_guard_enabled": True})
    assert not [e for f in _cadence_frames(ONE, 13.0) for e in det.process(f).evidence if "duplicate high-risk" in e]
    det = ProtocolDetector({"cadence_guard_enabled": True})
    hits = [e for f in _cadence_frames(TWO, 13.0) for e in det.process(f).evidence if "duplicate high-risk" in e]
    assert len(hits) == 1 and "Δt=0.50s" in hits[0]


def test_classifier_cadence_guard_evaluates_each_command_once():
    clf = AttackSubModeClassifier()
    assert not any(clf.check_command_cadence(f)[0] for f in _cadence_frames(ONE, 13.0))
    clf = AttackSubModeClassifier()
    flagged = [r for f in _cadence_frames(TWO, 13.0) if (r := clf.check_command_cadence(f))[0]]
    assert len(flagged) == 1 and flagged[0][1] == AttackSubMode.CMD_MODE_FLIP


# --------------------------------------------------------------------------- #
# 4. control-plane input checks
# --------------------------------------------------------------------------- #

@pytest.fixture
def sim_client(tmp_path, monkeypatch):
    engine = LiveEngine(spec=SourceSpec(kind="sim"), db_path=str(tmp_path / "e.sqlite"))
    monkeypatch.setattr(app_module, "engine", engine)
    try:
        yield TestClient(app_module.app)  # not entered: no lifespan, nothing starts
    finally:
        engine.store.close()


@pytest.mark.parametrize("origin, status", [
    ("http://localhost:9999", 403),  # another local port: same hostname is not the same origin
    ("https://127.0.0.1:8000", 403),  # scheme differs from the allow-listed origin
    ("http://localhost:5173", 200),  # allow-listed dashboard dev origin
])
def test_control_plane_origin_must_match_exactly(sim_client, origin, status):
    r = sim_client.post("/api/defense/mode", json={"mode": "passive"}, headers={"Origin": origin})
    assert r.status_code == status, r.text


@pytest.mark.parametrize("payload", [
    {"attack": "gps_spoofing", "drift_rate_ms": "abc"},
    {"attack": "gps_spoofing", "drift_rate_ms": 1e9},
    {"attack": "gps_spoofing", "drift_rate_ms": -1.0},
    {"attack": "gps_spoofing", "drift_rate_ms": True},
    {"attack": "gps_spoofing", "mode": "../x"},
    {"attack": "gps_spoofing", "mode": 5},
])
def test_attack_payload_is_validated_before_it_reaches_the_loop(sim_client, payload):
    assert sim_client.post("/api/simulation/attack", json=payload).status_code == 400


def test_valid_attack_payload_is_accepted(sim_client):
    r = sim_client.post("/api/simulation/attack", json={"attack": "gps_spoofing", "mode": "gradual_drift",
                                                         "drift_rate_ms": 0.5})
    assert r.status_code == 200 and r.json()["ok"] is True
