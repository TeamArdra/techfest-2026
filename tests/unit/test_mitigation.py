"""Unit tests for AegisFlight Autonomous Defense & Recovery Engine (aegisflight.mitigation)."""

from __future__ import annotations

import struct

from fastapi.testclient import TestClient

from aegisflight.backend.app import app
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.actuator import MavlinkActuator, x25_crc
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.golden_state import GoldenFlightState
from aegisflight.mitigation.parameter_estimator import ParameterEstimator
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.submode_classifier import AttackSubModeClassifier
from aegisflight.mitigation.types import AttackSubMode, DefenseMode, MitigationState


def _make_dummy_snapshot(
    t: float = 10.0,
    lat: float = 18.9220,
    lon: float = 72.8347,
    alt: float = 25.0,
    groundspeed: float = 5.0,
    heading: float = 90.0,
    flight_mode: str = "AUTO",
    armed: bool = True,
    vx: float = 0.0,
    vy: float | None = None,
) -> TelemetrySnapshot:
    return TelemetrySnapshot(
        t=t,
        lat=lat,
        lon=lon,
        alt_msl=alt,
        rel_alt=alt,
        vx=vx,
        vy=groundspeed if vy is None else vy,
        vz=0.0,
        groundspeed=groundspeed,
        roll=0.0,
        pitch=0.0,
        yaw=heading,
        heading=heading,
        rollspeed=0.0,
        pitchspeed=0.0,
        yawspeed=0.0,
        flight_mode=flight_mode,
        armed=armed,
        battery_remaining=90.0,
    )


def _make_dummy_frame(
    snap: TelemetrySnapshot,
    gps_seen: bool = True,
    gps_raw_seen: bool = True,
    heartbeat_seen: bool = True,
    msg_rate: float = 10.0,
    gps_baro_alt_diff_m: float = 0.0,
    pos_residual_m: float = 0.0,
) -> FeatureFrame:
    return FeatureFrame(
        t=snap.t,
        snapshot=snap,
        gps_seen=gps_seen,
        gps_raw_seen=gps_raw_seen,
        heartbeat_seen=heartbeat_seen,
        msg_rate_hz=msg_rate,
        gps_baro_alt_diff_m=gps_baro_alt_diff_m,
        pos_residual_m=pos_residual_m,
    )


def _make_dummy_assessment(
    t: float = 10.0,
    threat: bool = False,
    attack_type: AttackType = AttackType.BENIGN,
    severity: Severity = Severity.NORMAL,
    threat_score: float = 0.0,
    evidence: list[str] | None = None,
    contributing_detectors: list[str] | None = None,
    integrity_status: IntegrityStatus = IntegrityStatus.VALID,
) -> ThreatAssessment:
    return ThreatAssessment(
        t=t,
        wall_time=t,
        threat=threat,
        threat_score=threat_score,
        severity=severity,
        attack_type=attack_type,
        confidence=0.9 if threat else 0.0,
        evidence=evidence or [],
        detector_scores={},
        contributing_detectors=contributing_detectors or [],
        integrity_status=integrity_status,
        latency_ms=1.2,
        is_alert=threat,
    )


# --- 1. Passive Mode Non-Interference ---

def test_passive_mode_zero_counter_frames():
    ctrl = MitigationController(mode=DefenseMode.PASSIVE)
    snap = _make_dummy_snapshot(t=10.0)
    frame = _make_dummy_frame(snap)
    asmt = _make_dummy_assessment(
        t=10.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.CRITICAL,
        threat_score=0.95,
        evidence=["gps_innov_pos > 5.0m"],
    )

    action = ctrl.step(frame, asmt)
    assert ctrl.state == MitigationState.AUTO_MITIGATING
    assert action.counter_frames == []
    assert not ctrl.sanitizer.active


# --- 2. Advisory Mode STATUSTEXT ---

def test_advisory_mode_statustext_frames():
    ctrl = MitigationController(mode=DefenseMode.ADVISORY)
    snap = _make_dummy_snapshot(t=10.0)
    frame = _make_dummy_frame(snap)
    asmt = _make_dummy_assessment(
        t=10.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.HIGH,
        threat_score=0.85,
        evidence=["gps drift detected"],
    )

    action = ctrl.step(frame, asmt)
    assert ctrl.state == MitigationState.AUTO_MITIGATING
    assert len(action.counter_frames) == 1
    assert action.counter_frames[0].startswith(b"\xfd")  # MAVLink v2
    assert not ctrl.sanitizer.active


# --- 3. Active IPS GPS Spoofing EKF Switch and Coordinate Sanitizer ---

def test_active_ips_gps_spoofing_ekf_switch():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.set_capabilities(ekf_secondary=True)  # the switch is only sent when a secondary is declared
    # 1. Nominal tick sets golden anchor
    snap0 = _make_dummy_snapshot(t=1.0, lat=18.9220, lon=72.8347, alt=25.0)
    frame0 = _make_dummy_frame(snap0)
    asmt0 = _make_dummy_assessment(t=1.0, threat=False)
    ctrl.step(frame0, asmt0)
    assert ctrl.golden.has_anchor

    # 2. Attack tick with drift
    snap1 = _make_dummy_snapshot(t=2.0, lat=18.9250, lon=72.8347, alt=25.0)
    frame1 = _make_dummy_frame(snap1)
    asmt1 = _make_dummy_assessment(
        t=2.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.CRITICAL,
        threat_score=0.92,
        evidence=["horizontal position divergence > 200m"],
    )

    ctrl.step(frame1, asmt1)  # first threat tick: not yet confirmed
    action = ctrl.step(frame1, asmt1)  # confirmed on the 2nd consecutive tick
    assert ctrl.state == MitigationState.AUTO_MITIGATING
    assert action.sub_mode == AttackSubMode.GPS_GRADUAL_DRIFT
    assert action.ekf_switched is True
    assert action.sanitize_gps is True
    assert len(action.counter_frames) >= 1  # EKF switch frame emitted
    assert ctrl.sanitizer.active is True


# --- 4. Recovery Monitor: 25 Clean Ticks Restores EKF Primary ---

def test_active_ips_quarantine_recovery():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS, recovery_clean_ticks=25)
    ctrl.set_capabilities(ekf_secondary=True)
    # Step into attack
    snap0 = _make_dummy_snapshot(t=1.0, lat=18.9220, lon=72.8347)
    ctrl.step(_make_dummy_frame(snap0), _make_dummy_assessment(t=1.0, threat=False))

    snap1 = _make_dummy_snapshot(t=2.0, lat=18.9250, lon=72.8347)
    ctrl.step(
        _make_dummy_frame(snap1),
        _make_dummy_assessment(t=2.0, threat=True, attack_type=AttackType.GPS_SPOOFING, severity=Severity.CRITICAL),
    )
    ctrl.step(
        _make_dummy_frame(_make_dummy_snapshot(t=2.2, lat=18.9250, lon=72.8347)),
        _make_dummy_assessment(t=2.2, threat=True, attack_type=AttackType.GPS_SPOOFING, severity=Severity.CRITICAL),
    )
    assert ctrl.state == MitigationState.AUTO_MITIGATING

    # 24 clean ticks -> still mitigating
    for tick in range(24):
        t = 3.0 + tick * 0.2
        snap = _make_dummy_snapshot(t=t, lat=18.9220, lon=72.8347)
        act = ctrl.step(_make_dummy_frame(snap), _make_dummy_assessment(t=t, threat=False))
        assert ctrl.state == MitigationState.AUTO_MITIGATING
        assert act.clean_streak == tick + 1

    # 25th clean tick -> recovered to NOMINAL, EKF primary restored
    t_rec = 3.0 + 24 * 0.2
    snap_rec = _make_dummy_snapshot(t=t_rec, lat=18.9220, lon=72.8347)
    act_rec = ctrl.step(_make_dummy_frame(snap_rec), _make_dummy_assessment(t=t_rec, threat=False))
    assert ctrl.state == MitigationState.NOMINAL
    assert not ctrl.sanitizer.active
    assert any("PRIMARY" in str(act_rec.last_command_sent) or "RESTORE" in str(act_rec.last_command_sent) for _ in [1])


# --- 5. GPS Replay Freeze ---

def test_gps_replay_freeze_submode():
    clf = AttackSubModeClassifier()
    snap = _make_dummy_snapshot(lat=18.9220, lon=72.8347, groundspeed=10.0, vy=0.0)
    frame = _make_dummy_frame(snap)
    asmt = _make_dummy_assessment(
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        evidence=["gps fix frozen", "stale coordinates under motion"],
    )
    sub = clf.classify(frame, asmt)
    assert sub == AttackSubMode.GPS_REPLAY_FREEZE


# --- 6. Command Injection Rogue SysID Isolation and Mode Restoration ---

def test_command_injection_isolation_and_restore():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    # Set golden state trusted mode
    snap0 = _make_dummy_snapshot(t=1.0, flight_mode="AUTO")
    ctrl.step(_make_dummy_frame(snap0), _make_dummy_assessment(t=1.0, threat=False))
    assert ctrl.golden.trusted_mode == "AUTO"

    # Rogue injection from attacker sysid 99 hijack to GUIDED
    snap1 = _make_dummy_snapshot(t=2.0, flight_mode="GUIDED")
    asmt1 = _make_dummy_assessment(
        t=2.0,
        threat=True,
        attack_type=AttackType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        evidence=["unauthorized SET_MODE command from sysid 99"],
    )

    act = ctrl.step(_make_dummy_frame(snap1), asmt1)
    assert ctrl.state == MitigationState.AUTO_MITIGATING
    assert 99 in act.quarantined_sysids
    assert ctrl.sanitizer.quarantined_sysids == {99}
    # Command frame issued to restore AUTO
    assert len(act.counter_frames) >= 1


# --- 7. Telemetry Manipulation Altitude Bias Estimation ---

def test_telemetry_manipulation_altitude_bias():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    snap0 = _make_dummy_snapshot(t=1.0, alt=30.0)
    ctrl.step(_make_dummy_frame(snap0), _make_dummy_assessment(t=1.0, threat=False))

    # Injected altitude shift to 70.0m (+40m bias)
    snap1 = _make_dummy_snapshot(t=2.0, alt=70.0)
    asmt1 = _make_dummy_assessment(
        t=2.0,
        threat=True,
        attack_type=AttackType.TELEMETRY_MANIPULATION,
        severity=Severity.HIGH,
        evidence=["baro altitude divergence 40.0m"],
    )
    frame1 = _make_dummy_frame(snap1, gps_baro_alt_diff_m=40.0)
    act = ctrl.step(frame1, asmt1)
    assert act.sub_mode == AttackSubMode.TELEM_ALTITUDE_BIAS
    assert act.sanitize_alt is True
    assert abs(act.params.alt_bias_m - 40.0) < 1.0


# --- 8. DoS Rate Limiting Submode ---

def test_dos_flood_submode():
    clf = AttackSubModeClassifier()
    snap = _make_dummy_snapshot()
    frame = _make_dummy_frame(snap, msg_rate=150.0)
    asmt = _make_dummy_assessment(
        threat=True,
        attack_type=AttackType.DOS,
        evidence=["packet flood msg_rate=150Hz"],
    )
    sub = clf.classify(frame, asmt)
    assert sub == AttackSubMode.DOS_FLOOD


# --- 9. Firmware Integrity Ground Disarm vs In-Flight Takeover ---

def test_firmware_integrity_ground_vs_inflight():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    # Ground condition: armed = False
    snap_ground = _make_dummy_snapshot(t=1.0, alt=0.2, groundspeed=0.0, armed=False)
    asmt_fw = _make_dummy_assessment(
        t=1.0,
        threat=True,
        attack_type=AttackType.FIRMWARE_INTEGRITY,
        severity=Severity.CRITICAL,
        integrity_status=IntegrityStatus.INVALID,
    )
    act_ground = ctrl.step(_make_dummy_frame(snap_ground), asmt_fw)
    assert act_ground.sub_mode == AttackSubMode.FW_TAMPERED
    assert any(b for b in act_ground.counter_frames)

    # In-flight condition: alt=30m, armed = True -> Escalates to GCS_TAKEOVER
    ctrl.reset()
    snap_flight = _make_dummy_snapshot(t=1.0, alt=30.0, groundspeed=6.0, armed=True)
    act_flight = ctrl.step(_make_dummy_frame(snap_flight), asmt_fw)
    assert act_flight.state == MitigationState.GCS_TAKEOVER


# --- 10. Manual Overrides ---

def test_manual_overrides():
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl._quarantined_sysids.add(42)
    ctrl.sanitizer.configure(active=True, quarantined_sysids={42})

    # safe_hold
    act_hold = ctrl.manual_override("safe_hold")
    assert act_hold.state == MitigationState.SAFE_HOLD

    # reset_quarantine
    act_reset = ctrl.manual_override("reset_quarantine")
    assert 42 not in act_reset.quarantined_sysids
    assert len(ctrl.sanitizer.quarantined_sysids) == 0

    # ack_takeover
    act_ack = ctrl.manual_override("ack_takeover")
    assert act_ack.state == MitigationState.NOMINAL


# --- 11. MavlinkActuator Binary Encoding & CRC Validation ---

def test_mavlink_actuator_encoding():
    actuator = MavlinkActuator()

    # set_mode
    frame_mode = actuator.encode_set_mode("ALT_HOLD")
    assert frame_mode.startswith(b"\xfd")  # MAVLink v2 magic
    assert len(frame_mode) >= 12

    # ekf_source_switch
    frame_ekf = actuator.encode_ekf_source_switch(source_set=2)
    assert frame_ekf.startswith(b"\xfd")

    # prearm_disarm
    frame_disarm = actuator.encode_prearm_disarm(force=True)
    assert frame_disarm.startswith(b"\xfd")

    # statustext
    frame_hud = actuator.encode_statustext("TEST ALERT")
    assert frame_hud.startswith(b"\xfd")

    # param_set
    frame_param = actuator.encode_param_set("EK3_SRC1_POSXY", 0.0)
    assert frame_param.startswith(b"\xfd")


# --- 12. FrameSanitizer Drop Quarantined SysIDs ---

def test_frame_sanitizer_quarantine_drop():
    sanitizer = FrameSanitizer()
    sanitizer.configure(active=True, quarantined_sysids={99})

    # Fake MAVLink v2 frame from sysid 99 (header byte 5 is sysid)
    # 0: magic, 1: len, 2: incompat, 3: compat, 4: seq, 5: sysid, 6: compid, 7..9: msgid
    fake_frame = bytearray(b"\xfd\x01\x00\x00\x01\x63\x01\x00\x00\x00\xaa\x12\x34")
    assert sanitizer.sanitize_frame(fake_frame, direction="up", sysid=99) is None  # Dropped

    # From clean sysid 1 -> passed
    fake_clean = bytearray(b"\xfd\x01\x00\x00\x01\x01\x01\x00\x00\x00\xaa\x12\x34")
    assert sanitizer.sanitize_frame(fake_clean, direction="up", sysid=1) is not None


# --- 13. FrameSanitizer GLOBAL_POSITION_INT Offset Correction & CRC ---

def test_frame_sanitizer_gpi_offset_subtraction():
    from pymavlink.dialects.v20 import common as mav2

    sanitizer = FrameSanitizer()
    lat_offset_deg = 0.0010  # ~111m
    lon_offset_deg = 0.0010
    sanitizer.configure(active=True, sanitize_gps=True, lat_offset_deg=lat_offset_deg, lon_offset_deg=lon_offset_deg)

    enc = mav2.MAVLink(None)
    enc.srcSystem = 1
    enc.srcComponent = 1
    enc.seq = 5
    msg = mav2.MAVLink_global_position_int_message(
        10000,
        int(18.9230 * 1e7),
        int(72.8357 * 1e7),
        25000,
        25000,
        0,
        0,
        0,
        9000,
    )
    wire_frame = bytes(msg.pack(enc))

    sanitized = sanitizer.sanitize_frame(wire_frame, direction="down", sysid=1, compid=1, msgid=33, seq=5)
    assert sanitized is not None
    assert len(sanitized) == len(wire_frame)

    # Verify subtracted lat and lon
    header_len = 10
    payload_len = 28
    san_lat = struct.unpack_from("<i", sanitized, header_len + 4)[0] / 1e7
    san_lon = struct.unpack_from("<i", sanitized, header_len + 8)[0] / 1e7
    assert abs(san_lat - 18.9220) < 1e-5
    assert abs(san_lon - 72.8347) < 1e-5

    # Verify updated CRC
    recomputed_crc = x25_crc(sanitized[1:header_len + payload_len] + bytes([104]))
    wire_crc = struct.unpack_from("<H", sanitized, header_len + payload_len)[0]
    assert wire_crc == recomputed_crc


# --- 14. GoldenFlightState Dead-Reckoning ---

def test_golden_flight_state_dead_reckoning():
    g = GoldenFlightState()
    snap0 = _make_dummy_snapshot(t=0.0, lat=18.9220, lon=72.8347, groundspeed=10.0, heading=0.0)  # North
    g.update(snap0, _make_dummy_assessment(t=0.0, threat=False))

    # Threat tick 1.0s later -> propagate dead reckoning North
    snap1 = _make_dummy_snapshot(t=1.0, lat=18.9300, lon=72.8347, groundspeed=10.0, heading=0.0)
    asmt1 = _make_dummy_assessment(t=1.0, threat=True, attack_type=AttackType.GPS_SPOOFING, severity=Severity.HIGH)
    g.update(snap1, asmt1)

    # In 1s at 10m/s North (~0.00009 degrees lat), predicted lat should be ~18.92209, NOT 18.9300
    assert abs(g.dr_lat - 18.92209) < 0.00005
    assert abs(g.dr_lat - snap1.lat) > 0.005


# --- 15. ParameterEstimator Closed-Form Outputs ---

def test_parameter_estimator():
    est = ParameterEstimator()
    g = GoldenFlightState()
    snap_anchor = _make_dummy_snapshot(t=0.0, lat=18.9220, lon=72.8347, alt=20.0)
    g.update(snap_anchor, _make_dummy_assessment(t=0.0, threat=False))

    snap_threat = _make_dummy_snapshot(t=5.0, lat=18.9230, lon=72.8347, alt=35.0)
    asmt_threat = _make_dummy_assessment(
        t=5.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.HIGH,
        evidence=["rogue cmd from sysid 1337"],
    )

    params = est.estimate(_make_dummy_frame(snap_threat), g, AttackSubMode.GPS_GRADUAL_DRIFT, asmt_threat)
    assert params.north_offset_m > 50.0  # ~111m
    assert params.alt_bias_m == 15.0  # 35 - 20
    assert 1337 in params.rogue_sysids


# --- 16. Fast-Path Rust / Python CRC parity ---

def test_x25_crc_known_vector():
    # Test vector standard for MAVLink X.25 CRC
    data = b"Hello, MAVLink!"
    crc = x25_crc(data)
    assert isinstance(crc, int)
    assert 0 <= crc <= 0xFFFF


# --- 17. LiveEngine Status & Mitigation Dictionary Integration ---

def test_live_engine_mitigation_integration():
    spec = SourceSpec(kind="sim", defense_mode="advisory")
    engine = LiveEngine(spec=spec, db_path=":memory:")
    stat = engine.status()
    assert stat["defense_mode"] == "advisory"
    assert "mitigation" in stat
    assert stat["mitigation"]["mode"] == "advisory"
    assert stat["mitigation"]["state"] == "NOMINAL"


# --- 18. REST API /api/defense/mode Endpoint ---

def test_rest_defense_mode_endpoint():
    client = TestClient(app)
    # Valid mode
    resp = client.post("/api/defense/mode", json={"mode": "active-ips"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["mode"] == "active-ips"

    # Status reflects change
    st = client.get("/api/status").json()
    assert st["defense_mode"] == "active-ips"

    # Invalid mode
    resp_bad = client.post("/api/defense/mode", json={"mode": "invalid-mode"})
    assert resp_bad.status_code == 400
    assert resp_bad.json()["ok"] is False


# --- 19. REST API /api/defense/override Endpoint ---

def test_rest_defense_override_endpoint():
    client = TestClient(app)
    # Valid override safe_hold
    resp = client.post("/api/defense/override", json={"action": "safe_hold"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["mitigation"]["state"] == "SAFE_HOLD"

    # Acknowledge takeover -> returns to NOMINAL
    resp_ack = client.post("/api/defense/override", json={"action": "ack_takeover"})
    assert resp_ack.status_code == 200
    assert resp_ack.json()["mitigation"]["state"] == "NOMINAL"

    # Invalid action
    resp_bad = client.post("/api/defense/override", json={"action": "invalid_action"})
    assert resp_bad.status_code == 400


# --- 20. Compact Telemetry Suppression in LiveEngine ---

def test_compact_telemetry_suppression():
    spec = SourceSpec(kind="sim", defense_mode="active-ips")
    engine = LiveEngine(spec=spec, db_path=":memory:")
    engine.mitigation.state = MitigationState.AUTO_MITIGATING

    from aegisflight.sources.stream import TelemetryTick
    # Tick without messages -> assessment is None -> suppressed during mitigation
    tick = TelemetryTick(t=10.0, tick=1, messages=[])

    import asyncio
    asyncio.run(engine._process(tick))
    # _latest_update was NOT updated because non-decision tick is suppressed during mitigation
    assert engine._latest_update is None


# --- 21. Trajectory Return to Normal under ACTIVE_IPS vs Divergence in PASSIVE ---

def test_trajectory_return_to_normal_with_active_ips():
    ctrl = MitigationController(mode=DefenseMode.PASSIVE)
    # 1. Clean anchor at t=0
    snap0 = _make_dummy_snapshot(t=0.0, lat=19.1334, lon=72.9133, groundspeed=10.0, heading=0.0)
    ctrl.step(_make_dummy_frame(snap0), _make_dummy_assessment(t=0.0, threat=False))

    # 2. Attack in PASSIVE mode: vehicle drifts East to lon=72.9150 while true heading is North (0.0 rad)
    snap1 = _make_dummy_snapshot(t=1.0, lat=19.1335, lon=72.9150, groundspeed=10.0, heading=0.0)
    asmt1 = _make_dummy_assessment(
        t=1.0, threat=True, attack_type=AttackType.GPS_SPOOFING, severity=Severity.HIGH, threat_score=0.85
    )
    act_passive = ctrl.step(_make_dummy_frame(snap1), asmt1)
    assert act_passive.sanitize_gps is False
    # Unprotected effective lon follows spoofed lon
    assert abs(ctrl.golden.effective_lon - 72.9150) < 1e-6

    # 3. Switch to ACTIVE_IPS mid-attack: trajectory must steer back toward dead-reckoned lon (~72.9133)
    ctrl.set_mode(DefenseMode.ACTIVE_IPS)
    ctrl.set_capabilities(ekf_secondary=True)
    for step_idx in range(1, 12):
        t = 1.0 + step_idx * 0.2
        # Spoofed lon keeps drifting further East
        spoof_lon = 72.9150 + step_idx * 0.0003
        snap_k = _make_dummy_snapshot(t=t, lat=19.1335 + step_idx * 0.00002, lon=spoof_lon, groundspeed=10.0, heading=0.0)
        asmt_k = _make_dummy_assessment(
            t=t, threat=True, attack_type=AttackType.GPS_SPOOFING, severity=Severity.CRITICAL, threat_score=0.95
        )
        act_ips = ctrl.step(_make_dummy_frame(snap_k), asmt_k)
        assert act_ips.sanitize_gps is True
        assert act_ips.ekf_switched is (step_idx >= 2)  # confirmed on the 2nd consecutive tick

    # After ~11 ticks in ACTIVE_IPS, effective_lon has returned close to the nominal DR lon (72.9133)
    # and is far from the runaway spoofed lon (~72.9183)
    assert abs(ctrl.golden.effective_lon - 72.9133) < 0.0001
    assert abs(act_ips.params.trusted_lon - 72.9133) < 0.0001
    # And dead-reckoned latitude moved North with groundspeed=10m/s
    assert ctrl.golden.dr_lat > 19.1335


# --- 22. MAVLink-2 Cryptographic Signing & Replay Protection (IDS & IPS Modes) ---

def test_mavlink2_signing_and_replay_guard_ids_and_ips():
    from aegisflight.detectors import ProtocolDetector
    from aegisflight.features.extractor import CommandEvent
    from aegisflight.mavlink.signing import (
        MAVLINK_IFLAG_SIGNED,
        MAVLINK_SIGNATURE_LEN,
        MavlinkSignatureVerifier,
        sign_mavlink2_frame,
    )

    key = b"AegisFlightStage2SecretKey32Byte"
    assert len(key) == 32
    verifier = MavlinkSignatureVerifier(key)
    actuator = MavlinkActuator(secret_key=key, link_id=3)

    # 1. Signed counter-command emitted by MavlinkActuator
    signed_pkt = actuator.encode_set_mode("AUTO")
    assert signed_pkt[0] == 0xFD
    assert bool(signed_pkt[2] & MAVLINK_IFLAG_SIGNED)
    assert len(signed_pkt) == 10 + signed_pkt[1] + 2 + MAVLINK_SIGNATURE_LEN

    # 2. First verification succeeds and records timestamp
    res1 = verifier.verify_frame(signed_pkt)
    assert res1.valid is True
    assert res1.signed is True
    assert res1.replayed is False

    # 3. Replaying the exact same signed packet fails immediately (tau_frame <= tau_last)
    res_replay = verifier.verify_frame(signed_pkt)
    assert res_replay.valid is False
    assert res_replay.replayed is True
    assert res_replay.reason == "replay_timestamp_non_monotonic"

    # 4. Tampering with 1 byte of the MAC fails constant-time SHA-256 check
    fresh_pkt = sign_mavlink2_frame(
        MavlinkActuator().encode_set_mode("GUIDED"),
        key,
        link_id=3,
        timestamp_10us=res1.timestamp_10us + 500,
    )
    tampered_pkt = bytes(fresh_pkt[:-1]) + bytes([fresh_pkt[-1] ^ 0xFF])
    res_tamper = verifier.verify_frame(tampered_pkt)
    assert res_tamper.valid is False
    assert res_tamper.reason == "mac_mismatch"

    # 5. Unsigned link State-Aware Command Cadence Guard in IDS (PASSIVE) vs IPS (ACTIVE_IPS)
    proto = ProtocolDetector({"cadence_guard_enabled": True, "cadence_min_interval_s": 1.5})
    snap_air = _make_dummy_snapshot(t=5.0, groundspeed=12.0, armed=True, flight_mode="AUTO")
    # Duplicate disarm / mid-air disarm from GCS sysid 255
    cmds = [
        CommandEvent(recv_time=4.8, sysid=255, compid=190, command=400, params=(0.0,)),
        CommandEvent(recv_time=5.0, sysid=255, compid=190, command=400, params=(0.0,)),
    ]
    frame_cmd = _make_dummy_frame(snap_air)
    frame_cmd.commands_recent = cmds
    det_res = proto.process(frame_cmd)
    assert det_res.triggered is True
    assert det_res.attack_votes[AttackType.COMMAND_INJECTION] >= 0.90

    asmt_cmd = _make_dummy_assessment(
        t=5.0,
        threat=True,
        attack_type=AttackType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        evidence=det_res.evidence,
    )

    # In PASSIVE (IDS) mode: detects & classifies CMD_ARM_DISARM_BURST with 0 bytes sent
    ctrl_ids = MitigationController(mode=DefenseMode.PASSIVE, secret_key=key)
    ctrl_ids.step(_make_dummy_frame(snap_air), _make_dummy_assessment(t=4.0, threat=False))
    act_ids = ctrl_ids.step(frame_cmd, asmt_cmd)
    assert act_ids.sub_mode == AttackSubMode.CMD_ARM_DISARM_BURST
    assert act_ids.counter_frames == []

    # In ACTIVE_IPS (Defense) mode: logs VETO_DISARM & REPLAY_GUARD
    ctrl_ips = MitigationController(mode=DefenseMode.ACTIVE_IPS, secret_key=key)
    ctrl_ips.step(_make_dummy_frame(snap_air), _make_dummy_assessment(t=4.0, threat=False))
    act_ips = ctrl_ips.step(frame_cmd, asmt_cmd)
    assert act_ips.sub_mode == AttackSubMode.CMD_ARM_DISARM_BURST
    tags = {a["tag"] for a in act_ips.actions}
    assert "VETO_DISARM" in tags
    assert "REPLAY_GUARD" in tags


# --- 23. 2D Page-Hinkley / CUSUM Micro-Drift (< 0.3 m/s) in IDS & IPS Modes ---

def test_cusum_micro_drift_integrator_ids_and_ips():
    import random

    from aegisflight.detectors import CusumDriftIntegrator, PhysicsDetector

    rng = random.Random(42)
    cusum = CusumDriftIntegrator(slack_ms=0.06, threshold_m=1.0)

    # 1. Zero-mean Gaussian turbulence (~0.12 m/s sigma) cancels out over 100 steps
    for _ in range(100):
        vn = rng.gauss(0.0, 0.12)
        ve = rng.gauss(0.0, 0.12)
        cusum.update_velocity_residual(10.0 + vn, ve, 10.0, 0.0, dt=0.2)
    assert cusum.triggered is False
    assert cusum.magnitude_m < 0.5

    # 2. Directional 0.22 m/s micro-drift (< 0.3 m/s noise floor) accumulates monotonically
    cusum.reset()
    phys = PhysicsDetector({"cusum_enabled": True, "cusum_threshold_m": 1.0, "cusum_slack_ms": 0.05})
    for _ in range(40):
        phys.cusum.update_velocity_residual(10.0, 0.22, 10.0, 0.0, dt=0.2)
    assert phys.cusum.triggered is True
    snap_micro = _make_dummy_snapshot(t=8.0, lat=19.1334, lon=72.9135, groundspeed=10.0, heading=0.0)
    frame_micro = _make_dummy_frame(snap_micro, pos_residual_m=0.6)
    frame_micro.cusum_drift_m = phys.cusum.magnitude_m
    res_phys = phys.process(frame_micro)
    assert res_phys.triggered is True
    assert res_phys.attack_votes[AttackType.GPS_SPOOFING] >= 0.65
    assert any("CUSUM micro-drift" in e for e in res_phys.evidence)

    asmt_micro = _make_dummy_assessment(
        t=8.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.HIGH,
        evidence=res_phys.evidence,
    )

    # 3. PASSIVE (IDS) mode: detects gradual_drift, sends 0 bytes, leaves GPS unsanitized
    ctrl_ids = MitigationController(mode=DefenseMode.PASSIVE)
    ctrl_ids.step(_make_dummy_frame(_make_dummy_snapshot(t=0.0, lat=19.1334, lon=72.9133)), _make_dummy_assessment(t=0.0, threat=False))
    act_ids = ctrl_ids.step(frame_micro, asmt_micro)
    assert act_ids.sub_mode == AttackSubMode.GPS_GRADUAL_DRIFT
    assert act_ids.counter_frames == []
    assert act_ids.sanitize_gps is False
    assert act_ids.params.drift_rate_ms > 0.0

    # 4. ACTIVE_IPS (Defense) mode: switches EKF and clamps micro-drift coordinates
    ctrl_ips = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl_ips.set_capabilities(ekf_secondary=True)
    ctrl_ips.step(_make_dummy_frame(_make_dummy_snapshot(t=0.0, lat=19.1334, lon=72.9133)), _make_dummy_assessment(t=0.0, threat=False))
    ctrl_ips.step(frame_micro, asmt_micro)
    act_ips = ctrl_ips.step(frame_micro, asmt_micro)
    assert act_ips.sub_mode == AttackSubMode.GPS_GRADUAL_DRIFT
    assert act_ips.sanitize_gps is True
    assert act_ips.ekf_switched is True
    assert len(act_ips.counter_frames) == 2  # STATUSTEXT warning + EKF switch


# --- 24. Control-Plane Token Auth & CORS/Origin Lockdown ---

def test_control_plane_auth_and_cors_lockdown(monkeypatch):
    client = TestClient(app)

    # 1. Foreign Origin on mutating POST is rejected with 403 Forbidden
    r_evil = client.post(
        "/api/defense/mode",
        json={"mode": "passive"},
        headers={"Origin": "http://evil.attacker.example"},
    )
    assert r_evil.status_code == 403

    # 2. Tauri localhost Origin is permitted
    r_tauri = client.post(
        "/api/defense/mode",
        json={"mode": "passive"},
        headers={"Origin": "tauri://localhost"},
    )
    assert r_tauri.status_code == 200

    # 3. When AEGIS_API_TOKEN is configured, mutating POST requires matching X-Aegis-Token or Bearer
    monkeypatch.setenv("AEGIS_API_TOKEN", "top-secret-gcs-key-2026")
    r_no_tok = client.post("/api/defense/mode", json={"mode": "active-ips"})
    assert r_no_tok.status_code == 401

    r_bad_tok = client.post(
        "/api/defense/mode",
        json={"mode": "active-ips"},
        headers={"X-Aegis-Token": "wrong-key"},
    )
    assert r_bad_tok.status_code == 401

    r_ok_tok = client.post(
        "/api/defense/mode",
        json={"mode": "active-ips"},
        headers={"X-Aegis-Token": "top-secret-gcs-key-2026"},
    )
    assert r_ok_tok.status_code == 200
    assert r_ok_tok.json()["mode"] == "active-ips"


# --- 25. All Dataset Injections, Bidirectional Quarantine, AGL Sanitization, and Real-World SysID Resilience (IDS & IPS) ---

def test_all_dataset_injections_and_realworld_resilience_ids_and_ips():
    import struct

    from aegisflight.features.extractor import CommandEvent
    from aegisflight.mitigation.sanitizer import (
        _V2_MAGIC,
        GLOBAL_POSITION_INT_ID,
        FrameContext,
        FrameSanitizer,
    )

    # A. Test the 4 previously mismatched submodes in Classifier
    ctrl = MitigationController(mode=DefenseMode.PASSIVE)
    # 1. gps_spoofing:replay_freeze -> GPS_REPLAY_FREEZE
    snap_rf = _make_dummy_snapshot(t=1.0, lat=19.1334, lon=72.9133, groundspeed=12.0)
    frame_rf = _make_dummy_frame(snap_rf)
    asmt_rf = _make_dummy_assessment(
        t=1.0,
        threat=True,
        attack_type=AttackType.GPS_SPOOFING,
        severity=Severity.HIGH,
        evidence=["GPS freeze: position unchanged despite groundspeed"],
    )
    act_rf = ctrl.step(frame_rf, asmt_rf)
    assert act_rf.sub_mode == AttackSubMode.GPS_REPLAY_FREEZE
    assert act_rf.counter_frames == []  # PASSIVE: 0 bytes

    # 2. mavlink_anomaly:rogue_sysid -> MAV_ROGUE_SYSID
    frame_rs = _make_dummy_frame(snap_rf)
    frame_rs.sources = [(1, 1), (42, 1)]
    asmt_rs = _make_dummy_assessment(
        t=2.0,
        threat=True,
        attack_type=AttackType.MAVLINK_ANOMALY,
        severity=Severity.HIGH,
        evidence=["Rogue telemetry source sysid=42"],
    )
    act_rs = ctrl.step(frame_rs, asmt_rs)
    assert act_rs.sub_mode == AttackSubMode.MAV_ROGUE_SYSID
    assert 42 in act_rs.params.rogue_sysids

    # 3. command_injection:rogue_command -> CMD_ROGUE_SOURCE
    frame_rc = _make_dummy_frame(snap_rf)
    frame_rc.commands_recent = [
        CommandEvent(recv_time=3.0, sysid=99, compid=1, command=176, params=(1.0,))
    ]
    asmt_rc = _make_dummy_assessment(
        t=3.0,
        threat=True,
        attack_type=AttackType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        evidence=["Unexpected command source sysid=99"],
    )
    act_rc = ctrl.step(frame_rc, asmt_rc)
    assert act_rc.sub_mode == AttackSubMode.CMD_ROGUE_SOURCE
    assert 99 in act_rc.params.rogue_sysids

    # 4. dos:latency -> DOS_BLACKOUT
    frame_lat = _make_dummy_frame(snap_rf)
    frame_lat.max_seq_gap = 250
    frame_lat.interarrival_jitter_ms = 60.0
    asmt_lat = _make_dummy_assessment(
        t=4.0,
        threat=True,
        attack_type=AttackType.MAVLINK_ANOMALY,
        severity=Severity.CRITICAL,
        evidence=["Severe packet latency jitter"],
    )
    act_lat = ctrl.step(frame_lat, asmt_lat)
    assert act_lat.sub_mode == AttackSubMode.DOS_BLACKOUT

    # Now verify in ACTIVE_IPS mode, dos:latency triggers LINK_WATCHDOG
    ctrl_ips = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl_ips.step(_make_dummy_frame(snap_rf), _make_dummy_assessment(t=0.0, threat=False))
    act_ips_lat = ctrl_ips.step(frame_lat, asmt_lat)
    assert act_ips_lat.sub_mode == AttackSubMode.DOS_BLACKOUT
    assert any(a["tag"] == "LINK_WATCHDOG" for a in act_ips_lat.actions)

    # B. Test Bidirectional Quarantine in Sanitizer
    sanitizer = FrameSanitizer()
    sanitizer.configure(active=True, quarantined_sysids={42, 99})
    # Uplink command from sysid 99 dropped
    ctx_up = FrameContext(
        direction="up",
        raw=b"\xfd\x01\x00\x00\x00\x63\x01\x00\x00\x00\x00\x00\x00\x00",
        recv_ns=1_000_000_000,
        sysid=99,
        compid=1,
        seq=1,
        msgid=76,
        signed=False,
    )
    assert sanitizer(ctx_up) == []
    # Downlink telemetry from sysid 42 dropped
    ctx_down = FrameContext(
        direction="down",
        raw=b"\xfd\x01\x00\x00\x00\x2a\x01\x00\x00\x00\x00\x00\x00\x00",
        recv_ns=1_000_000_000,
        sysid=42,
        compid=1,
        seq=1,
        msgid=30,
        signed=False,
    )
    assert sanitizer(ctx_down) == []
    # Legitimate vehicle sysid 1 passes
    ctx_legit = FrameContext(
        direction="down",
        raw=b"\xfd\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00",
        recv_ns=1_000_000_000,
        sysid=1,
        compid=1,
        seq=1,
        msgid=30,
        signed=False,
    )
    assert len(sanitizer(ctx_legit)) == 1
    assert sanitizer.frames_dropped == 2

    # C. Test Dual Alt + Relative Alt (AGL) Sanitization
    header = bytes([_V2_MAGIC, 28, 0, 0, 1, 1, 1, 33, 0, 0])
    time_boot_ms = 1000
    lat_raw = int(19.1334 * 1e7)
    lon_raw = int(72.9133 * 1e7)
    alt_raw = 50000  # 50m MSL
    rel_alt_raw = 30000  # 30m AGL
    payload = struct.pack("<Iiiiihhhh", time_boot_ms, lat_raw, lon_raw, alt_raw, rel_alt_raw, 0, 0, 0, 0)
    crc = bytes([0x12, 0x34])  # dummy CRC
    raw_gpos = header + payload + crc

    sanitizer.configure(active=True, sanitize_alt=True, alt_bias_m=10.0)
    ctx_gpos = FrameContext(
        direction="down",
        raw=raw_gpos,
        recv_ns=1_000_000_000,
        sysid=1,
        compid=1,
        seq=1,
        msgid=GLOBAL_POSITION_INT_ID,
        signed=False,
    )
    san_pkts = sanitizer(ctx_gpos)
    assert len(san_pkts) == 1
    san_buf = san_pkts[0]
    out_alt = struct.unpack_from("<i", san_buf, 22)[0]
    out_rel_alt = struct.unpack_from("<i", san_buf, 26)[0]
    assert out_alt == 40000  # 50m - 10m bias = 40m
    assert out_rel_alt == 20000  # 30m - 10m bias = 20m

    # D. Test Real-World Custom SysID Auto-Learning
    ctrl_learn = MitigationController(mode=DefenseMode.PASSIVE)
    # Vehicle flying with custom sysid=7 (e.g. multi-UAV or custom PX4 sysid)
    frame_sys7 = _make_dummy_frame(snap_rf)
    frame_sys7.sources = [(7, 1)]
    asmt_nominal = _make_dummy_assessment(t=0.0, threat=False, severity=Severity.NORMAL)
    ctrl_learn.step(frame_sys7, asmt_nominal)
    assert 7 in ctrl_learn.classifier.allowed_sysids
    assert 7 in ctrl_learn.estimator.allowed_sysids


# --- 26. REST API /api/topology Endpoint ---

def test_rest_topology_endpoints():
    client = TestClient(app)
    # GET topology
    resp_get = client.get("/api/topology")
    assert resp_get.status_code == 200
    data_get = resp_get.json()
    assert data_get["ok"] is True
    assert "topology" in data_get
    assert "auto" in data_get["available"]

    # POST valid topology
    for top in ("a", "b", "a+b", "ids", "auto"):
        resp_post = client.post("/api/topology", json={"topology": top})
        assert resp_post.status_code == 200
        assert resp_post.json()["ok"] is True
        assert resp_post.json()["topology"] == top

    # POST invalid topology
    resp_bad = client.post("/api/topology", json={"topology": "invalid_topology"})
    assert resp_bad.status_code == 400
    assert resp_bad.json()["ok"] is False


# --- 27. Closed-Loop Cyber-Physical Simulation & Topology A/B Verification Across All 20 Submodes ---

def test_closed_loop_topology_a_and_b_across_all_20_submodes():
    """Verify cyber-physical vehicle flight dynamics across all 20 attack sub-modes:
    1. PASSIVE (IDS): 0 bytes sent, vehicle follows unmitigated hijacked dynamics.
    2. Topology A (Sidecar): MavlinkActuator restores AUTO, with brief reaction detour.
    3. Topology B (Inline): FrameSanitizer drops/filters inline, 0.0 m detour.
    """
    from aegisflight.benchmark.extended import MODES

    total_submodes = sum(len(sub) for sub in MODES.values())
    assert total_submodes == 20

    base_tele = {
        "lat": 19.1334,
        "lon": 72.9133,
        "alt_msl": 60.0,
        "rel_alt": 60.0,
        "flight_mode": "AUTO",
        "groundspeed": 12.0,
        "armed": True,
    }

    spec = SourceSpec(kind="sim", defense_mode="passive")
    engine = LiveEngine(spec=spec, db_path=":memory:")

    for atk_class, submodes in MODES.items():
        for submode in submodes:
            # 1. Test PASSIVE mode (IDS)
            engine.set_defense_mode("passive")
            engine._active_attack_name = f"{atk_class}:{submode}"
            engine._sim_t = 10.0
            asmt_atk = _make_dummy_assessment(t=10.0, threat=True, severity=Severity.HIGH)
            asmt_atk.sub_mode = AttackSubMode(f"{atk_class}.{submode}") if f"{atk_class}.{submode}" in [e.value for e in AttackSubMode] else AttackSubMode.NONE

            # Step twin for 1.0 second under attack in PASSIVE
            for step_i in range(5):
                engine._step_cyber_physical_twin(10.0 + (step_i + 1) * 0.2, base_tele, asmt_atk)

            up_passive = engine._make_update(11.0, asmt_atk)
            # In PASSIVE: sanitized_telemetry mirrors unmitigated telemetry
            assert up_passive["sanitized_telemetry"]["flight_mode"] == up_passive["telemetry"]["flight_mode"]
            assert up_passive["defense_mode"] == "passive"

            if submode == "mode_flip":
                assert up_passive["telemetry"]["flight_mode"] == "LAND"
                assert up_passive["telemetry"]["rel_alt"] < 60.0
                assert up_passive["telemetry"]["groundspeed"] < 12.0
            elif submode == "gcs_replay":
                assert up_passive["telemetry"]["flight_mode"] == "RTL"
            elif submode == "arm_disarm_burst":
                assert up_passive["telemetry"]["armed"] is False
                assert up_passive["telemetry"]["rel_alt"] < 60.0
            elif submode == "rogue_command":
                assert up_passive["telemetry"]["flight_mode"] == "GUIDED"

            # 2. Test ACTIVE_IPS under Topology B (Inline Bridge)
            engine.set_topology("b")
            engine.set_defense_mode("active-ips")
            # Step twin under Topology B
            for step_i in range(5):
                engine._step_cyber_physical_twin(12.0 + (step_i + 1) * 0.2, base_tele, asmt_atk)

            up_top_b = engine._make_update(13.0, asmt_atk)
            assert up_top_b["defense_mode"] == "active-ips"
            assert up_top_b["topology"] == "b"
            # In Topology B: 0.0 m detour, command attacks blocked inline, flight stays AUTO at 12 m/s
            if submode in ("mode_flip", "gcs_replay", "arm_disarm_burst", "rogue_command"):
                assert up_top_b["sanitized_telemetry"]["flight_mode"] == "AUTO"
                assert up_top_b["sanitized_telemetry"]["groundspeed"] == 12.0
                assert up_top_b["sanitized_telemetry"]["rel_alt"] == 60.0
                assert up_top_b["sanitized_telemetry"]["armed"] is True

            # 3. Test ACTIVE_IPS under Topology A (Sidecar Actuator)
            engine.set_topology("a")
            engine.set_defense_mode("active-ips")
            # First 0.3s: reaction detour occurs
            engine._step_cyber_physical_twin(14.2, base_tele, asmt_atk)
            up_top_a_early = engine._make_update(14.2, asmt_atk)
            assert up_top_a_early["topology"] == "a"
            if submode == "mode_flip":
                # During early reaction window, FC starts responding to command
                assert up_top_a_early["sanitized_telemetry"]["flight_mode"] in ("LAND", "AUTO")

            # After >0.4s: counter-actuation takes effect and restores AUTO
            for step_i in range(5):
                engine._step_cyber_physical_twin(14.4 + (step_i + 1) * 0.2, base_tele, asmt_atk)
            up_top_a_late = engine._make_update(15.4, asmt_atk)
            if submode in ("mode_flip", "gcs_replay", "arm_disarm_burst", "rogue_command"):
                assert up_top_a_late["sanitized_telemetry"]["flight_mode"] == "AUTO"
                assert up_top_a_late["sanitized_telemetry"]["rel_alt"] == 60.0



