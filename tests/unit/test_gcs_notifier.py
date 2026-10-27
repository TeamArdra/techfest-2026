"""Unit tests for MAVLink STATUSTEXT GCS alert notifications."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

from pymavlink.dialects.v20 import common as mav

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.mavlink.gcs_notifier import GcsNotifier


def _make_assessment(*, is_alert: bool = True, severity: Severity = Severity.CRITICAL,
                     attack_type: AttackType = AttackType.GPS_SPOOFING) -> ThreatAssessment:
    return ThreatAssessment(
        t=10.0,
        wall_time=1700000000.0,
        threat=is_alert,
        threat_score=0.92,
        confidence=0.88,
        severity=severity,
        attack_type=attack_type,
        secondary_indicators=[],
        detector_scores={"protocol": 0.0, "physics": 0.9},
        evidence=["position residual 32.4m > 12.0m"],
        contributing_detectors=["physics"],
        integrity_status=IntegrityStatus.VALID,
        is_alert=is_alert,
        latency_ms=0.18,
    )


def test_gcs_notifier_skips_non_alerts():
    mock_tr = MagicMock()
    notifier = GcsNotifier(enabled=True, udp_target=None, transport=mock_tr)
    non_alert = _make_assessment(is_alert=False)
    assert not notifier.notify(non_alert)
    assert mock_tr.send.call_count == 0
    assert notifier.alerts_sent == 0


def test_gcs_notifier_dispatches_via_transport():
    mock_tr = MagicMock()
    mock_tr.send.return_value = True
    notifier = GcsNotifier(enabled=True, udp_target=None, transport=mock_tr, sysid=1, compid=191)

    asmt = _make_assessment(is_alert=True, severity=Severity.CRITICAL, attack_type=AttackType.GPS_SPOOFING)
    assert notifier.notify(asmt)
    assert mock_tr.send.call_count == 1
    assert notifier.alerts_sent == 1

    packed = mock_tr.send.call_args[0][0]
    # Parse the sent bytes with pymavlink
    parser = mav.MAVLink(None)
    msg = None
    for b in packed:
        parsed = parser.parse_char(bytes([b]))
        if parsed is not None:
            msg = parsed
            break
    assert msg is not None
    assert msg.get_type() == "STATUSTEXT"
    assert msg.severity == mav.MAV_SEVERITY_CRITICAL
    assert "[AEGIS] CRITICAL: GPS_SPOOFING" in msg.text.rstrip("\x00")
    assert msg.get_srcSystem() == 1
    assert msg.get_srcComponent() == 191


def test_gcs_notifier_cooldown_deduplication():
    mock_tr = MagicMock()
    mock_tr.send.return_value = True
    notifier = GcsNotifier(enabled=True, udp_target=None, transport=mock_tr, cooldown_s=1.0)

    asmt = _make_assessment(is_alert=True, attack_type=AttackType.GPS_SPOOFING)
    assert notifier.notify(asmt)
    assert mock_tr.send.call_count == 1

    # Second immediate notification with same attack type should be dropped by cooldown
    assert not notifier.notify(asmt)
    assert mock_tr.send.call_count == 1
    assert notifier.alerts_sent == 1

    # Different attack type should be allowed through immediately
    asmt_dos = _make_assessment(is_alert=True, attack_type=AttackType.DOS)
    assert notifier.notify(asmt_dos)
    assert mock_tr.send.call_count == 2
    assert notifier.alerts_sent == 2


def test_gcs_notifier_udp_dispatch():
    # Bind a real local loopback UDP socket to verify end-to-end receipt
    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx_sock.bind(("127.0.0.1", 0))
    _, port = rx_sock.getsockname()
    rx_sock.settimeout(2.0)

    try:
        notifier = GcsNotifier(enabled=True, udp_target=("127.0.0.1", port), transport=None)
        asmt = _make_assessment(is_alert=True, severity=Severity.HIGH, attack_type=AttackType.DOS)
        assert notifier.notify(asmt)
        assert notifier.alerts_sent == 1

        data, _ = rx_sock.recvfrom(512)
        parser = mav.MAVLink(None)
        msg = None
        for b in data:
            parsed = parser.parse_char(bytes([b]))
            if parsed is not None:
                msg = parsed
                break
        assert msg is not None
        assert msg.get_type() == "STATUSTEXT"
        assert msg.severity == mav.MAV_SEVERITY_ERROR
        assert "[AEGIS] HIGH: DOS" in msg.text.rstrip("\x00")
    finally:
        notifier.close()
        rx_sock.close()
