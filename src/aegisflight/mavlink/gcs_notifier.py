"""MAVLink STATUSTEXT alert broadcaster for Ground Control Stations (GCS).

Translates AegisFlight ThreatAssessment alerts into standard MAVLink STATUSTEXT
messages (e.g. `[AEGIS] CRITICAL: GPS_SPOOFING`) and broadcasts them to GCS
endpoints (Mission Planner, QGroundControl).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from pymavlink.dialects.v20 import common as mav

from ..core.enums import Severity
from ..core.types import ThreatAssessment


class SendTransport(Protocol):
    def send(self, data: bytes) -> bool: ...


SEVERITY_MAP: dict[Severity, int] = {
    Severity.CRITICAL: mav.MAV_SEVERITY_CRITICAL,   # 2
    Severity.HIGH: mav.MAV_SEVERITY_ERROR,          # 3
    Severity.SUSPICIOUS: mav.MAV_SEVERITY_WARNING,  # 4
    Severity.WATCH: mav.MAV_SEVERITY_NOTICE,        # 5
}


@dataclass
class GcsNotifier:
    """Dispatches MAVLink STATUSTEXT alerts to GCS via UDP and/or an active transport."""

    enabled: bool = True
    udp_target: tuple[str, int] | None = ("127.0.0.1", 14550)
    transport: Any | None = None
    sysid: int = 1
    compid: int = 191  # MAV_COMP_ID_ONBOARD_COMPUTER
    cooldown_s: float = 1.0  # rate limit per attack type to prevent link flooding
    _seq: int = 0
    _last_sent: dict[str, float] = field(default_factory=dict)
    _sock: socket.socket | None = None
    alerts_sent: int = 0

    def __post_init__(self) -> None:
        if self.udp_target is not None:
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                self._sock = None

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def notify(self, assessment: ThreatAssessment) -> bool:
        """Encode and dispatch a STATUSTEXT message if assessment is an alert."""
        if not self.enabled or not assessment.is_alert:
            return False

        # Deduplication and rate-limiting per attack class
        now = time.time()
        atk_key = assessment.attack_type.value
        if now - self._last_sent.get(atk_key, 0.0) < self.cooldown_s:
            return False

        mav_sev = SEVERITY_MAP.get(assessment.severity, mav.MAV_SEVERITY_WARNING)
        text_str = f"[AEGIS] {assessment.severity.name}: {assessment.attack_type.value}"
        # MAVLink STATUSTEXT text field is max 50 bytes (null-terminated / padded)
        text_bytes = text_str[:50].encode("utf-8")

        m = mav.MAVLink(None, srcSystem=self.sysid, srcComponent=self.compid)
        m.seq = self._seq
        self._seq = (self._seq + 1) % 256
        msg = m.statustext_encode(severity=mav_sev, text=text_bytes)
        packed = msg.pack(m)

        sent = False
        # 1. Send via attached transport if available (e.g. serial/UDP radio)
        if self.transport is not None and hasattr(self.transport, "send"):
            try:
                sent = bool(self.transport.send(packed)) or sent
            except Exception:
                pass

        # 2. Send via UDP target (e.g. standard GCS listening on port 14550)
        if self._sock is not None and self.udp_target is not None:
            try:
                self._sock.sendto(packed, self.udp_target)
                sent = True
            except Exception:
                pass

        if sent:
            self._last_sent[atk_key] = now
            self.alerts_sent += 1
        return sent
