"""Endpoint identification and hardware capability fingerprinting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .profiles import AutopilotType


class EndpointType(str, Enum):
    FLIGHT_CONTROLLER = "FLIGHT_CONTROLLER"
    GCS = "GCS"
    COMPANION = "COMPANION"
    RADIO = "RADIO"
    UNKNOWN = "UNKNOWN"


@dataclass
class EndpointInfo:
    """Discovered MAVLink node on a communication link."""

    sysid: int
    compid: int
    endpoint_type: EndpointType
    autopilot_id: int = 0
    autopilot_name: str = "UNKNOWN"
    vehicle_type: str = "GENERIC"
    firmware_version: str = "UNKNOWN"
    capabilities: int = 0


@dataclass
class HardwareFingerprint:
    """Fingerprint of the active flight system and attached peripherals."""

    autopilot: AutopilotType = AutopilotType.UNKNOWN
    autopilot_version_str: str = "Unknown"
    vehicle_class: str = "COPTER"
    primary_sysid: int = 1
    gcs_sysids: set[int] = field(default_factory=lambda: {255})

    # Sensor availability
    has_gps: bool = True
    has_secondary_gps: bool = False
    has_optical_flow: bool = False
    has_distance_sensor: bool = False
    has_vision_nav: bool = False

    # Link properties
    has_radio_status: bool = False
    radio_rssi: int | None = None

    # Autopilot configuration
    forwards_mavlink: bool = True
    accepts_companion_commands: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["autopilot"] = self.autopilot.value
        d["gcs_sysids"] = list(self.gcs_sysids)
        return d


class EndpointIdentifier:
    """Maintains observed MAVLink messages and resolves hardware capability fingerprint."""

    def __init__(self) -> None:
        self.fingerprint = HardwareFingerprint()
        self.endpoints: dict[tuple[int, int], EndpointInfo] = {}

    def observe_message(self, msgname: str, fields: dict[str, Any], sysid: int, compid: int) -> None:
        """Update hardware fingerprint based on observed MAVLink packet."""
        src = (sysid, compid)

        if msgname == "HEARTBEAT":
            m_type = fields.get("type", 0)
            autopilot = fields.get("autopilot", 0)

            if m_type == 6:  # MAV_TYPE_GCS
                self.fingerprint.gcs_sysids.add(sysid)
                self.endpoints[src] = EndpointInfo(
                    sysid=sysid,
                    compid=compid,
                    endpoint_type=EndpointType.GCS,
                    autopilot_name="GCS",
                )
            elif autopilot in (3, 12) or m_type in (1, 2, 13, 14, 20):  # ArduPilot or PX4 or Copter/Plane
                ap_type = AutopilotType.ARDUPILOT if autopilot == 3 else (
                    AutopilotType.PX4 if autopilot == 12 else AutopilotType.GENERIC
                )
                self.fingerprint.autopilot = ap_type
                self.fingerprint.primary_sysid = sysid

                # Resolve vehicle class
                v_class = "COPTER"
                if m_type == 1:
                    v_class = "PLANE"
                elif m_type == 20:
                    v_class = "VTOL"
                elif m_type == 10:
                    v_class = "ROVER"
                self.fingerprint.vehicle_class = v_class

                self.endpoints[src] = EndpointInfo(
                    sysid=sysid,
                    compid=compid,
                    endpoint_type=EndpointType.FLIGHT_CONTROLLER,
                    autopilot_id=autopilot,
                    autopilot_name=ap_type.value,
                    vehicle_type=v_class,
                )

        elif msgname == "AUTOPILOT_VERSION":
            caps = fields.get("capabilities", 0)
            self.fingerprint.has_gps = True
            major = (fields.get("flight_sw_version", 0) >> 24) & 0xFF
            minor = (fields.get("flight_sw_version", 0) >> 16) & 0xFF
            patch = (fields.get("flight_sw_version", 0) >> 8) & 0xFF
            self.fingerprint.autopilot_version_str = f"{major}.{minor}.{patch}"
            if src in self.endpoints:
                self.endpoints[src].capabilities = caps
                self.endpoints[src].firmware_version = self.fingerprint.autopilot_version_str

        elif msgname in ("GPS2_RAW", "GPS_RTK"):
            self.fingerprint.has_secondary_gps = True

        elif msgname == "OPTICAL_FLOW":
            self.fingerprint.has_optical_flow = True

        elif msgname == "DISTANCE_SENSOR":
            self.fingerprint.has_distance_sensor = True

        elif msgname == "VISION_POSITION_ESTIMATE":
            self.fingerprint.has_vision_nav = True

        elif msgname == "RADIO_STATUS":
            self.fingerprint.has_radio_status = True
            self.fingerprint.radio_rssi = fields.get("rssi")
