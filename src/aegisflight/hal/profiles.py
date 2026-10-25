"""Firmware-specific command profiles and translation layer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..mavlink.codec import COPTER_MODES


class AutopilotType(str, Enum):
    ARDUPILOT = "ARDUPILOT"
    PX4 = "PX4"
    GENERIC = "GENERIC"
    UNKNOWN = "UNKNOWN"


# Plane mode map for ArduPlane
PLANE_MODES: dict[str, int] = {
    "MANUAL": 0,
    "CIRCLE": 1,
    "STABILIZE": 2,
    "TRAINING": 3,
    "ACRO": 4,
    "FBWA": 5,
    "FBWB": 6,
    "CRUISE": 7,
    "AUTOTUNE": 8,
    "AUTO": 10,
    "RTL": 11,
    "LOITER": 12,
    "TAKEOFF": 13,
    "AVOID_ADSB": 14,
    "GUIDED": 15,
}

# PX4 Custom mode encoding
PX4_MAIN_MODES = {
    "MANUAL": 1,
    "ALTCTL": 2,
    "POSCTL": 3,
    "AUTO": 4,
    "ACRO": 5,
    "OFFBOARD": 6,
    "STABILIZED": 7,
    "RATTITUDE": 8,
}

PX4_AUTO_SUBMODES = {
    "READY": 1,
    "TAKEOFF": 2,
    "LOITER": 3,
    "MISSION": 4,
    "RTL": 5,
    "LAND": 6,
    "RTGS": 7,
    "FOLLOW_TARGET": 8,
    "PRECLAND": 9,
    "VTOL_TAKEOFF": 10,
}


@dataclass
class ModeCommand:
    """Wire representation of an autopilot flight mode change command."""

    command_name: str
    custom_mode: int
    base_mode: int = 1
    params: tuple[float, ...] = ()


class FirmwareProfile:
    """Translates high-level defense actions into firmware-accurate MAVLink commands."""

    def __init__(self, autopilot: AutopilotType, vehicle_class: str = "COPTER") -> None:
        self.autopilot = autopilot
        self.vehicle_class = vehicle_class.upper()

    @property
    def is_supported_for_ips(self) -> bool:
        """Only ArduPilot and PX4 have verified closed-loop IPS control profiles."""
        return self.autopilot in (AutopilotType.ARDUPILOT, AutopilotType.PX4)

    def resolve_mode_number(self, mode_name: str) -> int:
        """Resolve mode string (e.g. 'AUTO', 'LAND', 'LOITER') to firmware mode integer."""
        mode_upper = mode_name.upper().strip()

        if self.autopilot == AutopilotType.ARDUPILOT:
            if self.vehicle_class == "PLANE":
                return PLANE_MODES.get(mode_upper, 10)  # default AUTO=10
            return COPTER_MODES.get(mode_upper, 3)  # default AUTO=3

        if self.autopilot == AutopilotType.PX4:
            if mode_upper in ("AUTO", "MISSION"):
                main = PX4_MAIN_MODES["AUTO"]
                sub = PX4_AUTO_SUBMODES["MISSION"]
                return (main << 16) | (sub << 24)
            if mode_upper == "LOITER":
                main = PX4_MAIN_MODES["AUTO"]
                sub = PX4_AUTO_SUBMODES["LOITER"]
                return (main << 16) | (sub << 24)
            if mode_upper == "RTL":
                main = PX4_MAIN_MODES["AUTO"]
                sub = PX4_AUTO_SUBMODES["RTL"]
                return (main << 16) | (sub << 24)
            if mode_upper == "LAND":
                main = PX4_MAIN_MODES["AUTO"]
                sub = PX4_AUTO_SUBMODES["LAND"]
                return (main << 16) | (sub << 24)
            # Default POSCTL
            return (PX4_MAIN_MODES["POSCTL"] << 16)

        return 0

    def encode_restore_mode(self, mode_name: str = "AUTO") -> ModeCommand:
        """Build the exact MAV_CMD_DO_SET_MODE command for this firmware."""
        custom_mode = self.resolve_mode_number(mode_name)
        return ModeCommand(
            command_name="MAV_CMD_DO_SET_MODE",
            custom_mode=custom_mode,
            base_mode=1,
            params=(1.0, float(custom_mode)),
        )

    def encode_ekf_switch(self, secondary_available: bool = True) -> dict[str, Any]:
        """Encode sensor source change command for GPS spoofing counter-action."""
        if self.autopilot == AutopilotType.ARDUPILOT and secondary_available:
            # ArduPilot MAV_CMD_SET_EKF_SOURCE_SET (42007)
            # Param 1 = 2 (Optical Flow / Non-GPS source set)
            return {
                "command": "MAV_CMD_SET_EKF_SOURCE_SET",
                "command_id": 42007,
                "param1": 2.0,
                "strategy": "EKF_SOURCE_SET_2",
            }

        # PX4 or non-source-set fallback: command vehicle to safe altitude hold
        return {
            "command": "MAV_CMD_DO_SET_MODE",
            "command_id": 176,
            "param1": 1.0,
            "param2": float(self.resolve_mode_number("LOITER")),
            "strategy": "SAFE_LOITER_HOLD",
        }


def get_firmware_profile(autopilot: AutopilotType, vehicle_class: str = "COPTER") -> FirmwareProfile:
    return FirmwareProfile(autopilot=autopilot, vehicle_class=vehicle_class)
