"""Data structures and enums for the AegisFlight Autonomous Defense Layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..core.enums import AttackType


class DefenseMode(str, Enum):
    """Operational posture of AegisFlight."""

    PASSIVE = "passive"        # Default: strictly bytes_sent = 0
    ADVISORY = "advisory"      # GCS STATUSTEXT alerts only, zero control actuation
    ACTIVE_IPS = "active-ips"  # Autonomous inline sanitization + counter-actuation


class MitigationState(str, Enum):
    """4-State Escalation Finite State Machine (FSM)."""

    NOMINAL = "NOMINAL"                        # Clean flight; updating GoldenFlightState anchor
    AUTO_MITIGATING = "AUTO_MITIGATING"        # Active counter-program neutralizing attack
    SAFE_HOLD = "SAFE_HOLD"                    # Multi-sensor conflict; loitering on baro/attitude
    GCS_TAKEOVER = "GCS_TAKEOVER"              # Unrecoverable safety margin breach; pilot required


class AttackSubMode(str, Enum):
    """Granular tactical sub-modes across the 6 challenge attack classes."""

    NONE = "none"
    # Class 1: GPS_SPOOFING
    GPS_GRADUAL_DRIFT = "gps_spoofing:gradual_drift"
    GPS_SUDDEN_OFFSET = "gps_spoofing:sudden_offset"
    GPS_REPLAY_FREEZE = "gps_spoofing:replay_freeze"
    # Class 2: MAVLINK_ANOMALY
    MAV_SEQ_SCRAMBLE = "mavlink_anomaly:seq_scramble"
    MAV_RATE_SPIKE = "mavlink_anomaly:rate_spike"
    MAV_ROGUE_SYSID = "mavlink_anomaly:rogue_sysid"
    # Class 3: COMMAND_INJECTION
    CMD_ROGUE_SOURCE = "command_injection:rogue_command"
    CMD_MODE_FLIP = "command_injection:mode_flip"
    CMD_ARM_DISARM_BURST = "command_injection:arm_disarm_burst"
    # Class 4: TELEMETRY_MANIPULATION
    TELEM_ALTITUDE_BIAS = "telemetry_manipulation:altitude_bias"
    TELEM_SPEED_MISMATCH = "telemetry_manipulation:speed_mismatch"
    TELEM_BATTERY_JUMP = "telemetry_manipulation:battery_jump"
    TELEM_FROZEN_ATTITUDE = "telemetry_manipulation:frozen_attitude"
    # Class 5: DOS
    DOS_FLOOD = "dos:flood"
    DOS_BLACKOUT = "dos:blackout"
    DOS_GNSS_JAMMING = "dos:gnss_jamming"
    # Class 6: FIRMWARE_INTEGRITY
    FW_TAMPERED = "firmware_integrity:default"


@dataclass(slots=True)
class AttackParameters:
    """Closed-form quantitative parameters of an active attack."""

    attack_type: AttackType = AttackType.BENIGN
    sub_mode: AttackSubMode = AttackSubMode.NONE
    # Inputs (Trusted Reference Anchor)
    trusted_lat: float | None = None
    trusted_lon: float | None = None
    trusted_alt_m: float | None = None
    trusted_mode: str | None = None
    # Computed Quantitative Attack Parameters (Outputs)
    lat_offset_deg: float = 0.0
    lon_offset_deg: float = 0.0
    north_offset_m: float = 0.0
    east_offset_m: float = 0.0
    drift_rate_ms: float = 0.0
    alt_bias_m: float = 0.0
    speed_bias_ms: float = 0.0
    battery_bias_v: float = 0.0
    rogue_sysids: tuple[int, ...] = ()
    target_restore_mode: str | None = None


@dataclass(slots=True)
class MitigationAction:
    """Output decision of MitigationController for one tick."""

    t: float
    mode: DefenseMode
    state: MitigationState
    sub_mode: AttackSubMode
    params: AttackParameters
    clean_streak: int = 0
    recovery_target_ticks: int = 25
    counter_frames: list[bytes] = field(default_factory=list)
    quarantined_sysids: frozenset[int] = field(default_factory=frozenset)
    sanitize_gps: bool = False
    sanitize_alt: bool = False
    ekf_switched: bool = False
    last_command_sent: str | None = None
    actions: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        p = self.params
        q_sysids = sorted(self.quarantined_sysids)
        cf_sent = len(self.counter_frames)
        clean_streak = self.clean_streak
        target_ticks = max(1, self.recovery_target_ticks)
        progress = round(min(1.0, clean_streak / target_ticks), 3)

        inputs_dict = {
            "trusted_lat": round(p.trusted_lat, 6) if p.trusted_lat is not None else None,
            "trusted_lon": round(p.trusted_lon, 6) if p.trusted_lon is not None else None,
            "trusted_alt_m": round(p.trusted_alt_m, 2) if p.trusted_alt_m is not None else None,
            "trusted_mode": p.trusted_mode,
        }

        outputs_dict = {
            "north_offset_m": round(p.north_offset_m, 2),
            "east_offset_m": round(p.east_offset_m, 2),
            "drift_rate_ms": round(p.drift_rate_ms, 2),
            "alt_bias_m": round(p.alt_bias_m, 2),
            "speed_bias_ms": round(p.speed_bias_ms, 2),
            "battery_bias_v": round(p.battery_bias_v, 2),
            "rogue_sysids": list(p.rogue_sysids),
            "target_restore_mode": p.target_restore_mode,
            "quarantined_sysids": q_sysids,
            "sanitize_gps": self.sanitize_gps,
            "sanitize_alt": self.sanitize_alt,
            "ekf_switched": self.ekf_switched,
            "last_command_sent": self.last_command_sent,
            "counter_frames_sent": cf_sent,
        }

        params_dict = {
            "attack_type": p.attack_type.value if hasattr(p.attack_type, "value") else str(p.attack_type),
            "sub_mode": p.sub_mode.value if hasattr(p.sub_mode, "value") else str(p.sub_mode),
            "trusted_lat": inputs_dict["trusted_lat"],
            "trusted_lon": inputs_dict["trusted_lon"],
            "trusted_alt_m": inputs_dict["trusted_alt_m"],
            "trusted_mode": inputs_dict["trusted_mode"],
            "lat_offset_deg": round(p.lat_offset_deg, 7),
            "lon_offset_deg": round(p.lon_offset_deg, 7),
            "north_offset_m": outputs_dict["north_offset_m"],
            "east_offset_m": outputs_dict["east_offset_m"],
            "drift_rate_ms": outputs_dict["drift_rate_ms"],
            "alt_bias_m": outputs_dict["alt_bias_m"],
            "speed_bias_ms": outputs_dict["speed_bias_ms"],
            "battery_bias_v": outputs_dict["battery_bias_v"],
            "rogue_sysids": outputs_dict["rogue_sysids"],
            "target_restore_mode": outputs_dict["target_restore_mode"],
        }

        return {
            "t": round(self.t, 3),
            "mode": self.mode.value,
            "state": self.state.value,
            "sub_mode": self.sub_mode.value,
            "clean_streak": clean_streak,
            "recovery_target_ticks": self.recovery_target_ticks,
            "recovery_progress": progress,
            "counter_frames_sent": cf_sent,
            "quarantined_sysids": q_sysids,
            "sanitize_gps": self.sanitize_gps,
            "sanitize_alt": self.sanitize_alt,
            "ekf_switched": self.ekf_switched,
            "last_command_sent": self.last_command_sent,
            "actions": self.actions,
            "inputs": inputs_dict,
            "outputs": outputs_dict,
            "params": params_dict,
            "summary": self.summary,
        }
