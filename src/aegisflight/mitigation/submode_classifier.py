"""Tactical attack sub-mode classifier for selecting mitigation playbooks."""

from __future__ import annotations

import math

from ..core.enums import AttackType
from ..core.geo import EARTH_RADIUS_M
from ..core.types import ThreatAssessment
from ..detectors.physics import CusumDriftIntegrator
from ..features.extractor import FeatureFrame
from .types import AttackSubMode

HIGH_RISK_COMMANDS = frozenset({400, 176, 20, 21})  # ARM_DISARM, DO_SET_MODE, NAV_RTL, NAV_LAND


class AttackSubModeClassifier:
    """Classifies granular attack sub-modes from FeatureFrame and ThreatAssessment.

    Includes:
      - 2D Page-Hinkley / CUSUM Vector Residual Integrator for subtle micro-drift (< 0.3 m/s).
      - State-Aware Command Cadence Guard for duplicate high-risk commands (disarm / RTL / mode flip).
    """

    def __init__(
        self,
        cusum_slack_ms: float = 0.05,
        cusum_threshold_m: float = 1.2,
        cadence_min_interval_s: float = 1.5,
        expected_sysids: tuple[int, ...] = (1, 3),
        expected_gcs_sysids: tuple[int, ...] = (253, 254, 255),
    ) -> None:
        self._prev_lat: float | None = None
        self._prev_lon: float | None = None
        self._prev_t: float | None = None
        self.cusum = CusumDriftIntegrator(slack_ms=cusum_slack_ms, threshold_m=cusum_threshold_m)
        self.cadence_min_interval_s = cadence_min_interval_s
        self.expected_sysids = set(expected_sysids)
        self.expected_gcs_sysids = set(expected_gcs_sysids)
        self.allowed_sysids = set(self.expected_sysids | self.expected_gcs_sysids)
        self._last_cmd_t: dict[tuple[int, int], float] = {}
        self.last_cadence_violation: str | None = None

    def reset(self) -> None:
        self._prev_lat = None
        self._prev_lon = None
        self._prev_t = None
        self.cusum.reset()
        self.allowed_sysids = set(self.expected_sysids | self.expected_gcs_sysids)
        self._last_cmd_t.clear()
        self.last_cadence_violation = None

    def update_cusum(self, frame: FeatureFrame) -> float:
        """Update 2D Page-Hinkley CUSUM state from consecutive frame snapshots."""
        snap = frame.snapshot
        if (
            snap.lat is not None
            and snap.lon is not None
            and self._prev_lat is not None
            and self._prev_lon is not None
            and self._prev_t is not None
        ):
            dt = frame.t - self._prev_t
            if 1e-6 < dt <= 2.0:
                dn = math.radians(snap.lat - self._prev_lat) * EARTH_RADIUS_M
                de = math.radians(snap.lon - self._prev_lon) * EARTH_RADIUS_M * math.cos(math.radians(snap.lat))
                vx = snap.vx or 0.0
                vy = snap.vy or 0.0
                self.cusum.update_displacement(dn - vx * dt, de - vy * dt, dt)
        return max(frame.cusum_drift_m, self.cusum.magnitude_m)

    def check_command_cadence(self, frame: FeatureFrame) -> tuple[bool, AttackSubMode, str]:
        """State-aware command cadence guard for unsigned links.

        Flags:
          1. Duplicate high-risk commands (ARM_DISARM=400, DO_SET_MODE=176, RTL=20, LAND=21)
             arriving faster than normal operator heartbeat cadence (< cadence_min_interval_s).
          2. In-flight motor disarm (command=400, param1=0) while groundspeed > 1.0 m/s.
          3. MAVLink-2 signature / timestamp replay failure (sig_invalid_count > 0).
        """
        self.last_cadence_violation = None
        snap = frame.snapshot

        if frame.sig_invalid_count > 0:
            reason = f"MAVLink-2 signature/timestamp replay violation ({frame.sig_invalid_count} invalid frame(s))"
            self.last_cadence_violation = reason
            return True, AttackSubMode.CMD_ROGUE_SOURCE, reason

        seen_in_frame: dict[tuple[int, int], float] = {}
        for c in frame.commands_recent:
            if c.command not in HIGH_RISK_COMMANDS:
                continue
            # Check in-flight motor disarm attempt
            if c.command == 400 and (not c.params or c.params[0] == 0.0):
                if (snap.groundspeed or 0.0) > 1.0 and snap.armed:
                    reason = f"Mid-air motor disarm vetoed (sysid={c.sysid}, groundspeed={snap.groundspeed:.1f} m/s)"
                    self.last_cadence_violation = reason
                    return True, AttackSubMode.CMD_ARM_DISARM_BURST, reason

            key = (c.sysid, c.command)
            last = self._last_cmd_t.get(key)
            if last is not None and c.recv_time <= last:
                continue  # already evaluated on an earlier decision (commands_recent is a sliding window)
            prev_t = seen_in_frame.get(key, last)
            if (
                c.sysid in self.expected_gcs_sysids
                and prev_t is not None
                and 0.0 < (c.recv_time - prev_t) < self.cadence_min_interval_s
            ):
                sub = (
                    AttackSubMode.CMD_ARM_DISARM_BURST
                    if c.command == 400
                    else AttackSubMode.CMD_MODE_FLIP
                )
                reason = (
                    f"Duplicate high-risk command (cmd={c.command}, sysid={c.sysid}, "
                    f"Δt={c.recv_time - prev_t:.2f}s < {self.cadence_min_interval_s:.1f}s)"
                )
                self.last_cadence_violation = reason
                seen_in_frame[key] = c.recv_time
                self._last_cmd_t[key] = c.recv_time
                return True, sub, reason

            seen_in_frame[key] = c.recv_time
            self._last_cmd_t[key] = c.recv_time

        return False, AttackSubMode.NONE, ""

    def classify(self, frame: FeatureFrame, asmt: ThreatAssessment) -> AttackSubMode:
        atk = asmt.attack_type
        snap = frame.snapshot
        ev_text = " ".join(asmt.evidence).lower()

        dt_pos = (frame.t - self._prev_t) if self._prev_t is not None else 0.0
        is_frozen_pos = (
            snap.lat is not None
            and snap.lon is not None
            and self._prev_lat is not None
            and self._prev_lon is not None
            and dt_pos > 1e-3
            and abs(snap.lat - self._prev_lat) < 1e-7
            and abs(snap.lon - self._prev_lon) < 1e-7
        )
        self.update_cusum(frame)
        if snap.lat is not None and snap.lon is not None:
            self._prev_lat = snap.lat
            self._prev_lon = snap.lon
            self._prev_t = frame.t

        if atk == AttackType.GPS_SPOOFING:
            if frame.max_seq_gap >= 240 and frame.interarrival_jitter_ms > 47.5:
                return AttackSubMode.DOS_BLACKOUT
            if frame.accel_ms2 > 20.0:
                return AttackSubMode.GPS_SUDDEN_OFFSET

            v_gps = math.hypot(snap.vx or 0.0, snap.vy or 0.0)
            has_gps_vel = snap.vx is not None or snap.vy is not None
            if (snap.groundspeed is not None and snap.groundspeed > 2.0 and ((has_gps_vel and v_gps < 0.3) or is_frozen_pos)) or (
                "freeze" in ev_text or "frozen" in ev_text or "stale" in ev_text
            ):
                return AttackSubMode.GPS_REPLAY_FREEZE
            if frame.pos_residual_m >= 30.0:
                return AttackSubMode.GPS_SUDDEN_OFFSET
            return AttackSubMode.GPS_GRADUAL_DRIFT

        if atk == AttackType.COMMAND_INJECTION:
            cadence_hit, cadence_sub, _ = self.check_command_cadence(frame)
            if frame.cmd_rate_hz > 3.5 or sum(1 for c in frame.commands_recent if c.command == 400) > 4:
                return AttackSubMode.CMD_ARM_DISARM_BURST
            if cadence_hit:
                return cadence_sub
            if (
                any(c.sysid not in self.allowed_sysids for c in frame.commands_recent)
                or "unexpected source" in ev_text
                or "sysid" in ev_text
            ):
                return AttackSubMode.CMD_ROGUE_SOURCE
            if (
                any(c.command in (176, 20, 21) for c in frame.commands_recent)
                or "set_mode" in ev_text
                or "mode" in ev_text
                or "rtl" in ev_text
            ):
                return AttackSubMode.CMD_MODE_FLIP
            return AttackSubMode.CMD_MODE_FLIP

        if atk == AttackType.MAVLINK_ANOMALY:
            if (
                frame.n_sources > 2
                or "sysid" in ev_text
                or "rogue telemetry" in ev_text
                or any(s not in self.allowed_sysids for (s, _) in frame.sources)
            ):
                return AttackSubMode.MAV_ROGUE_SYSID
            if frame.max_seq_gap >= 240 and frame.interarrival_jitter_ms > 47.5:
                return AttackSubMode.DOS_BLACKOUT
            if frame.max_seq_gap > 30 or "seq" in ev_text:
                return AttackSubMode.MAV_SEQ_SCRAMBLE
            return AttackSubMode.MAV_RATE_SPIKE

        if atk == AttackType.TELEMETRY_MANIPULATION:
            if frame.gps_baro_alt_diff_m > 8.0 or abs(frame.alt_rate_ms) > 25.0:
                return AttackSubMode.TELEM_ALTITUDE_BIAS
            if frame.battery_v_rise > 0.4 or frame.battery_v_rate < -2.0:
                return AttackSubMode.TELEM_BATTERY_JUMP
            if frame.yaw_course_diff_deg > 25.0:
                return AttackSubMode.TELEM_FROZEN_ATTITUDE
            return AttackSubMode.TELEM_SPEED_MISMATCH

        if atk == AttackType.DOS:
            if "message-rate spike" in ev_text and frame.msg_rate_hz < 250.0:
                return AttackSubMode.MAV_RATE_SPIKE
            if frame.msg_rate_hz > 84.0 or "flood" in ev_text:
                return AttackSubMode.DOS_FLOOD
            if (snap.gps_fix_type is not None and snap.gps_fix_type < 3) or "gnss" in ev_text:
                return AttackSubMode.DOS_GNSS_JAMMING
            return AttackSubMode.DOS_BLACKOUT

        if atk == AttackType.FIRMWARE_INTEGRITY:
            return AttackSubMode.FW_TAMPERED

        return AttackSubMode.NONE
