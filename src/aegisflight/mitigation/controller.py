"""Central 4-State FSM controller for autonomous intrusion mitigation and recovery."""

from __future__ import annotations

from typing import Any

from ..core.enums import AttackType, Severity
from ..core.types import ThreatAssessment
from ..features.extractor import FeatureFrame
from .actuator import MavlinkActuator
from .golden_state import GoldenFlightState
from .parameter_estimator import ParameterEstimator
from .sanitizer import FrameSanitizer
from .submode_classifier import AttackSubModeClassifier
from .types import AttackParameters, AttackSubMode, DefenseMode, MitigationAction, MitigationState


class MitigationController:
    """Coordinates autonomous attack parameterization, frame sanitization, and recovery."""

    def __init__(
        self,
        mode: DefenseMode = DefenseMode.PASSIVE,
        recovery_clean_ticks: int = 25,
        command_cooldown_s: float = 1.0,
        secret_key: bytes | None = None,
    ) -> None:
        self.mode = mode
        self.recovery_clean_ticks = recovery_clean_ticks
        self.command_cooldown_s = command_cooldown_s

        self.state: MitigationState = MitigationState.NOMINAL
        self.golden = GoldenFlightState()
        self.classifier = AttackSubModeClassifier()
        self.estimator = ParameterEstimator()
        self.actuator = MavlinkActuator(secret_key=secret_key)
        self.sanitizer = FrameSanitizer()

        self._clean_streak = 0
        self._attack_streak = 0
        self._ekf_switched = False
        self._sanitize_gps_latched = False
        self._last_cmd_t: dict[str, float] = {}
        self._last_cmd_name: str | None = None
        self._quarantined_sysids: set[int] = set()
        self.action_history: list[dict[str, Any]] = []

    def _add_action(self, t: float, tag: str, detail: str) -> None:
        if self.action_history and self.action_history[-1]["tag"] == tag and abs(t - self.action_history[-1]["t"]) < 1.0:
            return
        self.action_history.append({"t": round(t, 2), "tag": tag, "detail": detail})
        if len(self.action_history) > 30:
            self.action_history.pop(0)

    def set_mode(self, mode: DefenseMode | str) -> None:
        """Update operational posture (passive, advisory, active-ips)."""
        new_mode = DefenseMode(mode)
        if new_mode != self.mode:
            self.mode = new_mode
            if self.mode != DefenseMode.ACTIVE_IPS:
                self.sanitizer.configure(active=False)
                self._quarantined_sysids.clear()
                self._ekf_switched = False
                self._sanitize_gps_latched = False
                self._last_cmd_name = None
            self._add_action(self.golden.anchor_t or 0.0, "MODE_CHANGE", f"Switched defense posture to {self.mode.value.upper()}")

    def reset(self) -> None:
        """Reset state machine to nominal baseline."""
        self.state = MitigationState.NOMINAL
        self._clean_streak = 0
        self._attack_streak = 0
        self._ekf_switched = False
        self._sanitize_gps_latched = False
        self._last_cmd_t.clear()
        self._last_cmd_name = None
        self._quarantined_sysids.clear()
        self.action_history.clear()
        self.golden.reset()
        self.classifier.reset()
        self.estimator.reset()
        self.sanitizer.configure(active=False)

    def _can_send_command(self, cmd_key: str, t: float) -> bool:
        last = self._last_cmd_t.get(cmd_key, -1e9)
        return (t - last) >= self.command_cooldown_s

    def _record_command(self, cmd_key: str, t: float) -> None:
        self._last_cmd_t[cmd_key] = t
        self._last_cmd_name = cmd_key

    def step(self, frame: FeatureFrame, asmt: ThreatAssessment) -> MitigationAction:
        """Process one decision tick through the mitigation state machine."""
        t = asmt.t
        # 1. Update golden state anchor or propagate dead reckoning
        self.golden.update(
            frame.snapshot,
            asmt,
            active_ips=(self.mode == DefenseMode.ACTIVE_IPS),
            pos_residual_m=frame.pos_residual_m,
        )

        is_threat = asmt.threat and asmt.severity.rank >= Severity.SUSPICIOUS.rank

        # --- A. Clean or sub-threshold tick: Recovery & nominal tracking ---
        if not is_threat:
            self._attack_streak = 0
            if (
                not asmt.threat
                and asmt.severity == Severity.NORMAL
                and len(frame.sources) == 1
                and not frame.commands_recent
            ):
                for s, _c in frame.sources:
                    self.classifier.allowed_sysids.add(s)
                    self.estimator.allowed_sysids.add(s)
            if self.state in (MitigationState.AUTO_MITIGATING, MitigationState.SAFE_HOLD):
                self._clean_streak += 1
                if self._clean_streak >= self.recovery_clean_ticks:
                    # Successfully recovered!
                    counter_frames: list[bytes] = []
                    if self.mode == DefenseMode.PASSIVE:
                        summary = f"[AEGIS IDS] CLEARED: Telemetry clean for {self._clean_streak * 0.2:.1f}s -> Nominal baseline"
                    elif self.mode == DefenseMode.ADVISORY:
                        summary = f"[AEGIS ADV] CLEARED: Telemetry clean for {self._clean_streak * 0.2:.1f}s -> Alert resolved"
                    else:
                        summary = f"[AEGIS DEF] RESOLVED: Telemetry clean for {self._clean_streak * 0.2:.1f}s -> Resumed normal operation"

                    if self.mode == DefenseMode.ACTIVE_IPS:
                        if self._ekf_switched and self._can_send_command("EKF_SWITCH_PRIMARY", t):
                            counter_frames.append(self.actuator.encode_ekf_source_switch(source_set=1))
                            self._record_command("EKF_SWITCH_PRIMARY", t)
                            self._ekf_switched = False

                        # restore only a mode that was actually observed as trusted and can be encoded;
                        # never a default (an AUTO fallback would start a mission)
                        restore_mode = self.golden.trusted_mode
                        if self.actuator.knows_mode(restore_mode) and self._can_send_command(f"RESTORE_{restore_mode}", t):
                            counter_frames.append(self.actuator.encode_set_mode(restore_mode))
                            self._record_command(f"RESTORE_{restore_mode}", t)

                        # Deactivate sanitizer
                        self.sanitizer.configure(active=False)
                        self._quarantined_sysids.clear()

                    self._sanitize_gps_latched = False
                    self.state = MitigationState.NOMINAL
                    self._add_action(t, "RECOVERED", f"Telemetry verified clean for {self._clean_streak * 0.2:.1f}s -> Resumed nominal baseline")
                    return MitigationAction(
                        t=t,
                        mode=self.mode,
                        state=self.state,
                        sub_mode=AttackSubMode.NONE,
                        params=AttackParameters(
                            trusted_lat=self.golden.effective_lat or self.golden.trusted_lat,
                            trusted_lon=self.golden.effective_lon or self.golden.trusted_lon,
                            trusted_alt_m=self.golden.trusted_alt_m,
                            trusted_mode=self.golden.trusted_mode,
                        ),
                        clean_streak=self._clean_streak,
                        recovery_target_ticks=self.recovery_clean_ticks,
                        counter_frames=counter_frames,
                        last_command_sent=self._last_cmd_name,
                        actions=list(self.action_history),
                        summary=summary,
                    )

            params = AttackParameters(
                trusted_lat=self.golden.effective_lat or self.golden.trusted_lat,
                trusted_lon=self.golden.effective_lon or self.golden.trusted_lon,
                trusted_alt_m=self.golden.trusted_alt_m,
                trusted_mode=self.golden.trusted_mode,
            )
            in_recovery = self.state in (MitigationState.AUTO_MITIGATING, MitigationState.SAFE_HOLD)
            return MitigationAction(
                t=t,
                mode=self.mode,
                state=self.state,
                sub_mode=AttackSubMode.NONE,
                params=params,
                clean_streak=self._clean_streak,
                recovery_target_ticks=self.recovery_clean_ticks,
                counter_frames=[],
                quarantined_sysids=frozenset(self._quarantined_sysids),
                sanitize_gps=bool(in_recovery and self._sanitize_gps_latched and self.mode == DefenseMode.ACTIVE_IPS),
                ekf_switched=bool(in_recovery and self._ekf_switched and self.mode == DefenseMode.ACTIVE_IPS),
                last_command_sent=self._last_cmd_name,
                actions=list(self.action_history),
                summary=(
                    (f"[AEGIS IDS] VERIFYING CLEARANCE ({self._clean_streak}/{self.recovery_clean_ticks} clean ticks)" if in_recovery else "Nominal flight (IDS passive)")
                    if self.mode == DefenseMode.PASSIVE
                    else (f"[AEGIS ADV] VERIFYING CLEARANCE ({self._clean_streak}/{self.recovery_clean_ticks} clean ticks)" if in_recovery else "Nominal flight (advisory)")
                    if self.mode == DefenseMode.ADVISORY
                    else (f"[AEGIS DEF] VERIFYING RECOVERY ({self._clean_streak}/{self.recovery_clean_ticks} clean ticks)" if in_recovery else "Nominal flight")
                ),
            )

        # --- B. Threat Tick: Active attack detected ---
        self._clean_streak = 0
        self._attack_streak += 1

        sub_mode = self.classifier.classify(frame, asmt)
        params = self.estimator.estimate(frame, self.golden, sub_mode, asmt)

        # 4-State Escalation Logic
        if sub_mode == AttackSubMode.FW_TAMPERED and frame.snapshot.armed:
            self.state = MitigationState.GCS_TAKEOVER
            if self.mode == DefenseMode.PASSIVE:
                summary = "[AEGIS IDS] CRITICAL INTEGRITY ALERT: Firmware tamper detected in flight"
            elif self.mode == DefenseMode.ADVISORY:
                summary = "[AEGIS ADV] PILOT TAKEOVER REQUIRED: Firmware tamper detected in flight"
            else:
                summary = "[AEGIS DEF] ESCALATED: CRITICAL FIRMWARE TAMPER IN FLIGHT -> PILOT TAKEOVER REQUIRED"
            self._add_action(t, "ESCALATION", "Firmware tamper detected in-flight -> Pilot takeover required")
        elif self._attack_streak > 150:  # > 30 seconds continuous spoofing/jamming
            self.state = MitigationState.SAFE_HOLD
            if self.mode == DefenseMode.PASSIVE:
                summary = "[AEGIS IDS] SUSTAINED INTRUSION (>30s): Continuous attack vector detected"
            elif self.mode == DefenseMode.ADVISORY:
                summary = "[AEGIS ADV] HOLD RECOMMENDED (>30s): Continuous attack vector detected"
            else:
                summary = "[AEGIS DEF] ESCALATED: LONG-DURATION ATTACK (>30s) -> SAFE HOLD LOITER ENGAGED"
            self._add_action(
                t,
                "SAFE_HOLD",
                "Sustained attack >30s -> Engaged safe loiter on baro/attitude"
                if self.mode == DefenseMode.ACTIVE_IPS
                else "Sustained attack >30s detected on link",
            )
        else:
            self.state = MitigationState.AUTO_MITIGATING
            if self.mode == DefenseMode.PASSIVE:
                summary = f"[AEGIS IDS] DETECTED: {sub_mode.value.upper()} (score={asmt.threat_score:.2f}) — Passive monitoring (0B TX)"
            elif self.mode == DefenseMode.ADVISORY:
                summary = f"[AEGIS ADV] HUD ALERT: {sub_mode.value.upper()} (score={asmt.threat_score:.2f}) — STATUSTEXT dispatched"
            else:
                summary = f"[AEGIS DEF] MITIGATING: {sub_mode.value.upper()} (score={asmt.threat_score:.2f})"
            if self._attack_streak == 1:
                self._add_action(t, "DETECTED", f"Identified {sub_mode.value} (score={asmt.threat_score:.2f})")

        counter_frames = []
        sanitize_gps = self._sanitize_gps_latched and self.mode == DefenseMode.ACTIVE_IPS
        sanitize_alt = False
        rate_limit_active = False

        if self.mode == DefenseMode.ACTIVE_IPS:
            # 1. GPS Spoofing Playbook (guarded against packet-reordering latency spikes)
            if sub_mode.value.startswith("gps_spoofing"):
                sanitize_gps = True
                self._sanitize_gps_latched = True
                self._add_action(t, "SANITIZE_GPS", f"GPS sanitizer active: clamping N:{params.north_offset_m:.1f}m E:{params.east_offset_m:.1f}m false offset")
                if not self._ekf_switched and self._can_send_command("EKF_SWITCH_SECONDARY", t):
                    counter_frames.append(self.actuator.encode_ekf_source_switch(source_set=2))
                    self._record_command("EKF_SWITCH_SECONDARY", t)
                    self._ekf_switched = True
                    self._add_action(t, "EKF_SWITCH", "Autopilot commanded to switch EKF to Optical Flow / Non-GPS DR")

            # 2. Command Injection Playbook
            elif asmt.attack_type == AttackType.COMMAND_INJECTION:
                for r in params.rogue_sysids:
                    if r not in self._quarantined_sysids:
                        self._add_action(t, "QUARANTINE", f"Quarantined rogue sender SysID {r} (hostile packets dropped)")
                    self._quarantined_sysids.add(r)

                if self.classifier.last_cadence_violation:
                    self._add_action(t, "REPLAY_GUARD", self.classifier.last_cadence_violation)

                if sub_mode == AttackSubMode.CMD_ARM_DISARM_BURST:
                    # reported only: nothing on this path drops the command before the autopilot
                    self._add_action(t, "VETO_DISARM", "Flagged motor arm/disarm command burst in flight (not blocked)")

                if (self.actuator.knows_mode(params.target_restore_mode)
                        and self._can_send_command(f"RESTORE_{params.target_restore_mode}", t)):
                    counter_frames.append(self.actuator.encode_set_mode(params.target_restore_mode))
                    self._record_command(f"RESTORE_{params.target_restore_mode}", t)
                    self._add_action(t, "RESTORE_MODE", f"Dispatched counter-command: restored mode {params.target_restore_mode}")

            # 3. MAVLink Anomaly Playbook
            elif asmt.attack_type == AttackType.MAVLINK_ANOMALY and sub_mode != AttackSubMode.DOS_BLACKOUT:
                for r in params.rogue_sysids:
                    if r not in self._quarantined_sysids:
                        self._add_action(t, "QUARANTINE", f"Quarantined anomalous sender SysID {r} (packets dropped)")
                    self._quarantined_sysids.add(r)
                if sub_mode == AttackSubMode.MAV_RATE_SPIKE:
                    rate_limit_active = True
                    self._add_action(t, "RATE_LIMIT", "Anomalous message rate spike gatekeeper engaged")

            # 4. Telemetry Manipulation Playbook
            elif asmt.attack_type == AttackType.TELEMETRY_MANIPULATION:
                if sub_mode == AttackSubMode.TELEM_ALTITUDE_BIAS:
                    sanitize_alt = True
                    self._add_action(t, "SANITIZE_ALT", f"Altitude clamp active: neutralized {params.alt_bias_m:.1f}m false offset")
                elif sub_mode == AttackSubMode.TELEM_SPEED_MISMATCH:
                    self._add_action(t, "SPEED_CLAMP", f"Rejected {params.speed_bias_ms:.1f}m/s VFR speed bias -> locked to EKF velocity")
                elif sub_mode == AttackSubMode.TELEM_BATTERY_JUMP:
                    self._add_action(t, "BATT_FILTER", f"Clamped erratic battery spike ({params.battery_bias_v:.2f}V/s) -> holding golden anchor {self.golden.trusted_battery_v or 24.0:.1f}V")
                elif sub_mode == AttackSubMode.TELEM_FROZEN_ATTITUDE:
                    self._add_action(t, "AHRS_CROSSCHECK", "Frozen attitude telemetry isolated -> cross-checking course-over-ground")

            # 5. DoS Flood / Jamming / Latency Blackout Playbook
            elif asmt.attack_type == AttackType.DOS or sub_mode == AttackSubMode.DOS_BLACKOUT:
                if sub_mode in (AttackSubMode.DOS_FLOOD, AttackSubMode.MAV_RATE_SPIKE):
                    rate_limit_active = True
                    self._add_action(t, "RATE_LIMIT", "Hostile frame rate flooding gatekeeper engaged (100Hz cap)")
                elif sub_mode == AttackSubMode.DOS_GNSS_JAMMING:
                    sanitize_gps = True
                    self._sanitize_gps_latched = True
                    self._add_action(t, "ANTI_JAM_DR", "GNSS receiver jammed (fix lost) -> switched navigation to IMU/Baro dead reckoning")
                    if not self._ekf_switched and self._can_send_command("EKF_SWITCH_SECONDARY", t):
                        counter_frames.append(self.actuator.encode_ekf_source_switch(source_set=2))
                        self._record_command("EKF_SWITCH_SECONDARY", t)
                        self._ekf_switched = True
                elif sub_mode == AttackSubMode.DOS_BLACKOUT:
                    self._add_action(t, "LINK_WATCHDOG", "Telemetry blackout/latency detected -> holding golden state & arming failsafe loiter")

            # 6. Firmware Integrity Playbook
            elif asmt.attack_type == AttackType.FIRMWARE_INTEGRITY:
                # only when the vehicle is KNOWN to be disarmed (armed=None is unknown, never "disarmed"),
                # and never with the force-disarm code
                if frame.snapshot.armed is False and self._can_send_command("PREARM_DISARM", t):
                    counter_frames.append(self.actuator.encode_prearm_disarm(force=False))
                    self._record_command("PREARM_DISARM", t)
                    self._add_action(t, "PREARM_LOCK", "Autopilot pre-arm check locked: tampered firmware")

            # 7. Safe Hold Escalation Playbook
            if self.state == MitigationState.SAFE_HOLD and self._can_send_command("SET_MODE_ALT_HOLD", t):
                counter_frames.append(self.actuator.encode_set_mode("ALT_HOLD"))
                self._record_command("SET_MODE_ALT_HOLD", t)
                self._add_action(t, "SAFE_HOLD_CMD", "Counter-actuation dispatched: engaged ALT_HOLD loiter")

            # Update inline sanitizer
            self.sanitizer.configure(
                active=True,
                quarantined_sysids=self._quarantined_sysids,
                sanitize_gps=sanitize_gps,
                sanitize_alt=sanitize_alt,
                lat_offset_deg=params.lat_offset_deg,
                lon_offset_deg=params.lon_offset_deg,
                alt_bias_m=params.alt_bias_m,
                rate_limit_active=rate_limit_active,
            )
        elif self.mode == DefenseMode.ADVISORY:
            if self._can_send_command("STATUSTEXT_ALERT", t):
                text = f"AEGIS: {sub_mode.value.upper()} ({asmt.threat_score:.2f})"
                counter_frames.append(self.actuator.encode_statustext(text))
                self._record_command("STATUSTEXT_ALERT", t)
                self._add_action(t, "STATUSTEXT", f"Dispatched HUD alert: {text}")

        return MitigationAction(
            t=t,
            mode=self.mode,
            state=self.state,
            sub_mode=sub_mode,
            params=params,
            clean_streak=self._clean_streak,
            recovery_target_ticks=self.recovery_clean_ticks,
            counter_frames=counter_frames,
            quarantined_sysids=frozenset(self._quarantined_sysids),
            sanitize_gps=sanitize_gps,
            sanitize_alt=sanitize_alt,
            ekf_switched=self._ekf_switched,
            last_command_sent=self._last_cmd_name,
            actions=list(self.action_history),
            summary=summary,
        )

    def manual_override(self, action: str) -> MitigationAction:
        """Handle manual GCS operator override commands."""
        counter_frames: list[bytes] = []
        if action == "safe_hold":
            self.state = MitigationState.SAFE_HOLD
            if self.mode == DefenseMode.ACTIVE_IPS:
                counter_frames.append(self.actuator.encode_set_mode("ALT_HOLD"))
                self._last_cmd_name = "SET_MODE_ALT_HOLD"
                summary = "[AEGIS DEF] MANUAL OVERRIDE: Engaged SAFE_HOLD (ALT_HOLD)"
                self._add_action(0.0, "MANUAL_SAFE_HOLD", "Pilot engaged manual SAFE_HOLD override")
            elif self.mode == DefenseMode.ADVISORY:
                summary = "[AEGIS ADV] MANUAL OVERRIDE: SAFE_HOLD state flagged"
                self._add_action(0.0, "MANUAL_SAFE_HOLD", "Pilot flagged manual SAFE_HOLD advisory")
            else:
                summary = "[AEGIS IDS] MANUAL OVERRIDE: SAFE_HOLD flagged (0 bytes sent)"
                self._add_action(0.0, "MANUAL_SAFE_HOLD", "Operator flagged manual SAFE_HOLD state (passive)")
        elif action == "reset_quarantine":
            self._quarantined_sysids.clear()
            self.sanitizer.quarantined_sysids.clear()
            summary = "[AEGIS DEF] MANUAL OVERRIDE: Reset quarantined sysids"
            self._add_action(0.0, "RESET_QUARANTINE", "Pilot flushed quarantined system IDs")
        elif action == "ack_takeover":
            self.state = MitigationState.NOMINAL
            summary = "[AEGIS DEF] MANUAL OVERRIDE: Acknowledged pilot takeover"
            self._add_action(0.0, "ACK_TAKEOVER", "Pilot acknowledged takeover -> Reset to nominal baseline")
        else:
            summary = f"[AEGIS DEF] Unknown override action '{action}'"

        return MitigationAction(
            t=0.0,
            mode=self.mode,
            state=self.state,
            sub_mode=AttackSubMode.NONE,
            params=AttackParameters(),
            counter_frames=counter_frames,
            quarantined_sysids=frozenset(self._quarantined_sysids),
            last_command_sent=self._last_cmd_name,
            actions=list(self.action_history),
            summary=summary,
        )
