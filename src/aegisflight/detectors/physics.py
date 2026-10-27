"""Detector B — cyber-physical consistency.

Cross-checks physically-coupled telemetry channels that an attacker cannot
falsify all at once: the reported position track vs the velocity-implied track
(GPS spoofing), GPS altitude vs barometric altitude, GPS-velocity speed vs
VFR_HUD groundspeed, altitude/acceleration plausibility, battery-voltage
dynamics, and heading (attitude) vs course-over-ground. A light hysteresis
suppresses single-tick sensor-noise spikes on the soft checks; a hard position
residual fires immediately.
"""

from __future__ import annotations

import math
from collections.abc import Callable

from ..core.enums import AttackType, DetectorName
from ..core.types import DetectorResult
from ..features.extractor import FeatureFrame
from .base import Detector, ramp


class CusumDriftIntegrator:
    """2D Page-Hinkley / CUSUM Vector Residual Integrator for subtle micro-drift (< 0.3 m/s).

    Implements isotropic 2D radial soft-thresholding:
        u_k = S_{k-1} + (v_gps,k - v_imu,k) * dt
        S_k = max(0, 1 - (nu * dt) / ||u_k||) * u_k
    Zero-mean Gaussian turbulence cancels out over time (sum(eps_k) ~ 0), whereas a
    directional micro-drift (0.15 - 0.30 m/s) accumulates monotonically past threshold_m.
    """

    def __init__(self, slack_ms: float = 0.05, threshold_m: float = 1.2) -> None:
        self.slack_ms = float(slack_ms)
        self.threshold_m = float(threshold_m)
        self.s_north_m: float = 0.0
        self.s_east_m: float = 0.0

    @property
    def magnitude_m(self) -> float:
        return math.hypot(self.s_north_m, self.s_east_m)

    @property
    def triggered(self) -> bool:
        return self.magnitude_m >= self.threshold_m

    def reset(self) -> None:
        self.s_north_m = 0.0
        self.s_east_m = 0.0

    def update_displacement(self, inc_n_m: float, inc_e_m: float, dt: float) -> float:
        """Update 2D CUSUM state from a step displacement residual (inc_n, inc_e) over dt."""
        if dt <= 0.0:
            return self.magnitude_m
        un = self.s_north_m + inc_n_m
        ue = self.s_east_m + inc_e_m
        umag = math.hypot(un, ue)
        allowance = self.slack_ms * dt
        if umag > allowance and umag > 1e-12:
            scale = (umag - allowance) / umag
            self.s_north_m = un * scale
            self.s_east_m = ue * scale
        else:
            self.s_north_m = 0.0
            self.s_east_m = 0.0
        return self.magnitude_m

    def update_velocity_residual(
        self,
        v_gps_n_ms: float,
        v_gps_e_ms: float,
        v_imu_n_ms: float,
        v_imu_e_ms: float,
        dt: float,
    ) -> float:
        """Update 2D CUSUM state directly from GPS vs IMU/reference velocity vectors."""
        return self.update_displacement(
            (v_gps_n_ms - v_imu_n_ms) * dt,
            (v_gps_e_ms - v_imu_e_ms) * dt,
            dt,
        )


class PhysicsDetector(Detector):
    name = DetectorName.PHYSICS

    def __init__(self, cfg: dict) -> None:
        p = cfg
        self.pos_resid = float(p.get("gps_pos_residual_m", 12.0))
        self.pos_resid_hard = float(p.get("gps_pos_residual_hard_m", 30.0))
        self.speed_cons = float(p.get("gps_speed_consistency_ms", 5.0))
        self.alt_cons = float(p.get("alt_consistency_m", 8.0))
        self.alt_jump = float(p.get("alt_jump_ms", 25.0))
        self.max_accel = float(p.get("max_accel_ms2", 20.0))
        self.max_jerk = float(p.get("max_jerk_ms3", 60.0))
        self.batt_rise = float(p.get("battery_rise_v", 0.4))
        self.batt_drop = float(p.get("battery_drop_rate_v_s", 2.0))
        # heading-vs-course tolerance (deg); config key added for per-vehicle profiles,
        # the default stays the Stage-1 constant 25.0
        self.yaw_course_deg = float(p.get("yaw_course_deg", 25.0))
        self.hysteresis_ticks = int(p.get("hysteresis_ticks", 2))
        self.cusum_enabled = bool(p.get("cusum_enabled", False))
        self.cusum_threshold_m = float(p.get("cusum_threshold_m", 1.2))
        self.cusum_slack_ms = float(p.get("cusum_slack_ms", 0.05))
        self.cusum = CusumDriftIntegrator(
            slack_ms=self.cusum_slack_ms,
            threshold_m=self.cusum_threshold_m,
        )
        # Estimator-aware residual (2026-10-25; v2 2026-10-26; rules in ``process`` and
        # docs/DETECTION.md). True: at a GATED fix (EKF_STATUS_REPORT has said "no horizontal
        # solution" continuously for >= 2 s and is fresh) the position-vs-velocity residual is not
        # spoofing evidence; velocity-implied movement the position does not show, and single-fix
        # jumps, are checked instead. False: the Stage-1 rule on ``pos_residual_m``, ignoring
        # estimator state.
        # Inert only while no EKF_STATUS_REPORT has been received (Stage-1 SIM, PX4 / ArduPilot SITL
        # as captured); the report is unauthenticated, so an injected one can activate it (it needs
        # >= 2 s of sustained no-solution reports).
        self.estimator_gate = bool(p.get("estimator_gate", True))
        self._soft_streak = 0

    def process(self, frame: FeatureFrame) -> DetectorResult:
        evidence: list[str] = []
        votes: dict[AttackType, float] = {}
        signals: dict[str, float] = {}
        score = 0.0
        hard = False

        def bump(attack: AttackType, s: float, hard_hit: bool = False) -> None:
            nonlocal score, hard
            votes[attack] = max(votes.get(attack, 0.0), s)
            score = max(score, s)
            hard = hard or hard_hit

        # ---- GPS position residual (spoofing) ----
        signals["pos_residual_m"] = frame.pos_residual_m
        nav_note: str | None = None
        if not self.estimator_gate or frame.pos_residual_nav_m is None:
            # gate off, or no EKF_STATUS_REPORT ever received: the Stage-1 rule exactly
            self._residual_rule(frame.pos_residual_m, bump, evidence)
        else:
            # Estimator-aware rule (v2). ``pos_residual_nav_m`` equals ``pos_residual_m`` exactly
            # while the window holds no gated or transition fix, and ``pos_step_max_m`` is then 0,
            # so a link whose estimator never holds "no solution" for 2 s gets the Stage-1 rule.
            signals["pos_residual_nav_m"] = frame.pos_residual_nav_m
            step = frame.pos_step_max_m
            signals["pos_step_max_m"] = step
            if step >= self.pos_resid_hard:
                # one unclamped residual increment |dp - v*dt| >= hard at a gated or transition fix (a
                # step the velocity does not account for; elsewhere it is clamped / left out)
                bump(AttackType.GPS_SPOOFING, 1.0, hard_hit=True)
                evidence.append(
                    f"position discontinuity {step:.1f} m in one fix ≥ hard {self.pos_resid_hard:.0f} m "
                    "(at or leaving an estimator state without a horizontal solution)"
                )
            if frame.nav_gated:
                # The estimator reports no horizontal solution, so the position-vs-velocity residual
                # is not used. What is still checked: velocity-implied movement that the reported
                # position does not show (a frozen position, or one moving against the velocity).
                # It is bounded by |sum v*dt|, so wander with a pinned (~0) velocity cannot trigger it.
                sf = frame.pos_vel_shortfall_gated_m
                signals["pos_vel_shortfall_gated_m"] = sf
                if sf >= self.pos_resid_hard:
                    bump(AttackType.GPS_SPOOFING, 1.0, hard_hit=True)
                    evidence.append(
                        "estimator reports no horizontal solution but its velocity implies "
                        f"{sf:.1f} m of movement the position does not show "
                        f"≥ hard {self.pos_resid_hard:.0f} m"
                    )
                elif sf > self.pos_resid:
                    s = ramp(sf, self.pos_resid, self.pos_resid_hard)
                    bump(AttackType.GPS_SPOOFING, max(0.55, s))
                    evidence.append(
                        "estimator reports no horizontal solution but its velocity implies "
                        f"{sf:.1f} m of movement the position does not show > {self.pos_resid:.0f} m"
                    )
                flags = f"{frame.ekf_flags:#06x}" if frame.ekf_flags is not None else "unknown"
                nav_note = (
                    "navigation: estimator reports no horizontal position solution "
                    f"(EKF_STATUS_REPORT flags {flags}); position-vs-velocity residual "
                    f"{frame.pos_residual_m:.1f} m not used as spoofing evidence "
                    "(degraded navigation, not attack evidence)"
                )
            else:
                self._residual_rule(frame.pos_residual_nav_m, bump, evidence)

        # ---- 2D Page-Hinkley / CUSUM micro-drift (< 0.3 m/s) ----
        cusum_val = max(frame.cusum_drift_m, self.cusum.magnitude_m)
        signals["cusum_drift_m"] = cusum_val
        if (self.cusum_enabled or self.cusum.triggered) and cusum_val >= self.cusum_threshold_m:
            s = ramp(cusum_val, self.cusum_threshold_m, self.cusum_threshold_m * 3.0)
            bump(AttackType.GPS_SPOOFING, max(0.65, s), hard_hit=True)
            evidence.append(
                f"CUSUM micro-drift residual {cusum_val:.2f} m ≥ {self.cusum_threshold_m:.1f} m "
                "(sustained sub-noise velocity divergence)"
            )

        # ---- GPS altitude vs baro (telemetry manipulation / spoofing) ----
        ad = frame.gps_baro_alt_diff_m
        signals["gps_baro_alt_diff_m"] = ad
        if ad > self.alt_cons:
            s = ramp(ad, self.alt_cons, self.alt_cons * 3)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.55, s))
            evidence.append(f"GPS/baro altitude mismatch {ad:.1f} m > {self.alt_cons:.0f} m")

        # ---- GPS speed vs VFR groundspeed (telemetry manipulation) ----
        sd = frame.gps_vfr_speed_diff_ms
        signals["gps_vfr_speed_diff_ms"] = sd
        # Gated on position presence (P1 follow-up, "Coverage, not attack"): if GLOBAL_POSITION_INT
        # was NEVER received there is no GPS velocity, so ``sd`` is just the VFR groundspeed and a
        # moving vehicle would turn the missing stream into TELEMETRY_MANIPULATION evidence.
        # ``gps_seen`` None (hand-built frames) / True (extractor, Stage-1 SIM) behave as before.
        # Only this rule is gated: the feature is unchanged (ML_FEATURES is frozen) and the ML
        # detector still sees it. A stale GPS velocity after a loss is still compared (pre-existing).
        if frame.gps_seen is not False and sd > self.speed_cons:
            s = ramp(sd, self.speed_cons, self.speed_cons * 3)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.5, s))
            evidence.append(f"GPS/VFR speed mismatch {sd:.1f} m/s > {self.speed_cons:.0f} m/s")

        # ---- altitude rate plausibility ----
        if abs(frame.alt_rate_ms) > self.alt_jump:
            s = ramp(abs(frame.alt_rate_ms), self.alt_jump, self.alt_jump * 2)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.5, s))
            evidence.append(f"implausible altitude rate {frame.alt_rate_ms:.1f} m/s")

        # ---- acceleration / jerk plausibility ----
        if frame.accel_ms2 > self.max_accel:
            s = ramp(frame.accel_ms2, self.max_accel, self.max_accel * 2)
            bump(AttackType.GPS_SPOOFING, max(0.5, s))
            evidence.append(f"implausible acceleration {frame.accel_ms2:.1f} m/s²")

        # ---- battery dynamics (telemetry manipulation) ----
        if frame.battery_v_rise > self.batt_rise:
            s = ramp(frame.battery_v_rise, self.batt_rise, self.batt_rise * 4)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.5, s))
            evidence.append(f"battery voltage rose {frame.battery_v_rise:.2f} V (implausible)")
        elif -frame.battery_v_rate > self.batt_drop:
            s = ramp(-frame.battery_v_rate, self.batt_drop, self.batt_drop * 3)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.5, s))
            evidence.append(f"battery collapse {-frame.battery_v_rate:.2f} V/s")
        signals["battery_v_rate"] = frame.battery_v_rate

        # ---- heading (attitude) vs course-over-ground (frozen attitude) ----
        yc = frame.yaw_course_diff_deg
        signals["yaw_course_diff_deg"] = yc
        if yc > self.yaw_course_deg:
            s = ramp(yc, self.yaw_course_deg, 90.0)
            bump(AttackType.TELEMETRY_MANIPULATION, max(0.5, s))
            evidence.append(f"heading/course mismatch {yc:.0f}° (attitude inconsistent with track)")

        # ---- hysteresis on soft (non-hard) triggers ----
        if score > 0.0:
            self._soft_streak += 1
        else:
            self._soft_streak = 0
        if not hard and self._soft_streak < self.hysteresis_ticks:
            score *= 0.35  # damp until the anomaly persists
        if nav_note is not None and score == 0.0:
            # diagnostic only when physics found nothing in this frame, so it never sits among scored
            # physics evidence (fusion then lists it after the other detectors' evidence)
            evidence.append(nav_note)

        return DetectorResult(
            detector=self.name,
            score=score,
            triggered=score >= 0.5,
            evidence=evidence,
            attack_votes=votes,
            signals=signals,
        )

    def _residual_rule(self, pr: float, bump: Callable[..., None], evidence: list[str]) -> None:
        """The Stage-1 position-residual thresholds (soft / hard), unchanged."""
        if pr >= self.pos_resid_hard:
            bump(AttackType.GPS_SPOOFING, 1.0, hard_hit=True)
            evidence.append(f"position residual {pr:.1f} m ≥ hard {self.pos_resid_hard:.0f} m")
        elif pr > self.pos_resid:
            s = ramp(pr, self.pos_resid, self.pos_resid_hard)
            bump(AttackType.GPS_SPOOFING, max(0.55, s))
            evidence.append(
                f"position residual {pr:.1f} m > {self.pos_resid:.0f} m "
                "(reported track diverges from velocity)"
            )

    def reset(self) -> None:
        self._soft_streak = 0
        self.cusum.reset()
