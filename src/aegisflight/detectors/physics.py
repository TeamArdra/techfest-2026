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

from ..core.enums import AttackType, DetectorName
from ..core.types import DetectorResult
from ..features.extractor import FeatureFrame
from .base import Detector, ramp


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
        pr = frame.pos_residual_m
        signals["pos_residual_m"] = pr
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
        if sd > self.speed_cons:
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

        return DetectorResult(
            detector=self.name,
            score=score,
            triggered=score >= 0.5,
            evidence=evidence,
            attack_votes=votes,
            signals=signals,
        )

    def reset(self) -> None:
        self._soft_streak = 0
