"""Golden flight state tracker and non-GPS dead-reckoning propagator."""

from __future__ import annotations

import math

from ..core.enums import AttackType, Severity
from ..core.geo import offset_latlon
from ..core.types import TelemetrySnapshot, ThreatAssessment


class GoldenFlightState:
    """Maintains trusted vehicle reference state and non-GPS dead reckoning."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.anchor_t: float | None = None
        self.trusted_lat: float | None = None
        self.trusted_lon: float | None = None
        self.trusted_alt_m: float | None = None
        self.trusted_rel_alt_m: float | None = None
        self.trusted_mode: str | None = None
        self.trusted_armed: bool | None = None
        self.trusted_battery_v: float | None = None
        self.vx_ms: float = 0.0
        self.vy_ms: float = 0.0
        self.trusted_speed_ms: float = 0.0
        self.trusted_heading_deg: float = 0.0

        # Dead-reckoning position estimate (updated even during GPS attacks)
        self.dr_lat: float | None = None
        self.dr_lon: float | None = None
        self.last_dr_t: float | None = None

        # Effective vehicle position (follows spoofed GPS in PASSIVE, converges to DR in ACTIVE_IPS)
        self.effective_lat: float | None = None
        self.effective_lon: float | None = None

    @property
    def has_anchor(self) -> bool:
        return self.trusted_lat is not None and self.trusted_lon is not None

    def update(
        self,
        snap: TelemetrySnapshot,
        asmt: ThreatAssessment,
        *,
        active_ips: bool = False,
        pos_residual_m: float = 0.0,
    ) -> None:
        """Update golden anchor on clean ticks; propagate dead-reckoning under attack."""
        is_clean = (
            not asmt.threat
            and asmt.severity == Severity.NORMAL
            and pos_residual_m < 8.0
        )

        if is_clean:
            if snap.lat is not None and snap.lon is not None:
                self.trusted_lat = snap.lat
                self.trusted_lon = snap.lon
                self.dr_lat = snap.lat
                self.dr_lon = snap.lon
                if self.effective_lat is not None and self.effective_lon is not None:
                    # Smoothly converge if recovering from a previous passive drift
                    dist_deg = math.hypot(snap.lat - self.effective_lat, snap.lon - self.effective_lon)
                    if dist_deg > 0.00015:
                        self.effective_lat += 0.35 * (snap.lat - self.effective_lat)
                        self.effective_lon += 0.35 * (snap.lon - self.effective_lon)
                    else:
                        self.effective_lat = snap.lat
                        self.effective_lon = snap.lon
                else:
                    self.effective_lat = snap.lat
                    self.effective_lon = snap.lon

            if snap.alt_msl is not None:
                self.trusted_alt_m = snap.alt_msl
            elif snap.baro_alt is not None:
                self.trusted_alt_m = snap.baro_alt
            if snap.rel_alt is not None:
                self.trusted_rel_alt_m = snap.rel_alt
            elif self.trusted_alt_m is not None:
                self.trusted_rel_alt_m = self.trusted_alt_m

            if snap.flight_mode is not None:
                self.trusted_mode = snap.flight_mode

            if snap.armed is not None:
                self.trusted_armed = snap.armed

            if snap.battery_voltage is not None:
                self.trusted_battery_v = snap.battery_voltage

            self.vx_ms = snap.vx or 0.0
            self.vy_ms = snap.vy or 0.0
            self.trusted_speed_ms = (
                snap.groundspeed
                if snap.groundspeed is not None
                else math.hypot(self.vx_ms, self.vy_ms)
            )
            if snap.heading is not None:
                self.trusted_heading_deg = float(snap.heading)
            elif snap.yaw is not None:
                self.trusted_heading_deg = (
                    float(snap.yaw)
                    if abs(snap.yaw) > 2.0 * math.pi
                    else math.degrees(snap.yaw)
                )

            self.anchor_t = snap.t
            self.last_dr_t = snap.t
            return

        # Under attack or elevated threat:
        # If the attack is NOT GPS spoofing and GPS position residual is nominal,
        # anchor dead-reckoning to clean truthful GPS fixes so non-GPS attacks don't drift.
        is_gps_attack = asmt.attack_type == AttackType.GPS_SPOOFING or pos_residual_m >= 8.0
        if not is_gps_attack and snap.lat is not None and snap.lon is not None:
            self.dr_lat = snap.lat
            self.dr_lon = snap.lon
            self.last_dr_t = snap.t

        vn = 0.0
        ve = 0.0
        dt = 0.0
        if self.dr_lat is not None and self.dr_lon is not None and self.last_dr_t is not None:
            dt = max(0.0, min(snap.t - self.last_dr_t, 2.0))
            if dt > 1e-4:
                # Isolate corrupted speed and yaw from dead-reckoning during telemetry anomalies
                speed_corrupted = any("speed" in str(e).lower() for e in asmt.evidence)
                if speed_corrupted or snap.groundspeed is None:
                    speed = self.trusted_speed_ms
                else:
                    speed = snap.groundspeed

                yaw_corrupted = any(
                    "yaw" in str(e).lower() or "attitude" in str(e).lower() or "frozen" in str(e).lower()
                    for e in asmt.evidence
                )
                if yaw_corrupted:
                    heading_rad = math.radians(self.trusted_heading_deg)
                elif snap.heading is not None:
                    heading_rad = math.radians(snap.heading)
                elif snap.yaw is not None:
                    heading_rad = math.radians(snap.yaw) if abs(snap.yaw) > 2.0 * math.pi else snap.yaw
                else:
                    heading_rad = math.radians(self.trusted_heading_deg)

                head_vn = speed * math.cos(heading_rad)
                head_ve = speed * math.sin(heading_rad)
                v_mag = math.hypot(snap.vx or 0.0, snap.vy or 0.0)
                if (
                    not speed_corrupted
                    and snap.vx is not None
                    and snap.vy is not None
                    and v_mag > 0.5
                    and speed > 0.5
                    and abs(v_mag - speed) <= 2.5
                    and (snap.vx * head_vn + snap.vy * head_ve) >= 0.90 * v_mag * speed
                ):
                    vn = snap.vx
                    ve = snap.vy
                else:
                    vn = head_vn
                    ve = head_ve
                self.dr_lat, self.dr_lon = offset_latlon(self.dr_lat, self.dr_lon, vn * dt, ve * dt)
                self.last_dr_t = snap.t

        # Update effective vehicle trajectory based on whether ACTIVE_IPS is engaged
        if active_ips and self.dr_lat is not None and self.dr_lon is not None:
            if self.effective_lat is None or self.effective_lon is None:
                self.effective_lat = self.dr_lat
                self.effective_lon = self.dr_lon
            else:
                if dt > 1e-4:
                    self.effective_lat, self.effective_lon = offset_latlon(
                        self.effective_lat, self.effective_lon, vn * dt, ve * dt
                    )
                # Smooth kinematic return toward dead-reckoned nominal path
                alpha = 0.32
                self.effective_lat += alpha * (self.dr_lat - self.effective_lat)
                self.effective_lon += alpha * (self.dr_lon - self.effective_lon)
        else:
            # Unprotected (PASSIVE / ADVISORY): vehicle follows corrupted GPS coordinates
            if snap.lat is not None and snap.lon is not None:
                self.effective_lat = snap.lat
                self.effective_lon = snap.lon
