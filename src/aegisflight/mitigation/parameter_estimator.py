"""Closed-form quantitative attack parameter estimator."""

from __future__ import annotations

import math
import re
from typing import Any

from ..core.enums import AttackType
from ..core.geo import EARTH_RADIUS_M
from ..features.extractor import FeatureFrame
from .golden_state import GoldenFlightState
from .types import AttackParameters, AttackSubMode


class ParameterEstimator:
    """Estimates exact quantitative parameters of an identified attack."""

    def __init__(
        self,
        expected_sysids: tuple[int, ...] = (1, 3),
        expected_gcs_sysids: tuple[int, ...] = (253, 254, 255),
    ) -> None:
        self.expected_sysids = set(expected_sysids)
        self.expected_gcs_sysids = set(expected_gcs_sysids)
        self.allowed_sysids = set(self.expected_sysids | self.expected_gcs_sysids)

    def reset(self) -> None:
        self.allowed_sysids = set(self.expected_sysids | self.expected_gcs_sysids)

    def estimate(
        self,
        frame: FeatureFrame,
        golden: GoldenFlightState,
        sub_mode: AttackSubMode,
        asmt: Any = None,
    ) -> AttackParameters:
        snap = frame.snapshot
        atk_type = AttackType.BENIGN
        if sub_mode.startswith("gps_spoofing"):
            atk_type = AttackType.GPS_SPOOFING
        elif sub_mode.startswith("mavlink_anomaly"):
            atk_type = AttackType.MAVLINK_ANOMALY
        elif sub_mode.startswith("command_injection"):
            atk_type = AttackType.COMMAND_INJECTION
        elif sub_mode.startswith("telemetry_manipulation"):
            atk_type = AttackType.TELEMETRY_MANIPULATION
        elif sub_mode.startswith("dos"):
            atk_type = AttackType.DOS
        elif sub_mode.startswith("firmware_integrity"):
            atk_type = AttackType.FIRMWARE_INTEGRITY

        # 1. Kinematic coordinate displacement
        lat_off = 0.0
        lon_off = 0.0
        north_m = 0.0
        east_m = 0.0
        if (
            snap.lat is not None
            and snap.lon is not None
            and golden.dr_lat is not None
            and golden.dr_lon is not None
        ):
            lat_off = snap.lat - golden.dr_lat
            lon_off = snap.lon - golden.dr_lon
            north_m = math.radians(lat_off) * EARTH_RADIUS_M
            east_m = math.radians(lon_off) * EARTH_RADIUS_M * math.cos(math.radians(golden.dr_lat))

        # 2. Drift velocity estimate (combines 3s residual window and 12s CUSUM micro-drift horizon)
        drift_rate = 0.0
        if sub_mode == AttackSubMode.GPS_GRADUAL_DRIFT:
            r3 = frame.pos_residual_m / 3.0 if frame.pos_residual_m > 0 else 0.0
            rcusum = getattr(frame, "cusum_drift_m", 0.0) / 10.0
            drift_rate = max(r3, rcusum)
        elif sub_mode == AttackSubMode.GPS_SUDDEN_OFFSET:
            drift_rate = math.hypot(north_m, east_m)

        # 3. Altitude bias (GPS vs Barometer or Golden Anchor)
        alt_bias = 0.0
        if snap.alt_msl is not None and snap.baro_alt is not None:
            alt_bias = snap.alt_msl - snap.baro_alt
        elif frame.gps_baro_alt_diff_m > 0:
            alt_bias = frame.gps_baro_alt_diff_m
        elif golden.trusted_alt_m is not None and snap.alt_msl is not None:
            alt_bias = snap.alt_msl - golden.trusted_alt_m

        # 4. Rogue sysids
        rogues = set()
        for s, _c in frame.sources:
            if s not in self.allowed_sysids:
                rogues.add(s)
        for cmd in frame.commands_recent:
            if cmd.sysid not in self.allowed_sysids:
                rogues.add(cmd.sysid)
        if asmt is not None:
            for ev in getattr(asmt, "evidence", ()):
                for m in re.finditer(r"sys(?:id)?\s*[:=]?\s*(\d+)", ev, re.IGNORECASE):
                    sid = int(m.group(1))
                    if sid not in self.allowed_sysids:
                        rogues.add(sid)

        # 5. Target restore mode
        target_mode = None
        if golden.trusted_mode is not None and (
            snap.flight_mode != golden.trusted_mode or sub_mode == AttackSubMode.CMD_MODE_FLIP
        ):
            target_mode = golden.trusted_mode

        ref_lat = (
            golden.effective_lat
            if golden.effective_lat is not None
            else (golden.dr_lat if golden.dr_lat is not None else golden.trusted_lat)
        )
        ref_lon = (
            golden.effective_lon
            if golden.effective_lon is not None
            else (golden.dr_lon if golden.dr_lon is not None else golden.trusted_lon)
        )

        return AttackParameters(
            attack_type=atk_type,
            sub_mode=sub_mode,
            trusted_lat=ref_lat,
            trusted_lon=ref_lon,
            trusted_alt_m=golden.trusted_alt_m,
            trusted_mode=golden.trusted_mode,
            lat_offset_deg=lat_off,
            lon_offset_deg=lon_off,
            north_offset_m=north_m,
            east_offset_m=east_m,
            drift_rate_ms=drift_rate,
            alt_bias_m=alt_bias,
            speed_bias_ms=frame.gps_vfr_speed_diff_ms,
            battery_bias_v=frame.battery_v_rise,
            rogue_sysids=tuple(sorted(rogues)),
            target_restore_mode=target_mode,
        )
