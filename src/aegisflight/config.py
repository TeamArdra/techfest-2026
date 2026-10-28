"""Configuration loading for AegisFlight.

All tunables live in YAML under ``configs/`` so that thresholds are never
scattered as magic numbers through the source. This module provides typed
dataclasses and a small loader with sensible built-in defaults, so the library
works even if the YAML files are absent (useful for tests and pip-installs).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Repository layout: this file is src/aegisflight/config.py
PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parents[1]
CONFIG_DIR = REPO_ROOT / "configs"


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config {path} must be a mapping at top level")
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


# --------------------------------------------------------------------------- #
# Built-in defaults (kept in one place, documented, overridable via YAML).
# --------------------------------------------------------------------------- #

DEFAULT_SIMULATION: dict[str, Any] = {
    "seed": 42,
    "sample_rate_hz": 10.0,
    "duration_s": 120.0,
    "home": {"lat": 19.1334, "lon": 72.9133, "alt_msl": 12.0},  # IIT Bombay-ish
    "cruise_alt_m": 60.0,
    "cruise_speed_ms": 12.0,
    "route": "survey_box",  # survey_box | out_and_back | perimeter
    "battery_capacity_v": 25.2,  # 6S nominal
    "noise": {
        "gps_pos_m": 0.6,  # 1-sigma horizontal GPS noise (metres)
        "gps_alt_m": 1.2,
        "vel_ms": 0.15,
        "attitude_rad": 0.01,
        "baro_m": 0.8,
        "hdop": 0.05,
    },
}

DEFAULT_MESSAGE_RATES: dict[str, int] = {
    # decimation: emit message every N simulator ticks (10 Hz base -> rates below)
    "HEARTBEAT": 10,  # 1 Hz
    "GLOBAL_POSITION_INT": 2,  # 5 Hz
    "ATTITUDE": 1,  # 10 Hz
    "VFR_HUD": 2,  # 5 Hz
    "SYS_STATUS": 5,  # 2 Hz
    "GPS_RAW_INT": 2,  # 5 Hz
}

DEFAULT_DETECTOR: dict[str, Any] = {
    "decision_rate_hz": 5.0,  # run fusion at this cadence
    "protocol": {
        "expected_sysids": [1],
        "expected_gcs_sysids": [255, 254],
        "autopilot_compid": 1,
        "gcs_compids": [190, 191, 200],
        "heartbeat_timeout_s": 3.0,
        "max_msg_rate_hz": 400.0,  # aggregate; above this => flood
        "nominal_msg_rate_hz": 28.0,  # expected steady-state aggregate
        "msg_rate_spike_factor": 3.0,  # rate > factor*nominal => suspicious
        "max_seq_gap": 30,  # sequence jump over window => loss/DoS
        "min_interarrival_ms": 0.4,  # bursts faster than this are abnormal
        "gps_dropout_s": 2.0,  # no GPS for this long => stale/DoS
        "allowed_commands_in_flight": [
            "MAV_CMD_NAV_WAYPOINT",
            "MAV_CMD_DO_SET_MODE",
            "MAV_CMD_NAV_LOITER_UNLIM",
            "MAV_CMD_DO_CHANGE_SPEED",
            "MAV_CMD_NAV_RETURN_TO_LAUNCH",
        ],
        "sensitive_commands": [
            "MAV_CMD_COMPONENT_ARM_DISARM",
            "MAV_CMD_DO_FLIGHTTERMINATION",
            "MAV_CMD_NAV_LAND",
            "MAV_CMD_DO_SET_HOME",
        ],
        "command_burst_window_s": 2.0,
        "command_burst_max": 4,
        "require_signing": False,  # if True, unsigned msgs are flagged
        "min_gnss_fix_type": 3,  # GPS_RAW_INT fix_type below this = no 3D fix
        "min_gnss_satellites": 5,
        "gnss_loss_ticks": 5,  # consecutive decisions before the fix-loss rule fires
    },
    "physics": {
        "gps_pos_residual_m": 12.0,  # predicted vs reported position gap
        "gps_pos_residual_hard_m": 30.0,
        "gps_speed_consistency_ms": 5.0,  # |gps-derived speed - VFR speed|
        "alt_consistency_m": 8.0,  # |GPS alt - baro alt| (after bias)
        "alt_jump_ms": 25.0,  # altitude derivative implausible
        "max_accel_ms2": 20.0,  # implausible acceleration
        "max_jerk_ms3": 60.0,
        "battery_rise_v": 0.4,  # voltage should not jump up
        "battery_drop_rate_v_s": 2.0,  # nor drop absurdly fast
        "attitude_rate_consistency": 1.2,  # rad/s mismatch tolerance
        "hysteresis_ticks": 2,  # consecutive ticks before firing
        "ekf_var_warn": 0.5,  # uncalibrated engineering defaults (docs/DETECTION.md)
        "ekf_var_reject": 1.0,
        "sat_jump_min": 6,
        "snr_spread_min_db": 1.5,
        "snr_min_sats": 8,
        "gps_ekf_vel_disagree_ms": 3.0,
    },
    "anomaly": {
        "model_path": "models/isoforest.joblib",
        "score_threshold": 0.62,  # normalised anomaly score => triggered
        "contamination": 0.02,
        "n_estimators": 200,
        "warmup_ticks": 20,  # need this many samples before scoring
    },
    "fusion": {
        "weights": {
            "protocol_rule": 0.30,
            "physics_consistency": 0.34,
            "ml_anomaly": 0.16,
            "firmware_integrity": 0.20,
        },
        "threat_threshold": 0.45,  # threat_score above this => threat
        "severity_bands": {  # lower-bound threat_score for each severity
            "WATCH": 0.30,
            "SUSPICIOUS": 0.45,
            "HIGH": 0.62,
            "CRITICAL": 0.80,
        },
        "alert_threshold_severity": "SUSPICIOUS",
        "cooldown_s": 4.0,  # suppress duplicate alerts of same type within
        "clear_ticks": 4,  # consecutive normal ticks before clearing state
    },
}

DEFAULT_ATTACKS: dict[str, Any] = {
    "gps_spoofing": {
        "mode": "gradual_drift",  # sudden_offset | gradual_drift | replay_freeze
        "start_s": 40.0,
        "duration_s": 30.0,
        "offset_m": 120.0,  # for sudden_offset (metres, NE bearing)
        "bearing_deg": 90.0,
        "drift_rate_ms": 6.0,  # for gradual_drift (metres/sec injected)
    },
    "mavlink_anomaly": {
        "mode": "rogue_sysid",  # rogue_sysid | rate_spike | seq_scramble | packet_loss
        "start_s": 40.0,
        "duration_s": 30.0,
        "rogue_sysid": 42,
        "rogue_compid": 1,
        "rate_multiplier": 5.0,
        "loss_prob": 0.5,
    },
    "command_injection": {
        "mode": "rogue_command",  # rogue_command | mode_flip | arm_disarm_burst
        "start_s": 45.0,
        "duration_s": 20.0,
        "source_sysid": 66,
        "source_compid": 200,
        "command": "MAV_CMD_COMPONENT_ARM_DISARM",
        "burst": 6,
    },
    "telemetry_manipulation": {
        "mode": "altitude_bias",  # altitude_bias | speed_mismatch | battery_jump | frozen_attitude
        "start_s": 40.0,
        "duration_s": 30.0,
        "altitude_bias_m": 35.0,
        "speed_bias_ms": 9.0,
        "battery_jump_pct": 30.0,
    },
    "dos": {
        "mode": "flood",  # flood | blackout | latency
        "start_s": 45.0,
        "duration_s": 20.0,
        "flood_multiplier": 12.0,
        "blackout_prob": 0.9,
        "latency_ms": 400.0,
    },
    "firmware_integrity": {
        "start_s": 30.0,
        "tamper_component": "ekf3_params.bin",
    },
}


@dataclass
class AegisConfig:
    """Aggregated, resolved configuration."""

    simulation: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULT_SIMULATION))
    message_rates: dict[str, int] = field(
        default_factory=lambda: copy.deepcopy(DEFAULT_MESSAGE_RATES)
    )
    detector: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULT_DETECTOR))
    attacks: dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULT_ATTACKS))

    @classmethod
    def load(cls, config_dir: Path | str | None = None) -> AegisConfig:
        """Load config from YAML, deep-merged over the built-in defaults."""
        cfg_dir = Path(config_dir) if config_dir else CONFIG_DIR
        sim = _deep_merge(DEFAULT_SIMULATION, _read_yaml(cfg_dir / "simulation.yaml"))
        det_yaml = _read_yaml(cfg_dir / "detector.yaml")
        det = _deep_merge(DEFAULT_DETECTOR, det_yaml)
        rates = _deep_merge(
            {"message_rates": DEFAULT_MESSAGE_RATES},
            {"message_rates": sim.get("message_rates", {})},
        )["message_rates"]
        atk = _deep_merge(DEFAULT_ATTACKS, _read_yaml(cfg_dir / "attacks.yaml"))
        return cls(simulation=sim, message_rates=rates, detector=det, attacks=atk)


def load_config(config_dir: Path | str | None = None) -> AegisConfig:
    return AegisConfig.load(config_dir)
