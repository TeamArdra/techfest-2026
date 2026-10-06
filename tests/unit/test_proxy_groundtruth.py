"""Unit tests for ``aegisflight.proxy.groundtruth`` -- schema, round-trip, red/blue
holdout rule, and ``compute_actual_effect``. No sockets, no PX4."""

from __future__ import annotations

import json
import math

import pytest

from aegisflight.core.geo import EARTH_RADIUS_M
from aegisflight.proxy.groundtruth import (
    REQUIRED_PROVENANCE_KEYS,
    FrameLogEntry,
    FrameLogWriter,
    Manifest,
    compute_actual_effect,
    is_holdout,
    read_frame_log,
    read_manifest,
    write_manifest,
)

GOOD_PROVENANCE = {
    "px4_git_describe": "v1.18.0-rc1-27-gc239c63807",
    "aegisflight_git_commit": "deadbeef",
    "python_version": "3.13.15",
    "pymavlink_version": "2.4.50",
}


def _manifest(**overrides) -> Manifest:
    fields = {
        "trial_id": "gps_mod_gradual_drift_t03",
        "seed": 20261006,
        "trial_index": 3,
        "provenance": GOOD_PROVENANCE,
        "attack_type": "gps_spoofing",
        "attack_mode": "gradual_drift",
        "message_type": "GLOBAL_POSITION_INT",
        "target_system": 3,
        "target_component": 1,
        "injection_point": "downlink",
        "claim_class": "link_level_detection",
        "environment": "SITL",
        "attack_action": "modify_fields",
        "parameters": {
            "drift_rate_ms": 6.4, "bearing_deg": 118.2, "onset_s": 37.1, "duration_s": 28.9,
        },
        "attack_start_utc": "2026-10-06T14:30:37.100000Z",
        "attack_end_utc": "2026-10-06T14:31:06.000000Z",
        "frames_seen": 1584,
        "frames_modified": 1296,
        "frames_dropped": 0,
        "frames_injected": 0,
        "expected_effect": {
            "feature": "pos_residual_m", "predicted_threshold_cross_s_after_onset": 1.9,
        },
    }
    fields.update(overrides)
    return Manifest(**fields)


# --------------------------------------------------------------------------- #
# Manifest schema / validation
# --------------------------------------------------------------------------- #


def test_manifest_detector_fields_always_null_and_not_settable():
    m = _manifest()
    assert m.detector_decision is None
    assert m.time_to_detection_s is None
    # not a constructor parameter at all -- passing it is a TypeError, not silently accepted
    with pytest.raises(TypeError):
        Manifest(**{**vars(m), "detector_decision": "attack"})  # type: ignore[arg-type]


def test_manifest_schema_id_and_version_are_fixed():
    m = _manifest()
    assert m.schema_id == "aegisflight.proxy.groundtruth"
    assert m.schema_version == "1.0.0"
    with pytest.raises(TypeError):
        Manifest(**{**_manifest().__dict__, "schema_id": "other"})


def test_manifest_rejects_missing_provenance_keys():
    for missing in REQUIRED_PROVENANCE_KEYS:
        bad = {k: v for k, v in GOOD_PROVENANCE.items() if k != missing}
        with pytest.raises(ValueError):
            _manifest(provenance=bad)


def test_manifest_accepts_extra_provenance_keys():
    extra = {**GOOD_PROVENANCE, "gazebo_version": "8.15.0"}
    m = _manifest(provenance=extra)
    assert m.provenance["gazebo_version"] == "8.15.0"


def test_manifest_rejects_bad_injection_point():
    with pytest.raises(ValueError):
        _manifest(injection_point="sideways")


def test_manifest_holdout_default_empty_and_settable():
    m = _manifest()
    assert m.holdout_seeds == ()
    m2 = _manifest(holdout_seeds=(1, 2, 3))
    assert m2.holdout_seeds == (1, 2, 3)


# --------------------------------------------------------------------------- #
# manifest round-trip
# --------------------------------------------------------------------------- #


def test_manifest_round_trip(tmp_path):
    m = _manifest(holdout_seeds=(1, 2), actual_effect={"max_lat_lon_delta_m": 184.3})
    path = tmp_path / "manifest.json"
    write_manifest(m, path)
    loaded = read_manifest(path)
    assert loaded == m
    assert loaded.detector_decision is None and loaded.time_to_detection_s is None


def test_manifest_written_json_is_iso8601_and_matches_schema_fields(tmp_path):
    m = _manifest()
    path = tmp_path / "manifest.json"
    write_manifest(m, path)
    data = json.loads(path.read_text())
    assert data["schema_id"] == "aegisflight.proxy.groundtruth"
    assert data["schema_version"] == "1.0.0"
    assert data["environment"] == "SITL"
    assert data["claim_class"] == "link_level_detection"
    assert data["detector_decision"] is None and data["time_to_detection_s"] is None
    assert data["attack_start_utc"].endswith("Z")
    assert data["attack_end_utc"].endswith("Z")
    # every documented §4 field is present
    for key in (
        "trial_id", "seed", "trial_index", "attack_type", "attack_mode", "message_type",
        "target_system", "target_component", "injection_point", "claim_class", "environment",
        "attack_action", "parameters", "attack_start_utc", "attack_end_utc", "frames_seen",
        "frames_modified", "frames_dropped", "frames_injected", "expected_effect",
        "actual_effect", "detector_decision", "time_to_detection_s",
    ):
        assert key in data, key


def test_manifest_write_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "trial" / "manifest.json"
    write_manifest(_manifest(), path)
    assert path.exists()


# --------------------------------------------------------------------------- #
# holdout rule
# --------------------------------------------------------------------------- #


def test_is_holdout():
    assert is_holdout(5, [1, 5, 9])
    assert not is_holdout(5, [1, 9])
    assert not is_holdout(5, [])


# --------------------------------------------------------------------------- #
# frame log: schema, append-only, round-trip
# --------------------------------------------------------------------------- #


def _entry(**overrides) -> FrameLogEntry:
    fields = {
        "seq_no": 211,
        "proxy_recv_time_utc": "2026-10-06T14:30:38.041223Z",
        "recv_ns": 38_041_223_000,
        "msgid": 33,
        "sysid": 3,
        "compid": 1,
        "mavlink_seq": 57,
        "action": "modified",
        "field_deltas": {"lat_1e7deg": 1823, "lon_1e7deg": -940},
        "crc_recomputed": True,
        "original_len": 40,
        "modified_len": 40,
    }
    fields.update(overrides)
    return FrameLogEntry(**fields)


def test_frame_log_entry_rejects_invalid_action():
    with pytest.raises(ValueError):
        _entry(action="teleported")


def test_frame_log_round_trip(tmp_path):
    path = tmp_path / "frames.jsonl"
    entries = [_entry(seq_no=i) for i in range(5)]
    with FrameLogWriter(path) as w:
        for e in entries:
            w.append(e)
    loaded = read_frame_log(path)
    assert loaded == entries


def test_frame_log_is_append_only_and_flushed(tmp_path):
    path = tmp_path / "frames.jsonl"
    w = FrameLogWriter(path)
    w.append(_entry(seq_no=1))
    # flushed immediately -- readable before close()
    assert len(read_frame_log(path)) == 1
    w.append(_entry(seq_no=2))
    assert len(read_frame_log(path)) == 2
    w.close()
    # re-opening the writer for the same path appends, does not truncate
    with FrameLogWriter(path) as w2:
        w2.append(_entry(seq_no=3))
    assert [e.seq_no for e in read_frame_log(path)] == [1, 2, 3]


def test_frame_log_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "frames.jsonl"
    with FrameLogWriter(path) as w:
        w.append(_entry())
    assert path.exists()


def test_frame_log_one_line_per_entry_is_valid_json(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as w:
        w.append(_entry(seq_no=1))
        w.append(_entry(seq_no=2))
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # does not raise


# --------------------------------------------------------------------------- #
# compute_actual_effect
# --------------------------------------------------------------------------- #


def test_compute_actual_effect_matches_applied_displacement(tmp_path):
    ref_lat_deg = 47.3977418
    lat_rad = math.radians(ref_lat_deg)
    path = tmp_path / "frames.jsonl"
    # three monotonically growing modified frames (gradual drift), plus one
    # 'forwarded' frame that must be excluded from the measurement
    deltas_sequence = [
        {"lat_1e7deg": 100, "lon_1e7deg": 0},
        {"lat_1e7deg": 500, "lon_1e7deg": 0},
        {"lat_1e7deg": 1823, "lon_1e7deg": -940},
    ]
    with FrameLogWriter(path) as w:
        w.append(_entry(seq_no=0, action="forwarded", field_deltas={}, crc_recomputed=False))
        for i, d in enumerate(deltas_sequence):
            w.append(_entry(seq_no=i + 1, field_deltas=d))

    result = compute_actual_effect(path, ref_lat_deg=ref_lat_deg)
    assert result["frames_counted"] == 3

    # independent re-derivation (mirrors what the module does, but written
    # separately here so a bug in the module's own formula would be caught)
    expected_mags = []
    for d in deltas_sequence:
        north_m = math.radians(d["lat_1e7deg"] / 1e7) * EARTH_RADIUS_M
        east_m = math.radians(d["lon_1e7deg"] / 1e7) * EARTH_RADIUS_M * math.cos(lat_rad)
        expected_mags.append(math.hypot(north_m, east_m))

    assert result["max_lat_lon_delta_m"] == pytest.approx(max(expected_mags), rel=1e-9)
    assert result["mean_lat_lon_delta_m"] == pytest.approx(
        sum(expected_mags) / len(expected_mags), rel=1e-9
    )
    assert result["position_residual_proxy_estimate_m"] == result["mean_lat_lon_delta_m"]
    # the max is the last (largest) frame for a monotonic gradual drift
    assert result["max_lat_lon_delta_m"] == pytest.approx(expected_mags[-1], rel=1e-9)


def test_compute_actual_effect_empty_log_is_zero(tmp_path):
    path = tmp_path / "frames.jsonl"
    with FrameLogWriter(path) as w:
        w.append(_entry(action="forwarded", field_deltas={}, crc_recomputed=False))
    result = compute_actual_effect(path, ref_lat_deg=47.0)
    assert result == {
        "max_lat_lon_delta_m": 0.0,
        "mean_lat_lon_delta_m": 0.0,
        "position_residual_proxy_estimate_m": 0.0,
        "frames_counted": 0,
    }


def test_compute_actual_effect_ref_lat_matters():
    # same lon delta, different ref latitudes -> different metre figures
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "frames.jsonl"
        with FrameLogWriter(path) as w:
            w.append(_entry(field_deltas={"lat_1e7deg": 0, "lon_1e7deg": 1000}))
        at_equator = compute_actual_effect(path, ref_lat_deg=0.0)
        at_pole_ish = compute_actual_effect(path, ref_lat_deg=80.0)
        assert at_equator["max_lat_lon_delta_m"] > at_pole_ish["max_lat_lon_delta_m"]
