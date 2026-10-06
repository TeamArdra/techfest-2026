"""Shared helpers for the PX4 SITL calibration scripts (``scripts/sitl/calib_*.py``).

Environment: SITL (replayed tlog), attack NONE. Nothing here is attack detection.

Replays a recorded tlog through the UNCHANGED :class:`IDSPipeline` using the live
header-first parser path (``frame_ticks``) and returns one row per decision with
every ``FeatureFrame`` quantity the detectors read, the four detector scores, the
fused verdict, evidence strings and the pipeline's own ``latency_ms``.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))  # sibling script modules (tlog_stats)

from tlog_stats import iter_raw_frames  # noqa: E402

from aegisflight.config import AegisConfig, load_config  # noqa: E402
from aegisflight.features.extractor import ML_FEATURES  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import frame_ticks  # noqa: E402

CALIB_FLIGHTS = tuple(f"data/sitl/raw/benign_{i:03d}.tlog" for i in range(1, 6))
HELDOUT_FLIGHTS = tuple(f"data/sitl/raw/benign_{i:03d}.tlog" for i in range(6, 11))
PROFILE_DIR = "configs/px4_sitl"
STAGE1_MODEL = "models/isoforest.joblib"
PX4_MODEL = "models/isoforest_px4.joblib"
OUT_DIR = REPO / "artifacts" / "sitl" / "calibration"

# extra FeatureFrame quantities read by detectors but outside ML_FEATURES
EXTRA_FRAME_FIELDS = ("heartbeat_age_s", "gps_age_s", "battery_v_rise", "battery_v_rate",
                      "jerk_ms3", "n_sources", "interarrival_mean_ms", "signed_ratio")
# a detector "triggers" at these normalised scores (same constants the reference replay uses)
DET_TRIG = {"det_protocol_rule": 0.5, "det_physics_consistency": 0.5, "det_ml_anomaly": 0.62}


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else REPO / p


def load_raw_frames(tlog: str | Path) -> list[tuple[float, bytes]]:
    return [(ts, fb) for ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(resolve(tlog))]


def replay_rows(tlog: str | Path, cfg: AegisConfig, model_path: str | None,
                frames: list[tuple[float, bytes]] | None = None) -> list[dict]:
    """One dict per decision. ``model_path=None`` => ML detector is a no-op."""
    frames = frames if frames is not None else load_raw_frames(tlog)
    pipe = IDSPipeline(cfg, model_path=model_path, firmware_dir=None)
    rows: list[dict] = []
    for tick in frame_ticks(frames):
        a = pipe.process_tick(tick)
        if a is None:
            continue
        f = pipe.last_frame
        row: dict = {
            "t": a.t, "threat": bool(a.threat), "threat_score": a.threat_score,
            "pred": a.attack_type.value if a.threat else "BENIGN",
            "evidence": list(a.evidence), "latency_ms": a.latency_ms,
            "flight_mode": f.snapshot.flight_mode, "rel_alt": f.snapshot.rel_alt,
            "sources": sorted(f"{s}/{c}" for s, c in f.sources),
            **{f"det_{k}": v for k, v in a.detector_scores.items()},
        }
        for n in (*ML_FEATURES, *EXTRA_FRAME_FIELDS):
            row[n] = float(getattr(f, n))
        row["airborne"] = (f.snapshot.rel_alt or 0.0) > 2.0
        rows.append(row)
    return rows


def cfg_for(profile: str) -> AegisConfig:
    """``profile``: 'default' (Stage-1 configs/) or 'px4_sitl' (configs/px4_sitl overrides)."""
    if profile == "default":
        return load_config()
    if profile == "px4_sitl":
        return load_config(resolve(PROFILE_DIR))
    raise ValueError(profile)
