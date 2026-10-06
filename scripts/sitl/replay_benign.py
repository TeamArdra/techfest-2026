"""Replay benign PX4 SITL tlogs through the UNCHANGED Stage-1 IDS pipeline.

    .venv/Scripts/python.exe scripts/sitl/replay_benign.py data/sitl/raw/benign_001.tlog [more.tlog ...] \
        --out artifacts/sitl/benign_replay.json [--no-ml]

Environment: SITL (PX4 + Gazebo), replayed from a recorded tlog. Attack: NONE.
Claim class: none -- this is a false-alarm / feature-shift reference for the
default Stage-1 configuration, NOT attack detection. Every decision here is a
benign decision, so any ``threat=True`` row is a false alarm (FP).

``--config-dir configs/px4_sitl --model models/isoforest_px4.joblib`` replays the same flights under
the PX4 SITL calibration profile (see docs/CALIBRATION_PX4.md); defaults remain Stage-1.

Uses the existing tlog adapter + ``realdata.score_tlog_flight`` (no new pipeline
code), 10 Hz ticks, decisions every 2nd tick (5 Hz), Stage-1 config + model.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from aegisflight.config import load_config
from aegisflight.external import realdata, tlog_adapter
from aegisflight.features.extractor import ML_FEATURES

MODEL = "models/isoforest.joblib"
DET_TRIG = {"det_protocol_rule": 0.5, "det_physics_consistency": 0.5, "det_ml_anomaly": 0.62}


def replay(tlog: str, cfg, model: str | None, adapter: str = "tlog") -> list[dict]:
    """``adapter='tlog'``: Stage-1 pymavlink tlog adapter; ``'live'``: header-first live parser path."""
    rows: list[dict] = []
    if adapter == "live":
        from tlog_stats import iter_raw_frames  # sibling script module

        from aegisflight.sources.mavlink_live import frame_ticks
        frames = [(ts, fb) for ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(tlog)]
        for r in realdata.score_tlog_flight(frame_ticks(frames), cfg, model):
            r["seg"] = 0
            r["airborne"] = (r["rel_alt"] or 0.0) > 2.0
            rows.append(r)
        return rows
    for k, (_t0, envs) in enumerate(tlog_adapter.segments(tlog_adapter.iter_tlog(tlog))):
        if len(envs) < 50:
            continue
        for r in realdata.score_tlog_flight(tlog_adapter.tlog_ticks(envs), cfg, model):
            r["seg"] = k
            r["airborne"] = (r["rel_alt"] or 0.0) > 2.0
            rows.append(r)
    return rows


def summarise_run(name: str, rows: list[dict]) -> dict:
    n = len(rows)
    air = [r for r in rows if r["airborne"]]
    ev: Counter = Counter()
    for r in rows:
        if r["threat"]:
            ev.update(e.split(":")[0][:60] for e in r["evidence"])
    out = {
        "flight": name, "decisions": n, "airborne_decisions": len(air),
        "false_alarm_decisions": sum(bool(r["threat"]) for r in rows),
        "false_alarm_rate": (sum(bool(r["threat"]) for r in rows) / n) if n else None,
        "false_alarm_decisions_airborne": sum(bool(r["threat"]) for r in air),
        "pred_classes": dict(Counter(r["pred"] for r in rows)),
        "detector_trigger_rate": {d: (sum(r.get(d, 0.0) >= th for r in rows) / n if n else None)
                                  for d, th in DET_TRIG.items()},
        "evidence_top": ev.most_common(12),
        "sources_seen": sorted({s for r in rows for s in r["sources"]}),
        "max_sources_per_decision": max((r["n_sources"] for r in rows), default=0),
    }
    cols = [*ML_FEATURES, "threat_score", *DET_TRIG]
    out["feature_summary"] = realdata.summarise(rows, cols)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tlogs", nargs="+")
    ap.add_argument("--out", default="artifacts/sitl/benign_replay.json")
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--adapter", choices=("tlog", "live"), default="tlog")
    ap.add_argument("--config-dir", default=None,
                    help="directory holding detector.yaml overrides (default: configs/ = Stage-1); "
                         "e.g. configs/px4_sitl for the PX4 SITL calibration profile")
    ap.add_argument("--model", default=MODEL, help="anomaly model bundle (default: Stage-1 models/isoforest.joblib)")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")  # evidence strings contain non-cp1252 glyphs
    cfg = load_config(a.config_dir)
    model = None if a.no_ml or not Path(a.model).exists() else a.model
    runs, all_rows = [], []
    for t in a.tlogs:
        rows = replay(t, cfg, model, a.adapter)
        all_rows += rows
        runs.append(summarise_run(Path(t).name, rows))
        r = runs[-1]
        print(f"{r['flight']}: decisions={r['decisions']} FA={r['false_alarm_decisions']} "
              f"({(r['false_alarm_rate'] or 0) * 100:.2f}%) classes={r['pred_classes']} trig={r['detector_trigger_rate']}")
        print("   evidence:", r["evidence_top"][:6])
    doc = {"schema": "aegisflight.sitl_benign_replay/1", "environment": "SITL (replayed tlog)", "attack_status": "NONE",
           "claim_class": "none (false-alarm reference)", "model": model, "ml_enabled": model is not None, "adapter": a.adapter,
           "config_dir": a.config_dir or "configs (Stage-1 default)",
           "runs": runs, "pooled": summarise_run("POOLED", all_rows)}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
