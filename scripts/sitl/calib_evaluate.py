"""Evaluate A/B/C detector conditions on benign PX4 SITL flights (false alarms only).

    .venv/Scripts/python.exe scripts/sitl/calib_evaluate.py --set calib
    .venv/Scripts/python.exe scripts/sitl/calib_evaluate.py --set heldout     # ONCE, after freezing

Environment: SITL (replayed tlog). Attack: NONE. Claim class: none. Every decision is
benign, so a threat flag is a false alarm; this is NOT attack detection.

Conditions
  A   Stage-1 default config + Stage-1 simulator-trained model          (reference)
  B   PX4 profile (configs/px4_sitl) with the ML detector OFF
  B2  PX4 profile + Stage-1 model        (diagnostic: shows the Stage-1 model still saturates)
  C   PX4 profile + PX4-benign model (models/isoforest_px4.joblib)

Held-out protocol: ``--set heldout`` first writes
``artifacts/sitl/calibration/heldout_lock.json`` containing the SHA-256 of the profile
YAML, both models and this script's git-visible inputs, and REFUSES to run if the lock
already exists (the held-out set is single-use). If the profile is changed after seeing
held-out results the set is burned; pass ``--burned`` to re-run and the artifact is
then tagged ``held_out_burned: true``.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

from aegisflight.features.extractor import ML_FEATURES  # noqa: E402

CONDITIONS = {
    "A": ("default", cc.STAGE1_MODEL, "Stage-1 default config + Stage-1 model"),
    "B": ("px4_sitl", None, "PX4 profile, ML off"),
    "B2": ("px4_sitl", cc.STAGE1_MODEL, "PX4 profile + Stage-1 model (diagnostic)"),
    "C": ("px4_sitl", cc.PX4_MODEL, "PX4 profile + PX4-benign model"),
}
_NUM = re.compile(r"-?\d+(\.\d+)?")


def norm_evidence(e: str) -> str:
    return _NUM.sub("#", e)[:90]


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [float("nan"), float("nan")]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def summarise(name: str, rows: list[dict]) -> dict:
    n = len(rows)
    fa = [r for r in rows if r["threat"]]
    det = {d: [r[d] >= th for r in rows] for d, th in cc.DET_TRIG.items()}
    ev_fa: Counter = Counter()
    ev_all: Counter = Counter()
    for r in rows:
        for e in r["evidence"]:
            ev_all[norm_evidence(e)] += 1
            if r["threat"]:
                ev_fa[norm_evidence(e)] += 1
    lat = np.array([r["latency_ms"] for r in rows]) if rows else np.array([0.0])
    # which detectors were over their trigger on false-alarm decisions
    combo: Counter = Counter()
    for r in fa:
        combo["+".join(sorted(d.replace("det_", "") for d in cc.DET_TRIG if r[d] >= cc.DET_TRIG[d])) or "fusion-only"] += 1
    return {
        "flight": name, "decisions": n,
        "false_alarm_decisions": len(fa),
        "false_alarm_rate": len(fa) / n if n else None,
        "false_alarm_rate_wilson95_DECISION_LEVEL_optimistic": wilson(len(fa), n),
        "airborne_decisions": sum(r["airborne"] for r in rows),
        "false_alarm_decisions_airborne": sum(r["threat"] and r["airborne"] for r in rows),
        "pred_classes": dict(Counter(r["pred"] for r in fa)),
        "detector_trigger_rate": {d: (sum(v) / n if n else None) for d, v in det.items()},
        "false_alarm_detector_combinations": dict(combo),
        "evidence_in_false_alarm_decisions": ev_fa.most_common(15),
        "evidence_all_decisions": ev_all.most_common(15),
        "decision_latency_ms": {"mean": float(lat.mean()), "p95": float(np.percentile(lat, 95)),
                                "max": float(lat.max())},
        "max_seq_gap_ge_30_decisions": sum(r["max_seq_gap"] > 30 for r in rows),
        "flight_mode_UNKNOWN_decisions": sum(r["flight_mode"] in (None, "UNKNOWN") for r in rows),
        "cold_start_decisions_hb_or_gps_never_seen": sum(
            r["heartbeat_age_s"] >= 999.0 or r["gps_age_s"] >= 999.0 for r in rows),
        "feature_p50_p95_max": {n_: [float(np.percentile([r[n_] for r in rows], q)) if q < 100
                                     else float(max(r[n_] for r in rows)) for q in (50, 95, 100)]
                                for n_ in ML_FEATURES} if rows else {},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--set", choices=("calib", "heldout"), required=True)
    ap.add_argument("--burned", action="store_true", help="re-run held-out after the profile changed (tags the set burned)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    flights = cc.CALIB_FLIGHTS if a.set == "calib" else cc.HELDOUT_FLIGHTS
    out_path = cc.OUT_DIR / f"evaluation_{a.set}.json"
    cc.OUT_DIR.mkdir(parents=True, exist_ok=True)

    frozen = {
        "profile_yaml_sha256": cc.sha256(cc.resolve(cc.PROFILE_DIR) / "detector.yaml"),
        "px4_model_sha256": cc.sha256(cc.resolve(cc.PX4_MODEL)),
        "stage1_model_sha256": cc.sha256(cc.resolve(cc.STAGE1_MODEL)),
        "stage1_detector_yaml_sha256": cc.sha256(cc.resolve("configs/detector.yaml")),
        "derivation_json_sha256": cc.sha256(cc.OUT_DIR / "derivation.json"),
    }
    burned = False
    if a.set == "heldout":
        lock = cc.OUT_DIR / "heldout_lock.json"
        if lock.exists() and not a.burned:
            print(f"REFUSING: {lock} exists - the held-out set was already used (single-use).")
            return 2
        burned = lock.exists()
        lock.write_text(json.dumps({"written": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "frozen_before_run": frozen,
                                    "held_out_burned": burned}, indent=2))

    t0 = time.perf_counter()
    result: dict = {
        "schema": "aegisflight.sitl_calibration_eval/1", "set": a.set,
        "environment": "SITL (replayed tlog)", "attack_status": "NONE", "claim_class": "none (false-alarm only)",
        "held_out_burned": burned, "frozen_inputs": frozen,
        "host": {"platform": platform.platform(), "cpu_count": os.cpu_count(), "python": platform.python_version(),
                 "note": "decision latency is wall time on a shared dev host; load-dependent, not a benchmark"},
        "flights": [{"tlog": t, "sha256": cc.sha256(cc.resolve(t))} for t in flights],
        "conditions": {},
    }
    raw = {t: cc.load_raw_frames(t) for t in flights}
    for cid, (profile, model, desc) in CONDITIONS.items():
        cfg = cc.cfg_for(profile)
        runs, allrows = [], []
        for t in flights:
            rows = cc.replay_rows(t, cfg, model, raw[t])
            allrows += rows
            runs.append(summarise(Path(t).name, rows))
        pooled = summarise("POOLED", allrows)
        result["conditions"][cid] = {"description": desc, "profile": profile, "model": model,
                                     "per_flight": runs, "pooled": pooled}
        print(f"[{a.set}] {cid} {desc}: FA {pooled['false_alarm_decisions']}/{pooled['decisions']} "
              f"({pooled['false_alarm_rate'] * 100:.2f}%) per-flight "
              f"{[r['false_alarm_decisions'] for r in runs]}")
    result["wall_s"] = time.perf_counter() - t0
    out_path.write_text(json.dumps(result, indent=2, default=str))
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
