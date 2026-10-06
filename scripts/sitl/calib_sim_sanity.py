"""EXPLORATORY SIM sanity check: what does the PX4 profile do to Stage-1 SIM attacks?

    .venv/Scripts/python.exe scripts/sitl/calib_sim_sanity.py [--seeds 42 43] [--workers 3]

Environment: SIM (in-process simulator), NOT SITL. Claim class: none -- this only bounds
the COST side of loosening thresholds. It is exploratory (n = number of seeds per mode,
default 2), it does NOT replace the committed benchmark, and it never writes under
``artifacts/benchmarks*``. Output: ``artifacts/sitl/calibration/sim_sanity.json``.

Configurations compared (Stage-1 simulator model for all, identical sessions/seeds):
  default          Stage-1 configs/
  profile_sysid1   PX4 profile with expected_sysids forced back to the SIM vehicle id [1]
                   (isolates the effect of the THRESHOLD changes: rate, battery, yaw-course, grace)
  *_noml           same, with the ML detector OFF (isolates the RULE changes; with the Stage-1 ML on, the
                   simulator-trained model catches most attacks by itself and masks the threshold effect)
  profile_raw      PX4 profile as shipped (expected_sysids [3]) - benign SIM flags sys1 as rogue,
                   shown only for the benign row to demonstrate the profile is not portable to SIM
Attack windows/modes are the Stage-1 defaults from ``configs/attacks.yaml`` with the mode
swapped per class (``benchmark.extended.MODES``). Nothing about the attacks is modified.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

from aegisflight.benchmark.extended import MODES  # noqa: E402
from aegisflight.benchmark.runner import run_session  # noqa: E402

MODEL = cc.STAGE1_MODEL


def make_cfg(kind: str, scenario: str, mode: str):
    base = kind.removesuffix("_noml")
    cfg = cc.cfg_for("default" if base == "default" else "px4_sitl")
    cfg = copy.deepcopy(cfg)
    if base == "profile_sysid1":
        cfg.detector["protocol"]["expected_sysids"] = [1]
    if scenario != "benign" and mode and mode != "default":
        cfg.attacks[scenario]["mode"] = mode
    return cfg


def one(args: tuple[str, str, str, int]) -> dict:
    kind, scenario, mode, seed = args
    cfg = make_cfg(kind, scenario, mode)
    model = None if kind.endswith("_noml") else str(cc.resolve(MODEL))
    res = run_session(cfg, scenario, seed=seed, model_path=model, grace_s=5.0)
    inwin = [r for r in res.records if r.true_label.is_attack and r.scored]
    ben = [r for r in res.records if (not r.true_label.is_attack) and r.scored]
    return {"config": kind, "scenario": scenario, "mode": mode, "seed": seed,
            "in_window_decisions": len(inwin), "in_window_detected": sum(r.threat for r in inwin),
            "benign_scored_decisions": len(ben), "benign_false_alarms": sum(r.threat for r in ben),
            "time_to_detect_s": res.time_to_detect_s}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 43])
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    jobs = []
    for seed in a.seeds:
        for kind in ("default", "profile_sysid1", "profile_raw", "default_noml", "profile_sysid1_noml"):
            jobs.append((kind, "benign", "", seed))
        for sc, modes in MODES.items():
            for m in modes:
                for kind in ("default", "profile_sysid1", "default_noml", "profile_sysid1_noml"):
                    jobs.append((kind, sc, m, seed))
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        res = list(ex.map(one, jobs))
    agg: dict = {}
    for r in res:
        key = f"{r['scenario']}:{r['mode']}" if r["mode"] else r["scenario"]
        d = agg.setdefault(key, {}).setdefault(r["config"], {"in_window": 0, "detected": 0, "ttd": [],
                                                              "benign_dec": 0, "benign_fa": 0, "sessions": 0})
        d["in_window"] += r["in_window_decisions"]
        d["detected"] += r["in_window_detected"]
        d["benign_dec"] += r["benign_scored_decisions"]
        d["benign_fa"] += r["benign_false_alarms"]
        d["sessions"] += 1
        if r["time_to_detect_s"] is not None:
            d["ttd"].append(r["time_to_detect_s"])
    doc = {"schema": "aegisflight.sitl_calibration_sim_sanity/1",
           "environment": "SIM (in-process simulator) - EXPLORATORY, not SITL, not the committed benchmark",
           "claim_class": "none (cost-side sanity check of loosened thresholds)",
           "seeds": a.seeds, "model": MODEL, "profile_yaml_sha256": cc.sha256(cc.resolve(cc.PROFILE_DIR) / "detector.yaml"),
           "per_session": res, "per_mode": agg}
    out = cc.OUT_DIR / "sim_sanity.json"
    out.write_text(json.dumps(doc, indent=2))
    for k, v in agg.items():
        print(k, {c: (f"{x['detected']}/{x['in_window']}" if x["in_window"] else f"FA {x['benign_fa']}/{x['benign_dec']}")
                  for c, x in v.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
