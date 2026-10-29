#!/usr/bin/env python
"""Compare AegisFlight with a pre-defined simple-threshold baseline on the SAME ``SIM`` decisions.

Both systems read the same telemetry ticks of the Stage-1 benchmark grid (``harness.run_benchmark``: scenarios x seeds 1..6 x routes,
ML on). For every decision tick the AegisFlight pipeline produces its assessment and the baseline
(``configs/baseline_threshold.yaml``: fixed single-value limits, any rule fires => threat) is evaluated on the pipeline's own
``FeatureFrame``, so both see byte-identical inputs. Scoring replicates ``benchmark/runner.py`` (5 s warm-up, 5 s post-attack grace);
the script verifies that its AegisFlight confusion counts equal ``artifacts/benchmarks/results.json`` and fails otherwise.

Outputs (in --out): ``comparison.json``, ``comparison.md``, ``per_session.csv``, ``baseline_meta.json``.
The unit for intervals is the SESSION (decisions inside a session are correlated; Wilson 95 %).

Environment ``SIM``; claim class "link-level detection". Both detectors and the attacks are the team's: this is design evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import yaml

from aegisflight.attacks import build_attack
from aegisflight.benchmark.harness import ROUTES, SCENARIOS
from aegisflight.benchmark.runner import _with_route
from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import SimulatedTelemetrySource

Z = 1.959964


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    h = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def baseline_fires(frame, rules: dict) -> list[str]:
    s = frame.snapshot
    fired = []
    if frame.heartbeat_age_s > rules["heartbeat_age_s_gt"]:
        fired.append("heartbeat_age")
    if frame.gps_age_s > rules["gps_age_s_gt"]:
        fired.append("gps_age")
    if frame.loss_ratio > rules["loss_ratio_gt"]:
        fired.append("loss_ratio")
    if s.groundspeed is not None and s.groundspeed > rules["groundspeed_ms_gt"]:
        fired.append("groundspeed")
    if abs(frame.alt_rate_ms) > rules["abs_vertical_rate_ms_gt"]:
        fired.append("vertical_rate")
    if s.satellites is not None and s.satellites < rules["satellites_lt"]:
        fired.append("satellites")
    if s.gps_fix_type is not None and s.gps_fix_type < rules["gps_fix_type_lt"]:
        fired.append("gps_fix_type")
    if s.battery_remaining is not None and 0 <= s.battery_remaining < rules["battery_remaining_pct_lt"]:
        fired.append("battery")
    return fired


def run_one(cfg, scenario, seed, route, model_path, rules, warmup_s=5.0, grace_s=5.0):
    """Return scored decisions as (t, is_attack, aegis_threat, baseline_threat, baseline_rules)."""
    cfg = _with_route(cfg, route)
    fw_dir = tempfile.mkdtemp(prefix="aegis_fw_")
    pipe = IDSPipeline(cfg, model_path=model_path, firmware_dir=fw_dir)
    rng = np.random.default_rng(seed + 99)
    kw = {"firmware_dir": fw_dir} if "firmware_integrity" in scenario.split("+") else {}
    attack = build_attack(scenario, cfg.attacks, rng, **kw)
    src = SimulatedTelemetrySource(cfg, attack, seed=seed)
    last_attack_t = -1e18
    rows = []
    for tick in src.stream():
        a = pipe.process_tick(tick)
        if a is None:
            continue
        is_atk = tick.label.is_attack
        if is_atk:
            last_attack_t = a.t
        in_grace = (not is_atk) and (a.t - last_attack_t) < grace_s
        if a.t < warmup_s or in_grace:
            continue
        fired = baseline_fires(pipe.last_frame, rules)
        rows.append((a.t, is_atk, bool(a.threat), bool(fired), tuple(fired)))
    return rows


def conf(rows, idx):
    tp = sum(1 for r in rows if r[1] and r[idx])
    fn = sum(1 for r in rows if r[1] and not r[idx])
    fp = sum(1 for r in rows if not r[1] and r[idx])
    tn = sum(1 for r in rows if not r[1] and not r[idx])
    return tp, fp, tn, fn


def stats(tp, fp, tn, fn):
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": tp / (tp + fn) if tp + fn else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
    }


def session_hit(scenario, rows):
    """(aegis, baseline): benign = any false-positive decision; attack = any detected attack decision."""
    if scenario == "benign":
        return [any(r[2] for r in rows), any(r[3] for r in rows)]
    return [any(r[1] and r[2] for r in rows), any(r[1] and r[3] for r in rows)]


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()


def _f(x):
    return "n/a" if x is None else f"{x:.4f}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rules", type=Path, default=Path("configs/baseline_threshold.yaml"))
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--committed", type=Path, default=Path("artifacts/benchmarks/results.json"))
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5, 6])
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rules = yaml.safe_load(a.rules.read_text(encoding="utf-8"))["rules"]
    cfg = load_config()

    sess = []  # (scenario, seed, route, rows)
    for scenario in SCENARIOS:
        for i, seed in enumerate(a.seeds):
            route = ROUTES[i % len(ROUTES)]
            sess.append((scenario, seed, route, run_one(cfg, scenario, seed, route, a.model, rules)))
            print(scenario, seed, route, len(sess[-1][3]), flush=True)

    allrows = [r for *_, rows in sess for r in rows]
    aegis = stats(*conf(allrows, 2))
    base = stats(*conf(allrows, 3))

    committed = json.loads(a.committed.read_text(encoding="utf-8"))["binary"]
    ok = all(aegis[k] == committed[k] for k in ("tp", "fp", "tn", "fn"))
    if not ok:
        print("MISMATCH vs committed benchmark", aegis, committed)
        return 2

    by_class: dict[str, list] = {}
    for scenario, _, _, rows in sess:
        by_class.setdefault(scenario, []).append(rows)
    firings: dict[str, int] = {}
    for scenario, _, _, rows in sess:
        for r in rows:
            for name in r[4]:
                key = f"{scenario}:{name}:{'attack' if r[1] else 'benign'}"
                firings[key] = firings.get(key, 0) + 1

    out_cls = {}
    for scenario, sessions in by_class.items():
        flat = [r for rows in sessions for r in rows]
        hits = [session_hit(scenario, rows) for rows in sessions]
        n = len(sessions)
        ka, kb = sum(h[0] for h in hits), sum(h[1] for h in hits)
        out_cls[scenario] = {
            "sessions": n,
            "aegis": {"sessions_hit": ka, "wilson95": wilson(ka, n), "decisions": stats(*conf(flat, 2))},
            "baseline": {"sessions_hit": kb, "wilson95": wilson(kb, n), "decisions": stats(*conf(flat, 3))},
        }

    rules_sha = hashlib.sha256(a.rules.read_bytes()).hexdigest()
    meta = {
        "environment": "SIM", "claim_class": "link-level detection (design evidence; team-written attacks and detectors)",
        "rules_file": str(a.rules).replace("\\", "/"), "rules_sha256": rules_sha, "rules": rules,
        "git_head": _git("rev-parse", "HEAD"),
        "git_dirty_paths": _git("status", "--porcelain", "--untracked-files=no").splitlines(),
        "python": platform.python_version(), "model": a.model,
        "model_sha256": hashlib.sha256(Path(a.model).read_bytes()).hexdigest() if Path(a.model).exists() else None,
        "seeds": a.seeds, "routes": ROUTES, "warmup_s": 5.0, "grace_s": 5.0,
        "aegis_counts_equal_committed_benchmark": ok,
        "regenerate": f"python scripts/baseline_comparison.py --out {str(a.out).replace(chr(92), '/')}",
    }
    result = {"overall": {"aegisflight": aegis, "threshold_baseline": base}, "per_class": out_cls,
              "baseline_rule_firings_by_scenario_rule_kind": firings}
    (a.out / "comparison.json").write_text(json.dumps({"meta": meta, **result}, indent=2), encoding="utf-8")
    (a.out / "baseline_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    with (a.out / "per_session.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "seed", "route", "n_scored", "aegis_session_hit", "baseline_session_hit"])
        for scenario, seed, route, rows in sess:
            h = session_hit(scenario, rows)
            w.writerow([scenario, seed, route, len(rows), int(h[0]), int(h[1])])

    md = ["# AegisFlight vs simple-threshold baseline (SIM)", "",
          f"Same {len(allrows)} scored decisions for both systems (Stage-1 grid; `{meta['regenerate']}`). "
          f"Baseline rules: `{meta['rules_file']}` sha256 `{rules_sha[:16]}…`.",
          "AegisFlight counts equal `artifacts/benchmarks/results.json` (checked by the script).", "",
          "| System | TP | FP | TN | FN | Recall | FPR | Precision |", "|---|---|---|---|---|---|---|---|"]
    for name, s in (("AegisFlight", aegis), ("Threshold baseline", base)):
        md.append(f"| {name} | {s['tp']} | {s['fp']} | {s['tn']} | {s['fn']} | {_f(s['recall'])} | {_f(s['fpr'])} | {_f(s['precision'])} |")
    md += ["", "## Per scenario",
           "Decisions: attack rows TP/FN, benign row FP/TN. Sessions: sessions with at least one detected attack decision "
           "(benign row: at least one false-positive decision), Wilson 95 % on sessions.", "",
           "| Scenario | Sessions | AegisFlight decisions | AegisFlight sessions | Baseline decisions | Baseline sessions |",
           "|---|---|---|---|---|---|"]
    for sc, c in out_cls.items():
        ad, bd = c["aegis"]["decisions"], c["baseline"]["decisions"]
        wa, wb = c["aegis"]["wilson95"], c["baseline"]["wilson95"]
        da, db = (f"FP {ad['fp']} / TN {ad['tn']}", f"FP {bd['fp']} / TN {bd['tn']}") if sc == "benign" else (
            f"{ad['tp']} / {ad['fn']}", f"{bd['tp']} / {bd['fn']}")
        md.append(f"| {sc} | {c['sessions']} | {da} | {c['aegis']['sessions_hit']}/{c['sessions']} [{wa[0]:.2f}, {wa[1]:.2f}] "
                  f"| {db} | {c['baseline']['sessions_hit']}/{c['sessions']} [{wb[0]:.2f}, {wb[1]:.2f}] |")
    md += ["", "## Limitations", "",
           "- `SIM` only; the attacks, the simulator, AegisFlight and this baseline are all team-written. Not an estimate of real-world performance.",
           "- The baseline is deliberately minimal (single-value limits). It is not a model of ArduPilot or PX4 failsafes, which are configured per vehicle and were not run.",
           "- Attack windows were designed against AegisFlight's checks; the baseline limits were fixed beforehand and not tuned to the attacks.",
           "- 6 sessions per scenario: session intervals are wide. Decision-level counts are correlated within a session and carry no interval.", ""]
    (a.out / "comparison.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
