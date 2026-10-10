"""Replay a recorded ArduPilot SITL tlog through the UNCHANGED pipeline under a chosen config/model.

    .venv/Scripts/python.exe scripts/ardupilot/replay_ap_tlog.py \
        data/ardupilot/raw/ap_benign_six_001.clean.tlog --run artifacts/ardupilot/ap_benign_six_001 \
        [--config-dir configs/ardupilot_sitl] [--no-ml] [--json out.json]

Environment: REPLAY of an ArduCopter SITL capture (the capture itself is SITL; replaying it is not a
new flight). ``--run`` points at the live run's artifact directory so decisions can be labelled
with the flight phase (collector events, shifted onto the capture's clock using the run's measured
pipe clock offset) and so the replay can be checked against the live decisions (``--check-live``).
Claim class: none for benign tlogs (false-alarm reference); for an attacked tlog see
``evaluate_ap_attack.py``.

Replay and live share the tick-bucketing core (``frame_ticks`` vs ``LiveMavlinkSource``); they see
the same bytes but replay uses the tlog's microsecond stamps instead of the live monotonic ones, so
a decision can differ from the live run at a tick boundary. ``--check-live`` reports exactly how
many decisions are identical in threat/alert verdict rather than assuming it.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "sitl"))

from tlog_stats import iter_raw_frames  # noqa: E402

from aegisflight.config import load_config  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import frame_ticks  # noqa: E402


def load_phases(run: Path | None) -> tuple[list[tuple[float, str]], float]:
    """(phase start in the TLOG's unix seconds, name) list and the first-frame-independent offset."""
    if run is None or not (run / "events.jsonl").exists():
        return [], 0.0
    offset_s = 0.0
    sj = run / "summary.json"
    if sj.exists():
        off = json.loads(sj.read_text(encoding="utf-8")).get("pipe_integrity", {}).get("clock_offset_us_median")
        offset_s = (off or 0) / 1e6
    ev = [json.loads(x) for x in (run / "events.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    return [(e["t_unix"] + offset_s, e["name"]) for e in ev if e["event"] == "phase"], offset_s


def replay(tlog: Path, cfg, model: str | None, rate_hz: float) -> tuple[list[dict], float]:
    frames = [(ts, fb) for ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(tlog)]
    t0 = frames[0][0] if frames else 0.0
    pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
    rows: list[dict] = []
    for tick in frame_ticks(frames, sample_rate_hz=rate_hz):
        a = pipe.process_tick(tick)
        if a is None:
            continue
        rows.append({"t": round(a.t, 3), "unix": round(t0 + a.t, 3), "threat": bool(a.threat),
                     "alert": bool(a.is_alert), "type": a.attack_type.value, "score": round(a.threat_score, 4),
                     "latency_ms": round(a.latency_ms, 3), "evidence": a.evidence,
                     "detector_scores": {k: round(v, 4) for k, v in a.detector_scores.items()},
                     "contributing_detectors": a.contributing_detectors})
    return rows, t0


def label_phases(rows: list[dict], phases: list[tuple[float, str]]) -> None:
    for r in rows:
        cur = "boot"
        for t_ph, name in phases:
            if r["unix"] >= t_ph:
                cur = name
        r["phase"] = cur


def summarise(rows: list[dict]) -> dict:
    by_phase: dict[str, dict] = {}
    for r in rows:
        p = by_phase.setdefault(r.get("phase", "?"), {"decisions": 0, "threat": 0, "alerts": 0})
        p["decisions"] += 1
        p["threat"] += r["threat"]
        p["alerts"] += r["alert"]
    det: Counter[str] = Counter()
    ev: Counter[str] = Counter()
    for r in rows:
        for k, v in r["detector_scores"].items():
            if v >= 0.5:
                det[k] += 1
        if r["alert"]:
            for e in r["evidence"] if isinstance(r["evidence"], list) else [r["evidence"]]:
                ev[str(e)[:80]] += 1
    n = len(rows)
    return {"decisions": n, "threat_decisions": sum(r["threat"] for r in rows),
            "alert_decisions": sum(r["alert"] for r in rows),
            "alert_rate_per_decision": round(sum(r["alert"] for r in rows) / n, 5) if n else None,
            "by_phase": by_phase, "detector_ge_0.5": dict(det), "alert_types": dict(Counter(
                r["type"] for r in rows if r["alert"])), "alert_evidence_top": ev.most_common(12)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tlog")
    ap.add_argument("--run", help="artifact dir of the live run (for phase labels / --check-live)")
    ap.add_argument("--config-dir", default=None)
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--check-live", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    cfg = load_config(a.config_dir)
    model = None if a.no_ml or not a.model or not Path(a.model).exists() else a.model
    rate = float(cfg.simulation.get("sample_rate_hz", 10.0))
    rows, _t0 = replay(Path(a.tlog), cfg, model, rate)
    run = Path(a.run) if a.run else None
    phases, offset_s = load_phases(run)
    label_phases(rows, phases)
    out = {"tlog": a.tlog, "config_dir": a.config_dir or "configs (Stage-1 default)", "ml_enabled": model is not None,
           "clock_offset_s_used_for_phases": offset_s, **summarise(rows)}
    if a.check_live and run and (run / "decisions.jsonl").exists():
        live = [json.loads(x) for x in (run / "decisions.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
        live = [x for x in live if x.get("phase") != "post_link"]
        n = min(len(live), len(rows))
        out["vs_live"] = {"live_decisions": len(live), "replay_decisions": len(rows),
                          "same_threat_verdict": sum(live[i]["threat"] == rows[i]["threat"] for i in range(n)),
                          "same_alert_verdict": sum(live[i]["alert"] == rows[i]["alert"] for i in range(n)),
                          "compared": n}
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "alert_evidence_top"}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
