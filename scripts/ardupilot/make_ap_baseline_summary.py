"""Regenerate the ArduPilot-SITL benign baseline summary from the recorded runs (generated; do not hand-edit).

    .venv/Scripts/python.exe scripts/ardupilot/make_ap_baseline_summary.py

Inputs: ``artifacts/ardupilot/ap_benign_*/`` (live runs: Stage-1 configuration + Stage-1 ML model) and
their clean tlogs ``data/ardupilot/raw/<run>.clean.tlog`` (replayed here with the ML detector OFF, same
bytes, same pipeline). Environment: SITL (live) + REPLAY (ML-off variant). Claim class: none -- benign
false-alarm / coverage / cost reference, not detection evidence, not about real vehicles.

"In-flight" phases are takeoff, square, rtl, landed (collector phase events). "Ground" phases are boot,
await_gps, arm (start-up before GPS lock / arming), reported separately because the start-up
sentinels and a no-fix GPS legitimately trip rules there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parents[1]

from replay_ap_tlog import label_phases, load_phases, replay, summarise  # noqa: E402

from aegisflight.config import load_config  # noqa: E402

INFLIGHT = {"takeoff", "square", "rtl", "landed"}
GROUND = {"boot", "await_gps", "arm"}
def _flew(run: Path) -> bool:
    """A run counts as a benign flight only if it ended cleanly, nothing was lost, and it reached takeoff..landed."""
    try:
        s = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (s.get("harness_exit_code") == 0 and bool(s.get("pipe_integrity", {}).get("identical"))
            and bool(s.get("hash_chain", {}).get("ok")) and INFLIGHT <= set(s.get("by_phase", {})))


RUNS = sorted(p.name for p in (REPO / "artifacts" / "ardupilot").glob("ap_benign_*") if _flew(p))


def phase_totals(by_phase: dict, names: set[str]) -> dict:
    d = sum(v["decisions"] for k, v in by_phase.items() if k in names)
    al = sum(v["alerts"] for k, v in by_phase.items() if k in names)
    return {"decisions": d, "alert_decisions": al}


def main() -> int:
    cfg = load_config(None)
    rate = float(cfg.simulation.get("sample_rate_hz", 10.0))
    out: dict = {"schema": "aegisflight.ardupilot_baseline_summary/1",
                 "environment": "SITL (live runs) + REPLAY (ML-off variant of the same bytes)",
                 "claim_class": "none (benign false-alarm / coverage / cost reference)",
                 "config": "Stage-1 configs/ unchanged (no ArduPilot profile)", "runs": {}}
    for name in RUNS:
        run = REPO / "artifacts" / "ardupilot" / name
        s = json.loads((run / "summary.json").read_text(encoding="utf-8"))
        tlog = REPO / "data" / "ardupilot" / "raw" / f"{name}.clean.tlog"
        phases, _ = load_phases(run)
        live_dec = [json.loads(x) for x in (run / "decisions.jsonl").read_text(encoding="utf-8").splitlines() if x]
        live_dec = [d for d in live_dec if d.get("phase") != "post_link"]
        by_live: dict = {}
        for d in live_dec:
            p = by_live.setdefault(d["phase"], {"decisions": 0, "threat": 0, "alerts": 0})
            p["decisions"] += 1
            p["threat"] += d["threat"]
            p["alerts"] += d["alert"]
        rows, _ = replay(tlog, cfg, None, rate)  # ML OFF
        label_phases(rows, phases)
        noml = summarise(rows)
        out["runs"][name] = {
            "stream_config": s["stream_config"], "link_span_s": s["link_span_s"], "decisions": s["decisions"],
            "frames": s["pipe_stats"]["frames_received"], "pipe_identical": s["pipe_integrity"]["identical"],
            "hash_chain_ok": s["hash_chain"]["ok"], "orphan_after": s["orphan_arducopter_after_run"],
            "live_stage1_ml": {"alert_decisions": s["alert_decisions"], "threat_decisions": s["threat_decisions"],
                               "ground": phase_totals(by_live, GROUND), "in_flight": phase_totals(by_live, INFLIGHT),
                               "alert_types": s["alert_types"]},
            "replay_ml_off": {"decisions": noml["decisions"], "alert_decisions": noml["alert_decisions"],
                              "ground": phase_totals(noml["by_phase"], GROUND),
                              "in_flight": phase_totals(noml["by_phase"], INFLIGHT),
                              "alert_evidence": noml["alert_evidence_top"]},
            "message_rates_hz": {k: v["rate_hz"] for k, v in s["message_coverage_pipeline"].items()},
            "aggregate_msg_rate_hz": s["aggregate_msg_rate_hz"], "link_bytes_per_s": s["link_bytes_per_s"],
            "other_message_types": len(s["other_messages"]),
            "decision_latency_ms": s["decision_latency_ms"], "tick_close_to_emit_ms": s["tick_close_to_emit_ms"],
            "resources_ids_process_ml_on": s["resources_ids_process"], "late_ticks": s["source_stats"]["late_ticks"],
            "bad_frames": s["source_stats"]["bad_frames"], "unverified_frames": s["source_stats"]["unverified_frames"],
        }
    tot = {"flights": len(out["runs"])}
    for variant, key in (("stage1_ml_on_live", "live_stage1_ml"), ("ml_off_replay", "replay_ml_off")):
        for zone in ("ground", "in_flight"):
            tot[f"{variant}_{zone}_decisions"] = sum(r[key][zone]["decisions"] for r in out["runs"].values())
            tot[f"{variant}_{zone}_alert_decisions"] = sum(r[key][zone]["alert_decisions"] for r in out["runs"].values())
    out["totals"] = tot
    (REPO / "artifacts" / "ardupilot" / "BASELINE_SUMMARY.json").write_text(json.dumps(out, indent=2),
                                                                           encoding="utf-8")

    L = ["# ArduPilot SITL benign baseline (generated; do not edit)", "",
         "Environment: **SITL** (ArduCopter 4.7.1, isolated netns, pipe transport, wall-clock 1x) for the live runs; "
         "the ML-off columns are a **REPLAY** of the same recorded bytes. Claim class: **none** -- benign false-alarm / "
         "coverage / cost reference. Not detection evidence; says nothing about real vehicles.",
         "Regenerate: `.venv/Scripts/python.exe scripts/ardupilot/make_ap_baseline_summary.py` "
         "(inputs: `artifacts/ardupilot/ap_benign_*`, `data/ardupilot/raw/*.clean.tlog`).", "",
         "In-flight = takeoff, square, rtl, landed. Ground = boot, await_gps, arm (start-up before GPS lock / arming).", "",
         "| run | stream | decisions | Stage-1+ML alerts (ground / in-flight) | ML-off alerts (ground / in-flight) |",
         "|---|---|---|---|---|"]
    for n, r in out["runs"].items():
        a, b = r["live_stage1_ml"], r["replay_ml_off"]
        L.append(f"| {n} | {r['stream_config']} | {r['decisions']} | "
                 f"{a['ground']['alert_decisions']}/{a['ground']['decisions']} / "
                 f"{a['in_flight']['alert_decisions']}/{a['in_flight']['decisions']} | "
                 f"{b['ground']['alert_decisions']}/{b['ground']['decisions']} / "
                 f"{b['in_flight']['alert_decisions']}/{b['in_flight']['decisions']} |")
    L += ["", f"Totals over {tot['flights']} flights: Stage-1+ML in-flight alerts "
          f"{tot['stage1_ml_on_live_in_flight_alert_decisions']}/{tot['stage1_ml_on_live_in_flight_decisions']}; "
          f"ML-off in-flight alerts {tot['ml_off_replay_in_flight_alert_decisions']}/"
          f"{tot['ml_off_replay_in_flight_decisions']}; ML-off ground alerts "
          f"{tot['ml_off_replay_ground_alert_decisions']}/{tot['ml_off_replay_ground_decisions']}.", "",
          "| run | agg Hz | B/s | lat p50/p95/p99/max ms | emit p50/p99 ms | CPU mean/max % of 1 core | RSS MB |",
          "|---|---|---|---|---|---|---|"]
    for n, r in out["runs"].items():
        la, em, rs = r["decision_latency_ms"], r["tick_close_to_emit_ms"], r["resources_ids_process_ml_on"]
        L.append(f"| {n} | {r['aggregate_msg_rate_hz']} | {r['link_bytes_per_s']} | {la['p50']}/{la['p95']}/{la['p99']}/"
                 f"{la['max']} | {em['p50']}/{em['p99']} | {rs['cpu_pct_of_one_core_mean']}/"
                 f"{rs['cpu_pct_of_one_core_max']} | {rs['rss_mb_max']} |")
    L += ["", "Resource figures are the Windows IDS process only, with the Stage-1 ML model loaded (the WSL simulator is "
          "excluded); latency is the pipeline's own per-decision compute time; `emit` is tick-close to tick-emit.", ""]
    (REPO / "artifacts" / "ardupilot" / "BASELINE_SUMMARY.md").write_text("\n".join(L), encoding="utf-8")
    print(json.dumps(tot, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
