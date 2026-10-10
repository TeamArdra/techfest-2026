"""Score one ArduPilot-SITL attack run against its PRE-REGISTERED criteria (blue/validation side).

    .venv/Scripts/python.exe scripts/ardupilot/evaluate_ap_attack.py artifacts/ardupilot/<run> \
        --prereg artifacts/ardupilot/<run>/preregistration.json

Reads only artifacts the run already wrote (summary / manifest / decisions / alerts / attack ground
truth) plus the run's CLEAN tlog, which is replayed through the same pipeline and configuration as
the CONTROL arm: identical flight, identical bytes, no modification. The attack's ground truth is
read here, after the fact; nothing in this file feeds back into a detector.

Environment: SITL (link-level; see ``ap_attack.py``). Claim class: link-level detection ONLY.
This file never states anything about the vehicle's estimator or physical flight: the simulator
never received a modified frame.

Verdicts
--------
* ``INVALID``   a validity gate failed (the run cannot support any claim, for or against)
* ``DETECTED``  every detection criterion met
* ``MISSED``    valid run, a detection criterion failed (reported as plainly as a hit)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parents[1]

from replay_ap_tlog import replay  # noqa: E402

from aegisflight.config import load_config  # noqa: E402


def read_jsonl(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def in_window(rows: list[dict], lo: float, hi: float) -> list[dict]:
    return [r for r in rows if lo <= r["t"] <= hi]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run")
    ap.add_argument("--prereg", required=True)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")

    run = Path(a.run)
    pre = json.loads(Path(a.prereg).read_text(encoding="utf-8"))
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    live = [d for d in read_jsonl(run / "decisions.jsonl") if d.get("phase") != "post_link"]
    alerts = read_jsonl(run / "alerts.jsonl") if (run / "alerts.jsonl").exists() else []
    att = manifest.get("attack") or {}
    res = att.get("result") or {}
    win = att.get("window_decision_time")
    crit = pre["criteria"]

    run_cfg = None if summary["config_dir"].startswith("configs (Stage-1") else summary["config_dir"]
    # -- validity gates: any failure => INVALID (no claim either way) -------------------------- #
    gates = {
        "harness_exit_code_0": summary["harness_exit_code"] == 0,
        "pipe_integrity_identical": bool(summary["pipe_integrity"].get("identical")),
        "pipe_overflow_zero": summary["pipe_stats"]["dropped_overflow"] == 0,
        "pipe_reader_no_error": summary["pipe_stats"].get("last_error") is None,
        "phase_events_present": (run / "events.jsonl").exists(),
        "window_inside_link": bool(win) and win["end_t_s"] <= summary["link_span_s"],
        "hash_chain_ok": bool(summary["hash_chain"]["ok"]),
        "no_orphan_simulator": summary["orphan_arducopter_after_run"] == "none",
        "no_default_netns_leak": "leak=no" in (manifest.get("postcheck") or ""),
        "attack_hook_errors_zero": summary["tap_stats"]["hook_errors"] == 0,
        "attack_gate_opened": bool(res.get("gate_opened")),
        "attack_frames_modified_min": res.get("frames_modified", 0) >= crit["min_frames_modified"],
        "prereg_matches_run_spec": pre["attack"]["spec"] == att.get("spec"),
        "prereg_config_matches_run": pre["config_dir"] == run_cfg,
        "prereg_ml_matches_run": pre["ml_enabled"] == summary["ml_enabled"],
    }
    effect = res.get("actual_effect") or {}
    out: dict = {"run": str(run), "environment": summary["environment"], "attack": att.get("attack"),
                 "claim_class": att.get("claim_class"), "validity_gates": gates, "window_decision_time": win,
                 "attack_result": res}
    if not all(gates.values()) or win is None:
        out["verdict"] = "INVALID"
        out["failed_gates"] = [k for k, v in gates.items() if not v] + ([] if win is not None else ["window_known"])
        _emit(out, a.json)
        return 1

    lo, hi = win["onset_t_s"], win["end_t_s"] + crit["post_window_grace_s"]

    # -- control arm: the SAME flight's clean frames, same pipeline/config/model ---------------- #
    cfg = load_config(None if pre["config_dir"] is None else REPO / pre["config_dir"])
    model = str(REPO / pre["model"]) if pre["ml_enabled"] else None
    clean_tlog = Path(manifest["clean_tlog"]["path"])
    ctrl, _ = replay(clean_tlog, cfg, model, float(cfg.simulation.get("sample_rate_hz", 10.0)))

    obs_win, ctrl_win = in_window(live, lo, hi), in_window(ctrl, lo, hi)
    obs_alerts = [d for d in obs_win if d["alert"]]
    ctrl_alerts = [d for d in ctrl_win if d["alert"]]
    first = obs_alerts[0] if obs_alerts else None
    first_full = next((x for x in alerts if first and abs(x["t"] - first["t"]) < 1e-6), None)
    # pre-onset in-flight false alarms in the OBSERVED arm (benign portion of the same run)
    flight = {"takeoff", "square", "rtl", "landed"}
    pre_onset = [d for d in live if d["t"] < win["onset_t_s"] and d.get("phase") in flight]
    pre_fa = [d for d in pre_onset if d["alert"]]
    ctrl_inflight_fa = [d for d in ctrl if d["alert"]]

    # an empty control window or no pre-onset in-flight decisions would make C1 / B1 true by absence of data
    vacuous = [k for k, bad in (("control_window_nonempty", len(ctrl_win) == 0),
                                ("pre_onset_inflight_nonempty", len(pre_onset) == 0)) if bad]
    if vacuous:
        out["verdict"] = "INVALID"
        out["failed_gates"] = vacuous
        _emit(out, a.json)
        return 1

    detectors_in_first = (first_full or {}).get("contributing_detectors") or []
    checks = {
        "D1_alert_in_window": len(obs_alerts) >= 1,
        "D2_alert_type_expected": bool(first) and first["type"] in crit["expected_alert_types"],
        "D3_physics_detector_contributed": crit["required_detector"] in detectors_in_first,
        "C1_control_arm_alert_free_in_window": len(ctrl_alerts) == 0,
        "B1_pre_onset_inflight_false_alarms_le": len(pre_fa) <= crit["max_pre_onset_false_alarms"],
    }
    out.update({
        "window_scored_t_s": [lo, hi],
        "observed_arm": {"decisions_in_window": len(obs_win), "alert_decisions_in_window": len(obs_alerts),
                         "first_alert": ({"t": first["t"], "type": first["type"], "score": first["score"],
                                          "t_after_onset_s": round(first["t"] - win["onset_t_s"], 2),
                                          "contributing_detectors": detectors_in_first,
                                          "evidence": (first_full or {}).get("evidence"),
                                          "event_id": (first_full or {}).get("event_id"),
                                          "hash": (first_full or {}).get("hash")} if first else None),
                         "alert_types_in_window": sorted({d["type"] for d in obs_alerts}),
                         "pre_onset_inflight_decisions": len(pre_onset), "pre_onset_inflight_alerts": len(pre_fa)},
        "control_arm": {"decisions_in_window": len(ctrl_win), "alert_decisions_in_window": len(ctrl_alerts),
                        "alerts_whole_flight_all_phases": len(ctrl_inflight_fa),
                        "note": "replay of this run's CLEAN frames; phases are not labelled here, so the "
                                "whole-flight count includes the start-up (boot/await_gps) alerts"},
        "realised_attack": {"frames_modified": res.get("frames_modified"), "effect": effect},
        "criteria_checks": checks,
        "criteria_note": "D1-D3 and C1 decide the verdict; B1 is the baseline guard and must also hold",
    })
    out["verdict"] = "DETECTED" if all(checks.values()) else "MISSED"
    out["failed_criteria"] = [k for k, v in checks.items() if not v]
    _emit(out, a.json)
    return 0 if out["verdict"] == "DETECTED" else 2


def _emit(out: dict, path: str | None) -> None:
    text = json.dumps(out, indent=2, default=str)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    raise SystemExit(main())
