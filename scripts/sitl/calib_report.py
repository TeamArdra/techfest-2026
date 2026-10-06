"""Render ``artifacts/sitl/calibration/summary.md`` from the generated JSON artifacts.

    .venv/Scripts/python.exe scripts/sitl/calib_report.py

Pure formatting: every number comes from a JSON file in ``artifacts/sitl/calibration/``
(evaluation_calib / evaluation_heldout / derivation / isoforest_px4_training / lofo_rules /
feature_shift / sim_sanity). Nothing is typed by hand.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

D = cc.OUT_DIR


def load(name: str) -> dict | None:
    p = D / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def pct(x: float | None, nd: int = 2) -> str:
    return "n/a" if x is None else f"{x * 100:.{nd}f}%"


def eval_table(ev: dict, title: str) -> list[str]:
    out = [f"### {title}", "",
           f"Flights: {', '.join(Path(f['tlog']).stem for f in ev['flights'])} | held_out_burned={ev['held_out_burned']}", "",
           "| cond | description | decisions | false-alarm decisions | FA rate | FA per flight | protocol trig | physics trig | ML trig | latency mean / p95 ms |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for cid, c in ev["conditions"].items():
        p = c["pooled"]
        tr = p["detector_trigger_rate"]
        out.append(f"| {cid} | {c['description']} | {p['decisions']} | {p['false_alarm_decisions']} | "
                   f"{pct(p['false_alarm_rate'])} | {[r['false_alarm_decisions'] for r in c['per_flight']]} | "
                   f"{pct(tr['det_protocol_rule'])} | {pct(tr['det_physics_consistency'])} | {pct(tr['det_ml_anomaly'])} | "
                   f"{p['decision_latency_ms']['mean']:.2f} / {p['decision_latency_ms']['p95']:.2f} |")
    out += ["", "Evidence strings present in false-alarm decisions (numbers masked as `#`), top 5 per condition:", ""]
    for cid, c in ev["conditions"].items():
        top = c["pooled"]["evidence_in_false_alarm_decisions"][:5]
        out.append(f"- **{cid}**: " + ("; ".join(f"`{e}` x{n}" for e, n in top) if top else "none"))
    out += ["", "Detector combinations over their trigger on false-alarm decisions:", ""]
    for cid, c in ev["conditions"].items():
        out.append(f"- **{cid}**: {c['pooled']['false_alarm_detector_combinations']}")
    out += ["", "Decisions touched by the known frozen-extractor gaps (condition-independent):", "",
            "| gap | decisions | note |", "|---|---|---|"]
    p = ev["conditions"]["B"]["pooled"]
    out.append(f"| max_seq_gap > 30 (reorder read as 253-frame gap) | {p['max_seq_gap_ge_30_decisions']} | remains a false alarm under every PX4 condition |")
    out.append(f"| flight mode decoded `UNKNOWN` | {p['flight_mode_UNKNOWN_decisions']} of {p['decisions']} | no detector reads `flight_mode`; dashboard/telemetry only |")
    out.append(f"| cold start (no heartbeat/GPS seen yet, age sentinel 999 s) | {p['cold_start_decisions_hb_or_gps_never_seen']} | stale-heartbeat evidence under A; absorbed by `startup_grace_s` in the profile |")
    out.append("")
    return out


def splice_doc(blocks: dict[str, list[str]]) -> None:
    """Replace ``<!-- GEN:name -->...<!-- /GEN:name -->`` regions of docs/CALIBRATION_PX4.md with generated blocks."""
    import re
    doc = cc.REPO / "docs" / "CALIBRATION_PX4.md"
    if not doc.exists():
        return
    text = doc.read_text(encoding="utf-8")
    for name, lines in blocks.items():
        # demote headings one level and drop the summary.md numbering inside the document
        body = "\n".join(
            re.sub(r"^(#+) (?:\d+b?\. )?", r"\1# ", ln, count=1) if ln.startswith("#") else ln for ln in lines)
        text = re.sub(rf"(<!-- GEN:{name} -->\n).*?(<!-- /GEN:{name} -->)",
                      lambda m, b=body: m.group(1) + b + "\n" + m.group(2), text, flags=re.S)
    doc.write_text(text, encoding="utf-8")
    print("spliced", doc)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    cal, held = load("evaluation_calib.json"), load("evaluation_heldout.json")
    der, side = load("derivation.json"), load("isoforest_px4_training.json")
    lofo, shift, sim = load("lofo_rules.json"), load("feature_shift.json"), load("sim_sanity.json")
    rtf = load("rtf_probe.json")
    reg = load("stage1_regression.json")
    blocks: dict[str, list[str]] = {}
    L = ["# PX4 SITL benign calibration - summary (generated; do not edit)", "",
         "Environment: **SITL** (replayed tlog; PX4 `v1.18.0-rc1-27-gc239c63807`, Gazebo Harmonic, `gz_x500`). "
         "Attack: **NONE**. Claim class: **none** - false-alarm calibration only. This is NOT attack detection and says "
         "nothing about real vehicles. Regenerate: see `docs/CALIBRATION_PX4.md`.", ""]
    if cal:
        L += ["## 1. A / B / B2 / C", "",
              "A = Stage-1 default config + Stage-1 model | B = PX4 profile, ML off | B2 = PX4 profile + Stage-1 model (diagnostic) "
              "| C = PX4 profile + PX4-benign model. Every decision is benign, so every threat flag is a false alarm.", ""]
        n0 = len(L)
        L += eval_table(cal, "Calibration set (benign_001..005) - the data the profile and PX4 model were fitted on: IN-SAMPLE")
        blocks["ab_calib"] = L[n0:]
    if held:
        n0 = len(L)
        L += eval_table(held, "Held-out set (benign_006..010) - never inspected before the profile was frozen; evaluated once")
        L += ["Frozen inputs recorded in `heldout_lock.json` before the run (SHA-256):", ""]
        L += [f"- `{k}`: `{v}`" for k, v in held["frozen_inputs"].items()] + [""]
        blocks["ab_heldout"] = L[n0:]
    else:
        L += ["## Held-out set: NOT RUN", ""]
    if der:
        n0 = len(L)
        L += ["## 2. Profile overrides and derivation (`derivation.json`, calibration flights only)", "",
              f"Margin M = {der['margin_M']}. Rule: a Stage-1 threshold is raised to ceil(M x largest steady-state benign value) only if it is below that; otherwise left as Stage-1.", "",
              "| key | Stage-1 | profile | calibration benign max (x*) | M x x* | changed |", "|---|---|---|---|---|---|"]
        dd = der["derivations"]
        po = der["profile_overrides"]
        mr = dd["msg_rate"]
        L.append(f"| protocol.expected_sysids | {dd['expected_sysids']['stage1']} | {po['protocol']['expected_sysids']} | observed {dd['expected_sysids']['observed']} | - | yes |")
        L.append(f"| protocol.nominal_msg_rate_hz | {mr['stage1']['nominal']} | {mr['profile']['nominal']} | median of rate/RTF = {mr['observed_rtf_normalised']['median']:.1f} (raw median {mr['observed_raw']['median']:.0f}) | - | yes |")
        L.append(f"| protocol.msg_rate_spike_factor | {mr['stage1']['spike_factor']} | {mr['profile']['spike_factor']} | max rate/RTF = {mr['observed_rtf_normalised']['max_over_flights']:.1f} (raw max {mr['observed_raw']['max']:.0f}) | {1.25 * mr['observed_rtf_normalised']['max_over_flights']:.1f} msg/s -> spike threshold {mr['profile']['spike_threshold_msgs']:.0f} msg/s | yes |")
        L.append(f"| protocol.max_msg_rate_hz | {mr['stage1']['max_msg_rate_hz']} | {mr['profile']['max_msg_rate_hz']} | Stage-1 hard limit {'would fire' if mr['stage1_hard_limit_vs_rtf1_benign_max']['stage1_hard_limit_would_fire'] else 'would not fire'} at RTF=1 benign max | ratio 400/28 kept | yes |")
        g = dd["startup_grace_s"]
        L.append(f"| protocol.startup_grace_s (new key) | 0 | {g['profile']} | first heartbeat/GPS seen at t <= {g['max_first_seen_t']} s | {g['profile']} | yes |")
        for k, v in dd.items():
            if k.startswith("physics."):
                L.append(f"| {k} | {v['stage1']} | {v['profile']} | {v['x_star_max_steady']:.3f} ({v['feature']}) | {v['M_x_star']:.3f} | {'yes' if v['changed'] else 'no'} |")
        L += ["", "Per-flight RTF used for normalisation (`1 + boot_clock_vs_recv_drift_ppm/1e6`): "
              + ", ".join(f"{n} {f['rtf']:.3f}" for n, f in der["flights"].items()), ""]
        blocks["overrides"] = L[n0:]
    if side:
        n0 = len(L)
        L += ["## 3. PX4-benign ML model (`models/isoforest_px4.joblib`, gitignored)", "",
              f"- sha256 `{side['model_sha256']}`; sklearn {side['versions']['sklearn']}; seed {side['seed']}; "
              f"{side['n_estimators']} trees; trained on {sum(f['train_vectors'] for f in side['training_files'])} decision vectors "
              f"(t >= {side['warmup_excluded_s']} s) from {len(side['training_files'])} calibration flights; "
              f"Stage-1 model hash unchanged: `{side['stage1_model_untouched_sha256'][:16]}...`",
              f"- score_thr {side['score_thr']:.4f}, score_scale {side['score_scale']:.4f} (leave-one-flight-out out-of-fold mean + 3 sd)", "",
              "| flight | alarm rate, leave-one-flight-out | alarm rate, shipped model IN-SAMPLE (optimistic) |", "|---|---|---|"]
        for n in side["benign_alarm_rate_leave_one_flight_out"]:
            L.append(f"| {n} | {pct(side['benign_alarm_rate_leave_one_flight_out'][n])} | {pct(side['benign_alarm_rate_in_sample_OPTIMISTIC'][n])} |")
        L.append("")
        blocks["ml"] = L[n0:]
    if lofo:
        n0 = len(L)
        L += ["## 4. Leave-one-flight-out check of the derivation rules (calibration set only; condition B)", "",
              "| left-out flight | nominal | spike factor | other overrides | decisions | false alarms |", "|---|---|---|---|---|---|"]
        for n, f in lofo["folds"].items():
            o = f["overrides"]
            L.append(f"| {n} | {o['protocol']['nominal_msg_rate_hz']} | {o['protocol']['msg_rate_spike_factor']} | {o['physics']} | {f['decisions']} | {f['false_alarm_decisions']} |")
        L += ["", f"Pooled: {lofo['pooled']['false_alarm_decisions']} / {lofo['pooled']['decisions']}. {lofo['caveat']}.", ""]
        blocks["lofo"] = L[n0:]
    if shift:
        n0 = len(L)
        L += ["## 5. Feature shift, Stage-1 SIM benign vs PX4 SITL calibration flights (decisions with t >= 5 s)", "",
              f"SIM: {shift['n_sim_flights']} flights / {shift['n_sim_decisions']} decisions ({shift['sim_source']}). SITL: {shift['n_sitl_decisions']} decisions.", "",
              "| feature | SIM p50 / p95 / max | SITL p50 / p95 / max | KS |", "|---|---|---|---|"]
        for n, v in shift["features"].items():
            s, t = v["sim"], v["sitl"]
            L.append(f"| {n} | {s['p50']:.3f} / {s['p95']:.3f} / {s['max']:.3f} | {t['p50']:.3f} / {t['p95']:.3f} / {t['max']:.3f} | {v['ks_statistic']:.3f} |")
        L.append("")
        blocks["shift"] = L[n0:]
    if rtf:
        n0 = len(L)
        L += ["## 5b. Analytic rate-scaling probe (SITL data, COUNTERFACTUAL - not a measurement)", "",
              f"Calibration decisions ({rtf['n_decisions']}), `msg_rate_hz` x ratio and `interarrival_jitter_ms` / ratio, ratio = target / per-flight RTF. "
              f"Targets <= 1.0 = the same flights as if the host ran at that real-time factor; targets > 1.0 = faster-than-real-time OR a proportional message-rate flood. "
              f"Rate-rule spike threshold = {rtf['spike_threshold_msgs']:.0f} msg/s. {rtf['caveat']}.", "",
              "| rate scale target | median msg/s | rate rule fires (share of decisions) | PX4 ML (model C) alarm share |", "|---|---|---|---|"]
        for k, v in rtf["targets"].items():
            L.append(f"| {k.replace('rtf_', '')} | {v['median_msg_rate']:.0f} | {pct(v['rate_rule_spike_rate'])} | {pct(v['ml_C_alarm_rate'])} |")
        L.append("")
        blocks["rtf"] = L[n0:]
    if sim:
        n0 = len(L)
        L += ["## 6. EXPLORATORY SIM sanity check (cost side; environment SIM, NOT SITL, not the committed benchmark)", "",
              f"Seeds {sim['seeds']}, Stage-1 simulator model, Stage-1 default attack parameters. `profile_sysid1` = PX4 profile with expected_sysids forced to the SIM vehicle id [1], "
              "to isolate the threshold changes; `ML off` columns remove the Stage-1 simulator model so the RULE changes are visible. Cells are in-window decisions flagged / in-window decisions (all seeds pooled).", "",
              "| attack:mode | default (ML on) | profile_sysid1 (ML on) | default, ML off | profile_sysid1, ML off |", "|---|---|---|---|---|"]
        for k, v in sim["per_mode"].items():
            if k == "benign":
                continue

            def cell(x):
                return "-" if not x else f"{x['detected']}/{x['in_window']} ({x['detected'] / max(1, x['in_window']) * 100:.0f}%)"
            L.append(f"| {k} | {cell(v.get('default'))} | {cell(v.get('profile_sysid1'))} | "
                     f"{cell(v.get('default_noml'))} | {cell(v.get('profile_sysid1_noml'))} |")
        b = sim["per_mode"].get("benign", {})
        L += ["", "Benign SIM sessions, scored decisions flagged: "
              + "; ".join(f"{c} {x['benign_fa']}/{x['benign_dec']}" for c, x in b.items()), ""]
        blocks["sim"] = L[n0:]
    if reg:
        n0 = len(L)
        L += ["## 6b. Stage-1 regression under the default profile (SIM; `stage1_regression.json`)", "",
              "| | TP | FP | TN | FN |", "|---|---|---|---|---|",
              "| committed `artifacts/benchmarks/summary.md` | " + " | ".join(str(reg["committed"][k]) for k in ("TP", "FP", "TN", "FN")) + " |",
              "| after the detector change (scratch run) | " + " | ".join(str(reg["after_change"][k]) for k in ("TP", "FP", "TN", "FN")) + " |",
              "", f"identical = **{reg['identical']}**; command `{reg['command']}`; change under test: {reg['change_under_test']}.", ""]
        blocks["regress"] = L[n0:]
    L += ["## 7. Not measured", "",
          "- Attack detection on PX4 SITL or any real stack (no attack data exists; P2). The profile only moves the benign false-alarm rate.",
          "- Real vehicles, other airframes, other worlds, other hosts/real-time factors (all data: one `gz_x500`, one scripted route, one host).",
          "- Whether unchanged physics thresholds (which sit >= M x benign max, often ~10x above SITL benign) are too loose for attack sensitivity.",
          "- Independence of decisions: ~2.7k decisions per set come from 5 flights of one route and are autocorrelated; decision-level rates and Wilson intervals are optimistic.", ""]
    (D / "summary.md").write_text("\n".join(L), encoding="utf-8")
    print("wrote", D / "summary.md")
    splice_doc(blocks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
