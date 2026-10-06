"""Generate artifacts/sitl/P1_summary.md from the P1 JSON artifacts (no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p1_summary.py

Inputs (all produced by scripts/sitl/*): benign_00N.json (manifests),
benign_00N_stream_stats.json, benign_replay_stage1_default*.json,
live_run_001.summary.json, live_run_001_offline_replay.json.
Environment tags: SITL (live UDP) and SITL (replayed tlog). Attack: NONE.
"""

from __future__ import annotations

import json
from pathlib import Path

ART = Path("artifacts/sitl")
RAW = Path("data/sitl/raw")


def jl(p: Path):
    return json.loads(p.read_text())


def main() -> int:
    L: list[str] = ["# P1 summary - benign PX4 SITL (generated; do not edit)", "",
                    "Environment: **SITL**. Attack: **NONE**. Claim class: none (reference / false-alarm measurement).",
                    "Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p1_summary.py`.", ""]
    man = [jl(p) for p in sorted(RAW.glob("benign_00[1-5].json"))]
    L += [f"PX4: `{man[0]['px4_git_describe']}` (release candidate, not a stable tag) | Gazebo `{man[0]['gazebo']}` | "
          f"model `{man[0]['sim_model']}` | vehicle sysid/compid `{man[0]['vehicle']['sysid']}/{man[0]['vehicle']['compid']}`", "",
          "## Captures (artifacts/sitl/benign_00N_stream_stats.json, data/sitl/raw/benign_00N.json)", "",
          "| flight | frames | dur s | frames/s | SITL clock vs wall (ppm) | mean RTF (=1+ppm/1e6) | fwd seq gaps | reordered | net missing | duplicates | signed |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for m in man:
        n = m["tlog"].split(".")[0]
        s = jl(ART / f"{n}_stream_stats.json")
        src = next(iter(s["sources"].values()))
        L.append(f"| {n} | {s['frames']} | {s['duration_s']} | {s['frames'] / s['duration_s']:.1f} | "
                 f"{s['boot_clock_vs_recv_drift_ppm']} | {1 + s['boot_clock_vs_recv_drift_ppm'] / 1e6:.3f} | {src['seq_forward_gaps']} | {src['seq_reordered']} | {src['seq_net_missing']} | {src['seq_duplicates']} | {s['signed_frames']} |")
    L += ["", "## Stage-1 default detectors on benign SITL (artifacts/sitl/benign_replay_stage1_default*.json)", "",
          "| adapter | flight | decisions | false-alarm decisions | classes | protocol trig | physics trig | ML trig |",
          "|---|---|---|---|---|---|---|---|"]
    for f, ad in (("benign_replay_stage1_default.json", "tlog (Stage-1 adapter)"),
                  ("benign_replay_stage1_default_liveparser.json", "live parser (header-first)")):
        d = jl(ART / f)
        for r in d["runs"] + [d["pooled"]]:
            t = r["detector_trigger_rate"]
            L.append(f"| {ad} | {r['flight']} | {r['decisions']} | {r['false_alarm_decisions']} | {r['pred_classes']} | "
                     f"{t['det_protocol_rule']:.3f} | {t['det_physics_consistency']:.3f} | {t['det_ml_anomaly']:.3f} |")
    d = jl(ART / "benign_replay_stage1_default_liveparser.json")["pooled"]["feature_summary"]
    L += ["", "## Feature shift (pooled, live parser; Stage-1 simulator values must be taken from `aegis benchmark` artifacts)", "",
          "| feature | p50 | p95 | max |", "|---|---|---|---|"]
    for k in ("msg_rate_hz", "interarrival_jitter_ms", "max_seq_gap", "pos_residual_m", "gps_vfr_speed_diff_ms",
              "gps_baro_alt_diff_m", "yaw_course_diff_deg", "loss_ratio"):
        v = d[k]
        L.append(f"| {k} | {v['p50']:.3f} | {v['p95']:.3f} | {v['max']:.3f} |")
    live = jl(ART / "live_run_002.summary.json")
    eq = jl(ART / "live_run_002_equivalence.json")
    prov = live.get("provenance", {})
    L += ["", "## Live UDP run vs offline replay of the same bytes (artifacts/sitl/live_run_002.*, *_equivalence.json)", "",
          f"- live: decisions={live['decisions']} threat_decisions={live['threat_decisions']} classes={live['classes']}",
          f"- source stats: {live['source_stats']}",
          f"- per-decision comparison: compared={eq['compared']} flag_mismatches={eq['threat_flag_mismatches']} "
          f"score_mismatches(>{eq['score_tol']})={eq['score_mismatches_over_tol']} max_abs_score_diff={eq['max_abs_score_diff']:.4g}; "
          f"offline-only t={eq['offline_only_t']} live-only t={eq['live_only_t']}",
          f"- caveat: {eq['caveat']}",
          "- the IDS is an ACTIVE link partner (sends the GCS heartbeat PX4 needs); the benign flight driver used a distinct sysid (254/191)",
          f"- decision latency (live, Windows, ML on): {live['decision_latency_ms']}",
          f"- provenance: commit `{prov.get('aegisflight_commit')}` dirty={prov.get('working_tree_dirty')} "
          f"model_sha256=`{prov.get('model_sha256')}` tlog_sha256=`{prov.get('tlog_sha256')}`"]
    out = ART / "P1_summary.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
