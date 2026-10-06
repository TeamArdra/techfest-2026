"""Aggregate P2 live-attack trial manifests into artifacts/sitl/P2_summary.md (no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2_summary.py artifacts/sitl/p2_trial_*.manifest.json

Environment: SITL. Attack: downlink GLOBAL_POSITION_INT gradual drift (docs/ATTACK_PROXY.md Sec3).
Claim class: link-level detection (SITL) only -- PX4 never receives a modified frame (the
relay's up_hook is passthrough); this is NOT GPS spoofing of the vehicle and says nothing
about MAVLink signing (the link is unsigned).

For each trial, joins the IDS decisions (``<trial>.ids_decisions.jsonl``) against the attack
window from the manifest to compute: any false alarm outside the window, whether a
GPS_SPOOFING / threat decision occurred inside-or-just-after the window, and time-to-first-
detection measured from attack *end* (pos_residual_m is a running sum -- see
docs/STAGE2_PROGRESS.md -- so "time from onset" would conflate drift duration with detector
latency; both are reported).
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
from pathlib import Path


def load_trial(manifest_path: Path) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    onset, dur = m["parameters"]["onset_s"], m["parameters"]["duration_s"]
    end = onset + dur
    pre = [r for r in rows if r["t"] < onset]
    post = [r for r in rows if r["t"] >= end]
    false_alarms_pre = [r for r in pre if r["threat"]]
    detections_post = [r for r in post if r["threat"] and r["type"] == "GPS_SPOOFING"]
    other_post = [r for r in post if r["threat"] and r["type"] != "GPS_SPOOFING"]
    ttd_from_end = (detections_post[0]["t"] - end) if detections_post else None
    ttd_from_onset = (detections_post[0]["t"] - onset) if detections_post else None
    return {
        "trial": m["trial_id"], "seed": m["seed"], "trial_index": m["trial_index"],
        "onset_s": round(onset, 2), "duration_s": round(dur, 2), "drift_rate_ms": round(m["parameters"]["drift_rate_ms"], 3),
        "bearing_deg": round(m["parameters"]["bearing_deg"], 1),
        "expected_max_displacement_m": round(m["expected_effect"]["max_displacement_m"], 2),
        "actual_max_displacement_m": round(m["actual_effect"]["max_lat_lon_delta_m"], 2) if m["actual_effect"] else None,
        "frames_seen": m["frames_seen"], "frames_modified": m["frames_modified"],
        "frames_dropped": m["frames_dropped"], "frames_injected": m["frames_injected"],
        "frames_skipped_signed": m["frames_skipped_signed"],
        "decisions_total": len(rows), "decisions_pre_onset": len(pre),
        "false_alarms_pre_onset": len(false_alarms_pre),
        "detected_gps_spoofing_post": len(detections_post) > 0,
        "other_threat_types_post": sorted({r["type"] for r in other_post}),
        "time_to_detection_from_end_s": round(ttd_from_end, 2) if ttd_from_end is not None else None,
        "time_to_detection_from_onset_s": round(ttd_from_onset, 2) if ttd_from_onset is not None else None,
        "model_choice": m["parameters"].get("model_choice"), "profile": m["parameters"].get("detector_profile"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifests", nargs="+", help="glob(s) for *.manifest.json")
    ap.add_argument("--out", default="artifacts/sitl/P2_summary.md")
    a = ap.parse_args(argv)

    paths = sorted({Path(p) for pat in a.manifests for p in glob.glob(pat)})
    trials = [load_trial(p) for p in paths]
    if not trials:
        print("no trial manifests matched")
        return 1

    detected = sum(t["detected_gps_spoofing_post"] for t in trials)
    fa = sum(t["false_alarms_pre_onset"] for t in trials)
    ttd = [t["time_to_detection_from_end_s"] for t in trials if t["time_to_detection_from_end_s"] is not None]
    L = ["# P2 summary - first live attack trials on PX4 SITL (generated; do not edit)", "",
        "Environment: **SITL**. Attack: downlink `GLOBAL_POSITION_INT` gradual drift "
        "(`docs/ATTACK_PROXY.md` Sec3). Claim class: **link-level detection (SITL) only** -- PX4 never "
        "receives a modified frame; this is not GPS spoofing of the vehicle and says nothing about signing.",
        f"Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p2_summary.py {' '.join(a.manifests)}`.", "",
        f"**{detected}/{len(trials)} trials**: a `GPS_SPOOFING` decision fired at or after the attack window closed, "
        f"with **{fa} false alarms** in any trial's pre-onset (benign) portion "
        f"({sum(t['decisions_pre_onset'] for t in trials)} pre-onset decisions pooled).",
        f"Time-to-detection from attack end: n={len(ttd)}"
        + (f", mean={statistics.mean(ttd):.2f}s, median={statistics.median(ttd):.2f}s, "
           f"min={min(ttd):.2f}s, max={max(ttd):.2f}s" if ttd else " (no detections)"), "",
        "| trial | onset s | dur s | rate m/s | bearing | expected m | actual m | frames mod | pre-onset FA | "
        "detected | ttd-from-end s | other threat types |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for t in trials:
        L.append(f"| {t['trial']} | {t['onset_s']} | {t['duration_s']} | {t['drift_rate_ms']} | {t['bearing_deg']} | "
                 f"{t['expected_max_displacement_m']} | {t['actual_max_displacement_m']} | {t['frames_modified']} | "
                 f"{t['false_alarms_pre_onset']} | {'yes' if t['detected_gps_spoofing_post'] else 'NO'} | "
                 f"{t['time_to_detection_from_end_s']} | {t['other_threat_types_post'] or '-'} |")
    L += ["", "## Limitations",
         "- n reflects however many trials have completed when this was last regenerated; a small n (as called for "
         "by the design, >=10) is not a statistically powerful sample -- report counts, not a rate with confidence bounds.",
         "- All trials share one scripted benign-flight-free attack window on one airframe/world/host; this is not "
         "independent of host load (see `docs/PX4_SITL_INTEGRATION.md` Sec2 on RTF variability).",
         "- `pos_residual_m` is a running sum (see module docstring); time-to-detection-from-end conflates drift "
         "duration with detector latency less than time-to-detection-from-onset does, but neither is a clean "
         "'alarm latency' figure independent of this attack's own duration parameter.",
         "- No claim about PX4's own trajectory/estimator: the relay's uplink stays passthrough by construction.",
         "- No comparison yet against the Stage-1 *simulated* `gps_spoofing` attack class recall (different injection point)."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(Path(a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
