"""Aggregate P2 DROP / DELAY live-SITL trial manifests into a generated summary
(no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2dd_summary.py --attack drop \
        "artifacts/sitl/p2d_n10_trial_*.manifest.json" --out artifacts/sitl/P2_drop_summary.md
    .venv/Scripts/python.exe scripts/sitl/make_p2dd_summary.py --attack delay \
        "artifacts/sitl/p2l_n10_trial_*.manifest.json" --out artifacts/sitl/P2_delay_summary.md

Environment: SITL. Claim class: **link-level detection** only -- the relay manipulates what the IDS tap
sees of PX4's downlink; PX4 itself is the sender and is mechanically unaffected. No estimator effect, no
physical deviation, no signing claim. The vehicle is disarmed on the ground (no flight driver, same as
the GPS-drift batch and the pilots), so the downlink carries a static-vehicle stream.

Scoring definitions (fixed BEFORE the n=10 results were read; not tuned afterwards):
* DROP detected  = a threat decision whose evidence contains "GPS dropout" at t in
  [onset, onset + duration + 5 s].
* DELAY detected = any threat decision at t in [onset, onset + duration + delay + 5 s] (the delay's effect
  tails off ~delay_s after the window as the backlog drains in order).
* false alarm    = a threat decision at t < onset.
Integrity gates (reported separately; a trial violating them is not scored as evidence about the
detector): relay `hook_errors == 0`, and no frames left held at the end (`frames_down - forwarded_down`
must equal `dropped_by_hook` for drop and 0 for delay).
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
from pathlib import Path

TAIL_S = 5.0


def load_trial(manifest_path: Path, attack: str) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    p = m["parameters"]
    onset, dur = p["onset_s"], p["duration_s"]
    delay = p.get("delay_s", 0.0) if attack == "delay" else 0.0
    end = onset + dur
    hi = end + delay + TAIL_S
    pre = [r for r in rows if r["t"] < onset]
    win = [r for r in rows if onset <= r["t"] <= hi]
    if attack == "drop":
        det = [r for r in win if r["threat"] and any("GPS dropout" in e for e in r["evidence"])]
    else:
        det = [r for r in win if r["threat"]]
    fa = [r for r in pre if r["threat"]]
    post_other = [r for r in rows if r["t"] > hi and r["threat"]]
    rs = m["ids_summary"]["relay_stats"]
    eff = m.get("actual_effect") or {}
    held_end = rs["frames_down"] - rs["forwarded_down"]
    integrity_ok = rs["hook_errors"] == 0 and (
        held_end == rs["dropped_by_hook"] if attack == "drop" else held_end == 0)
    return {
        "trial": m["trial_id"], "idx": m["trial_index"], "onset": round(onset, 2), "dur": round(dur, 2),
        "delay": round(delay, 3), "effect": eff, "hook_errors": rs["hook_errors"], "held_end": held_end,
        "frames_dropped": m["frames_dropped"], "dropped_by_hook": rs["dropped_by_hook"],
        "integrity_ok": integrity_ok, "decisions": len(rows), "pre_decisions": len(pre), "fa_pre": len(fa),
        "detected": bool(det), "first_t": round(det[0]["t"], 2) if det else None,
        "latency_from_onset": round(det[0]["t"] - onset, 2) if det else None,
        "n_win_threat": len([r for r in win if r["threat"]]),
        "types": sorted({r["type"] for r in win if r["threat"]}),
        # first 3 evidence strings in CHRONOLOGICAL order (not sorted -- a lexical sort would put
        # "10.0s" before "2.0s" and mislead about what was actually seen first)
        "ev": [e for r in sorted(win, key=lambda r: r["t"]) if r["threat"] for e in r["evidence"]][:3],
        "post_other": len(post_other),
        "model": p.get("model_choice"), "profile": p.get("detector_profile"),
        "commit": (m.get("full_provenance") or {}).get("aegisflight_commit"),
        "dirty": (m.get("full_provenance") or {}).get("dirty_paths_count"),
        "px4": (m.get("provenance") or {}).get("px4_git_describe"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--attack", choices=("drop", "delay"), required=True)
    ap.add_argument("manifests", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    paths = sorted({Path(p) for pat in a.manifests for p in glob.glob(pat)})
    T = [load_trial(p, a.attack) for p in paths]
    if not T:
        print("no manifests matched")
        return 1
    ok = [t for t in T if t["integrity_ok"]]
    det = sum(t["detected"] for t in ok)
    pre_n = sum(t["pre_decisions"] for t in ok)
    fa_n = sum(t["fa_pre"] for t in ok)
    lat = [t["latency_from_onset"] for t in ok if t["latency_from_onset"] is not None]
    name = "DROP (downlink GLOBAL_POSITION_INT + GPS_RAW_INT suppression)" if a.attack == "drop" else \
        "DELAY (all unsigned downlink frames held a fixed delay, released in order)"
    L = [f"# P2 {a.attack.upper()} summary - live SITL trials (generated; do not edit)", "",
         f"Environment: **SITL**. Attack: {name}. Claim class: **link-level detection** only (the vehicle is "
         "disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). "
         f"Regenerate: `scripts/sitl/make_p2dd_summary.py --attack {a.attack} <manifests> --out <this file>`.", "",
         f"- Trials: **{len(T)}**; passing the integrity gates: **{len(ok)}** "
         f"(`hook_errors == 0` and no frames left held).",
         f"- **Link-level detection (SITL): {det}/{len(ok)}** integrity-passing trials "
         f"({'GPS-dropout evidence' if a.attack == 'drop' else 'any threat decision'} in the scoring window).",
         f"- Pre-onset false alarms (integrity-passing trials pooled): **{fa_n}/{pre_n}** decisions.",
         (f"- Time from onset to first detection: median {statistics.median(lat):.2f} s, "
          f"min {min(lat):.2f} s, max {max(lat):.2f} s (n={len(lat)})." if lat else
          "- No trial detected; no latency to report."), ""]
    bad = [t for t in T if not t["integrity_ok"]]
    if bad:
        L += ["**Integrity-gate failures (NOT scored as evidence about the detector):** " +
              ", ".join(f"{t['trial']} (hook_errors={t['hook_errors']}, held_at_end={t['held_end']})" for t in bad), ""]
    L += ["| trial | idx | onset s | dur s | " + ("delay s | " if a.attack == "delay" else "") +
          ("frames dropped | " if a.attack == "drop" else "frames delayed | ") +
          "hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | "
          "evidence (sample) |",
          "|" + "---|" * (14 if a.attack == "delay" else 13)]
    for t in T:
        e = t["effect"]
        nfr = e.get("frames_dropped") if a.attack == "drop" else e.get("frames_delayed")
        L.append(f"| {t['trial']} | {t['idx']} | {t['onset']} | {t['dur']} | " +
                 (f"{t['delay']} | " if a.attack == "delay" else "") +
                 f"{nfr} | {t['hook_errors']} | {t['held_end']} | {t['fa_pre']}/{t['pre_decisions']} | "
                 f"{'yes' if t['detected'] else 'NO'} | {t['latency_from_onset']} | {t['n_win_threat']} | "
                 f"{', '.join(t['types']) or '-'} | {'; '.join(x[:60] for x in t['ev']) or '-'} |")
    post = sum(t["post_other"] for t in T)
    L += ["", "## Provenance",
          f"- PX4: {sorted({str(t['px4']) for t in T})}; detector profile {sorted({str(t['profile']) for t in T})}, "
          f"model {sorted({str(t['model']) for t in T})}; aegisflight commit {sorted({str(t['commit'])[:7] for t in T})}; "
          f"`src`/`scripts`/`configs` dirty-path counts {sorted({t['dirty'] for t in T})} "
          "(uncommitted changes at run time; not a clean-commit reproduction until committed).",
          f"- Threat decisions after the scoring window (not attributed to the attack): {post}.", "",
          "## Limitations",
          "- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; "
          "fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.",
          "- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped "
          "on, nothing about vehicle behaviour."]
    if a.attack == "delay":
        L += ["- The scoring window counts ANY threat decision; a decision need not be caused by the delay "
              "(see types/evidence per trial). Absence of detection is a legitimate, reported result: the "
              "delay changes arrival times, not content or sequence, so little detector signal is expected."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
