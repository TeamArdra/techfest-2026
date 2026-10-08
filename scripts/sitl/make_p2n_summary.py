"""Aggregate P2 GNSS-fix-degradation live-SITL trial manifests into a generated summary
(no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2n_summary.py \
        "artifacts/sitl/p2n_n10_trial_*.manifest.json" --out artifacts/sitl/P2_gnss_summary.md

Environment: SITL. Claim class: **link-level detection** only -- the relay rewrites
``GPS_RAW_INT.fix_type``/``satellites_visible`` on the downlink the IDS tap sees; PX4 itself is the
sender, its estimator and flight are untouched (vehicle disarmed on the ground, no flight driver).
No estimator effect, no physical deviation, no real GNSS jamming/RF, no signing claim.

Scoring definitions (fixed BEFORE any live GNSS trial was run; not tuned afterwards):
* detected      = a threat decision whose evidence contains "GNSS fix lost" at t in
                  [onset, onset + duration + 5 s].
* values match  = every in-window "GNSS fix lost" evidence string reports exactly the drawn
                  (fix_type, satellites) -- an end-to-end check that the detector saw the bytes
                  the attack wrote (independent of the manifest's recorded deltas).
* false alarm   = a threat decision (any type) at t < onset; the GNSS-rule-specific count
                  ("GNSS fix lost" before onset) is reported separately.
Integrity gates (a trial violating them is reported but NOT scored as evidence about the
detector): relay ``hook_errors == 0``; ``frames_modified > 0``; the manifest's ``frames_modified``
equals the frame-log's; exactly one distinct fix_type delta and one satellites delta written;
``frames_skipped_signed == 0``.
Time `t` of decisions is on the IDS clock and the attack onset on the relay's first-vehicle-frame
clock (same convention and same small offset as make_p2dd_summary.py).
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import statistics
from pathlib import Path

TAIL_S = 5.0
_EV = re.compile(r"GNSS fix lost: fix_type=(\d+), satellites=(\d+)")


def _gnss_ev(row: dict) -> list[str]:
    return [e for e in row["evidence"] if "GNSS fix lost" in e]


def load_trial(manifest_path: Path) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    p = m["parameters"]
    onset, dur = p["onset_s"], p["duration_s"]
    hi = onset + dur + TAIL_S
    pre = [r for r in rows if r["t"] < onset]
    win = [r for r in rows if onset <= r["t"] <= hi]
    det = [r for r in win if r["threat"] and _gnss_ev(r)]
    fa = [r for r in pre if r["threat"]]
    fa_gnss = [r for r in pre if _gnss_ev(r)]
    vals = [_EV.search(e) for r in det for e in _gnss_ev(r)]
    vals_ok = bool(vals) and all(
        v and (int(v.group(1)), int(v.group(2))) == (p["fix_type"], p["satellites_visible"]) for v in vals)
    rs = m["ids_summary"]["relay_stats"]
    eff = m.get("actual_effect") or {}
    integrity_ok = (rs["hook_errors"] == 0 and m["frames_modified"] > 0
                    and m["frames_modified"] == eff.get("frames_modified")
                    and len(eff.get("fix_type_deltas_written", [])) == 1
                    and len(eff.get("satellites_visible_deltas_written", [])) == 1
                    and m.get("frames_skipped_signed", 0) == 0)
    return {
        "trial": m["trial_id"], "idx": m["trial_index"], "onset": round(onset, 2), "dur": round(dur, 2),
        "fix": p["fix_type"], "sats": p["satellites_visible"], "hook_errors": rs["hook_errors"],
        "frames_modified": m["frames_modified"], "integrity_ok": integrity_ok,
        "pre_decisions": len(pre), "fa_pre": len(fa), "fa_gnss_pre": len(fa_gnss),
        "detected": bool(det), "values_ok": vals_ok,
        "latency_from_onset": round(det[0]["t"] - onset, 2) if det else None,
        "n_win_gnss": len(det),
        "types": sorted({r["type"] for r in win if r["threat"]}),
        # chronological, not sorted lexically
        "ev": [e for r in sorted(win, key=lambda r: r["t"]) if r["threat"] for e in r["evidence"]][:2],
        "post_other": len([r for r in rows if r["t"] > hi and r["threat"]]),
        "model": p.get("model_choice"), "profile": p.get("detector_profile"),
        "commit": (m.get("full_provenance") or {}).get("aegisflight_commit"),
        "dirty": (m.get("full_provenance") or {}).get("dirty_paths_count"),
        "px4": (m.get("provenance") or {}).get("px4_git_describe"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifests", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    paths = sorted({Path(p) for pat in a.manifests for p in glob.glob(pat)})
    T = [load_trial(p) for p in paths]
    if not T:
        print("no manifests matched")
        return 1
    ok = [t for t in T if t["integrity_ok"]]
    det = sum(t["detected"] for t in ok)
    vok = sum(t["values_ok"] for t in ok if t["detected"])
    pre_n = sum(t["pre_decisions"] for t in ok)
    fa_n = sum(t["fa_pre"] for t in ok)
    fag_n = sum(t["fa_gnss_pre"] for t in ok)
    lat = [t["latency_from_onset"] for t in ok if t["latency_from_onset"] is not None]
    L = ["# P2 GNSS-degradation summary - live SITL trials (generated; do not edit)", "",
         "Environment: **SITL**. Attack: `GPS_RAW_INT.fix_type`/`satellites_visible` rewritten below the protocol "
         "rule's thresholds for a window (position fields untouched). Claim class: **link-level detection** only "
         "(vehicle disarmed on the ground; PX4 is the sender and its estimator is unaffected; not real GNSS "
         "jamming, no estimator/physical/signing claim). "
         "Regenerate: `scripts/sitl/make_p2n_summary.py <manifests> --out <this file>`.", "",
         f"- Trials: **{len(T)}**; passing the integrity gates: **{len(ok)}**.",
         f"- **Link-level detection (SITL): {det}/{len(ok)}** integrity-passing trials ('GNSS fix lost' evidence "
         "in [onset, onset+duration+5s]).",
         f"- Detector-saw-the-written-bytes check (evidence fix_type/satellites == drawn values): "
         f"**{vok}/{det}** detected trials.",
         f"- Pre-onset false alarms, any threat (integrity-passing trials pooled): **{fa_n}/{pre_n}** decisions; "
         f"GNSS-rule-specific pre-onset evidence: **{fag_n}**.",
         (f"- Time from onset to first GNSS detection: median {statistics.median(lat):.2f} s, "
          f"min {min(lat):.2f} s, max {max(lat):.2f} s (n={len(lat)})." if lat else
          "- No trial detected; no latency to report."), ""]
    bad = [t for t in T if not t["integrity_ok"]]
    if bad:
        L += ["**Integrity-gate failures (NOT scored as evidence about the detector):** " +
              ", ".join(f"{t['trial']} (hook_errors={t['hook_errors']}, frames_modified={t['frames_modified']})"
                        for t in bad), ""]
    L += ["| trial | idx | onset s | dur s | fix_type | sats | frames modified | hook_errors | pre-onset FA | "
          "pre-onset GNSS ev. | detected | values match | latency s | GNSS-evidence decisions in window | "
          "types | evidence (sample) |", "|" + "---|" * 16]
    for t in T:
        L.append(f"| {t['trial']} | {t['idx']} | {t['onset']} | {t['dur']} | {t['fix']} | {t['sats']} | "
                 f"{t['frames_modified']} | {t['hook_errors']} | {t['fa_pre']}/{t['pre_decisions']} | "
                 f"{t['fa_gnss_pre']} | {'yes' if t['detected'] else 'NO'} | "
                 f"{'yes' if t['values_ok'] else ('-' if not t['detected'] else 'NO')} | "
                 f"{t['latency_from_onset']} | {t['n_win_gnss']} | {', '.join(t['types']) or '-'} | "
                 f"{'; '.join(x[:60] for x in t['ev']) or '-'} |")
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
          "- The attack writes values far below the rule's thresholds (fix_type 0-1, satellites 0-4 vs 3 / 5) "
          "by design: this is a positive control for the dedicated GNSS-fix-loss rule on live PX4 data, NOT a "
          "sensitivity measurement. A subtle degradation (e.g. fix_type 3 with 5 satellites, or a slow decline) "
          "was not tested.",
          "- Detection is **link-level**: the IDS sees the degraded status the proxy put on its tap; it says "
          "nothing about how PX4 or a real receiver behaves under jamming."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
