"""Aggregate P2 command-injection trial manifests into artifacts/sitl/P2_injection_summary.md
(no hand-typed numbers; every outcome sentence below is computed from the manifests/logs).

    .venv/Scripts/python.exe scripts/sitl/make_p2i_summary.py \
        artifacts/sitl/p2i_trial_*.manifest.json artifacts/sitl/p2i_fix_trial_*.manifest.json

Environment: SITL. Attack: uplink rogue `COMMAND_LONG` force-disarm (sysid 66/compid 200),
piggybacked on a real uplink frame, mirrored to the IDS tap (docs/ATTACK_PROXY.md injection
attack). Claims, never merged:
1. Command-path effect (SITL): did PX4 accept/ack the rogue command? (`actual_effect.acked`)
2. Link-level detection (SITL): did the IDS flag it (`COMMAND_INJECTION` / "command(s) from
   unexpected source" evidence) at or after the injection?  -- a SEPARATE question from (1).
3. Harness delivery: did each injected frame actually reach the IDS pipeline's input
   (`ids_ingest.jsonl`, rogue seq == injection index)?  Only a frame that reached the IDS can
   count for or against the detector.

Two batches are reported separately and must not be pooled:
* PRE-FIX (`p2i_trial_*`): relay mirrored an uplink frame (and anything the hook added to it) to
  every client EXCEPT its sender. The IDS tap sends its own heartbeat, so whenever that heartbeat
  carried the injection the IDS never received it. The carrier was not logged. The 5/10 detection
  split of this batch is a harness defect, not a detector/transport result.
* POST-FIX (`p2i_fix_trial_*`, manifests carry `injection_carriers`): hook-added frames are
  mirrored to ALL clients; the carrier of every injection is logged.

This topology also has two non-expected-GCS clients (carrier 252/193 and the benign flight driver
253/192) whose heartbeats trip the protocol detector's rogue-telemetry-source rule on every
decision that sees them: a known ARTIFACT of the harness, reported separately, never a benign
false-alarm-rate measurement (must not be merged with docs/CALIBRATION_PX4.md numbers).
"""

from __future__ import annotations

import argparse
import glob
import json
from collections import Counter
from pathlib import Path


def _ingest_rows(manifest_path: Path) -> list[dict] | None:
    p = Path(str(manifest_path).replace(".manifest.json", ".ids_ingest.jsonl"))
    if not p.exists():
        return None
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln]


def load_trial(manifest_path: Path) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    onset = m["parameters"]["onset_s"]
    cmd_rows = [r for r in rows if any("command(s) from unexpected source" in e for e in r["evidence"])]
    # carrier (sys252/comp193) AND benign driver (sys253/comp192) are both non-expected GCS identities
    # in this topology; counted together, they are the same artifact.
    carrier_rogue_rows = [r for r in rows
                          if any("sys252/comp193" in e or "sys253/comp192" in e for e in r["evidence"])]
    effect = m.get("actual_effect") or {}
    ingest = _ingest_rows(manifest_path)
    post_fix = "injection_carriers" in m
    n_inj = int(m["frames_injected"])
    reached = None
    carriers = m.get("injection_carriers")
    missed = None
    if ingest is not None:
        seqs = [r["seq"] for r in ingest if r["sysid"] == 66 and r["msg"] == "COMMAND_LONG" and "seq" in r]
        reached = len(seqs) if post_fix else sum(1 for r in ingest if r["sysid"] == 66)
        if post_fix:
            reached_idx = set(seqs)
            missed = [i for i in range(n_inj) if (i % 256) not in reached_idx]
    return {
        "trial": m["trial_id"], "seed": m["seed"], "trial_index": m["trial_index"],
        "onset_s": round(onset, 2), "burst_count": m["parameters"]["burst_count"],
        "frames_injected": n_inj, "acked": bool(effect.get("acked")),
        "first_ack_result_name": effect.get("first_ack_result_name"),
        "time_to_first_ack_s": effect.get("time_to_first_ack_s"),
        "decisions_total": len(rows),
        "detected_command_injection": len(cmd_rows) > 0,
        "first_detection_t": round(cmd_rows[0]["t"], 2) if cmd_rows else None,
        "detection_latency_from_onset_s": round(cmd_rows[0]["t"] - onset, 2) if cmd_rows else None,
        "n_command_evidence_decisions": len(cmd_rows),
        "n_carrier_rogue_artifact_decisions": len(carrier_rogue_rows),
        "has_ids_ingest_tap": ingest is not None,
        "post_fix": post_fix, "carriers": carriers, "reached_ids": reached, "missed_idx": missed,
        "commit": (m.get("full_provenance") or {}).get("aegisflight_commit"),
        "dirty": (m.get("full_provenance") or {}).get("working_tree_dirty"),
        "dirty_paths": (m.get("full_provenance") or {}).get("dirty_paths_count"),
    }


def _table(trials: list[dict], post: bool) -> list[str]:
    if post:
        hdr = ("| trial | idx | onset s | injected | carried by (sysid) | reached IDS | acked | ack result | ttfa s | "
               "detected | latency s (from onset) | harness-artifact decisions |")
        L = [hdr, "|" + "---|" * 12]
        for t in trials:
            c = Counter(t["carriers"] or [])
            carried = ", ".join(f"{k}x{v}" for k, v in sorted(c.items())) or "-"
            L.append(f"| {t['trial']} | {t['trial_index']} | {t['onset_s']} | {t['frames_injected']} | {carried} | "
                     f"{t['reached_ids']}/{t['frames_injected']} | {'yes' if t['acked'] else 'NO'} | "
                     f"{t['first_ack_result_name']} | {t['time_to_first_ack_s']} | "
                     f"{'yes' if t['detected_command_injection'] else 'NO'} | {t['detection_latency_from_onset_s']} | "
                     f"{t['n_carrier_rogue_artifact_decisions']} |")
    else:
        hdr = ("| trial | idx | ingest tap | onset s | injected | reached IDS | acked | ack result | ttfa s | detected | "
               "latency s (from onset) | harness-artifact decisions |")
        L = [hdr, "|" + "---|" * 12]
        for t in trials:
            rch = f"{t['reached_ids']}/{t['frames_injected']}" if t["reached_ids"] is not None else "not logged"
            L.append(f"| {t['trial']} | {t['trial_index']} | {'yes' if t['has_ids_ingest_tap'] else 'no'} | "
                     f"{t['onset_s']} | {t['frames_injected']} | {rch} | {'yes' if t['acked'] else 'NO'} | "
                     f"{t['first_ack_result_name']} | {t['time_to_first_ack_s']} | "
                     f"{'yes' if t['detected_command_injection'] else 'NO'} | {t['detection_latency_from_onset_s']} | "
                     f"{t['n_carrier_rogue_artifact_decisions']} |")
    return L


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifests", nargs="+", help="glob(s) for *.manifest.json")
    ap.add_argument("--out", default="artifacts/sitl/P2_injection_summary.md")
    a = ap.parse_args(argv)

    paths = sorted({Path(p) for pat in a.manifests for p in glob.glob(pat)})
    trials = [load_trial(p) for p in paths]
    if not trials:
        print("no trial manifests matched")
        return 1
    post = [t for t in trials if t["post_fix"]]
    pre = [t for t in trials if not t["post_fix"]]

    L = ["# P2 command-injection summary - live SITL trials (generated; do not edit)", "",
         "Environment: **SITL**. Attack: uplink rogue `COMMAND_LONG` force-disarm "
         "(sysid 66/compid 200), piggybacked on a real uplink frame, mirrored to the IDS tap. "
         "Regenerate: `scripts/sitl/make_p2i_summary.py artifacts/sitl/p2i_trial_*.manifest.json "
         "artifacts/sitl/p2i_fix_trial_*.manifest.json`.", "",
         "Claims, never merged: **command-path effect** (PX4 acked the rogue command), **link-level detection** "
         "(IDS produced `COMMAND_INJECTION`-type evidence, \"command(s) from unexpected source\", at or after "
         "the injection), and **harness delivery** (each injected frame actually reached the IDS pipeline's "
         "input). A detector outcome only counts when the frame reached the IDS. The two batches below are "
         "different harness versions and are never pooled.", ""]

    if post:
        acked = sum(t["acked"] for t in post)
        det = sum(t["detected_command_injection"] for t in post)
        inj = sum(t["frames_injected"] for t in post)
        rch = sum(t["reached_ids"] or 0 for t in post)
        all_carriers = Counter(c for t in post for c in (t["carriers"] or []))
        undelivered = [(t["trial"], t["missed_idx"]) for t in post if t["missed_idx"]]
        commits = sorted({str(t["commit"]) for t in post})
        dirty = sum(1 for t in post if t["dirty"])
        L += ["## POST-FIX batch (relay mirrors hook-added frames to all clients)", "",
              f"- **Command-path effect (SITL)**: PX4 accepted/acked the rogue command in **{acked}/{len(post)}** trials.",
              f"- **Link-level detection (SITL)**: the IDS produced command-injection evidence in "
              f"**{det}/{len(post)}** trials.",
              f"- **Harness delivery**: **{rch}/{inj}** injected frames reached the IDS pipeline input "
              f"(carriers across all injections, sysid x count: "
              f"{', '.join(f'{k}x{v}' for k, v in sorted(all_carriers.items()))}).",
              ("- Every injected frame reached the IDS, whichever client carried it."
               if not undelivered else
               "- **Injected frames that did NOT reach the IDS (investigate before reading any detection number):** "
               + "; ".join(f"{tr}: injection idx {ix}" for tr, ix in undelivered)),
              f"- Provenance: aegisflight commit(s) {', '.join(commits)}; `src`/`scripts`/`configs` dirty in "
              f"{dirty}/{len(post)} manifests (dirty-path counts {sorted({t['dirty_paths'] for t in post})}): the "
              f"uncommitted relay mirror fix and the trial/summary script edits themselves (the fix is not in the "
              f"recorded commit; `tests/` and `docs/` are outside the provenance scope). Result is not a clean-commit "
              f"reproduction until those paths are committed.", ""]
        L += _table(post, True)
        L += [""]

    if pre:
        acked = sum(t["acked"] for t in pre)
        det = sum(t["detected_command_injection"] for t in pre)
        with_tap = [t for t in pre if t["has_ids_ingest_tap"]]
        inj_t = sum(t["frames_injected"] for t in with_tap)
        rch_t = sum(t["reached_ids"] or 0 for t in with_tap)
        det_not_reached = [t["trial"] for t in with_tap if t["reached_ids"] == 0 and t["detected_command_injection"]]
        L += ["## PRE-FIX batch (superseded; harness defect, NOT a detector or transport result)", "",
              f"- Command-path effect (SITL): PX4 acked in **{acked}/{len(pre)}** trials.",
              f"- Link-level detection: **{det}/{len(pre)}** trials - but in this harness version the relay did not "
              f"mirror a hook-added frame to the uplink frame's own sender, and the IDS tap sends its own "
              f"heartbeat; when that heartbeat carried the injection the IDS never received it. The carrier was "
              f"not logged, so which injections were undeliverable cannot be reconstructed per injection.",
              f"- Of the {len(with_tap)} trials with the `ids_ingest.jsonl` tap, injected frames that reached the IDS "
              f"input: **{rch_t}/{inj_t}**; trials with zero frames reaching the IDS cannot say anything about the "
              f"detector. Trials detected despite zero frames reaching the ingest tap: "
              f"{det_not_reached if det_not_reached else 'none'}.",
              "- Earlier drafts of this summary attributed the split to a timing/concurrency race in "
              "`UdpMavlinkTransport`. That hypothesis is disproven (see `docs/STAGE2_PROGRESS.md`, 2026-10-07 "
              "root-cause entry): the transport delivered every frame the relay mirrored to it.", ""]
        L += _table(pre, False)
        L += [""]

    L += ["## Known experimental artifact, not a false-alarm-rate result",
          "TWO non-expected-GCS identities in this topology trigger the protocol rogue-telemetry-source rule: the "
          "inert \"carrier\" client (sysid 252/compid 193) and the benign flight-driver client (sysid 253/compid "
          "192); both are outside the PX4 profile's `expected_sysids`/`expected_gcs_sysids`. The last column counts "
          "decisions citing either. It is a property of this harness (an uplink-mirroring harness needs non-IDS "
          "uplink clients), never a benign false-alarm measurement; do not merge it with "
          "`docs/CALIBRATION_PX4.md`.", "",
          "## Limitations",
          "- n=10 per batch, not a statistically powered sample; counts are reported, not a rate with confidence bounds.",
          "- One airframe/world/host, one benign flight driver script, one seed family (2001 + trial_index).",
          "- `acked` is independent of detection. Detection is link-level only: the IDS saw a mirrored copy of the "
          "frame on a bump-in-the-wire tap; this says nothing about estimator effects or physical flight deviation, "
          "and the mirrored-tap topology is a harness choice (a deployed IDS would need an actual uplink vantage point).",
          "- The link is unsigned throughout (no claim about MAVLink signing); SITL only (no real hardware/RF)."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(Path(a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
