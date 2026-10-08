"""Aggregate P2 REPLAY-v2 live-SITL trial manifests into a generated summary (no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2r_v2_summary.py \
        "artifacts/sitl/p2r_v2_trial_*.manifest.json" --out artifacts/sitl/P2_replay_v2_summary.md

Environment: SITL. Attack: byte-identical replay of a legitimate, unsigned COMMAND_LONG
(force-disarm) captured from an EXPECTED GCS identity (sysid 255/compid 190, in
`expected_gcs_sysids`), re-sent 15-30s later. See `run_p2_replay_v2_trial.py` and
`attacks_live_dos_replay.py::ReplayAttack` for the attack itself.

Three claims are scored SEPARATELY, as the task requires -- they must never be merged:

1. **Harness delivery**: did the IDS's own pipeline actually receive both the original capture
   and the replay as distinct COMMAND_LONG frames (`ids_ingest` tap, logged before any detector
   logic runs)? This is NOT a detection claim -- it is "did the evidence even reach the thing
   being asked to detect it".
2. **Command-path effect (SITL)**: did PX4 ACK both the original and the replay with
   MAV_RESULT_ACCEPTED? (From the proxy's own frame log / ack-watch, never from the detector.)
3. **Link-level detection (SITL), sequence-continuity mechanism**: a threat decision in
   [replay_recv_time, replay_recv_time + TAIL_S] whose evidence contains "sequence gap". This
   is scored as its OWN mechanism, deliberately distinct from "any threat decision in the
   window" (reported alongside it), because of WHY it exists: replaying a byte-identical old
   frame reuses an old MAVLink `seq` value from sysid 255, while the real GCS's own heartbeat
   has kept incrementing that source's running sequence counter in the meantime (the capture
   client never stops heartbeating) -- so the per-source `max_seq_gap` rule in
   `detectors/protocol.py` (an EXISTING, unmodified Stage-1 rule having nothing to do with
   identity/provenance) sees what looks like a huge backward sequence jump and fires
   `MAVLINK_ANOMALY`. This is NOT the identity/provenance rule the attack's own docstring (and
   the documented `command_injection:gcs_replay` gap) says can never fire for an expected-GCS
   sysid -- that rule indeed never fires here (sysid 255 is in `expected_gcs_sysids`, confirmed
   by the absence of any `COMMAND_INJECTION`-typed evidence in any trial below). It is a
   SEPARATE, pre-existing feature picking this up by a different mechanism. Scoring rule fixed
   BEFORE this n=10 batch was run (after the n=1 diagnostic that first showed the mechanism;
   no detector code or threshold was touched to produce it -- `configs/detector.yaml`'s
   `max_seq_gap: 30` and `configs/px4_sitl/detector.yaml`'s silence on it are both untouched).

Known boundary (derived analytically, NOT separately tested live -- disclosed, not hidden):
`FeatureExtractor`'s per-source gap is `(seq - prev) % 256`; replaying an OLDER seq while the
source's own counter has moved forward by `delta` heartbeats always computes to `256 - delta`
(mod 256 wraparound makes "behind" look like "almost all the way around"), so detection by this
mechanism needs `256 - delta - 1 > 30`, i.e. `delta < 225` -- at this attack's 1 Hz capture-client
heartbeat and `replay_delay_s` range (15-30s), `delta` is ~15-30, far inside that bound, and this
holds for the FULL drawn range, not just the particular draws in this batch. The same arithmetic
means a replay delayed by more than ~225s (at 1 Hz), or performed while the real GCS identity
has gone silent in between, is NOT covered by this mechanism -- not claimed here.

Integrity gate (a trial violating it is not scored as evidence about the detector):
relay `hook_errors == 0`, and the attack's own `frames_seen > 0` / capture succeeded.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

TAIL_S = 5.0


def load_trial(manifest_path: Path) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    ingest_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_ingest.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    ingest = [json.loads(ln) for ln in ingest_path.read_text().splitlines() if ln] if ingest_path.exists() else []
    eff = m.get("actual_effect") or {}
    rs = m["ids_summary"]["relay_stats"]
    p = m["parameters"]

    captured, replayed = bool(eff.get("captured")), bool(eff.get("replayed"))
    cmd_long_ingest = [r for r in ingest if r.get("msg") == "COMMAND_LONG" and r.get("sysid") == 255]
    capture_delivered = len(cmd_long_ingest) >= 1
    replay_delivered = len(cmd_long_ingest) >= 2
    orig_ack = (eff.get("original_ack") or {}).get("result_name")
    replay_ack = (eff.get("replay_ack") or {}).get("result_name")
    path_effect_ok = orig_ack == "MAV_RESULT_ACCEPTED" and replay_ack == "MAV_RESULT_ACCEPTED"

    replay_t = cmd_long_ingest[1]["tick_t"] if replayed and replay_delivered else None

    first_cmd_t = cmd_long_ingest[0]["tick_t"] if cmd_long_ingest else 0.0
    pre = [r for r in rows if r["t"] < first_cmd_t]
    fa_pre = [r for r in pre if r["threat"]]
    win = [r for r in rows if replay_t is not None and replay_t <= r["t"] <= replay_t + TAIL_S]
    seqgap_det = [r for r in win if r["threat"] and any("sequence gap" in e for e in r["evidence"])]
    any_det = [r for r in win if r["threat"]]
    command_injection_evidence = [r for r in rows if r["threat"] and r["type"] == "COMMAND_INJECTION"]

    integrity_ok = rs["hook_errors"] == 0 and m["frames_seen"] > 0

    return {
        "trial": m["trial_id"], "idx": m["trial_index"], "delay_s": round(p.get("replay_delay_s", 0.0), 2),
        "captured": captured, "replayed": replayed,
        "capture_delivered": capture_delivered, "replay_delivered": replay_delivered,
        "orig_ack": orig_ack, "replay_ack": replay_ack, "path_effect_ok": path_effect_ok,
        "replay_t": round(replay_t, 2) if replay_t is not None else None,
        "seqgap_detected": bool(seqgap_det),
        "seqgap_latency": round(seqgap_det[0]["t"] - replay_t, 2) if seqgap_det and replay_t is not None else None,
        "any_detected": bool(any_det),
        "n_identity_evidence": len(command_injection_evidence),
        "fa_pre": len(fa_pre), "pre_decisions": len(pre),
        "integrity_ok": integrity_ok, "hook_errors": rs["hook_errors"],
        "ev": [e for r in sorted(win, key=lambda r: r["t"]) if r["threat"] for e in r["evidence"]][:3],
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
    n_cap_del = sum(t["capture_delivered"] for t in ok)
    n_rep_del = sum(t["replay_delivered"] for t in ok)
    n_path = sum(t["path_effect_ok"] for t in ok)
    n_seqgap = sum(t["seqgap_detected"] for t in ok)
    n_any = sum(t["any_detected"] for t in ok)
    n_identity = sum(t["n_identity_evidence"] for t in ok)
    fa_n = sum(t["fa_pre"] for t in ok)
    pre_n = sum(t["pre_decisions"] for t in ok)
    lat = [t["seqgap_latency"] for t in ok if t["seqgap_latency"] is not None]

    L = ["# P2 REPLAY-v2 summary - live SITL trials (generated; do not edit)", "",
         "Environment: **SITL**. Attack: byte-identical replay of a captured, unsigned COMMAND_LONG "
         "(force-disarm) from an EXPECTED GCS identity (sysid 255, in `expected_gcs_sysids`), 15-30s later. "
         "Three claims scored separately (see module docstring): harness delivery, command-path effect, "
         "link-level detection via the sequence-continuity mechanism (NOT identity/provenance). "
         "Regenerate: `scripts/sitl/make_p2r_v2_summary.py <manifests> --out <this file>`.", "",
         f"- Trials: **{len(T)}**; passing the integrity gate: **{len(ok)}** (`hook_errors == 0`, attack saw frames).",
         f"- **Harness delivery**: original capture reached the IDS in **{n_cap_del}/{len(ok)}**; "
         f"the replay also reached it in **{n_rep_del}/{len(ok)}**.",
         f"- **Command-path effect (SITL)**: both the original and replayed command ACCEPTED by PX4 in "
         f"**{n_path}/{len(ok)}**.",
         f"- **Link-level detection (SITL), sequence-continuity mechanism**: `MAVLINK_ANOMALY` "
         f"(\"sequence gap\") within {TAIL_S:g}s of the replay in **{n_seqgap}/{len(ok)}**; any threat "
         f"decision in that window: **{n_any}/{len(ok)}**.",
         f"- **Identity/provenance rule**: `COMMAND_INJECTION`-typed evidence across all trials: "
         f"**{n_identity}** (expected: 0 -- sysid 255 is an expected GCS identity, confirming the "
         "documented `command_injection:gcs_replay` gap holds for THIS rule; detection above comes from "
         "a different, orthogonal mechanism).",
         f"- Pre-replay false alarms (integrity-passing trials pooled): **{fa_n}/{pre_n}** decisions.",
         (f"- Sequence-gap detection latency after the replay: "
          f"{', '.join(f'{x:.2f}s' for x in sorted(lat))} (n={len(lat)})." if lat else
          "- No trial detected by the sequence-gap mechanism; no latency to report."), ""]

    bad = [t for t in T if not t["integrity_ok"]]
    if bad:
        L += ["**Integrity-gate failures (NOT scored as evidence about the detector):** " +
              ", ".join(f"{t['trial']} (hook_errors={t['hook_errors']})" for t in bad), ""]

    L += ["| trial | idx | delay s | capture delivered | replay delivered | orig ack | replay ack | "
          "seq-gap detected | latency s | any detected | identity evidence | pre-replay FA | evidence (sample) |",
          "|" + "---|" * 13]
    for t in T:
        L.append(f"| {t['trial']} | {t['idx']} | {t['delay_s']} | {'yes' if t['capture_delivered'] else 'NO'} | "
                 f"{'yes' if t['replay_delivered'] else 'NO'} | {t['orig_ack']} | {t['replay_ack']} | "
                 f"{'yes' if t['seqgap_detected'] else 'NO'} | {t['seqgap_latency']} | "
                 f"{'yes' if t['any_detected'] else 'NO'} | {t['n_identity_evidence']} | "
                 f"{t['fa_pre']}/{t['pre_decisions']} | {'; '.join(x[:60] for x in t['ev']) or '-'} |")

    L += ["", "## Provenance",
          f"- PX4: {sorted({str(t['px4']) for t in T})}; detector profile {sorted({str(t['profile']) for t in T})}, "
          f"model {sorted({str(t['model']) for t in T})}; aegisflight commit {sorted({str(t['commit'])[:7] for t in T})}; "
          f"`src`/`scripts`/`configs` dirty-path counts {sorted({t['dirty'] for t in T})} "
          "(uncommitted changes at run time; not a clean-commit reproduction until committed).", "",
          "## Limitations",
          "- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; "
          "fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.",
          "- The sequence-gap mechanism is analytically shown (see module docstring) to depend on the real "
          "GCS identity continuing to heartbeat between capture and replay, and on the replay delay staying "
          "well under ~225s at a 1Hz heartbeat given `max_seq_gap: 30` -- both hold for the full drawn range "
          "(15-30s) here, but this is NOT evidence about a replay performed after the real GCS has gone "
          "silent, or after a much longer delay.",
          "- Detection here is **link-level** only: it says the IDS can see the stale sequence number on the "
          "link it is tapped on, nothing about vehicle behaviour or the estimator.",
          "- This is a single command (force-disarm) replayed against an already-disarmed vehicle; not "
          "evidence about replaying a different command or one with in-flight consequence."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
