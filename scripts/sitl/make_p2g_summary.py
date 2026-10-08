"""Aggregate P2 expected-GCS IMPERSONATION live-SITL trials into a generated summary (no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2g_summary.py \
        --variant "informed (seq_policy=track_identity)=artifacts/sitl/p2g_inf_trial_*.manifest.json" \
        --variant "naive (seq_policy=own_counter)=artifacts/sitl/p2g_naive_trial_*.manifest.json" \
        --out artifacts/sitl/P2_gcs_impersonation_summary.md

Environment: SITL. Attack: a FRESH forged COMMAND_LONG (force-disarm) stamped sysid 255/compid 190 -- an identity in
the PX4 profile's `expected_gcs_sysids` -- built from scratch (not a replay), piggybacked on a real uplink frame.
Claim class: command-path effect (SITL) + link-level detection. Vehicle disarmed on the ground: an ACCEPTED ack of a
force-disarm is a command-path acceptance, NOT an observable state change. No estimator / physical claim.

Scoring (fixed BEFORE any batch result was read; hypotheses are recorded in each manifest's `expected_effect`):
1. **Command-path effect**: the ack count / first ack result straight from the proxy's own frame log (never from
   detector output).
2. **Harness delivery**: the number of COMMAND_LONG frames from 255/190 that reached the IDS pipeline input
   (`ids_ingest` tap, written before any detector runs) must equal the number injected; the legitimate GCS client
   in this topology never sends a COMMAND_LONG, so every such frame is a forgery.
3. **Seq continuity achieved** (an attack-implementation check, NOT a detection result): for each forged frame, was its
   seq exactly (previous real 255/190 frame's seq + 1) mod 256 as the IDS saw it? Tells whether the attacker
   variant really did what its name says.
4. **Detection**, split by the mechanism that fired, within [first forged frame, last forged frame + TAIL_S]:
   - provenance/identity rule: evidence "unexpected source" (expected: never, 255 is an expected identity);
   - sequence-continuity rule: evidence "sequence gap";
   - any threat decision at all (includes ML-only decisions).
   Pre-injection false alarms = threat decisions before the first forged frame (pooled; harness has no rogue-source noise).
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

TAIL_S = 5.0
ID_SYSID, ID_COMPID = 255, 190


def load_trial(manifest_path: Path) -> dict:
    stem = manifest_path.name.replace(".manifest.json", "")
    d = manifest_path.parent
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [json.loads(ln) for ln in (d / f"{stem}.ids_decisions.jsonl").read_text(encoding="utf-8").splitlines() if ln]
    ingest = [json.loads(ln) for ln in (d / f"{stem}.ids_ingest.jsonl").read_text(encoding="utf-8").splitlines() if ln]
    frames = [json.loads(ln) for ln in (d / f"{stem}.frames.jsonl").read_text(encoding="utf-8").splitlines() if ln]
    eff = m.get("actual_effect") or {}
    rs = m["ids_summary"]["relay_stats"]
    p = m["parameters"]

    injected = [f for f in frames if f.get("action") == "injected"]
    forged = [r for r in ingest if r["msg"] == "COMMAND_LONG" and r["sysid"] == ID_SYSID and r["compid"] == ID_COMPID]
    delivered = len(forged) == len(injected) and len(injected) > 0

    # seq continuity as seen by the IDS: walk the ingest stream in receipt order
    last_real: int | None = None
    cont = 0
    for r in ingest:
        if r["sysid"] != ID_SYSID or r["compid"] != ID_COMPID:
            continue
        if r["msg"] == "COMMAND_LONG":
            if last_real is not None and r["seq"] == (last_real + 1) % 256:
                cont += 1
        else:
            last_real = r["seq"]

    t0 = forged[0]["tick_t"] if forged else None
    t1 = forged[-1]["tick_t"] if forged else None
    win = [r for r in rows if t0 is not None and t0 <= r["t"] <= t1 + TAIL_S]
    pre = [r for r in rows if t0 is not None and r["t"] < t0]
    thr = [r for r in win if r["threat"]]
    ident = [r for r in thr if any("unexpected source" in e for e in r["evidence"])]
    seqg = [r for r in thr if any("sequence gap" in e for e in r["evidence"])]
    return {
        "trial": m["trial_id"], "idx": m["trial_index"], "policy": p.get("seq_policy"),
        "n_inj": len(injected), "acked": eff.get("ack_count", 0),
        "ack": eff.get("first_ack_result_name"), "delivered": delivered, "n_forged_ingest": len(forged),
        "continuous": cont, "any": bool(thr), "ident": bool(ident), "seqgap": bool(seqg),
        "fa_pre": sum(r["threat"] for r in pre), "pre_n": len(pre),
        "ev": [e for r in thr for e in r["evidence"]][:2],
        "integrity_ok": rs["hook_errors"] == 0 and len(injected) > 0,
        "profile": p.get("detector_profile"), "model": p.get("model_choice"),
        "commit": (m.get("full_provenance") or {}).get("aegisflight_commit"),
        "dirty": (m.get("full_provenance") or {}).get("dirty_paths_count"),
        "px4": (m.get("provenance") or {}).get("px4_git_describe"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--variant", action="append", required=True, help="LABEL=GLOB (repeatable)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    L = ["# P2 expected-GCS impersonation summary - live SITL trials (generated; do not edit)", "",
         "Environment: **SITL**. Attack: a fresh forged `COMMAND_LONG` (force-disarm) stamped with an EXPECTED GCS "
         "identity (sysid 255/compid 190), not a replay. Command-path effect, harness delivery and detection are "
         "scored separately (see the script docstring). Vehicle disarmed: an ACCEPTED ack is acceptance only, not an "
         "observable state change. Regenerate: `scripts/sitl/make_p2g_summary.py --variant LABEL=GLOB ... --out <this file>`.", ""]
    allT: list[dict] = []
    for spec in a.variant:
        label, _, pattern = spec.partition("=")
        T = [load_trial(Path(p)) for p in sorted(glob.glob(pattern))]
        if not T:
            print(f"no manifests for {label}")
            return 1
        allT += T
        ok = [t for t in T if t["integrity_ok"]]
        n = len(ok)
        inj = sum(t["n_inj"] for t in ok)
        cont = sum(t["continuous"] for t in ok)
        L += [f"## Variant: {label}", "",
              f"- Trials: **{len(T)}**; passing the integrity gate (no hook errors, >=1 injection): **{n}**; "
              f"forged frames injected: **{inj}**.",
              f"- **Command-path effect (SITL)**: trials where PX4 acked the forged command `MAV_RESULT_ACCEPTED`: "
              f"**{sum(t['ack'] == 'MAV_RESULT_ACCEPTED' for t in ok)}/{n}**.",
              f"- **Harness delivery**: trials where every forged frame reached the IDS pipeline input: "
              f"**{sum(t['delivered'] for t in ok)}/{n}** ({sum(t['n_forged_ingest'] for t in ok)}/{inj} frames).",
              f"- **Seq continuity achieved** (attack-implementation check, not detection): "
              f"**{cont}/{inj}** forged frames carried exactly (previous real 255/190 seq + 1).",
              f"- **Link-level detection (SITL)** within the forged-frame window (+{TAIL_S:g}s): "
              f"any threat decision **{sum(t['any'] for t in ok)}/{n}**; "
              f"identity/provenance rule **{sum(t['ident'] for t in ok)}/{n}**; "
              f"sequence-continuity rule **{sum(t['seqgap'] for t in ok)}/{n}**.",
              f"- Pre-injection false alarms (pooled): **{sum(t['fa_pre'] for t in ok)}/{sum(t['pre_n'] for t in ok)}** decisions.",
              "", "| trial | idx | injected | acks | first ack | delivered | seq-continuous | any | identity | seq-gap | pre FA | evidence (sample) |",
              "|" + "---|" * 12]
        for t in T:
            L.append(f"| {t['trial']} | {t['idx']} | {t['n_inj']} | {t['acked']} | {t['ack']} | "
                     f"{'yes' if t['delivered'] else 'NO'} | {t['continuous']}/{t['n_inj']} | "
                     f"{'yes' if t['any'] else 'NO'} | {'yes' if t['ident'] else 'NO'} | "
                     f"{'yes' if t['seqgap'] else 'NO'} | {t['fa_pre']}/{t['pre_n']} | "
                     f"{'; '.join(x[:60] for x in t['ev']) or '-'} |")
        L.append("")
    L += ["## Provenance",
          f"- PX4: {sorted({str(t['px4']) for t in allT})}; detector profile {sorted({str(t['profile']) for t in allT})}, "
          f"model {sorted({str(t['model']) for t in allT})}; aegisflight commit {sorted({str(t['commit'])[:7] for t in allT})}; "
          f"dirty-path counts {sorted({t['dirty'] for t in allT})} (uncommitted changes at run time; not a clean-commit "
          "reproduction until committed).", "",
          "## Limitations",
          "- n=10 per variant is the design floor, reported as counts (no confidence interval); one airframe/world/host; "
          "fresh SITL boot per trial; unsigned link; vehicle disarmed on the ground; SITL only.",
          "- The informed attacker reads the 255/190 heartbeat sequence off the clear-text link; that is a statement about "
          "an attacker with read access to the link (the MITM position this proxy already assumes), not about a remote one.",
          "- Link-level only: this says what the IDS could see on its tap; it says nothing about vehicle behaviour, and an "
          "ACCEPTED ack of a disarm sent to an already-disarmed vehicle is not a demonstrated physical effect.",
          "- Only the rules present in the PX4-profile detector were exercised; a deliberately designed duplicate-sequence or "
          "timing-consistency check (not implemented) is not evaluated here."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
