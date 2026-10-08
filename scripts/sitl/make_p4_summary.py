"""Aggregate P4 MAVLink-2 signing live-SITL trials into a generated summary (no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p4_summary.py \
        "artifacts/sitl/p4_sign_n10_trial_*.manifest.json" --out artifacts/sitl/P4_signing_summary.md

Environment: SITL. Five questions, scored SEPARATELY per trial (see ``run_p4_signing_trial.py``'s own
docstring for the full design): legitimate signed command accepted/rejected; unsigned forged command
accepted/rejected (command-path effect); did the IDS's own verifying parser observe the forged bytes at
all (``sig_invalid`` increasing by the number of frames injected -- proof of reaching the parser,
independent of being decodable); did the NEW P4 rule (``sig_invalid_count`` -> evidence string
containing "signature verification") flag it; did ANY rule flag something in that window (the pre-existing,
cruder ``signed_ratio`` rule included, disclosed as noisy in this harness -- see Limitations).

**Found live, characterized before this n=10 batch was read (see ``docs/STAGE2_PROGRESS.md``, the
"signing bootstrap transient" entry):** `sig_invalid` reliably shows a ONE-TIME burst in the ~1s
immediately after a trial's own `enable_signing()` call, then zero for the rest of a clean trial (traced
across six independent diagnostic measurements: 100% of the noise fell in the first 1-second bucket after
the transition, 0 for the following 19s in a 20s check). The scoring windows below are fixed BEFORE
reading this batch's results, exactly to separate that transient (it lands in "pre-window", not in the
attack's onset window) from the attack-detection measurement -- not a post-hoc adjustment.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

TAIL_S = 5.0


def load_trial(manifest_path: Path) -> dict:
    stem = manifest_path.name.replace(".manifest.json", "")
    d = manifest_path.parent
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [json.loads(ln) for ln in (d / f"{stem}.ids_decisions.jsonl").read_text(encoding="utf-8").splitlines() if ln]
    eff = m.get("actual_effect") or {}
    ids = m["ids_summary"]
    rs = ids["relay_stats"]
    legit_ack = ids.get("legit_signed_command_ack") or {}
    p = m["parameters"]

    forged_n = eff.get("frames_injected", 0)
    path_rejected = eff.get("ack_count", 0) == 0  # expected: unsigned forged command gets NO ack at all
    legit_ok = legit_ack.get("result") == 0  # MAV_RESULT_ACCEPTED

    sig_before = ids.get("ids_sig_invalid_before", 0)
    sig_after = ids.get("ids_sig_invalid_after", 0)
    sig_delta_total = sig_after - sig_before

    # onset window: approximate using the trial's own onset_s/gap -- the attack's two forged frames land
    # within [onset_s, onset_s + burst_count*gap_s]; add TAIL_S for detection latency
    onset = p.get("onset_s", 0.0)
    window_end = onset + p.get("burst_count", 1) * p.get("inter_injection_gap_s", 0.0) + TAIL_S
    pre = [r for r in rows if r["t"] < onset]
    win = [r for r in rows if onset <= r["t"] <= window_end]
    sig_rule_win = [r for r in win if r["threat"] and any("signature verification" in e for e in r["evidence"])]
    any_win = [r for r in win if r["threat"]]
    sig_rule_pre = [r for r in pre if r["threat"] and any("signature verification" in e for e in r["evidence"])]
    any_pre = [r for r in pre if r["threat"]]

    integrity_ok = rs["hook_errors"] == 0 and forged_n > 0 and legit_ack.get("signed") is True

    return {
        "trial": m["trial_id"], "idx": m["trial_index"], "forged_n": forged_n,
        "legit_ok": legit_ok, "legit_ack_signed": legit_ack.get("signed"),
        "path_rejected": path_rejected, "ack_count": eff.get("ack_count", 0),
        "sig_observed": sig_delta_total >= forged_n > 0,
        "sig_delta_total": sig_delta_total,
        "detected_via_sig_rule": bool(sig_rule_win), "detected_any": bool(any_win),
        "pre_sig_rule_fa": len(sig_rule_pre), "pre_any_fa": len(any_pre), "pre_n": len(pre),
        "integrity_ok": integrity_ok, "hook_errors": rs["hook_errors"],
        "ev": [e for r in win if r["threat"] for e in r["evidence"]][:2],
        "profile": p.get("detector_profile"), "model": p.get("model_choice"),
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
    n = len(ok)

    L = ["# P4 MAVLink-2 signing summary - live SITL trials (generated; do not edit)", "",
         "Environment: **SITL**. Attack: the same informed expected-GCS-impersonation forgery as the P2 "
         "batch (sysid 255/190, correctly-tracked sequence), run once signing is bootstrapped and the IDS "
         "profile's `require_signing` is forced on. Five questions scored separately (see module "
         "docstring): legitimate-command acceptance, forged-command acceptance (command-path effect), "
         "IDS observation, detection via the new signing rule, detection via any rule. "
         "Regenerate: `scripts/sitl/make_p4_summary.py <manifests> --out <this file>`.", "",
         f"- Trials: **{len(T)}**; passing the integrity gate (no hook errors, >=1 forged frame, legit ack "
         f"confirmed signed): **{n}**.",
         f"- **Legitimate signed command accepted**: **{sum(t['legit_ok'] for t in ok)}/{n}**.",
         f"- **Unsigned forged command REJECTED (0 acks)** -- command-path effect: "
         f"**{sum(t['path_rejected'] for t in ok)}/{n}**.",
         f"- **IDS observed the forged bytes** (verifying parser's `sig_invalid` rose by >= the number of "
         f"forged frames): **{sum(t['sig_observed'] for t in ok)}/{n}**.",
         f"- **Link-level detection via the new signing rule** (`sig_invalid_count` evidence) in the "
         f"forged-frame window: **{sum(t['detected_via_sig_rule'] for t in ok)}/{n}**.",
         f"- **Any rule fired** in that window (includes the pre-existing, cruder `signed_ratio` rule -- "
         f"see Limitations): **{sum(t['detected_any'] for t in ok)}/{n}**.",
         f"- Pre-onset false alarms, new signing rule only (clean baseline): "
         f"**{sum(t['pre_sig_rule_fa'] for t in ok)}/{sum(t['pre_n'] for t in ok)}** decisions.",
         f"- Pre-onset false alarms, ANY rule (includes the one-time bootstrap transient + the "
         f"continuously-noisy `signed_ratio` rule -- see Limitations): "
         f"**{sum(t['pre_any_fa'] for t in ok)}/{sum(t['pre_n'] for t in ok)}** decisions.", ""]

    bad = [t for t in T if not t["integrity_ok"]]
    if bad:
        L += ["**Integrity-gate failures (NOT scored as evidence about the detector):** " +
              ", ".join(f"{t['trial']} (hook_errors={t['hook_errors']})" for t in bad), ""]

    L += ["| trial | idx | forged | legit ack ok | path rejected | sig observed | sig-rule detected | "
          "any detected | pre FA (sig-rule) | pre FA (any) | evidence (sample) |",
          "|" + "---|" * 11]
    for t in T:
        L.append(f"| {t['trial']} | {t['idx']} | {t['forged_n']} | {'yes' if t['legit_ok'] else 'NO'} | "
                 f"{'yes' if t['path_rejected'] else 'NO'} | {'yes' if t['sig_observed'] else 'NO'} | "
                 f"{'yes' if t['detected_via_sig_rule'] else 'NO'} | {'yes' if t['detected_any'] else 'NO'} | "
                 f"{t['pre_sig_rule_fa']}/{t['pre_n']} | {t['pre_any_fa']}/{t['pre_n']} | "
                 f"{'; '.join(x[:60] for x in t['ev']) or '-'} |")

    L += ["", "## Provenance",
          f"- PX4: {sorted({str(t['px4']) for t in T})}; detector profile {sorted({str(t['profile']) for t in T})}, "
          f"model {sorted({str(t['model']) for t in T})}; aegisflight commit {sorted({str(t['commit'])[:7] for t in T})}; "
          f"dirty-path counts {sorted({t['dirty'] for t in T})} (uncommitted changes at run time; not a "
          "clean-commit reproduction until committed).", "",
          "## Limitations",
          "- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; "
          "fresh SITL boot AND a cleared signing-key file per trial (`run_trial_batch.sh`); unsigned-until-"
          "bootstrapped link; vehicle disarmed on the ground; SITL only.",
          "- **The one-time signing-bootstrap transient**: characterized separately, SITL-free in spirit but "
          "confirmed live across 6 independent diagnostic runs before this batch -- ~1s of spurious "
          "`sig_invalid` right after `enable_signing()` as PX4's own downlink and the verifier's per-stream "
          "timestamp tracking settle, then exactly 0 for the remainder of a clean trial. This is NOT an "
          "ongoing noise floor; it is bucketed into the trial's PRE-onset window (onset is several seconds "
          "later), so it shows up as pre-onset false alarms, not as attack detections -- reported, not hidden.",
          "- **The pre-existing `signed_ratio` rule is link-wide and blunt**: it fires on ANY unsigned "
          "traffic regardless of source, and this harness deliberately has one always-unsigned inert "
          "carrier client (the attack's own piggyback-delivery mechanism, not a calibrated real "
          "deployment) -- so 'any rule fired' / 'any FA' numbers above are expected to look noisy and must "
          "not be read as a false-alarm rate for a real deployment. The NEW `sig_invalid_count` rule is "
          "the clean, intended signal and is reported separately for exactly this reason.",
          "- Detection here is **link-level** (IDS-side), separate from and in addition to PX4's own "
          "command-path rejection -- the two are never merged into one number.",
          "- A single command (force-disarm) against an already-disarmed vehicle; not evidence about a "
          "different command or one with in-flight consequence.",
          "- The informed attacker's identity-impersonation mechanics are unchanged from the P2 batch; "
          "this experiment is only about what happens once signing is active, not a new attack design."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
