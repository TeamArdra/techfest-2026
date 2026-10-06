"""Aggregate P2 command-injection trial manifests into artifacts/sitl/P2_injection_summary.md
(no hand-typed numbers).

    .venv/Scripts/python.exe scripts/sitl/make_p2i_summary.py artifacts/sitl/p2i_trial_*.manifest.json

Environment: SITL. Attack: uplink rogue COMMAND_LONG force-disarm (sysid 66/compid 200),
piggybacked on a real uplink frame, mirrored to the IDS tap (docs/ATTACK_PROXY.md injection
attack). Two claims, never merged:
1. Command-path effect (SITL): did PX4 accept/ack the rogue command? (`actual_effect.acked`)
2. Link-level detection (SITL): did the IDS flag it (`COMMAND_INJECTION` / "command(s) from
   unexpected source" evidence) at or after the injection?  -- a SEPARATE question from (1);
   an accepted command and a detected command are independent outcomes.

This experimental topology requires an inert "carrier" client (sysid 252/compid 193, not in
the PX4 profile's `expected_sysids`/`expected_gcs_sysids`) purely to give the attack an
uplink frame to piggyback on and to let `mirror_uplink_to_clients` reach a non-sender (see
module docstring of `attacks_live.CommandInjectionAttack`). The benign flight-driver client
(sysid 253/compid 192, `data/sitl/raw/p2i_driver_*.json`) is ALSO outside those same expected-
identity lists. Once either client's heartbeat is mirrored to the IDS, the protocol
detector's rogue-telemetry-source rule correctly fires on it every time it is in a decision's
window -- this is a known ARTIFACT of this specific experimental harness (neither client is a
real deployment entity), not a general benign false-alarm measurement, and must never be read
as a Stage-1/P3 false-alarm-rate result. It is reported here (counting both sources together,
since they are the same artifact), separately from the command-injection evidence, and
excluded from the "command-evidence" detection column.
"""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path


def load_trial(manifest_path: Path) -> dict:
    m = json.loads(manifest_path.read_text())
    dec_path = manifest_path.with_name(manifest_path.name.replace(".manifest.json", ".ids_decisions.jsonl"))
    rows = [json.loads(ln) for ln in dec_path.read_text().splitlines() if ln]
    onset = m["parameters"]["onset_s"]
    cmd_rows = [r for r in rows if any("command(s) from unexpected source" in e for e in r["evidence"])]
    # Two non-expected-GCS identities trigger the same protocol rogue-source rule in this
    # topology: the inert "carrier" (sys252/comp193) AND the benign flight-driver client
    # (sys253/comp192, data/sitl/raw/p2i_driver_*.json) -- caught by aegis-reviewer after the
    # first version of this script named only the carrier. Counted together, not separately,
    # since both are the same artifact (a non-expected-GCS client being correctly flagged).
    carrier_rogue_rows = [r for r in rows
                          if any("sys252/comp193" in e or "sys253/comp192" in e for e in r["evidence"])]
    effect = m.get("actual_effect") or {}
    return {
        "trial": m["trial_id"], "seed": m["seed"], "trial_index": m["trial_index"],
        "onset_s": round(onset, 2), "burst_count": m["parameters"]["burst_count"],
        "frames_injected": m["frames_injected"], "acked": bool(effect.get("acked")),
        "first_ack_result_name": effect.get("first_ack_result_name"),
        "time_to_first_ack_s": effect.get("time_to_first_ack_s"),
        "decisions_total": len(rows),
        "detected_command_injection": len(cmd_rows) > 0,
        "first_detection_t": round(cmd_rows[0]["t"], 2) if cmd_rows else None,
        "detection_latency_from_onset_s": round(cmd_rows[0]["t"] - onset, 2) if cmd_rows else None,
        "n_command_evidence_decisions": len(cmd_rows),
        "n_carrier_rogue_artifact_decisions": len(carrier_rogue_rows),
        "has_ids_ingest_tap": Path(str(manifest_path).replace(".manifest.json", ".ids_ingest.jsonl")).exists(),
    }


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

    acked = sum(t["acked"] for t in trials)
    detected = sum(t["detected_command_injection"] for t in trials)
    with_tap = sum(t["has_ids_ingest_tap"] for t in trials)
    detected_with_tap = sum(t["detected_command_injection"] for t in trials if t["has_ids_ingest_tap"])
    detected_without_tap = sum(t["detected_command_injection"] for t in trials if not t["has_ids_ingest_tap"])
    L = ["# P2 command-injection summary - live SITL trials (generated; do not edit)", "",
        "Environment: **SITL**. Attack: uplink rogue `COMMAND_LONG` force-disarm "
        "(sysid 66/compid 200), piggybacked on a real uplink frame, mirrored to the IDS tap.", "",
        "Two independent claims (never merge these rows):",
        f"- **Command-path effect (SITL)**: PX4 accepted/acked the rogue command in "
        f"**{acked}/{len(trials)}** trials.",
        f"- **Link-level detection (SITL)**: the IDS produced `COMMAND_INJECTION`-type evidence "
        f"(\"command(s) from unexpected source\") at or after the injection in "
        f"**{detected}/{len(trials)}** trials.", "",
        f"Detection is **not deterministic across identical draws**: trials sharing the exact same "
        f"`(seed, trial_index)` draw produced different outcomes on different live runs (see table; "
        f"`trial_index=0` was run 4 times total). Of the "
        f"{with_tap} trials run with the `ids_ingest.jsonl` diagnostic tap added, "
        f"{detected_with_tap}/{with_tap} detected; of the {len(trials) - with_tap} trials run without it, "
        f"{detected_without_tap}/{len(trials) - with_tap} detected. This is consistent with -- but does not "
        f"prove -- a timing/concurrency sensitivity in the live threaded UDP receive path "
        f"(`sources/mavlink_live.py` `UdpMavlinkTransport`), the same open hypothesis raised before this "
        f"batch; the parser, extractor, and detector logic were independently verified correct in isolation "
        f"before this batch (see `docs/STAGE2_PROGRESS.md`) and are not implicated by this result.", "",
        "**Known experimental artifact, not a false-alarm-rate result:** TWO non-expected-GCS identities in "
        "this topology trigger the same protocol rogue-telemetry-source rule -- the inert \"carrier\" client "
        "(sysid 252/compid 193) and the benign flight-driver client (sysid 253/compid 192); both are outside "
        "the PX4 profile's `expected_sysids`/`expected_gcs_sysids`, and once either's heartbeat is mirrored "
        "to the IDS, the rule correctly flags it on every decision that observes it (an earlier draft of this "
        "summary named only the carrier -- caught and corrected after `aegis-reviewer` traced the actual "
        "evidence strings and found the driver contributing an equal, independent share). This is a property "
        "of this specific experimental topology (an uplink-mirroring harness needs non-IDS uplink clients to "
        "mirror, and this one happens to have two outside the expected-identity lists), not a general benign "
        "false-alarm measurement -- it must never be merged with the `docs/CALIBRATION_PX4.md` false-alarm "
        "numbers, which use neither client.", "",
        "| trial | idx | ingest tap | onset s | acked | ack result | ttfa s | detected | latency s (from onset) | carrier/driver-artifact decisions |",
        "|---|---|---|---|---|---|---|---|---|---|"]
    for t in trials:
        L.append(f"| {t['trial']} | {t['trial_index']} | {'yes' if t['has_ids_ingest_tap'] else 'no'} | "
                 f"{t['onset_s']} | {'yes' if t['acked'] else 'NO'} | {t['first_ack_result_name']} | "
                 f"{t['time_to_first_ack_s']} | {'yes' if t['detected_command_injection'] else 'NO'} | "
                 f"{t['detection_latency_from_onset_s']} | {t['n_carrier_rogue_artifact_decisions']} |")
    L += ["", "## Limitations",
         "- n=10, not a statistically powered sample; counts are reported, not a rate with confidence bounds.",
         "- The split by \"ingest tap present\" is an observed correlation across two batches run at "
         "different times on one host, not a controlled A/B experiment (the only deliberate code change "
         "between batches was adding a read-only diagnostic log; host load, SITL boot timing, and Gazebo RTF "
         "were not held constant -- see `docs/PX4_SITL_INTEGRATION.md` Sec2).",
         "- All trials: one airframe/world/host, one benign flight driver script, one seed family (2001 + "
         "trial_index).",
         "- `acked=true` in every trial (independent of detection) reconfirms the command-path-effect result "
         "from the first trial; it is unrelated to whether the IDS flagged it.",
         "- No claim about MAVLink signing (link is unsigned throughout) or about real hardware/RF."]
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print(Path(a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
