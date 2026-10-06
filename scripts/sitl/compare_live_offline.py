"""Per-decision equivalence: live decisions vs offline replay of the SAME teed bytes.

    .venv/Scripts/python.exe scripts/sitl/compare_live_offline.py \
        artifacts/sitl/live_run_002.jsonl data/sitl/raw/live_run_002.tlog --out artifacts/sitl/live_run_002_equivalence.json

Environment: SITL. Compares, for every decision time ``t`` present in both: threat flag,
attack type, and threat score (tolerance 1e-3: the live JSONL rounds to 3 dp). Reports
decisions present on only one side (the final tick is expected offline-only when the live
run stopped at ``max_ticks``).

What this does and does NOT show: it shows the clock-driven live loop + tee reproduce the
offline assembly of the same frames. Both sides share ``_TickAssembler`` and the parser, so
it is NOT an independent decode check, and with an uncalibrated detector (every decision an
alarm) agreement on the threat flag is weak -- the score agreement is the informative part.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from replay_benign import MODEL, replay

from aegisflight.config import load_config


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("live_jsonl")
    ap.add_argument("tlog")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tol", type=float, default=1e-3)
    a = ap.parse_args(argv)

    live = {round(r["t"], 2): r for r in (json.loads(x) for x in Path(a.live_jsonl).read_text().splitlines() if x)}
    cfg = load_config()
    model = MODEL if Path(MODEL).exists() else None
    off = {round(r["t"], 2): r for r in replay(a.tlog, cfg, model, adapter="live")}
    common = sorted(set(live) & set(off))
    bad_flag = bad_type = bad_score = 0
    max_diff = 0.0
    for t in common:
        lv, o = live[t], off[t]
        bad_flag += bool(lv["threat"]) != bool(o["threat"])
        bad_type += lv["type"] != (o["pred"] if o["threat"] else "BENIGN") and lv["threat"] != o["threat"]
        d = abs(lv["score"] - o["threat_score"])
        max_diff = max(max_diff, d)
        bad_score += d > a.tol
    doc = {
        "schema": "aegisflight.sitl_live_equivalence/1", "environment": "SITL", "attack_status": "NONE",
        "live_decisions": len(live), "offline_decisions": len(off), "compared": len(common),
        "live_only_t": sorted(set(live) - set(off)), "offline_only_t": sorted(set(off) - set(live)),
        "threat_flag_mismatches": bad_flag, "type_mismatches_when_flag_differs": bad_type,
        "score_mismatches_over_tol": bad_score, "score_tol": a.tol, "max_abs_score_diff": max_diff,
        "caveat": "shared assembler+parser: not an independent decode check; all-alarm regime makes flag agreement weak",
    }
    Path(a.out).write_text(json.dumps(doc, indent=2))
    print(json.dumps(doc, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
