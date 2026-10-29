#!/usr/bin/env python
"""Session-level Wilson 95 % intervals for the independent ``SITL`` attack trials and the ``REPLAY`` false-alarm flights.

Reads ONLY existing generated artifacts (nothing is re-run, nothing is simulated):

* ``SITL``: the per-trial tables in ``artifacts/sitl/P2_*_summary.md`` and ``artifacts/sitl/closure/final_*_summary.md``.
  One trial = one fresh PX4 SITL boot with one attack; the unit of analysis is the trial. A table is used only if it has a
  yes/no column named ``detected`` (or ``any`` / ``any detected``); every parsed row is listed in the output.
* ``REPLAY`` (real flight logs, benign / fault evidence, NOT attack detection): per-flight rows of
  ``artifacts/external/px4_review_v2/per_flight.csv`` (mapping ``px4_telemetry``) and ``artifacts/external/alfa_calibrated/results.json``
  (``per_flight``). The unit is the flight (log); decisions inside a flight are correlated and are never pooled into an interval.

Intervals are Wilson 95 %. With n = 3..24 they are wide; a k/n of 3/3 gives a lower bound of 0.44. Trials share one airframe, one world,
one host and one script family, so even the session-level interval ignores that shared dependence (stated in the output).

Usage: python scripts/make_session_ci_sitl_replay.py --out artifacts/validation/session_ci_sitl_replay_20261029
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
from pathlib import Path

Z = 1.959964
YES = {"yes", "true", "1"}
NO = {"no", "false", "0"}
ALFA_MIN_DECISIONS = 500


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    h = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse_tables(md: str):
    """Yield (section_title, header, rows) for each markdown table."""
    lines = md.splitlines()
    title, i = "", 0
    while i < len(lines):
        if lines[i].startswith("#"):
            title = lines[i].lstrip("# ").strip()
        if lines[i].startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            header = _cells(lines[i])
            j, rows = i + 2, []
            while j < len(lines) and lines[j].startswith("|"):
                rows.append(_cells(lines[j]))
                j += 1
            yield title, header, rows
            i = j
            continue
        i += 1


def sitl_tables(paths: list[Path]) -> list[dict]:
    out = []
    for p in paths:
        for title, header, rows in parse_tables(p.read_text(encoding="utf-8")):
            low = [h.lower() for h in header]
            col = next((low.index(n) for n in ("detected", "any detected", "any") if n in low), None)
            if col is None or "trial" not in low[0] or "superseded" in title.lower():
                continue  # superseded batches (harness defect) are not evidence
            vals = [(r[0], r[col].lower()) for r in rows if len(r) == len(header)]
            if not vals or any(v not in YES | NO for _, v in vals):
                continue
            k = sum(v in YES for _, v in vals)
            n = len(vals)
            lo, hi = wilson(k, n)
            out.append({"file": str(p).replace("\\", "/"), "section": title, "column": header[col], "trials": n, "detected": k,
                        "wilson95": [round(lo, 4), round(hi, 4)], "trial_ids": [t for t, _ in vals],
                        "undetected": [t for t, v in vals if v in NO]})
    return out


def replay_flights(px4_csv: Path, alfa_json: Path) -> list[dict]:
    out = []
    with px4_csv.open(newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["mapping"] == "px4_telemetry"]
    for label, key, thr in (("any physics-detector trigger", "physics_trigger_rate", 0.0),
                            ("physics trigger on > 1 % of airborne ticks", "physics_trigger_rate", 0.01),
                            ("ML navigation probe alarm on > 1 % of airborne ticks", "ml_probe_alarm_rate", 0.01)):
        k = sum(float(r[key]) > thr for r in rows)
        lo, hi = wilson(k, len(rows))
        out.append({"source": str(px4_csv).replace("\\", "/"), "environment": "REPLAY", "dataset": "PX4 Flight Review public logs, mapping px4_telemetry",
                    "claim": "false-alarm evidence on real flights (no attacks); network features absent, ML is a navigation probe",
                    "metric": f"flights with {label}", "flights": len(rows), "k": k, "wilson95": [round(lo, 4), round(hi, 4)]})
    all_pf = json.loads(alfa_json.read_text(encoding="utf-8"))["per_flight"]
    # A log with fewer than ALFA_MIN_DECISIONS kept decisions (100 s at 5 Hz) says nothing about a false-alarm rate; the cut is fixed here,
    # not chosen from the outcome, and the excluded count is reported.
    pf = [r for r in all_pf if r["threat_rate"] is not None and r["decisions_kept"] >= ALFA_MIN_DECISIONS]
    for label, thr in (("any fused threat decision", 0.0), ("fused threat on > 1 % of decisions", 0.01)):
        k = sum(float(r["threat_rate"]) > thr for r in pf)
        lo, hi = wilson(k, len(pf))
        out.append({"source": str(alfa_json).replace("\\", "/"), "environment": "REPLAY", "dataset": "ALFA held-out dates, per-vehicle calibrated protocol rate, ML off",
                    "claim": "false-alarm / fault evidence on real flights; the dataset's faults are physical, not cyber attacks",
                    "metric": f"flight logs with {label} (all labelled and unlabelled decisions)", "flights": len(pf), "k": k, "excluded_short_or_empty_logs": len(all_pf) - len(pf),
                    "wilson95": [round(lo, 4), round(hi, 4)]})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    sitl_paths = sorted(Path("artifacts/sitl").glob("P2_*_summary.md")) + sorted(Path("artifacts/sitl/closure").glob("final_*_summary.md"))
    sitl = sitl_tables(sitl_paths)
    replay = replay_flights(Path("artifacts/external/px4_review_v2/per_flight.csv"), Path("artifacts/external/alfa_calibrated/results.json"))
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    inputs = {str(p).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in sitl_paths}
    doc = {"sitl_session_level": sitl, "replay_flight_level": replay, "git_head": head, "input_sha256": inputs,
           "regenerate": f"python scripts/make_session_ci_sitl_replay.py --out {str(a.out).replace(chr(92), '/')}"}
    (a.out / "session_ci.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    md = ["# Session-level uncertainty for SITL trials and REPLAY flights (generated; do not edit)", "",
          f"Regenerate: `{doc['regenerate']}`. Inputs: existing generated artifacts only (hashes in `session_ci.json`). Wilson 95 %; the unit is the trial / flight, never the decision.", "",
          "## SITL attack trials (link-level detection on PX4 SITL; one fresh boot per trial)", "",
          "| Source table | Section | Trials | Detected | Wilson 95 % | Not detected |", "|---|---|---|---|---|---|"]
    for r in sitl:
        md.append(f"| `{r['file']}` | {r['section']} | {r['trials']} | {r['detected']} | [{r['wilson95'][0]:.2f}, {r['wilson95'][1]:.2f}] | {', '.join(r['undetected']) or '-'} |")
    md += ["", "Limits: all trials use one airframe, world, host and script family, so trials are not independent of that shared setup and the intervals are optimistic about generalisation. "
           "The vehicle is disarmed on the ground in most batches. Detection is link-level only. Tables whose column is not yes/no and batches marked superseded are skipped. Both the n=10 batches (`P2_*`) and the later n=3 closure batches (`final_*`) are listed; they are different runs, not pooled.", "",
           "## REPLAY of real flight logs (false-alarm / fault evidence, not attack detection)", "",
           "| Dataset | Metric | Flights | k | Wilson 95 % |", "|---|---|---|---|---|"]
    for r in replay:
        md.append(f"| {r['dataset']} (`{r['source']}`) | {r['metric']} | {r['flights']} | {r['k']} | [{r['wilson95'][0]:.2f}, {r['wilson95'][1]:.2f}] |")
    md += ["", f"ALFA rows keep only logs with >= {ALFA_MIN_DECISIONS} decisions (excluded: {replay[-1]['excluded_short_or_empty_logs']} of {replay[-1]['flights'] + replay[-1]['excluded_short_or_empty_logs']} logs). "
           "Limits: flights are not randomly drawn from a population (PX4: seeded sample of public logs; ALFA: one airframe family, held-out dates). "
           "ALFA files can include several recordings of one flight (the source artifact dedups decisions, not files). "
           "No attack-detection claim and no real-world rate follows from these rows.", ""]
    (a.out / "session_ci.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
