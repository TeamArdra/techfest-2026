#!/usr/bin/env python
"""Session-level uncertainty and time-to-first-alert tables from a benchmark ``sessions.csv``.

Reads the per-session table written by ``scripts/benchmark_extended.py`` (columns ``kind,key,detected,ttd_s,fp_decisions``)
and writes into ``--out``:

* ``session_ci.csv`` / ``session_ci.md``: per attack class and per mode, sessions detected / sessions with a Wilson 95 %
  interval. The unit is the **session** (one flight with one attack); decisions inside a session are strongly correlated
  and are never treated as independent samples. Benign and link-stress benign sessions are reported as the share of sessions
  with at least one false-positive decision.
* ``latency_by_class.csv`` / ``.md``: time to first alert among the sessions that were detected (n, min, median,
  max, and a nearest-rank 95th percentile that is only printed when n >= 20, because below that it is just the maximum).
* ``stats_meta.json``: input path and SHA-256, git HEAD, and a statement of what the numbers are.

Everything here is ``SIM`` (generated sessions, attacks written by the team): design evidence, not an estimate of
real-world detection probability. Intervals are narrow only when n is large; with n = 4 per mode they are wide on purpose.

Usage: python scripts/make_submission_stats.py --sessions artifacts/benchmarks_extended/sessions.csv --out <dir>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from pathlib import Path

import pandas as pd

Z = 1.959964


def wilson(k: int, n: int, z: float = Z) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _cls(row) -> str:
    return row["key"].split(":")[0] if row["kind"] == "single" else row["kind"]


def _md(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join("" if pd.isna(v) else str(v) for v in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    src, out = Path(a.sessions), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(src)
    df["klass"] = df.apply(_cls, axis=1)
    df["detected"] = df["detected"].astype(bool)
    attack = df[df["kind"].isin(["single", "combo"])]

    rows = []
    for level, groups in (("class", attack.groupby("klass")), ("mode", attack.groupby("key"))):
        for name, g in groups:
            k, n = int(g["detected"].sum()), len(g)
            lo, hi = wilson(k, n)
            rows.append({"level": level, "name": name, "sessions": n, "detected": k,
                         "rate": round(k / n, 4), "wilson95_lo": round(lo, 4), "wilson95_hi": round(hi, 4)})
    for kind, g in df[~df["kind"].isin(["single", "combo"])].groupby("kind"):
        k, n = int((g["fp_decisions"] > 0).sum()), len(g)
        lo, hi = wilson(k, n)
        rows.append({"level": "benign sessions with >=1 false-positive decision", "name": kind, "sessions": n,
                     "detected": k, "rate": round(k / n, 4), "wilson95_lo": round(lo, 4), "wilson95_hi": round(hi, 4)})
    ci = pd.DataFrame(rows)
    ci.to_csv(out / "session_ci.csv", index=False)

    lat_rows = []
    for name, g in [*attack.groupby("klass"), *attack.groupby("key")]:
        t = g.loc[g["detected"], "ttd_s"].dropna().astype(float)
        if t.empty:
            continue
        p95 = round(float(t.quantile(0.95, interpolation="higher")), 2) if len(t) >= 20 else None
        lat_rows.append({"name": name, "detected_sessions": len(t), "min_s": round(t.min(), 2),
                         "median_s": round(t.median(), 2), "p95_s": p95, "max_s": round(t.max(), 2)})
    lat = pd.DataFrame(lat_rows)
    lat.to_csv(out / "latency_by_class.csv", index=False)

    (out / "session_ci.md").write_text(
        "## Session-level detection with Wilson 95 % intervals\n\nUnit = session. `SIM`, team-authored attacks. Decision-level "
        "recall is in `artifacts/benchmarks_extended/summary.md`; its decisions are correlated within a session and are not "
        "independent.\n\n" + _md(ci), encoding="utf-8")
    (out / "latency_by_class.md").write_text(
        "## Time to first alert (detected sessions only)\n\n`p95_s` is blank when fewer than 20 detected sessions exist. "
        "Undetected sessions are excluded here and listed in the CI table.\n\n" + _md(lat), encoding="utf-8")

    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        head = None
    (out / "stats_meta.json").write_text(json.dumps({
        "script": "scripts/make_submission_stats.py", "input": str(src),
        "input_sha256": hashlib.sha256(src.read_bytes()).hexdigest(), "git_head": head,
        "environment": "SIM", "z": Z, "unit": "session",
        "note": "design evidence; attacks and detectors written by the same team; no real-vehicle data"}, indent=2) + "\n",
        encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
