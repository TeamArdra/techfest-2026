#!/usr/bin/env python
"""Compare two ``results.csv`` files from ``aegis benchmark`` and report whether every non-timing cell is equal.

Timing, CPU, memory and throughput columns depend on the machine and are excluded by name. Prints and (with ``--json``)
writes: the shape of both tables, the number of compared cells, how many are equal, and the columns that differ.

Usage: python scripts/compare_benchmark_runs.py <committed results.csv> <rerun results.csv> [--json out.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

TIMING_HINTS = ("latency_ms", "compute", "cpu", "rss", "throughput", "wall", "msgs_per_s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("committed")
    ap.add_argument("rerun")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    x, y = pd.read_csv(a.committed), pd.read_csv(a.rerun)
    res: dict = {"committed": a.committed, "rerun": a.rerun,
                 "committed_sha256": hashlib.sha256(Path(a.committed).read_bytes()).hexdigest(),
                 "rerun_sha256": hashlib.sha256(Path(a.rerun).read_bytes()).hexdigest(),
                 "shape_committed": list(x.shape), "shape_rerun": list(y.shape)}
    if x.shape != y.shape or list(x.columns) != list(y.columns):
        res["comparable"] = False
    else:
        cols = [c for c in x.columns if not any(h in c.lower() for h in TIMING_HINTS)]
        eq = x[cols].fillna("NA").astype(str) == y[cols].fillna("NA").astype(str)
        res.update({"comparable": True, "excluded_timing_columns": [c for c in x.columns if c not in cols],
                    "cells_compared": int(eq.size), "cells_equal": int(eq.values.sum()),
                    "columns_that_differ": [c for c in cols if not eq[c].all()]})
    print(json.dumps(res, indent=2))
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return 0 if res.get("comparable") and res.get("cells_equal") == res.get("cells_compared") else 1


if __name__ == "__main__":
    raise SystemExit(main())
