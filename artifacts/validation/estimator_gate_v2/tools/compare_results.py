"""Exact comparison of two result trees, ignoring only machine-dependent timing/resource fields.

usage: compare_results.py bench <baseline_dir> <candidate_dir>
       compare_results.py json  <baseline.json> <candidate.json>
"""
from __future__ import annotations

import csv
import json
import math
import sys
from pathlib import Path

TIMING_KEYS = {"compute_latency_ms", "throughput", "resources", "elapsed_s", "wall_s", "runtime_s"}
TIMING_COLS = {"throughput_msgs_per_s", "mean_compute_latency_ms"}


def same(a, b) -> bool:
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    return a == b


def walk(a, b, path: str, out: list[str], counter: list[int]) -> None:
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k in TIMING_KEYS:
                continue
            if k not in a or k not in b:
                out.append(f"{path}/{k}: key only in {'candidate' if k not in a else 'baseline'}")
                continue
            walk(a[k], b[k], f"{path}/{k}", out, counter)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: list length {len(a)} != {len(b)}")
        for i, (x, y) in enumerate(zip(a, b, strict=False)):
            walk(x, y, f"{path}[{i}]", out, counter)
    else:
        counter[0] += 1
        if not same(a, b):
            out.append(f"{path}: {a!r} != {b!r}")


def cmp_json(p1: Path, p2: Path) -> tuple[int, list[str]]:
    out: list[str] = []
    counter = [0]
    walk(json.loads(p1.read_text(encoding="utf-8")), json.loads(p2.read_text(encoding="utf-8")), "", out, counter)
    return counter[0], out


def cmp_csv(p1: Path, p2: Path) -> tuple[int, list[str]]:
    r1 = list(csv.DictReader(p1.open(encoding="utf-8")))
    r2 = list(csv.DictReader(p2.open(encoding="utf-8")))
    out: list[str] = []
    n = 0
    if len(r1) != len(r2):
        out.append(f"row count {len(r1)} != {len(r2)}")
    for i, (a, b) in enumerate(zip(r1, r2, strict=False)):
        for col in a:
            if col in TIMING_COLS:
                continue
            n += 1
            if a[col] != b.get(col):
                out.append(f"row {i} ({a.get('scenario')},{a.get('seed')}) {col}: {a[col]!r} != {b.get(col)!r}")
    return n, out


def main() -> int:
    mode, x, y = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    if mode == "bench":
        n_csv, d_csv = cmp_csv(x / "results.csv", y / "results.csv")
        n_js, d_js = cmp_json(x / "results.json", y / "results.json")
        cand = json.loads((y / "results.json").read_text(encoding="utf-8"))
        print("candidate confusion_matrix:", cand.get("confusion_matrix"))
        print(f"CSV non-timing cells compared: {n_csv}, differing: {len(d_csv)}")
        print(f"JSON non-timing leaves compared: {n_js}, differing: {len(d_js)}")
        for line in (d_csv + d_js)[:40]:
            print("  DIFF", line)
        return 0 if not (d_csv or d_js) else 1
    n, d = cmp_json(x, y)
    print(f"JSON non-timing leaves compared: {n}, differing: {len(d)}")
    for line in d[:60]:
        print("  DIFF", line)
    return 0 if not d else 1


if __name__ == "__main__":
    sys.exit(main())
