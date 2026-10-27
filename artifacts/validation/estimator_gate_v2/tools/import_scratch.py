"""Persist the estimator-gate v2 regression evidence from the session scratch into this bundle (aegis-validation,
2026-10-26). Nothing here re-runs the benchmark or ALFA: it copies their outputs, re-runs the exact comparator on
them, and writes ``manifest.json`` (sha256 of every source and every bundled file).

Copies are byte-for-byte, with ONE documented exception: ``alfa_gps_{head,final}.json`` carry a ``code`` field that is
the absolute path of the imported ``aegisflight/__init__.py`` (it names the local user profile / drive). That single
field is replaced by a placeholder (``<wt_head>/...`` or ``<repo>/...``); the script asserts every other value is
unchanged and records both hashes.

    .venv/Scripts/python.exe artifacts/validation/estimator_gate_v2/tools/import_scratch.py --scratch <scratch>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[4]
TOOLS = BUNDLE / "tools"

VERBATIM = {  # scratch-relative source -> bundle-relative destination
    "compare_results.py": "tools/compare_results.py",
    "alfa_gps_probe.py": "tools/alfa_gps_probe.py",
    "alfa_init_probe.py": "tools/alfa_init_probe.py",
    "bench_final/summary.md": "stage1_regression/summary.md",
    "bench_final/results.csv": "stage1_regression/results.csv",
    "bench_final/results.json": "stage1_regression/results.json",
    **{f"alfa_head/{c}/{f}": f"alfa/before/{c}/{f}" for c in ("alfa", "alfa_calibrated")
       for f in ("results.json", "summary.md")},
    **{f"alfa_final/{c}/{f}": f"alfa/after/{c}/{f}" for c in ("alfa", "alfa_calibrated")
       for f in ("results.json", "summary.md")},
}
REDACT_CODE = {"alfa_gps_head.json": ("alfa/gps_spoofing_decisions/alfa_gps_head.json",
                                      "<wt_head>/src/aegisflight/__init__.py"),
               "alfa_gps_final.json": ("alfa/gps_spoofing_decisions/alfa_gps_final.json",
                                       "<repo>/src/aegisflight/__init__.py")}
COORD_KEYS = re.compile(r'"(lat|lon|latitude|longitude|lat_deg|lon_deg)"', re.IGNORECASE)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def compare(mode: str, a: Path, b: Path, out: Path) -> int:
    p = subprocess.run([sys.executable, str(TOOLS / "compare_results.py"), mode, str(a), str(b)],
                       capture_output=True, text=True, encoding="utf-8",
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"# compare_results.py {mode} <baseline> <candidate> (exit {p.returncode})\n"
                   f"# baseline : {a.relative_to(REPO).as_posix() if a.is_relative_to(REPO) else a.name}\n"
                   f"# candidate: {b.relative_to(REPO).as_posix() if b.is_relative_to(REPO) else b.name}\n"
                   + p.stdout + p.stderr, encoding="utf-8", newline="\n")
    return p.returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scratch", required=True)
    a = ap.parse_args(argv)
    scratch = Path(a.scratch)
    manifest: dict = {"verbatim_copies": {}, "redacted_copies": {}, "comparisons": {}, "coordinate_scan": {}}

    for src_rel, dst_rel in VERBATIM.items():
        src, dst = scratch / src_rel, BUNDLE / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        assert dst.read_bytes() == src.read_bytes()
        manifest["verbatim_copies"][dst_rel] = {"source": f"<scratch>/{src_rel}", "sha256": sha(dst.read_bytes())}

    for src_rel, (dst_rel, placeholder) in REDACT_CODE.items():
        src, dst = scratch / src_rel, BUNDLE / dst_rel
        orig = json.loads(src.read_text(encoding="utf-8"))
        red = dict(orig, code=placeholder)
        assert {k: v for k, v in red.items() if k != "code"} == {k: v for k, v in orig.items() if k != "code"}
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(red, indent=1), encoding="utf-8", newline="\n")
        manifest["redacted_copies"][dst_rel] = {
            "source": f"<scratch>/{src_rel}", "source_sha256": sha(src.read_bytes()),
            "sha256": sha(dst.read_bytes()), "changed_field": "code (absolute local path -> placeholder)",
            "rows": len(orig["rows"]), "n_tlogs": orig["n_tlogs"]}

    cmp = {
        "stage1_regression/compare_vs_committed_baseline.txt":
            ("bench", REPO / "artifacts/benchmarks", BUNDLE / "stage1_regression"),
        "alfa/compare_before_after_alfa.txt":
            ("json", BUNDLE / "alfa/before/alfa/results.json", BUNDLE / "alfa/after/alfa/results.json"),
        "alfa/compare_before_after_alfa_calibrated.txt":
            ("json", BUNDLE / "alfa/before/alfa_calibrated/results.json",
             BUNDLE / "alfa/after/alfa_calibrated/results.json"),
        "alfa/compare_committed_vs_before_alfa.txt":
            ("json", REPO / "artifacts/external/alfa/results.json", BUNDLE / "alfa/before/alfa/results.json"),
        "alfa/compare_committed_vs_before_alfa_calibrated.txt":
            ("json", REPO / "artifacts/external/alfa_calibrated/results.json",
             BUNDLE / "alfa/before/alfa_calibrated/results.json"),
    }
    for out_rel, (mode, x, y) in cmp.items():
        rc = compare(mode, x, y, BUNDLE / out_rel)
        manifest["comparisons"][out_rel] = {"mode": mode, "exit": rc}

    for p in sorted(BUNDLE.rglob("*.json")):
        if p.name == "manifest.json":
            continue
        manifest["coordinate_scan"][p.relative_to(BUNDLE).as_posix()] = len(COORD_KEYS.findall(
            p.read_text(encoding="utf-8")))

    manifest["bundle_files"] = {p.relative_to(BUNDLE).as_posix(): {"bytes": p.stat().st_size,
                                                                   "sha256": sha(p.read_bytes())}
                                for p in sorted(BUNDLE.rglob("*")) if p.is_file() and p.name != "manifest.json"
                                and "__pycache__" not in p.parts}
    (BUNDLE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(manifest["comparisons"], indent=1))
    print("coordinate-key hits:", sum(manifest["coordinate_scan"].values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
