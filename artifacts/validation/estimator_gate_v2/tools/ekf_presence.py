"""Which replay inputs can exercise the estimator gate at all (aegis-validation, 2026-10-26).

Per tlog: the number of EKF_STATUS_REPORT frames (ardupilotmega id 193), how many say "no horizontal position
solution" (CONST_POS_MODE set, or neither EKF_POS_HORIZ_ABS nor EKF_POS_HORIZ_REL set: the same definition as
``features/extractor.py``), and the longest continuous no-solution span with report gaps <= 2 s (v2 gates a fix only
after >= 2 s of such reports). Reads the tlogs only; nothing is fed to any detector.

    .venv/Scripts/python.exe artifacts/validation/estimator_gate_v2/tools/ekf_presence.py \
        --out artifacts/validation/estimator_gate_v2/replay_identity/ekf_presence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "scripts" / "sitl"))
from pymavlink.dialects.v20 import ardupilotmega as apm  # noqa: E402
from tlog_stats import iter_raw_frames  # noqa: E402

HORIZ = apm.EKF_POS_HORIZ_ABS | apm.EKF_POS_HORIZ_REL
CONST = apm.EKF_CONST_POS_MODE
GLOBS = ("data/ardupilot/raw/*.tlog", "data/sitl/raw/benign_*.tlog")
FILES = tuple(f"data/hardware/raw/telemetry_radio_{n}.tlog" for n in ("005", "007", "008", "009"))


def scan(p: Path) -> dict:
    mav = apm.MAVLink(None)
    mav.robust_parsing = True
    n = nosol = 0
    run_start = last = None
    longest = 0.0
    for ts, _s, _c, _q, mid, _g, fb in iter_raw_frames(p):
        if mid != 193:
            continue
        for m in mav.parse_buffer(fb) or []:
            if m.get_type() != "EKF_STATUS_REPORT":
                continue
            n += 1
            sol = bool(m.flags & HORIZ) and not m.flags & CONST
            if sol or (last is not None and ts - last > 2.0):
                run_start = None
            if not sol:
                nosol += 1
                if run_start is None:
                    run_start = ts
                longest = max(longest, ts - run_start)
            last = ts
    return {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "ekf_status_reports": n,
            "no_solution_reports": nosol, "longest_no_solution_span_s": round(longest, 2)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    files = sorted({p for g in GLOBS for p in REPO.glob(g)}) + [REPO / f for f in FILES if (REPO / f).exists()]
    rows = {p.relative_to(REPO).as_posix(): scan(p) for p in files}
    out = {"definition": "no solution = CONST_POS_MODE or not (POS_HORIZ_ABS | POS_HORIZ_REL); span = continuous "
                         "no-solution reports with gaps <= 2 s",
           "n_files": len(rows), "n_with_ekf_status_report": sum(r["ekf_status_reports"] > 0 for r in rows.values()),
           "files": rows}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8", newline="\n")
    print(f"{out['n_with_ekf_status_report']} of {len(rows)} files contain EKF_STATUS_REPORT -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
