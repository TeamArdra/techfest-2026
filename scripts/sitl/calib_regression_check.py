"""Compare a scratch ``aegis benchmark --out <dir> --no-figures`` run with the committed Stage-1 baseline.

    aegis benchmark --out <scratch> --no-figures
    .venv/Scripts/python.exe scripts/sitl/calib_regression_check.py <scratch>

Environment: SIM. Only the TP/FP/TN/FN line is compared (timing rows are machine-dependent).
Writes ``artifacts/sitl/calibration/stage1_regression.json``; never writes under ``artifacts/benchmarks*``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import calib_common as cc  # noqa: E402

PAT = re.compile(r"TP / FP / TN / FN \| (\d+) / (\d+) / (\d+) / (\d+)")


def counts(path: Path) -> list[int]:
    m = PAT.search(path.read_text(encoding="utf-8"))
    if not m:
        raise SystemExit(f"no confusion line in {path}")
    return [int(x) for x in m.groups()]


def main() -> int:
    scratch = Path(sys.argv[1]) / "summary.md"
    committed = cc.REPO / "artifacts" / "benchmarks" / "summary.md"
    a, b = counts(committed), counts(scratch)
    doc = {"schema": "aegisflight.stage1_regression/1", "environment": "SIM",
           "committed": dict(zip(("TP", "FP", "TN", "FN"), a, strict=True)),
           "after_change": dict(zip(("TP", "FP", "TN", "FN"), b, strict=True)),
           "identical": a == b,
           "command": "aegis benchmark --out <scratch> --no-figures",
           "change_under_test": "detectors/protocol.py startup_grace_s (default 0), detectors/physics.py yaw_course_deg (default 25.0)"}
    (cc.OUT_DIR / "stage1_regression.json").write_text(json.dumps(doc, indent=2))
    print(doc)
    return 0 if a == b else 1


if __name__ == "__main__":
    raise SystemExit(main())
