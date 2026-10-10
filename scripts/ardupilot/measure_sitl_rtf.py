"""SITL real-time factor from a capture: simulator ``time_boot_ms`` against the capture's wall-clock stamps.

    .venv/Scripts/python.exe scripts/ardupilot/measure_sitl_rtf.py --json artifacts/ardupilot/sitl_rtf.json \
        data/ardupilot/raw/ap_benign_six_001.clean.tlog [more.tlog ...]

Uses ATTITUDE (id 30; streamed at ~10 Hz) ``time_boot_ms`` (first u32 of the payload). Boot-time frames carry a bogus
``time_boot_ms`` (the simulator logs "Waiting for internal clock bits to be set"), so only frames with
``time_boot_ms`` in (30 s, 10,000 s) are used, and the slope is a least-squares fit over those frames, not
last-minus-first. Environment: REPLAY analysis of SITL captures. Claim class: none.
"""

from __future__ import annotations

import argparse
import json
import statistics
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "scripts" / "sitl"))

from tlog_stats import iter_raw_frames  # noqa: E402


def rtf(tlog: Path) -> dict:
    pts = [(ts, struct.unpack_from("<I", fb, 10)[0] / 1000.0)
           for ts, _sy, _co, _sq, mid, _sg, fb in iter_raw_frames(tlog) if mid == 30 and fb[0] == 0xFD]
    pts = [(w, b) for w, b in pts if 30.0 < b < 10_000.0]
    if len(pts) < 50:
        return {"tlog": str(tlog), "error": "too few usable ATTITUDE frames", "frames": len(pts)}
    mw, mb = statistics.fmean(w for w, _ in pts), statistics.fmean(b for _, b in pts)
    slope = (sum((w - mw) * (b - mb) for w, b in pts) / sum((w - mw) ** 2 for w, _ in pts))
    return {"tlog": str(tlog), "frames_used": len(pts), "wall_span_s": round(pts[-1][0] - pts[0][0], 1),
            "rtf_least_squares_slope": round(slope, 4)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tlogs", nargs="+")
    ap.add_argument("--json")
    a = ap.parse_args()
    rows = [rtf(Path(t)) for t in a.tlogs]
    vals = [r["rtf_least_squares_slope"] for r in rows if "rtf_least_squares_slope" in r]
    out = {"schema": "aegisflight.sitl_rtf/1", "environment": "REPLAY analysis of SITL captures", "runs": rows,
           "min": min(vals) if vals else None, "max": max(vals) if vals else None}
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
