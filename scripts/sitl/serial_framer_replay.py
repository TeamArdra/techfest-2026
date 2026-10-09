"""Replay a recorded SITL tlog through ``MavlinkStreamFramer`` as if it arrived over a serial port.

Environment: REPLAY of a PX4 SITL capture. Claim class: none -- this checks FRAMING only (how many
recorded frames the serial framer would emit under each unknown-id policy); it is not detection
evidence and says nothing about a physical serial link (the bytes are re-chunked, not timed).

    python scripts/sitl/serial_framer_replay.py data/sitl/raw/benign_001.tlog \
        --json artifacts/sitl/serial_framer_replay_benign_001.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # sibling script module (tlog_stats)

from tlog_stats import iter_raw_frames  # noqa: E402

from aegisflight.sources.mavlink_live import _load_dialect  # noqa: E402
from aegisflight.sources.mavlink_serial import MavlinkStreamFramer  # noqa: E402


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def replay(tlog: Path, read_size: int) -> dict:
    known = _load_dialect().mavlink_map
    frames = [(mid, fb) for _ts, _sy, _co, _sq, mid, _sg, fb in iter_raw_frames(tlog)]
    blob = b"".join(fb for _, fb in frames)
    out_of_dialect = Counter(mid for mid, _ in frames if mid not in known)

    def run(**kw) -> tuple[MavlinkStreamFramer, int]:
        f = MavlinkStreamFramer(**kw)
        n = 0
        for i in range(0, len(blob), read_size):
            n += len(f.feed(blob[i : i + read_size]))
        return f, n

    default, n_default = run()
    opt_in, n_opt_in = run(accept_unverified_ids=True)
    return {
        "tlog": str(tlog).replace("\\", "/"),
        "tlog_sha256": sha256(tlog),
        "environment": "REPLAY (PX4 SITL capture re-chunked into fixed-size reads; no timing)",
        "read_size_bytes": read_size,
        "frames_in_capture": len(frames),
        "bytes_in_capture": len(blob),
        "out_of_dialect_frames_in_capture": sum(out_of_dialect.values()),
        "out_of_dialect_ids_in_capture": {str(k): v for k, v in sorted(out_of_dialect.items())},
        "default_policy": {
            "frames_emitted": n_default,
            "unverifiable_rejects": default.unverifiable_rejects,
            "crc_rejects": default.crc_rejects,
            "garbage_bytes": default.garbage_bytes,
            "crc_bytes_checked": default.crc_bytes_checked,
        },
        "accept_unverified_ids": {
            "frames_emitted": n_opt_in,
            "unverified_accepted": opt_in.unverified_accepted,
            "crc_rejects": opt_in.crc_rejects,
            "garbage_bytes": opt_in.garbage_bytes,
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tlog", type=Path, nargs="+")
    ap.add_argument("--read-size", type=int, default=256)
    ap.add_argument("--json", type=Path, help="write the results here (single tlog: an object)")
    a = ap.parse_args()
    results = [replay(p, a.read_size) for p in a.tlog]
    text = json.dumps(results[0] if len(results) == 1 else results, indent=2)
    if a.json:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
