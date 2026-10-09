"""Replay a recorded SITL tlog through ``MavlinkStreamFramer`` as if it arrived over a serial port.

Environment: REPLAY of a PX4 SITL capture. Claim class: none -- this checks FRAMING and the effect
of dropped frames on features; it is not detection evidence and says nothing about a physical
serial link (the bytes are re-chunked into fixed-size reads, not timed, and every emitted frame
keeps the ORIGINAL capture timestamp of that frame, so serial read-completion stamping is NOT
modelled).

Two policies are compared with the full capture (the baseline, which is also what the tlog replay
path sees):

* ``default``       -- ``SerialMavlinkTransport`` defaults: ids without a crc_extra are refused;
* ``verified_px4``  -- ``extra_crc=PX4_SITL_EXTRA_CRC`` (values verified for this PX4 build; see
                       ``aegisflight.sources.mavlink_live``), passed to the framer AND the parser.

For each policy it reports exact frame identity and order against the capture, an accounting that
separates genuine out-of-dialect frames refused from false candidates met while rescanning, an
independent CRC re-check of every emitted frame (reference ``_x25``, not the framer's table CRC),
and the effect on sequence-gap / loss features and on the ML score through the unchanged
``IDSPipeline`` (profile ``configs/px4_sitl`` + ``models/isoforest_px4.joblib``, thresholds
untouched).

    python scripts/sitl/serial_framer_replay.py data/sitl/raw/benign_001.tlog \
        --json artifacts/sitl/serial_framer_replay_benign_001.json
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # sibling script modules (tlog_stats, calib_common)

import calib_common as cc  # noqa: E402
from tlog_stats import iter_raw_frames  # noqa: E402

from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import (  # noqa: E402
    PX4_SITL_EXTRA_CRC,
    LiveStats,
    _load_dialect,
    _x25,
    frame_ticks,
)
from aegisflight.sources.mavlink_serial import MavlinkStreamFramer  # noqa: E402

ML_TRIGGER = cc.DET_TRIG["det_ml_anomaly"]


def frame_msgid(fb: bytes) -> int:
    return fb[7] | fb[8] << 8 | fb[9] << 16 if fb[0] == 0xFD else fb[5]


def independent_crc_ok(fb: bytes, extra: dict[int, int], known: dict) -> bool:
    """Re-verify a frame with the REFERENCE CRC (mavlink_live._x25), not the framer's table CRC."""
    mid = frame_msgid(fb)
    cls = known.get(mid)
    ce = cls.crc_extra if cls is not None else extra.get(mid)
    if ce is None:
        return False
    hdr = 10 if fb[0] == 0xFD else 6
    end = hdr + fb[1]
    return _x25(bytes([ce]), _x25(fb[1:end])) == int.from_bytes(fb[end : end + 2], "little")


def framer_pass(blob: bytes, read_size: int, **kw) -> tuple[MavlinkStreamFramer, list[bytes]]:
    f = MavlinkStreamFramer(**kw)
    out: list[bytes] = []
    for i in range(0, len(blob), read_size):
        out += f.feed(blob[i : i + read_size])
    return f, out


def is_ordered_subsequence(sub: list[bytes], full: list[bytes]) -> bool:
    it = iter(full)
    return all(any(x == y for y in it) for x in sub)


def pipeline_rows(frames: list[tuple[float, bytes]], extra: dict[int, int] | None) -> dict:
    """Decision-level rows from the UNCHANGED pipeline (px4_sitl profile, PX4-benign model)."""
    pipe = IDSPipeline(cc.cfg_for("px4_sitl"), model_path=str(cc.resolve(cc.PX4_MODEL)),
                       firmware_dir=None)
    stats = LiveStats()
    rows: dict[float, dict] = {}
    for tick in frame_ticks(frames, stats=stats, extra_crc=extra):
        a = pipe.process_tick(tick)
        if a is None:
            continue
        fr = pipe.last_frame
        rows[round(a.t, 6)] = {
            "max_seq_gap": float(fr.max_seq_gap), "loss_ratio": float(fr.loss_ratio),
            "ml": float(a.detector_scores.get("ml_anomaly", math.nan)),
            "threat": bool(a.threat), "score": float(a.threat_score),
        }
    return {"rows": rows, "unverified_frames": stats.unverified_frames,
            "bad_frames": stats.bad_frames, "frames_received": stats.frames_received}


def window_gap_counts(rows: dict[float, dict]) -> dict:
    wins: dict[int, bool] = {}
    for t, r in rows.items():
        wins[int(t)] = wins.get(int(t), False) or r["max_seq_gap"] > 0
    return {"windows": len(wins), "windows_with_seq_gap": sum(wins.values())}


def effect(rows: dict[float, dict], base: dict[float, dict]) -> dict:
    ts = sorted(set(rows) & set(base))
    gaps = [rows[t]["max_seq_gap"] for t in ts]
    dml = [abs(rows[t]["ml"] - base[t]["ml"]) for t in ts]
    return {
        "decisions": len(rows),
        "decisions_compared_with_baseline": len(ts),
        "decisions_with_seq_gap": sum(g > 0 for g in gaps),
        "max_seq_gap_max": max(gaps) if gaps else 0.0,
        "loss_ratio_mean": sum(rows[t]["loss_ratio"] for t in ts) / max(1, len(ts)),
        **window_gap_counts(rows),
        "ml_score_abs_diff_mean": sum(dml) / max(1, len(dml)),
        "ml_score_abs_diff_max": max(dml) if dml else 0.0,
        "decisions_ml_score_changed": sum(d > 1e-9 for d in dml),
        "ml_trigger_crossings_changed": sum(
            (rows[t]["ml"] >= ML_TRIGGER) != (base[t]["ml"] >= ML_TRIGGER) for t in ts),
        "threat_flag_changed": sum(rows[t]["threat"] != base[t]["threat"] for t in ts),
        "threat_decisions": sum(rows[t]["threat"] for t in rows),
    }


def replay(tlog: Path, read_size: int, with_features: bool) -> dict:
    known = _load_dialect().mavlink_map
    raw = [(ts, fb) for ts, _sy, _co, _sq, _mid, _sg, fb in iter_raw_frames(cc.resolve(tlog))]
    cap = [fb for _, fb in raw]
    blob = b"".join(cap)
    ood = Counter(frame_msgid(fb) for fb in cap if frame_msgid(fb) not in known)
    result: dict = {
        "tlog": str(tlog).replace("\\", "/"),
        "tlog_sha256": cc.sha256(cc.resolve(tlog)),
        "environment": "REPLAY (PX4 SITL capture re-chunked into fixed-size reads; original "
                       "per-frame timestamps kept; serial stamping not modelled)",
        "read_size_bytes": read_size,
        "frames_in_capture": len(cap),
        "bytes_in_capture": len(blob),
        "out_of_dialect_frames_in_capture": sum(ood.values()),
        "out_of_dialect_ids_in_capture": {str(k): v for k, v in sorted(ood.items())},
        "px4_sitl_extra_crc": {str(k): v for k, v in sorted(PX4_SITL_EXTRA_CRC.items())},
        "policies": {},
    }
    base_rows = None
    if with_features:
        base = pipeline_rows(raw, None)
        base_rows = base["rows"]
        result["baseline_all_frames"] = {
            "note": "every capture frame, default parser (out-of-dialect frames reach the parser as "
                    "header-sanity-only 'unverified' frames) = what the tlog replay path sees",
            "parser_unverified_frames": base["unverified_frames"],
            "parser_bad_frames": base["bad_frames"],
            **effect(base_rows, base_rows),
        }

    for name, extra in (("default", None), ("verified_px4", PX4_SITL_EXTRA_CRC)):
        f, out = framer_pass(blob, read_size, extra_crc=extra)
        verifiable = set(known) | set(extra or {})
        expected = [fb for fb in cap if frame_msgid(fb) in verifiable]
        refused_ids = Counter(frame_msgid(fb) for fb in cap if frame_msgid(fb) not in verifiable)
        tally = f.unverifiable_ids
        genuine_candidates = sum(tally.get(i, 0) for i in refused_ids)
        pol = {
            "framer_extra_crc_ids": sorted(extra or {}),
            "identity_and_order": {
                "frames_emitted": len(out),
                "emitted_equals_expected_exactly": out == expected,
                "emitted_is_ordered_subsequence_of_capture": is_ordered_subsequence(out, cap),
                "expected_frames": len(expected),
            },
            "no_crc_bypass": {
                "unverified_accepted": f.unverified_accepted,
                "emitted_frames_reverified_with_reference_crc": sum(
                    independent_crc_ok(fb, extra or {}, known) for fb in out),
                "all_emitted_reverified": all(independent_crc_ok(fb, extra or {}, known)
                                              for fb in out),
            },
            "accounting": {
                "genuine_frames_refused": sum(refused_ids.values()),
                "genuine_frames_refused_by_id": {str(k): v for k, v in sorted(refused_ids.items())},
                "capture_frames_neither_emitted_nor_refused": len(cap) - len(out)
                                                              - sum(refused_ids.values()),
                "unverifiable_candidates_total": f.unverifiable_rejects,
                "unverifiable_candidates_at_genuine_refused_ids": genuine_candidates,
                "false_unverifiable_candidates_from_rescanning":
                    f.unverifiable_rejects - genuine_candidates,
                "false_candidate_ids_observed": {
                    str(k): v for k, v in sorted(tally.items()) if k not in refused_ids},
                "crc_rejects_all_false_candidates_capture_is_uncorrupted": f.crc_rejects,
                "header_rejects": f.header_rejects,
                "garbage_bytes": f.garbage_bytes,
                "crc_bytes_checked": f.crc_bytes_checked,
            },
        }
        if with_features:
            kept = [(ts, fb) for ts, fb in raw if frame_msgid(fb) in verifiable]
            run = pipeline_rows(kept, extra)
            pol["pipeline_effect_vs_baseline"] = {
                "frames_fed": len(kept),
                "parser_unverified_frames": run["unverified_frames"],
                "parser_bad_frames": run["bad_frames"],
                **effect(run["rows"], base_rows),
            }
        result["policies"][name] = pol
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tlog", type=Path)
    ap.add_argument("--read-size", type=int, default=256)
    ap.add_argument("--no-features", action="store_true", help="skip the pipeline replays (fast)")
    ap.add_argument("--json", type=Path, help="write the results here")
    a = ap.parse_args()
    text = json.dumps(replay(a.tlog, a.read_size, not a.no_features), indent=2)
    if a.json:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
