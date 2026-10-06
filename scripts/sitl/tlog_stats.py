"""Stream statistics for a MAVLink .tlog (written for PX4 SITL captures, works on any tlog).

    .venv/Scripts/python.exe scripts/sitl/tlog_stats.py data/sitl/raw/benign_001.tlog [--json out.json]

Reports what the live-source design must respect: per-(sysid,compid) message
rates, inter-arrival jitter, sequence-number gaps (UDP loss), MAVLink framing
version, signing flag, receive-clock monotonicity, time_boot_ms vs receive-time
drift, and the PX4 custom_mode decoding. Environment tag of the *input* decides
the claim class -- this script only describes the stream.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from pymavlink import mavutil

# PX4 custom_mode: byte2 = main mode, byte3 = sub mode (px4_custom_mode.h)
PX4_MAIN = {1: "MANUAL", 2: "ALTCTL", 3: "POSCTL", 4: "AUTO", 5: "ACRO", 6: "OFFBOARD", 7: "STABILIZED", 8: "RATTITUDE"}
PX4_AUTO_SUB = {1: "READY", 2: "TAKEOFF", 3: "LOITER", 4: "MISSION", 5: "RTL", 6: "LAND", 7: "RTGS", 8: "FOLLOW_TARGET",
                9: "PRECLAND", 10: "VTOL_TAKEOFF"}


def decode_px4_mode(custom_mode: int) -> str:
    main = (custom_mode >> 16) & 0xFF
    sub = (custom_mode >> 24) & 0xFF
    name = PX4_MAIN.get(main, f"MAIN_{main}")
    return f"{name}/{PX4_AUTO_SUB.get(sub, sub)}" if main == 4 else name


def pct(v: list[float], q: float) -> float:
    if not v:
        return float("nan")
    s = sorted(v)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def iter_raw_frames(path: str | Path):
    """Yield ``(recv_unix_s, sysid, compid, seq, msgid, signed, frame_bytes)`` from raw tlog framing.

    Independent of any dialect: pymavlink reports frames outside its dialect as
    ``UNKNOWN_n`` with src 0/0, which corrupts per-source sequence accounting.
    """
    import struct
    data = Path(path).read_bytes()
    i = 0
    while i + 8 + 12 <= len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        f = i + 8
        if data[f] == 0xFE:  # MAVLink 1: magic,len,seq,sysid,compid,msgid(1)
            flen = 8 + data[f + 1]
            yield (ts, data[f + 3], data[f + 4], data[f + 2], data[f + 5], False, data[f:f + flen])
            i = f + flen
            continue
        if data[f] != 0xFD:  # corruption: stop
            return
        ln, inc = data[f + 1], data[f + 2]
        flen = 12 + ln + (13 if inc & 1 else 0)
        yield (ts, data[f + 5], data[f + 6], data[f + 4], data[f + 7] | data[f + 8] << 8 | data[f + 9] << 16,
               bool(inc & 1), data[f:f + flen])
        i = f + flen


def msg_name(msgid: int) -> str:
    from pymavlink.dialects.v20 import all as dialect
    cls = dialect.mavlink_map.get(msgid)
    return getattr(cls, "msgname", None) or f"MSG_{msgid}"


def stream_stats(path: str | Path, dialect: str = "ardupilotmega") -> dict:
    conn = mavutil.mavlink_connection(str(path), dialect=dialect, robust_parsing=True)
    first = last = None
    n = bad = 0
    per: dict[tuple, list[float]] = defaultdict(list)
    seq_prev: dict[tuple, int] = {}
    seq_lost: Counter = Counter()
    seq_total: Counter = Counter()
    magic: Counter = Counter()
    signed = 0
    back_steps = 0
    prev_ts = None
    modes: Counter = Counter()
    mode_seq: list[tuple[float, str]] = []
    hb_info: dict = {}
    gaps: list[tuple[float, int]] = []
    reorders: list[tuple[float, int]] = []
    seq_reorder: Counter = Counter()
    unwrapped: dict[tuple, int] = {}
    seen: dict[tuple, set[int]] = {}
    drift: list[tuple[float, float]] = []  # (recv_t, time_boot_ms/1000)
    for ts, sy, co, sq, mid, sg, _f in iter_raw_frames(path):
        src = (sy, co)
        per[(src, msg_name(mid))].append(ts)
        magic[f"0x{_f[0]:02X}"] += 1
        signed += sg
        if src in seq_prev:
            d = (sq - seq_prev[src]) % 256
            if 2 <= d < 128:            # forward jump (frames skipped *at that moment*)
                seq_lost[src] += d - 1
                gaps.append((round(ts, 3), d - 1))
            elif d >= 128:              # backward step (or repeat) -> out-of-order / duplicate
                seq_reorder[src] += 1
                reorders.append((round(ts, 3), 256 - d))
            unwrapped[src] += d if d < 128 else d - 256
        else:
            unwrapped[src] = 0
            seen[src] = set()
        seen[src].add(unwrapped[src])
        seq_prev[src] = sq
        seq_total[src] += 1
    while True:
        msg = conn.recv_match(blocking=False)
        if msg is None:
            break
        name = msg.get_type()
        if name == "BAD_DATA":
            bad += 1
            continue
        ts = float(msg._timestamp)
        first = ts if first is None else first
        last = ts
        if prev_ts is not None and ts < prev_ts:
            back_steps += 1
        prev_ts = ts
        n += 1
        src = (msg.get_srcSystem(), msg.get_srcComponent())
        if name == "HEARTBEAT" and msg.type != mavutil.mavlink.MAV_TYPE_GCS:
            m = decode_px4_mode(msg.custom_mode)
            modes[m] += 1
            if not mode_seq or mode_seq[-1][1] != m:
                mode_seq.append((round(ts - first, 2), m))
            hb_info = {"type": msg.type, "autopilot": msg.autopilot, "base_mode_last": msg.base_mode,
                       "system_status_last": msg.system_status, "mavlink_version": msg.mavlink_version,
                       "custom_mode_last_hex": hex(msg.custom_mode)}
        if hasattr(msg, "time_boot_ms") and src[0] != 255 and name in ("ATTITUDE", "GLOBAL_POSITION_INT"):
            drift.append((ts - first, msg.time_boot_ms / 1000.0))
    dur = (last - first) if first is not None else 0.0
    rows = []
    for (src, name), ts in sorted(per.items(), key=lambda kv: -len(kv[1])):
        d = [b - a for a, b in zip(ts, ts[1:], strict=False)]
        rows.append({"src": f"{src[0]}/{src[1]}", "msg": name, "count": len(ts),
                     "rate_hz": round(len(ts) / dur, 3) if dur else 0.0,
                     "dt_median_ms": round(statistics.median(d) * 1e3, 2) if d else None,
                     "dt_p99_ms": round(pct(d, 0.99) * 1e3, 2) if d else None,
                     "dt_max_ms": round(max(d) * 1e3, 2) if d else None})
    drift_ppm = None
    if len(drift) > 10:
        (r0, b0), (r1, b1) = drift[0], drift[-1]
        if r1 - r0 > 1:
            drift_ppm = round(((b1 - b0) / (r1 - r0) - 1.0) * 1e6, 1)
    return {
        "frames": n, "bad_data": bad, "duration_s": round(dur, 2),
        "first_recv_unix": first, "recv_clock_backsteps": back_steps,
        "framing_magic": dict(magic), "signed_frames": signed,
        "sources": {f"{s[0]}/{s[1]}": {"frames": seq_total[s], "seq_forward_gaps": seq_lost[s], "seq_reordered": seq_reorder[s],
                                       "seq_span": (max(seen[s]) - min(seen[s]) + 1) if seen.get(s) else 0,
                                       "seq_unique": len(seen.get(s, ())),
                                       "seq_net_missing": ((max(seen[s]) - min(seen[s]) + 1) - len(seen[s])) if seen.get(s) else 0,
                                       "seq_duplicates": seq_total[s] - len(seen.get(s, ())),
                                       "net_loss_pct": round(100.0 * (((max(seen[s]) - min(seen[s]) + 1) - len(seen[s])) if seen.get(s) else 0) / max(1, (max(seen[s]) - min(seen[s]) + 1) if seen.get(s) else 1), 3)}
                    for s in seq_total},
        "seq_gap_events": len(gaps), "seq_gap_sizes_top": sorted((g[1] for g in gaps), reverse=True)[:10],
        "seq_gap_t_offsets_s": [round(g[0] - (first or 0.0), 2) for g in gaps[:40]],
        "seq_reorder_events": len(reorders),
        "seq_reorder_t_offsets_s": [round(g[0] - (first or 0.0), 2) for g in reorders[:40]],
        "seq_reorder_depths": [g[1] for g in reorders[:40]],
        "heartbeat": hb_info, "modes": dict(modes), "mode_transitions": mode_seq,
        "boot_clock_vs_recv_drift_ppm": drift_ppm,
        "messages": rows,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("tlog")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    st = stream_stats(a.tlog)
    print(f"frames={st['frames']} dur={st['duration_s']}s bad={st['bad_data']} magic={st['framing_magic']} "
          f"signed={st['signed_frames']} backsteps={st['recv_clock_backsteps']} drift_ppm={st['boot_clock_vs_recv_drift_ppm']}")
    print("sources:", json.dumps(st["sources"]))
    print("heartbeat:", json.dumps(st["heartbeat"]))
    print("mode transitions:", st["mode_transitions"])
    print(f"{'src':6s} {'msg':30s} {'n':>6s} {'Hz':>8s} {'dt_med':>8s} {'dt_p99':>8s} {'dt_max':>8s}")
    for r in st["messages"]:
        print(f"{r['src']:6s} {r['msg']:30s} {r['count']:6d} {r['rate_hz']:8.2f} {r['dt_median_ms']!s:>8s} "
              f"{r['dt_p99_ms']!s:>8s} {r['dt_max_ms']!s:>8s}")
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(st, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
