"""Passive MAVLink probe for a physical flight controller on a serial port (RECEIVE ONLY).

Environment tag: BENCH -- a physical flight controller on a desk, USB-attached, disarmed, no props,
no airframe. That is neither SIM nor SITL nor a flight (HITL/FIELD); results say nothing about a
vehicle in the air. Claim class: none -- this describes the telemetry stream (coverage, rates,
framing health); it is not detection evidence.

Safety contract (checked, not just promised):
* Nothing is ever written to the port: ``SerialMavlinkTransport.send()`` is never called and the
  report records ``bytes_sent`` (must be 0). No heartbeat, no request, no command, no parameter read.
* Only ONE process may hold the port: the script fails fast (exit 2) if the open fails (e.g. a GCS
  already has it) instead of retrying forever.
* The USB-CDC link ignores the baud rate; ``--baud`` only matters for a UART/radio link.

Outputs: a JSON report (``--json``) and, optionally, the raw frames as a MAVLink ``.tlog``
(8-byte big-endian wall-clock microseconds + frame; ``--tlog``) so the capture can be replayed
through the same code offline. Raw captures may contain the bench GPS position: keep them local
(``data/hardware/raw/*.tlog`` is git-ignored).

    .venv/Scripts/python.exe scripts/hardware/pixhawk_passive_probe.py --port COM5 --duration 120 \
        --json artifacts/hardware/pixhawk6x_probe_001.json --tlog data/hardware/raw/pixhawk6x_001.tlog
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from aegisflight.sources.mavlink_live import LiveStats, MavlinkFrameParser
from aegisflight.sources.mavlink_serial import SerialMavlinkTransport

#: Messages the Stage-1 feature extractor reads (``features/extractor.py``); coverage is scored against these.
PIPELINE_MESSAGES = ("HEARTBEAT", "SYS_STATUS", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "ATTITUDE", "VFR_HUD")

MAV_STATE = {0: "UNINIT", 1: "BOOT", 2: "CALIBRATING", 3: "STANDBY", 4: "ACTIVE", 5: "CRITICAL",
             6: "EMERGENCY", 7: "POWEROFF", 8: "TERMINATION"}
MAV_AUTOPILOT = {0: "GENERIC", 3: "ARDUPILOTMEGA", 12: "PX4"}
MAV_TYPE = {0: "GENERIC", 1: "FIXED_WING", 2: "QUADROTOR", 10: "GROUND_ROVER", 11: "SURFACE_BOAT",
            12: "SUBMARINE", 13: "HEXAROTOR", 14: "OCTOROTOR", 20: "VTOL_TILTROTOR", 21: "VTOL_RESERVED2",
            6: "GCS", 18: "ONBOARD_CONTROLLER", 27: "ADSB", 30: "GIMBAL", 31: "ODID"}
MAV_MODE_FLAG_SAFETY_ARMED = 128


def _pct(v: list[float], q: float) -> float | None:
    if not v:
        return None
    s = sorted(v)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))]


def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10,
                             cwd=Path(__file__).resolve().parents[2])
        return out.stdout.strip() or None
    except Exception:  # noqa: BLE001 - provenance only
        return None


def _seq_loss(seqs: list[int]) -> tuple[int, int, int]:
    """(expected_frames, lost, regressions) for a 0..255 wrapping sequence, in arrival order."""
    lost = regressions = 0
    prev = None
    for s in seqs:
        if prev is not None:
            d = (s - prev) & 0xFF
            if d == 0 or d > 200:  # duplicate / backwards step: not a forward gap
                regressions += 1
            else:
                lost += d - 1
        prev = s
    return len(seqs) + lost, lost, regressions


def _header(frame: bytes) -> tuple[int, int, int, int, bool, bool]:
    """(sysid, compid, seq, msgid, v2, signed) straight from the raw header."""
    if frame[0] == 0xFD:
        return frame[5], frame[6], frame[4], frame[7] | frame[8] << 8 | frame[9] << 16, True, bool(frame[2] & 1)
    return frame[3], frame[4], frame[2], frame[5], False, False


def run(args: argparse.Namespace) -> int:
    import pymavlink
    import serial

    transport = SerialMavlinkTransport(args.port, baudrate=args.baud, reconnect=True,
                                       reconnect_interval_s=args.reconnect_interval)
    stats = LiveStats()
    parser = MavlinkFrameParser(stats)
    tlog_fh = None
    if args.tlog:
        Path(args.tlog).parent.mkdir(parents=True, exist_ok=True)
        tlog_fh = open(args.tlog, "wb")
    mono0 = time.monotonic_ns()
    wall0_us = time.time_ns() // 1000

    per_msg_t: dict[str, list[float]] = defaultdict(list)
    per_msg_count: Counter[str] = Counter()
    per_msg_id: dict[str, int] = {}
    src_seq: dict[tuple[int, int], list[int]] = defaultdict(list)
    sys_seq: dict[int, list[int]] = defaultdict(list)
    link_seq: list[int] = []
    versions: Counter[str] = Counter()
    signed_frames = 0
    heartbeats: list[dict] = []
    statustext: list[dict] = []
    autopilot_version: dict | None = None
    first_frame_s = first_hb_s = None
    frames = 0
    bytes_in_frames = 0
    decode_none = 0
    gap_events: list[dict] = []
    last_frame_t: float | None = None

    transport.start()
    t_start = time.monotonic()
    deadline = t_start + args.duration
    open_checked = False
    try:
        while time.monotonic() < deadline:
            time.sleep(0.02)
            if not open_checked and time.monotonic() - t_start > 3.0:
                open_checked = True
                if not transport.connected and not args.keep_trying:
                    print(f"FAIL: cannot open {args.port}: {transport.last_error}", file=sys.stderr)
                    return 2
            for stamp_ns, frame in transport.poll():
                t = (stamp_ns - mono0) / 1e9
                if tlog_fh is not None:
                    tlog_fh.write(struct.pack(">Q", wall0_us + (stamp_ns - mono0) // 1000) + frame)
                frames += 1
                bytes_in_frames += len(frame)
                sysid, compid, seq, msgid, v2, signed = _header(frame)
                versions["v2" if v2 else "v1"] += 1
                signed_frames += signed
                src_seq[(sysid, compid)].append(seq)
                sys_seq[sysid].append(seq)
                link_seq.append(seq)
                if first_frame_s is None:
                    first_frame_s = t
                if last_frame_t is not None and t - last_frame_t > args.gap_report_s:
                    gap_events.append({"after_t_s": round(last_frame_t, 3), "gap_s": round(t - last_frame_t, 3)})
                last_frame_t = t
                envs = parser.parse(frame, t)
                if not envs:
                    decode_none += 1
                    continue
                e = envs[0]
                per_msg_count[e.msgname] += 1
                per_msg_id[e.msgname] = e.msgid
                per_msg_t[e.msgname].append(t)
                f = e.fields
                if e.msgname == "HEARTBEAT":
                    if first_hb_s is None:
                        first_hb_s = t
                    if len(heartbeats) < 400:
                        heartbeats.append({"t_s": round(t, 3), "sysid": e.sysid, "compid": e.compid,
                                           "type": f.get("type"), "autopilot": f.get("autopilot"),
                                           "base_mode": f.get("base_mode"), "custom_mode": f.get("custom_mode"),
                                           "system_status": f.get("system_status"),
                                           "mavlink_version": f.get("mavlink_version")})
                elif e.msgname == "STATUSTEXT" and len(statustext) < 100:
                    txt = f.get("text", "")
                    statustext.append({"t_s": round(t, 3), "severity": f.get("severity"),
                                       "text": txt.rstrip("\x00") if isinstance(txt, str) else str(txt)})
                elif e.msgname == "AUTOPILOT_VERSION" and autopilot_version is None:
                    autopilot_version = {k: f.get(k) for k in (
                        "flight_sw_version", "middleware_sw_version", "os_sw_version", "board_version",
                        "vendor_id", "product_id", "capabilities")}
    except KeyboardInterrupt:
        print("interrupted: finalising report", file=sys.stderr)
    finally:
        transport.close()
        if tlog_fh is not None:
            tlog_fh.close()

    span = (last_frame_t - first_frame_s) if (first_frame_s is not None and last_frame_t is not None) else 0.0
    t_stats = transport.stats
    msgs = {}
    for name in sorted(per_msg_count, key=lambda n: per_msg_id[n]):
        ts = per_msg_t[name]
        d = [(b - a) * 1000.0 for a, b in zip(ts, ts[1:], strict=False)]
        msgs[name] = {
            "msgid": per_msg_id[name], "count": per_msg_count[name],
            "rate_hz": round(len(ts) / span, 3) if span > 0 else None,
            "interarrival_ms_median": round(statistics.median(d), 2) if d else None,
            "interarrival_ms_p95": round(_pct(d, 0.95), 2) if d else None,
            "interarrival_ms_max": round(max(d), 2) if d else None,
        }
    seq_report: dict[str, dict] = {"per_sysid_compid": {}, "per_sysid": {}}
    for (s, c), v in sorted(src_seq.items()):
        exp, lost, reg = _seq_loss(v)
        seq_report["per_sysid_compid"][f"{s}/{c}"] = {"frames": len(v), "inferred_lost": lost,
                                                      "non_forward_steps": reg,
                                                      "loss_ratio": round(lost / exp, 5) if exp else None}
    for s, v in sorted(sys_seq.items()):
        exp, lost, reg = _seq_loss(v)
        seq_report["per_sysid"][str(s)] = {"frames": len(v), "inferred_lost": lost, "non_forward_steps": reg,
                                           "loss_ratio": round(lost / exp, 5) if exp else None}
    exp, lost, reg = _seq_loss(link_seq)
    seq_report["whole_link"] = {"frames": len(link_seq), "inferred_lost": lost, "non_forward_steps": reg,
                                "loss_ratio": round(lost / exp, 5) if exp else None}

    hb_summary = None
    if heartbeats:
        by_src: dict[str, Counter] = defaultdict(Counter)
        for h in heartbeats:
            by_src[f"{h['sysid']}/{h['compid']}"][json.dumps(
                {k: h[k] for k in ("type", "autopilot", "base_mode", "custom_mode", "system_status",
                                   "mavlink_version")}, sort_keys=True)] += 1
        hb_summary = {}
        for src, cnt in by_src.items():
            decoded = []
            for k, n in cnt.most_common():
                d = json.loads(k)
                d["type_name"] = MAV_TYPE.get(d["type"], f"TYPE_{d['type']}")
                d["autopilot_name"] = MAV_AUTOPILOT.get(d["autopilot"], f"AP_{d['autopilot']}")
                d["system_status_name"] = MAV_STATE.get(d["system_status"], str(d["system_status"]))
                d["armed"] = bool(d["base_mode"] & MAV_MODE_FLAG_SAFETY_ARMED)
                decoded.append({"state": d, "count": n})
            hb_summary[src] = decoded

    coverage = {m: {"seen": m in per_msg_count, "rate_hz": msgs.get(m, {}).get("rate_hz")}
                for m in PIPELINE_MESSAGES}
    report = {
        "schema": "pixhawk_passive_probe/1",
        "environment": "BENCH (physical flight controller on a desk, USB, disarmed, no props, no airframe)",
        "claim_class": "none (stream description only; not detection evidence)",
        "provenance": {
            "git_commit": _git_commit(), "python": platform.python_version(), "pymavlink": pymavlink.__version__,
            "pyserial": serial.__version__, "platform": platform.platform(),
            "command": " ".join(sys.argv), "unix_time_start": wall0_us / 1e6,
        },
        "port": args.port, "baud_arg": args.baud, "duration_requested_s": args.duration,
        "first_frame_s": first_frame_s, "first_heartbeat_s": first_hb_s, "stream_span_s": round(span, 3),
        "frames": frames, "frame_bytes": bytes_in_frames,
        "mean_frame_rate_hz": round(frames / span, 2) if span > 0 else None,
        "mean_byte_rate_Bps": round(bytes_in_frames / span, 1) if span > 0 else None,
        "mavlink_versions": dict(versions), "signed_frames": signed_frames,
        "frames_without_envelope": decode_none,
        "parser_stats": stats.as_dict(),
        "transport_stats": t_stats,
        "passive_check": {"bytes_sent": t_stats["bytes_sent"], "write_errors": t_stats["write_errors"],
                          "passed": t_stats["bytes_sent"] == 0},
        "pipeline_message_coverage": coverage,
        "messages": msgs,
        "sequence_accounting": seq_report,
        "stream_gaps_over_s": {"threshold_s": args.gap_report_s, "events": gap_events[:50],
                               "count": len(gap_events)},
        "heartbeats": hb_summary,
        "statustext": statustext,
        "autopilot_version_message": autopilot_version,
        "tlog": args.tlog,
    }
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: report[k] for k in (
        "frames", "stream_span_s", "mean_frame_rate_hz", "first_frame_s", "first_heartbeat_s",
        "mavlink_versions", "signed_frames", "passive_check", "pipeline_message_coverage")},
        indent=2, default=str))
    print("transport:", {k: t_stats[k] for k in (
        "bytes_received", "frames_received", "crc_rejects", "header_rejects", "unverifiable_rejects",
        "garbage_bytes", "resync_events", "partial_timeouts", "disconnects", "reconnects",
        "open_failures", "reader_faults", "dropped_overflow", "last_error")})
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True,
                    help="serial device, e.g. COM5 (the MAVLink CDC interface, NOT the SLCAN one)")
    ap.add_argument("--baud", type=int, default=115200, help="ignored by USB-CDC; matters for UART/radio links")
    ap.add_argument("--duration", type=float, default=60.0, help="seconds to listen")
    ap.add_argument("--json", help="write the JSON report here")
    ap.add_argument("--tlog", help="write the raw frames as a .tlog here (git-ignored location)")
    ap.add_argument("--reconnect-interval", type=float, default=1.0)
    ap.add_argument("--gap-report-s", type=float, default=2.5,
                    help="report silences longer than this (must exceed the 1 Hz heartbeat period; the "
                         "pipeline's heartbeat_timeout_s is 3.0)")
    ap.add_argument("--keep-trying", action="store_true",
                    help="do not fail fast if the port cannot be opened (use for a replug test)")
    return run(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
