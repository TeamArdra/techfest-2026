"""Redacted GNSS summary of a recorded tlog: fix, quality, freshness and consistency (offline).

    .venv/Scripts/python.exe scripts/hardware/gnss_tlog_summary.py data/hardware/raw/telemetry_radio_009.tlog \
        --json artifacts/hardware/gnss_summary_009.json

Reads a repo-framed ``.tlog`` (8-byte big-endian host microseconds + one MAVLink frame) with pymavlink;
no port, no transmit. Reports GPS_RAW_INT fix type / satellites / DOP / accuracy / velocity /
``time_usec`` steps, GLOBAL_POSITION_INT spread / velocity / ``time_boot_ms`` order, the horizontal
disagreement between the two position messages, the speed implied by successive GLOBAL_POSITION_INT
positions, the SYS_STATUS GPS sensor bits and EKF_STATUS_REPORT flags. Positions are reported only as
distances in metres from the first fix: **no absolute latitude/longitude is written**, so the output
can be committed (the tlog itself is git-ignored because it holds the bench location).

Claim class: none (a description of the receiver's reports). Environment: whatever the capture was.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics as st
import sys
from collections import Counter
from pathlib import Path

from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as apm
from pymavlink.dialects.v20 import common as mav2

EARTH_RADIUS_M = 6371008.8
_TYPES = ("GPS_RAW_INT", "GLOBAL_POSITION_INT", "EKF_STATUS_REPORT", "SYS_STATUS", "VFR_HUD")


def _ne(lat0: float, lon0: float, lat: float, lon: float) -> tuple[float, float]:
    return (math.radians(lat - lat0) * EARTH_RADIUS_M,
            math.radians(lon - lon0) * EARTH_RADIUS_M * math.cos(math.radians(lat0)))


def _stats(xs: list[float | None]) -> dict[str, float] | None:
    v = [x for x in xs if x is not None]
    if not v:
        return None
    return {"n": len(v), "min": round(min(v), 3), "median": round(st.median(v), 3), "max": round(max(v), 3)}


def summarise(tlog: Path) -> dict:
    conn = mavutil.mavlink_connection(str(tlog), dialect="ardupilotmega")
    got: dict[str, list] = {k: [] for k in _TYPES}
    while (msg := conn.recv_match(blocking=False)) is not None:
        if msg.get_type() in got:
            got[msg.get_type()].append((msg._timestamp, msg))
    raw, gpi = got["GPS_RAW_INT"], got["GLOBAL_POSITION_INT"]
    fix_names = {k: v.name for k, v in mav2.enums["GPS_FIX_TYPE"].items()}
    first = next(((r.lat / 1e7, r.lon / 1e7) for _, r in raw if r.lat or r.lon), None)

    def off(lat_e7: int, lon_e7: int) -> float | None:
        if first is None or not (lat_e7 or lon_e7):
            return None
        return math.hypot(*_ne(first[0], first[1], lat_e7 / 1e7, lon_e7 / 1e7))

    tus = [r.time_usec for _, r in raw]
    tus_steps = [(b - a) / 1e6 for a, b in zip(tus, tus[1:], strict=False)]
    out: dict = {
        "schema": "aegisflight.gnss_tlog_summary/1",
        "tlog": tlog.as_posix(),
        "claim_class": "none (receiver reports, no detection claim)",
        "redaction": "positions only as metres from the first GPS_RAW_INT fix; no absolute coordinates",
        "GPS_RAW_INT": {
            "n": len(raw),
            "fix_type": {f"{k} {fix_names.get(k, '?')}": v
                         for k, v in sorted(Counter(r.fix_type for _, r in raw).items())},
            "fix_ge_3_and_sats_ge_5": sum(1 for _, r in raw if r.fix_type >= 3 and r.satellites_visible >= 5),
            "satellites_visible": _stats([r.satellites_visible for _, r in raw]),
            "eph_hdop": _stats([r.eph / 100 if r.eph != 65535 else None for _, r in raw]),
            "epv_vdop": _stats([r.epv / 100 if r.epv != 65535 else None for _, r in raw]),
            "h_acc_m": _stats([r.h_acc / 1000 if getattr(r, "h_acc", 0) else None for _, r in raw]),
            "vel_ms": _stats([r.vel / 100 if r.vel != 65535 else None for _, r in raw]),
            "lat_lon_zero": sum(1 for _, r in raw if r.lat == 0 and r.lon == 0),
            "time_usec_zero": sum(1 for v in tus if v == 0),
            "time_usec_step_s": _stats(tus_steps),
            "time_usec_backsteps": sum(1 for d in tus_steps if d < 0),
            "host_interval_s": _stats([b[0] - a[0] for a, b in zip(raw, raw[1:], strict=False)]),
            "offset_from_first_fix_m": _stats([off(r.lat, r.lon) for _, r in raw]),
            "alt_msl_range_m": (lambda a: round(max(a) - min(a), 3) if a else None)([r.alt / 1000 for _, r in raw]),
        },
    }
    tb = [g.time_boot_ms for _, g in gpi]
    out["GLOBAL_POSITION_INT"] = {
        "n": len(gpi),
        "lat_lon_zero": sum(1 for _, g in gpi if g.lat == 0 and g.lon == 0),
        "offset_from_first_fix_m": _stats([off(g.lat, g.lon) for _, g in gpi]),
        "speed_ms": _stats([math.hypot(g.vx, g.vy) / 100 for _, g in gpi]),
        "vz_ms": _stats([g.vz / 100 for _, g in gpi]),
        "time_boot_ms_backsteps": sum(1 for a, b in zip(tb, tb[1:], strict=False) if b < a),
    }
    dis = []
    for t, g in gpi:
        if raw and (g.lat or g.lon):
            tr, r = min(raw, key=lambda x: abs(x[0] - t))
            if abs(tr - t) < 0.3 and (r.lat or r.lon):
                dis.append(math.hypot(*_ne(r.lat / 1e7, r.lon / 1e7, g.lat / 1e7, g.lon / 1e7)))
    out["gps_raw_vs_global_position_m"] = _stats(dis)
    implied = []
    for (_, a), (_, b) in zip(gpi, gpi[1:], strict=False):
        dt = (b.time_boot_ms - a.time_boot_ms) / 1000
        if dt > 0 and (a.lat or a.lon):
            implied.append(math.hypot(*_ne(a.lat / 1e7, a.lon / 1e7, b.lat / 1e7, b.lon / 1e7)) / dt)
    out["global_position_implied_speed_ms"] = _stats(implied)
    if got["SYS_STATUS"]:
        bit, s = mav2.MAV_SYS_STATUS_SENSOR_GPS, got["SYS_STATUS"]
        out["SYS_STATUS_gps_sensor"] = {
            "n": len(s),
            "present": sum(1 for _, x in s if x.onboard_control_sensors_present & bit),
            "enabled": sum(1 for _, x in s if x.onboard_control_sensors_enabled & bit),
            "healthy": sum(1 for _, x in s if x.onboard_control_sensors_health & bit),
        }
    if got["EKF_STATUS_REPORT"]:
        e = got["EKF_STATUS_REPORT"]
        out["EKF_STATUS_REPORT"] = {
            "n": len(e),
            "flags": {hex(k): v for k, v in sorted(Counter(x.flags for _, x in e).items())},
            "pos_horiz_abs": sum(1 for _, x in e if x.flags & apm.EKF_POS_HORIZ_ABS),
            "pos_horiz_rel": sum(1 for _, x in e if x.flags & apm.EKF_POS_HORIZ_REL),
            "const_pos_mode": sum(1 for _, x in e if x.flags & apm.EKF_CONST_POS_MODE),
            "gps_glitching": sum(1 for _, x in e if x.flags & apm.EKF_GPS_GLITCHING),
        }
    if got["VFR_HUD"]:
        out["VFR_HUD_groundspeed_ms"] = _stats([v.groundspeed for _, v in got["VFR_HUD"]])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tlog", type=Path)
    ap.add_argument("--json", type=Path, help="write the summary here (refuses to overwrite)")
    a = ap.parse_args(argv)
    if a.json is not None and a.json.exists():
        print(f"refusing to overwrite {a.json}", file=sys.stderr)
        return 2
    text = json.dumps(summarise(a.tlog), indent=1)
    if a.json is not None:
        a.json.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
