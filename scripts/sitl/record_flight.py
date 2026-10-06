"""Record a BENIGN PX4 SITL flight from Windows as a raw MAVLink .tlog.

Acts as a normal ground station on the PX4 GCS UDP link (heartbeats + commands),
writes every received frame to ``<out>.tlog`` (pymavlink/Mission-Planner format:
big-endian uint64 microsecond receive-time + the raw frame) and a small JSON
manifest. NO attack is injected: ``attack_status = NONE``.

    .venv/Scripts/python.exe scripts/sitl/record_flight.py --out data/sitl/raw/benign_001

Environment tag: SITL. The tlog is the raw experimental evidence; it is
gitignored (data/sitl/raw/) and only the manifest is committed.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from provenance import collect, sha256_file
from pymavlink import mavutil

DISTRO = "Ubuntu-24.04"


def wsl_ip(distro: str = DISTRO) -> str:
    """Current WSL NAT IP (changes across reboots -- never hard-coded)."""
    out = subprocess.run(["wsl", "-d", distro, "--", "hostname", "-I"], capture_output=True, text=True, timeout=30)
    return out.stdout.split()[0]


def px4_describe(distro: str = DISTRO, px4_dir: str = "/home/astryx/PX4-Autopilot") -> str:
    out = subprocess.run(["wsl", "-d", distro, "--cd", px4_dir, "--", "git", "describe", "--tags", "--always"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip()


def gz_version(distro: str = DISTRO) -> str:
    out = subprocess.run(["wsl", "-d", distro, "--", "gz", "sim", "--versions"], capture_output=True, text=True, timeout=30)
    return out.stdout.strip().splitlines()[0] if out.stdout.strip() else "unknown"


class Gcs:
    """Minimal benign GCS: heartbeats, tlog recording, a few PX4 commands."""

    def __init__(self, host: str, port: int, tlog_path: Path, sysid: int = 255, compid: int = 190) -> None:
        self.m = mavutil.mavlink_connection(f"udpout:{host}:{port}", source_system=sysid, source_component=compid,
                                            dialect="common")
        self.tlog = open(tlog_path, "wb")  # noqa: SIM115 - closed in close()
        self.last_hb = 0.0
        self.target = (1, 1)
        self.pos: dict | None = None
        self.hb = None
        self.nframes = 0
        self._ack: dict[int, int] = {}

    def pump(self, timeout: float = 0.05) -> None:
        now = time.time()
        if now - self.last_hb >= 1.0:
            self.m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            self.last_hb = now
        while True:
            msg = self.m.recv_match(blocking=True, timeout=timeout)
            if msg is None:
                return
            timeout = 0  # drain without blocking after the first
            ts = float(getattr(msg, "_timestamp", time.time()))
            buf = msg.get_msgbuf()
            if buf:
                self.tlog.write(struct.pack(">Q", int(ts * 1e6)) + bytes(buf))
                self.nframes += 1
            t = msg.get_type()
            if t == "HEARTBEAT" and msg.get_srcComponent() == 1 and msg.type != mavutil.mavlink.MAV_TYPE_GCS:
                self.hb = msg
                self.target = (msg.get_srcSystem(), msg.get_srcComponent())
            elif t == "COMMAND_ACK":
                self._ack[msg.command] = msg.result
            elif t == "GLOBAL_POSITION_INT":
                self.pos = {"lat": msg.lat / 1e7, "lon": msg.lon / 1e7, "alt": msg.alt / 1e3, "rel": msg.relative_alt / 1e3}

    def wait(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.pump()

    def cmd(self, command: int, *p: float) -> int | None:
        p = tuple(p) + (0.0,) * (7 - len(p))
        self.m.mav.command_long_send(self.target[0], self.target[1], command, 0, *p)
        end = time.time() + 3.0
        while time.time() < end:
            self.pump(0.1)
            if command in self._ack:
                return self._ack.pop(command)
        return None

    def armed(self) -> bool:
        return bool(self.hb and self.hb.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)

    def goto(self, lat: float, lon: float, alt_amsl: float, tol_m: float = 3.0, timeout: float = 45.0) -> bool:
        self.cmd(mavutil.mavlink.MAV_CMD_DO_REPOSITION, -1, 1, 0, math.nan, lat, lon, alt_amsl)
        end = time.time() + timeout
        while time.time() < end:
            self.pump()
            if self.pos:
                dn = (self.pos["lat"] - lat) * 111_320.0
                de = (self.pos["lon"] - lon) * 111_320.0 * math.cos(math.radians(lat))
                if math.hypot(dn, de) < tol_m and abs(self.pos["alt"] - alt_amsl) < tol_m:
                    return True
        return False

    def close(self) -> None:
        self.tlog.close()


def fly(g: Gcs, alt_m: float, side_m: float) -> dict:
    ev: dict = {}
    t0 = time.time()
    while (g.hb is None or g.pos is None) and time.time() - t0 < 30:
        g.pump()
    if g.hb is None or g.pos is None:
        raise RuntimeError("no heartbeat/position from PX4 within 30 s")
    home = dict(g.pos)
    ev["home"] = home
    ev["t_start"] = datetime.now(UTC).isoformat()
    g.wait(5)
    res = None
    for _ in range(40):  # PX4 refuses until EKF / GCS-link preflight checks pass
        res = g.cmd(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 1)
        if res == mavutil.mavlink.MAV_RESULT_ACCEPTED:
            break
        g.wait(2)
    ev["arm_result"] = res
    if res != mavutil.mavlink.MAV_RESULT_ACCEPTED:
        raise RuntimeError(f"arming rejected: {res}")
    ev["t_armed"] = datetime.now(UTC).isoformat()
    tgt = home["alt"] + alt_m
    ev["takeoff_result"] = g.cmd(mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, math.nan, 0, 0, math.nan, math.nan, math.nan, tgt)
    end = time.time() + 40
    while time.time() < end and (g.pos is None or g.pos["alt"] < tgt - 2):
        g.pump()
    ev["t_at_altitude"] = datetime.now(UTC).isoformat()
    dlat = side_m / 111_320.0
    dlon = side_m / (111_320.0 * math.cos(math.radians(home["lat"])))
    legs = [(dlat, 0), (dlat, dlon), (0, dlon), (0, 0)]
    ev["legs_reached"] = []
    for a, b in legs:
        ev["legs_reached"].append(g.goto(home["lat"] + a, home["lon"] + b, tgt))
        g.wait(2)
    ev["land_result"] = g.cmd(mavutil.mavlink.MAV_CMD_NAV_LAND, 0, 0, 0, math.nan, math.nan, math.nan, home["alt"])
    end = time.time() + 60
    while time.time() < end and g.armed():
        g.pump()
    ev["t_landed"] = datetime.now(UTC).isoformat()
    ev["disarmed_after_land"] = not g.armed()
    g.wait(3)
    return ev


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="output stem (writes <stem>.tlog and <stem>.json)")
    ap.add_argument("--host", default=None, help="WSL IP (default: discovered)")
    ap.add_argument("--port", type=int, default=18572)
    ap.add_argument("--sysid", type=int, default=255, help="GCS sysid (use a distinct id when another GCS/IDS shares PX4)")
    ap.add_argument("--compid", type=int, default=190)
    ap.add_argument("--alt", type=float, default=20.0)
    ap.add_argument("--side", type=float, default=40.0)
    ap.add_argument("--hover-only", type=float, default=0.0, help="record N seconds without flying")
    ap.add_argument("--purpose", default="benign PX4 SITL reference capture")
    a = ap.parse_args(argv)

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    host = a.host or wsl_ip()
    g = Gcs(host, a.port, out.with_suffix(".tlog"), a.sysid, a.compid)
    t_wall = time.time()
    started = datetime.now(UTC).isoformat()
    try:
        if a.hover_only > 0:
            g.wait(a.hover_only)
            events: dict = {"mode": "observe-only"}
        else:
            events = fly(g, a.alt, a.side)
    finally:
        g.close()
    duration = time.time() - t_wall
    manifest = {
        "schema": "aegisflight.sitl_capture/1",
        "purpose": a.purpose,
        "environment": "SITL",
        "attack_status": "NONE",
        "claim_class": "none (benign reference / calibration capture)",
        "started_utc": started,
        "duration_s": round(duration, 2),
        "frames": g.nframes,
        "tlog": out.with_suffix(".tlog").name,
        "link": {"transport": "udp", "host": host, "port": a.port, "role": f"GCS sysid={a.sysid} compid={a.compid}"},
        "vehicle": {"sysid": g.target[0], "compid": g.target[1]},
        "px4_git_describe": px4_describe(),
        "gazebo": gz_version(),
        "sim_model": "gz_x500 (headless)",
        "client": {"python": sys.version.split()[0]},
        "flight_events": events,
        "gazebo_note": "installed version (gz sim --versions), not queried from the running server",
        "provenance": collect(tlog_sha256=sha256_file(out.with_suffix(".tlog"))),
    }
    out.with_suffix(".json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ("duration_s", "frames", "vehicle", "px4_git_describe")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
