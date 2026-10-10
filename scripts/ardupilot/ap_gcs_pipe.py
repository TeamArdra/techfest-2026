#!/usr/bin/env python3
"""GCS-role collector for an ISOLATED ArduCopter SITL: configures telemetry, flies a benign
scripted flight, and pipes every received frame to stdout as length-prefixed records.

Runs INSIDE the network namespace built by ``ap_netns_run.sh`` (python3 + pymavlink only, no
repo imports). Environment tag: SITL. The vehicle is a simulator; every command below is sent to
that simulator and NEVER to a physical flight controller. Nothing here listens on a port: the
only channel out of the namespace is stdout (see ``aegisflight.sources.frame_pipe``).

stdout  : ``>H length`` + one raw MAVLink frame, per frame received from the vehicle (downlink
          only; the GCS's own uplink is not mirrored there -- it is logged in ``--events``).
--events: JSONL of every uplink action (heartbeat excluded) and flight-phase change, with unix time.
--tlog  : the same downlink frames as a MAVLink .tlog (8-byte BE unix-us + frame) written on THIS
          side, so the Windows-side copy can be checked for pipe loss.

Telemetry configuration (``--stream``), chosen deliberately because ArduPilot streams nothing but
HEARTBEAT/TIMESYNC until a GCS asks (measured passively on SITL and on a Pixhawk 6X):
  six    MAV_CMD_SET_MESSAGE_INTERVAL for exactly the six messages the Stage-1 extractor reads, at
         the Stage-1 simulator rates (SYS_STATUS 2, GPS_RAW_INT 5, GLOBAL_POSITION_INT 5, ATTITUDE
         10, VFR_HUD 5 Hz; HEARTBEAT 1 Hz is unsolicited).
  groups REQUEST_DATA_STREAM at stream-group level (EXTENDED_STATUS 2, POSITION 5, EXTRA1 10,
         EXTRA2 5 Hz). This is what the persistent SRx_* parameters of a real FC would give, so it
         is the deployment-relevant configuration; it also carries the other members of each
         group (see the capture's message table).
Profiles (``--profile``): ``idle`` (stay disarmed on the ground) or ``flight`` (GUIDED, arm,
takeoff, square, RTL, land, disarm).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
import threading
import time

os.environ["MAVLINK20"] = "1"

from pymavlink import mavutil  # noqa: E402

mavlink = mavutil.mavlink

SIX_RATES_HZ = {  # msgid: Hz  (Stage-1 simulation.yaml message_rates)
    1: 2,    # SYS_STATUS
    24: 5,   # GPS_RAW_INT
    33: 5,   # GLOBAL_POSITION_INT
    30: 10,  # ATTITUDE
    74: 5,   # VFR_HUD
}
GROUP_RATES_HZ = {  # REQUEST_DATA_STREAM ids: MAV_DATA_STREAM_*
    mavlink.MAV_DATA_STREAM_EXTENDED_STATUS: 2,
    mavlink.MAV_DATA_STREAM_POSITION: 5,
    mavlink.MAV_DATA_STREAM_EXTRA1: 10,
    mavlink.MAV_DATA_STREAM_EXTRA2: 5,
}
MODE_GUIDED, MODE_RTL, MODE_LAND = 4, 6, 9
POS_ONLY_MASK = 0b0000111111111000  # use x/y/z position only


class Collector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.conn = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255,
                                               source_component=190)
        self.lock = threading.Lock()  # pymavlink senders are not thread-safe
        self.stop = threading.Event()
        self.out = sys.stdout.buffer
        self.tlog = open(args.tlog, "wb") if args.tlog else None  # noqa: SIM115 - closed in run()
        self.events = open(args.events, "w", encoding="utf-8") if args.events else None  # noqa: SIM115
        self.frames = 0
        self.bad_data = 0
        self.state: dict = {"armed": False, "alt_rel_m": 0.0, "lat": None, "lon": None, "fix": 0,
                            "mode": None, "acks": {}, "last_hb": 0.0, "statustext": []}
        self.pipe_broken = False

    # -- logging -------------------------------------------------------------------- #

    def event(self, ev: str, **kw: object) -> None:
        rec = {"t_unix": round(time.time(), 6), "event": ev, **kw}
        print("EVENT", json.dumps(rec), file=sys.stderr, flush=True)
        if self.events:
            self.events.write(json.dumps(rec) + "\n")
            self.events.flush()

    # -- reader thread: downlink -> stdout + tlog + state ---------------------------- #

    def reader(self) -> None:
        while not self.stop.is_set():
            try:
                msg = self.conn.recv_match(blocking=True, timeout=0.2)
            except Exception as exc:  # noqa: BLE001 - connection died
                self.event("reader_error", error=repr(exc))
                self.stop.set()
                return
            if msg is None:
                continue
            kind = msg.get_type()
            if kind == "BAD_DATA":
                self.bad_data += 1
                continue
            frame = bytes(msg.get_msgbuf())
            ts_us = int(time.time() * 1e6)
            try:
                self.out.write(struct.pack(">H", len(frame)) + frame)
                self.out.flush()
            except (BrokenPipeError, OSError):
                self.pipe_broken = True
                self.event("stdout_closed")
                self.stop.set()
                return
            if self.tlog:
                self.tlog.write(struct.pack(">Q", ts_us) + frame)
            self.frames += 1
            self._track(kind, msg)

    def _track(self, kind: str, msg: object) -> None:
        s = self.state
        if kind == "HEARTBEAT" and msg.get_srcSystem() == 1 and msg.get_srcComponent() == 1:
            s["armed"] = bool(msg.base_mode & mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
            s["mode"] = msg.custom_mode
            s["last_hb"] = time.monotonic()
        elif kind == "GLOBAL_POSITION_INT":
            s["alt_rel_m"] = msg.relative_alt / 1000.0
            s["lat"], s["lon"] = msg.lat / 1e7, msg.lon / 1e7
        elif kind == "GPS_RAW_INT":
            s["fix"] = msg.fix_type
        elif kind == "COMMAND_ACK":
            s["acks"][msg.command] = (msg.result, time.monotonic())
        elif kind == "STATUSTEXT":
            txt = msg.text if isinstance(msg.text, str) else msg.text.decode("ascii", "replace")
            s["statustext"].append(txt.rstrip("\x00"))
            del s["statustext"][:-40]

    # -- uplink helpers (SITL only) -------------------------------------------------- #

    def heartbeat_loop(self) -> None:
        while not self.stop.wait(1.0):
            with self.lock:
                self.conn.mav.heartbeat_send(mavlink.MAV_TYPE_GCS, mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)

    def cmd(self, command: int, *params: float) -> None:
        p = list(params) + [0.0] * (7 - len(params))
        self.event("command", command=command, params=params)
        with self.lock:
            self.conn.mav.command_long_send(1, 1, command, 0, *p)

    def wait_for(self, pred, timeout_s: float, what: str) -> bool:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end and not self.stop.is_set():
            if pred():
                return True
            time.sleep(0.2)
        self.event("timeout", what=what, timeout_s=timeout_s)
        return False

    def set_mode(self, mode: int) -> None:
        self.cmd(mavlink.MAV_CMD_DO_SET_MODE, mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode)

    # -- scenario ------------------------------------------------------------------- #

    def configure_streams(self) -> None:
        if self.args.stream == "six":
            for msgid, hz in SIX_RATES_HZ.items():
                self.cmd(mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, msgid, int(1e6 / hz))
                time.sleep(0.05)
        else:
            for sid, hz in GROUP_RATES_HZ.items():
                self.event("request_data_stream", stream=sid, hz=hz)
                with self.lock:
                    self.conn.mav.request_data_stream_send(1, 1, sid, hz, 1)
                time.sleep(0.05)

    def square(self, side_m: float, alt_m: float) -> None:
        lat0, lon0 = self.state["lat"], self.state["lon"]
        dlat = side_m / 111_320.0
        dlon = side_m / (111_320.0 * math.cos(math.radians(lat0)))
        corners = [(lat0 + dlat, lon0), (lat0 + dlat, lon0 + dlon), (lat0, lon0 + dlon), (lat0, lon0)]
        for i, (la, lo) in enumerate(corners):
            self.event("waypoint", index=i, lat=la, lon=lo, alt_m=alt_m)
            with self.lock:
                self.conn.mav.set_position_target_global_int_send(
                    0, 1, 1, mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, POS_ONLY_MASK,
                    int(la * 1e7), int(lo * 1e7), alt_m, 0, 0, 0, 0, 0, 0, 0, 0)
            self.wait_for(lambda la=la, lo=lo: self._dist_m(la, lo) < 4.0, 40.0, f"waypoint {i}")

    def _dist_m(self, la: float, lo: float) -> float:
        s = self.state
        if s["lat"] is None:
            return 1e9
        dy = (s["lat"] - la) * 111_320.0
        dx = (s["lon"] - lo) * 111_320.0 * math.cos(math.radians(la))
        return math.hypot(dx, dy)

    def flight(self) -> None:
        s = self.state
        self.event("phase", name="await_gps")
        self.wait_for(lambda: s["fix"] >= 3 and s["lat"] is not None, 120.0, "GPS 3D fix")
        self.set_mode(MODE_GUIDED)
        time.sleep(1.0)
        self.event("phase", name="arm")
        armed = False
        for attempt in range(1, 41):  # EKF/pre-arm checks need time after boot
            self.cmd(mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 1)
            if self.wait_for(lambda: s["armed"], 4.0, f"arm attempt {attempt}"):
                armed = True
                break
        if not armed:
            self.event("abort", reason="could not arm", statustext=s["statustext"][-10:])
            return
        self.event("phase", name="takeoff")
        self.cmd(mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, self.args.alt_m)
        self.wait_for(lambda: s["alt_rel_m"] >= self.args.alt_m * 0.9, 60.0, "takeoff altitude")
        self.event("phase", name="square")
        self.square(self.args.side_m, self.args.alt_m)
        self.event("phase", name="rtl")
        self.set_mode(MODE_RTL)
        self.wait_for(lambda: not s["armed"], 150.0, "landed+disarmed")
        self.event("phase", name="landed", armed=s["armed"], alt_rel_m=s["alt_rel_m"])

    def run(self) -> int:
        t_start = time.monotonic()
        self.event("start", argv=sys.argv[1:], stream=self.args.stream, profile=self.args.profile)
        self.conn.wait_heartbeat(timeout=30)
        self.event("heartbeat_seen", sysid=self.conn.target_system, compid=self.conn.target_component)
        threads = [threading.Thread(target=self.reader, daemon=True),
                   threading.Thread(target=self.heartbeat_loop, daemon=True)]
        for t in threads:
            t.start()
        try:
            self.configure_streams()
            if self.args.profile == "flight":
                self.flight()
            else:
                self.wait_for(lambda: False, self.args.idle_s, "idle window")
            time.sleep(self.args.tail_s)
            return 0
        finally:
            self.event("end", frames=self.frames, bad_data=self.bad_data, pipe_broken=self.pipe_broken,
                       seconds=round(time.monotonic() - t_start, 1))
            self.stop.set()
            for t in threads:
                t.join(timeout=2.0)
            if self.tlog:
                self.tlog.close()
            if self.events:
                self.events.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stream", choices=("six", "groups"), default="six")
    ap.add_argument("--profile", choices=("idle", "flight"), default="flight")
    ap.add_argument("--idle-s", type=float, default=60.0)
    ap.add_argument("--alt-m", type=float, default=15.0)
    ap.add_argument("--side-m", type=float, default=50.0)
    ap.add_argument("--tail-s", type=float, default=5.0)
    ap.add_argument("--events", help="JSONL of uplink actions and phases")
    ap.add_argument("--tlog", help="tlog of the downlink frames, written inside the namespace")
    return Collector(ap.parse_args()).run()


if __name__ == "__main__":
    sys.exit(main())
