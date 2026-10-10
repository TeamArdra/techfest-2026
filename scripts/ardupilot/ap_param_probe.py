#!/usr/bin/env python3
"""DIAGNOSTIC flight-driver substitute (SITL only): read back stream parameters over SERIAL0.

Used with ``AP_DRIVER=ap_param_probe.py`` in ``ap_netns_run_passive.sh`` to answer one question: were the
``SERIAL1_*`` / ``SR1_*`` defaults in ``sitl_defaults_monitor_port.parm`` actually applied by the simulator?
Reads parameters with PARAM_REQUEST_READ (a read of the SIMULATOR; never a physical flight controller) and
writes them to the events file. Accepts and ignores the flight-driver arguments so it can stand in for it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"

from pymavlink import mavutil  # noqa: E402

NAMES = ["SERIAL0_PROTOCOL", "SERIAL1_PROTOCOL", "SERIAL1_BAUD", "SR1_EXT_STAT", "MAV_TELEM_DELAY", "MAV_OPTIONS",
         "MAV1_RAW_SENS", "MAV1_EXT_STAT", "MAV1_POSITION", "MAV1_EXTRA1", "MAV1_EXTRA2", "MAV1_EXTRA3",
         "MAV2_RAW_SENS", "MAV2_EXT_STAT", "MAV2_POSITION", "MAV2_EXTRA1", "MAV2_EXTRA2", "MAV2_EXTRA3"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True)
    ap.add_argument("--tlog")
    ap.add_argument("--stream")
    ap.add_argument("--profile")
    ap.add_argument("--idle-s")
    a, _ = ap.parse_known_args()
    conn = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255, source_component=190)
    conn.wait_heartbeat(timeout=30)
    got: dict[str, float | None] = dict.fromkeys(NAMES)
    for n in NAMES:
        conn.mav.param_request_read_send(1, 1, n.encode(), -1)
        end = time.monotonic() + 3.0
        while time.monotonic() < end:
            m = conn.recv_match(type="PARAM_VALUE", blocking=True, timeout=0.5)
            if m is not None and m.param_id.rstrip("\x00") == n:
                got[n] = m.param_value
                break
    with open(a.events, "w", encoding="utf-8") as f:
        f.write(json.dumps({"t_unix": time.time(), "event": "params", "values": got}) + "\n")
    print(json.dumps(got), file=sys.stderr)
    time.sleep(20)  # keep the simulator alive so the monitor can be observed for a while
    return 0


if __name__ == "__main__":
    sys.exit(main())
