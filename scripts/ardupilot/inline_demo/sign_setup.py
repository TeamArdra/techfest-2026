"""Provision MAVLink-2 signing into the SITL over the direct SERIAL0 link (5760), then hold the link."""
import sys
import time

from pymavlink import mavutil

key = open(sys.argv[1], "rb").read()
m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255, source_component=190)
m.wait_heartbeat(timeout=30)
ts = int((time.time() - 1420070400) * 100000)
m.mav.setup_signing_send(m.target_system, m.target_component, list(key), ts)
print("setup_signing sent ts", ts, flush=True)
end = time.time() + float(sys.argv[2]) if len(sys.argv) > 2 else time.time() + 5
while time.time() < end:
    m.recv_match(blocking=True, timeout=0.5)
