"""Observer on the GCS side (hub port 5802, read-only downlink copy): logs every AEGIS STATUSTEXT with its time.

usage: watch_alarm.py   (runs until killed)
"""
import os
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

o = mavutil.mavlink_connection("tcp:127.0.0.1:5802", source_system=253, source_component=1)
while True:
    msg = o.recv_match(type="STATUSTEXT", blocking=True, timeout=1)
    if msg is not None and "AEGIS" in msg.text:
        print(f"STATUSTEXT t={round(time.time())} sev={msg.severity} {msg.text}", flush=True)
