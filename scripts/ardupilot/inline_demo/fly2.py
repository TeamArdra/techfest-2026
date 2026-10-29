"""Fly the SITL copter on a rectangle and log its own position (truth) once a second."""
import json
import sys
import time

from pymavlink import mavutil

m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
m.wait_heartbeat(timeout=30)
print("heartbeat from", m.target_system, m.target_component, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
for name, val in (("SR1_POSITION", 5), ("SR1_EXTRA1", 5), ("SR1_EXTRA2", 5), ("SR1_RAW_SENS", 2),
                  ("SR1_EXT_STAT", 2), ("SR1_EXTRA3", 2), ("ARMING_CHECK", 0)):
    m.param_set_send(name, val)
    time.sleep(0.2)
truth = open(f"C:/afsitl/truth_{sys.argv[1]}.jsonl", "w")
state = {"alt": 0.0, "armed": False, "mode": None, "fix": 0}


def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        msg = m.recv_match(blocking=True, timeout=0.5)
        if msg is None:
            continue
        t = msg.get_type()
        if t == "GLOBAL_POSITION_INT":
            state["alt"] = msg.relative_alt / 1000.0
            truth.write(json.dumps({"t": time.time(), "lat": msg.lat / 1e7, "lon": msg.lon / 1e7,
                                    "rel_alt": state["alt"]}) + "\n")
            truth.flush()
        elif t == "HEARTBEAT":
            state["armed"] = bool(msg.base_mode & 0x80)
            state["mode"] = msg.custom_mode
        elif t == "GPS_RAW_INT":
            state["fix"] = msg.fix_type


def ack(label):
    a = m.recv_match(type="COMMAND_ACK", blocking=True, timeout=3)
    print(label, "ack:", getattr(a, "result", None), flush=True)


print("waiting for GPS/EKF ...", flush=True)
pump(45)
print("state", state, flush=True)
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)  # GUIDED
pump(2)
m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
ack("arm")
pump(3)
print("state", state, flush=True)
m.mav.command_long_send(m.target_system, m.target_component, 22, 0, 0, 0, 0, 0, 0, 0, 30)
ack("takeoff")
pump(25)
print("state", state, flush=True)
lat0, lon0 = 12.9716, 77.5946
legs = [(0.0010, 0.0000), (0.0010, 0.0014), (0.0000, 0.0014), (0.0000, 0.0000)]   # about 110 m x 150 m
for dlat, dlon in legs:
    m.mav.set_position_target_global_int_send(
        0, m.target_system, m.target_component, 6, 0b0000111111111000,
        int((lat0 + dlat) * 1e7), int((lon0 + dlon) * 1e7), 30, 0, 0, 0, 0, 0, 0, 0, 0)
    for _ in range(11):
        pump(2)
        print("t", round(time.time()), "mode", state["mode"], "alt", round(state["alt"],1), flush=True)
    print("leg done", state, flush=True)
print("done", flush=True)
sys.exit(0)
