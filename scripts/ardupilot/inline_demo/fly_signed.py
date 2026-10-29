"""Pilot for the signing scenario: arm, take off, fly, make a legitimate mode change, keep flying.

usage: fly_signed.py <label> <keyfile|->
With key '-' the pilot is unsigned. Prints marker lines the runner script waits for.
"""
import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

label, keyfile = sys.argv[1], sys.argv[2]
m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
if keyfile != "-":
    m.setup_signing(open(keyfile, "rb").read(), sign_outgoing=True, allow_unsigned_callback=lambda *a: True,
                    link_id=1)
m.wait_heartbeat(timeout=30)
print("heartbeat from", m.target_system, m.target_component, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
for name, val in (("SR1_POSITION", 5), ("SR1_EXTRA1", 5), ("SR1_EXTRA2", 5), ("SR1_RAW_SENS", 2),
                  ("SR1_EXT_STAT", 2), ("SR1_EXTRA3", 2), ("ARMING_CHECK", 0)):
    m.param_set_send(name, val)
    time.sleep(0.2)
truth = open(f"C:/afsitl/truth_{label}.jsonl", "w")
state = {"alt": 0.0, "armed": False, "mode": None, "fix": 0}
log = {"hb": 0, "msgs": 0}


def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        msg = m.recv_match(blocking=True, timeout=0.5)
        if msg is None:
            continue
        t = msg.get_type()
        log["msgs"] += 1
        if t == "GLOBAL_POSITION_INT":
            state["alt"] = msg.relative_alt / 1000.0
            truth.write(json.dumps({"t": time.time(), "rel_alt": state["alt"]}) + "\n")
            truth.flush()
        elif t == "HEARTBEAT":
            log["hb"] += 1
            state["armed"] = bool(msg.base_mode & 0x80)
            state["mode"] = msg.custom_mode
        elif t == "GPS_RAW_INT":
            state["fix"] = msg.fix_type


def ack(tag):
    a = m.recv_match(type="COMMAND_ACK", blocking=True, timeout=3)
    print(tag, "ack:", getattr(a, "result", None), flush=True)


def set_mode(mode, name):
    m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode)
    pump(3)
    print("modechange", name, "->", state["mode"], "ok" if state["mode"] == mode else "FAILED", flush=True)


print("waiting for GPS/EKF ...", flush=True)
pump(45)
print("state", state, log, flush=True)
set_mode(4, "GUIDED")
m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
ack("arm")
pump(3)
print("state", state, flush=True)
m.mav.command_long_send(m.target_system, m.target_component, 22, 0, 0, 0, 0, 0, 0, 0, 30)
ack("takeoff")
pump(25)
print("state", state, flush=True)
lat0, lon0 = 12.9716, 77.5946
legs = [(0.0010, 0.0000), (0.0010, 0.0014), (0.0000, 0.0014), (0.0000, 0.0000)]
for i, (dlat, dlon) in enumerate(legs):
    m.mav.set_position_target_global_int_send(
        0, m.target_system, m.target_component, 6, 0b0000111111111000,
        int((lat0 + dlat) * 1e7), int((lon0 + dlon) * 1e7), 30, 0, 0, 0, 0, 0, 0, 0, 0)
    if i == 0:
        pump(20)
        print("leg done", state, flush=True)
        set_mode(5, "LOITER")
        set_mode(4, "GUIDED")
        print("modechange done", flush=True)
        continue
    for _ in range(11):
        pump(2)
        print("t", round(time.time()), "mode", state["mode"], "alt", round(state["alt"], 1), flush=True)
print("done", state, log, flush=True)
sys.exit(0)
