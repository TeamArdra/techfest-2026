"""Pilot for the wrap-around replay test (unsigned link).

usage: fly_wrap.py <label>
After take-off and one leg: LOITER, then ONE genuine DO_SET_MODE(GUIDED) (the frame the attacker captures, seq S),
LOITER again, then ~20/s filler heartbeats until the 8-bit counter wraps back to S-3. It writes wrap_<label>.ready
(containing S) and pauses; attack_wrap.py replays the captured bytes and writes replayed_<label>.flag. The pilot then
continues the counter past S and sends a legitimate DO_SET_MODE(GUIDED) (new seq) that must still be forwarded.
Control file in C:/afsitl: stop_<label>.flag ends the pilot.
"""
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

label = sys.argv[1]
flag = lambda n: os.path.exists(f"C:/afsitl/{n}_{label}.flag")  # noqa: E731
m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
m.wait_heartbeat(timeout=30)
print("heartbeat from", m.target_system, m.target_component, flush=True)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
for name, val in (("SR1_POSITION", 5), ("SR1_EXTRA1", 5), ("SR1_EXTRA2", 5), ("SR1_RAW_SENS", 2),
                  ("SR1_EXT_STAT", 2), ("SR1_EXTRA3", 2), ("ARMING_CHECK", 0)):
    m.param_set_send(name, val)
    time.sleep(0.2)
state = {"alt": 0.0, "armed": False, "mode": None}
last_hb = [0.0]
modes_seen = []
acks = []


def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        if time.time() - last_hb[0] >= 1.0:
            m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            last_hb[0] = time.time()
        msg = m.recv_match(blocking=True, timeout=0.3)
        if msg is None:
            continue
        t = msg.get_type()
        if t == "COMMAND_ACK":
            acks.append((msg.command, msg.result))
        elif t == "GLOBAL_POSITION_INT":
            state["alt"] = msg.relative_alt / 1000.0
        elif t == "HEARTBEAT" and msg.get_srcSystem() == 1:
            state["armed"] = bool(msg.base_mode & 0x80)
            if state["mode"] != msg.custom_mode:
                modes_seen.append((round(time.time()), msg.custom_mode))
            state["mode"] = msg.custom_mode


def cmd_mode(mode):
    """DO_SET_MODE through COMMAND_LONG; returns the COMMAND_ACK result or None."""
    acks.clear()
    m.mav.command_long_send(m.target_system, m.target_component, 176, 0, 1, mode, 0, 0, 0, 0, 0)
    end = time.time() + 2.0
    while time.time() < end:
        pump(0.2)
        for cmd, res in acks:
            if cmd == 176:
                return res
    return None


print("waiting for GPS/EKF ...", flush=True)
pump(45)
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)
pump(3)
m.mav.command_long_send(m.target_system, m.target_component, 400, 0, 1, 0, 0, 0, 0, 0, 0)
pump(4)
m.mav.command_long_send(m.target_system, m.target_component, 22, 0, 0, 0, 0, 0, 0, 0, 30)
pump(25)
print("state", state, flush=True)
m.mav.set_position_target_global_int_send(
    0, m.target_system, m.target_component, 6, 0b0000111111111000,
    int((12.9716 + 0.0010) * 1e7), int(77.5946 * 1e7), 30, 0, 0, 0, 0, 0, 0, 0, 0)
pump(15)
print("leg done", state, flush=True)
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 5)   # LOITER
pump(3)
print("LOITER ->", state["mode"], flush=True)
S = m.mav.seq
r = cmd_mode(4)                      # the genuine, capturable DO_SET_MODE(GUIDED) at seq S
print(f"CAPTURED_CMD seq={S} ack={r} mode={state['mode']}", flush=True)
pump(1)
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 5)   # LOITER again
pump(3)
print("LOITER again ->", state["mode"], flush=True)
t0 = time.time()
n = 0
while m.mav.seq != (S - 3) % 256 or n < 10:
    m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    n += 1
    pump_end = time.time() + 0.05
    while time.time() < pump_end:
        msg = m.recv_match(blocking=True, timeout=0.02)
        if msg is not None and msg.get_type() == "HEARTBEAT" and msg.get_srcSystem() == 1:
            state["mode"] = msg.custom_mode
print(f"fillers={n} in {round(time.time() - t0, 1)}s counter now={m.mav.seq} (S={S}) mode={state['mode']}", flush=True)
open(f"C:/afsitl/wrap_{label}.ready", "w").write(str(S))
t1 = time.time()
while not flag("replayed") and time.time() - t1 < 90:
    msg = m.recv_match(blocking=True, timeout=0.3)
    if msg is not None and msg.get_type() == "HEARTBEAT" and msg.get_srcSystem() == 1:
        state["mode"] = msg.custom_mode
print("after replay, pilot mode seen:", state["mode"], flush=True)
for _ in range(6):                    # the pilot's own counter passes S with ordinary heartbeats
    m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    pump(0.3)
r = cmd_mode(4)                       # legitimate command, new seq, same payload as the captured one
pump(2)
print(f"LEGIT_AFTER_REPLAY ack={r} mode={state['mode']} counter={m.mav.seq}", flush=True)
while not flag("stop"):
    pump(0.5)
print("done", state, flush=True)
