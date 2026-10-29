"""Pilot for the unsigned-link smart-attacker scenario.

usage: fly_unsigned.py <label>
Real GCS behaviour on an unsigned link: sysid 255 / compid 190, 1 Hz heartbeat, takes off, flies one leg, makes a
legitimate LOITER -> GUIDED mode change (the frame an attacker can capture), then holds and sends a benign
DO_SET_MODE(GUIDED) every 5 s ("BEAT", checked by COMMAND_ACK).  Control files in C:/afsitl:
  restart_<label>.flag  -> the pilot restarts its MAVLink sequence counter (GCS restart) and retries LOITER/GUIDED
  stop_<label>.flag     -> the pilot ends.
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
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 5)   # genuine LOITER
pump(3)
print("legit LOITER ->", state["mode"], flush=True)
m.mav.set_mode_send(m.target_system, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)   # back to GUIDED
pump(3)
print("modechange done", state, flush=True)
beats = []
next_beat = time.time() + 2
restarted = False
while not flag("stop") and time.time() < next_beat + 600:
    pump(0.5)
    if time.time() >= next_beat:
        r = cmd_mode(4)
        beats.append(r)
        print(f"BEAT {len(beats)} t={round(time.time())} ack={r} mode={state['mode']}", flush=True)
        next_beat = time.time() + 5
    if flag("restart") and not restarted:
        restarted = True
        m.mav.seq = 0       # GCS restart: sequence counter back to 0
        t0 = time.time()
        tries = 0
        ok = False
        while tries < 10 and not ok:
            tries += 1
            r = cmd_mode(5)
            ok = r == 0 and state["mode"] == 5
            print(f"RESTART try {tries} LOITER ack={r} mode={state['mode']} dt={round(time.time() - t0, 1)}",
                  flush=True)
            if not ok:
                pump(1.0)
        pump(2)
        ok2 = False
        for _ in range(10):
            r = cmd_mode(4)
            if r == 0 and state["mode"] == 4:
                ok2 = True
                break
        print(f"restart done loiter_ok={ok} tries={tries} back_to_guided_ok={ok2} mode={state['mode']}",
              flush=True)
print("beats", beats, flush=True)
print("done", state, "modes_seen", modes_seen, flush=True)
