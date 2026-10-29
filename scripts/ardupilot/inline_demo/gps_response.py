"""GPS spoofing response test (bridge deployment) against ArduCopter SITL, loopback only.

usage: gps_response.py <label> <benign|glitch|drift|override> [passive|active-ips]

SITL SERIAL1 (5762) <- `aegis ips-bridge` -> hub (5800/5801) -> pilot (this script, sysid 255).  A separate direct
link to SERIAL0 (5760) plays the "simulator console" and writes the SITL GPS fault parameters (SIM_GPS1_GLTCH_X/Y are
a position offset in DEGREES, 0.001 deg ~ 111 m north; there is no horizontal-drift parameter, so `drift` ramps
GLTCH_X by script).  Flight: GUIDED, takeoff to 30 m, hold.  Scenarios:
  benign    no fault (control)
  glitch    GLTCH_X 0 -> 0.001 in one step (~111 m)
  drift     GLTCH_X ramps 0 -> 0.001 at DRIFT_DEG_PER_S (default ~1 m/s; scripted steps every second)
  override  glitch, and the pilot sends LOITER once the bridge reports GPS_CONFIRMED
Prints the mode timeline, STATUSTEXT seen on the GCS side, and the bridge status (actions, counters).
Only processes started here are stopped (by PID).  Logs: C:/afsitl/<name>_<label>.*
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

LABEL, SCEN = sys.argv[1], sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else "active-ips"
D = "C:/afsitl"
CFG = f"{D}/cfg_ap_copter"  # copy of configs/ardupilot_copter (absolute path)
AEGIS = "C:/afvenv/Scripts/aegis.exe"
PY = "C:/afvenv/Scripts/python.exe"
HERE = os.path.dirname(os.path.abspath(__file__)).replace("\\", "/")
procs = []


def start(args, log):
    f = open(f"{D}/{log}_{LABEL}.log", "wb")
    p = subprocess.Popen(args, cwd=D, stdout=f, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def bridge_status():
    try:
        return json.load(urllib.request.urlopen("http://127.0.0.1:8090/status", timeout=3))
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def cf(st):
    try:
        return st["analyser"]["counter_frames_sent"], st["analyser"]["alerts"]
    except Exception:  # noqa: BLE001
        return None


def events_since(label, wall):
    import sqlite3
    try:
        c = sqlite3.connect(f"{D}/gpsbridge_{label}.sqlite")
        rows = c.execute("select wall_time,attack_type,severity,threat_score,evidence from events where wall_time>=? "
                         "order by id", (wall,)).fetchall()
        return [(round(r[0] - wall, 1), r[1], r[2], r[3], json.loads(r[4])[:3]) for r in rows]
    except Exception as e:  # noqa: BLE001
        return f"db error {e}"


def main():
    try:
        os.remove(f"{D}/eeprom.bin")
    except OSError:
        pass
    start([f"{D}/ArduCopter.elf", "--model", "+", "--speedup", "1", "--defaults", "mon.parm",
           "--home", "12.9716,77.5946,920,90"], "sitl")
    start([PY, f"{HERE}/hub.py"], "hub")
    time.sleep(3)
    console = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=254, source_component=190)
    console.wait_heartbeat(timeout=30)
    start([AEGIS, "ips-bridge", "--fc-port", "socket://127.0.0.1:5762", "--fc-baud", "115200",
           "--gcs-port", "socket://127.0.0.1:5800", "--gcs-baud", "115200", "--allow-url", "--defense-mode", MODE,
           "--config-dir", CFG, "--status-port", "8090", "--db", f"{D}/gpsbridge_{LABEL}.sqlite",
           "--seconds", "400"], "bridge")
    time.sleep(4)
    pilot = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
    pilot.wait_heartbeat(timeout=30)
    ts, tc = pilot.target_system, pilot.target_component
    pilot.mav.request_data_stream_send(ts, tc, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
    pilot.param_set_send("ARMING_CHECK", 0)
    st = {"mode": None, "alt": 0.0, "lat": None, "lon": None}
    t0 = time.time()
    timeline, texts, sec = [], [], []
    lastHB = [0.0]
    nxt = [time.time()]

    def pump(s):
        end = time.time() + s
        while time.time() < end:
            if time.time() - lastHB[0] >= 1.0:
                pilot.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                lastHB[0] = time.time()
            m = pilot.recv_match(blocking=True, timeout=0.2)
            if m is not None:
                t = m.get_type()
                if t == "GLOBAL_POSITION_INT":
                    st["alt"], st["lat"], st["lon"] = m.relative_alt / 1000.0, m.lat / 1e7, m.lon / 1e7
                elif t == "HEARTBEAT" and m.get_srcSystem() == 1:
                    if st["mode"] != m.custom_mode:
                        timeline.append((round(time.time() - t0, 1), m.custom_mode))
                    st["mode"] = m.custom_mode
                elif t == "STATUSTEXT":
                    texts.append((round(time.time() - t0, 1), m.text))
            if time.time() >= nxt[0]:
                nxt[0] += 1.0
                sec.append((round(time.time() - t0, 1), st["mode"], round(st["alt"], 1),
                            None if st["lat"] is None else round(st["lat"], 5),
                            None if st["lon"] is None else round(st["lon"], 5)))

    print("waiting for EKF", flush=True)
    pump(45)
    pilot.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)
    pump(3)
    pilot.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    pump(4)
    pilot.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, 0, 0, 0, 30)
    pump(25)
    print("airborne", st, flush=True)
    pump(8)
    base = bridge_status()
    pre = cf(base)
    print("pre-fault bridge (counter_frames_sent, alerts):", pre, flush=True)
    t_fault = None
    wall0 = time.time()
    if SCEN in ("glitch", "override"):
        console.param_set_send("SIM_GPS1_GLTCH_X", 0.001)
        t_fault = time.time() - t0
        print(f"FAULT glitch GLTCH_X=0.001 at t={t_fault:.1f}", flush=True)
    elif SCEN == "drift":
        t_fault = time.time() - t0
        print(f"FAULT drift ramp starts t={t_fault:.1f}", flush=True)

        def ramp():
            step = float(os.environ.get("DRIFT_DEG_PER_S", "9e-6"))  # 9e-6 deg ~ 1 m/s north
            for i in range(1, int(0.001 / step) + 1):
                console.param_set_send("SIM_GPS1_GLTCH_X", step * i)
                time.sleep(1.0)
        threading.Thread(target=ramp, daemon=True).start()
    t_override = None
    end = time.time() + (75 if SCEN != "drift" else 110)
    while time.time() < end:
        pump(0.5)
        if SCEN == "override" and t_override is None:
            if any("GPS unreliable" in x[1] for x in texts):
                pilot.mav.command_long_send(ts, tc, 176, 0, 1, 5, 0, 0, 0, 0, 0)  # DO_SET_MODE LOITER
                t_override = round(time.time() - t0, 1)
                print(f"PILOT OVERRIDE LOITER sent t={t_override}", flush=True)
    fin = bridge_status()
    print("FAULT_T", t_fault, "OVERRIDE_T", t_override, flush=True)
    print("MODE CHANGES:", timeline, flush=True)
    print("STATUSTEXT (GCS side):", texts, flush=True)
    print("TIMELINE(1Hz) t,mode,alt,lat,lon:", sec, flush=True)
    print("BRIDGE (counter_frames_sent, alerts) after:", cf(fin), flush=True)
    print("BRIDGE EVENTS since fault (dt, type, severity, score, evidence):", json.dumps(events_since(LABEL, wall0)), flush=True)
    print("BRIDGE POLICY:", json.dumps(fin.get("policy")), flush=True)
    try:
        a = fin["analyser"]
        print("BRIDGE ANALYSER:", json.dumps({k: a[k] for k in a if k != "mitigation"})[:1500], flush=True)
    except Exception as e:  # noqa: BLE001
        print("analyser n/a", e, flush=True)


try:
    main()
finally:
    for p in procs:
        p.kill()
