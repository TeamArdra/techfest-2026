"""Topology A (sidecar only) recovery test against ArduCopter SITL, loopback only.

usage: sidecar_recovery.py <label> <passive|active-ips> <attacker_sysid> [--no-attack]

SITL (C:/afsitl) -> pilot DIRECT on SERIAL0 (5760): takes off to 30 m in GUIDED, then goes SILENT (receive only).
A pure sidecar `aegis serve --source serial --serial-port socket://127.0.0.1:5762` sits on SERIAL1 (streams enabled by
MAV2_* params), no bridge and no filtering hub.  An attacker on SERIAL2 (5763) sends DO_SET_MODE(LAND) from the given
sysid.  Prints the mode timeline (1 Hz), the sidecar /api/status mitigation block and the LAND -> GUIDED time.
Only processes started here are stopped (by PID).  Logs go to C:/afsitl/<name>_<label>.*
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

LABEL, MODE, ATT_SYS = sys.argv[1], sys.argv[2], int(sys.argv[3])
ATTACK = "--no-attack" not in sys.argv
D = "C:/afsitl"
CFG = "C:/afsitl/cfg_ap_copter"  # copy of configs/ardupilot_copter (absolute)
REPO_CFG = os.environ.get("AEGIS_CFG", CFG)
AEGIS = "C:/afvenv/Scripts/aegis.exe"
procs = []


def start(args, log, cwd=D):
    f = open(f"{D}/{log}_{LABEL}.log", "wb")
    p = subprocess.Popen(args, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def status():
    try:
        return json.load(urllib.request.urlopen("http://127.0.0.1:8105/api/status", timeout=3))
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def main():
    for f in ("eeprom.bin",):
        try:
            os.remove(f"{D}/{f}")
        except OSError:
            pass
    start([f"{D}/ArduCopter.elf", "--model", "+", "--speedup", "1", "--defaults", "mon.parm", "--home", "12.9716,77.5946,920,90"], "sitl")
    time.sleep(3)
    pilot = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255, source_component=190)
    pilot.wait_heartbeat(timeout=30)
    tsys, tcomp = pilot.target_system, pilot.target_component
    pilot.mav.request_data_stream_send(tsys, tcomp, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
    # MAV2_* streams come from --defaults mon.parm (copy of scripts/ardupilot/sitl_defaults_monitor_port.parm)
    for name, val in (("ARMING_CHECK", 0),):
        pilot.param_set_send(name, val)
        time.sleep(0.3)
    time.sleep(1)
    start([AEGIS, "serve", "--port", "8105", "--source", "serial", "--serial-port", "socket://127.0.0.1:5762",
           "--allow-url", "--baud", "115200", "--defense-mode", MODE, "--config-dir", REPO_CFG,
           "--db", f"{D}/sidecar_{LABEL}.sqlite"], "serve")
    state = {"mode": None, "alt": 0.0, "armed": False}
    timeline = []
    t0 = time.time()
    last_hb = [0.0]
    sil = [False]

    def pump(sec):
        end = time.time() + sec
        while time.time() < end:
            if not sil[0] and time.time() - last_hb[0] >= 1.0:
                pilot.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                last_hb[0] = time.time()
            m = pilot.recv_match(blocking=True, timeout=0.2)
            if m is None:
                continue
            t = m.get_type()
            if t == "GLOBAL_POSITION_INT":
                state["alt"] = m.relative_alt / 1000.0
            elif t == "HEARTBEAT" and m.get_srcSystem() == 1:
                state["armed"] = bool(m.base_mode & 0x80)
                if state["mode"] != m.custom_mode:
                    timeline.append((round(time.time() - t0, 1), "mode", m.custom_mode))
                state["mode"] = m.custom_mode

    print("waiting for EKF", flush=True)
    pump(45)
    pilot.mav.set_mode_send(tsys, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)
    pump(3)
    pilot.mav.command_long_send(tsys, tcomp, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    pump(4)
    pilot.mav.command_long_send(tsys, tcomp, 22, 0, 0, 0, 0, 0, 0, 0, 30)
    pump(25)
    print("airborne", state, flush=True)
    sil[0] = True  # pilot goes SILENT: no heartbeat, no command from here on
    pump(12)
    print("pilot silent; pre-attack status", json.dumps(status().get("mitigation", status()))[:400], flush=True)
    t_att = None
    if ATTACK:
        a = mavutil.mavlink_connection("tcp:127.0.0.1:5763", source_system=ATT_SYS, source_component=1)
        a.wait_heartbeat(timeout=15)
        t_att = time.time() - t0
        a.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)
        print(f"ATTACK sent t={t_att:.1f} from sysid {ATT_SYS}", flush=True)
    sec_log = []
    end = time.time() + 70
    nxt = time.time()
    while time.time() < end:
        pump(0.25)
        if time.time() >= nxt:
            sec_log.append((round(time.time() - t0, 1), state["mode"], round(state["alt"], 1)))
            nxt += 1.0
    st = status()
    print("TIMELINE(1Hz) t,mode,alt:", sec_log, flush=True)
    print("MODE CHANGES:", timeline, flush=True)
    print("SIDECAR STATUS:", json.dumps(st)[:3000], flush=True)
    land = [t for t, k, v in timeline if v == 9 and t_att is not None and t >= t_att - 1]
    back = [t for t, k, v in timeline if v == 4 and land and t > land[0]]
    print(f"RESULT label={LABEL} mode={MODE} sysid={ATT_SYS} attack_t={t_att} land_t={land[:1]} "
          f"guided_again_t={back[:1]} land_to_guided_s={(back[0] - land[0]) if back and land else None}", flush=True)


try:
    main()
finally:
    for p in procs:
        p.kill()
