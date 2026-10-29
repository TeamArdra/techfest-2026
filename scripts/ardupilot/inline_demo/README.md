# Inline IPS against ArduCopter SITL (loopback demo)

Reproduces the run recorded in `docs/INLINE_IPS.md` ("SITL evidence"). Windows paths are hard-coded to `C:/afsitl`
(SITL files) and `C:/afvenv` (Python venv); edit `run_case.sh` for your layout.

1. Put the ArduPilot SITL build (`ArduCopter.elf` and its Cygwin DLLs from the ArduPilot firmware server, or a native
   build) in `C:/afsitl` and copy these scripts there. Nothing here downloads a binary for you.
2. `./run_case.sh passive passive` then `./run_case.sh active active-ips` (about 5 minutes each).

Topology: SITL SERIAL1 (tcp 5762) <- `aegis ips-bridge` -> `hub.py` (5800) -> pilot script `fly2.py` and an observer
`aegis serve` dashboard (5802). `attack.py` sends a forged LAND from sysid 66. `holder.py` keeps SERIAL0 connected
(SITL waits for it before opening its other ports). Everything binds to loopback, except SITL's own listeners, which
the ArduPilot build opens on all interfaces: stop it when done.

## Signing and unsigned smart-attacker scenarios

- `sign_setup.py <keyfile>`: provision MAVLink-2 signing into a fresh SITL over SERIAL0 (5760), then restart SITL with the
  same `eeprom.bin`. Keys are random 32-byte files you create yourself; never commit them.
- `run_signing.sh <label> <passive|active-ips>` with `fly_signed.py` (signed pilot) and `attack_signed.py` (unsigned,
  wrong-key and replay attacks). `hub.py` records the uplink to `$HUB_TAP` so the replay attacker has a capture.
- `run_unsigned.sh <label> <passive|active-ips>` with `fly_unsigned.py` (pilot with 1 Hz heartbeat, GCS restart) and
  `attack2.py` (own-counter forgery, replay, counter-tracking attacker). Wipes `eeprom.bin` so signing is off.
- `run_wrap.sh <label>` and `run_contested.sh <label> <alert|drop-sensitive>` (unsigned, active-ips): wrap-around replay (`fly_wrap.py`, `attack_wrap.py`) and counter-tracking attacker (`attack2.py track`, `watch_alarm.py` STATUSTEXT observer). See docs/INLINE_IPS.md.
