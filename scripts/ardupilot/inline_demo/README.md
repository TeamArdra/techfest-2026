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
