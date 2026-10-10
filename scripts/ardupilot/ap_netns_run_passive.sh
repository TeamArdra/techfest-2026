#!/usr/bin/env bash
# AegisFlight Stage-2 / deployment preparation: PASSIVE-MONITOR experiment on ArduCopter SITL. Environment: SITL.
#
#   wsl -d Ubuntu-24.04 -- bash /mnt/d/.../scripts/ardupilot/ap_netns_run_passive.sh <run_dir> -- [flight-driver args]
#
# Question answered: if the FC streams on a dedicated serial port because of PERSISTENT parameters
# (SERIAL1_PROTOCOL / SR1_*), can a monitor that NEVER transmits see everything the IDS needs?
#   SERIAL0 (tcp, 5760): a GCS (ap_gcs_pipe.py) flies the simulator; its frames are discarded here.
#   SERIAL1 (tcp, 5762): the monitor (ap_passive_monitor_pipe.py): raw socket, never sends; its frames are stdout.
# Same isolation contract as ap_netns_run.sh (private netns, loopback only, proved at run time, only stdout
# leaves, post-check for leaks). Writes only under <run_dir>. Never touches the ArduPilot/PX4 trees.
set -u
set -o pipefail

AP_BIN=/home/astryx/ardupilot/build/sitl/bin/arducopter
AP_DEFAULTS=/home/astryx/ardupilot/Tools/autotest/default_params/copter.parm
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EXTRA_DEFAULTS="$HERE/sitl_defaults_monitor_port.parm"
PORTS_RE=':(5760|5761|5762|5763|5501|20722)[[:space:]]'

exec 3>&1 1>&2

# ----------------------------------------------------------------------------- inner ------ #
if [ "${AP_NETNS_INNER:-0}" = 1 ]; then
  : "${RUN_DIR:?}" "${DEFAULT_NS:?}"
  AP_PID=""; MON_PID=""; CLEANED=0
  ap_running() { [ -n "$AP_PID" ] && [ -r "/proc/$AP_PID/stat" ] \
    && [ "$(awk '{print $3}' "/proc/$AP_PID/stat" 2>/dev/null)" != "Z" ]; }
  cleanup() {
    [ "$CLEANED" = 1 ] && return; CLEANED=1
    if [ -n "$MON_PID" ] && kill -0 "$MON_PID" 2>/dev/null; then kill -TERM "$MON_PID" 2>/dev/null; wait "$MON_PID" 2>/dev/null; fi
    if [ -z "$AP_PID" ]; then echo "cleanup: arducopter never launched"; return; fi
    if ap_running; then
      echo "cleanup: SIGTERM -> arducopter pid $AP_PID"; kill -TERM "$AP_PID" 2>/dev/null
      for _ in $(seq 1 50); do ap_running || break; sleep 0.1; done
      if ap_running; then echo "cleanup: still running after 5s -> SIGKILL"; kill -KILL "$AP_PID" 2>/dev/null; fi
    else echo "cleanup: arducopter pid $AP_PID had already exited"; fi
    wait "$AP_PID" 2>/dev/null; echo "cleanup: arducopter exit status $? (143=SIGTERM, 137=SIGKILL)"
    if ap_running; then echo "cleanup: FAILED, pid $AP_PID still running"; else echo "cleanup: pid $AP_PID gone"; fi
  }
  trap cleanup EXIT
  trap 'echo "inner: signal received"; exit 143' TERM INT HUP
  touch "$RUN_DIR/inner_started"

  echo "== inner: isolation checks"
  MY_NS=$(readlink /proc/self/ns/net) || { echo "ISOLATION FAIL: cannot read own netns"; exit 90; }
  if [ -z "$MY_NS" ] || [ "$MY_NS" = "$DEFAULT_NS" ]; then echo "ISOLATION FAIL: still in default netns"; exit 90; fi
  ip link set lo up || { echo "ISOLATION FAIL: cannot bring lo up"; exit 91; }
  ip -o link show lo | grep -Eq '[<,]UP[,>]' || { echo "ISOLATION FAIL: lo not UP"; exit 91; }
  ip -o link show; ip -o addr show
  if [ -n "$(ip -o addr show | awk '$2 != "lo"')" ]; then echo "ISOLATION FAIL: non-loopback address"; exit 92; fi
  if [ -n "$(ip -4 route show default 2>/dev/null)$(ip -6 route show default 2>/dev/null)" ]; then
    echo "ISOLATION FAIL: default route present"; exit 92; fi
  if [ -n "$(ss -Hlntu)" ]; then echo "ISOLATION FAIL: pre-existing listeners"; exit 92; fi
  echo "netns $MY_NS (default $DEFAULT_NS): loopback only, no route, no listeners -> isolation OK"
  PYTHONDONTWRITEBYTECODE=1 python3 -c 'from pymavlink import mavutil' \
    || { echo "PREREQ FAIL: pymavlink not importable inside namespace"; exit 94; }

  RT="$RUN_DIR/rt"; mkdir -p "$RT/terrain" || exit 95; cd "$RT" || exit 95
  echo "== inner: launching arducopter (cwd $RT) with SERIAL1 on tcp and $EXTRA_DEFAULTS"
  "$AP_BIN" -I0 --model + --speedup 1 --sysid 1 \
    --home -35.363261,149.165230,584,353 \
    --defaults "$AP_DEFAULTS,$EXTRA_DEFAULTS" \
    --serial0 tcp:0 --serial1 tcp:2 --serial2 none \
    --serial5 none --serial6 none --serial7 none --serial8 none \
    > "$RUN_DIR/arducopter.log" 2>&1 < /dev/null &
  AP_PID=$!; echo "$AP_PID" > "$RUN_DIR/ap.pid"
  LISTEN=0
  for _ in $(seq 1 100); do
    ap_running || { echo "FAIL: arducopter exited before listening"; tail -n 30 "$RUN_DIR/arducopter.log"; exit 93; }
    if ss -Hlnt | grep -Eq ':5760[[:space:]]' && grep -q "SERIAL1" "$RUN_DIR/arducopter.log"; then LISTEN=1; break; fi
    sleep 0.2
  done
  [ "$(readlink "/proc/$AP_PID/exe" 2>/dev/null)" = "$AP_BIN" ] || { echo "FAIL: pid $AP_PID is not arducopter"; exit 97; }
  [ "$LISTEN" = 1 ] || { echo "FAIL: tcp 5760 / SERIAL1 never came up"; tail -n 20 "$RUN_DIR/arducopter.log"; exit 96; }
  grep -E "bind port|SERIAL[0-9] on TCP" "$RUN_DIR/arducopter.log"
  MON_PORT=$(grep -Eo "SERIAL1 on TCP port [0-9]+" "$RUN_DIR/arducopter.log" | grep -Eo "[0-9]+$" | head -1)
  [ -n "$MON_PORT" ] || { echo "FAIL: could not read SERIAL1's TCP port from the simulator log"; exit 98; }
  ss -lntup
  echo "== inner: monitor on SERIAL1 (port $MON_PORT, receive-only; stdout = binary frame stream)"
  # shellcheck disable=SC2086  # MON_ARGS is a deliberate word list
  PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/ap_passive_monitor_pipe.py" --port "$MON_PORT" ${MON_ARGS:-} \
    --events "$RUN_DIR/monitor_events.jsonl" --tlog "$RUN_DIR/downlink.tlog" >&3 &
  MON_PID=$!
  sleep 1.5
  echo "== inner: flight driver on SERIAL0 (its frames are discarded)"
  PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/${AP_DRIVER:-ap_gcs_pipe.py}" "$@" \
    --events "$RUN_DIR/events.jsonl" --tlog "$RUN_DIR/driver_downlink.tlog" > /dev/null
  RC=$?
  echo "flight driver exit status: $RC"
  sleep 1
  kill -TERM "$MON_PID" 2>/dev/null; wait "$MON_PID" 2>/dev/null; MON_RC=$?; MON_PID=""
  echo "monitor exit status: $MON_RC"
  tail -n 15 "$RUN_DIR/arducopter.log"
  exit "$RC"
fi

# ----------------------------------------------------------------------------- outer ------ #
RUN_DIR=${1:?usage: ap_netns_run_passive.sh <run_dir> [monitor args] -- [flight-driver args]}; shift
MON_ARGS=""  # e.g. --send-heartbeat (the NOT-receive-only variant); default: none = strictly receive-only
while [ $# -gt 0 ] && [ "$1" != "--" ]; do MON_ARGS="$MON_ARGS $1"; shift; done
[ "${1:-}" = "--" ] && shift
export MON_ARGS
mkdir -p "$RUN_DIR" || { echo "PREREQ FAIL: cannot create $RUN_DIR"; exit 2; }
port_listeners() { ss -Hlntu | grep -E "$PORTS_RE"; }
{
  echo "== ap_netns_run_passive $(date -u +%Y%m%dT%H%M%SZ) run_dir=$RUN_DIR"
  for c in unshare ip ss timeout python3 pgrep sha256sum readlink; do
    command -v "$c" >/dev/null || { echo "PREREQ FAIL: missing tool $c"; exit 2; }; done
  [ -x "$AP_BIN" ] || { echo "PREREQ FAIL: binary not executable: $AP_BIN"; exit 2; }
  [ -r "$AP_DEFAULTS" ] || { echo "PREREQ FAIL: defaults not readable: $AP_DEFAULTS"; exit 2; }
  [ -r "$EXTRA_DEFAULTS" ] || { echo "PREREQ FAIL: extra defaults not readable: $EXTRA_DEFAULTS"; exit 2; }
  for f in ap_gcs_pipe.py ap_passive_monitor_pipe.py; do [ -r "$HERE/$f" ] || { echo "PREREQ FAIL: missing $f"; exit 2; }; done
  if pgrep -a -x arducopter; then echo "PREREQ FAIL: an arducopter process is already running"; exit 2; fi
  if port_listeners; then echo "PREREQ FAIL: SITL ports already in use in the default namespace"; exit 2; fi
  DEFAULT_NS=$(readlink /proc/self/ns/net) || { echo "PREREQ FAIL: cannot read default netns"; exit 2; }
  echo "kernel:         $(uname -r)"
  echo "binary sha256:  $(sha256sum "$AP_BIN" | cut -d' ' -f1)"
  echo "ardupilot HEAD: $(GIT_OPTIONAL_LOCKS=0 git -C /home/astryx/ardupilot rev-parse HEAD 2>&1)"
  echo "defaults:       $AP_DEFAULTS sha256 $(sha256sum "$AP_DEFAULTS" | cut -d' ' -f1)"
  echo "extra defaults: $EXTRA_DEFAULTS sha256 $(sha256sum "$EXTRA_DEFAULTS" | cut -d' ' -f1)"
  echo "collector:      $HERE/ap_gcs_pipe.py sha256 $(sha256sum "$HERE/ap_gcs_pipe.py" | cut -d' ' -f1)"
  echo "monitor:        $HERE/ap_passive_monitor_pipe.py sha256 $(sha256sum "$HERE/ap_passive_monitor_pipe.py" | cut -d' ' -f1)"
  echo "default netns:  $DEFAULT_NS"
  ss -Hlntu > "$RUN_DIR/ss_default_before.txt"
} > "$RUN_DIR/preflight.txt" 2>&1; PRE_RC=$?
cat "$RUN_DIR/preflight.txt"
[ "$PRE_RC" = 0 ] || exit 2

export RUN_DIR AP_BIN AP_DEFAULTS HERE AP_NETNS_INNER=1
DEFAULT_NS=$(readlink /proc/self/ns/net); export DEFAULT_NS
echo "== launching inside: unshare --user --map-root-user --net"
timeout --kill-after=15 "${AP_OUTER_TIMEOUT:-900}" \
  unshare --user --map-root-user --net --fork --kill-child=SIGTERM \
  bash "${BASH_SOURCE[0]}" "$@" >&3
RC=$?
echo "== namespace run exit status: $RC"

{
  echo "== post-check (default namespace)"
  sleep 1
  BACKSTOP=no
  if [ -s "$RUN_DIR/ap.pid" ]; then
    APPID=$(cat "$RUN_DIR/ap.pid")
    if [ -d "/proc/$APPID" ] && [ "$(readlink "/proc/$APPID/exe" 2>/dev/null)" = "$AP_BIN" ]; then
      echo "tracked arducopter pid $APPID STILL ALIVE -> backstop SIGTERM/SIGKILL"; BACKSTOP=yes
      kill -TERM "$APPID" 2>/dev/null; sleep 3; [ -d "/proc/$APPID" ] && kill -KILL "$APPID" 2>/dev/null
    else echo "tracked arducopter pid $APPID: gone"; fi
  else echo "no tracked pid (arducopter never launched)"; fi
  ss -Hlntu > "$RUN_DIR/ss_default_after.txt"
  if port_listeners; then LEAK=yes; else echo "listeners on the SITL ports in default namespace: none"; LEAK=no; fi
  NEW=$(comm -13 <(sort "$RUN_DIR/ss_default_before.txt") <(sort "$RUN_DIR/ss_default_after.txt"))
  if [ -n "$NEW" ]; then echo "NEW listeners in default namespace vs before:"; echo "$NEW"; else echo "new listeners in default namespace vs before: none"; fi
  if pgrep -a -x arducopter; then REMAIN=yes; else echo "arducopter processes remaining: none"; REMAIN=no; fi
  echo "== summary: rc=$RC leak=$LEAK remaining_process=$REMAIN backstop=$BACKSTOP"
} 2>&1 | tee "$RUN_DIR/postcheck.txt"
exit "$RC"
