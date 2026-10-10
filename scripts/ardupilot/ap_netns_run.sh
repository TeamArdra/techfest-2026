#!/usr/bin/env bash
# AegisFlight Stage-2 / P1: run ArduCopter SITL inside a PRIVATE network namespace and stream its
# downlink to stdout through ap_gcs_pipe.py. Environment tag: SITL.
#
#   wsl -d Ubuntu-24.04 -- bash /mnt/d/.../scripts/ardupilot/ap_netns_run.sh <run_dir> -- [collector args]
#
# Isolation contract (proved at run time, not assumed; fail closed, no fallback):
#   * `unshare --user --map-root-user --net`: the simulator's TCP 5760 exists ONLY inside the new
#     namespace, which has loopback and nothing else (no interface, address, route or listener).
#   * The ONLY channel out is this script's stdout (binary: length-prefixed MAVLink frames).
#     Every diagnostic goes to stderr. Nothing is bound in the default namespace; the post-check
#     compares listeners before/after and records it in <run_dir>/postcheck.txt.
# Writes only under <run_dir> (create it under /home/astryx/aegis_sitl_ap/logs/). The ArduPilot
# tree and the PX4 tree are never touched. Exit codes: 2 prerequisite, 9x isolation (see inner),
# otherwise the collector's.
set -u
set -o pipefail

AP_BIN=/home/astryx/ardupilot/build/sitl/bin/arducopter
AP_DEFAULTS=/home/astryx/ardupilot/Tools/autotest/default_params/copter.parm
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PORTS_RE=':(5760|5501|20722)[[:space:]]'

# stdout is reserved for the binary stream: keep a handle to it (fd 3) and send our text to stderr
exec 3>&1 1>&2

# ----------------------------------------------------------------------------- inner ------ #
if [ "${AP_NETNS_INNER:-0}" = 1 ]; then
  : "${RUN_DIR:?}" "${DEFAULT_NS:?}"
  AP_PID=""; CLEANED=0
  ap_running() { [ -n "$AP_PID" ] && [ -r "/proc/$AP_PID/stat" ] \
    && [ "$(awk '{print $3}' "/proc/$AP_PID/stat" 2>/dev/null)" != "Z" ]; }
  cleanup() {
    [ "$CLEANED" = 1 ] && return; CLEANED=1
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

  RT="$RUN_DIR/rt"; mkdir -p "$RT/terrain" || exit 95; cd "$RT" || exit 95   # fresh eeprom each run
  echo "== inner: launching arducopter (cwd $RT)"
  "$AP_BIN" -I0 --model + --speedup 1 --sysid 1 \
    --home -35.363261,149.165230,584,353 \
    --defaults "$AP_DEFAULTS" \
    --serial0 tcp:0 --serial1 none --serial2 none \
    --serial5 none --serial6 none --serial7 none --serial8 none \
    > "$RUN_DIR/arducopter.log" 2>&1 < /dev/null &
  AP_PID=$!; echo "$AP_PID" > "$RUN_DIR/ap.pid"
  LISTEN=0
  for _ in $(seq 1 100); do
    ap_running || { echo "FAIL: arducopter exited before listening"; tail -n 30 "$RUN_DIR/arducopter.log"; exit 93; }
    if ss -Hlnt | grep -Eq ':5760[[:space:]]'; then LISTEN=1; break; fi
    sleep 0.2
  done
  [ "$(readlink "/proc/$AP_PID/exe" 2>/dev/null)" = "$AP_BIN" ] || { echo "FAIL: pid $AP_PID is not arducopter"; exit 97; }
  [ "$LISTEN" = 1 ] || { echo "FAIL: tcp 5760 never listened"; exit 96; }
  ss -lntup
  echo "== inner: collector (SITL only); stdout = binary frame stream"
  PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/ap_gcs_pipe.py" "$@" \
    --events "$RUN_DIR/events.jsonl" --tlog "$RUN_DIR/downlink.tlog" >&3
  RC=$?
  echo "collector exit status: $RC"
  if ap_running; then echo "arducopter still running after collector: yes"; else echo "arducopter still running after collector: NO (exited on its own)"; fi
  tail -n 15 "$RUN_DIR/arducopter.log"
  exit "$RC"
fi

# ----------------------------------------------------------------------------- outer ------ #
RUN_DIR=${1:?usage: ap_netns_run.sh <run_dir> -- [collector args]}; shift
[ "${1:-}" = "--" ] && shift
mkdir -p "$RUN_DIR" || { echo "PREREQ FAIL: cannot create $RUN_DIR"; exit 2; }
port_listeners() { ss -Hlntu | grep -E "$PORTS_RE"; }
{
  echo "== ap_netns_run $(date -u +%Y%m%dT%H%M%SZ) run_dir=$RUN_DIR"
  for c in unshare ip ss timeout python3 pgrep sha256sum readlink; do
    command -v "$c" >/dev/null || { echo "PREREQ FAIL: missing tool $c"; exit 2; }; done
  [ -x "$AP_BIN" ] || { echo "PREREQ FAIL: binary not executable: $AP_BIN"; exit 2; }
  [ -r "$AP_DEFAULTS" ] || { echo "PREREQ FAIL: defaults not readable: $AP_DEFAULTS"; exit 2; }
  [ -r "$HERE/ap_gcs_pipe.py" ] || { echo "PREREQ FAIL: missing ap_gcs_pipe.py"; exit 2; }
  if pgrep -a -x arducopter; then echo "PREREQ FAIL: an arducopter process is already running"; exit 2; fi
  if port_listeners; then echo "PREREQ FAIL: 5760/5501/20722 already in use in the default namespace"; exit 2; fi
  DEFAULT_NS=$(readlink /proc/self/ns/net) || { echo "PREREQ FAIL: cannot read default netns"; exit 2; }
  echo "kernel:         $(uname -r)"
  echo "binary sha256:  $(sha256sum "$AP_BIN" | cut -d' ' -f1)"
  echo "ardupilot HEAD: $(GIT_OPTIONAL_LOCKS=0 git -C /home/astryx/ardupilot rev-parse HEAD 2>&1)"
  echo "defaults:       $AP_DEFAULTS sha256 $(sha256sum "$AP_DEFAULTS" | cut -d' ' -f1)"
  echo "collector:      $HERE/ap_gcs_pipe.py sha256 $(sha256sum "$HERE/ap_gcs_pipe.py" | cut -d' ' -f1)"
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
  if port_listeners; then LEAK=yes; else echo "listeners on 5760/5501/20722 in default namespace: none"; LEAK=no; fi
  NEW=$(comm -13 <(sort "$RUN_DIR/ss_default_before.txt") <(sort "$RUN_DIR/ss_default_after.txt"))
  if [ -n "$NEW" ]; then echo "NEW listeners in default namespace vs before:"; echo "$NEW"; else echo "new listeners in default namespace vs before: none"; fi
  if pgrep -a -x arducopter; then REMAIN=yes; else echo "arducopter processes remaining: none"; REMAIN=no; fi
  echo "== summary: rc=$RC leak=$LEAK remaining_process=$REMAIN backstop=$BACKSTOP"
} 2>&1 | tee "$RUN_DIR/postcheck.txt"
exit "$RC"
