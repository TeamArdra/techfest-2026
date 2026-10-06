#!/usr/bin/env bash
# Start an ISOLATED headless PX4 SITL + Gazebo instance for AegisFlight (runs INSIDE WSL).
#
#   wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh start|stop|status
#
# Isolation (so it never touches another SITL the user may already be running):
#   * PX4 instance index $AEGIS_PX4_INSTANCE (default 2): GCS link UDP :18570+i,
#     offboard link :14580+i -> remote :14540+i
#   * its own Gazebo transport partition ($GZ_PARTITION=aegis<i>)
#   * its own working directory OUTSIDE the PX4 tree ($AEGIS_SITL_RUN), so the PX4
#     checkout stays clean (params / dataman / logs are written there)
# No PX4 source or build config is modified; only the built binary + env vars are used.
set -euo pipefail

PX4_DIR="${PX4_DIR:-$HOME/PX4-Autopilot}"
INST="${AEGIS_PX4_INSTANCE:-2}"
RUN="${AEGIS_SITL_RUN:-$HOME/aegis_sitl/i${INST}}"
MODEL="${PX4_SIM_MODEL:-gz_x500}"
BUILD="$PX4_DIR/build/px4_sitl_default"
PIDFILE="$RUN/px4.pid"

case "${1:-status}" in
  start)
    mkdir -p "$RUN"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "already running (pid $(cat "$PIDFILE"))"; exit 0
    fi
    # Gazebo resource/plugin paths (same file PX4's own launcher sources)
    # shellcheck disable=SC1091
    set +u; . "$BUILD/rootfs/gz_env.sh"; set -u
    export HEADLESS=1 GZ_IP=127.0.0.1 GZ_PARTITION="aegis${INST}"
    export PX4_SIM_MODEL="$MODEL" PX4_GZ_WORLD="${PX4_GZ_WORLD:-default}"
    # deterministic home position (PX4 default Zurich); override with PX4_HOME_*
    export PX4_HOME_LAT="${PX4_HOME_LAT:-47.397742}" PX4_HOME_LON="${PX4_HOME_LON:-8.545594}" PX4_HOME_ALT="${PX4_HOME_ALT:-488.0}"
    cd "$RUN"
    ln -sfn "$BUILD/etc" "$RUN/etc"
    nohup "$BUILD/bin/px4" -d -i "$INST" -w "$RUN" -s etc/init.d-posix/rcS "$RUN" \
      > "$RUN/px4.log" 2>&1 &
    echo $! > "$PIDFILE"
    echo "started pid $(cat "$PIDFILE"); log: $RUN/px4.log"
    ;;
  stop)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      kill "$(cat "$PIDFILE")" || true
      sleep 2
    fi
    # stop only OUR gazebo server (identified by our partition), never another user's
    for p in $(pgrep -f "gz sim" || true); do
      if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -qx "GZ_PARTITION=aegis${INST}"; then kill "$p" || true; fi
    done
    rm -f "$PIDFILE"; echo stopped
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then echo "running pid $(cat "$PIDFILE")"; else echo "not running"; fi
    ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2;;
esac
