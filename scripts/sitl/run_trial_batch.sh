#!/usr/bin/env bash
# Run N live SITL trials of one P2 trial driver, with a FRESH PX4 SITL boot per trial (Git Bash on Windows).
#
#   bash scripts/sitl/run_trial_batch.sh <driver.py> <out-prefix> <seed> <first-idx> <last-idx> <start-num> [extra driver args...]
#   e.g. bash scripts/sitl/run_trial_batch.sh run_p2_replay_v2_trial.py artifacts/sitl/p2r_v2_trial 5101 1 9 2 --seconds 70
#
# <start-num> is the 3-digit file number given to trial_index=<first-idx>; later trials increment it
# (trial_index i -> number start-num + (i - first-idx)). This lets a batch resume after a pilot that
# already claimed trial_index 0 as _001 without renumbering anything. Nothing already on disk is
# overwritten (the drivers refuse to run if their output exists). A trial that fails to boot/connect is
# reported and the batch continues.
#
# Also clears any persisted MAVLink-2 signing key (found live during the P4 pilot: the key
# survives a PX4 restart within the same isolated run dir, which made a later trial's "was THIS
# trial's SETUP_SIGNING the operative bootstrap" ambiguous). Harmless for every non-signing
# driver (the file simply never exists for them).
set -u
DRIVER="$1"; PREFIX="$2"; SEED="$3"; FIRST="$4"; LAST="$5"; NUMBASE="$6"; shift 6
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="$ROOT/.venv/Scripts/python.exe"
WSLRUN='bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh'
cd "$ROOT" || exit 2
fail=0
for ((i=FIRST; i<=LAST; i++)); do
  n=$(printf "%03d" $((NUMBASE + i - FIRST)))
  out="${PREFIX}_${n}"
  echo "=== trial_index=$i -> $out"
  MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- $WSLRUN stop >/dev/null 2>&1
  sleep 3
  MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- bash -c 'rm -f ~/aegis_sitl/i2/mavlink/mavlink-signing-key.bin' >/dev/null 2>&1
  MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- $WSLRUN start >/dev/null 2>&1
  ready=0
  for _ in $(seq 1 60); do
    if MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- bash -c 'grep -q "Startup script returned successfully" ~/aegis_sitl/i2/px4.log' 2>/dev/null; then ready=1; break; fi
    sleep 1
  done
  [ $ready = 1 ] || { echo "  SITL did not become ready"; fail=$((fail+1)); continue; }
  sleep 8
  PYTHONUNBUFFERED=1 "$PY" "scripts/sitl/$DRIVER" --seed "$SEED" --trial-index "$i" --out "$out" "$@" \
    > "${out}.stdout.txt" 2>&1 || { echo "  driver failed (see ${out}.stdout.txt)"; fail=$((fail+1)); }
done
MSYS_NO_PATHCONV=1 wsl -d Ubuntu-24.04 -- $WSLRUN stop >/dev/null 2>&1
echo "batch done; failed trials: $fail"
