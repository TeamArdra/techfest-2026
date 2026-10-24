#!/usr/bin/env bash
# SCRATCH ONLY. run_one.sh NAME MODE TLOG PORT DELAY SECONDS
#   MODE=repo    -> scripts/hardware/virtual_serial_replay.py (exact repo tool, speed 1.0)
#   MODE=delayed -> scratch delayed_replay.py (frames start DELAY s after the runner connects)
#   MODE=silent  -> scratch delayed_replay.py "-" (accept, send nothing)
set -u
NAME=$1; MODE=$2; TLOG=$3; PORT=$4; DELAY=$5; SECS=$6
REPO=D:/Ardra/techfest-2026/aegisflight
DR=C:/Users/RajTi/AppData/Local/Temp/claude/D--Ardra-techfest-2026-aegisflight/f5128bb2-9476-487d-8b36-490148e1965e/scratchpad/px4/dryrun
PY=$REPO/.venv/Scripts/python.exe
OUT=$DR/$NAME
READY=$DR/$NAME.ready; SLOG=$DR/$NAME.server.json
rm -f "$READY"
cd "$REPO" || exit 9
case $MODE in
  repo)    "$PY" scripts/hardware/virtual_serial_replay.py "$TLOG" --port "$PORT" --speed 1.0 --ready-file "$READY" > "$DR/$NAME.server.out" 2>&1 & ;;
  delayed) "$PY" -I "$DR/delayed_replay.py" "$TLOG" "$PORT" "$DELAY" "$READY" "$SLOG" 2 > "$DR/$NAME.server.out" 2>&1 & ;;
  silent)  "$PY" -I "$DR/delayed_replay.py" - "$PORT" -1 "$READY" "$SLOG" $((SECS + 10)) > "$DR/$NAME.server.out" 2>&1 & ;;
esac
SRV=$!
for _ in $(seq 1 150); do [ -f "$READY" ] && break; sleep 0.1; done
if [ ! -f "$READY" ]; then echo "SERVER NOT READY (port $PORT busy?)" > "$DR/$NAME.console.txt"; kill $SRV 2>/dev/null; exit 8; fi
"$PY" scripts/hardware/run_serial_ids.py --port "socket://127.0.0.1:$PORT" --allow-url --baud 115200 \
  --out-dir "$OUT" --seconds "$SECS" --no-reconnect > "$DR/$NAME.console.txt" 2>&1
echo "EXIT=$?" >> "$DR/$NAME.console.txt"
"$REPO/.venv/Scripts/aegis.exe" verify-log "$OUT/events.sqlite" > "$DR/$NAME.verify.txt" 2>&1
echo "EXIT=$?" >> "$DR/$NAME.verify.txt"
wait $SRV
