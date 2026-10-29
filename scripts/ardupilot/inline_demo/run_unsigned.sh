#!/bin/bash
# usage: run_unsigned.sh <label> <passive|active-ips>   (no key anywhere; SITL eeprom is wiped so signing is off)
LABEL=$1; MODE=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
cd /c/afsitl
rm -f eeprom.bin tap_$LABEL.bin restart_$LABEL.flag stop_$LABEL.flag
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin $PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5762 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --allow-unsigned --defense-mode $MODE --config-dir C:/afsitl/cfg_ap --status-port 8090 --db C:/afsitl/bridge_$LABEL.sqlite --seconds 400 > bridge_$LABEL.log 2>&1 &
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5802 --allow-url --baud 115200 --db C:/afsitl/gcsids_$LABEL.sqlite > serve_$LABEL.log 2>&1 &
sleep 4
$PY fly_unsigned.py $LABEL > fly_$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 8
echo "attack at $(date +%s)" > attack_$LABEL.log
curl -s http://127.0.0.1:8090/status > status_pre_$LABEL.json
$PY attack2.py tap_$LABEL.bin own,replay >> attack_$LABEL.log 2>&1
sleep 8
touch restart_$LABEL.flag
until grep -q "^restart done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 8
$PY attack2.py tap_$LABEL.bin track >> attack_$LABEL.log 2>&1
sleep 12
curl -s http://127.0.0.1:8090/status > status_$LABEL.json
curl -s http://127.0.0.1:8104/api/status > gcsstatus_$LABEL.json
touch stop_$LABEL.flag
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
echo finished > case_$LABEL.done
