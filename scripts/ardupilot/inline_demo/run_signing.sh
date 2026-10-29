#!/bin/bash
# usage: run_signing.sh <label> <passive|active-ips>   (sign.key / wrong.key must exist; SITL eeprom already holds the key)
LABEL=$1; MODE=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
cd /c/afsitl
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
rm -f tap_$LABEL.bin sign_state_$LABEL.json
HUB_TAP=C:/afsitl/tap_$LABEL.bin $PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5762 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --defense-mode $MODE --signing-key-file sign.key --signing-state sign_state_$LABEL.json --config-dir C:/afsitl/cfg_ap --status-port 8090 --db C:/afsitl/bridge_$LABEL.sqlite --seconds 400 > bridge_$LABEL.log 2>&1 &
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5802 --allow-url --baud 115200 --signing-key-file sign.key --db C:/afsitl/gcsids_$LABEL.sqlite > serve_$LABEL.log 2>&1 &
sleep 4
$PY fly_signed.py $LABEL sign.key > fly_$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 3
echo "attack at $(date +%s)" > attack_$LABEL.log
curl -s http://127.0.0.1:8090/status > status_pre_$LABEL.json
$PY attack_signed.py tap_$LABEL.bin wrong.key >> attack_$LABEL.log 2>&1
$PY attack_signed.py tap_$LABEL.bin wrong.key v1 >> attack_$LABEL.log 2>&1
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 5; done
curl -s http://127.0.0.1:8090/status > status_$LABEL.json
curl -s http://127.0.0.1:8104/api/status > gcsstatus_$LABEL.json
echo finished > case_$LABEL.done
