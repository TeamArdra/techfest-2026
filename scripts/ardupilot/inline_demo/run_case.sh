#!/bin/bash
# usage: run_case.sh <label> <passive|active-ips>
LABEL=$1; MODE=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
cd /c/afsitl
for n in ArduCopter.elf; do taskkill //IM $n //F >/dev/null 2>&1; done
for p in 5800 5801 5802 8090 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
$PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5762 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --defense-mode $MODE --config-dir C:/afsitl/cfg_ap --status-port 8090 --db C:/afsitl/bridge_$LABEL.sqlite --seconds 400 > bridge_$LABEL.log 2>&1 &
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5802 --allow-url --baud 115200 --db C:/afsitl/gcsids_$LABEL.sqlite > serve_$LABEL.log 2>&1 &
sleep 4
$PY fly2.py $LABEL > fly_$LABEL.log 2>&1 &
# wait for the first leg, then attack twice 20 s apart
until grep -q "^leg done" fly_$LABEL.log 2>/dev/null; do sleep 5; done
echo "attack at $(date +%s)" > attack_$LABEL.log
$PY attack.py >> attack_$LABEL.log 2>&1
sleep 20
$PY attack.py >> attack_$LABEL.log 2>&1
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 5; done
curl -s http://127.0.0.1:8090/status > status_$LABEL.json
curl -s http://127.0.0.1:8104/api/status > gcsstatus_$LABEL.json
echo finished > case_$LABEL.done
