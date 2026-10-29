#!/bin/bash
# usage: run_contested.sh <label> <alert|drop-sensitive>   active-ips, unsigned: counter-tracking attacker vs the real pilot
LABEL=$1; CP=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
cd /c/afsitl
rm -f eeprom.bin tap_$LABEL.bin restart_$LABEL.flag stop_$LABEL.flag
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin $PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5762 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --defense-mode active-ips --contested-policy $CP --config-dir C:/afsitl/cfg_ap --status-port 8090 --seconds 400 --status-interval 2 > bridge_$LABEL.log 2>&1 &
sleep 4
$PY watch_alarm.py > alarm_$LABEL.log 2>&1 &
$PY fly_unsigned.py $LABEL > fly_$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 8
curl -s http://127.0.0.1:8090/status > status_pre_$LABEL.json
echo "attack at $(date +%s)" > attack_$LABEL.log
$PY attack2.py tap_$LABEL.bin track >> attack_$LABEL.log 2>&1
sleep 12
curl -s http://127.0.0.1:8090/status > status_$LABEL.json
touch stop_$LABEL.flag
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
echo finished > case_$LABEL.done
