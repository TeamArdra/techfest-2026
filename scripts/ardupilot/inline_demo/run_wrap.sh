#!/bin/bash
# usage: run_wrap.sh <label>   active-ips, unsigned: wrap-around replay of a captured DO_SET_MODE(GUIDED)
LABEL=$1; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
cd /c/afsitl
rm -f eeprom.bin tap_$LABEL.bin wrap_$LABEL.ready replayed_$LABEL.flag stop_$LABEL.flag
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin $PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5762 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --allow-unsigned --defense-mode active-ips --config-dir C:/afsitl/cfg_ap --status-port 8090 --seconds 300 --status-interval 2 > bridge_$LABEL.log 2>&1 &
sleep 4
$PY fly_wrap.py $LABEL > fly_$LABEL.log 2>&1 &
$PY attack_wrap.py $LABEL > attack_$LABEL.log 2>&1 &
until grep -q "^LEGIT_AFTER_REPLAY" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 3
curl -s http://127.0.0.1:8090/status > status_$LABEL.json
touch stop_$LABEL.flag
sleep 3
echo finished > case_$LABEL.done
