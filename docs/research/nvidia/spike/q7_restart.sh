#!/bin/bash
SP=$SPIKE_DIR
OS=$SP/bin/os
OUT=$SP/logs/q7_restart.jsonl
EV=$SP/logs/q7_restart_events.txt
: > $OUT; : > $EV
timeout 60 $OS sandbox exec -n chio-spike-1 --no-tty -- python3 /sandbox/p2/upload2/probe2.py loop http://host.openshell.internal:27604/echo 32 200 /sandbox/p2/upload2/token1.txt > $OUT 2>&1 &
LOOP=$!
sleep 6
OLD=$(cat $SP/logs/mw.pid)
echo "kill_old $OLD $(date +%s.%N)" >> $EV
kill $OLD
sleep 12
cd $SP/mw
setsid nohup .venv/bin/python chio_mw.py --bind 10.20.1.67:27601 --log $SP/logs/mw2.jsonl --receipts $SP/logs/receipts2.jsonl > $SP/logs/mw2.out 2>&1 < /dev/null &
echo $! > $SP/logs/mw.pid
echo "start_new $(cat $SP/logs/mw.pid) $(date +%s.%N)" >> $EV
wait $LOOP
echo "loop_done $(date +%s.%N)" >> $EV
