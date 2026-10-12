#!/bin/bash
SP=$SPIKE_DIR
OS=$SP/bin/os
EV=$SP/logs/q5_events.txt; : > $EV
timeout 100 $OS sandbox exec -n chio-spike-2 --no-tty --timeout 95 -- python3 /sandbox/p2/upload2/probe2.py loop http://host.openshell.internal:27604/echo 75 100 /sandbox/p2/upload2/token1.txt > $SP/logs/q5_loop.jsonl 2>&1 < /dev/null &
LOOP=$!
for round in 1 2 3; do
  sleep 6
  echo "submit_B $(date +%s.%N)" >> $EV
  $OS policy set chio-spike-2 --policy $SP/policy2/chioB.yaml < /dev/null >> $EV 2>&1
  echo "submitted_B $(date +%s.%N)" >> $EV
  sleep 12
  echo "submit_A $(date +%s.%N)" >> $EV
  $OS policy set chio-spike-2 --policy $SP/policy2/chioA.yaml < /dev/null >> $EV 2>&1
  echo "submitted_A $(date +%s.%N)" >> $EV
done
wait $LOOP
$OS policy list chio-spike-2 -o json < /dev/null > $SP/logs/q5_policy_list.json 2>&1
echo "done $(date +%s.%N)" >> $EV
