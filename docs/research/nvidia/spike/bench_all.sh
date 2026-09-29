#!/bin/bash
# Latency matrix: for each middleware policy variant, run sequential keep-alive benchmarks
# against the guarded host (middleware selected) and the baseline host (no middleware).
SP=$SPIKE_DIR
OS=$SP/bin/os
OUT=$SP/logs/bench2.jsonl
SB=chio-spike-2
EX="timeout 300 $OS sandbox exec -n $SB --no-tty --timeout 290 -- python3 /sandbox/p2/upload2/probe2.py"
for variant in none regex null chioA cg none; do
  timeout 90 $OS policy set $SB --policy $SP/policy2/$variant.yaml --wait < /dev/null > /dev/null 2>&1
  echo "{\"variant_start\": \"$variant\", \"t\": $(date +%s.%N)}" >> $OUT
  for spec in "1000 1000" "300 65536" "100 1048576"; do
    set -- $spec
    n=$1; size=$2
    if [ "$variant" = "cg" ] && [ "$size" -gt 262144 ]; then continue; fi
    for host in host.openshell.internal host.docker.internal; do
      line=$($EX bench http://$host:27604/echo $n $size /sandbox/p2/upload2/token1.txt < /dev/null 2>&1 | tail -1)
      echo "{\"variant\": \"$variant\", \"host\": \"$host\", \"result\": $line}" >> $OUT
    done
  done
done
echo "{\"done\": $(date +%s.%N)}" >> $OUT
