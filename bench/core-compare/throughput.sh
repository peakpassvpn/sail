#!/bin/bash
# usage: [ENV=...] ./throughput.sh label dir(down|up) reps -- command...
cd "$(dirname "$0")"
label=$1; dir=$2; reps=$3; shift 4
"$@" >/dev/null 2>&1 & P=$!
sleep 1
out=()
for i in $(seq $reps); do
  c0=$(ps -o cputime= -p $P | awk -F: '{print $1*60+$2}')
  r=$(./loadgen/loadgen throughput -streams 8 -bytes 67108864 -dir $dir | python3 -c 'import json,sys;print(round(json.load(sys.stdin)["mbps"]))')
  c1=$(ps -o cputime= -p $P | awk -F: '{print $1*60+$2}')
  out+=("$r/$(python3 -c "print(round(($c1-$c0)/0.537,2))")")
done
kill $P; wait $P 2>/dev/null
med=$(printf '%s\n' "${out[@]}" | python3 -c 'import sys,statistics as s;v=[l.split("/") for l in sys.stdin.read().split()];print(round(s.median(float(a) for a,b in v)), s.median(float(b) for a,b in v))')
printf "%-26s %-4s median MB/s, s/GB: %-12s  runs: %s\n" "$label" "$dir" "$med" "${out[*]}"
