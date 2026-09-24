#!/bin/bash
# usage: syscount/measure.sh label dir(down|up) -- command...
# Prints socket syscalls per GB transferred and average bytes per call.
cd "$(dirname "$0")/.."
label=$1; dir=$2; shift 3
out=$(mktemp)
DYLD_INSERT_LIBRARIES=$PWD/syscount/syscount.dylib SYSCOUNT_OUT=$out "$@" >/dev/null 2>&1 & P=$!
sleep 1
cat $out > $out.before 2>/dev/null
./loadgen/loadgen throughput -streams 8 -bytes 67108864 -dir $dir >/dev/null
sleep 0.5
kill $P; wait $P 2>/dev/null
python3 - "$label" "$dir" $out.before $out <<'PY'
import sys
label, d, before, after = sys.argv[1:]
def load(p):
    try: return {l.split()[0]: list(map(int, l.split()[1:])) for l in open(p) if l.strip()}
    except FileNotFoundError: return {}
b, a = load(before), load(after)
gb = 8 * 67108864 / 1e9
parts = []
for k in sorted(a):
    c = a[k][0] - b.get(k, [0,0,0])[0]; n = a[k][1] - b.get(k, [0,0,0])[1]; e = a[k][2] - b.get(k, [0,0,0])[2]
    if c < 50: continue
    parts.append(f"{k} {c/gb/1000:.1f}k/GB avg {n/max(c-e,1)/1024:.1f}KB eagain {100*e/c:.0f}%")
print(f"{label:<18} {d:<4} " + " | ".join(parts) if parts else f"{label:<18} {d:<4} (no calls seen)")
PY
rm -f $out $out.before $out.tmp
