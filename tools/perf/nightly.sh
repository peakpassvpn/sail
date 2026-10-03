#!/usr/bin/env bash
# The performance regression checks' tier B (roadmap 5.4): base and new
# builds of sail, measured in turn on a quiet shared Linux host, so that
# the host's drift falls on both; the paired ratios go to btier.py.
#
#   tools/perf/nightly.sh NEW_SHA [BASE_SHA]
#
# NEW_SHA and BASE_SHA are master commits whose perf workflow ran: their
# x86_64 musl builds are taken from its artifacts. Without BASE_SHA, base
# is new: a calibration of the noise. The host and its paths are local
# configuration, never in the repository:
#
#   ~/.config/sail/perf-host   PERF_HOST=user@host
#                              PERF_DIR=<working directory on the host>
#                              PERF_JOBS=<the host's job registry directory>
#                              SINGBOX=<sing-box on the host> (default: on PATH)
#                              PERF_OWNER=<who the registry names as running it>
#
# It runs only when no registered job holds its CPUs and the host is
# quiet, registers itself for the run, and removes what it made. The
# nightly runs are tools/perf/nightly-host.sh's, on the host itself, from a
# timer there; this is for a run by hand between two commits.
set -euo pipefail
# shellcheck source=/dev/null
. "$HOME/.config/sail/perf-host"
: "${PERF_HOST:?}" "${PERF_DIR:?}" "${PERF_JOBS:?}"
SINGBOX=${SINGBOX:-sing-box}
OWNER=${PERF_OWNER:-sail tier B}

NEW=$1
BASE=${2:-$1}
ROUNDS=${ROUNDS:-6}
# The CPUs it takes, and the namespaces and subnets agreed for it.
CLIENT_CPU=${CLIENT_CPU:-2}
SERVER_CPU=${SERVER_CPU:-3}
export NETEM_NS=${NETEM_NS:-54} NETEM_NET=${NETEM_NET:-90}
SERVER_NAME=${SERVER_NAME:-pf54} SERVER_NET=${SERVER_NET:-92}
# Quiet: the 1-minute load the 5.5 runs took as quiet.
MAX_LOAD=${MAX_LOAD:-1.0}
# Its peak memory, declared in the registry: 10k connections held, the
# server and its load clients (3.6's per-connection figures), with room.
MEM_MB=${MEM_MB:-800}
# What the registry lets all jobs declare together.
HOST_MEM_MB=${HOST_MEM_MB:-3000}
JOB=sail-5.4-perf
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# netem's scripts must take the namespaces chosen above, or the run would
# take another's (nc5, 10.95).
for script in netns.sh run.py; do
  if ! grep -q NETEM_NS "$ROOT/scripts/netem/$script"; then
    echo "scripts/netem/$script does not take NETEM_NS: no run" >&2
    exit 1
  fi
done
STATE=${PERF_STATE:-$HOME/Projects/sail-tunnel/perf-baselines/b-tier}
STAMP=$(date -u +%Y%m%dT%H%MZ)
OUT=$STATE/$STAMP
mkdir -p "$OUT"

# The x86_64 musl build of a commit, from its perf workflow's artifact.
fetch() {
  local sha=$1 dir=$STATE/bin/$1
  if [ ! -x "$dir/sail" ]; then
    local run
    run=$(gh run list -R peakpassvpn/sail --workflow perf.yml --commit "$sha" --status success \
      --json databaseId --jq '.[0].databaseId')
    [ -n "$run" ] || { echo "no successful perf run for $sha" >&2; exit 1; }
    gh run download "$run" -R peakpassvpn/sail -n sail-x86_64-unknown-linux-musl -D "$dir"
    chmod +x "$dir/sail"
  fi
}
fetch "$NEW"
fetch "$BASE"
(cd "$ROOT/scripts/netem/netgen" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o "$STATE/netgen" .)

remote() { ssh -o ConnectTimeout=10 "$PERF_HOST" "$@"; }

# Its CPUs free and the host quiet, or no run tonight.
held=$(remote "grep -l -E '^cores:.*(any|(^|[^0-9])($CLIENT_CPU|$SERVER_CPU)([^0-9]|$))' $PERF_JOBS/* 2>/dev/null | grep -v '/$JOB\$' || true")
if [ -n "$held" ]; then
  echo "skipped: registered jobs hold CPUs $CLIENT_CPU-$SERVER_CPU: $held" | tee "$OUT/skipped"
  exit 0
fi
# A measurement needs quiet: no build running, no other measurement, and
# the memory declared by all jobs within the host's share.
building=$(remote "pgrep -x 'cargo|rustc|cc1|cc1plus|ld' | head -1 || true")
if [ -n "$building" ]; then
  echo "skipped: a build runs on the host" | tee "$OUT/skipped"
  exit 0
fi
# A registered build may be about to start: its file says "build" with its
# memory ("mem: 3.7G, build").
registered=$(remote "grep -l -E '^mem:.*build' $PERF_JOBS/* 2>/dev/null | grep -v '/$JOB\$' || true")
if [ -n "$registered" ]; then
  echo "skipped: a build is registered: $registered" | tee "$OUT/skipped"
  exit 0
fi
measuring=$(remote "grep -l -E '^kind: *measurement' $PERF_JOBS/* 2>/dev/null | grep -v '/$JOB\$' || true")
if [ -n "$measuring" ]; then
  echo "skipped: another measurement runs: $measuring" | tee "$OUT/skipped"
  exit 0
fi
# Each job's declared memory in MB, whichever way it is written: "800 MB",
# "800M", "3.7G", "3.7 GB".
declared=$(remote "grep -h -E '^mem:' $PERF_JOBS/* 2>/dev/null | awk '{
  line = tolower(\$0); sub(/^mem: */, \"\", line)
  if (match(line, /[0-9]+(\\.[0-9]+)?/)) {
    n = substr(line, RSTART, RLENGTH); unit = substr(line, RSTART + RLENGTH)
    sub(/^ */, \"\", unit)
    sum += (unit ~ /^g/) ? n * 1024 : n
  }
} END { printf \"%d\", sum }'")
if [ $((${declared:-0} + MEM_MB)) -gt "$HOST_MEM_MB" ]; then
  echo "skipped: ${declared} MB declared, and $MEM_MB more passes $HOST_MEM_MB" | tee "$OUT/skipped"
  exit 0
fi
load=$(remote "cut -d' ' -f1 /proc/loadavg")
if awk -v l="$load" -v m="$MAX_LOAD" 'BEGIN { exit !(l > m) }'; then
  echo "skipped: load $load above $MAX_LOAD" | tee "$OUT/skipped"
  exit 0
fi

WORK=$PERF_DIR/$STAMP
remote "mkdir -p $WORK/base $WORK/new && cat > $PERF_JOBS/$JOB" <<JOBFILE
owner: $OWNER (5.4 performance regression, tier B)
kind: measurement
what: base $BASE / new $NEW, $ROUNDS rounds each, in turn
mem: $MEM_MB MB
cores: $CLIENT_CPU-$SERVER_CPU (taskset)
netns: nc$NETEM_NS/ns$NETEM_NS, ${SERVER_NAME}c/${SERVER_NAME}s; subnets 10.$NETEM_NET-10.$((NETEM_NET + 2)), 10.$SERVER_NET
started: $(date -u '+%Y-%m-%d %H:%M UTC')
expected end: about 40 minutes later
stop: NETEM_NS=$NETEM_NS NETEM_NET=$NETEM_NET sh $WORK/netem/netns.sh down; remove this file
JOBFILE
cleanup() {
  remote "NETEM_NS=$NETEM_NS NETEM_NET=$NETEM_NET sh $WORK/netem/netns.sh down; rm -f $PERF_JOBS/$JOB" || true
}
trap cleanup EXIT

rsync -az --no-o --no-g "$STATE/bin/$BASE/sail" "$PERF_HOST:$WORK/base/sail"
rsync -az --no-o --no-g "$STATE/bin/$NEW/sail" "$PERF_HOST:$WORK/new/sail"
rsync -az --no-o --no-g "$STATE/netgen" "$PERF_HOST:$WORK/netgen"
rsync -az --no-o --no-g --exclude netgen --exclude __pycache__ "$ROOT/scripts/netem/" "$PERF_HOST:$WORK/netem/"
rsync -az --no-o --no-g --exclude __pycache__ "$ROOT/scripts/server-accept/" "$PERF_HOST:$WORK/server-accept/"

# Client budgets (mobile and server profiles of the client), turn by turn:
# base then new on odd rounds, new then base on even ones.
for round in $(seq 1 "$ROUNDS"); do
  order="base new"
  [ $((round % 2)) -eq 0 ] && order="new base"
  for which in $order; do
    remote "cd $WORK/netem && NETEM_NS=$NETEM_NS NETEM_NET=$NETEM_NET python3 run.py \
      --work $WORK/$which/r$round --sail $WORK/$which/sail --netgen $WORK/netgen \
      --protocols direct,trojan --clients sail-mobile,sail-server --only baseline,rate10m \
      --cpus $CLIENT_CPU --server-cpus $SERVER_CPU" > "$OUT/netem-$which-r$round.log" 2>&1
  done
done

# The server budget: server-accept pairs base and new within each round.
remote "cd $WORK/server-accept && python3 run.py --work $WORK/server --sail $WORK/new/sail \
  --sail-base $WORK/base/sail --servers sail,sail-base --singbox $SINGBOX --netgen $WORK/netgen \
  --protocols ss2022,trojan --shapes idle,bulk --rounds $ROUNDS --conns 10000 --rate 1000 \
  --server-cores $SERVER_CPU --load-cores $CLIENT_CPU --name $SERVER_NAME --net $SERVER_NET" \
  > "$OUT/server-accept.log" 2>&1

# The summaries back here, outside the repository.
rsync -az --no-o --no-g --include '*/' --include 'summary.json' --exclude '*' \
  "$PERF_HOST:$WORK/" "$OUT/results/"
# What the host was, for a baseline that shifts: swap may change memory
# figures under pressure.
{
  echo "base $BASE new $NEW rounds $ROUNDS"
  echo "host swap: $(remote "swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' '")"
  echo "host swappiness: $(remote 'cat /proc/sys/vm/swappiness')"
} > "$OUT/run"
"$ROOT/tools/perf/btier.py" "$OUT" | tee "$OUT/report.md"
