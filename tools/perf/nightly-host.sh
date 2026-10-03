#!/usr/bin/env bash
# Tier B of the performance regression checks (roadmap 5.4), run nightly
# on the shared Linux test host itself, by a timer there: no session
# starts it, and the host holds no credentials.
#
#   tools/perf/nightly-host.sh
#
# It runs from a read-only checkout of master that the host's wrapper has
# just fetched over https, and reads its settings from the file
# $PERF_CONFIG names (the host's, never in the repository):
#
#   PERF_ROOT    where it keeps its state, builds and runs
#   PERF_JOBS    the host's job registry directory
#   SINGBOX      sing-box on the host (server-accept compares against it)
#   PERF_OWNER   who the registry names as running it
#   MEASURE_AT   when the measurement may start, HH:MM UTC (01:05)
#
# Each night:
#  1. Skip, saying why, if a soak, a build, a measurement or anything
#     exclusive is registered, or a lock it needs is held.
#  2. Build master's sail-cli as shipped for Linux, x86_64 musl with
#     mimalloc, in the release profile without LTO (fat LTO does not fit
#     the host's memory): `new`. Kept by commit, so a commit is built once.
#  3. Measure from MEASURE_AT on cores CLIENT_CPU and SERVER_CPU: `new`
#     against the previous night's build (`base`), and against the pinned
#     reference, the calibration night's build, replaced only by hand
#     (`echo <sha> > $PERF_ROOT/reference`). The first night, with neither,
#     is the calibration: new against itself, the spread is the noise.
#  4. Write status.txt (ran / skipped: why / failed: why) and, when it ran,
#     summary.json and report-*.md; keep the last KEEP runs.
set -uo pipefail

# shellcheck source=/dev/null
. "${PERF_CONFIG:?the settings file of the host}"
: "${PERF_ROOT:?}" "${PERF_JOBS:?}" "${SINGBOX:?}"
OWNER=${PERF_OWNER:-sail tier B}
MEASURE_AT=${MEASURE_AT:-01:05}
CLIENT_CPU=${CLIENT_CPU:-2}
SERVER_CPU=${SERVER_CPU:-3}
export NETEM_NS=${NETEM_NS:-54} NETEM_NET=${NETEM_NET:-90}
SERVER_NAME=${SERVER_NAME:-pf54} SERVER_NET=${SERVER_NET:-92}
ROUNDS=${ROUNDS:-4}
CALIBRATION_ROUNDS=${CALIBRATION_ROUNDS:-6}
MAX_LOAD=${MAX_LOAD:-1.0}
KEEP=${KEEP:-14}
TARGET=x86_64-unknown-linux-musl
PROFILE="x86_64 musl, mimalloc, release profile, lto=false"
JOB=sail-5.4-nightly
# The standing entry that reserves the window; not a job that blocks.
WINDOW=sail-5.4-nightly-window
LOCKS=("netns-nc$NETEM_NS" "netns-ns$NETEM_NS" "netns-${SERVER_NAME}c" "netns-${SERVER_NAME}s")

SRC=$(cd "$(dirname "$0")/../.." && pwd)
STAMP=$(date -u +%Y-%m-%dT%H%MZ)
RUN=$PERF_ROOT/runs/$STAMP
mkdir -p "$RUN" "$PERF_ROOT/bin"
exec >>"$RUN/log" 2>&1

status() {
  echo "$STAMP $*" >"$RUN/status.txt"
  echo "status: $*"
}

# The last KEEP runs; older ones go, so the log does not grow unbounded.
ls -1d "$PERF_ROOT"/runs/*/ 2>/dev/null | sort | head -n -"$KEEP" | xargs -r rm -rf

# A run that dies without saying so still says it started.
status "started"
held_locks=()
cleanup() {
  NETEM_NS=$NETEM_NS NETEM_NET=$NETEM_NET sh "$SRC/scripts/netem/netns.sh" down >/dev/null 2>&1 || true
  for lock in "${held_locks[@]}"; do rm -rf "$PERF_JOBS/locks/$lock"; done
  rm -f "$PERF_JOBS/$JOB"
}
trap cleanup EXIT
trap 'status "failed: stopped (the time limit of the timer, or by hand)"; exit 1' TERM INT

# 1. Anything that needs the host to itself, or that a build or a
# measurement would disturb, registered by another: no run tonight.
others() {
  find "$PERF_JOBS" -maxdepth 1 -type f ! -name README ! -name "$JOB" ! -name "$WINDOW" "$@"
}
busy=$(others -exec grep -l -i -E '^kind: *measurement|exclusive|soak|^mem:.*build' {} + 2>/dev/null || true)
if [ -n "$busy" ]; then
  status "skipped: registered: $(echo "$busy" | xargs -n1 basename | tr '\n' ' ')"
  exit 0
fi
for lock in "${LOCKS[@]}"; do
  if [ -e "$PERF_JOBS/locks/$lock" ]; then
    status "skipped: lock $lock is held by $(cat "$PERF_JOBS/locks/$lock/owner" 2>/dev/null || echo someone)"
    exit 0
  fi
done
for lock in "${LOCKS[@]}"; do
  if mkdir "$PERF_JOBS/locks/$lock" 2>/dev/null; then
    echo "$JOB" >"$PERF_JOBS/locks/$lock/owner"
    held_locks+=("$lock")
  else
    status "skipped: lock $lock was taken as this run claimed it"
    exit 0
  fi
done

register() {
  cat >"$PERF_JOBS/$JOB" <<JOBFILE
owner: $OWNER (5.4 performance regression, tier B, nightly)
kind: $1
what: $2
mem: $3
cores: $4
netns: nc$NETEM_NS/ns$NETEM_NS, ${SERVER_NAME}c/${SERVER_NAME}s; subnets 10.$NETEM_NET-10.$((NETEM_NET + 2)), 10.$SERVER_NET
resources: ${LOCKS[*]}
started: $(date -u '+%Y-%m-%d %H:%M UTC')
expected end: about 01:50 UTC
stop: systemctl stop sail-perf-nightly.service (it releases its locks and removes this file)
JOBFILE
}

# 2. The build: exclusive, as a sail build here is.
NEW=$(git -C "$SRC" rev-parse --short=8 HEAD)
register "build, exclusive" "building sail-cli $NEW ($PROFILE)" "3.7G, build" "0-3"
built() { [ -x "$PERF_ROOT/bin/$1/sail" ]; }
if ! built "$NEW"; then
  echo "building $NEW"
  if ! (cd "$SRC" && scripts/install_cross_toolchain.sh "$TARGET" >/dev/null &&
    CARGO_BUILD_JOBS=4 CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_DIR="$PERF_ROOT/target" \
      scripts/cross.sh "$TARGET" build --locked --release -p sail-cli); then
    status "failed: the build of $NEW failed (see log); no measurement"
    exit 1
  fi
  mkdir -p "$PERF_ROOT/bin/$NEW"
  cp "$PERF_ROOT/target/$TARGET/release/sail" "$PERF_ROOT/bin/$NEW/sail"
fi
# netgen, the load generator, by the hash of its sources.
netgen_hash=$(cd "$SRC/scripts/netem/netgen" && cat ./*.go go.mod go.sum 2>/dev/null | sha256sum | cut -c1-16)
NETGEN=$PERF_ROOT/bin/netgen-$netgen_hash
if [ ! -x "$NETGEN" ]; then
  if ! (cd "$SRC/scripts/netem/netgen" && CGO_ENABLED=0 PATH=/usr/local/go/bin:$PATH go build -o "$NETGEN" .); then
    status "failed: netgen did not build (see log); no measurement"
    exit 1
  fi
fi

# 3. The measurement, from MEASURE_AT, on its cores, with the host quiet.
now=$(date -u +%s)
at=$(date -u -d "today $MEASURE_AT" +%s)
[ "$now" -lt "$at" ] && sleep $((at - now))
register measurement "new $NEW against the previous night and the reference" "800 MB" "$CLIENT_CPU-$SERVER_CPU (taskset)"
load=$(cut -d' ' -f1 /proc/loadavg)
if awk -v l="$load" -v m="$MAX_LOAD" 'BEGIN { exit !(l > m) }'; then
  status "skipped: load $load above $MAX_LOAD at $MEASURE_AT"
  exit 0
fi

BASE=$(cat "$PERF_ROOT/last" 2>/dev/null || true)
REF=$(cat "$PERF_ROOT/reference" 2>/dev/null || true)
if [ -z "$REF" ]; then
  REF=$NEW
  echo "$REF" >"$PERF_ROOT/reference"
fi
built "$BASE" || BASE=$NEW
built "$REF" || REF=$NEW
mkdir -p "$RUN/work"
cp -r "$SRC/scripts/netem" "$SRC/scripts/server-accept" "$RUN/work/"

# One comparison: new against `against`, ROUNDS rounds, in turn, then the
# server budget paired by server-accept; btier.py's layout under $1.
compare() {
  local dir=$1 against=$2 rounds=$3
  mkdir -p "$dir"
  for round in $(seq 1 "$rounds"); do
    order="base new"
    [ $((round % 2)) -eq 0 ] && order="new base"
    for which in $order; do
      local sha=$NEW
      [ "$which" = base ] && sha=$against
      (cd "$RUN/work/netem" && python3 run.py --work "$dir/results/$which/r$round" \
        --sail "$PERF_ROOT/bin/$sha/sail" --netgen "$NETGEN" \
        --protocols direct,trojan --clients sail-mobile,sail-server --only baseline,rate10m \
        --cpus "$CLIENT_CPU" --server-cpus "$SERVER_CPU") || return 1
    done
  done
  (cd "$RUN/work/server-accept" && python3 run.py --work "$dir/results/server" \
    --sail "$PERF_ROOT/bin/$NEW/sail" --sail-base "$PERF_ROOT/bin/$against/sail" \
    --servers sail,sail-base --singbox "$SINGBOX" --netgen "$NETGEN" \
    --protocols ss2022,trojan --shapes idle,bulk --rounds "$rounds" --conns 10000 --rate 1000 \
    --server-cores "$SERVER_CPU" --load-cores "$CLIENT_CPU" --name "$SERVER_NAME" --net "$SERVER_NET") || return 1
}

pairs=()
if [ "$BASE" = "$NEW" ] && [ "$REF" = "$NEW" ]; then
  compare "$RUN/calibration" "$NEW" "$CALIBRATION_ROUNDS" || { status "failed: calibration (see log)"; exit 1; }
  pairs+=(calibration)
else
  if [ "$BASE" != "$NEW" ]; then
    compare "$RUN/previous" "$BASE" "$ROUNDS" || { status "failed: new against previous (see log)"; exit 1; }
    pairs+=(previous)
  fi
  if [ "$REF" != "$BASE" ] && [ "$REF" != "$NEW" ]; then
    compare "$RUN/reference" "$REF" "$ROUNDS" || { status "failed: new against reference (see log)"; exit 1; }
    pairs+=(reference)
  fi
fi
echo "$NEW" >"$PERF_ROOT/last"

# 4. The reports, and what the host was.
verdict=ok
for pair in "${pairs[@]}"; do
  "$SRC/tools/perf/btier.py" "$RUN/$pair" >"$RUN/report-$pair.md" || verdict=regression
done
python3 - "$RUN" "$NEW" "$BASE" "$REF" "$PROFILE" "$verdict" "${pairs[@]}" <<'PY'
import json, subprocess, sys
run, new, base, ref, profile, verdict, *pairs = sys.argv[1:]
swap = subprocess.run(["swapon", "--show=NAME,SIZE", "--noheadings"], capture_output=True, text=True).stdout.split()
json.dump({
    "new": new, "base": base, "reference": ref, "build": profile,
    "pairs": pairs, "verdict": verdict,
    "reports": {p: open(f"{run}/report-{p}.md").read() for p in pairs},
    "host": {"swap": swap, "swappiness": open("/proc/sys/vm/swappiness").read().strip()},
}, open(f"{run}/summary.json", "w"), indent=1)
PY
# What it measured needs no more room than its summaries.
rm -rf "$RUN/work"
for pair in "${pairs[@]}"; do
  find "$RUN/$pair" -type f ! -name summary.json -delete
done
status "ran: new $NEW, base $BASE, reference $REF; ${pairs[*]}; $verdict"
