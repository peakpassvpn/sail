#!/usr/bin/env bash
# macOS, as root (CI's tun-macos job): a desktop's TUN config, which takes
# the runner's own traffic. auto_route and strict_route with no
# route_address, and these left out: a server's public address (1.1.1.1
# stands in for it), multicast, broadcast and link-local, of both families.
# A watchdog kills sail after 60 s whatever happens, so a runner that loses
# its connection gets it back.
set -uo pipefail
SAIL=${SAIL:-target/debug/sail}
W=$(mktemp -d)
EXCLUDED=1.1.1.1
THROUGH=1.0.0.1

fail() { echo "FAIL: $*"; exit 1; }
cleanup() {
  sudo -n pkill -9 -f "^$SAIL -c $W/" 2>/dev/null || true
  for log in "$W"/*.log "$W"/*.out; do
    [ -e "$log" ] && { echo "--- $log"; tail -30 "$log"; }
  done
}
trap cleanup EXIT

table() { # the routing table of both families, without the host routes
  # the system clones and expires on its own (flag W)
  for family in inet inet6; do
    netstat -rn -f "$family" | awk 'NR > 3 && $3 !~ /W/'
  done | sort
}

cat > "$W/d.json" <<JSON
{ "log": { "level": "debug", "output": "$W/d.log" },
  "inbounds": [{ "type": "tun", "tag": "tun-in",
                 "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                 "auto_route": true, "strict_route": true,
                 "route_exclude_address": ["$EXCLUDED/32", "224.0.0.0/4",
                   "255.255.255.255/32", "169.254.0.0/16", "fe80::/10", "ff00::/8"] }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "auto_detect_interface": true, "final": "direct" } }
JSON

via() { route -n get -"$1" "$2" 2>/dev/null | sed -n 's/^ *interface: //p'; }

# The utun the start routed: auto_route logs its routes once they are all
# in, after the utun is up (waiting for "is up" read the routes too soon).
up_name() {
  for _ in $(seq 1 150); do
    name=$(sed -n 's/.*auto_route: [0-9]* routes into \(utun[0-9]*\).*/\1/p' "$1" 2>/dev/null | head -1)
    [ -n "$name" ] && { echo "$name"; return 0; }
    sleep 0.1
  done
  return 1
}

run_once() { # how it ends: TERM or KILL
  local how=$1 before after name pid phys
  before=$(table)
  phys=$(via inet "$THROUGH")
  echo "physical: $phys; IPv6 default: $(via inet6 2001:4860:4860::8888 || true)"
  : > "$W/d.log"
  # The watchdog first: whatever happens, sail is gone in 60 s.
  (sleep 60; sudo -n pkill -9 -f "^$SAIL -c $W/") & watchdog=$!
  sudo -n "$SAIL" -c "$W/d.json" > "$W/d.out" 2>&1 &
  name=$(up_name "$W/d.log") || fail "no 'auto_route: ... routes into' line"
  pid=$(pgrep -f "^$SAIL -c $W/d.json" | head -1)
  sleep 1
  echo "== up as $name; the table now, against before:"
  diff <(echo "$before") <(table)
  local got
  got=$(via inet 8.8.8.8); echo "8.8.8.8 through: $got"
  [ "$got" = "$name" ] || echo "FAIL: the default does not go through $name"
  got=$(via inet "$EXCLUDED"); echo "$EXCLUDED (excluded) through: $got"
  [ "$got" != "$name" ] || echo "FAIL: an excluded address goes through $name"
  got=$(via inet6 2001:db8::1); echo "2001:db8::1 through: ${got:-nothing}"
  got=$(via inet6 fe80::1%"$phys"); echo "fe80::1 (excluded) through: ${got:-nothing}"
  code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "https://$THROUGH/" 2>&1)
  echo "curl https://$THROUGH: $code"
  grep -c "$THROUGH" "$W/d.log" | sed 's/^/log lines naming '"$THROUGH"': /'
  code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "https://$EXCLUDED/" 2>&1)
  echo "curl https://$EXCLUDED (excluded): $code"
  grep -c "$EXCLUDED:443" "$W/d.log" | sed 's/^/log lines naming '"$EXCLUDED"':443 (want 0): /'
  echo "== $how"
  sudo -n kill -"$how" "$pid"
  for _ in $(seq 1 100); do sudo -n kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill "$watchdog" 2>/dev/null
  sleep 1
  after=$(table)
  if [ "$after" = "$before" ]; then
    echo "OK: after $how the table equals the one before"
  else
    echo "FAIL: after $how the table differs:"
    diff <(echo "$before") <(echo "$after")
  fi
}

run_once TERM
run_once KILL
