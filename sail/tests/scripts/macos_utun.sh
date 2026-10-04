#!/usr/bin/env bash
# macOS, as root (CI's tun-macos job): a TUN with no interface_name gets
# a free utun chosen at start; auto_route with route_address (IPv4 and
# IPv6, so the utun's own networks of both families are routed too) points
# them through it; a configured name already taken fails the start; a
# kill -9 leaves no utun and no route through it. Routes only test
# prefixes, so the runner's own traffic is untouched: auto_route without
# route_address (the default route) stays unverified here. On macOS sail
# keeps no sweep ledger, so step 3 shows what the kernel removes itself.
set -euo pipefail
SAIL=${SAIL:-target/debug/sail}
W=$(mktemp -d)
# A destination in each routed prefix, and in each of the utun's networks.
V4_ROUTED=198.18.0.1
V6_ROUTED=2001:db8::1
V4_OWN=172.19.0.2
V6_OWN=fdfe:dcba:9876::2

fail() { echo "FAIL: $*"; exit 1; }

# Whatever happens, no sail is left and the logs are shown.
cleanup() {
  sudo -n pkill -9 -f "^$SAIL -c $W/" 2>/dev/null || true
  for log in "$W"/*.log "$W"/*.out; do
    [ -e "$log" ] && { echo "--- $log"; tail -20 "$log"; }
  done
}
trap cleanup EXIT

config() { # extra-fields name
  cat > "$W/$2.json" <<JSON
{ "log": { "level": "debug", "output": "$W/$2.log" },
  "inbounds": [{ "type": "tun", "tag": "tun-in"$1,
                 "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                 "auto_route": true,
                 "route_address": ["198.18.0.0/15", "2001:db8::/32"] }],
  "outbounds": [{ "type": "direct", "tag": "direct" }] }
JSON
}

# The utun the start routed: auto_route logs its routes once they are all
# in, after the utun is up (waiting for "is up" read the routes too soon).
up_name() { # log -> the name the start logged
  for _ in $(seq 1 150); do
    name=$(sed -n 's/.*auto_route: [0-9]* routes into \(utun[0-9]*\).*/\1/p' "$1" 2>/dev/null | head -1)
    [ -n "$name" ] && { echo "$name"; return 0; }
    sleep 0.1
  done
  return 1
}

# sail's own pid, the child of the sudo started as `$1`.
sail_pid() {
  for _ in $(seq 1 50); do
    pid=$(pgrep -P "$1" | head -1)
    [ -n "$pid" ] && { echo "$pid"; return 0; }
    sleep 0.1
  done
  return 1
}

# The interface the system routes `$2` (inet or inet6) through, if any.
via() {
  route -n get -"$1" "$2" 2>/dev/null | sed -n 's/^ *interface: //p'
}

routes_through() { # name: every routed and own destination goes through it
  local name=$1 family dest got
  for pair in "inet $V4_ROUTED" "inet6 $V6_ROUTED" "inet $V4_OWN" "inet6 $V6_OWN"; do
    read -r family dest <<< "$pair"
    got=$(via "$family" "$dest")
    [ "$got" = "$name" ] || fail "$dest goes through '${got:-nothing}', not $name"
    echo "OK: $dest through $name"
  done
}

routes_gone() { # name: none of them goes through it
  local name=$1 family dest got
  for pair in "inet $V4_ROUTED" "inet6 $V6_ROUTED"; do
    read -r family dest <<< "$pair"
    got=$(via "$family" "$dest")
    [ "$got" != "$name" ] || fail "$dest still goes through $name"
  done
  if netstat -rn | grep -qw "$name"; then
    netstat -rn | grep -w "$name"
    fail "routes through $name left"
  fi
  echo "OK: no route through $name"
}

gone() { # pid: waits up to 10 s for it to end
  for _ in $(seq 1 100); do
    sudo -n kill -0 "$1" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

echo "== interfaces before"; ifconfig -l

echo "== 1: no interface_name: a free utun is chosen"
config "" a
sudo -n "$SAIL" -c "$W/a.json" > "$W/a.out" 2>&1 & SUDO_A=$!
NAME=$(up_name "$W/a.log") || fail "no 'auto_route: ... routes into' line"
A=$(sail_pid "$SUDO_A") || fail "no sail under sudo $SUDO_A"
echo "chosen: $NAME (sail pid $A)"
ifconfig "$NAME" >/dev/null || fail "$NAME does not exist"
echo "OK: $NAME exists"
ifconfig "$NAME"
routes_through "$NAME"

echo "== 2: a configured name already taken fails the start"
config ", \"interface_name\": \"$NAME\"" b
set +e
sudo -n "$SAIL" -c "$W/b.json" > "$W/b.out" 2>&1 & SUDO_B=$!
for _ in $(seq 1 100); do kill -0 "$SUDO_B" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SUDO_B" 2>/dev/null; then
  set -e
  fail "the second start still runs after 10 s"
fi
wait "$SUDO_B"; rc=$?
set -e
echo "exit $rc"
grep -h "$NAME" "$W/b.out" "$W/b.log" 2>/dev/null | tail -3 || true
[ "$rc" -ne 0 ] || fail "the second start exited 0"
echo "OK: it failed"

echo "== 3: kill -9 leaves nothing"
sudo -n kill -9 "$A"
gone "$A" || fail "sail $A still runs after kill -9"
wait "$SUDO_A" 2>/dev/null || true
sleep 0.5
if ifconfig "$NAME" >/dev/null 2>&1; then fail "$NAME left"; fi
echo "OK: $NAME gone"
routes_gone "$NAME"

echo "== 4: a second unset start chooses again, and stops cleanly"
config "" c
sudo -n "$SAIL" -c "$W/c.json" > "$W/c.out" 2>&1 & SUDO_C=$!
NAME2=$(up_name "$W/c.log") || fail "no 'auto_route: ... routes into' line on the second start"
C=$(sail_pid "$SUDO_C") || fail "no sail under sudo $SUDO_C"
echo "chosen: $NAME2 (sail pid $C)"
routes_through "$NAME2"
sudo -n kill -TERM "$C"
gone "$C" || fail "sail $C still runs 10 s after SIGTERM"
wait "$SUDO_C" 2>/dev/null || true
if ifconfig "$NAME2" >/dev/null 2>&1; then fail "$NAME2 left after a stop"; fi
routes_gone "$NAME2"
echo "OK: all"

echo "== 5: a route already there for a routed prefix (someone's static route)"
GW=$(route -n get default | sed -n 's/^ *gateway: //p')
sudo -n route -n add -net 198.18.0.0/15 "$GW"
echo "before: 198.18.0.1 through $(via inet 198.18.0.1)"
config "" e
sudo -n "$SAIL" -c "$W/e.json" > "$W/e.out" 2>&1 & SUDO_E=$!
NAME5=$(up_name "$W/e.log") || fail "no 'auto_route: ... routes into' line"
E=$(sail_pid "$SUDO_E") || fail "no sail under sudo $SUDO_E"
echo "while up: 198.18.0.1 through $(via inet 198.18.0.1)"
grep -h "replaced the route" "$W/e.log" || fail "no warning naming the route replaced"
sudo -n kill -TERM "$E"
gone "$E" || fail "sail $E still runs 10 s after SIGTERM"
echo "after stop: 198.18.0.1 through $(via inet 198.18.0.1); the static route: $(netstat -rn -f inet | grep -E '^198\.18' || echo gone)"
sudo -n route -n delete -net 198.18.0.0/15 "$GW" >/dev/null 2>&1 || true
echo "OK: 5 reported"
