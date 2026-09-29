#!/bin/bash
# auto_route on Linux, without auto_redirect, end to end (root; needs socat
# and curl), in network namespaces of its own, leaving the host alone:
#   sar-r: runs sail with a TUN and auto_route; the "host" whose traffic is taken
#   sar-w: the "internet" behind two uplinks, with TCP and UDP servers
set -u
SAIL=${SAIL:-target/debug/sail}
DIR=${DIR:-/tmp/sail-ar-route}
mkdir -p $DIR
A="ip netns exec sar-r"
W="ip netns exec sar-w"
cleanup() {
  [ -n "${SAILPID:-}" ] && kill $SAILPID 2>/dev/null && sleep 1
  ip netns pids sar-w 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids sar-r 2>/dev/null | xargs -r kill -9 2>/dev/null
  ip netns del sar-r 2>/dev/null
  ip netns del sar-w 2>/dev/null
}
cleanup
ip netns add sar-r
ip netns add sar-w
# Two uplinks: the default route moves from the first to the second.
ip link add sar-ra type veth peer name sar-wa
ip link add sar-rb type veth peer name sar-wb
ip link set sar-ra netns sar-r
ip link set sar-rb netns sar-r
ip link set sar-wa netns sar-w
ip link set sar-wb netns sar-w
$A ip link set lo up
$W ip link set lo up
$A ip addr add 10.241.0.1/24 dev sar-ra
$A ip addr add 10.242.0.1/24 dev sar-rb
$A ip link set sar-ra up
$A ip link set sar-rb up
$W ip addr add 10.241.0.2/24 dev sar-wa
$W ip addr add 10.241.0.3/24 dev sar-wa
$W ip addr add 10.242.0.2/24 dev sar-wb
$W ip link set sar-wa up
$W ip link set sar-wb up
for ip in 198.51.100.10 198.51.100.11; do $W ip addr add $ip/32 dev lo; done
$A ip route add default via 10.241.0.2

$W socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo "peer=$SOCAT_PEERADDR"' &
$W socat UDP-RECVFROM:9999,bind=198.51.100.10,fork SYSTEM:'cat' &
sleep 0.5

# $1: more tun fields.
write_config() {
  cat > $DIR/config.json <<EOF
{
  "log": { "level": "debug", "output": "$DIR/sail.log" },
  "inbounds": [{
    "type": "tun", "tag": "tun-in", "interface_name": "sartun",
    "address": ["172.31.241.1/30"],
    "auto_route": true, "strict_route": true$1
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
EOF
}
write_config ""
start_sail() {
  : > $DIR/sail.log
  $A $SAIL -c $DIR/config.json > $DIR/sail.out 2>&1 &
  SAILPID=$!
  sleep 3
}
fail=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
mark() { wc -l < $DIR/sail.log; }
# Whether the log after line $2 names the destination $1.
logged() { tail -n +$(( $2 + 1 )) $DIR/sail.log | grep -q "dst=$1"; }
tcp() { $A socat -T3 - TCP:$1:8080 </dev/null 2>&1; }

start_sail
echo "--- rules"; $A ip rule | grep -E "^90(0[0-9]|10):"
echo "--- v6 rules"; $A ip -6 rule | grep -E "^90(0[0-9]|10):"
echo "--- table 2022"; $A ip route show table 2022

m=$(mark); out=$(tcp 198.51.100.10)
echo "tcp: $out"
check "tcp goes through sail and out of the uplink" '[[ "$out" == *peer=10.241.0.1* ]] && logged 198.51.100.10:8080 $m'
check "auto_detect_interface was implied" 'grep -q "outbound traffic goes through sar-ra" $DIR/sail.log'

m=$(mark); out=$(echo ping-udp | $A socat -T3 - UDP:198.51.100.10:9999 2>&1)
check "udp goes through sail" '[[ "$out" == ping-udp ]] && logged 198.51.100.10:9999 $m'

# With all addresses routed, the main table's own routes (the LAN) win.
m=$(mark); out=$(tcp 10.241.0.3)
check "the LAN goes past sail" '[[ "$out" == *peer=10.241.0.1* ]] && ! logged 10.241.0.3:8080 $m'

check "strict_route makes the missing IPv6 unreachable" '$A ip -6 rule | grep -q "unreachable"'

# The default route moves to the second uplink: sail's own traffic follows.
$A ip route replace default via 10.242.0.2 dev sar-rb
sleep 2.5
m=$(mark); out=$(tcp 198.51.100.10)
echo "tcp after the move: $out"
check "sail follows the default interface" '[[ "$out" == *peer=10.242.0.1* ]] && logged 198.51.100.10:8080 $m'
$A ip route replace default via 10.241.0.2 dev sar-ra
sleep 2.5

kill $SAILPID; wait $SAILPID 2>/dev/null; SAILPID=
sleep 0.5
check "stopping removes the rules" '! $A ip rule | grep -qE "^90(0[0-9]|10):"'
check "stopping empties the table" '[ -z "$($A ip route show table 2022)" ]'
check "and traffic goes direct" '[[ "$(tcp 198.51.100.10)" == *peer=10.241.0.1* ]]'

# A run that dies leaves its rules, which route nothing; the next start
# replaces them. From here, some addresses are left out.
write_config ', "route_exclude_address": ["198.51.100.11/32"]'
start_sail
kill -9 $SAILPID; wait $SAILPID 2>/dev/null; SAILPID=
sleep 0.5
check "after a crash, traffic still goes direct" '[[ "$(tcp 198.51.100.10)" == *peer=10.241.0.1* ]]'
before=$($A ip rule | grep -cE "^90(0[0-9]|10):")
start_sail
after=$($A ip rule | grep -cE "^90(0[0-9]|10):")
echo "rules left by the crash: $before, after the restart: $after"
check "a restart replaces what a crash left" '[ "$after" -gt 0 ] && [ "$after" -eq "$(( before ))" ]'
m=$(mark); out=$(tcp 198.51.100.10)
check "and routes again" '[[ "$out" == *peer=10.241.0.1* ]] && logged 198.51.100.10:8080 $m'
m=$(mark); out=$(tcp 198.51.100.11)
check "route_exclude_address goes past sail" '[[ "$out" == *peer=10.241.0.1* ]] && ! logged 198.51.100.11:8080 $m'
kill $SAILPID; wait $SAILPID 2>/dev/null; SAILPID=

tail -3 $DIR/sail.out
cleanup
exit $fail
