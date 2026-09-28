#!/bin/bash
# auto_redirect end to end (Linux, root; needs socat and curl), in network
# namespaces of its own, leaving the host's network alone:
#   sar-a: runs sail with a TUN and auto_redirect; the "host" whose traffic is taken
#   sar-w: the "internet", 10.231.0.2-5 on a veth, with TCP and UDP servers
set -u
SAIL=${SAIL:-target/debug/sail}
DIR=${DIR:-/tmp/sail-ar-e2e}
mkdir -p $DIR
cleanup() {
  [ -n "${SAILPID:-}" ] && kill $SAILPID 2>/dev/null && sleep 1
  ip netns pids sar-w 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns pids sar-a 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del sar-a 2>/dev/null
  ip netns del sar-w 2>/dev/null
}
cleanup
ip netns add sar-a
ip netns add sar-w
ip link add sar-va type veth peer name sar-vw
ip link set sar-va netns sar-a
ip link set sar-vw netns sar-w
A="ip netns exec sar-a"
W="ip netns exec sar-w"
$A ip link set lo up
$W ip link set lo up
$A ip addr add 10.231.0.1/24 dev sar-va
$A ip link set sar-va up
for i in 2 3 4 5; do $W ip addr add 10.231.0.$i/24 dev sar-vw; done
$W ip link set sar-vw up
# A "public" server outside the LAN subnet, so auto_redirect takes it.
$W ip addr add 198.51.100.10/32 dev sar-vw
$W ip addr add 198.51.100.11/32 dev sar-vw
$W ip addr add 198.51.100.12/32 dev sar-vw
$W ip addr add 198.51.100.13/32 dev sar-vw
$A ip route add default via 10.231.0.2
$A ip addr add fd31::1/64 dev sar-va nodad
$W ip addr add fd31::2/64 dev sar-vw nodad
$W ip addr add 2001:db8:51::10/128 dev sar-vw nodad
$A ip -6 route add default via fd31::2
$W ip route add default dev sar-vw

# Servers in sar-w: TCP says who it saw, UDP echoes.
$W socat TCP6-LISTEN:8080,fork,reuseaddr,ipv6only=0 SYSTEM:'echo "peer=$SOCAT_PEERADDR"' &
for ip in 198.51.100.10 198.51.100.11; do
  $W socat UDP-RECVFROM:9999,bind=$ip,fork SYSTEM:'cat' &
done
sleep 0.5

cat > $DIR/config.json <<'EOF'
{
  "log": { "level": "debug", "output": "SAIL_LOG" },
  "inbounds": [{
    "type": "tun", "tag": "tun-in", "interface_name": "sartun",
    "address": ["172.31.231.1/30", "fdfe:231::1/126"],
    "auto_route": true, "auto_redirect": true
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": {
    "rules": [
      { "ip_cidr": ["198.51.100.11/32"], "action": "bypass" },
      { "ip_cidr": ["198.51.100.12/32"], "action": "reject" }
    ],
    "final": "direct"
  }
}
EOF
sed -i "s#SAIL_LOG#$DIR/sail.log#" $DIR/config.json
: > $DIR/sail.log
$A $SAIL -c $DIR/config.json > $DIR/sail.out 2>&1 &
SAILPID=$!
sleep 3

fail=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

echo "--- rules"; $A ip rule | grep -E "^(9000|9001|9002|32768)"
echo "--- table 2022"; $A ip route show table 2022

out=$($A curl -s -m 5 http://198.51.100.10:8080/ 2>&1; $A socat -T3 - TCP:198.51.100.10:8080 </dev/null 2>&1)
echo "tcp proxied: $out"
check "tcp redirected reaches the server" '[[ "$out" == *ffff:0ae7:0001* ]]'
check "tcp redirected went through sail" 'grep -q "198.51.100.10:8080" $DIR/sail.log'

out=$($A socat -T3 - TCP:198.51.100.11:8080 </dev/null 2>&1)
echo "tcp bypassed: $out"
check "tcp bypassed reaches the server" '[[ "$out" == *ffff:0ae7:0001* ]]'
check "tcp bypassed never reached sail's dispatcher" '! grep -v "pre-match\|prematch" $DIR/sail.log | grep -q "198.51.100.11:8080"'

out=$(timeout 1 $A socat -T3 - TCP:198.51.100.12:8080 </dev/null 2>&1)
echo "tcp rejected: $out"
check "tcp rejected is refused at once" '[[ "$out" == *"Connection refused"* ]]'

out=$(echo ping-udp | $A socat -T3 - UDP:198.51.100.10:9999 2>&1)
echo "udp proxied: $out"
check "udp through the tun echoes" '[[ "$out" == ping-udp ]]'
check "udp went through sail" 'grep -q "198.51.100.10:9999" $DIR/sail.log'

out=$(echo ping-udp2 | $A socat -T3 - UDP:198.51.100.11:9999 2>&1)
echo "udp bypassed: $out"
check "udp bypassed echoes" '[[ "$out" == ping-udp2 ]]'
check "udp bypassed never reached sail's dispatcher" '! grep -q "198.51.100.11:9999" $DIR/sail.log'

out=$($A socat -T3 - TCP6:[2001:db8:51::10]:8080 </dev/null 2>&1)
echo "tcp6 proxied: $out"
check "tcp over IPv6 is redirected" '[[ "$out" == *fd31:0000:0000:0000:0000:0000:0000:0001* ]] && grep -q "2001:db8:51::10" $DIR/sail.log'

out=$($A socat -T3 - TCP:10.231.0.3:8080 </dev/null 2>&1)
check "the LAN subnet is left alone" '[[ "$out" == *ffff:0ae7:0001* ]] && ! grep -q "10.231.0.3:8080" $DIR/sail.log'

# A new address on an interface joins the local set.
$A ip addr add 192.0.2.1/24 dev sar-va
sleep 1
check "a new address joins the local set" 'grep -q "local addresses now.*192.0.2.0" $DIR/sail.log'

kill $SAILPID; wait $SAILPID 2>/dev/null; SAILPID=
sleep 0.5
out=$($A socat -T3 - TCP:198.51.100.10:8080 </dev/null 2>&1)
check "stopping removes the table: TCP goes direct" '[[ "$out" == *ffff:0ae7:0001* ]]'
check "stopping removes the rules" '! $A ip rule | grep -qE "^(9000|9001|9002|32768):"'
tail -5 $DIR/sail.out

# A reload that changes the rule-set of route_address_set refills the set.
reload_config() {
  cat > $DIR/reload.json.tmp <<EOF
{
  "log": { "level": "debug", "output": "$DIR/sail.log" },
  "inbounds": [{
    "type": "tun", "tag": "tun-in", "interface_name": "sartun",
    "address": ["172.31.231.1/30"],
    "auto_route": true, "auto_redirect": true,
    "route_address_set": ["taken"]
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "rule_set": [$1], "final": "direct" }
}
EOF
  mv $DIR/reload.json.tmp $DIR/reload.json
}
taken() { echo '{ "type": "inline", "tag": "taken", "rules": [{ "ip_cidr": ["'$1'"] }] }'; }
# Whether a connection to $1 made now shows in the log after line $2.
through_sail() {
  $A socat -T3 - TCP:$1:8080 </dev/null >/dev/null 2>&1
  sleep 0.3
  tail -n +$(( $2 + 1 )) $DIR/sail.log | grep -q "dst=$1:8080"
}
mark() { wc -l < $DIR/sail.log; }
reloads() { grep -c "reloaded from config file" $DIR/sail.log; }
wait_reload() {
  for _ in $(seq 50); do
    [ "$(reloads)" -gt "$1" ] && return 0
    sleep 0.1
  done
  return 1
}

reload_config "$(taken 198.51.100.10/32)"
: > $DIR/sail.log
$A $SAIL -c $DIR/reload.json --auto-reload > $DIR/sail-reload.out 2>&1 &
SAILPID=$!
sleep 3
check "route_address_set takes its rule-set's addresses" 'through_sail 198.51.100.10 $(mark)'
check "route_address_set leaves the others" '! through_sail 198.51.100.13 $(mark)'
n=$(reloads)
reload_config "$(taken 198.51.100.13/32)"
check "the reload happened" 'wait_reload $n'
sleep 0.5
check "after a reload, the new rule-set's addresses are taken" 'through_sail 198.51.100.13 $(mark)'
check "after a reload, the old ones are not" '! through_sail 198.51.100.10 $(mark)'
# A reload without the rule-set the TUN names fails, and changes nothing.
reload_config ""
sleep 2
check "a reload without the rule-set fails" 'grep -q "route_address_set" $DIR/sail.log && [ "$(reloads)" -eq "$((n + 1))" ]'
check "a failed reload keeps the sets" 'through_sail 198.51.100.13 $(mark)'
kill $SAILPID; wait $SAILPID 2>/dev/null; SAILPID=
cleanup
exit $fail
