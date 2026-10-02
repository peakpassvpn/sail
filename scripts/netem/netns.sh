#!/bin/sh
# Two network namespaces joined by a veth pair, for the weak-network tests
# (roadmap 5.5). Everything happens inside them: the host's own namespace,
# routes and firewall are never touched.
#
#   netns.sh up                 create nc$NS (client, 10.$NET.0.1) and ns$NS (server,
#                               10.$NET.0.2): nc5 and ns5, 10.95.0.0/24 by default
#   netns.sh shape SPEC...      replace the shaping on both ends; SPEC is netem's
#                               own words, applied to each direction, e.g.
#                                 delay 25ms 2.5ms distribution normal
#                                 loss 2%
#                                 loss gemodel 1% 30% 70% 0.1%
#                                 delay 10ms reorder 25% 50%
#                               with "rate 10mbit" it limits the rate too
#   netns.sh clear              no shaping
#   netns.sh blackhole          drop everything, both ways (the link stays up)
#   netns.sh linkdown|linkup    the veth pair down or up
#   netns.sh switch|unswitch    move the client's default route to a second
#                               veth pair and take the first down, as a
#                               phone leaving Wi-Fi for cellular; and back
#   netns.sh down               delete both namespaces
#
# On a shared host whose jobs claim named resources by creating a directory
# (mkdir is atomic), NETEM_LOCK_DIR names where: `up` claims
# $NETEM_LOCK_DIR/netns-nc$NS and .../netns-ns$NS before it creates
# anything, writing NETEM_LOCK_OWNER (default "netem") into each one's
# owner file, and fails if either is held; `down` releases the claims it
# owns.
set -eu
# Which pair: NETEM_NS names the namespaces nc$NS and ns$NS (default 5),
# NETEM_NET the three /24s 10.$NET-10.$((NET+2)) they use (default 95), so
# that two runs side by side take pairs of their own. run.py reads the same.
NS=${NETEM_NS:-5}
NET=${NETEM_NET:-95}
# Digits without a leading zero: sh reads 095 as octal, and nc05 is not nc5.
case $NS in
  [1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
  *) echo "NETEM_NS: 1 to 999, no leading zero, not '$NS'" >&2; exit 2 ;;
esac
case $NET in
  [1-9] | [1-9][0-9] | [1-9][0-9][0-9]) ;;
  *) echo "NETEM_NET: 1 to 253, no leading zero, not '$NET'" >&2; exit 2 ;;
esac
if [ "$NET" -lt 1 ] || [ "$NET" -gt 253 ]; then
  echo "NETEM_NET: 1 to 253, so that 10.$NET-10.$((NET + 2)) are addresses" >&2
  exit 2
fi
C=nc$NS
S=ns$NS
CV0=nc${NS}v0
SV0=ns${NS}v0
CV1=nc${NS}v1
SV1=ns${NS}v1
NET1=$((NET + 1))
NET2=$((NET + 2))
CA=10.$NET.0.1
SA=10.$NET.0.2
# The traffic tool's server also answers on an address off the link, behind
# the client's default route: a TUN with auto_route takes traffic that uses
# the default route, never a destination the link reaches directly.
FAR=10.$NET1.0.1
# A second path between the two, for the default route to move to.
CA2=10.$NET2.0.1
SA2=10.$NET2.0.2

LOCKS=${NETEM_LOCK_DIR:-}
OWNER=${NETEM_LOCK_OWNER:-netem}

# Claims the lock of each namespace, or none: one held by another is left.
claim() {
  [ -n "$LOCKS" ] || return 0
  mkdir -p "$LOCKS"
  taken=""
  for ns in $C $S; do
    if mkdir "$LOCKS/netns-$ns" 2>/dev/null; then
      echo "$OWNER" > "$LOCKS/netns-$ns/owner"
      taken="$taken $ns"
    else
      echo "netns $ns is claimed by $(cat "$LOCKS/netns-$ns/owner" 2>/dev/null || echo '?')" >&2
      for t in $taken; do rm -rf "$LOCKS/netns-$t"; done
      exit 1
    fi
  done
}

# Releases the claims this owner holds.
release() {
  [ -n "$LOCKS" ] || return 0
  for ns in $C $S; do
    if [ "$(cat "$LOCKS/netns-$ns/owner" 2>/dev/null)" = "$OWNER" ]; then
      rm -rf "$LOCKS/netns-$ns"
    fi
  done
}

case "$1" in
up)
  claim
  # Whatever stops it from here gives the claims back.
  trap release EXIT
  for ns in $C $S; do
    if ip netns list | grep -qw "$ns"; then
      echo "netns $ns exists: another run?" >&2
      exit 1
    fi
  done
  if ip -br addr | grep -qE "(^|[^0-9])10\.($NET|$NET1|$NET2)\.0\."; then
    echo "10.$NET.0.0/24, 10.$NET1.0.0/24 or 10.$NET2.0.0/24 is in use on the host" >&2
    exit 1
  fi
  ip netns add $C
  ip netns add $S
  ip link add $CV0 type veth peer name $SV0
  ip link set $CV0 netns $C
  ip link set $SV0 netns $S
  ip -n $C addr add $CA/24 dev $CV0
  ip -n $S addr add $SA/24 dev $SV0
  for ns in $C $S; do
    ip -n $ns link set lo up
  done
  ip -n $C link set $CV0 up
  ip -n $S link set $SV0 up
  ip -n $S addr add $FAR/32 dev lo
  ip -n $C route add default via $SA
  ip link add $CV1 type veth peer name $SV1
  ip link set $CV1 netns $C
  ip link set $SV1 netns $S
  ip -n $C addr add $CA2/24 dev $CV1
  ip -n $S addr add $SA2/24 dev $SV1
  ip -n $C link set $CV1 up
  ip -n $S link set $SV1 up
  # netem shapes packets as the stack hands them over: no segmentation
  # offload, so a "packet" is one on the wire.
  ip netns exec $C ethtool -K $CV0 tso off gso off gro off >/dev/null 2>&1 || true
  ip netns exec $S ethtool -K $SV0 tso off gso off gro off >/dev/null 2>&1 || true
  trap - EXIT
  ;;
shape)
  shift
  # Without a limit of its own, the queue holds whatever the delay keeps
  # in flight; a rate-limited link names its own, or it would buffer
  # minutes of traffic.
  case " $* " in
    *" limit "*) limit= ;;
    *) limit="limit 100000" ;;
  esac
  ip netns exec $C tc qdisc replace dev $CV0 root netem "$@" $limit
  ip netns exec $S tc qdisc replace dev $SV0 root netem "$@" $limit
  ;;
clear)
  ip netns exec $C tc qdisc del dev $CV0 root 2>/dev/null || true
  ip netns exec $S tc qdisc del dev $SV0 root 2>/dev/null || true
  ;;
blackhole)
  ip netns exec $C tc qdisc replace dev $CV0 root netem loss 100%
  ip netns exec $S tc qdisc replace dev $SV0 root netem loss 100%
  ;;
linkdown)
  ip -n $C link set $CV0 down
  ;;
linkup)
  ip -n $C link set $CV0 up
  # Taking the link down took the default route with it.
  ip -n $C route replace default via $SA
  ;;
switch)
  ip -n $C route replace default via $SA2 dev $CV1
  ip -n $C link set $CV0 down
  ;;
unswitch)
  ip -n $C link set $CV0 up
  ip -n $C route replace default via $SA dev $CV0
  ;;
down)
  ip netns del $C 2>/dev/null || true
  ip netns del $S 2>/dev/null || true
  release
  ;;
*)
  echo "usage: netns.sh up|shape SPEC...|clear|blackhole|linkdown|linkup|switch|unswitch|down" >&2
  exit 2
  ;;
esac
