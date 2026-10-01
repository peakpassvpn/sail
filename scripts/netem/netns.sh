#!/bin/sh
# Two network namespaces joined by a veth pair, for the weak-network tests
# (roadmap 5.5). Everything happens inside them: the host's own namespace,
# routes and firewall are never touched.
#
#   netns.sh up                 create nc5 (client, 10.95.0.1) and ns5 (server, 10.95.0.2)
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
set -eu
C=nc5
S=ns5
CA=10.95.0.1
SA=10.95.0.2
# The traffic tool's server also answers on an address off the link, behind
# the client's default route: a TUN with auto_route takes traffic that uses
# the default route, never a destination the link reaches directly.
FAR=10.96.0.1
# A second path between the two, for the default route to move to.
CA2=10.97.0.1
SA2=10.97.0.2

case "$1" in
up)
  for ns in $C $S; do
    if ip netns list | grep -qw "$ns"; then
      echo "netns $ns exists: another run?" >&2
      exit 1
    fi
  done
  if ip -br addr | grep -qE "10\.9[567]\.0\."; then
    echo "10.95.0.0/24, 10.96.0.0/24 or 10.97.0.0/24 is in use on the host" >&2
    exit 1
  fi
  ip netns add $C
  ip netns add $S
  ip link add nc5v0 type veth peer name ns5v0
  ip link set nc5v0 netns $C
  ip link set ns5v0 netns $S
  ip -n $C addr add $CA/24 dev nc5v0
  ip -n $S addr add $SA/24 dev ns5v0
  for ns in $C $S; do
    ip -n $ns link set lo up
  done
  ip -n $C link set nc5v0 up
  ip -n $S link set ns5v0 up
  ip -n $S addr add $FAR/32 dev lo
  ip -n $C route add default via $SA
  ip link add nc5v1 type veth peer name ns5v1
  ip link set nc5v1 netns $C
  ip link set ns5v1 netns $S
  ip -n $C addr add $CA2/24 dev nc5v1
  ip -n $S addr add $SA2/24 dev ns5v1
  ip -n $C link set nc5v1 up
  ip -n $S link set ns5v1 up
  # netem shapes packets as the stack hands them over: no segmentation
  # offload, so a "packet" is one on the wire.
  ip netns exec $C ethtool -K nc5v0 tso off gso off gro off >/dev/null 2>&1 || true
  ip netns exec $S ethtool -K ns5v0 tso off gso off gro off >/dev/null 2>&1 || true
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
  ip netns exec $C tc qdisc replace dev nc5v0 root netem "$@" $limit
  ip netns exec $S tc qdisc replace dev ns5v0 root netem "$@" $limit
  ;;
clear)
  ip netns exec $C tc qdisc del dev nc5v0 root 2>/dev/null || true
  ip netns exec $S tc qdisc del dev ns5v0 root 2>/dev/null || true
  ;;
blackhole)
  ip netns exec $C tc qdisc replace dev nc5v0 root netem loss 100%
  ip netns exec $S tc qdisc replace dev ns5v0 root netem loss 100%
  ;;
linkdown)
  ip -n $C link set nc5v0 down
  ;;
linkup)
  ip -n $C link set nc5v0 up
  # Taking the link down took the default route with it.
  ip -n $C route replace default via $SA
  ;;
switch)
  ip -n $C route replace default via $SA2 dev nc5v1
  ip -n $C link set nc5v0 down
  ;;
unswitch)
  ip -n $C link set nc5v0 up
  ip -n $C route replace default via $SA dev nc5v0
  ;;
down)
  ip netns del $C 2>/dev/null || true
  ip netns del $S 2>/dev/null || true
  ;;
*)
  echo "usage: netns.sh up|shape SPEC...|clear|blackhole|linkdown|linkup|switch|unswitch|down" >&2
  exit 2
  ;;
esac
