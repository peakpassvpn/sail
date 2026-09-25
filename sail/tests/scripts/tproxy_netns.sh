#!/usr/bin/env bash
# Runs tests/test_tproxy_linux.rs: builds three network namespaces, a client,
# a router that runs sail with nftables REDIRECT and TPROXY rules, and a
# server, runs the tests in the router's, and removes the namespaces again.
#
# Needs root, iproute2, and nft or iptables. Everything it changes is inside the
# namespaces it creates; the host's own firewall and routing are untouched.
#
#   sudo sail/tests/scripts/tproxy_netns.sh [extra cargo test args]
#
# client  c0 10.33.1.2/24 fd33:1::2/64
#   |
# router  r0 10.33.1.1/24 fd33:1::1/64    sail: redirect :33201, tproxy :33202
#         r1 10.33.2.1/24 fd33:2::1/64
#   |
# server  s0 10.33.2.2/24 fd33:2::2/64    echo on tcp 33220, 33230, udp 33231

set -euo pipefail

CLIENT=sailtp-client
ROUTER=sailtp-router
SERVER=sailtp-server

SAIL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

cleanup() {
    for ns in "$CLIENT" "$ROUTER" "$SERVER"; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap cleanup EXIT
cleanup

in_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@"
}

for ns in "$CLIENT" "$ROUTER" "$SERVER"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done

ip link add c0 netns "$CLIENT" type veth peer name r0 netns "$ROUTER"
ip link add s0 netns "$SERVER" type veth peer name r1 netns "$ROUTER"

in_ns "$CLIENT" ip addr add 10.33.1.2/24 dev c0
in_ns "$CLIENT" ip addr add fd33:1::2/64 dev c0 nodad
in_ns "$CLIENT" ip link set c0 up
in_ns "$CLIENT" ip route add default via 10.33.1.1
in_ns "$CLIENT" ip -6 route add default via fd33:1::1

in_ns "$SERVER" ip addr add 10.33.2.2/24 dev s0
in_ns "$SERVER" ip addr add fd33:2::2/64 dev s0 nodad
in_ns "$SERVER" ip link set s0 up
in_ns "$SERVER" ip route add default via 10.33.2.1
in_ns "$SERVER" ip -6 route add default via fd33:2::1

in_ns "$ROUTER" ip addr add 10.33.1.1/24 dev r0
in_ns "$ROUTER" ip addr add fd33:1::1/64 dev r0 nodad
in_ns "$ROUTER" ip addr add 10.33.2.1/24 dev r1
in_ns "$ROUTER" ip addr add fd33:2::1/64 dev r1 nodad
in_ns "$ROUTER" ip link set r0 up
in_ns "$ROUTER" ip link set r1 up
in_ns "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
in_ns "$ROUTER" sysctl -qw net.ipv6.conf.all.forwarding=1
# Marked packets arrive for addresses routed elsewhere; strict reverse path
# filtering would drop them.
in_ns "$ROUTER" sysctl -qw net.ipv4.conf.all.rp_filter=0
in_ns "$ROUTER" sysctl -qw net.ipv4.conf.r0.rp_filter=0

# Packets TPROXY marks are delivered locally, to the socket it picked,
# rather than forwarded.
in_ns "$ROUTER" ip rule add fwmark 1 lookup 100
in_ns "$ROUTER" ip route add local 0.0.0.0/0 dev lo table 100
in_ns "$ROUTER" ip -6 rule add fwmark 1 lookup 100
in_ns "$ROUTER" ip -6 route add local ::/0 dev lo table 100

# The same rules with nft, or iptables where there is none.
if command -v nft >/dev/null; then
    in_ns "$ROUTER" nft -f - <<'EOF'
table inet sailtp {
    chain redirect {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "r0" tcp dport 33220 redirect to :33201
    }
    chain tproxy {
        type filter hook prerouting priority mangle; policy accept;
        iifname "r0" meta nfproto ipv4 tcp dport 33230 meta mark set 1 tproxy ip to :33202 accept
        iifname "r0" meta nfproto ipv4 udp dport 33231 meta mark set 1 tproxy ip to :33202 accept
        iifname "r0" meta nfproto ipv6 tcp dport 33230 meta mark set 1 tproxy ip6 to :33202 accept
        iifname "r0" meta nfproto ipv6 udp dport 33231 meta mark set 1 tproxy ip6 to :33202 accept
    }
}
EOF
else
    for ipt in iptables ip6tables; do
        in_ns "$ROUTER" "$ipt" -t nat -A PREROUTING -i r0 -p tcp --dport 33220 \
            -j REDIRECT --to-ports 33201
        in_ns "$ROUTER" "$ipt" -t mangle -A PREROUTING -i r0 -p tcp --dport 33230 \
            -j TPROXY --on-port 33202 --tproxy-mark 1
        in_ns "$ROUTER" "$ipt" -t mangle -A PREROUTING -i r0 -p udp --dport 33231 \
            -j TPROXY --on-port 33202 --tproxy-mark 1
    done
fi

cd "$SAIL_DIR"
# Built outside the namespaces, where cargo may reach the network.
cargo test -p sail --test test_tproxy_linux --no-run
in_ns "$ROUTER" env \
    SAILTP_CLIENT_NS="/var/run/netns/$CLIENT" \
    SAILTP_SERVER_NS="/var/run/netns/$SERVER" \
    cargo test --offline -p sail --test test_tproxy_linux "$@" -- --ignored --nocapture
