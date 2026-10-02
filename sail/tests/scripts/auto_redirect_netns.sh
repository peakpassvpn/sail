#!/usr/bin/env bash
# Runs tests/test_auto_redirect_linux.rs: builds two network namespaces, a
# host whose traffic sail takes with a TUN and auto_redirect, and an
# "internet", runs the test in the host's, and removes the namespaces again.
#
# Needs root, iproute2, nftables and python3. Everything it changes is inside
# the namespaces it creates; the host's own routing and firewall are
# untouched.
#
#   sudo sail/tests/scripts/auto_redirect_netns.sh [extra cargo test args]
#
# host (sad-h)                          internet (sad-w)
#   sad-ha 10.233.0.1/24, fd33::1/64  --  sad-wa 10.233.0.2/24, 10.233.0.3/24,
#   default via 10.233.0.2, fd33::2         fd33::2/64
#                                         lo 198.51.100.20-23/32 and
#                                         2001:db8:53::10-11/128: tcp 8080
#                                         answers the peer's address, udp 9999
#                                         echoes; 10.233.0.3 serves the same

set -euo pipefail

HOST=sad-h
NET=sad-w

SAIL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

cleanup() {
    ip netns pids "$NET" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$HOST" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$HOST" 2>/dev/null || true
    ip netns del "$NET" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

in_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@"
}

for ns in "$HOST" "$NET"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done

# Made here and moved, the veth keeps an index of the host's, and the TUN
# sail makes is the namespace's index 2, as the host's first interface
# is: where a TUN in a namespace and the host's DNS meet.
ip link add sad-ha type veth peer name sad-wa
ip link set sad-ha netns "$HOST"
ip link set sad-wa netns "$NET"

in_ns "$HOST" ip addr add 10.233.0.1/24 dev sad-ha
in_ns "$HOST" ip addr add fd33::1/64 dev sad-ha nodad
in_ns "$HOST" ip link set sad-ha up
in_ns "$HOST" ip route add default via 10.233.0.2
in_ns "$HOST" ip -6 route add default via fd33::2

in_ns "$NET" ip addr add 10.233.0.2/24 dev sad-wa
in_ns "$NET" ip addr add 10.233.0.3/24 dev sad-wa
in_ns "$NET" ip addr add fd33::2/64 dev sad-wa nodad
in_ns "$NET" ip link set sad-wa up
for ip in 198.51.100.20 198.51.100.21 198.51.100.22 198.51.100.23; do
    in_ns "$NET" ip addr add "$ip/32" dev lo
done
for ip in 2001:db8:53::10 2001:db8:53::11; do
    in_ns "$NET" ip addr add "$ip/128" dev lo
done

in_ns "$NET" python3 -c '
import socket, threading

def tcp():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", 8080))
    server.listen(64)
    while True:
        conn, peer = server.accept()
        with conn:
            address = peer[0].removeprefix("::ffff:")
            conn.sendall(("peer=" + address + "\n").encode())

threading.Thread(target=tcp, daemon=True).start()

# One socket an address, so that a reply comes from the address it was
# sent to rather than from the one the route back picks.
def udp(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((address, 9999))
    while True:
        data, peer = sock.recvfrom(2048)
        sock.sendto(data, peer)

for address in ("198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23",
                "10.233.0.3", "2001:db8:53::10", "2001:db8:53::11"):
    threading.Thread(target=udp, args=(address,), daemon=True).start()
threading.Event().wait()
' &

cd "$SAIL_DIR"
# Built outside the namespaces, where cargo may reach the network.
cargo build -p sail-cli
cargo test -p sail --test test_auto_redirect_linux --no-run
in_ns "$HOST" env SAIL_BIN="${CARGO_TARGET_DIR:-$SAIL_DIR/../target}/debug/sail" \
    cargo test --offline -p sail --test test_auto_redirect_linux "$@" -- --ignored --nocapture
