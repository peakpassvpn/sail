#!/usr/bin/env bash
# Runs tests/test_auto_route_linux.rs: builds two network namespaces, a host
# whose traffic sail takes with a TUN and auto_route, and an "internet"
# behind two uplinks, runs the test in the host's, and removes the
# namespaces again.
#
# Needs root, iproute2 and python3. Everything it changes is inside the
# namespaces it creates; the host's own routing is untouched.
#
#   sudo sail/tests/scripts/auto_route_netns.sh [extra cargo test args]
#
# host (sar-r)                       internet (sar-w)
#   sar-ra 10.241.0.1/24  ----------   sar-wa 10.241.0.2/24, 10.241.0.3/24
#   sar-rb 10.242.0.1/24  ----------   sar-wb 10.242.0.2/24
#   default via 10.241.0.2             lo 198.51.100.10-12/32: tcp 8080 answers
#                                      the peer's address, udp 9999 echoes;
#                                      10.241.0.3 serves the same

set -euo pipefail

HOST=sar-r
NET=sar-w

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

ip link add sar-ra netns "$HOST" type veth peer name sar-wa netns "$NET"
ip link add sar-rb netns "$HOST" type veth peer name sar-wb netns "$NET"

in_ns "$HOST" ip addr add 10.241.0.1/24 dev sar-ra
in_ns "$HOST" ip addr add 10.242.0.1/24 dev sar-rb
in_ns "$HOST" ip link set sar-ra up
in_ns "$HOST" ip link set sar-rb up
in_ns "$HOST" ip route add default via 10.241.0.2

in_ns "$NET" ip addr add 10.241.0.2/24 dev sar-wa
in_ns "$NET" ip addr add 10.241.0.3/24 dev sar-wa
in_ns "$NET" ip addr add 10.242.0.2/24 dev sar-wb
in_ns "$NET" ip link set sar-wa up
in_ns "$NET" ip link set sar-wb up
for ip in 198.51.100.10 198.51.100.11 198.51.100.12; do
    in_ns "$NET" ip addr add "$ip/32" dev lo
done

in_ns "$NET" python3 -c '
import socket, threading

def tcp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8080))
    server.listen(64)
    while True:
        conn, peer = server.accept()
        with conn:
            conn.sendall(("peer=" + peer[0] + "\n").encode())

threading.Thread(target=tcp, daemon=True).start()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", 9999))
while True:
    data, peer = udp.recvfrom(2048)
    udp.sendto(data, peer)
' &

cd "$SAIL_DIR"
# Built outside the namespaces, where cargo may reach the network.
cargo build -p sail-cli
cargo test -p sail --test test_auto_route_linux --no-run
in_ns "$HOST" env SAIL_BIN="${CARGO_TARGET_DIR:-$SAIL_DIR/../target}/debug/sail" \
    cargo test --offline -p sail --test test_auto_route_linux "$@" -- --ignored --nocapture
