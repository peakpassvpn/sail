#!/usr/bin/env bash
# Runs tests/test_network_switch_linux.rs: builds two network namespaces
# joined by two links, starts a server in one, and runs the test in the
# other, where sail runs and the test moves the default route from one link
# to the other. Removes the namespaces again.
#
# Needs root, iproute2 and python3. Everything it changes is inside the
# namespaces it creates; the host's own routing is untouched.
#
#   sudo sail/tests/scripts/network_switch_netns.sh [extra cargo test args]
#
# sail side (nc6)                    server side (ns6)
#   a0 10.94.0.2/24  ------------------  a1 10.94.0.1/24
#   b0 10.93.0.2/24  ------------------  b1 10.93.0.1/24
#   default via 10.94.0.1                lo 10.94.255.1/32: echo on tcp 7101,
#                                        which answers `whoami` with the
#                                        connection's source address

set -euo pipefail

SAIL_NS=nc6
SERVER_NS=ns6

SAIL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

cleanup() {
    # What runs in the namespaces goes with them; a namespace with a process
    # left in it would outlive its deletion.
    for ns in "$SAIL_NS" "$SERVER_NS"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
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

for ns in "$SAIL_NS" "$SERVER_NS"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done

ip link add a0 netns "$SAIL_NS" type veth peer name a1 netns "$SERVER_NS"
ip link add b0 netns "$SAIL_NS" type veth peer name b1 netns "$SERVER_NS"

in_ns "$SAIL_NS" ip addr add 10.94.0.2/24 dev a0
in_ns "$SAIL_NS" ip addr add 10.93.0.2/24 dev b0
in_ns "$SAIL_NS" ip link set a0 up
in_ns "$SAIL_NS" ip link set b0 up
in_ns "$SAIL_NS" ip route add default via 10.94.0.1 dev a0

in_ns "$SERVER_NS" ip addr add 10.94.0.1/24 dev a1
in_ns "$SERVER_NS" ip addr add 10.93.0.1/24 dev b1
in_ns "$SERVER_NS" ip addr add 10.94.255.1/32 dev lo
in_ns "$SERVER_NS" ip link set a1 up
in_ns "$SERVER_NS" ip link set b1 up

in_ns "$SERVER_NS" python3 -c '
import socket, threading

def serve(conn, peer):
    with conn:
        for line in conn.makefile("rb"):
            if line.strip() == b"whoami":
                conn.sendall(peer[0].encode() + b"\n")
            else:
                conn.sendall(line)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.94.255.1", 7101))
server.listen(64)
while True:
    conn, peer = server.accept()
    threading.Thread(target=serve, args=(conn, peer), daemon=True).start()
' &

cd "$SAIL_DIR"
# Built outside the namespaces, where cargo may reach the network.
cargo test -p sail --test test_network_switch_linux --no-run
in_ns "$SAIL_NS" env SAIL_SWITCH_NETNS=1 \
    cargo test --offline -p sail --test test_network_switch_linux "$@" -- --ignored --nocapture
