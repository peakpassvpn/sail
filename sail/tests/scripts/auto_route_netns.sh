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
#                                      10.241.0.3 serves the same;
#                                      lo 198.51.100.53/32: udp and tcp 53
#                                      answer every A query with
#                                      198.51.100.10
#
# The host's /etc/resolv.conf, as `ip netns exec` mounts it from
# /etc/netns/sar-r, names 198.51.100.53.

set -euo pipefail

HOST=sar-r
NET=sar-w

SAIL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

cleanup() {
    ip netns pids "$NET" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$HOST" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$HOST" 2>/dev/null || true
    ip netns del "$NET" 2>/dev/null || true
    rm -rf "/etc/netns/$HOST"
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
for ip in 198.51.100.10 198.51.100.11 198.51.100.12 198.51.100.53; do
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

# One socket an address, so that a reply comes from the address it was
# sent to rather than from the one the route back picks.
def udp(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 9999))
    while True:
        data, peer = sock.recvfrom(2048)
        sock.sendto(data, peer)

for address in ("198.51.100.10", "198.51.100.11", "198.51.100.12", "10.241.0.3"):
    threading.Thread(target=udp, args=(address,), daemon=True).start()

# A DNS server: every A query is answered with 198.51.100.10, any other
# with no records.
def reply(query):
    end = 12
    while end < len(query) and query[end] != 0:
        end += query[end] + 1
    end += 5
    if end > len(query):
        return None
    a = query[end - 4:end - 2] == b"\x00\x01"
    header = query[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if a else b"\x00\x00") + b"\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([198, 51, 100, 10]) if a else b""
    return header + query[12:end] + answer

def dns_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("198.51.100.53", 53))
    while True:
        query, peer = sock.recvfrom(2048)
        answer = reply(query)
        if answer:
            sock.sendto(answer, peer)

def dns_tcp_conn(conn):
    with conn:
        while True:
            head = conn.recv(2, socket.MSG_WAITALL)
            if len(head) < 2:
                return
            query = conn.recv(int.from_bytes(head, "big"), socket.MSG_WAITALL)
            answer = reply(query)
            if not answer:
                return
            conn.sendall(len(answer).to_bytes(2, "big") + answer)

def dns_tcp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("198.51.100.53", 53))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=dns_tcp_conn, args=(conn,), daemon=True).start()

threading.Thread(target=dns_udp, daemon=True).start()
threading.Thread(target=dns_tcp, daemon=True).start()
threading.Event().wait()
' &

mkdir -p "/etc/netns/$HOST"
echo "nameserver 198.51.100.53" >"/etc/netns/$HOST/resolv.conf"

cd "$SAIL_DIR"
# Built outside the namespaces, where cargo may reach the network.
cargo build -p sail-cli
cargo test -p sail --test test_auto_route_linux --no-run
# The host's own DNS settings, read in the host's namespace: resolved
# lists the links of the namespace it is asked from, so the test, in its
# namespace, cannot see the host's. sail in a namespace once set the host's
# eth0's servers, by the namespace's interface numbers, and a crash left
# them behind.
host_dns() { resolvectl dns 2>/dev/null || true; }
dns_before=$(host_dns)
status=0
in_ns "$HOST" env SAIL_BIN="${CARGO_TARGET_DIR:-$SAIL_DIR/../target}/debug/sail" \
    cargo test --offline -p sail --test test_auto_route_linux "$@" -- --ignored --nocapture --test-threads=1 ||
    status=$?
dns_after=$(host_dns)
if [ -z "$dns_before" ]; then
    echo "no systemd-resolved on the host: its DNS is not checked"
elif [ "$dns_before" != "$dns_after" ]; then
    echo "the host's DNS changed:"
    diff <(echo "$dns_before") <(echo "$dns_after") || true
    status=1
else
    echo "the host's DNS is as it was"
fi
exit "$status"
