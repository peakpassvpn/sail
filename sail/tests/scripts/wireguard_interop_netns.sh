#!/usr/bin/env bash
# Runs tests/test_wireguard_interop.rs against the Linux kernel's
# WireGuard: builds the two network namespaces its module docs describe, a
# kernel peer in sailwg-a with UDP echo servers behind it, runs the test in
# sailwg-b, and removes the namespaces again.
#
# Needs root, iproute2, wireguard-tools, socat and the kernel's wireguard
# module. Everything it changes is inside the namespaces it creates. Keys
# are made for the run and thrown away with it. WG_INTEROP_REKEY (a run of
# over three minutes) is left to whoever sets it.
#
#   sudo sail/tests/scripts/wireguard_interop_netns.sh [extra cargo test args]
#
# kernel (sailwg-a)                      sail (sailwg-b)
#   sailwg-va 172.31.99.1/24  --------    sailwg-vb 172.31.99.2/24
#   wg0 10.99.0.1/24, fd99::1/64,
#   listen 51820, peer at :51821
#   udp 7 echoes, v4 and v6

set -euo pipefail

KERNEL=sailwg-a
SAIL=sailwg-b
KEYS=

cleanup() {
    ip netns pids "$KERNEL" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns pids "$SAIL" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$KERNEL" 2>/dev/null || true
    ip netns del "$SAIL" 2>/dev/null || true
    if [ -n "$KEYS" ]; then rm -rf "$KEYS"; fi
}
trap cleanup EXIT
cleanup
KEYS=$(mktemp -d)

if ! modprobe wireguard 2>/dev/null && ! [ -d /sys/module/wireguard ]; then
    echo "the kernel has no wireguard module: the interop test cannot run here"
    exit 1
fi

in_ns() {
    local ns=$1
    shift
    ip netns exec "$ns" "$@"
}

for ns in "$KERNEL" "$SAIL"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done
ip link add sailwg-va netns "$KERNEL" type veth peer name sailwg-vb netns "$SAIL"
in_ns "$KERNEL" ip addr add 172.31.99.1/24 dev sailwg-va
in_ns "$SAIL" ip addr add 172.31.99.2/24 dev sailwg-vb
in_ns "$KERNEL" ip link set sailwg-va up
in_ns "$SAIL" ip link set sailwg-vb up

(umask 077 && wg genkey >"$KEYS/kernel.key" && wg genkey >"$KEYS/sail.key")
in_ns "$KERNEL" ip link add wg0 type wireguard
in_ns "$KERNEL" wg set wg0 private-key "$KEYS/kernel.key" listen-port 51820 \
    peer "$(wg pubkey <"$KEYS/sail.key")" allowed-ips 10.99.0.2/32,fd99::2/128 \
    endpoint 172.31.99.2:51821
in_ns "$KERNEL" ip addr add 10.99.0.1/24 dev wg0
in_ns "$KERNEL" ip addr add fd99::1/64 dev wg0
in_ns "$KERNEL" ip link set wg0 mtu 1420 up
in_ns "$KERNEL" socat UDP4-RECVFROM:7,fork EXEC:cat &
in_ns "$KERNEL" socat UDP6-RECVFROM:7,fork EXEC:cat &

in_ns "$SAIL" env WG_KERNEL_PUBLIC="$(wg pubkey <"$KEYS/kernel.key")" \
    WG_SAIL_PRIVATE="$(cat "$KEYS/sail.key")" \
    cargo test --offline -p sail --features wireguard --test test_wireguard_interop "$@" \
    -- --ignored --nocapture --test-threads=1
