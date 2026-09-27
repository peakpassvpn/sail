#!/usr/bin/env python3
"""Saves the first datagrams a QUIC client sends, for the QUIC sniffing
fixtures in sail/tests/fixtures/quic/.

Usage: capture-quic-initial.py PORT PREFIX [COUNT]

Listens for UDP on 127.0.0.1 and ::1 at PORT and writes the first COUNT
datagrams (default 3) from the first client to PREFIX-0.initial,
PREFIX-1.initial, ... without answering, so the client retransmits until it
gives up. It stops after COUNT datagrams or 60 seconds without one.

Point a browser with a fresh profile at https://localhost:PORT/ with QUIC
forced on for it; for Chrome:

    --user-data-dir=$(mktemp -d) --headless=new \
    --origin-to-force-quic-on=localhost:PORT https://localhost:PORT/
"""
import select
import socket
import sys


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    port, prefix = int(sys.argv[1]), sys.argv[2]
    want = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    sockets = []
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.bind((addr, port))
        sockets.append(s)
    client = None
    got = 0
    while got < want:
        ready, _, _ = select.select(sockets, [], [], 60)
        if not ready:
            break
        datagram, source = ready[0].recvfrom(65535)
        if client is None:
            client = source
        if source != client:
            continue
        path = f"{prefix}-{got}.initial"
        with open(path, "wb") as f:
            f.write(datagram)
        got += 1
        print(f"{path}: {len(datagram)} bytes", flush=True)


if __name__ == "__main__":
    main()
