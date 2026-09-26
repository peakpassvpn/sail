#!/usr/bin/env python3
"""Saves the ClientHello of each TLS connection, for the browser fingerprint
fixtures in sail/tests/fixtures/tls/.

Usage: capture-client-hello.py PORT PREFIX [COUNT]

Listens on 127.0.0.1 and ::1 at PORT and writes the first handshake message
of each connection (the ClientHello with its 4-byte header, reassembled from
TLS records) to PREFIX-0.hello, PREFIX-1.hello, ... It then closes the
connection, so the browser sees a failed handshake. It stops after COUNT
ClientHellos (default 3) or 60 seconds without one.

Point a browser with a fresh profile at https://localhost:PORT/ (a name, so
it sends SNI). See docs/roadmap.md 5.12 for each browser.
"""
import select
import socket
import sys


def read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    port, prefix = int(sys.argv[1]), sys.argv[2]
    want = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    listeners = []
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(8)
        listeners.append(s)
    got = 0
    while got < want:
        ready, _, _ = select.select(listeners, [], [], 60)
        if not ready:
            break
        conn, _ = ready[0].accept()
        conn.settimeout(5)
        try:
            body = b""
            while True:
                header = read_exact(conn, 5)
                if header[0] != 0x16:
                    raise ValueError("not a handshake record")
                body += read_exact(conn, int.from_bytes(header[3:5], "big"))
                if len(body) >= 4 and len(body) >= 4 + int.from_bytes(body[1:4], "big"):
                    break
            message = body[: 4 + int.from_bytes(body[1:4], "big")]
            path = f"{prefix}-{got}.hello"
            with open(path, "wb") as f:
                f.write(message)
            got += 1
            print(f"{path}: {len(message)} bytes", flush=True)
        except Exception as e:  # a probe or a non-TLS connection
            print(f"skipped a connection: {e}", flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
