#!/usr/bin/env bash
# macOS, as root (CI's tun-macos job): real traffic through a utun.
# auto_route sends 198.18.0.0/15 and 2001:db8::/32 into the TUN; a route
# rule overrides 198.18.0.10 to 127.0.0.1 and 2001:db8::10 to ::1, where
# echo servers listen, so a reply proves the round trip through the utun,
# sail's netstack and the direct outbound. Checks DNS queries to the TUN's
# DNS servers (IPv4 and IPv6, hijacked and answered by a hosts server),
# and TCP and UDP echoes over IPv4 and IPv6. Only test prefixes are
# routed: the runner's own traffic is untouched.
set -euo pipefail
SAIL=${SAIL:-target/debug/sail}
W=$(mktemp -d)
PORT=18877

fail() { echo "FAIL: $*"; exit 1; }

cleanup() {
  sudo -n pkill -9 -f "^$SAIL -c $W/" 2>/dev/null || true
  [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null || true
  for log in "$W"/*.log "$W"/*.out; do
    [ -e "$log" ] && { echo "--- $log"; tail -30 "$log"; }
  done
}
trap cleanup EXIT

cat > "$W/t.json" <<JSON
{ "log": { "level": "debug", "output": "$W/t.log" },
  "inbounds": [{ "type": "tun", "tag": "tun-in",
                 "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                 "auto_route": true,
                 "route_address": ["198.18.0.0/15", "2001:db8::/32"] }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "dns": { "servers": [{ "type": "hosts", "tag": "hosts", "predefined": {
             "probe.sail": ["198.18.0.10", "2001:db8::10"] } }] },
  "route": { "rules": [
    { "port": 53, "action": "hijack-dns" },
    { "ip_cidr": ["198.18.0.10/32"], "action": "route-options", "override_address": "127.0.0.1" },
    { "ip_cidr": ["2001:db8::10/128"], "action": "route-options", "override_address": "::1" }
  ], "final": "direct" } }
JSON

cat > "$W/echo.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
def tcp(family, host):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(16)
    while True:
        c, _ = s.accept()
        def serve(c):
            with c:
                while True:
                    b = c.recv(65536)
                    if not b: return
                    c.sendall(b)
        threading.Thread(target=serve, args=(c,), daemon=True).start()
def udp(family, host):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        b, a = s.recvfrom(65536)
        s.sendto(b, a)
for f, h in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    threading.Thread(target=tcp, args=(f, h), daemon=True).start()
    threading.Thread(target=udp, args=(f, h), daemon=True).start()
print("listening", flush=True)
threading.Event().wait()
PY

cat > "$W/client.py" <<'PY'
import socket, struct, sys, os
port = int(sys.argv[1])
ok = True
def check(name, cond, detail=""):
    global ok
    print(("OK: " if cond else "FAIL: ") + name + (" " + detail if detail and not cond else ""), flush=True)
    ok &= cond

def query(name, qtype):
    q = struct.pack(">HHHHHH", 0x5a1, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\0" + struct.pack(">HH", qtype, 1)

def answers(reply):
    count = struct.unpack(">H", reply[6:8])[0]
    i = 12
    while reply[i]: i += reply[i] + 1
    i += 5
    found = []
    for _ in range(count):
        if reply[i] & 0xc0 == 0xc0: i += 2
        else:
            while reply[i]: i += reply[i] + 1
            i += 1
        rtype, _, _, rdlen = struct.unpack(">HHIH", reply[i:i + 10]); i += 10
        data = reply[i:i + rdlen]; i += rdlen
        if rtype == 1: found.append(socket.inet_ntop(socket.AF_INET, data))
        if rtype == 28: found.append(socket.inet_ntop(socket.AF_INET6, data))
    return found

def dns(server, family, qtype, want):
    s = socket.socket(family, socket.SOCK_DGRAM); s.settimeout(3)
    got = []
    for _ in range(3):
        try:
            s.sendto(query("probe.sail", qtype), (server, 53))
            got = answers(s.recvfrom(4096)[0]); break
        except socket.timeout:
            continue
    check(f"DNS {'AAAA' if qtype == 28 else 'A'} of probe.sail from {server}", want in got, f"got {got}")

def tcp(family, host):
    data = os.urandom(256 * 1024)
    try:
        s = socket.create_connection((host, port), timeout=10)
        s.sendall(data); s.shutdown(socket.SHUT_WR)
        back = b""
        while True:
            b = s.recv(65536)
            if not b: break
            back += b
        check(f"TCP {host} echoes 256 KiB", back == data, f"{len(back)} bytes back")
    except OSError as e:
        check(f"TCP {host} echoes 256 KiB", False, str(e))

def udp(family, host):
    s = socket.socket(family, socket.SOCK_DGRAM); s.settimeout(2)
    good = 0
    for n, size in enumerate([1, 100, 512, 1200] * 5):
        payload = bytes([n]) + os.urandom(size)
        for _ in range(3):
            try:
                s.sendto(payload, (host, port))
                if s.recvfrom(65536)[0] == payload: good += 1; break
            except socket.timeout:
                continue
    check(f"UDP {host} echoes 20 datagrams", good == 20, f"{good} of 20")

dns("172.19.0.2", socket.AF_INET, 1, "198.18.0.10")
dns("172.19.0.2", socket.AF_INET, 28, "2001:db8::10")
dns("fdfe:dcba:9876::2", socket.AF_INET6, 28, "2001:db8::10")
tcp(socket.AF_INET, "198.18.0.10")
tcp(socket.AF_INET6, "2001:db8::10")
udp(socket.AF_INET, "198.18.0.10")
udp(socket.AF_INET6, "2001:db8::10")
sys.exit(0 if ok else 1)
PY

python3 "$W/echo.py" "$PORT" > "$W/echo.out" 2>&1 & SERVER=$!
for _ in $(seq 1 50); do grep -q listening "$W/echo.out" 2>/dev/null && break; sleep 0.1; done
grep -q listening "$W/echo.out" || fail "the echo servers did not start"

sudo -n "$SAIL" -c "$W/t.json" > "$W/t.out" 2>&1 &
for _ in $(seq 1 150); do
  # The log may not exist yet: under pipefail that would end the script.
  NAME=$(sed -n 's/.*auto_route: [0-9]* routes into \(utun[0-9]*\).*/\1/p' "$W/t.log" 2>/dev/null | head -1 || true)
  [ -n "$NAME" ] && break
  sleep 0.1
done
[ -n "${NAME:-}" ] || fail "no 'auto_route: ... routes into' line"
echo "routed into $NAME"
for dest in "inet 198.18.0.10" "inet6 2001:db8::10"; do
  read -r family addr <<< "$dest"
  got=$(route -n get -"$family" "$addr" 2>/dev/null | sed -n 's/^ *interface: //p' || true)
  [ "$got" = "$NAME" ] || fail "$addr goes through '${got:-nothing}', not $NAME"
done

python3 "$W/client.py" "$PORT" || fail "traffic through $NAME"
echo "OK: traffic through $NAME"
