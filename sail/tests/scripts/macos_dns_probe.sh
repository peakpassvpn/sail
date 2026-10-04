#!/usr/bin/env bash
# What the system makes of a TUN's DNS given as sail would give it, on a Mac,
# as root (CI's tun-macos job): one dynamic-store key, held by a session
# that adds it as temporary, of a service that does not exist,
#
#   State:/Network/Service/<id>/DNS = { ServerAddresses: [the TUN's peer],
#     SupplementalMatchDomains: [""], SearchOrder: 100000 }
#
# Says whether that resolver comes first in `scutil --dns` (the default
# resolver), and fails unless killing the session (kill -9) removes it.
# `scutil`'s `add ... temporary` is SCDynamicStoreAddTemporaryValue, and
# its process the session.

set -euo pipefail

KEY="State:/Network/Service/5A11D0E5-0000-4000-8000-00000000D115/DNS"
SERVER=172.19.0.2
W=$(mktemp -d)

cleanup() {
    [ -n "${HOLDER:-}" ] && sudo -n kill -9 "$HOLDER" 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    sudo -n scutil <<< "remove $KEY" 2>/dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT

first_resolver() { scutil --dns | awk '/^resolver #1$/{on=1} on&&/^$/{exit} on'; }
key_there() { scutil <<< "show $KEY" | grep -q ServerAddresses; }

echo "== before"
scutil --dns | sed -n '1,40p'
before=$(scutil --dns)

echo "== a session adds the key, as temporary"
mkfifo "$W/in"
sudo -n scutil < "$W/in" > "$W/out" 2>&1 &
SUDO=$!
exec 3> "$W/in"
for _ in $(seq 1 50); do
    HOLDER=$(pgrep -P "$SUDO" scutil || true)
    [ -n "$HOLDER" ] && break
    sleep 0.1
done
[ -n "$HOLDER" ] || { echo "FAIL: no scutil under sudo $SUDO"; exit 1; }
printf '%s\n' "d.init" "d.add ServerAddresses * $SERVER" \
    'd.add SupplementalMatchDomains * ""' "d.add SearchOrder # 100000" \
    "add $KEY temporary" >&3
for _ in $(seq 1 50); do key_there && break; sleep 0.1; done
key_there || { echo "FAIL: the key was not added"; cat "$W/out"; exit 1; }
scutil <<< "show $KEY"
sleep 1
echo "== scutil --dns with the key"
scutil --dns | sed -n '1,60p'
if first_resolver | grep -q "nameserver\[0\] : $SERVER"; then
    echo "RESULT: the TUN's resolver is #1 (the default resolver)"
else
    echo "RESULT: the TUN's resolver is NOT #1; #1 is:"
    first_resolver
fi
scutil --dns | grep -n "$SERVER" || echo "RESULT: $SERVER is in no resolver"

echo "== kill -9 of the session"
sudo -n kill -9 "$HOLDER"
HOLDER=
gone=
for _ in $(seq 1 50); do
    key_there || { gone=1; break; }
    sleep 0.1
done
[ -n "$gone" ] || { echo "FAIL: the key outlived its session's kill -9"; exit 1; }
echo "OK: the key went with its session"
sleep 1
[ "$(scutil --dns)" = "$before" ] && echo "OK: scutil --dns is as before" ||
    { echo "NOTE: scutil --dns differs from before:"; diff <(echo "$before") <(scutil --dns) || true; }
