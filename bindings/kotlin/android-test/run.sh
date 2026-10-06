#!/usr/bin/env bash
# Runs the emulator tests (src/androidTest) against the emulator adb sees,
# with echo servers on this host. The emulator reaches them at this host's
# own address, through its NAT: not at 10.0.2.2, its gateway, which is on
# its own network and so never goes through a VPN.
#
#   bindings/kotlin/android-test/run.sh <dir with x86_64/libsail.a>
#
# Needs SAIL_AGP, an NDK at NDK_PATH (the one libsail.a was built with),
# Gradle and python3. CI's android-emulator job runs it.

set -euo pipefail

libs=$(cd "$1" && pwd)
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
: "${SAIL_AGP:?}" "${NDK_PATH:?}"

# A TCP and a UDP echo server, each on a port of its own, for as long as
# this runs.
ports=$(mktemp)
python3 - "$ports" <<'PY' &
import socket, sys, threading
tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", 0)); tcp.listen(64)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("0.0.0.0", 0))
with open(sys.argv[1], "w") as f:
    f.write(f"{tcp.getsockname()[1]} {udp.getsockname()[1]}\n")
def echo(conn):
    with conn:
        while data := conn.recv(4096):
            conn.sendall(data)
def serve_tcp():
    while True:
        conn, _ = tcp.accept()
        threading.Thread(target=echo, args=(conn,), daemon=True).start()
threading.Thread(target=serve_tcp, daemon=True).start()
while True:
    data, peer = udp.recvfrom(4096)
    udp.sendto(data, peer)
PY
echo_pid=$!
trap 'kill $echo_pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$ports" ] && break; sleep 0.1; done
read -r tcp_port udp_port <"$ports"
host=$(hostname -I | awk '{ print $1 }')
echo "echo servers: $host, tcp $tcp_port, udp $udp_port"

# The device booted, and its package manager answering, before the tests
# begin; then the mark that they did (CI tries the boot again only without
# it).
adb wait-for-device
for _ in $(seq 120); do
	[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] &&
		adb shell pm path android >/dev/null 2>&1 && break
	sleep 1
done
[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] || {
	echo "the device did not finish booting" >&2
	exit 1
}
adb shell pm path android >/dev/null || {
	echo "the device's package manager does not answer" >&2
	exit 1
}
mkdir -p "$ROOT/bindings/kotlin/android-test/build"
touch "$ROOT/bindings/kotlin/android-test/build/tests-began"

ndk_version=$(sed -n 's/^Pkg\.Revision *= *//p' "$NDK_PATH/source.properties")
status=0
gradle --no-daemon -p "$ROOT/bindings/kotlin/android-test" connectedDebugAndroidTest \
	-Psail.agp="$SAIL_AGP" -Psail.abis=x86_64 \
	-Psail.ndkPath="$NDK_PATH" -Psail.ndkVersion="$ndk_version" \
	-Psail.libDir="$libs" -Psail.includeDir="$ROOT/sail-ffi/include" \
	-Pandroid.testInstrumentationRunnerArguments.echoHost="$host" \
	-Pandroid.testInstrumentationRunnerArguments.tcpPort="$tcp_port" \
	-Pandroid.testInstrumentationRunnerArguments.udpPort="$udp_port" || status=$?
# What the emulator logged, sail and the app with it, for a failure to be read.
mkdir -p "$ROOT/bindings/kotlin/android-test/build"
adb logcat -d >"$ROOT/bindings/kotlin/android-test/build/logcat.txt" 2>/dev/null || true
exit $status
