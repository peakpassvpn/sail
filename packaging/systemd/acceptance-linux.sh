#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage:
  acceptance-linux.sh --sail-binary /absolute/path [--artifacts DIR]
  acceptance-linux.sh --execute-in-disposable-system \
    --sail-binary /absolute/path --artifacts DIR [--port PORT] \
    [--tun-capability-check]

The default mode runs portable packaging checks and systemd-analyze verify.
The execution mode installs a uniquely named unit below /run, starts it, reads
its journal, tests failure restart and invalid-config rejection, and removes it.
It refuses to run unless PID 1 is systemd, the sail user already exists, and
/run/sail-systemd-acceptance-allowed contains exactly "disposable-system".

--tun-capability-check is a separate opt-in. It grants CAP_NET_ADMIN and
CAP_NET_RAW to the test service but does not create a TUN device or alter routes.
EOF
}

die() { printf '%s\n' "acceptance-linux.sh: $*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
sail_binary=
artifacts_root=
execute=false
tun_check=false
port=39876

while [ "$#" -gt 0 ]; do
    case $1 in
        --sail-binary) [ "$#" -ge 2 ] || die "--sail-binary needs a value"; sail_binary=$2; shift 2 ;;
        --artifacts) [ "$#" -ge 2 ] || die "--artifacts needs a value"; artifacts_root=$2; shift 2 ;;
        --port) [ "$#" -ge 2 ] || die "--port needs a value"; port=$2; shift 2 ;;
        --execute-in-disposable-system) execute=true; shift ;;
        --tun-capability-check) tun_check=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$sail_binary" ] || die "--sail-binary is required"
case $sail_binary in /*) ;; *) die "--sail-binary must be absolute" ;; esac
case $sail_binary in *[!A-Za-z0-9_./+-]*|*'/../'*|*/..) die "--sail-binary contains unsafe characters or components" ;; esac
[ -x "$sail_binary" ] || die "Sail binary is not executable: $sail_binary"
case $port in ''|*[!0-9]*) die "--port must be an integer" ;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || die "--port must be between 1024 and 65535"
if [ "$tun_check" = true ] && [ "$execute" != true ]; then
    die "--tun-capability-check requires --execute-in-disposable-system"
fi
if [ "$execute" = true ] && [ -z "$artifacts_root" ]; then
    die "--artifacts is required for runtime acceptance so failures retain evidence"
fi
if [ -n "$artifacts_root" ]; then
    case $artifacts_root in /*) ;; *) die "--artifacts must be absolute" ;; esac
    [ ! -L "$artifacts_root" ] || die "--artifacts must not be a symbolic link"
    mkdir -p "$artifacts_root"
    artifacts_root=$(CDPATH= cd -- "$artifacts_root" && pwd -P)
fi

"$script_dir/verify.sh"

if [ "$(uname -s)" != Linux ]; then
    note "SKIP systemd acceptance: Linux is required"
    exit 77
fi
if ! command -v systemd-analyze >/dev/null 2>&1; then
    note "SKIP systemd acceptance: systemd-analyze is unavailable"
    exit 77
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sail-systemd-acceptance.XXXXXX")
unit_name=sail-acceptance-$$.service
runtime_dir=/run/sail-systemd-acceptance-$$
unit_path=/run/systemd/system/$unit_name
dropin_dir=/run/systemd/system/$unit_name.d
cache_name=sail-acceptance-$$
cleanup_needed=false
artifact_dir=
current_step=rendering
acceptance_complete=false
started_at=0
if [ "$execute" = true ]; then acceptance_scope=runtime; else acceptance_scope=static; fi

cleanup() {
    rc=$1
    trap - EXIT HUP INT TERM
    if [ -n "$artifact_dir" ] && [ -d "$artifact_dir" ]; then
        for evidence in \
            "${rendered_unit:-}" "${merged_tun_unit:-}" \
            "$tmp_dir/config-check.txt" \
            "$tmp_dir/systemd-analyze-verify.txt" \
            "$tmp_dir/systemd-analyze-verify-tun.txt" \
            "$tmp_dir/journal-start.txt" \
            "$tmp_dir/process-status-ordinary.txt" \
            "$tmp_dir/process-status-tun.txt"; do
            if [ -f "$evidence" ]; then
                cp "$evidence" "$artifact_dir/" >/dev/null 2>&1 || true
            fi
        done
        if [ "$cleanup_needed" = true ]; then
            if command -v journalctl >/dev/null 2>&1 && [ "$started_at" -gt 0 ]; then
                journalctl -u "$unit_name" --since "@$started_at" --no-pager \
                    >"$artifact_dir/journal.txt" 2>&1 || true
            fi
            if command -v systemctl >/dev/null 2>&1; then
                systemctl show "$unit_name" >"$artifact_dir/systemctl-show.txt" 2>&1 || true
            fi
            if [ -f "$unit_path" ]; then
                cp "$unit_path" "$artifact_dir/" >/dev/null 2>&1 || true
            fi
            if [ -f "$dropin_dir/10-tun-transparent.conf" ]; then
                cp "$dropin_dir/10-tun-transparent.conf" "$artifact_dir/" >/dev/null 2>&1 || true
            fi
        fi
        if [ "$acceptance_complete" = true ] && [ "$rc" -eq 0 ]; then
            result=PASS
        elif [ "$rc" -eq 0 ]; then
            result=INCOMPLETE
        else
            result=FAIL
        fi
        {
            printf 'result=%s\n' "$result"
            printf 'exit_code=%s\n' "$rc"
            printf 'last_step=%s\n' "$current_step"
            printf 'scope=%s\n' "$acceptance_scope"
            printf 'unit=%s\n' "$unit_name"
            printf 'tun_capability_check=%s\n' "$tun_check"
        } >"$artifact_dir/result.txt"
    fi
    if [ "$cleanup_needed" = true ]; then
        systemctl stop "$unit_name" >/dev/null 2>&1 || true
        rm -f -- "$unit_path" "$dropin_dir/10-tun-transparent.conf"
        rmdir "$dropin_dir" >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        case $runtime_dir in /run/sail-systemd-acceptance-[0-9]*) rm -rf -- "$runtime_dir" ;; esac
        case /var/cache/$cache_name in /var/cache/sail-acceptance-[0-9]*) rm -rf -- "/var/cache/$cache_name" ;; esac
    fi
    rm -rf -- "$tmp_dir"
    exit "$rc"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_process_security_state() {
    security_expected_uid=$1
    security_expected_cap=$2
    security_evidence=$3
    security_attempt=0
    pid=0
    actual_uid=
    cap_eff=
    while [ "$security_attempt" -lt 50 ]; do
        pid=$(systemctl show "$unit_name" -p MainPID --value)
        if [ "$pid" -gt 1 ] 2>/dev/null && [ -r "/proc/$pid/status" ]; then
            actual_uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status")
            cap_eff=$(awk '/^CapEff:/{print $2}' "/proc/$pid/status")
            if [ "$actual_uid" = "$security_expected_uid" ] && \
                [ "$cap_eff" = "$security_expected_cap" ]; then
                cp "/proc/$pid/status" "$security_evidence"
                return 0
            fi
        fi
        security_attempt=$((security_attempt + 1))
        sleep 0.1
    done
    {
        printf 'expected_uid=%s\n' "$security_expected_uid"
        printf 'expected_cap_eff=%s\n' "$security_expected_cap"
        printf 'observed_pid=%s\n' "$pid"
        printf 'observed_uid=%s\n' "$actual_uid"
        printf 'observed_cap_eff=%s\n' "$cap_eff"
        if [ "$pid" -gt 1 ] 2>/dev/null && [ -r "/proc/$pid/status" ]; then
            cat "/proc/$pid/status"
        fi
    } >"$security_evidence"
    return 1
}

if [ -n "$artifacts_root" ]; then
    artifact_dir=$artifacts_root/run-$(date -u +%Y%m%dT%H%M%SZ)-$$
    mkdir "$artifact_dir"
    note "evidence: $artifact_dir"
fi

env_file=$tmp_dir/sail.env
config_file=$tmp_dir/config.json
rendered_unit=$tmp_dir/$unit_name
merged_tun_unit=$tmp_dir/sail-acceptance-tun-$$.service
cat >"$env_file" <<EOF
SAIL_CONFIG=$config_file
SAIL_DATA_DIR=$tmp_dir
SAIL_CACHE_DIR=/var/cache/$cache_name
SAIL_PROFILE=server
EOF
cat >"$config_file" <<EOF
{
  "log": { "level": "info", "format": "compact" },
  "inbounds": [{
    "type": "socks", "tag": "acceptance-socks",
    "listen": "127.0.0.1", "listen_port": $port
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
EOF
mkdir "$tmp_dir/cache-check"
sed -e "s|@SAIL_BINARY@|$sail_binary|g" \
    -e "s|EnvironmentFile=/etc/sail/sail.env|EnvironmentFile=$env_file|" \
    -e "s|CacheDirectory=sail|CacheDirectory=$cache_name|" \
    "$script_dir/sail.service.in" >"$rendered_unit"
cat "$rendered_unit" "$script_dir/sail-tun-transparent.conf" >"$merged_tun_unit"

current_step=config-check
if ! "$sail_binary" --config "$config_file" --data-dir "$tmp_dir" \
    --cache-dir "$tmp_dir/cache-check" --profile server --test \
    >"$tmp_dir/config-check.txt" 2>&1; then
    cat "$tmp_dir/config-check.txt" >&2
    die "real configuration check failed"
fi
cat "$tmp_dir/config-check.txt"
current_step=systemd-analyze-ordinary
systemd-analyze verify "$rendered_unit" >"$tmp_dir/systemd-analyze-verify.txt" 2>&1
current_step=systemd-analyze-tun
systemd-analyze verify "$merged_tun_unit" >"$tmp_dir/systemd-analyze-verify-tun.txt" 2>&1
note "PASS static: portable checks, real config check, and ordinary/TUN systemd-analyze verify"

if [ "$execute" != true ]; then
    current_step=static-complete
    acceptance_complete=true
    note "SKIP runtime: pass --execute-in-disposable-system only inside an isolated disposable system"
    exit 0
fi

current_step=runtime-preconditions
[ "$(id -u)" -eq 0 ] || die "runtime acceptance requires root inside the disposable system"
[ "$(cat /proc/1/comm)" = systemd ] || die "PID 1 must be systemd"
case $sail_binary in
    /home/*|/root/*|/run/user/*) die "runtime binary is hidden by ProtectHome; install it under /usr or /opt" ;; # sensitive-check: allow
esac
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
command -v journalctl >/dev/null 2>&1 || die "journalctl is required"
getent passwd sail >/dev/null 2>&1 || die "the non-login sail account must already exist"
[ -f /run/sail-systemd-acceptance-allowed ] || die "missing disposable-system marker"
grep -qx 'disposable-system' /run/sail-systemd-acceptance-allowed || die "invalid disposable-system marker"
[ ! -e "$unit_path" ] || die "test unit already exists: $unit_path"
[ ! -e "$runtime_dir" ] || die "test runtime directory already exists: $runtime_dir"

cleanup_needed=true
current_step=install-transient-unit
mkdir -m 0755 "$runtime_dir"
cp "$config_file" "$runtime_dir/config.json"
cat >"$runtime_dir/sail.env" <<EOF
SAIL_CONFIG=$runtime_dir/config.json
SAIL_DATA_DIR=$runtime_dir
SAIL_CACHE_DIR=/var/cache/$cache_name
SAIL_PROFILE=server
EOF
sed -e "s|$env_file|$runtime_dir/sail.env|g" \
    "$rendered_unit" >"$unit_path"
chmod 0644 "$runtime_dir/config.json" "$runtime_dir/sail.env" "$unit_path"
systemctl daemon-reload

current_step=start-ordinary
started_at=$(date +%s)
systemctl start "$unit_name"
active=$(systemctl is-active "$unit_name")
[ "$active" = active ] || die "ordinary service did not become active"
expected_uid=$(id -u sail)
[ "$expected_uid" != 0 ] || die "sail account unexpectedly has root UID"
if ! wait_for_process_security_state "$expected_uid" 0000000000000000 \
    "$tmp_dir/process-status-ordinary.txt"; then
    die "ordinary service did not settle to the expected UID and capability state"
fi
[ "$actual_uid" != 0 ] || die "ordinary service ran as root"
journalctl -u "$unit_name" --since "@$started_at" --no-pager >"$tmp_dir/journal-start.txt"
[ -s "$tmp_dir/journal-start.txt" ] || die "service produced no journal evidence"
note "PASS runtime: ordinary service active as non-root UID $actual_uid with journal output"

current_step=failure-restart
old_pid=$pid
kill -KILL "$old_pid"
attempt=0
new_pid=0
while [ "$attempt" -lt 50 ]; do
    new_pid=$(systemctl show "$unit_name" -p MainPID --value)
    if [ "$new_pid" -gt 1 ] && [ "$new_pid" != "$old_pid" ] && systemctl is-active --quiet "$unit_name"; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.2
done
[ "$new_pid" -gt 1 ] && [ "$new_pid" != "$old_pid" ] || die "service did not restart after failure"
restarts=$(systemctl show "$unit_name" -p NRestarts --value)
[ "$restarts" -ge 1 ] || die "systemd did not record a failure restart"
note "PASS runtime: failure restart created PID $new_pid (NRestarts=$restarts)"

current_step=reload-valid
reload_pid=$(systemctl show "$unit_name" -p MainPID --value)
reload_at=$(date +%s)
systemctl reload "$unit_name" || die "systemctl reload of a valid configuration failed"
attempt=0
until journalctl -u "$unit_name" --since "@$reload_at" --no-pager | grep -q 'SIGHUP: reloaded'; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || die "no reload in the journal"
    sleep 0.2
done
[ "$(systemctl show "$unit_name" -p MainPID --value)" = "$reload_pid" ] || die "reload replaced the process"
note "PASS runtime: systemctl reload reloaded in place (PID $reload_pid)"

current_step=reload-invalid
cp "$runtime_dir/config.json" "$tmp_dir/config-good.json"
printf '{ invalid json\n' >"$runtime_dir/config.json"
if systemctl reload "$unit_name"; then
    die "systemctl reload of an invalid configuration succeeded"
fi
systemctl is-active --quiet "$unit_name" || die "a refused reload stopped the service"
# Past the check too: the process itself keeps the configuration before.
signal_at=$(date +%s)
kill -HUP "$reload_pid"
attempt=0
until journalctl -u "$unit_name" --since "@$signal_at" --no-pager | grep -q 'the one before runs on'; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || die "no refused reload in the journal"
    sleep 0.2
done
systemctl is-active --quiet "$unit_name" || die "a failed reload stopped the service"
[ "$(systemctl show "$unit_name" -p MainPID --value)" = "$reload_pid" ] || die "a failed reload replaced the process"
cp "$tmp_dir/config-good.json" "$runtime_dir/config.json"
note "PASS runtime: an invalid configuration fails systemctl reload and leaves the service running"

current_step=drain-stop
command -v python3 >/dev/null 2>&1 || die "the drain check needs python3"
# A server that holds a connection, and a client that holds one to it
# through the SOCKS inbound for 3 s.
python3 - "$port" "$tmp_dir/drain-client.txt" <<'PY' &
import socket, sys, threading, time
socks_port, out = int(sys.argv[1]), sys.argv[2]
server = socket.socket(); server.bind(("127.0.0.1", 0)); server.listen()
target = server.getsockname()[1]
threading.Thread(target=lambda: [server.accept() for _ in range(4)], daemon=True).start()
c = socket.create_connection(("127.0.0.1", socks_port), timeout=5)
c.sendall(b"\x05\x01\x00"); c.recv(2)
c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big"))
reply = c.recv(10)
open(out, "w").write("connected %d\n" % reply[1])
time.sleep(3)
c.close()
open(out, "a").write("closed\n")
PY
client_pid=$!
attempt=0
until grep -q '^connected 0$' "$tmp_dir/drain-client.txt" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || die "the drain client did not connect through the service"
    sleep 0.1
done
stop_started=$(date +%s)
systemctl stop "$unit_name"
stop_took=$(( $(date +%s) - stop_started ))
wait "$client_pid" || true
grep -q '^closed$' "$tmp_dir/drain-client.txt" || die "the stop did not wait for the open connection"
[ "$stop_took" -ge 2 ] || die "the stop took ${stop_took}s: it did not wait for the open connection"
[ "$stop_took" -lt 30 ] || die "the stop took ${stop_took}s: it waited past the connection"
journalctl -u "$unit_name" --since "@$stop_started" --no-pager >"$tmp_dir/journal-drain.txt"
grep -q 'every connection finished' "$tmp_dir/journal-drain.txt" || die "no drain in the journal"
note "PASS runtime: systemctl stop drained the open connection (${stop_took}s)"

current_step=normal-stop
systemctl start "$unit_name"
systemctl stop "$unit_name"
systemctl is-active --quiet "$unit_name" && die "service remained active after stop"
note "PASS runtime: systemctl stop with nothing open completed through the unit's SIGTERM policy"

current_step=invalid-config-gate
printf '{ invalid json\n' >"$runtime_dir/config.json"
if systemctl start "$unit_name"; then
    die "invalid configuration unexpectedly started"
fi
systemctl is-active --quiet "$unit_name" && die "invalid configuration left the service active"
systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
note "PASS runtime: ExecStartPre rejected invalid configuration"

if [ "$tun_check" = true ]; then
    current_step=tun-capability-check
    [ -c /dev/net/tun ] || die "--tun-capability-check requires /dev/net/tun"
    cp "$config_file" "$runtime_dir/config.json"
    mkdir "$dropin_dir"
    cp "$script_dir/sail-tun-transparent.conf" "$dropin_dir/10-tun-transparent.conf"
    chmod 0644 "$dropin_dir/10-tun-transparent.conf"
    systemctl daemon-reload
    systemctl start "$unit_name"
    if ! wait_for_process_security_state "$expected_uid" 0000000000003000 \
        "$tmp_dir/process-status-tun.txt"; then
        die "TUN mode did not settle to the expected UID and capability state"
    fi
    [ "$actual_uid" = "$expected_uid" ] && [ "$actual_uid" != 0 ] || die "TUN mode did not remain non-root"
    device_policy=$(systemctl show "$unit_name" -p DevicePolicy --value)
    [ "$device_policy" = closed ] || die "unexpected TUN device policy: $device_policy"
    systemctl stop "$unit_name"
    note "PASS TUN opt-in: non-root process has exactly CAP_NET_ADMIN and CAP_NET_RAW"
fi

current_step=runtime-complete
acceptance_complete=true
note "PASS runtime acceptance; cleanup will remove the transient test unit"
