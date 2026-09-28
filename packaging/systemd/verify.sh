#!/bin/sh
set -eu

die() { printf '%s\n' "verify.sh: $*" >&2; exit 1; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sail-systemd-verify.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
root=$tmp_dir/root
mkdir "$root"

fake_sail=$tmp_dir/sail
cat >"$fake_sail" <<'EOF'
#!/bin/sh
for arg in "$@"; do
    case $arg in *FAIL_CONFIG*) exit 42 ;; esac
done
case " $* " in *' --test '*) printf '%s\n' ok ;; *) exit 43 ;; esac
EOF
chmod +x "$fake_sail"

if "$script_dir/acceptance-linux.sh" --sail-binary "$fake_sail" \
    --execute-in-disposable-system >/dev/null 2>&1; then
    die "runtime acceptance did not require a persistent artifact directory"
fi
if "$script_dir/acceptance-linux.sh" --sail-binary "$fake_sail" \
    --tun-capability-check >/dev/null 2>&1; then
    die "TUN acceptance bypassed the disposable execution gate"
fi

snapshot() { find "$root" -mindepth 1 -print | LC_ALL=C sort; }
hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}
before=$(snapshot)
"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" --dry-run >/dev/null
[ "$(snapshot)" = "$before" ] || die "dry-run changed the destination"

if "$script_dir/install.sh" --root relative --check-binary "$fake_sail" --dry-run >/dev/null 2>&1; then
    die "relative root was accepted"
fi
ln -s "$tmp_dir/escape" "$root/etc"
if "$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" --dry-run >/dev/null 2>&1; then
    die "symbolic-link target component was accepted"
fi
rm "$root/etc"

bad_config=$tmp_dir/FAIL_CONFIG
: >"$bad_config"
if "$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" --config "$bad_config" >/dev/null 2>&1; then
    die "failed configuration check did not block installation"
fi
[ -z "$(snapshot)" ] || die "failed config check changed the destination"

"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" >/dev/null
[ -f "$root/etc/systemd/system/sail.service" ] || die "unit was not installed"
[ -f "$root/etc/sail/config.json" ] || die "config was not installed"
config_hash=$(hash_file "$root/etc/sail/config.json")
"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" >/dev/null
[ "$(hash_file "$root/etc/sail/config.json")" = "$config_hash" ] || die "repeat install changed config"

printf '\n' >>"$root/etc/sail/config.json"
"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" >/dev/null
[ "$(tail -c 1 "$root/etc/sail/config.json" | wc -l | tr -d ' ')" = 1 ] || die "existing config was not preserved"

unit_hash=$(hash_file "$root/etc/systemd/system/sail.service")
"$script_dir/uninstall.sh" --root "$root" --dry-run >/dev/null
[ "$(hash_file "$root/etc/systemd/system/sail.service")" = "$unit_hash" ] || die "uninstall dry-run changed unit"
printf '# locally modified\n' >>"$root/etc/sail/sail.env"
"$script_dir/uninstall.sh" --root "$root" >/dev/null
[ ! -e "$root/etc/systemd/system/sail.service" ] || die "unit was not removed"
[ -e "$root/etc/sail/config.json" ] || die "config was removed"
[ -e "$root/etc/sail/sail.env" ] || die "modified environment file was removed"
"$script_dir/uninstall.sh" --root "$root" >/dev/null

"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" --mode tun >/dev/null
[ -f "$root/etc/systemd/system/sail.service.d/10-tun-transparent.conf" ] || die "TUN drop-in was not installed"
"$script_dir/install.sh" --root "$root" --check-binary "$fake_sail" --mode tun >/dev/null
"$script_dir/uninstall.sh" --root "$root" >/dev/null
[ ! -e "$root/etc/systemd/system/sail.service.d/10-tun-transparent.conf" ] || die "TUN drop-in was not removed"
[ -e "$root/etc/sail/sail.env" ] || die "pre-existing environment file was removed"

grep -q '^User=sail$' "$script_dir/sail.service.in" || die "base unit is not unprivileged"
grep -q '^CapabilityBoundingSet=$' "$script_dir/sail.service.in" || die "base capability set is not empty"
if grep -q '^ExecReload=' "$script_dir/sail.service.in"; then die "unsupported ExecReload is present"; fi
grep -q '^KillSignal=SIGTERM$' "$script_dir/sail.service.in" || die "SIGTERM stop is not explicit"
grep -q '^ExecStartPre=.* --test$' "$script_dir/sail.service.in" || die "config check is not an ExecStartPre gate"
grep -q 'CAP_NET_ADMIN' "$script_dir/sail-tun-transparent.conf" || die "TUN override lacks CAP_NET_ADMIN"

printf '%s\n' "systemd packaging static and temporary-root checks passed"
