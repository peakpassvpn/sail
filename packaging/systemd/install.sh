#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage: install.sh --root DIR --check-binary FILE [options]

Install systemd packaging below an explicit filesystem root. Nothing is
enabled, started, or daemon-reloaded.

Options:
  --root DIR              destination root (required; / needs --allow-system-root)
  --check-binary FILE     runnable sail used for the pre-install config check
  --service-binary PATH   absolute path written to the unit (default: /usr/bin/sail)
  --config FILE           initial config source (default: config.example.json)
  --mode ordinary|tun     install the unprivileged unit or the opt-in TUN drop-in
  --dry-run               validate and print operations without changing DIR
  --allow-system-root     explicitly permit --root / (normally for real packaging)
  -h, --help              show this help
EOF
}

die() { printf '%s\n' "install.sh: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
root=
check_binary=
service_binary=/usr/bin/sail
config_source=$script_dir/config.example.json
mode=ordinary
dry_run=false
allow_system_root=false

while [ "$#" -gt 0 ]; do
    case $1 in
        --root) [ "$#" -ge 2 ] || die "--root needs a value"; root=$2; shift 2 ;;
        --check-binary) [ "$#" -ge 2 ] || die "--check-binary needs a value"; check_binary=$2; shift 2 ;;
        --service-binary) [ "$#" -ge 2 ] || die "--service-binary needs a value"; service_binary=$2; shift 2 ;;
        --config) [ "$#" -ge 2 ] || die "--config needs a value"; config_source=$2; shift 2 ;;
        --mode) [ "$#" -ge 2 ] || die "--mode needs a value"; mode=$2; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --allow-system-root) allow_system_root=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$root" ] || die "--root is required"
[ -n "$check_binary" ] || die "--check-binary is required"
case $root in /*) ;; *) die "--root must be absolute" ;; esac
case $root in *'/../'*|*/..|*'/./'*|*/.) die "--root must not contain . or .. components" ;; esac
[ ! -L "$root" ] || die "--root must not be a symbolic link"
[ -d "$root" ] || die "--root must name an existing directory"
root=$(CDPATH= cd -- "$root" && pwd -P)
if [ "$root" = / ] && [ "$allow_system_root" != true ]; then
    die "refusing --root / without --allow-system-root"
fi
case $service_binary in
    /*) ;;
    *) die "--service-binary must be absolute" ;;
esac
case $service_binary in
    *[!A-Za-z0-9_./+-]*|*'/../'*|*/..) die "--service-binary contains unsafe characters or components" ;;
esac
case $mode in ordinary|tun) ;; *) die "--mode must be ordinary or tun" ;; esac
[ -x "$check_binary" ] || die "--check-binary is not executable: $check_binary"
[ -f "$config_source" ] || die "config source is not a regular file: $config_source"

for preserved in "$root/etc" "$root/etc/sail" "$root/etc/sail/config.json" "$root/etc/sail/sail.env"; do
    [ ! -L "$preserved" ] || die "refusing symbolic-link target component: $preserved"
done
for preserved_file in "$root/etc/sail/config.json" "$root/etc/sail/sail.env"; do
    if [ -e "$preserved_file" ] && [ ! -f "$preserved_file" ]; then
        die "preserved target is not a regular file: $preserved_file"
    fi
done

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sail-systemd-install.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
unit_rendered=$tmp_dir/sail.service
manifest_rendered=$tmp_dir/manifest
sed "s|@SAIL_BINARY@|$service_binary|g" "$script_dir/sail.service.in" >"$unit_rendered"

dest_config=$root/etc/sail/config.json
if [ -f "$dest_config" ]; then
    check_config=$dest_config
else
    check_config=$config_source
fi
say "checking configuration: $check_binary --config $check_config --data-dir $(dirname -- "$check_config") --cache-dir $tmp_dir/cache --profile server --test"
mkdir "$tmp_dir/cache"
"$check_binary" --config "$check_config" --data-dir "$(dirname -- "$check_config")" \
    --cache-dir "$tmp_dir/cache" --profile server --test

assert_safe_target() {
    rel=$1
    case $rel in etc/*|var/lib/sail-systemd-package/*) ;; *) die "internal unsafe target: $rel" ;; esac
    cursor=$root
    old_ifs=$IFS
    IFS=/
    for component in $rel; do
        IFS=$old_ifs
        cursor=$cursor/$component
        [ ! -L "$cursor" ] || die "refusing symbolic-link target component: $cursor"
        IFS=/
    done
    IFS=$old_ifs
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

unit_rel=etc/systemd/system/sail.service
env_rel=etc/sail/sail.env
config_rel=etc/sail/config.json
dropin_rel=etc/systemd/system/sail.service.d/10-tun-transparent.conf
manifest_rel=var/lib/sail-systemd-package/manifest
for rel in "$unit_rel" "$env_rel" "$config_rel" "$dropin_rel" "$manifest_rel"; do
    assert_safe_target "$rel"
done

preflight_managed() {
    src=$1 dest=$2
    if [ -e "$dest" ] && { [ ! -f "$dest" ] || ! cmp -s "$src" "$dest"; }; then
        die "refusing to overwrite a different existing managed file: $dest"
    fi
}
preflight_managed "$unit_rendered" "$root/$unit_rel"
if [ "$mode" = tun ]; then
    preflight_managed "$script_dir/sail-tun-transparent.conf" "$root/$dropin_rel"
elif [ -e "$root/$dropin_rel" ]; then
    die "TUN privilege drop-in exists; uninstall it before installing ordinary mode"
fi

env_was_absent=false
[ -e "$root/$env_rel" ] || env_was_absent=true
env_is_managed=$env_was_absent
if [ "$env_is_managed" = false ] && [ -f "$root/$manifest_rel" ] && \
    grep -Eq "^[0-9a-fA-F]+  $env_rel$" "$root/$manifest_rel"; then
    env_is_managed=true
fi

{
    printf '%s  %s\n' "$(hash_file "$unit_rendered")" "$unit_rel"
    if [ "$env_is_managed" = true ]; then
        printf '%s  %s\n' "$(hash_file "$script_dir/sail.env.example")" "$env_rel"
    fi
    if [ "$mode" = tun ]; then
        printf '%s  %s\n' "$(hash_file "$script_dir/sail-tun-transparent.conf")" "$dropin_rel"
    fi
} >"$manifest_rendered"
preflight_managed "$manifest_rendered" "$root/$manifest_rel"

install_one() {
    src=$1 dest=$2 mode_bits=$3 policy=$4
    if [ -e "$dest" ]; then
        if [ "$policy" = preserve ]; then
            say "preserve $dest"
        else
            say "unchanged $dest"
        fi
        return
    fi
    if [ "$dry_run" = true ]; then
        say "would install $dest ($mode_bits)"
        return
    fi
    mkdir -p "$(dirname -- "$dest")"
    install -m "$mode_bits" "$src" "$dest"
    say "installed $dest"
}

install_one "$config_source" "$root/$config_rel" 0640 preserve
install_one "$script_dir/sail.env.example" "$root/$env_rel" 0640 preserve
install_one "$unit_rendered" "$root/$unit_rel" 0644 managed
if [ "$mode" = tun ]; then
    install_one "$script_dir/sail-tun-transparent.conf" "$root/$dropin_rel" 0644 managed
fi
install_one "$manifest_rendered" "$root/$manifest_rel" 0644 managed

if [ "$dry_run" = true ]; then
    say "dry-run complete; destination was not changed"
else
    say "installation complete; no service was enabled, started, or reloaded"
fi
