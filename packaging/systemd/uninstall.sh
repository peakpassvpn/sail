#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage: uninstall.sh --root DIR [--dry-run] [--allow-system-root]

Remove only unchanged files recorded by install.sh. Configuration is never
removed. Nothing is stopped, disabled, or daemon-reloaded.
EOF
}
die() { printf '%s\n' "uninstall.sh: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

root=
dry_run=false
allow_system_root=false
while [ "$#" -gt 0 ]; do
    case $1 in
        --root) [ "$#" -ge 2 ] || die "--root needs a value"; root=$2; shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --allow-system-root) allow_system_root=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$root" ] || die "--root is required"
case $root in /*) ;; *) die "--root must be absolute" ;; esac
case $root in *'/../'*|*/..|*'/./'*|*/.) die "--root must not contain . or .. components" ;; esac
[ ! -L "$root" ] || die "--root must not be a symbolic link"
[ -d "$root" ] || die "--root must name an existing directory"
root=$(CDPATH= cd -- "$root" && pwd -P)
if [ "$root" = / ] && [ "$allow_system_root" != true ]; then
    die "refusing --root / without --allow-system-root"
fi

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

manifest=$root/var/lib/sail-systemd-package/manifest
if [ ! -e "$manifest" ]; then
    say "nothing to uninstall; manifest is absent"
    exit 0
fi
[ -f "$manifest" ] && [ ! -L "$manifest" ] || die "manifest is not a safe regular file"

while IFS='  ' read -r expected rel extra; do
    [ -n "$expected" ] || continue
    [ -z "${extra:-}" ] || die "invalid manifest entry"
    case $expected in *[!0-9a-fA-F]*|'') die "invalid manifest hash" ;; esac
    case $rel in
        etc/systemd/system/sail.service|etc/systemd/system/sail.service.d/10-tun-transparent.conf|etc/sail/sail.env) ;;
        *) die "refusing unexpected manifest path: $rel" ;;
    esac
    target=$root/$rel
    [ ! -L "$target" ] || die "refusing symbolic-link target: $target"
    if [ ! -e "$target" ]; then
        say "already absent $target"
    elif [ ! -f "$target" ]; then
        die "refusing non-regular target: $target"
    elif [ "$(hash_file "$target")" != "$expected" ]; then
        say "preserve modified $target"
    elif [ "$dry_run" = true ]; then
        say "would remove $target"
    else
        rm -- "$target"
        say "removed $target"
    fi
done <"$manifest"

if [ "$dry_run" = true ]; then
    say "would remove $manifest"
    say "dry-run complete; destination was not changed"
else
    rm -- "$manifest"
    say "removed $manifest"
    say "configuration and directories were preserved; no service state was changed"
fi
