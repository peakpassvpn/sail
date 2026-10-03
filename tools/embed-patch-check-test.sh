#!/bin/sh
# Tests tools/embed-patch-check.py on scratch workspaces that depend on this
# checkout's sail: directly, through a crate behind an optional feature, and
# with an entry of [patch] left out. Resolves the dependency graph only;
# nothing is compiled.
#
#   tools/embed-patch-check-test.sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
check="$root/tools/embed-patch-check.py"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

patch_section() {
    sed -n '/^\[patch.crates-io\]/,/^\[/p' "$root/Cargo.toml" | sed '$d'
}

fails() {
    if "$@" >"$scratch/out" 2>&1; then
        echo "FAIL: passed: $*"
        cat "$scratch/out"
        exit 1
    fi
}

# A crate that depends on sail, behind its feature `sail`.
mkdir -p "$scratch/core/src" "$scratch/host/src"
echo 'pub fn f() {}' >"$scratch/core/src/lib.rs"
cat >"$scratch/core/Cargo.toml" <<EOF
[package]
name = "core"
version = "0.0.0"
edition = "2021"

[dependencies]
sail = { path = "$root/sail", default-features = false, optional = true }
EOF

# The host, which reaches it through its own optional feature rust-core.
echo 'fn main() {}' >"$scratch/host/src/main.rs"
{
    cat <<EOF
[package]
name = "host"
version = "0.0.0"
edition = "2021"

[features]
rust-core = ["dep:core", "core/sail"]

[dependencies]
core = { path = "../core", optional = true }

[workspace]

EOF
    patch_section
} >"$scratch/host/Cargo.toml"
(cd "$scratch/host" && cargo generate-lockfile -q)

# Found behind the optional feature: by default (all features), and with
# the feature named.
python3 "$check" "$scratch/host"
python3 "$check" "$scratch/host" -- --features rust-core
# Not with the default features alone.
fails python3 "$check" "$scratch/host" --
grep -q "not among the dependencies" "$scratch/out"

# An entry left out is named.
sed -i.bak '/^route_manager = /d' "$scratch/host/Cargo.toml"
fails python3 "$check" "$scratch/host"
grep -q "route_manager: missing" "$scratch/out"

echo "embed-patch-check-test: ok"
