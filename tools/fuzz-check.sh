#!/usr/bin/env bash
# The fuzz workspaces build apart from sail's, on nightly with sanitizers,
# so nothing else compiles them. This keeps them buildable: each one's
# [patch.crates-io] must be the workspace's, and each must `cargo check` on
# the workspace's toolchain (libfuzzer-sys builds without the sanitizers;
# no fuzzing here).
#
# A fuzz workspace that tracks no Cargo.lock of its own is checked against
# the workspace's, so that it builds what sail ships.
#
#   tools/fuzz-check.sh             the drift check and the builds
#   tools/fuzz-check.sh --patches   the drift check alone
set -euo pipefail

cd "$(dirname "$0")/.."

WORKSPACES=(fuzz sail-netstack/fuzz)

python3 - "${WORKSPACES[@]}" <<'PY'
import sys, tomllib

def patches(path):
    with open(path, "rb") as f:
        return tomllib.load(f).get("patch", {}).get("crates-io", {})

root = patches("Cargo.toml")
drift = False
for ws in sys.argv[1:]:
    ours = patches(f"{ws}/Cargo.toml")
    if ours != root:
        drift = True
        print(f"{ws}/Cargo.toml: [patch.crates-io] differs from the workspace's")
        for name in sorted(set(root) | set(ours)):
            if root.get(name) != ours.get(name):
                print(f"  {name}: workspace {root.get(name)!r}, here {ours.get(name)!r}")
sys.exit(1 if drift else 0)
PY
echo "fuzz-check: [patch.crates-io] matches in ${WORKSPACES[*]}"

[ "${1:-}" = "--patches" ] && exit 0

for ws in "${WORKSPACES[@]}"; do
    echo "::group::cargo check $ws"
    if git ls-files --error-unmatch "$ws/Cargo.lock" >/dev/null 2>&1; then
        cargo check --locked --manifest-path "$ws/Cargo.toml" --bins
    else
        cp Cargo.lock "$ws/Cargo.lock"
        cargo check --manifest-path "$ws/Cargo.toml" --bins
        rm -f "$ws/Cargo.lock"
    fi
    echo "::endgroup::"
done
