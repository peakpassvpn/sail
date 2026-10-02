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
#   tools/fuzz-check.sh --sync      writes the workspace's [patch.crates-io]
#                                   into each fuzz workspace, after a bump
set -euo pipefail

cd "$(dirname "$0")/.."

WORKSPACES=(fuzz sail-netstack/fuzz)

python3 - "${1:-}" "${WORKSPACES[@]}" <<'PY'
import re, sys, tomllib

mode, workspaces = sys.argv[1], sys.argv[2:]
TABLE = re.compile(r"^\[patch\.crates-io\]\n.*?(?=^\[|\Z)", re.S | re.M)

def patches(path):
    with open(path, "rb") as f:
        return tomllib.load(f).get("patch", {}).get("crates-io", {})

if mode == "--sync":
    block = TABLE.search(open("Cargo.toml").read()).group(0).rstrip() + "\n"
    for ws in workspaces:
        path = f"{ws}/Cargo.toml"
        text = open(path).read()
        if TABLE.search(text):
            text = TABLE.sub(lambda _: block + "\n", text, count=1)
        else:
            text = text.rstrip() + "\n\n" + block
        open(path, "w").write(re.sub(r"\n{3,}", "\n\n", text).rstrip() + "\n")

root = patches("Cargo.toml")
drift = False
for ws in workspaces:
    ours = patches(f"{ws}/Cargo.toml")
    if ours != root:
        drift = True
        print(f"{ws}/Cargo.toml: [patch.crates-io] differs from the workspace's")
        for name in sorted(set(root) | set(ours)):
            if root.get(name) != ours.get(name):
                print(f"  {name}: workspace {root.get(name)!r}, here {ours.get(name)!r}")
if drift:
    print("run tools/fuzz-check.sh --sync, which writes the workspace's [patch.crates-io] into them")
sys.exit(1 if drift else 0)
PY
echo "fuzz-check: [patch.crates-io] matches in ${WORKSPACES[*]}"

case "${1:-}" in --patches|--sync) exit 0 ;; esac

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
