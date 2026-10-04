#!/usr/bin/env bash
# Writes THIRD_PARTY_LICENSES.md for a release: every crate in Cargo.lock
# that sail's packages build with, under its license and with its text
# (cargo-about, tools/licences/about.toml and about.hbs), then the
# licenses of the native code crates build in, as those projects ship
# them: BoringSSL (btls-sys), mimalloc (libmimalloc-sys). One file for
# every archive, which may hold less of it (it says so).
#
#   scripts/release/notices.sh <out file>
#
# Needs cargo-about and python3.
set -euo pipefail
out=${1:?usage: $0 <out file>}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
cargo about generate --workspace --locked -c tools/licences/about.toml \
	tools/licences/about.hbs -o "$out"
# Where a crate's source is, by name.
dir_of() {
	cargo metadata --format-version 1 --locked |
		python3 -c 'import json, os, sys
for p in json.load(sys.stdin)["packages"]:
    if p["name"] == sys.argv[1]:
        print(os.path.dirname(p["manifest_path"])); break' "$1"
}
native() {
	local title=$1 file=$2
	[ -s "$file" ] || { echo "notices: no license at $file" >&2; exit 1; }
	{
		printf '## %s\n\n~~~~text\n' "$title"
		cat "$file"
		printf '\n~~~~\n\n'
	} >>"$out"
}
{
	echo "# Native code built into the crates above"
	echo
	echo "This file is the same in every archive, and lists what any of them is"
	echo "built from: an archive may hold less. mimalloc is only in the Linux musl"
	echo "archives other than the MIPS and -router ones, which allocate with musl's own."
	echo
} >>"$out"
native "BoringSSL (built in by btls-sys)" "$(dir_of btls-sys)/deps/boringssl/LICENSE"
mimalloc=$(dir_of libmimalloc-sys)/c_src/mimalloc
for license in "$mimalloc"/*/LICENSE; do
	native "mimalloc $(basename "$(dirname "$license")") (built in by libmimalloc-sys)" "$license"
done
