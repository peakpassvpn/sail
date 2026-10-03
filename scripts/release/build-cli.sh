#!/usr/bin/env bash
# Builds sail-cli for a release target and packages it; the release
# workflow runs it twice for the reproducibility check.
#
#   scripts/release/build-cli.sh <target> <version> <out dir> [router]
#
# Needs SOURCE_DATE_EPOCH, and the cross toolchain installed.

set -euo pipefail

target=$1
version=$2
out=$3

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

: "${SOURCE_DATE_EPOCH:?}"
CFG_COMMIT_HASH=$(git log --pretty=format:'%h' -n 1)
CFG_COMMIT_DATE=$(git log --format="%ci" -n 1)
# No build machine's paths in what ships.
SAIL_RUSTFLAGS="--remap-path-prefix=$ROOT=/sail"
SAIL_RUSTFLAGS+=" --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
SAIL_RUSTFLAGS+=" --remap-path-prefix=$(rustc --print sysroot)=/rust"
export CFG_COMMIT_HASH CFG_COMMIT_DATE SAIL_RUSTFLAGS

# A router build: every feature, sized by the dist-router profile; on
# mipsel linked statically (+crt-static), whose libc a router's may not be.
variant=${4:-}
profile=dist
case $variant in
'') ;;
router)
	profile=dist-router
	case $target in
	mipsel-*) SAIL_RUSTFLAGS+=" -C target-feature=+crt-static" ;;
	esac
	;;
*) echo "build-cli: unknown variant: $variant" >&2 && exit 2 ;;
esac
scripts/cross.sh "$target" build --locked --profile "$profile" -p sail-cli
case $target in
*windows*) built=target/$target/$profile/sail.exe ;;
*) built=target/$target/$profile/sail ;;
esac
case $target in
mipsel-*)
	file "$built" | grep -q 'statically linked' ||
		{ echo "build-cli: $built is not statically linked: $(file "$built")" >&2; exit 1; }
	;;
esac
scripts/release/package-cli.sh "$target" "$version" "$built" "$out" "$variant"
