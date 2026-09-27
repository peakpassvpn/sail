#!/usr/bin/env bash
#
# Builds libsail.so for Android and its C header into
# target/sail-android-libs, on an x86_64 Linux host.
#
#   scripts/build_android.sh [debug|release] [targets]
#
# The NDK and the Rust targets come from scripts/install_cross_toolchain.sh,
# which this runs for each target; scripts/cross.sh sets the compilers.

set -euo pipefail

name=sail
package=sail-ffi

mode=${1:-release}
targets=${2:-"aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"}

BASE=$(cd "$(dirname "$0")" && pwd)
ROOT=$BASE/..

profile_args=(--release)
profile=release
if [ "$mode" = debug ]; then
	profile_args=()
	profile=debug
fi

for target in $targets; do
	"$BASE/install_cross_toolchain.sh" "$target"
	"$BASE/cross.sh" "$target" build -p $package "${profile_args[@]}"
done

android_libs=$ROOT/target/sail-android-libs
mkdir -p "$android_libs"
for target in $targets; do
	cp "$ROOT/target/$target/$profile/lib$name.so" "$android_libs/lib$name-$target.so"
done
cbindgen \
	--config "$ROOT/$package/cbindgen.toml" \
	"$ROOT/$package/src/lib.rs" >"$android_libs/$name.h"
