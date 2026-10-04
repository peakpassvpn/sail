#!/usr/bin/env bash
# Builds sail-ffi's static library for an Android target, for the AAR, and
# prints the system libraries it needs, which jni/CMakeLists.txt links.
#
#   scripts/release/build-lib-android.sh <target> <ABI> <out dir>
#
# Writes <out dir>/<ABI>/libsail.a. Needs SOURCE_DATE_EPOCH, and the NDK
# installed (scripts/install_cross_toolchain.sh).

set -euo pipefail

target=$1
abi=$2
out=$3

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

: "${SOURCE_DATE_EPOCH:?}"
# No build machine's paths in what ships.
SAIL_RUSTFLAGS="--remap-path-prefix=$ROOT=/sail"
SAIL_RUSTFLAGS+=" --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
SAIL_RUSTFLAGS+=" --remap-path-prefix=$(rustc --print sysroot)=/rust"
SAIL_RUSTFLAGS+=" --print native-static-libs"
export SAIL_RUSTFLAGS

# dist-mobile: dist, unwinding on a panic (Cargo.toml).
scripts/cross.sh "$target" build --locked --profile dist-mobile -p sail-ffi
mkdir -p "$out/$abi"
cp "target/$target/dist-mobile/libsail.a" "$out/$abi/libsail.a"
