#!/usr/bin/env bash
# Builds what a release ships for Apple systems, on macOS:
#   - sail for macOS, Apple silicon and Intel in one file, packaged by
#     package-cli.sh as macos-universal;
#   - SailC.xcframework: sail-ffi's static library for iOS, the iOS
#     simulator and macOS, with sail.h as the C module SailC that
#     bindings/swift imports. SwiftPM takes a binary target's name from
#     its XCFramework's, so both are SailC.
#
#   scripts/release/build-apple.sh <version> <out dir>
#
# Writes <out dir>/ship, <out dir>/symbols and <out dir>/ids.txt, as the
# other release scripts do. Needs SOURCE_DATE_EPOCH, Xcode, GNU tar (gtar)
# and the Rust targets below.

set -euo pipefail

version=$1
mkdir -p "$2/ship" "$2/symbols"
out=$(cd "$2" && pwd)

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

: "${SOURCE_DATE_EPOCH:?}"
# bindings/swift's platforms.
export MACOSX_DEPLOYMENT_TARGET=13.0
export IPHONEOS_DEPLOYMENT_TARGET=15.0
export CFG_COMMIT_HASH CFG_COMMIT_DATE
CFG_COMMIT_HASH=$(git log --pretty=format:'%h' -n 1)
CFG_COMMIT_DATE=$(git log --format="%ci" -n 1)
# No build machine's paths in what ships. rustc writes each file's dSYM
# itself (packed): dsymutil run later cannot find the objects LTO removed.
sysroot=$(rustc --print sysroot)
export RUSTFLAGS="--remap-path-prefix=$ROOT=/sail --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$sysroot=/rust"
export CARGO_PROFILE_DIST_SPLIT_DEBUGINFO=packed

MACOS="aarch64-apple-darwin x86_64-apple-darwin"
IOS=aarch64-apple-ios
SIMULATOR="aarch64-apple-ios-sim x86_64-apple-ios"

work=$(mktemp -d)

# sail for macOS, both architectures in one file, and their dSYMs in one.
for target in $MACOS; do
	cargo build --locked --profile dist -p sail-cli --target "$target"
done
lipo -create target/{aarch64,x86_64}-apple-darwin/dist/sail -output "$work/sail"
dsym=$work/sail.dSYM
cp -RL target/aarch64-apple-darwin/dist/sail.dSYM "$dsym"
dwarf=$(ls "$dsym"/Contents/Resources/DWARF/*)
lipo -create "$dwarf" target/x86_64-apple-darwin/dist/sail.dSYM/Contents/Resources/DWARF/* \
	-output "$dwarf.universal"
mv "$dwarf.universal" "$dwarf"
DSYM=$dsym "$ROOT/scripts/release/package-cli.sh" macos-universal "$version" "$work/sail" "$out"

# sail-ffi's static library, a slice for each platform.
for target in $MACOS $IOS $SIMULATOR; do
	cargo build --locked --profile dist -p sail-ffi --target "$target"
done
# Each thin library keeps its symbols but not its debug information (the
# app that links it makes the dSYM); the full one goes with the symbols.
# Split before lipo: split-symbols.sh tells a thin archive by its magic.
for target in $MACOS $IOS $SIMULATOR; do
	mkdir -p "$work/$target"
	cp "target/$target/dist/libsail.a" "$work/$target/libsail.a"
	"$ROOT/scripts/release/split-symbols.sh" "$work/$target/libsail.a" "$work/symbols-$target" >/dev/null
	mv "$work/symbols-$target/libsail.a" "$out/symbols/libsail-$target.a"
done
mkdir -p "$work/macos" "$work/ios" "$work/ios-simulator"
lipo -create "$work"/{aarch64,x86_64}-apple-darwin/libsail.a -output "$work/macos/libsail.a"
cp "$work/$IOS/libsail.a" "$work/ios/libsail.a"
lipo -create "$work"/aarch64-apple-ios-sim/libsail.a "$work"/x86_64-apple-ios/libsail.a \
	-output "$work/ios-simulator/libsail.a"

# The C module bindings/swift/Sources/SailC declares, over sail.h itself.
headers=$work/headers
mkdir -p "$headers"
cp sail-ffi/include/sail.h "$headers/"
sed -e 's|header "shim.h"|header "sail.h"|' -e 's|module SailC \[system\]|module SailC|' \
	bindings/swift/Sources/SailC/module.modulemap >"$headers/module.modulemap"
grep -q 'header "sail.h"' "$headers/module.modulemap" ||
	{ echo "build-apple: SailC's module map changed shape" >&2; exit 1; }

xcodebuild -create-xcframework \
	-library "$work/ios/libsail.a" -headers "$headers" \
	-library "$work/ios-simulator/libsail.a" -headers "$headers" \
	-library "$work/macos/libsail.a" -headers "$headers" \
	-output "$work/SailC.xcframework"

# The zip SwiftPM fetches: fixed order and times. Its SHA-256 is the
# checksum Package.swift gives.
stamp=$(TZ=UTC date -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)
(
	cd "$work"
	find SailC.xcframework -exec touch -h -t "$stamp" {} +
	find SailC.xcframework | LC_ALL=C sort | TZ=UTC zip -q -X -D -@ "$out/ship/SailC.xcframework.zip"
)
echo "SailC.xcframework.zip " >>"$out/ids.txt"
