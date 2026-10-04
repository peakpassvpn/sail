#!/usr/bin/env bash
# Builds what a release ships for Apple systems, on macOS:
#   - sail for macOS, a file for each architecture (aarch64- and
#     x86_64-apple-darwin), packaged by package-cli.sh as Linux's are;
#   - SailC.xcframework: sail-ffi's static library for iOS, the iOS
#     simulator and macOS, with sail.h as the C module SailC that
#     bindings/swift imports. SwiftPM takes a binary target's name from
#     its XCFramework's, so both are SailC.
#
#   scripts/release/build-apple.sh <version> <out dir>
#       everything, one target after another (a local build);
#   scripts/release/build-apple.sh <version> <out dir> --slice <target>
#       one target: its sail for macOS (darwin targets) and its slice of
#       sail-ffi, the thin library left in <out dir>/lib/<target>; the
#       release runs one job per target side by side;
#   scripts/release/build-apple.sh <version> <out dir> --xcframework <dir>
#       the XCFramework from the slices in <dir>/lib/<target>.
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
export CARGO_PROFILE_DIST_MOBILE_SPLIT_DEBUGINFO=packed

MACOS="aarch64-apple-darwin x86_64-apple-darwin"
IOS=aarch64-apple-ios
SIMULATOR="aarch64-apple-ios-sim x86_64-apple-ios"

work=$(mktemp -d)

# sail for macOS for one darwin target, with its own dSYM.
cli() {
	local target=$1
	cargo build --locked --profile dist -p sail-cli --target "$target"
	mkdir -p "$work/$target"
	cp "target/$target/dist/sail" "$work/$target/sail"
	DSYM="$ROOT/target/$target/dist/sail.dSYM" \
		"$ROOT/scripts/release/package-cli.sh" "$target" "$version" "$work/$target/sail" "$out"
}

# sail-ffi's static library for one target, built with the dist-mobile
# profile (dist, unwinding on a panic: Cargo.toml), left in <out>/lib/<target>; it
# prints the system libraries it needs, which the module map links. The thin
# library keeps its symbols but not its debug information (the app that
# links it makes the dSYM); the full one goes with the symbols. Split before
# lipo: split-symbols.sh tells a thin archive by its magic.
slice() {
	local target=$1
	RUSTFLAGS="$RUSTFLAGS --print native-static-libs" \
		cargo build --locked --profile dist-mobile -p sail-ffi --target "$target"
	mkdir -p "$out/lib/$target"
	cp "target/$target/dist-mobile/libsail.a" "$out/lib/$target/libsail.a"
	"$ROOT/scripts/release/split-symbols.sh" "$out/lib/$target/libsail.a" "$work/symbols-$target" >/dev/null
	mv "$work/symbols-$target/libsail.a" "$out/symbols/libsail-$target.a"
}

# The XCFramework from the slices under $1/lib.
xcframework() {
	local lib=$1/lib
	mkdir -p "$work/macos" "$work/ios" "$work/ios-simulator"
	lipo -create "$lib"/{aarch64,x86_64}-apple-darwin/libsail.a -output "$work/macos/libsail.a"
	cp "$lib/$IOS/libsail.a" "$work/ios/libsail.a"
	lipo -create "$lib"/aarch64-apple-ios-sim/libsail.a "$lib"/x86_64-apple-ios/libsail.a \
		-output "$work/ios-simulator/libsail.a"

	# The C module bindings/swift/Sources/SailC declares, over sail.h itself.
	headers=$work/headers
	mkdir -p "$headers"
	cp sail-ffi/include/sail.h "$headers/"
	# SwiftPM links the XCFramework's libsail.a itself: a `link "sail"` of the
	# module would look for it again, where the linker does not.
	sed -e 's|header "shim.h"|header "sail.h"|' -e 's|module SailC \[system\]|module SailC|' \
		-e '/link "sail"/d' \
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
}

case ${3:-} in
--slice)
	target=${4:?--slice needs a target}
	case $target in *-apple-darwin) cli "$target" ;; esac
	slice "$target"
	;;
--xcframework)
	xcframework "${4:?--xcframework needs the directory of the slices}"
	;;
'')
	for target in $MACOS; do cli "$target"; done
	for target in $MACOS $IOS $SIMULATOR; do slice "$target"; done
	xcframework "$out"
	rm -rf "$out/lib"
	;;
*)
	echo "build-apple: unknown mode $3" >&2; exit 2
	;;
esac
