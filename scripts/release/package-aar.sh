#!/usr/bin/env bash
# Builds sail's AAR from the static libraries the release built, checks it,
# and moves its native libraries' symbols apart.
#
#   scripts/release/package-aar.sh <version> <libs dir> <out dir>
#
# <libs dir> holds <ABI>/libsail.a for arm64-v8a, armeabi-v7a, x86_64 and
# x86. Needs SOURCE_DATE_EPOCH, AGP_VERSION, the NDK the libraries were
# built with (NDK_PATH), Gradle and an Android SDK. Writes:
#   ship/sail-<version>.aar
#   symbols/libsail_jni-<ABI>.so.debug
#   ids.txt  "sail-<version>.aar <build IDs, by ABI>"

set -euo pipefail

version=$1
libs=$(cd "$2" && pwd)
mkdir -p "$3/ship" "$3/symbols"
out=$(cd "$3" && pwd)

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
: "${SOURCE_DATE_EPOCH:?}" "${AGP_VERSION:?}" "${NDK_PATH:?}"
ABIS="arm64-v8a armeabi-v7a x86_64 x86"

# AGP checks the NDK's version against the one it would pick itself.
ndk_version=$(sed -n 's/^Pkg\.Revision *= *//p' "$NDK_PATH/source.properties")
gradle --no-daemon -q -p "$ROOT/bindings/kotlin/android" assembleRelease \
	-Psail.agp="$AGP_VERSION" -Psail.ndkPath="$NDK_PATH" -Psail.ndkVersion="$ndk_version" \
	-Psail.libDir="$libs" -Psail.includeDir="$ROOT/sail-ffi/include"
built=$(ls "$ROOT"/bindings/kotlin/android/build/outputs/aar/*-release.aar)

work=$(mktemp -d)
unzip -q "$built" -d "$work/aar"
llvm=$(echo "$NDK_PATH"/toolchains/llvm/prebuilt/*/bin)

# What the AAR must be: one library an ABI, exporting the JNI functions
# alone and linking no shared C++ runtime; the classes JNI reaches by name;
# the consumer rules as written.
fail=0
for abi in $ABIS; do
	so=$work/aar/jni/$abi/libsail_jni.so
	[ -f "$so" ] || { echo "package-aar: no $abi/libsail_jni.so" >&2; fail=1; continue; }
	extra=$("$llvm/llvm-nm" -D --defined-only "$so" | awk '{ print $NF }' |
		grep -Ev '^(JNI_OnLoad|Java_io_github_peakpassvpn_sail_.*)$' || true)
	[ -z "$extra" ] || { echo "package-aar: $abi exports more: ${extra//$'\n'/ }" >&2; fail=1; }
	if "$llvm/llvm-readelf" -d "$so" | grep NEEDED | grep -q 'libc++_shared'; then
		echo "package-aar: $abi needs libc++_shared.so" >&2
		fail=1
	fi
done
others=$(cd "$work/aar/jni" && find . -name '*.so' ! -name libsail_jni.so)
[ -z "$others" ] || { echo "package-aar: other libraries: $others" >&2; fail=1; }
classes=$(unzip -Z1 "$work/aar/classes.jar")
for class in Native PlatformBridge EventSink SailException; do
	grep -qx "io/github/peakpassvpn/sail/$class.class" <<<"$classes" ||
		{ echo "package-aar: no $class in classes.jar" >&2; fail=1; }
done
cmp -s "$work/aar/proguard.txt" "$ROOT/bindings/kotlin/android/consumer-rules.pro" ||
	{ echo "package-aar: proguard.txt is not consumer-rules.pro" >&2; fail=1; }
[ "$fail" = 0 ] || exit 1

# The symbols apart, as for every other file of the release.
ids=()
for abi in $ABIS; do
	so=$work/aar/jni/$abi/libsail_jni.so
	id=$("$ROOT/scripts/release/split-symbols.sh" "$so" "$work/symbols")
	mv "$work/symbols/libsail_jni.so.debug" "$out/symbols/libsail_jni-$abi.so.debug"
	ids+=("$abi:$id")
	echo "package-aar: $abi libsail_jni.so $(wc -c <"$so") bytes"
done

# Put back together with fixed order and times.
aar=sail-$version.aar
(
	cd "$work/aar"
	find . -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	find . -type f | sed 's|^\./||' | LC_ALL=C sort | TZ=UTC zip -q -X -D -@ "$out/ship/$aar"
)
echo "$aar $(IFS=,; echo "${ids[*]}")" >>"$out/ids.txt"
