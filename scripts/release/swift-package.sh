#!/usr/bin/env bash
# Points bindings/swift/Package.swift at a release's XCFramework, for the
# commit a release tags: SailC becomes a binary target, fetched from the
# release with its checksum, where the branch builds it from the source.
#
#   scripts/release/swift-package.sh <repository> <version> <SailC.xcframework.zip>

set -euo pipefail

repository=$1
version=$2
zip=$3

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# The package SwiftPM finds by the repository's URL: the root's, where
# there is one.
manifest=$ROOT/Package.swift
[ -f "$manifest" ] || manifest=$ROOT/bindings/swift/Package.swift
# What SwiftPM checks a binary target by: the zip's SHA-256.
checksum=$(sha256sum "$zip" | cut -d' ' -f1)
url=https://github.com/$repository/releases/download/v$version/SailC.xcframework.zip

# SailC's system library, wherever its path points, once.
pattern='^ *\.systemLibrary\(name: "SailC", path: "[^"]*"\),$'
lines=$(grep -nE "$pattern" "$manifest" | cut -d: -f1)
[ "$(echo "$lines" | grep -c .)" = 1 ] ||
	{ echo "swift-package: $manifest has not one SailC system library to replace" >&2; exit 1; }
binary="        .binaryTarget(name: \"SailC\", url: \"$url\", checksum: \"$checksum\"),"
awk -v n="$lines" -v binary="$binary" 'NR == n { print binary; next } { print }' \
	"$manifest" >"$manifest.new"
mv "$manifest.new" "$manifest"
if ! grep -qF "$binary" "$manifest" || grep -qE "$pattern" "$manifest"; then
	echo "swift-package: SailC was not replaced" >&2
	exit 1
fi
echo "$checksum"
