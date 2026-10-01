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
manifest=$ROOT/bindings/swift/Package.swift
# What SwiftPM checks a binary target by: the zip's SHA-256.
checksum=$(sha256sum "$zip" | cut -d' ' -f1)
url=https://github.com/$repository/releases/download/v$version/SailC.xcframework.zip

line='        .systemLibrary(name: "SailC", path: "Sources/SailC"),'
grep -qxF "$line" "$manifest" ||
	{ echo "swift-package: Package.swift has no SailC system library to replace" >&2; exit 1; }
binary="        .binaryTarget(name: \"SailC\", url: \"$url\", checksum: \"$checksum\"),"
awk -v line="$line" -v binary="$binary" '$0 == line { print binary; next } { print }' \
	"$manifest" >"$manifest.new"
mv "$manifest.new" "$manifest"
echo "$checksum"
