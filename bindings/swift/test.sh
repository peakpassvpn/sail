#!/bin/sh
# Builds sail-ffi's static library and runs the Swift package's tests
# against it, on macOS. The package's manifest is the repository's root
# Package.swift.
#   bindings/swift/test.sh [extra swift test arguments]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$here/../..
cargo build -p sail-ffi --manifest-path "$root/Cargo.toml"
target=$(cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml" |
    sed -E 's/.*"target_directory":"([^"]*)".*/\1/')
# The static library alone: next to the dynamic one, the linker takes that.
lib=$(mktemp -d)
trap 'rm -rf "$lib"' EXIT
cp "$target/debug/libsail.a" "$lib/"
cd "$root"
# A test that hangs fails the run, after 10 minutes, rather than holding
# the machine.
perl -e 'alarm shift; exec @ARGV' 600 swift test -Xlinker -L"$lib" "$@"
