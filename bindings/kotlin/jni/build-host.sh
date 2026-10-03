#!/bin/sh
# Builds libsail_jni for this host's JVM, for the tests: jni/sail_jni.c
# and sail-ffi's static library, linked into one library.
#   bindings/kotlin/jni/build-host.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$here/../../..
: "${JAVA_HOME:?set JAVA_HOME to a JDK}"
cargo build -p sail-ffi --manifest-path "$root/Cargo.toml"
target=$(cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml" |
    sed -E 's/.*"target_directory":"([^"]*)".*/\1/')
out=$here/../build/jni
mkdir -p "$out"
case $(uname) in
Darwin)
    os=darwin
    lib=libsail_jni.dylib
    flags="-dynamiclib -framework Security -framework CoreFoundation -framework CoreServices -framework SystemConfiguration -lc++ -liconv"
    ;;
*)
    os=linux
    lib=libsail_jni.so
    flags="-shared -fPIC -lpthread -ldl -lm -lstdc++"
    ;;
esac
# shellcheck disable=SC2086
cc -O1 -Wall -Werror -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$os" -I"$root/sail-ffi/include" \
    "$here/sail_jni.c" "$target/debug/libsail.a" $flags -o "$out/$lib"
echo "built $out/$lib"
