#!/usr/bin/env bash
#
# nasm, minus `-pthread`. scripts/cross.sh points CMake at this for
# x86_64-pc-windows-gnu: MinGW's GCC accepts -pthread, so CMake's Threads
# package puts it in Threads::Threads' compile options, which BoringSSL's
# libcrypto passes on to every language it builds, NASM included. NASM
# reads it as `-p thread`, pre-include a file named "thread", and fails.
args=()
for a in "$@"; do
	[ "$a" = -pthread ] || args+=("$a")
done
exec nasm "${args[@]}"
