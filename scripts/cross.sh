#!/usr/bin/env bash
#
# Runs cargo for TARGET with the toolchain scripts/install_cross_toolchain.sh
# installed, on an x86_64 Linux host:
#
#   scripts/cross.sh <target> <cargo subcommand> [args...]
#   scripts/cross.sh aarch64-unknown-linux-musl build --release -p sail-cli
#   scripts/cross.sh aarch64-unknown-linux-musl test -p sail
#
# It points the cc crate (CC_/CXX_/AR_<target>) and cargo's linker at the
# cross toolchain. btls-sys hands the same CC_/CXX_ to BoringSSL's CMake as
# CMAKE_{C,CXX}_COMPILER, and for Android adds the NDK's CMake toolchain file
# through ANDROID_NDK_HOME. Both compilers matter: BoringSSL is mostly C++,
# and a missing CXX_<target> makes CMake fall back to the host's c++.
#
# `test` and `run` go through a runner: qemu-user for arm/aarch64, wine for
# windows; x86_64 and i686 musl binaries are static and run on the host.

set -euo pipefail

target=${1:?usage: $0 <target> <cargo subcommand> [args...]}
shift

BASE=$(cd "$(dirname "$0")" && pwd)
SAIL_CROSS_DIR=${SAIL_CROSS_DIR:-$HOME/.sail-cross}
MUSL_CROSS_TAG=20260823
# The nightly mipsel's std is built with; install_cross_toolchain.sh's.
SAIL_NIGHTLY=nightly-2026-10-02
NDK_VERSION=r27d
ANDROID_API=21

t=${target//-/_}
T=$(echo "$t" | tr '[:lower:]' '[:upper:]')

set_toolchain() {
	local cc=$1 cxx=$2 ar=$3
	export "CC_$t=$cc" "CXX_$t=$cxx" "AR_$t=$ar" "CARGO_TARGET_${T}_LINKER=$cc"
}

case $target in
*-linux-musl*)
	# musl-cross's name for the toolchain: mipsel's is soft-float.
	case $target in
	mipsel-unknown-linux-musl) tc=mipsel-unknown-linux-muslsf ;;
	*) tc=$target ;;
	esac
	root=$SAIL_CROSS_DIR/musl-$MUSL_CROSS_TAG/$tc
	export PATH=$root/bin:$PATH
	set_toolchain "$tc-gcc" "$tc-g++" "$tc-ar"
	# btls-sys runs bindgen, i.e. the host's libclang, over BoringSSL's
	# headers; without the musl sysroot it reads the host's glibc headers,
	# which only happen to work for x86_64. It also becomes CMAKE_SYSROOT,
	# the sysroot GCC uses anyway.
	export "BORING_BSSL_SYSROOT_$t=$root/$tc/sysroot"
	case $target in
	# This GCC targets a plain i686, without SSE2, and BoringSSL's x86
	# assembly needs it; Rust's i686 targets assume it anyway.
	i686-*) export "CFLAGS_$t=-msse2" "CXXFLAGS_$t=-msse2" ;;
	aarch64-*) export "CARGO_TARGET_${T}_RUNNER=qemu-aarch64" ;;
	armv7-*) export "CARGO_TARGET_${T}_RUNNER=qemu-arm" ;;
	mipsel-*) export "CARGO_TARGET_${T}_RUNNER=qemu-mipsel" ;;
	arm-*)
		export "CARGO_TARGET_${T}_RUNNER=qemu-arm"
		# ARMv6 has no atomic instructions libstdc++ can inline; it calls
		# libgcc's __sync_* helpers, and Rust links static musl binaries
		# with -nodefaultlibs, so libgcc has to be asked for.
		export "CARGO_TARGET_${T}_RUSTFLAGS=-C link-arg=-lgcc"
		;;
	esac
	;;
x86_64-pc-windows-gnu)
	# The win32 thread model, named so it does not hang on which one the
	# distribution makes the default.
	set_toolchain x86_64-w64-mingw32-gcc-win32 x86_64-w64-mingw32-g++-win32 x86_64-w64-mingw32-ar
	# CMake takes the NASM it builds BoringSSL's assembly with from here.
	export ASM_NASM=$BASE/nasm_no_pthread.sh
	# btls-sys links libstdc++ as a dylib, so sail.exe would need
	# libstdc++-6.dll next to it. Link the archive instead; the directory
	# it is in has the GCC version in its name.
	libstdcxx=$(x86_64-w64-mingw32-g++-win32 -print-file-name=libstdc++.a)
	export "BORING_BSSL_RUST_CPPLIB_$t=static=stdc++"
	export "CARGO_TARGET_${T}_RUSTFLAGS=-L native=$(dirname "$libstdcxx")"
	export "CARGO_TARGET_${T}_RUNNER=wine"
	export WINEDEBUG=${WINEDEBUG:--all}
	;;
*-linux-android*)
	ndk=$SAIL_CROSS_DIR/android-ndk-$NDK_VERSION
	bin=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
	case $target in
	armv7-linux-androideabi) triple=armv7a-linux-androideabi$ANDROID_API ;;
	*) triple=$target$ANDROID_API ;;
	esac
	# The compilers are the NDK's plain clang and clang++, given the
	# API-level triple as a flag, rather than the $triple-clang wrappers:
	# btls-sys passes CC_/CXX_ to CMake as CMAKE_{C,CXX}_COMPILER alongside
	# the NDK's toolchain file, which picks bin/clang itself. When the two
	# differ CMake drops its cache and configures again without the -D
	# options, ANDROID_ABI among them, and BoringSSL comes out for the
	# default ABI, armeabi-v7a, whatever the target.
	set_toolchain "$bin/clang" "$bin/clang++" "$bin/llvm-ar"
	export "CFLAGS_$t=--target=$triple" "CXXFLAGS_$t=--target=$triple"
	export "CARGO_TARGET_${T}_LINKER=$bin/$triple-clang"
	# btls-sys finds the NDK, its CMake toolchain file and its sysroot for
	# bindgen through this. sail-ffi's bindgen (android/log.h) needs the
	# sysroot given.
	export ANDROID_NDK_HOME=$ndk
	export "BINDGEN_EXTRA_CLANG_ARGS_$t=--sysroot=$ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
	;;
*)
	echo "unsupported target: $target" >&2
	exit 1
	;;
esac

# Flags a caller adds, such as a release's path remapping, joined to the
# ones above: RUSTFLAGS would replace them, -lgcc and -L native among them.
if [ -n "${SAIL_RUSTFLAGS:-}" ]; then
	flags=CARGO_TARGET_${T}_RUSTFLAGS
	export "$flags=${!flags:-} $SAIL_RUSTFLAGS"
fi

sub=${1:?usage: $0 <target> <cargo subcommand> [args...]}
shift
case $target in
# Tier 3: std built from source by the pinned nightly.
# Its static link (+crt-static, as a release asks) takes the C runtime's
# start files and libunwind from the musl-cross toolchain, since a std
# built with -Zbuild-std ships none of its own (install_cross_toolchain.sh
# gives that toolchain a libunwind).
mipsel-*)
	flags=CARGO_TARGET_${T}_RUSTFLAGS
	export "$flags=${!flags:-} -C link-self-contained=no"
	exec cargo "+$SAIL_NIGHTLY" "$sub" -Zbuild-std=std,panic_abort --target "$target" "$@"
	;;
*) exec cargo "$sub" --target "$target" "$@" ;;
esac
