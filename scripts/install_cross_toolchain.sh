#!/usr/bin/env bash
#
# Installs what scripts/cross.sh needs to build for TARGET on an x86_64
# Linux host (Debian/Ubuntu): the Rust target, and a C/C++ toolchain for it,
# since BoringSSL (btls-sys) is C++ built with CMake.
#
#   scripts/install_cross_toolchain.sh <target> [--run]
#
# --run also installs what runs the target's binaries on this host, for
# `scripts/cross.sh <target> test`: qemu-user for arm/aarch64, wine for
# windows.
#
# Downloaded toolchains go under $SAIL_CROSS_DIR (default ~/.sail-cross),
# which CI caches. Versions are pinned here and checked by hash.

set -euo pipefail

target=${1:?usage: $0 <target> [--run]}
run=${2:-}

SAIL_CROSS_DIR=${SAIL_CROSS_DIR:-$HOME/.sail-cross}

# musl: GCC + musl + libstdc++ from https://github.com/cross-tools/musl-cross.
MUSL_CROSS_TAG=20260823
# mipsel is tier 3: no prebuilt std, so a pinned nightly builds it from
# rust-src (-Zbuild-std); the same as cross.sh's.
SAIL_NIGHTLY=nightly-2026-10-02
# Android: the NDK, r27 is the current LTS. Google publishes SHA-1 only.
NDK_VERSION=r27d
NDK_SHA1=22105e410cf29afcf163760cc95522b9fb981121

sudo=
if [ "$(id -u)" != 0 ]; then
	sudo=sudo
fi

apt_install() {
	# Only what is missing, so a warm host does not touch apt.
	local missing=()
	for p in "$@"; do
		dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
	done
	if [ ${#missing[@]} -gt 0 ]; then
		$sudo apt-get update -qq
		DEBIAN_FRONTEND=noninteractive $sudo apt-get install -y -qq --no-install-recommends "${missing[@]}"
	fi
}

# musl-cross's name for a target's toolchain: Rust's mipsel musl target is
# soft-float, as OpenWrt's mipsel packages are.
musl_toolchain() {
	case $1 in
	mipsel-unknown-linux-musl) echo mipsel-unknown-linux-muslsf ;;
	*) echo "$1" ;;
	esac
}

musl_sha256() {
	case $1 in
	x86_64-unknown-linux-musl) echo 9752ecb10bafc0fc2ea75b3ed864a78137f3e5ba9b1579f1f16923d444c48096 ;;
	i686-unknown-linux-musl) echo 685a00f2b4273894adc97343620647d31458c8097abc37c4043d287815f1837e ;;
	aarch64-unknown-linux-musl) echo 0fc483607d9ed83bdf75e7539bacc66721d7e37ca606377aed6a90cef82e45da ;;
	armv7-unknown-linux-musleabihf) echo 3e0c17cd4da0799102668dcbe4b041be740c61e93df80c0e1c36573ceecbe4ac ;;
	arm-unknown-linux-musleabi) echo d9542873fbe7a2239418d1a2798ef3dece6f0679ba218721880b25a051e61cfd ;;
	armv7-unknown-linux-musleabi) echo c330c0740878eec5b434e9cce19db548dedae41544048f59010f7e509e63332a ;;
	mipsel-unknown-linux-muslsf) echo f07b85de446e4e3e30d5561c4efc4061c364aa7d0237736b627fe9a05b5af2a7 ;;
	*)
		echo "no musl toolchain pinned for $1" >&2
		exit 1
		;;
	esac
}

install_musl() {
	local tc
	tc=$(musl_toolchain "$target")
	local dir=$SAIL_CROSS_DIR/musl-$MUSL_CROSS_TAG
	if [ ! -x "$dir/$tc/bin/$tc-g++" ]; then
		mkdir -p "$dir"
		local tarball=$dir/$tc.tar.xz
		curl -fsSL --retry 5 --retry-all-errors --speed-limit 10000 --speed-time 60 -C - -o "$tarball" \
			"https://github.com/cross-tools/musl-cross/releases/download/$MUSL_CROSS_TAG/$tc.tar.xz"
		echo "$(musl_sha256 "$tc")  $tarball" | sha256sum -c -
		tar -C "$dir" -xJf "$tarball"
		rm "$tarball"
	fi
	# A statically linked std asks for -lunwind, which a prebuilt std
	# brings and one built with -Zbuild-std (mipsel's) does not. GCC's
	# unwinder implements the same _Unwind_* interface: it is linked under
	# that name.
	case $target in
	mipsel-*)
		local eh
		eh=$(find "$dir/$tc/lib/gcc/$tc" -name libgcc_eh.a | head -n 1)
		[ -n "$eh" ] || { echo "no libgcc_eh.a in $dir/$tc" >&2; exit 1; }
		# The archive's directories are read-only; as a user (not root,
		# as in a CI runner) the link needs its own written to.
		chmod u+w "$(dirname "$eh")"
		ln -sf libgcc_eh.a "$(dirname "$eh")/libunwind.a"
		;;
	esac
	if [ "$run" = --run ]; then
		case $target in
		x86_64-* | i686-*) ;; # the host runs them
		*) apt_install qemu-user ;;
		esac
	fi
}

install_windows() {
	apt_install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 nasm
	if [ "$run" = --run ]; then
		apt_install wine wine64
	fi
}

install_android() {
	local dir=$SAIL_CROSS_DIR/android-ndk-$NDK_VERSION
	if [ ! -d "$dir/toolchains/llvm/prebuilt/linux-x86_64/bin" ]; then
		apt_install unzip
		mkdir -p "$SAIL_CROSS_DIR"
		local zip=$SAIL_CROSS_DIR/ndk.zip
		curl -fsSL --retry 5 --retry-all-errors --speed-limit 10000 --speed-time 60 -C - -o "$zip" \
			"https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-linux.zip"
		echo "$NDK_SHA1  $zip" | sha1sum -c -
		unzip -q "$zip" -d "$SAIL_CROSS_DIR"
		rm "$zip"
	fi
}

# CMake builds BoringSSL; bindgen (btls-sys, sail-ffi) loads libclang.
apt_install cmake libclang-dev

case $target in
*-linux-musl*) install_musl ;;
x86_64-pc-windows-gnu) install_windows ;;
*-linux-android*) install_android ;;
*)
	echo "unsupported target: $target" >&2
	exit 1
	;;
esac

case $target in
mipsel-*) rustup toolchain install "$SAIL_NIGHTLY" --profile minimal --component rust-src ;;
*) rustup target add "$target" ;;
esac
