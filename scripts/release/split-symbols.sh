#!/usr/bin/env bash
# Moves the debug information out of a built file, for a release: the file
# is stripped in place and its symbols go to <out dir>, named after it.
# On Apple, DSYM names the file's dSYM when it is not <file>.dSYM.
# Prints the file's ID, the one a crash report gives (ELF build ID, Mach-O
# UUID; a PE or a static library has none, and prints nothing).
#
#   scripts/release/split-symbols.sh <file> <out dir>
#
# ELF and PE use llvm-objcopy from the toolchain's llvm-tools component, so
# every target is split the same way without its own binutils. Mach-O uses
# Xcode's dsymutil and strip.

set -euo pipefail

file=$1
out=$2
mkdir -p "$out"
name=$(basename "$file")

llvm_tool() {
	local sysroot host
	sysroot=$(rustc --print sysroot)
	host=$(rustc -vV | sed -n 's/^host: //p')
	echo "$sysroot/lib/rustlib/$host/bin/$1"
}

case $(head -c 4 "$file" | od -An -tx1 | tr -d ' \n') in
7f454c46) # ELF
	objcopy=$(llvm_tool llvm-objcopy)
	"$objcopy" --only-keep-debug "$file" "$out/$name.debug"
	"$objcopy" --strip-all --add-gnu-debuglink="$out/$name.debug" "$file"
	"$(llvm_tool llvm-readobj)" --notes "$file" |
		sed -n 's/^ *Build ID: *//p' | head -1
	;;
cffaedfe | cefaedfe | cafebabe) # Mach-O, thin or universal
	# The dSYM rustc wrote beside the file, built with
	# CARGO_PROFILE_DIST_SPLIT_DEBUGINFO=packed (Apple only: elsewhere it
	# would move the debug information out of the file), as dsymutil run
	# here cannot find the objects LTO wrote and removed. Or, for a file
	# lipo put together, one dsymutil makes of the parts' dSYMs.
	dsym=${DSYM:-$file.dSYM}
	[ -d "$dsym" ] || { echo "split-symbols: no $dsym" >&2; exit 1; }
	# cargo puts a link to the one in deps/ beside the file.
	cp -RL "$dsym" "$out/$name.dSYM"
	strip -S "$file"
	dwarfdump --uuid "$out/$name.dSYM" | awk '{ print $2 }' | paste -sd, -
	;;
213c6172) # A static library: the app that links it makes the dSYM or
	# .debug, so the shipped one keeps its symbols but not its debug
	# information, and the full one goes beside the symbols.
	cp "$file" "$out/$name"
	case $(uname -s) in
	Darwin) strip -S "$file" ;;
	*) "$(llvm_tool llvm-objcopy)" --strip-debug "$file" ;;
	esac
	;;
4d5a*) # PE
	objcopy=$(llvm_tool llvm-objcopy)
	"$objcopy" --only-keep-debug "$file" "$out/$name.debug"
	"$objcopy" --strip-all --add-gnu-debuglink="$out/$name.debug" "$file"
	;;
*)
	echo "split-symbols: $file: not ELF, Mach-O or PE" >&2
	exit 1
	;;
esac
