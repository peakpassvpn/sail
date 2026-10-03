#!/usr/bin/env bash
# Packages a built sail for a release: strips it, keeps its symbols apart,
# and puts it in an archive with what runs it.
#
#   scripts/release/package-cli.sh <target> <version> <built file> <out dir> [variant]
#
# Writes to <out dir>, <name> being <target>, or <target>-<variant> for a
# variant (router):
#   ship/sail-<version>-<name>.tar.gz (.zip for Windows)
#   symbols/sail-<name>.debug or .dSYM
#   ids.txt       "<archive> <build ID>", for manifest.py
#   <name>.sha256    the stripped file's hash, which the reproducibility
#                    check compares
#
# Linux archives carry packaging/systemd and its guide; the Windows one
# carries wintun.dll, exactly as wintun.net ships it (WINTUN_VERSION and
# WINTUN_SHA256 pin the zip), with its license. On macOS (the
# *-apple-darwin targets) GNU tar does the archive, as gtar; DSYM names
# the file's dSYM for split-symbols.sh.

set -euo pipefail

target=$1
version=$2
built=$3
out=$4
variant=${5:-}

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi |
		cut -d' ' -f1
}
# GNU tar: fixed order, owner and times take its options.
tar=$(command -v gtar || command -v tar)
"$tar" --version 2>/dev/null | grep -q 'GNU tar' ||
	{ echo "package-cli: GNU tar needed (gtar on macOS)" >&2; exit 1; }
build=$target${variant:+-$variant}
name=sail-$version-$build
stage=$(mktemp -d)/$name
mkdir -p "$stage" "$out/ship" "$out/symbols"
out=$(cd "$out" && pwd)

case $target in
*windows*) exe=sail.exe ;;
*) exe=sail ;;
esac
cp "$built" "$stage/$exe"
id=$("$ROOT/scripts/release/split-symbols.sh" "$stage/$exe" "$out/symbols")
for f in "$out/symbols"/"$exe"*; do
	mv "$f" "$out/symbols/sail-$build${f##*/"$exe"}"
done
sha256 "$stage/$exe" >"$out/$build.sha256"

cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_LICENSES.md" "$stage/"
case $target in
*linux*)
	cp -R "$ROOT/packaging/systemd" "$stage/systemd"
	cp "$ROOT/docs/systemd-deployment.md" "$stage/systemd/README.md"
	cat >"$stage/README.txt" <<TXT
sail $version for $target

Run it:            ./sail -c config.json
Install a service: copy sail to /usr/bin/sail, then see systemd/README.md
                   (systemd/install.sh installs the unit and a checked
                   configuration; it enables and starts nothing).
TXT
	;;
*windows*)
	: "${WINTUN_VERSION:?}" "${WINTUN_SHA256:?}"
	zip=$(mktemp -d)/wintun.zip
	curl -sSfL -o "$zip" "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip"
	[ "$(sha256 "$zip")" = "$WINTUN_SHA256" ] ||
		{ echo "package-cli: wintun zip: not the pinned hash" >&2; exit 1; }
	unzip -q -j "$zip" wintun/bin/amd64/wintun.dll -d "$stage"
	unzip -q -p "$zip" wintun/LICENSE.txt >"$stage/wintun-LICENSE.txt"
	cat >"$stage/README.txt" <<TXT
sail $version for $target

Run it:  sail.exe -c config.json
The TUN inbound uses Wintun (wintun.dll, beside sail.exe), shipped
unmodified from wintun.net under its own license, wintun-LICENSE.txt.
TXT
	;;
*apple-darwin)
	cat >"$stage/README.txt" <<TXT
sail $version for macOS on $(case $target in aarch64-*) echo "Apple silicon" ;; *) echo Intel ;; esac)

Run it:  ./sail -c config.json
Not signed: macOS asks before the first run; allow it under System
Settings, Privacy & Security, or run: xattr -d com.apple.quarantine sail
TXT
	;;
esac

# The same bytes from the same inputs: fixed order, owner and times.
epoch=${SOURCE_DATE_EPOCH:?}
cd "$(dirname "$stage")"
case $target in
*windows*)
	archive=$name.zip
	find "$name" -exec touch -h -d "@$epoch" {} +
	find "$name" | LC_ALL=C sort | TZ=UTC zip -q -X -D -@ "$out/ship/$archive"
	;;
*)
	archive=$name.tar.gz
	"$tar" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
		-cf - "$name" | gzip -n -9 >"$out/ship/$archive"
	;;
esac
echo "$archive $id" >>"$out/ids.txt"
