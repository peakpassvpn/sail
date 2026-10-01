#!/usr/bin/env bash
# Packages a built sail for a release: strips it, keeps its symbols apart,
# and puts it in an archive with what runs it.
#
#   scripts/release/package-cli.sh <target> <version> <built file> <out dir>
#
# Writes to <out dir>:
#   ship/sail-<version>-<target>.tar.gz (.zip for Windows)
#   symbols/sail-<target>.debug or .dSYM
#   ids.txt       "<archive> <build ID>", for manifest.py
#   <target>.sha256  the stripped file's hash, which the reproducibility
#                    check compares
#
# Linux archives carry packaging/systemd and its guide; the Windows one
# carries wintun.dll, exactly as wintun.net ships it (WINTUN_VERSION and
# WINTUN_SHA256 pin the zip), with its license.

set -euo pipefail

target=$1
version=$2
built=$3
out=$4

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
name=sail-$version-$target
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
	mv "$f" "$out/symbols/sail-$target${f##*/"$exe"}"
done
sha256sum "$stage/$exe" | cut -d' ' -f1 >"$out/$target.sha256"

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
	echo "$WINTUN_SHA256  $zip" | sha256sum -c --quiet
	unzip -q -j "$zip" wintun/bin/amd64/wintun.dll -d "$stage"
	unzip -q -p "$zip" wintun/LICENSE.txt >"$stage/wintun-LICENSE.txt"
	cat >"$stage/README.txt" <<TXT
sail $version for $target

Run it:  sail.exe -c config.json
The TUN inbound uses Wintun (wintun.dll, beside sail.exe), shipped
unmodified from wintun.net under its own license, wintun-LICENSE.txt.
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
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
		-cf - "$name" | gzip -n -9 >"$out/ship/$archive"
	;;
esac
echo "$archive $id" >>"$out/ids.txt"
