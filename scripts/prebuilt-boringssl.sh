#!/usr/bin/env bash
# Has a CI job link the BoringSSL the btls fork publishes for the btls-sys
# Cargo.lock pins, rather than compile it: the archive of `target` from
# release bssl-<commit> of peakpassvpn/btls, checked against the release's
# SHA256SUMS and its build attestation, unpacked, and its variables
# (BORING_BSSL_PATH_<target> and the rest) written to $GITHUB_ENV. The same
# steps as the fork's scripts/prebuilt-boringssl.sh, for third parties;
# this one adds the fallback.
#
#   scripts/prebuilt-boringssl.sh <target>
#   scripts/prebuilt-boringssl.sh --check <target>
#
# --check, after a build: btls-sys linked the downloaded library, which its
# build script's output names, and not one a cache kept from a source build.
#
# When there is nothing to take (no release for the pinned commit yet, as
# after a pin bump, or no archive for the target, or GitHub not answering),
# the job compiles BoringSSL from source as before, with a warning on the
# run, so that a bump is not held up on publishing. When an archive is there
# but does not check out (checksum, attestation), the job fails: that is
# never a reason to build anyway.
#
# Needs curl, tar, and gh with GH_TOKEN (the job's own token reads public
# attestations). Without GITHUB_ENV it prints the exports instead.

set -euo pipefail

if [ "${1:-}" = --check ]; then
	target=${2:?usage: $0 --check <target>}
	var=BORING_BSSL_PATH_${target//-/_}
	path=${!var:-}
	if [ -z "$path" ]; then
		echo "BoringSSL for $target: compiled from source"
		exit 0
	fi
	output=$(ls -t target/debug/build/btls-sys-*/output "target/$target"/debug/build/btls-sys-*/output 2>/dev/null | head -1 || true)
	[ -n "$output" ] || { echo "::error::no btls-sys build output under target/" && exit 1; }
	grep 'rustc-link-search' "$output"
	if ! grep -qF "rustc-link-search=native=$path" "$output"; then
		echo "::error title=BoringSSL::btls-sys did not link $path ($output)"
		exit 1
	fi
	echo "BoringSSL for $target: linked from $path"
	exit 0
fi

target=${1:?usage: $0 <target>}
lock=${CARGO_LOCK:-Cargo.lock}
repo=peakpassvpn/btls

source_build() {
	echo "::warning title=BoringSSL from source::$1; this job compiles BoringSSL for $target from source"
	exit 0
}

commit=$(awk '
	/^name = "btls-sys"$/ { found = 1; next }
	found && /^source = / {
		if (match($0, /#[0-9a-f]+"$/)) print substr($0, RSTART + 1, RLENGTH - 2)
		exit
	}
	/^\[\[package\]\]/ { found = 0 }
' "$lock")
case $commit in
"" | *[!0-9a-f]*) echo "::error::$lock pins no btls-sys commit (got '$commit')" && exit 1 ;;
esac
[ ${#commit} -eq 40 ] || { echo "::error::not a full commit: $commit" && exit 1; }

base=https://github.com/$repo/releases/download/bssl-$commit
file=boringssl-$target.tar.gz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Whether there is a release: 404 is none yet; anything else but 200
# (after retries) is GitHub not answering.
code=$(curl -sSL --retry 3 -o "$work/SHA256SUMS" -w '%{http_code}' "$base/SHA256SUMS" || true)
case $code in
200) ;;
404) source_build "no release bssl-$commit in $repo yet" ;;
*) source_build "release bssl-$commit: HTTP ${code:-none} for its SHA256SUMS" ;;
esac
want=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS")
[ -n "$want" ] || source_build "release bssl-$commit has no $file"

dir=${BTLS_BORINGSSL_CACHE:-${RUNNER_TEMP:-$HOME/.cache}/btls-boringssl}/$commit/$target
# Git Bash on Windows: RUNNER_TEMP is D:\a\_temp, which tar reads as a host.
if command -v cygpath >/dev/null; then
	dir=$(cygpath -u "$dir")
fi
if [ ! -f "$dir/BUILDINFO" ]; then
	code=$(curl -sSL --retry 3 -o "$work/$file" -w '%{http_code}' "$base/$file" || true)
	[ "$code" = 200 ] || source_build "release bssl-$commit: HTTP ${code:-none} for $file"
	if command -v sha256sum >/dev/null; then
		got=$(sha256sum "$work/$file" | cut -d' ' -f1)
	else
		got=$(shasum -a 256 "$work/$file" | cut -d' ' -f1)
	fi
	if [ "$want" != "$got" ]; then
		echo "::error title=BoringSSL archive::$file: sha256 $got, the release's SHA256SUMS says $want"
		exit 1
	fi
	if ! command -v gh >/dev/null; then
		echo "::error title=BoringSSL archive::gh is needed to verify $file's build attestation"
		exit 1
	fi
	if ! gh attestation verify "$work/$file" -R "$repo" >&2; then
		echo "::error title=BoringSSL archive::$file: its build attestation does not verify"
		exit 1
	fi
	mkdir -p "$dir.tmp"
	tar -xzf "$work/$file" -C "$dir.tmp"
	rm -rf "$dir"
	mv "$dir.tmp" "$dir"
fi
sed 's/^/  /' "$dir/BUILDINFO" >&2

# Git Bash on Windows: a path cargo, a Windows program, reads (D:/x).
if command -v cygpath >/dev/null; then
	dir=$(cygpath -m "$dir")
fi
t=${target//-/_}
vars="BORING_BSSL_PATH_$t=$dir
BORING_BSSL_INCLUDE_PATH_$t=$dir/include
BORING_BSSL_ASSUME_PATCHED_$t=1"
if [ -n "${GITHUB_ENV:-}" ]; then
	echo "$vars" >>"$GITHUB_ENV"
	echo "BoringSSL for $target: release bssl-$commit, $dir" >&2
else
	echo "$vars" | sed "s/^\([^=]*\)=\(.*\)$/export \1='\2'/"
fi
