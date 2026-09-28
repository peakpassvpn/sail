#!/bin/sh
set -eu

die() { printf '%s\n' "acceptance-static-selftest.sh: $*" >&2; exit 1; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' "SKIP acceptance static self-test: Linux is required"
    exit 77
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sail-acceptance-selftest.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
fake_bin=$tmp_dir/bin
mkdir "$fake_bin"

cat >"$fake_bin/systemd-analyze" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$fake_bin/systemd-analyze"

success_root=$tmp_dir/success-evidence
PATH="$fake_bin:$PATH" "$script_dir/acceptance-linux.sh" \
    --sail-binary /bin/true --artifacts "$success_root" >/dev/null
success_result=$(find "$success_root" -name result.txt -type f -print)
[ -n "$success_result" ] || die "successful static run retained no result"
grep -qx 'result=PASS' "$success_result" || die "successful static run was not marked PASS"
grep -qx 'exit_code=0' "$success_result" || die "successful static exit code was not retained"
grep -qx 'last_step=static-complete' "$success_result" || die "successful static phase was not retained"
grep -qx 'scope=static' "$success_result" || die "successful static scope was not retained"

counter=$tmp_dir/analyze-counter
cat >"$fake_bin/systemd-analyze" <<EOF
#!/bin/sh
count=0
[ ! -f "$counter" ] || count=\$(cat "$counter")
count=\$((count + 1))
printf '%s\n' "\$count" >"$counter"
[ "\$count" -lt 2 ] || exit 42
EOF
chmod +x "$fake_bin/systemd-analyze"

failure_root=$tmp_dir/failure-evidence
set +e
PATH="$fake_bin:$PATH" "$script_dir/acceptance-linux.sh" \
    --sail-binary /bin/true --artifacts "$failure_root" >/dev/null 2>&1
failure_rc=$?
set -e
[ "$failure_rc" -eq 42 ] || die "expected analyzer failure 42, got $failure_rc"
failure_result=$(find "$failure_root" -name result.txt -type f -print)
[ -n "$failure_result" ] || die "failed static run retained no result"
grep -qx 'result=FAIL' "$failure_result" || die "failed static run was not marked FAIL"
grep -qx 'exit_code=42' "$failure_result" || die "failed static exit code was not retained"
grep -qx 'last_step=systemd-analyze-tun' "$failure_result" || die "failed static phase was not retained"
grep -qx 'scope=static' "$failure_result" || die "failed static scope was not retained"
failure_dir=$(dirname "$failure_result")
[ -f "$failure_dir/systemd-analyze-verify.txt" ] || die "ordinary analyzer evidence was lost"
[ -f "$failure_dir/systemd-analyze-verify-tun.txt" ] || die "failed analyzer evidence was lost"

printf '%s\n' "acceptance static success/failure evidence checks passed"
