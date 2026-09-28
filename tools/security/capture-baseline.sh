#!/usr/bin/env bash
set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
output="${1:-$script_dir/evidence/$(date -u +%F)}"

if [[ -e "$output" ]]; then
  echo "capture-baseline: refusing to overwrite $output" >&2
  exit 2
fi

for tool in cargo-audit cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "capture-baseline: missing $tool" >&2
    exit 3
  fi
done

if [[ "$(cargo-audit --version | awk '{print $2}')" != "0.22.2" ]] ||
  [[ "$(cargo-deny --version | awk '{print $2}')" != "0.20.2" ]]; then
  echo "capture-baseline: scanner versions do not match policy" >&2
  exit 3
fi

parent="$(dirname -- "$output")"
mkdir -p "$parent"
stage="$(mktemp -d "$parent/.baseline.XXXXXX")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/leaf-security-baseline.XXXXXX")"
trap 'rm -rf -- "$stage" "$scratch"' EXIT

cp "$repo_root/Cargo.lock" "$scratch/Cargo.lock"
lock_before="$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')"
snapshot_hash="$(shasum -a 256 "$scratch/Cargo.lock" | awk '{print $1}')"

{
  date -u '+captured_at_utc=%Y-%m-%dT%H:%M:%SZ'
  rustc --version
  cargo --version
  cargo-audit --version
  cargo-deny --version
} >"$stage/tool-versions.txt"

{
  echo "$snapshot_hash  Cargo.lock.snapshot"
  echo "tracked=$(git -C "$repo_root" ls-files --error-unmatch -- Cargo.lock >/dev/null 2>&1 && echo true || echo false)"
} >"$stage/lock.sha256"

python3 "$script_dir/check_sources.py" >"$stage/source-check.log" 2>&1
source_rc=$?

cargo-audit audit \
  --db "$scratch/advisory-db" \
  --file "$scratch/Cargo.lock" \
  --json >"$stage/cargo-audit.json" 2>"$stage/cargo-audit.stderr"
audit_rc=$?

{
  git -C "$scratch/advisory-db" rev-parse HEAD
  git -C "$scratch/advisory-db" show -s --format='%cI%n%s' HEAD
} >"$stage/advisory-db.txt"

cargo deny --locked \
  --manifest-path "$repo_root/Cargo.toml" \
  --config "$script_dir/deny.toml" \
  check licenses sources >"$stage/cargo-deny.log" 2>&1
deny_rc=$?

{
  for package in \
    hickory-proto@0.24.4 \
    maxminddb@0.24.0 \
    protobuf@3.6.0 \
    paste@1.0.15 \
    lru@0.12.5 \
    lru@0.16.4
  do
    echo "===== $package ====="
    cargo tree --locked --workspace --all-features --target all \
      --edges normal,build -i "$package"
    echo
  done
} >"$stage/reverse-dependencies.txt" 2>&1
tree_rc=$?

lock_after="$(shasum -a 256 "$repo_root/Cargo.lock" | awk '{print $1}')"
source_class="$([[ $source_rc -eq 0 ]] && echo pass || echo execution_error)"
audit_class="$([[ $audit_rc -eq 0 ]] && echo pass || echo execution_error)"
deny_class="$([[ $deny_rc -eq 0 ]] && echo pass || echo execution_error)"
if [[ $source_rc -ne 0 ]] && grep -q 'source-check: VIOLATION:' "$stage/source-check.log"; then
  source_class="findings"
fi
if [[ $audit_rc -ne 0 ]]; then
  audit_class="$(python3 - "$stage/cargo-audit.json" <<'PY'
import json
import sys

try:
    report = json.load(open(sys.argv[1]))
    print("findings" if report.get("vulnerabilities", {}).get("found") else "execution_error")
except (OSError, ValueError):
    print("execution_error")
PY
)"
fi
if [[ $deny_rc -ne 0 ]]; then
  deny_class="$(grep -Eq '^(error\[|licenses FAILED|sources FAILED)' "$stage/cargo-deny.log" && echo findings || echo execution_error)"
fi
{
  echo "source_check=$source_rc"
  echo "source_check_class=$source_class"
  echo "cargo_audit=$audit_rc"
  echo "cargo_audit_class=$audit_class"
  echo "cargo_deny=$deny_rc"
  echo "cargo_deny_class=$deny_class"
  echo "reverse_dependencies=$tree_rc"
  echo "lock_unchanged=$([[ "$lock_before" == "$lock_after" ]] && echo true || echo false)"
} >"$stage/exit-codes.txt"

mv "$stage" "$output"
trap 'rm -rf -- "$scratch"' EXIT
echo "capture-baseline: wrote $output"
if [[ "$snapshot_hash" != "$lock_before" || "$lock_before" != "$lock_after" ]]; then
  echo "capture-baseline: Cargo.lock changed during capture; evidence is invalid" >&2
  exit 2
fi
if [[ $tree_rc -ne 0 ]] || [[ "$source_class" == execution_error || "$audit_class" == execution_error || "$deny_class" == execution_error ]]; then
  echo "capture-baseline: evidence retained, but a scanner failed before producing policy findings" >&2
  exit 2
fi
