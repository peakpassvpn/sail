#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <target> <artifact>" >&2
    exit 2
fi
target="$1"
artifact="$2"
case "$target" in
    config_json | config_auto | subscription | rule_set_source | rule_set_binary | rule_set_mrs | dns_message | sniff | protocol_inbound) ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
esac
if [ ! -f "$artifact" ]; then
    echo "artifact is not a file: $artifact" >&2
    exit 2
fi

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
env CARGO_BUILD_JOBS=2 cargo +nightly fuzz run \
    --sanitizer address \
    --fuzz-dir "$root" \
    "$target" "$artifact" -- -runs=1 -max_len=262144 -timeout=10
