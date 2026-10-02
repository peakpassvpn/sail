#!/bin/sh
set -eu

duration="${1:-900}"
selection="${2:-all}"
targets="config_json config_auto subscription rule_set_source rule_set_binary rule_set_mrs dns_message sniff protocol_inbound"
case "$duration" in
    *[!0-9]* | "") echo "duration must be a positive number of seconds" >&2; exit 2 ;;
    0) echo "duration must be greater than zero" >&2; exit 2 ;;
esac
if [ "$selection" != "all" ]; then
    valid=0
    for target in $targets; do
        [ "$selection" = "$target" ] && valid=1
    done
    if [ "$valid" -ne 1 ]; then
        echo "target must be all or one of: $targets" >&2
        exit 2
    fi
fi

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$root/evidence/$run_id"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/sail-config-fuzz.XXXXXX")"
keep_scratch=0

cleanup() {
    if [ "$keep_scratch" -eq 0 ]; then
        rm -rf "$scratch"
    else
        echo "preserved failing scratch corpus: $scratch" >&2
    fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$evidence"
{
    rustc +nightly --version
    cargo +nightly --version
    cargo fuzz --version
    printf 'sanitizer\taddress\n'
    printf 'max_len\t262144\n'
    printf 'duration_seconds_per_target\t%s\n' "$duration"
    printf 'workers\t1\n'
} >"$evidence/toolchain.txt"
printf 'target\tseed\tstarted_utc\tended_utc\telapsed_seconds\texit_code\tlog\n' >"$evidence/summary.tsv"

run_target() {
    target="$1"
    seed="$2"
    # The tracked seeds, and what local runs left in corpus/.
    mkdir -p "$scratch/$target"
    if [ -d "$root/seeds/$target" ]; then
        cp -R "$root/seeds/$target/." "$scratch/$target/"
    fi
    if [ -d "$root/corpus/$target" ]; then
        cp -R "$root/corpus/$target/." "$scratch/$target/"
    fi
    if [ "$target" = "rule_set_binary" ]; then
        cp "$root/../sail/tests/fixtures/rule_set/domains.srs" \
            "$scratch/$target/domains.srs"
    fi
    if [ "$target" = "rule_set_mrs" ]; then
        cp "$root/../sail/tests/fixtures/rule_set/"*.mrs "$scratch/$target/"
    fi
    log="$evidence/$target.log"
    started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    started_epoch="$(date +%s)"

    set +e
    env CARGO_BUILD_JOBS=2 cargo +nightly fuzz run \
        --sanitizer address \
        --fuzz-dir "$root" \
        "$target" "$scratch/$target" -- \
        -dict="$root/config.dict" \
        -max_len=262144 \
        -max_total_time="$duration" \
        -timeout=10 \
        -seed="$seed" >"$log" 2>&1
    status=$?
    set -e

    ended_epoch="$(date +%s)"
    ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    elapsed=$((ended_epoch - started_epoch))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$seed" "$started_utc" "$ended_utc" "$elapsed" "$status" "$log" \
        >>"$evidence/summary.tsv"

    if [ "$status" -ne 0 ]; then
        keep_scratch=1
        echo "$target failed; preserve artifacts before retrying: $root/artifacts/$target" >&2
        return "$status"
    fi
}

run_selected() {
    case "$1" in
        config_json) seed="${CONFIG_JSON_SEED:-530053}" ;;
        config_auto) seed="${CONFIG_AUTO_SEED:-530054}" ;;
        subscription) seed="${SUBSCRIPTION_SEED:-530055}" ;;
        rule_set_source) seed="${RULE_SET_SOURCE_SEED:-530056}" ;;
        rule_set_binary) seed="${RULE_SET_BINARY_SEED:-530057}" ;;
        rule_set_mrs) seed="${RULE_SET_MRS_SEED:-530061}" ;;
        dns_message) seed="${DNS_MESSAGE_SEED:-530058}" ;;
        sniff) seed="${SNIFF_SEED:-530059}" ;;
        protocol_inbound) seed="${PROTOCOL_INBOUND_SEED:-530060}" ;;
    esac
    run_target "$1" "$seed"
}

if [ "$selection" = "all" ]; then
    for target in $targets; do
        run_selected "$target"
    done
else
    run_selected "$selection"
fi
printf 'campaign evidence: %s\n' "$evidence"
