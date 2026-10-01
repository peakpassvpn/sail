#!/bin/sh
# Refuses content that must not reach the public repository: absolute home
# and temp paths, run logs and evidence directories, and any pattern listed
# in a local, untracked patterns file (names, hosts, addresses that must not
# be published themselves, so they never live in this repository).
#
# Usage:
#   tools/sensitive-check.sh tree              every tracked file at HEAD
#   tools/sensitive-check.sh range BASE HEAD   lines, paths, messages and authors added in BASE..HEAD
#
# Local patterns: one extended regex per line in $SAIL_SENSITIVE_PATTERNS
# (default ~/.config/sail/sensitive-patterns); blank lines and # comments are
# skipped. A line containing "sensitive-check: allow" is exempt.
#
# Findings print as path:line only, never the matched text, because CI logs
# are public.
set -eu

generic='/Users/[A-Za-z0-9._-]+/|/home/[a-z][a-z0-9_-]*/|(^|[^A-Za-z0-9_.*])/root/[A-Za-z0-9._-]|/private/(tmp|var)/|claude-[0-9]+/'
bad_paths='(^|/)(evidence|validation)/|\.log$'

local_file=${SAIL_SENSITIVE_PATTERNS:-$HOME/.config/sail/sensitive-patterns}
patterns=$generic
if [ -r "$local_file" ]; then
    extra=$(grep -vE '^[[:space:]]*(#|$)' "$local_file" | paste -sd'|' -)
    [ -n "$extra" ] && patterns="$patterns|$extra"
fi

found=0
report() { echo "sensitive-check: $1"; found=1; }

case ${1:-} in
tree)
    git ls-files | grep -E "$bad_paths" | while read -r p; do echo "sensitive-check: $p: run log or evidence path"; done | grep . && found=1
    hits=$(git grep -nIE "$patterns" -- . ':!tools/sensitive-check.sh' | grep -v 'sensitive-check: allow' | cut -d: -f1,2) || true
    [ -n "$hits" ] && { echo "$hits" | sed 's/^/sensitive-check: /'; found=1; }
    ;;
range)
    base=${2:?base}; head=${3:?head}
    added=$(git diff --name-only --diff-filter=A "$base" "$head" | grep -E "$bad_paths") || true
    [ -n "$added" ] && { echo "$added" | sed 's/$/: run log or evidence path/;s/^/sensitive-check: /'; found=1; }
    hits=$(git diff --unified=0 --no-color "$base" "$head" -- . ':!tools/sensitive-check.sh' | awk -v re="$patterns" '
        /^\+\+\+ b\// { file = substr($0, 7); next }
        /^@@/ { split($3, a, ","); line = substr(a[1], 2) + 0; next }
        /^\+/ { if ($0 !~ /sensitive-check: allow/ && substr($0, 2) ~ re) print file ":" line; line++ }
    ') || true
    [ -n "$hits" ] && { echo "$hits" | sed 's/^/sensitive-check: /'; found=1; }
    for c in $(git rev-list "$base..$head"); do
        git log -1 --format=%B "$c" | grep -qE "$patterns" && report "commit $(git rev-parse --short "$c"): message"
        git log -1 --format='%an%n%ae%n%cn%n%ce' "$c" | grep -qE "$patterns" && report "commit $(git rev-parse --short "$c"): author or committer"
    done
    ;;
*)
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

if [ "$found" -ne 0 ]; then
    echo "sensitive-check: failed; keep such content outside the repository" >&2
    exit 1
fi
echo "sensitive-check: ok"
