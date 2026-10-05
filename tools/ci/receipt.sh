#!/usr/bin/env bash
# Green receipts: whether a CI layer already passed on a tree that differs
# from this one in documentation only (docs/testing.md, "Receipts").
#
#   tools/ci/receipt.sh fingerprint          prints the tree's fingerprint
#   tools/ci/receipt.sh check LAYER...       prints fingerprint=<fp> and,
#                                            per layer, <layer>=true|false
#
# The fingerprint is a SHA-256 of `git ls-tree -r HEAD` without what no
# build, test or check reads: docs/ (but docs/compat/, which tests compare
# with the code) and the Markdown files at the repository's root. Every
# other path counts, this workflow and these scripts included, so that a
# change to how a layer runs runs it again.
#
# A receipt is an artifact named green-<layer>-<fingerprint>, uploaded by
# the job that passed. It is looked up through the API across runs and
# branches (a cache entry made on a ci/* branch is not visible to
# master's runs), and trusted only from a run of this repository's own
# master or ci/* branches, which only a writer can push to. Anything that
# goes wrong in the lookup prints false: the layer runs.
set -euo pipefail

fingerprint() {
    git ls-tree -r HEAD |
        awk -F'\t' '!(($2 ~ /^docs\// && $2 !~ /^docs\/compat\//) || ($2 !~ /\// && $2 ~ /\.md$/))' |
        sha256sum | cut -c1-40
}

case ${1:-} in
fingerprint)
    fingerprint
    ;;
check)
    shift
    fp=$(fingerprint)
    echo "fingerprint=$fp"
    for layer in "$@"; do
        found=$(gh api -X GET "repos/$GITHUB_REPOSITORY/actions/artifacts" \
            -f name="green-$layer-$fp" -f per_page=100 \
            --jq '[.artifacts[]
                   | select(.expired == false
                            and .workflow_run.head_repository_id == .workflow_run.repository_id
                            and (.workflow_run.head_branch == "master"
                                 or ((.workflow_run.head_branch // "") | startswith("ci/"))))]
                  | length' 2>/dev/null) || found=0
        if [ "${found:-0}" -gt 0 ] 2>/dev/null; then
            echo "receipt: $layer passed before on $fp" >&2
            echo "$layer=true"
        else
            echo "$layer=false"
        fi
    done
    ;;
*)
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
