#!/usr/bin/env bash
# Tier A does not block (5.4): a metric over its limit is a warning on the
# run, and the job stays green; any other failure of report.py compare
# fails it.
#
#   crossed.sh STATUS COMPARE.md
set -eu
status=$1
case "$status" in
  0) ;;
  3) sed -n 's/^- \(.*\)$/::warning title=perf regression::\1/p' "$2" ;;
  *) exit "$status" ;;
esac
