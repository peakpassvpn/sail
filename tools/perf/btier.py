#!/usr/bin/env python3
"""Tier B's report (roadmap 5.4): the paired ratios new/base of a
nightly.sh run, and which crossed the design's limits.

    btier.py RUN_DIR

RUN_DIR holds results/{base,new}/r<N>/results/*/summary.json (netem's run.py,
one per round and build) and results/server/results/*/summary.json
(server-accept, which pairs the two itself). Prints a Markdown table; exits
1 when a ratio's 95% interval lies wholly past its limit. With base and new
the same build (a calibration), the spread of the ratios is the noise.
"""

import glob
import json
import math
import os
import re
import statistics
import sys

# metric -> (the side that is worse, the limit): an alert when the whole
# 95% interval lies past it. Design section 6: 10% for CPU and throughput
# (paired sigma 6.8% measured, so 6 rounds); memory per connection 10%;
# a setup's p50 only at a doubling.
LIMITS = {
    "cpu_s_per_gib": ("higher", 1.10),
    "mbps": ("lower", 0.90),
    "server_kb_per_conn": ("higher", 1.10),
    "setup.p99_ms": ("higher", 2.00),
}

# Two-sided 95% t quantiles by degrees of freedom.
T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26}


def interval(ratios):
    mean = statistics.mean(ratios)
    if len(ratios) < 2:
        return mean, None, None, None
    sd = statistics.stdev(ratios)
    half = T95.get(len(ratios) - 1, 2.0) * sd / math.sqrt(len(ratios))
    return mean, mean - half, mean + half, sd


def netem_metrics(path):
    """(cell, metric) -> value, of one run.py summary."""
    with open(path) as f:
        data = json.load(f)
    if data.get("schema") != 1:
        sys.exit(f"{path}: not netem's summary schema 1")
    out = {}
    for run in data["runs"]:
        for rec in run.get("records", []):
            if rec.get("workload") == "cell":
                continue
            res = rec.get("result") or {}
            cell = f'{run["name"]}/{rec["scenario"]}/{rec["workload"]}'
            if isinstance(res.get("mbps"), (int, float)):
                out[(cell, "mbps")] = res["mbps"]
            if rec.get("cpu_s") is not None and res.get("bytes"):
                out[(cell, "cpu_s_per_gib")] = rec["cpu_s"] / (res["bytes"] / 2**30)
    return out


def netem(run_dir):
    """(cell, metric) -> [new/base per round]."""
    rounds = {}
    for which in ("base", "new"):
        for path in glob.glob(f"{run_dir}/results/{which}/r*/results/*/summary.json"):
            n = int(re.search(r"/r(\d+)/", path).group(1))
            rounds.setdefault(n, {})[which] = netem_metrics(path)
    ratios = {}
    for n, sides in sorted(rounds.items()):
        if set(sides) != {"base", "new"}:
            continue
        for key, new in sides["new"].items():
            base = sides["base"].get(key)
            if base:
                ratios.setdefault(key, []).append(new / base)
    return ratios


def server(run_dir):
    """(cell, metric) -> (ratio, low, high), as server-accept paired them."""
    out = {}
    for path in glob.glob(f"{run_dir}/results/server/results/*/summary.json"):
        with open(path) as f:
            for name, row in json.load(f).items():
                if "ratio" not in row:
                    continue
                cell, _, metric = name.rpartition("/")
                low, high = (row.get("ratio_ci95") or [None, None])
                out[(f"server/{cell}", metric)] = (row["ratio"], low, high)
    return out


def verdict(metric, low, high):
    limit = LIMITS.get(metric)
    if not limit or low is None:
        return ""
    worse, at = limit
    if worse == "higher" and low > at or worse == "lower" and high < at:
        return f"**past {at:.2f}**"
    return "ok"


def main():
    run_dir = sys.argv[1]
    lines = ["| cell | metric | new/base | 95% interval | sd | verdict |",
             "| --- | --- | --- | --- | --- | --- |"]
    alerts = 0
    for (cell, metric), ratios in sorted(netem(run_dir).items()):
        mean, low, high, sd = interval(ratios)
        v = verdict(metric, low, high)
        alerts += v.startswith("**")
        span = f"{low:.3f}–{high:.3f}" if low is not None else "—"
        lines.append(f"| {cell} | {metric} | {mean:.3f} | {span} | "
                     f"{sd:.3f} | {v} |" if sd is not None else
                     f"| {cell} | {metric} | {mean:.3f} | {span} | — | {v} |")
    for (cell, metric), (ratio, low, high) in sorted(server(run_dir).items()):
        v = verdict(metric, low, high)
        alerts += v.startswith("**")
        span = f"{low:.3f}–{high:.3f}" if low is not None else "—"
        lines.append(f"| {cell} | {metric} | {ratio:.3f} | {span} | — | {v} |")
    print("\n".join(lines))
    if os.path.exists(f"{run_dir}/run"):
        print("\n" + open(f"{run_dir}/run").read().strip())
    if alerts:
        print(f"\n{alerts} past their limit")
        sys.exit(1)


if __name__ == "__main__":
    main()
