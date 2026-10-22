#!/usr/bin/env python3
"""Tier B's report (roadmap 5.4): the paired ratios new/base of a
nightly.sh run, and which crossed the design's limits.

    btier.py RUN_DIR

RUN_DIR holds results/{base,new}/r<N>/results/*/summary.json (netem's run.py,
one or more per round and build) and results/server/results/*/summary.json
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
# 95% interval lies past it. From the calibration of 2026-10-14 (one build
# against itself, 6 rounds, sd of the paired ratios): the client's
# throughput 0.4-2.8% and CPU per GiB 1.7-4.0%, but for trojan-server's
# download (5.6 and 8.1%); at 4 rounds an interval is about 1.4 sd either
# side. The netem cells' (the client's):
LIMITS = {
    "cpu_s_per_gib": ("higher", 1.10),
    "mbps": ("lower", 0.90),
    "setup.p50_ms": ("higher", 1.25),
    "rtt.p50_ms": ("higher", 1.25),
}
# server-accept's: memory per connection (within 2.1% at the
# calibration). Its bulk CPU and throughput (12 to 17%) and every p99 and
# p999 (33 to 53%) are too noisy to alert on: reported only.
SERVER_LIMITS = {
    "server_kb_per_conn": ("higher", 1.10),
}
# Cells whose noise leaves a 10% change within the interval at 4 rounds:
# what the smallest change is that they show.
DETECTS = {
    "trojan-sail-server/baseline/bulk_down": "detects ≥11%",
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
            for timing in ("setup", "rtt"):
                if isinstance((res.get(timing) or {}).get("p50_ms"), (int, float)):
                    out[(cell, f"{timing}.p50_ms")] = res[timing]["p50_ms"]
    return out


def netem(run_dir):
    """(cell, metric) -> [new/base per round]."""
    rounds = {}
    for which in ("base", "new"):
        for path in glob.glob(f"{run_dir}/results/{which}/r*/results/*/summary.json"):
            n = int(re.search(r"/r(\d+)/", path).group(1))
            # A round may hold several summaries, one a run.py run.
            rounds.setdefault(n, {}).setdefault(which, {}).update(netem_metrics(path))
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


def verdict(limits, cell, metric, low, high):
    limit = limits.get(metric)
    if not limit or low is None:
        return "reported"
    worse, at = limit
    if worse == "higher" and low > at or worse == "lower" and high < at:
        return f"**past {at:.2f}**"
    return f"ok, {DETECTS[cell]}" if cell in DETECTS else "ok"


def main():
    run_dir = sys.argv[1]
    lines = ["| cell | metric | new/base | 95% interval | sd | verdict |",
             "| --- | --- | --- | --- | --- | --- |"]
    alerts = 0
    for (cell, metric), ratios in sorted(netem(run_dir).items()):
        mean, low, high, sd = interval(ratios)
        v = verdict(LIMITS, cell, metric, low, high)
        alerts += v.startswith("**")
        span = f"{low:.3f}–{high:.3f}" if low is not None else "—"
        lines.append(f"| {cell} | {metric} | {mean:.3f} | {span} | "
                     f"{sd:.3f} | {v} |" if sd is not None else
                     f"| {cell} | {metric} | {mean:.3f} | {span} | — | {v} |")
    for (cell, metric), (ratio, low, high) in sorted(server(run_dir).items()):
        v = verdict(SERVER_LIMITS, cell, metric, low, high)
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
