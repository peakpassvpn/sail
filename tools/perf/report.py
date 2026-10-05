#!/usr/bin/env python3
"""Gathers and compares the performance regression checks' numbers (5.4).

    report.py collect --sha SHA [--size NAME=FILE ...] LOG... > perf.json
        Takes the `PERF {...}` lines of tools/perf/cli.py and of sail-ffi's
        perf_tests from LOGs, and the sizes of FILEs, into one file of
        numbers: the median of each over its rounds, and the rounds.

    report.py merge PERF.json... > perf.json
        One file of the files of one commit's jobs.

    report.py check PERF.json
        Fails unless the file is numbers only: the schema, a commit, metric
        names of [a-z0-9_.-] and numbers. Run before it is published.

    report.py compare NEW BASE [--release RELEASE]
        Compares NEW with BASE (the last scheduled or tag run) and, if given, with
        RELEASE (the last release's), by the thresholds below; writes a
        Markdown table, and exits 1 if any metric crossed one.

The file holds numbers, metric names and the commit only: it is published
as a workflow artifact of a public repository.
"""

import argparse
import json
import os
import re
import statistics
import sys

# metric suffix -> (largest growth against the last scheduled or tag run, against the
# last release, or None; source). The design's section 6, set from the
# calibration (ten runners, five rounds each, 2026-10-01): "spread" is the
# largest difference between two runners' medians. The most specific
# suffix first.
THRESHOLDS = [
    ("size_bytes", 0.02, 0.05, "5%: 5.8's release threshold; 2%: judgment (sizes are reproducible)"),
    ("allocations_per_connection", 0.02, 0.02, "measured: spread <=0.9%"),
    ("allocations_per_mib", 0.03, 0.03, "measured: spread <=1.9%"),
    ("allocated_bytes_per_mib", 0.25, 0.25, "measured: spread ~20%, a coarse alarm"),
    ("footprint_kb_per_connection", 0.10, 0.10, "judgment: macOS not yet calibrated"),
    ("footprint_kb", 0.10, 0.10, "judgment: macOS not yet calibrated"),
    ("kb_per_connection", 0.03, 0.03, "measured: spread <=0.8%"),
    ("rss_kb", 0.05, 0.05, "measured: spread <=2.7%"),
    ("_ms", 1.00, None, "measured: spread up to 62%; only a doubling"),
]

NAME = re.compile(r"^[a-z0-9_.-]+$")


def threshold(metric):
    for suffix, master, release, source in THRESHOLDS:
        if metric.endswith(suffix):
            return master, release, source
    return None


def collect(args):
    rounds = {}
    for path in args.logs:
        with open(path) as f:
            for line in f:
                if not line.startswith("PERF "):
                    continue
                row = json.loads(line[5:])
                # cli.py names its profile; perf_tests is the FFI's.
                prefix = "cli." + row.pop("profile") if "profile" in row else "ffi"
                row.pop("round", None)
                for key, value in row.items():
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        rounds.setdefault(f"{prefix}.{key}", []).append(value)
    for spec in args.size or []:
        name, _, path = spec.partition("=")
        rounds[f"size.{name}.size_bytes"] = [os.path.getsize(path)]
    for name in rounds:
        if not NAME.match(name):
            sys.exit(f"{name}: not a metric name")
    json.dump(
        {
            "schema": 1,
            "sha": args.sha,
            "metrics": {
                name: {"median": statistics.median(values), "rounds": values}
                for name, values in sorted(rounds.items())
            },
        },
        sys.stdout,
        indent=1,
    )
    print()


def merge(args):
    files = [load(p) for p in args.files]
    shas = {f["sha"] for f in files}
    if len(shas) != 1:
        sys.exit(f"files of different commits: {sorted(shas)}")
    metrics = {}
    for f in files:
        for name, value in f["metrics"].items():
            if name in metrics:
                # The same measurement in several jobs (calibration): their
                # rounds together.
                rounds = metrics[name]["rounds"] + value["rounds"]
                metrics[name] = {"median": statistics.median(rounds), "rounds": rounds}
            else:
                metrics[name] = value
    json.dump({"schema": 1, "sha": shas.pop(), "metrics": dict(sorted(metrics.items()))},
              sys.stdout, indent=1)
    print()


def check(args):
    data = load(args.file)
    problems = []
    if set(data) != {"schema", "sha", "metrics"} or data["schema"] != 1:
        problems.append("keys other than schema, sha, metrics")
    if not re.fullmatch(r"[0-9a-f]{7,40}", str(data.get("sha", ""))):
        problems.append("sha is not a commit")
    for name, value in data.get("metrics", {}).items():
        if not NAME.match(name):
            problems.append(f"{name!r}: not a metric name")
        if not isinstance(value, dict) or set(value) != {"median", "rounds"}:
            problems.append(f"{name}: not median and rounds")
            continue
        numbers = [value["median"], *value["rounds"]]
        if not all(isinstance(n, (int, float)) and not isinstance(n, bool) for n in numbers):
            problems.append(f"{name}: not numbers")
    if problems:
        sys.exit("\n".join(f"{args.file}: {p}" for p in problems))


def load(path):
    with open(path) as f:
        return json.load(f)


def compare(args):
    new = load(args.new)
    against = [("master", load(args.base))]
    if args.release:
        against.append(("release", load(args.release)))
    crossed = []
    lines = ["| metric | new | " + " | ".join(f"{n} ({b['sha'][:8]})" for n, b in against) + " | limit |",
             "| --- | --- | " + " | ".join("---" for _ in against) + " | --- |"]
    for metric, now in sorted(new["metrics"].items()):
        limits = threshold(metric)
        cells = []
        for which, base in against:
            old = base["metrics"].get(metric)
            if old is None or not old["median"]:
                cells.append("—")
                continue
            growth = now["median"] / old["median"] - 1
            limit = limits and (limits[0] if which == "master" else limits[1])
            over = limit is not None and growth > limit
            if over:
                crossed.append(f"{metric}: +{growth:.1%} against {which} (limit {limit:.0%})")
            cells.append(f"{'**' if over else ''}{growth:+.1%}{'**' if over else ''}")
        limit_text = f"{limits[0]:.0%} / {limits[1]:.0%}" if limits and limits[1] else (
            f"{limits[0]:.0%}" if limits else "—")
        lines.append(f"| {metric} | {now['median']:.6g} | " + " | ".join(cells) + f" | {limit_text} |")
    print("\n".join(lines))
    if crossed:
        print("\nOver the limit:\n" + "\n".join(f"- {c}" for c in crossed))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--sha", required=True)
    c.add_argument("--size", action="append", metavar="NAME=FILE")
    c.add_argument("logs", nargs="+")
    m = sub.add_parser("merge")
    m.add_argument("files", nargs="+")
    h = sub.add_parser("check")
    h.add_argument("file")
    k = sub.add_parser("compare")
    k.add_argument("new")
    k.add_argument("base")
    k.add_argument("--release")
    args = parser.parse_args()
    {"collect": collect, "merge": merge, "check": check, "compare": compare}[args.command](args)


if __name__ == "__main__":
    main()
