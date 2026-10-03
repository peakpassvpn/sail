#!/usr/bin/env python3
"""For a workspace that depends on sail as a crate, directly or through
another crate: its [patch.crates-io] holds sail's, entry for entry.

A [patch] section applies only in the workspace that declares it, so a
crate built on sail copies sail's: the forks sail builds with (btls,
quinn-proto and others), which crates from crates.io depend on too. This
checks the copy against the sail the lock file pins, so that a sail update
that moves a fork fails CI instead of building with the old one.

    tools/embed-patch-check.py [WORKSPACE] [-- CARGO_METADATA_ARGS...]

WORKSPACE is the directory of the depending workspace's Cargo.toml (the
current one by default). Run it after `cargo fetch`: it reads sail's own
workspace manifest from where Cargo checked sail out. Exits 1, naming each
entry missing or different; entries sail has no use for may stay.

The arguments after `--` go to `cargo metadata`, and choose the features
the dependency graph is resolved with; `--all-features` when none are
given, so that sail is found behind an optional dependency too (a feature
of the host's that brings in the crate that brings in sail). To check one
feature set: `-- --features rust-core`.
"""

import json
import os
import subprocess
import sys
import tomllib


def patches(manifest):
    with open(manifest, "rb") as f:
        return tomllib.load(f).get("patch", {}).get("crates-io", {})


def workspace_root(manifest_dir):
    """The nearest directory, from `manifest_dir` up, whose Cargo.toml has
    a [workspace]."""
    d = os.path.abspath(manifest_dir)
    while True:
        candidate = os.path.join(d, "Cargo.toml")
        if os.path.exists(candidate):
            with open(candidate, "rb") as f:
                if "workspace" in tomllib.load(f):
                    return candidate
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def main():
    args = sys.argv[1:]
    cargo_args = ["--all-features"]
    if "--" in args:
        at = args.index("--")
        args, cargo_args = args[:at], args[at + 1:]
    workspace = args[0] if args else "."
    ours = os.path.join(workspace, "Cargo.toml")
    run = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--manifest-path", ours, *cargo_args],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        sys.exit("embed-patch-check: cargo metadata failed:\n" + run.stderr.strip())
    metadata = json.loads(run.stdout)
    sails = [p for p in metadata["packages"] if p["name"] == "sail"]
    if not sails:
        sys.exit("embed-patch-check: sail is not among the dependencies resolved with "
                 + (" ".join(cargo_args) or "the default features"))
    if len(sails) > 1:
        sys.exit("embed-patch-check: more than one sail in the graph: "
                 + ", ".join(p["id"] for p in sails))
    sail = sails[0]
    theirs = workspace_root(os.path.dirname(sail["manifest_path"]))
    if theirs is None:
        sys.exit("embed-patch-check: no workspace manifest above " + sail["manifest_path"])

    wanted, have = patches(theirs), patches(ours)
    problems = []
    for name, spec in sorted(wanted.items()):
        if name not in have:
            problems.append(f"{name}: missing; sail has {spec}")
        elif have[name] != spec:
            problems.append(f"{name}: {have[name]}; sail has {spec}")
    if problems:
        print(f"embed-patch-check: [patch.crates-io] differs from sail {sail['version']}'s "
              "(copy its entries as they are):")
        for problem in problems:
            print("  " + problem)
        sys.exit(1)
    print(f"embed-patch-check: [patch.crates-io] holds sail {sail['version']}'s "
          f"{len(wanted)} entries")


if __name__ == "__main__":
    main()
