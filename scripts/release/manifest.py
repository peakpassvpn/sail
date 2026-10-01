#!/usr/bin/env python3
"""Writes a release's manifest.json and SHA256SUMS, and says how each file's
size moved since the last release.

    scripts/release/manifest.py <dist dir> <version> [last manifest.json]

<dist dir> holds what the release ships (archives and libraries) and
ids.txt, lines of "<file> <ID>" from split-symbols.sh. The toolchain and
runner come from the environment the release workflow sets.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import sys

# A file this much larger than in the last release is flagged in the
# release notes. A judgment call, to be set again after the first release.
GROWTH_FLAG = 0.05


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def version_of(*command):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True).stdout.splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        return None


def main():
    dist = pathlib.Path(sys.argv[1])
    version = sys.argv[2]
    last = {}
    if len(sys.argv) > 3 and pathlib.Path(sys.argv[3]).is_file():
        with open(sys.argv[3]) as f:
            last = {e["name"]: e for e in json.load(f)["files"]}

    ids = {}
    ids_file = dist / "ids.txt"
    if ids_file.is_file():
        for line in ids_file.read_text().splitlines():
            name, _, build_id = line.partition(" ")
            if build_id:
                ids[name] = build_id

    files, flagged = [], []
    for path in sorted(dist.iterdir()):
        if not path.is_file() or path.name in ("ids.txt", "manifest.json", "SHA256SUMS"):
            continue
        entry = {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)}
        stem = path.name.split(".")[0]
        for name, build_id in ids.items():
            if name == path.name or name == stem:
                entry["id"] = build_id
        before = last.get(path.name)
        if before:
            entry["last_bytes"] = before["bytes"]
            growth = entry["bytes"] / before["bytes"] - 1
            if growth > GROWTH_FLAG:
                flagged.append(f"{path.name}: {before['bytes']} -> {entry['bytes']} bytes (+{growth:.1%})")
        files.append(entry)

    manifest = {
        "version": version,
        "commit": os.environ.get("GITHUB_SHA"),
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
        "rustc": version_of("rustc", "-V"),
        "cargo": version_of("cargo", "-V"),
        "ndk": os.environ.get("ANDROID_NDK_VERSION"),
        "xcode": os.environ.get("XCODE_VERSION"),
        "gradle": os.environ.get("GRADLE_VERSION"),
        "runner_image": os.environ.get("ImageOS", "") + " " + os.environ.get("ImageVersion", ""),
        "rustflags": os.environ.get("RUSTFLAGS"),
        "files": files,
        "grown": flagged,
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (dist / "SHA256SUMS").write_text("".join(f"{e['sha256']}  {e['name']}\n" for e in files))
    for line in flagged:
        print(f"grown more than {GROWTH_FLAG:.0%}: {line}")


if __name__ == "__main__":
    main()
