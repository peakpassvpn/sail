#!/usr/bin/env python3
"""Validate workspace manifests and Cargo.lock against the source policy."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "tools/security/policy.toml"
FULL_REV = re.compile(r"[0-9a-f]{40}")
CHECKSUM = re.compile(r"[0-9a-f]{64}")
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"cannot read {path.relative_to(ROOT)}: {error}") from error


def dependency_specs(value: Any, location: str = ""):
    if isinstance(value, dict):
        if "git" in value:
            yield location, value
        for key, child in value.items():
            child_location = f"{location}.{key}" if location else str(key)
            yield from dependency_specs(child, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from dependency_specs(child, f"{location}[{index}]")


def normalize_repo(url: str) -> str:
    return url[:-4] if url.endswith(".git") else url


def main() -> int:
    errors: list[str] = []
    evidence: list[str] = []

    try:
        policy = load_toml(POLICY_PATH)
    except RuntimeError as error:
        print(f"source-check: ERROR: {error}", file=sys.stderr)
        return 2

    if policy.get("schema") != 1:
        print("source-check: ERROR: unsupported policy schema", file=sys.stderr)
        return 2

    allowed: dict[str, str] = {}
    for item in policy.get("git", []):
        url, rev = item.get("url"), item.get("rev")
        if not isinstance(url, str) or not isinstance(rev, str) or not FULL_REV.fullmatch(rev):
            print("source-check: ERROR: invalid [[git]] policy entry", file=sys.stderr)
            return 2
        key = normalize_repo(url)
        if key in allowed:
            print(f"source-check: ERROR: duplicate Git policy for {url}", file=sys.stderr)
            return 2
        allowed[key] = rev

    root_manifest = load_toml(ROOT / "Cargo.toml")
    workspace = root_manifest.get("workspace", {})
    actual_manifests = {"Cargo.toml"}
    for member in workspace.get("members", []):
        matches = sorted(ROOT.glob(member))
        if not matches:
            errors.append(f"workspace member pattern has no match: {member}")
        for match in matches:
            manifest = match / "Cargo.toml" if match.is_dir() else match
            actual_manifests.add(manifest.relative_to(ROOT).as_posix())

    configured_manifests = set(policy.get("manifests", []))
    for missing in sorted(actual_manifests - configured_manifests):
        errors.append(f"workspace manifest missing from policy: {missing}")
    for stale in sorted(configured_manifests - actual_manifests):
        errors.append(f"policy manifest is not a workspace member: {stale}")

    manifest_git_seen: set[str] = set()
    for relative in sorted(configured_manifests):
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"manifest does not exist: {relative}")
            continue
        try:
            manifest = load_toml(path)
        except RuntimeError as error:
            errors.append(str(error))
            continue
        for location, spec in dependency_specs(manifest):
            url = spec.get("git")
            rev = spec.get("rev")
            if not isinstance(url, str):
                errors.append(f"{relative}:{location}: git URL is not a string")
                continue
            normalized = normalize_repo(url)
            manifest_git_seen.add(normalized)
            if "branch" in spec or "tag" in spec:
                errors.append(f"{relative}:{location}: branch/tag Git specifiers are forbidden")
            if not isinstance(rev, str) or not FULL_REV.fullmatch(rev):
                errors.append(f"{relative}:{location}: rev must be a full lowercase 40-hex commit")
                continue
            expected = allowed.get(normalized)
            if expected is None:
                errors.append(f"{relative}:{location}: unapproved Git repository {url}")
            elif rev != expected:
                errors.append(
                    f"{relative}:{location}: revision {rev} differs from approved {expected}"
                )
            else:
                evidence.append(f"manifest {relative}:{location} -> {url}@{rev}")

    lock_relative = policy.get("lockfile")
    if not isinstance(lock_relative, str):
        print("source-check: ERROR: policy lockfile must be a string", file=sys.stderr)
        return 2
    lock_path = ROOT / lock_relative
    if not lock_path.is_file():
        errors.append(f"required lockfile is missing: {lock_relative}")
        lock = {}
    else:
        try:
            lock = load_toml(lock_path)
        except RuntimeError as error:
            errors.append(str(error))
            lock = {}

        if (ROOT / ".git").exists():
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", "--", lock_relative],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if tracked.returncode != 0:
                errors.append(
                    f"{lock_relative} is not tracked by Git; clean CI checkouts cannot audit it"
                )

    lock_git_seen: set[str] = set()
    for package in lock.get("package", []):
        name = package.get("name", "<unknown>")
        version = package.get("version", "<unknown>")
        source = package.get("source")
        if source is None:
            continue
        if source.startswith("registry+"):
            if source != CRATES_IO:
                errors.append(f"{name} {version}: unapproved registry source {source}")
            checksum = package.get("checksum")
            if not isinstance(checksum, str) or not CHECKSUM.fullmatch(checksum):
                errors.append(f"{name} {version}: registry package lacks a SHA-256 checksum")
            continue
        if not source.startswith("git+"):
            errors.append(f"{name} {version}: unsupported source {source}")
            continue

        parsed = urllib.parse.urlsplit(source[4:])
        repo = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        normalized = normalize_repo(repo)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        revisions = query.get("rev", [])
        locked_rev = parsed.fragment
        lock_git_seen.add(normalized)
        expected = allowed.get(normalized)
        if expected is None:
            errors.append(f"{name} {version}: unapproved Git repository {repo}")
        if len(revisions) != 1 or not FULL_REV.fullmatch(revisions[0]):
            errors.append(f"{name} {version}: lock source must contain one full ?rev= commit")
            continue
        requested_rev = revisions[0]
        if not FULL_REV.fullmatch(locked_rev):
            errors.append(f"{name} {version}: lock source fragment is not a full commit")
        elif requested_rev != locked_rev:
            errors.append(
                f"{name} {version}: requested revision {requested_rev} resolved to {locked_rev}"
            )
        if expected is not None and requested_rev != expected:
            errors.append(
                f"{name} {version}: lock revision {requested_rev} differs from approved {expected}"
            )
        if expected == requested_rev == locked_rev:
            evidence.append(f"lock {name} {version} -> {repo}@{locked_rev}")

    for unused in sorted(set(allowed) - (manifest_git_seen | lock_git_seen)):
        errors.append(f"approved Git repository is unused: {unused}")

    for line in evidence:
        print(f"source-check: evidence: {line}")
    if errors:
        for error in errors:
            print(f"source-check: VIOLATION: {error}", file=sys.stderr)
        print(f"source-check: FAIL ({len(errors)} violation(s))", file=sys.stderr)
        return 1
    print(
        f"source-check: PASS ({len(configured_manifests)} manifests, "
        f"{len(lock.get('package', []))} locked packages)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
