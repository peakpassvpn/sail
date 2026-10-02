#!/usr/bin/env python3
"""The C ABI only grows (docs/ffi.md, Compatibility): every function in the
header of the latest release keeps its signature, and SailPlatform keeps its
fields in order, new ones only at the end.

    tools/ffi-abi-check.py [TAG]

TAG defaults to the latest release tag (v*). Exits 1, naming what changed.
"""

import re
import subprocess
import sys

HEADER = "sail-ffi/include/sail.h"

# Changed before the rule held, from that release on: nothing to compare.
# Empty for every release after v0.15.0.
CHANGED_BEFORE_THE_RULE = {
    "v0.15.0": {"sail_check_config"},
}


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def latest_tag():
    tags = run("git", "tag", "--list", "v*", "--sort=-v:refname").split()
    return tags[0] if tags else None


def without_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def functions(text):
    """Each sail_ function's declaration, its whitespace made one space."""
    found = {}
    for match in re.finditer(r"[^;{}#]*?\b(sail_[a-z0-9_]+)\s*\([^;{}]*\)\s*;", without_comments(text)):
        declaration = " ".join(match.group(0).split())
        found[match.group(1)] = declaration
    return found


def platform_fields(text):
    """SailPlatform's fields, in order."""
    match = re.search(r"typedef struct SailPlatform\s*\{(.*?)\}\s*SailPlatform\s*;", without_comments(text), re.S)
    if not match:
        return []
    return [" ".join(field.split()) for field in match.group(1).split(";") if field.strip()]


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else latest_tag()
    if not tag:
        print("ffi-abi-check: no release yet")
        return
    try:
        released = run("git", "show", f"{tag}:{HEADER}")
    except subprocess.CalledProcessError:
        print(f"ffi-abi-check: {tag} has no {HEADER}")
        return
    with open(HEADER) as f:
        now = f.read()
    exempt = CHANGED_BEFORE_THE_RULE.get(tag, set())
    problems = []
    current = functions(now)
    for name, declaration in sorted(functions(released).items()):
        if name in exempt:
            continue
        if name not in current:
            problems.append(f"{name}: gone since {tag}")
        elif current[name] != declaration:
            problems.append(f"{name}: changed since {tag}\n    was: {declaration}\n    now: {current[name]}")
    was, is_ = platform_fields(released), platform_fields(now)
    if is_[: len(was)] != was:
        problems.append(f"SailPlatform: its fields since {tag} are no longer the first, in order")
    if problems:
        print("ffi-abi-check: a released function or field changed; a change is a new function "
              "(sail_x2), and SailPlatform grows only at its end:")
        for problem in problems:
            print("  " + problem)
        sys.exit(1)
    print(f"ffi-abi-check: the C ABI of {tag} holds ({len(functions(released))} functions)")


if __name__ == "__main__":
    main()
