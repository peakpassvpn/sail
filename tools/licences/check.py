#!/usr/bin/env python3
"""Checks that cargo-about's licences (tools/licences/about.toml) are
cargo-deny's (tools/security/deny.toml): its `accepted` is deny's `allow`,
and each crate deny makes an exception for accepts that exception's
licences, and no other crate is configured. Exits non-zero, saying what
differs."""

import pathlib
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parents[2]
about = tomllib.loads((root / "tools/licences/about.toml").read_text())
deny = tomllib.loads((root / "tools/security/deny.toml").read_text())["licenses"]

errors = []
if sorted(about["accepted"]) != sorted(deny["allow"]):
    only_about = sorted(set(about["accepted"]) - set(deny["allow"]))
    only_deny = sorted(set(deny["allow"]) - set(about["accepted"]))
    errors.append(f"accepted differs: only in about.toml {only_about}, only in deny.toml {only_deny}")

exceptions = {}
for e in deny.get("exceptions", []):
    name = e["crate"].split("@")[0]
    exceptions[name] = sorted(e["allow"])
crates = {k: sorted(v.get("accepted", [])) for k, v in about.items() if isinstance(v, dict)}
if crates != exceptions:
    errors.append(f"per-crate licences differ: about.toml {crates}, deny.toml exceptions {exceptions}")

for e in errors:
    print(f"licences: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
