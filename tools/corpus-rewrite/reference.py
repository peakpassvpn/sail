#!/usr/bin/env python3
# Copyright the sail authors. Licensed under the Apache License, Version 2.0.
"""What the reference implementations make of the corpus: `sing-box check`
over sail/tests/corpus/sing-box and `mihomo -t` over sail/tests/corpus/clash,
written to sail/tests/corpus/reference.json beside sail's own outcomes
(expected.json). Run by hand; the build and the tests never need either
program.

    tools/corpus-rewrite/reference.py --sing-box PATH --mihomo PATH

mihomo downloads its GeoIP and GeoSite data into a scratch home the first
time.
"""
import argparse, json, os, re, subprocess, tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "sail", "tests", "corpus")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def errors(text, corpus_dir):
    """Every error the program logged, its paths and log prefixes dropped:
    mihomo logs some at error level and goes on, so which of them failed
    the test is not known; sing-box stops at its first."""
    found = []
    for line in text.splitlines():
        line = ANSI.sub("", line)
        if "level=" in line and not re.search(r"level=(error|fatal)", line):
            continue
        if line.startswith(("WARN", "INFO", "DEBUG")) or "test failed" in line:
            continue
        m = re.search(r'msg="(.*)"', line)
        if m:
            line = m.group(1)
        line = re.sub(r"^(FATAL|ERROR)\[\d+\]\s*", "", line)
        line = line.replace(corpus_dir + os.sep, "")
        line = re.sub(r"/[^ :]*/(path-\d+\.\w+)", r"./\1", line)
        if line.strip():
            found.append(line.strip())
    return found or ["rejected"]


def run(cmd, cwd):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, "timed out"


def version(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
    return out[0].strip() if out else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sing-box", required=True)
    ap.add_argument("--mihomo", required=True)
    args = ap.parse_args()
    verdicts = {}
    with tempfile.TemporaryDirectory() as scratch:
        for name, cmd in (
            ("sing-box", lambda f: [args.sing_box, "check", "-c", f, "-D", scratch]),
            ("clash", lambda f: [args.mihomo, "-t", "-f", f, "-d", scratch]),
        ):
            directory = os.path.join(CORPUS, name)
            for file in sorted(os.listdir(directory)):
                code, out = run(cmd(os.path.join(directory, file)), scratch)
                key = f"{name}/{file}"
                verdicts[key] = {"ok": True} if code == 0 else {"errors": errors(out, directory)}
    reference = {
        "tools": {
            "sing-box": version([args.sing_box, "version"]),
            "mihomo": version([args.mihomo, "-v"]),
        },
        "note": "By hand, with tools/corpus-rewrite/reference.py. `errors` lists every error the program logged: mihomo logs some and goes on (global-client-fingerprint), so a rejection is any of them. A first rewriter wrote every wildcard domain as \"dN*.example\", which mihomo refuses; the Clash lists were repaired to \"dN.*.example\", a whole-label wildcard as the defaults have it (\"time.*.com\"). Surge has no reference program.",
        "verdicts": verdicts,
    }
    with open(os.path.join(CORPUS, "reference.json"), "w") as f:
        json.dump(reference, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
