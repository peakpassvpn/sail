#!/usr/bin/env python3
"""How far each fork sail depends on is from its upstream, as Markdown.

For every fork in forks.json: the upstream commits its branch has not merged,
the fork's own commits and how many of them upstream already has (git
cherry), upstream's latest tag, and whether the revision sail pins is the
branch's tip. Nothing is merged or pushed; a person does that, merging
upstream into the branch (never rebasing it: sail pins revisions, and a
rewritten branch would orphan them).

Usage: report.py [--repo DIR]   (DIR: the sail checkout, for its pins)
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent


def git(cwd, *args, check=True):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


def pins(repo, fork):
    """The revisions sail's manifests pin for `fork`, as {rev: [file, ...]}."""
    url = re.compile(r'git\s*=\s*"https://github\.com/' + re.escape(fork) + r'(?:\.git)?"[^}]*rev\s*=\s*"([0-9a-f]{7,40})"')
    found = {}
    for path in sorted(repo.glob("**/Cargo.toml")):
        if "target" in path.parts:
            continue
        for rev in url.findall(path.read_text()):
            files = found.setdefault(rev, [])
            if str(path.relative_to(repo)) not in files:
                files.append(str(path.relative_to(repo)))
    return found


def one(entry, repo, work):
    fork, branch = entry["fork"], entry["branch"]
    upstream, uref = entry["upstream"], entry["upstream_ref"]
    d = work / fork.replace("/", "_")
    git(work, "init", "-q", str(d))
    git(d, "remote", "add", "fork", f"https://github.com/{fork}.git")
    git(d, "remote", "add", "upstream", f"https://github.com/{upstream}.git")
    lines = [f"### [{fork}](https://github.com/{fork}/tree/{branch}) ← [{upstream}](https://github.com/{upstream}/tree/{uref})", ""]
    if not git(d, "ls-remote", "--heads", "fork", branch, check=False):
        return lines + [f"No `{branch}` branch yet.", ""], False
    git(d, "fetch", "-q", "--filter=blob:none", "fork", f"+refs/heads/{branch}:refs/f")
    git(d, "fetch", "-q", "--filter=blob:none", "--tags", "upstream", f"+refs/heads/{uref}:refs/u")
    behind = int(git(d, "rev-list", "--count", "refs/f..refs/u"))
    ours = git(d, "cherry", "refs/u", "refs/f").splitlines()
    absorbed = sum(1 for l in ours if l.startswith("-"))
    tag = git(d, "describe", "--tags", "--abbrev=0", "refs/u", check=False) or "none"
    tip = git(d, "rev-parse", "refs/f")
    lines.append(f"- Upstream `{uref}` has **{behind}** commit(s) the branch has not merged; latest upstream tag: `{tag}`.")
    lines.append(f"- The branch carries {len(ours)} commit(s) of its own; upstream already has {absorbed} of them.")
    action = behind > 0 or absorbed > 0
    for rev, files in pins(repo, fork).items():
        full = git(d, "rev-parse", "--verify", "-q", rev + "^{commit}", check=False)
        if not full:
            lines.append(f"- sail pins `{rev[:12]}` ({', '.join(files)}): **not found on the branch**, so a rewrite may have orphaned it.")
            action = True
        elif full == tip:
            lines.append(f"- sail pins the branch tip `{rev[:12]}` ({', '.join(files)}).")
        else:
            n = git(d, "rev-list", "--count", f"{full}..refs/f")
            lines.append(f"- sail pins `{rev[:12]}` ({', '.join(files)}), {n} commit(s) behind the branch tip `{tip[:12]}`.")
            action = True
    if absorbed and absorbed == len(ours):
        lines.append("- Every commit of the fork is upstream: sail can go back to upstream and the fork can be archived.")
    lines.append(f"- Owner: {entry['owner']}.")
    return lines + [""], action


def main():
    repo = pathlib.Path(sys.argv[sys.argv.index("--repo") + 1]) if "--repo" in sys.argv else HERE.parent.parent
    forks = json.loads((HERE / "forks.json").read_text())
    out = ["# Upstream sync report", "",
           "Generated weekly by the `upstream-watch` job of `.github/workflows/ci.yml` from `tools/upstream-watch/forks.json`. "
           "To sync a fork: merge upstream into its branch (no rebase, no force push), run its tests, "
           "then move sail's pin in one batch.", ""]
    pending = 0
    with tempfile.TemporaryDirectory() as tmp:
        for entry in forks:
            try:
                lines, action = one(entry, repo, pathlib.Path(tmp))
            except RuntimeError as e:
                lines, action = [f"### {entry['fork']}", "", f"Could not be checked: {e}", ""], True
            pending += action
            out += lines
    out.insert(2, f"**{pending}** of {len(forks)} fork(s) need attention." if pending else "Every fork is in step with its upstream.")
    out.insert(3, "")
    print("\n".join(out))


if __name__ == "__main__":
    main()
