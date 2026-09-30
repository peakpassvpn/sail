#!/usr/bin/env python3
# Copyright the sail authors. Licensed under the Apache License, Version 2.0.
"""Every field of a Surge profile, from Surge's manual (manual.nssurge.com),
as paths: `General.dns-server`, `Proxy[ss].encrypt-method`,
`Proxy[ss].server` (a value in a place of its own), `Proxy Group[url-test].
tolerance`, `Rule[DOMAIN]`, `Rule[IP-CIDR].no-resolve`, `WireGuard.mtu`,
`WireGuard.peer.endpoint`, `Keystore.base64`, `SSID Setting.suspend`, and a
section read as a whole by its name: `Host`, `MITM`.

    tools/surge-fields/extract.py MANUAL_DIR > sail/src/config/surge/fields.json

MANUAL_DIR holds the manual's pages as the site serves them, by their
paths (`profile/general.html`, `policies/shadowsocks.html`, ...). Run by
hand when the manual moves; the build and the tests read only the JSON.

It reads the headings the manual gives each key and parameter, the line
under each that says what it takes, and the tables of proxy types, group
types, rule types and rule parameters. What the manual says only in prose
is in `extra.json`. Only names and kinds are taken; no text is copied.
"""
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

HEADING = re.compile(r'<h([1-4]) id="([^"]*)">(.*?)</h\1>(?:\s*<p>(.*?)</p>)?', re.S)
CODE = re.compile(r"<code>(.*?)</code>", re.S)


def page(root, rel):
    text = open(os.path.join(root, rel), encoding="utf-8").read()
    start, end = text.find("<section"), text.find("</section>")
    return text[start:end] if start >= 0 else text


def plain(s):
    s = re.sub(r'<span class="badge">.*?</span>', "", s or "")
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def headings(body):
    """(level, id, text, the line under it)."""
    for m in HEADING.finditer(body):
        yield int(m.group(1)), m.group(2), plain(m.group(3)), m.group(4) or ""


def kind(line):
    """A key's kind, and a value of it besides its default, from what the
    manual says it takes: `Optional, Boolean, default: false`."""
    text = plain(line)
    default = re.search(r"default:\s*([^\s,.]+)", text)
    default = default.group(1).strip("`") if default else None
    if re.search(r"\bboolean\b", text, re.I):
        return "bool", "false" if default == "true" else "true"
    # A choice of values: `a` | `b`, `a` / `b`, `a` or `b`, before the
    # default.
    choice = re.search(
        r"<code>[^<]*</code>(?:\s*(?:\||/|or|,)\s*<code>[^<]*</code>)+", line.split("default:")[0]
    )
    values = [html.unescape(v) for v in CODE.findall(choice.group(0))] if choice else []
    values = [v for v in values if re.fullmatch(r"[\w.-]+", v)]
    if len(values) >= 2:
        other = [v for v in values if v != default]
        return "string", (other or values)[0]
    if re.search(r"in seconds|in milliseconds|integer|port number|\d+[–-]\d+", text, re.I):
        return "number", None
    return "string", None


def keys_of(text):
    """The keys a heading names: `username / password` is two;
    `interface: Required, ...` is `interface`, and what follows its kind."""
    head, _, rest = text.partition(":")
    names = [k.strip() for k in head.split("/")]
    names = [k for k in names if re.fullmatch(r"[a-z][a-z0-9-]*", k)]
    return names, rest


def params(body, sections=None):
    """The keys of a page's headings: every fourth-level heading, or those
    under the second- or third-level headings whose ids `sections` lists
    (by prefix). Each (key, kind, sample, proxy_only)."""
    out = []
    under = sections is None
    for level, hid, text, line in headings(body):
        if level < 4:
            if sections is not None:
                under = any(hid.startswith(s) for s in sections)
            continue
        if not under:
            continue
        names, rest = keys_of(text)
        what = line if not rest.strip() else rest
        k, sample = kind(what)
        only = "Proxy policies only" in plain(line)
        for name in names:
            out.append((name, k, sample, only))
    return out


def described(body, key):
    """What a page says under the heading of `key`, up to the next one."""
    for m in HEADING.finditer(body):
        if key in keys_of(plain(m.group(3)))[0]:
            rest = body[m.end():]
            end = re.search(r"<h[1-4] ", rest)
            return plain(m.group(4) or "") + " " + plain(rest[: end.start() if end else None])
    return ""


def holds_for(body, key, t, same_page):
    """Whether a parameter a page lists for the types `same_page` holds
    for `t`: not where it says it is for another only (`For h2-connect
    only`, `Required for tuic-v5`) or not used by `t`."""
    text = described(body, key)
    only = set(re.findall(r"\bFor ([\w-]+) only", text))
    only |= set(re.findall(r"\bRequired for ([\w-]+)", text))
    only &= set(same_page)
    never = set(re.findall(r"\bNot used by ([\w-]+)", text)) & set(same_page)
    return (not only or t in only) and t not in never


def table(body, after_id):
    """The rows of the first table after the heading `after_id`, as cells."""
    i = body.find(f'id="{after_id}"')
    if i < 0:
        sys.exit(f"no heading {after_id}")
    t = body[i:]
    t = t[t.find("<tbody>"): t.find("</tbody>")]
    rows = []
    for row in re.findall(r"<tr>(.*?)</tr>", t, re.S):
        rows.append(re.findall(r"<td>(.*?)</td>", row, re.S))
    return rows


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    root = argv[1]
    extra = json.load(open(os.path.join(HERE, "extra.json"), encoding="utf-8"))
    fields = {}

    def add(path, k="string", sample=None):
        entry = {"path": path, "json": k}
        if sample is not None:
            entry["sample"] = sample
        fields[path] = entry

    # [General].
    for key, k, sample, _ in params(page(root, "profile/general.html")):
        add(f"General.{key}", k, sample)

    # [Proxy]: the types of the table, each with the page it links to, and
    # the aliases of the built-in policies.
    overview = page(root, "policies/overview.html")
    types = {}
    quic = set()
    for cells in table(overview, "supported-proxy-protocols"):
        link = re.search(r'href="([^"]+)"', cells[1]).group(1)
        for t in CODE.findall(cells[0]):
            types[t] = f"policies/{link}"
            if "QUIC-based" in plain(cells[2]):
                quic.add(t)
    alias_line = next(p for p in re.findall(r"<p>(.*?)</p>", overview, re.S) if "built-in type keywords" in p)
    aliases = [a for a in CODE.findall(alias_line) if re.fullmatch(r"[a-z-]+", a)]
    common = params(page(root, "policies/parameters.html"))
    tls_page = page(root, "policies/tls.html")
    tls = params(tls_page, ["parameters"])
    shadow_tls = params(tls_page, ["shadow-tls"])
    for alias in aliases:
        add(f"Proxy[{alias}]")
        for key, k, sample, only in common:
            if not only:
                add(f"Proxy[{alias}].{key}", k, sample)
    for t, link in types.items():
        body = page(root, link)
        add(f"Proxy[{t}]")
        # A server and a port in places of their own, as the examples write
        # them.
        codes = " ".join(html.unescape(c) for c in re.findall(r"<pre><code>(.*?)</code></pre>", body, re.S))
        server = re.search(rf"=\s*{re.escape(t)}\s*,\s*[^,=\s]+\s*,\s*\d+", codes)
        if server:
            add(f"Proxy[{t}].server")
            add(f"Proxy[{t}].port", "number")
        same_page = [o for o, l in types.items() if l == link]
        for key, k, sample, _ in params(body, ["parameters", "policy-line"]):
            if holds_for(body, key, t, same_page):
                add(f"Proxy[{t}].{key}", k, sample)
        if "common-parameters" in body or "parameters.html" in body:
            if not re.search(r'id="policy-line"', body):
                for key, k, sample, _ in common:
                    add(f"Proxy[{t}].{key}", k, sample)
        if t in extra["tls"]["types"]:
            for key, k, sample, _ in tls:
                add(f"Proxy[{t}].{key}", k, sample)
        if server and t not in quic and t not in extra["no-shadow-tls"]["types"]:
            for key, k, sample, _ in shadow_tls:
                add(f"Proxy[{t}].{key}", k, sample)
    # [WireGuard <name>], and its peers' fields.
    wg = page(root, "policies/wireguard.html")
    for key, k, sample, _ in params(wg, ["wireguard-section"]):
        add(f"WireGuard.{key}", k, sample)
    for key, k, sample, _ in params(wg, ["peer-fields"]):
        add(f"WireGuard.peer.{key}", k, sample)

    # [Proxy Group]: the types of the table, the parameters every group
    # takes, those of policy including, and each type's own.
    groups = [CODE.findall(c[0])[0] for c in table(page(root, "policy-groups/overview.html"), "group-types")]
    group_common = params(page(root, "policy-groups/parameters.html"))
    including = params(page(root, "policy-groups/policy-including.html"))
    including += [(key, "string", None, False) for key in extra["group-params"]["keys"]]
    aliases = {k: v for k, v in extra["group-aliases"].items() if k != "note"}
    for g in groups + list(aliases):
        own = aliases.get(g, g)
        add(f"Proxy Group[{g}]")
        for key, k, sample, _ in params(page(root, f"policy-groups/{own}.html"), ["parameters"]):
            add(f"Proxy Group[{g}].{key}", k, sample)
        for key, k, sample, _ in group_common + including:
            limited = extra["group-limited"].get(own)
            if limited is not None and key not in limited:
                continue
            add(f"Proxy Group[{g}].{key}", k, sample)

    # [Rule]: the types of the index, and the parameters each takes.
    rules_page = page(root, "rules/overview.html")
    rule_types = [plain(c[0]) for c in table(rules_page, "rule-type-index")]
    for t in rule_types:
        add(f"Rule[{t}]")
    classes = {
        "Domain types": [t for t in rule_types if t.startswith("DOMAIN")],
        "IP types": ["IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"],
        "logical rules": ["AND", "OR", "NOT"],
    }
    for cells in table(rules_page, "rule-parameters"):
        key = plain(cells[0]).split("=")[0]
        k = "flag" if plain(cells[1]) == "flag" else "string"
        applies = plain(cells[2])
        if applies.startswith("Any rule"):
            which = rule_types
        else:
            which = []
            for part in applies.replace(" only", "").split(","):
                part = part.strip()
                which += classes.get(part, [part])
        for t in which:
            if t not in rule_types:
                sys.exit(f"rule parameter {key}: no rule type {t}")
            add(f"Rule[{t}].{key}", "number" if "seconds" in plain(cells[0]) else k)

    # The sections read key by key, and those read as a whole.
    for key, k, sample, _ in params(page(root, "profile/keystore.html")):
        add(f"Keystore.{key}", k, sample)
    for key, k, sample, _ in params(page(root, "features/subnet-settings.html")):
        add(f"SSID Setting.{key}", k, sample)
    sections = set()
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".html"):
                body = page(root, os.path.relpath(os.path.join(dirpath, f), root))
                for name in CODE.findall(body):
                    name = html.unescape(name)
                    m = re.fullmatch(r"\[([A-Z][A-Za-z ]*?)(?: (?:<[\w-]+>|\*))?\]", name)
                    if m:
                        sections.add(m.group(1))
    by_key = {"General", "Proxy", "Proxy Group", "Rule", "WireGuard", "Keystore", "SSID Setting"}
    for s in sorted(sections - by_key):
        add(s)

    for f in extra["fields"]:
        add(f["path"], f.get("json", "string"), f.get("sample"))

    dates = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".html"):
                text = open(os.path.join(dirpath, f), encoding="utf-8").read()
                dates += re.findall(r'"time":"(\d{4}-\d\d-\d\d)T', text)
    doc = {
        "surge": f"manual.nssurge.com of {max(dates)}",
        "note": "Generated by tools/surge-fields/extract.py from Surge's manual; do not edit.",
        "fields": [fields[p] for p in sorted(fields)],
    }
    json.dump(doc, sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
