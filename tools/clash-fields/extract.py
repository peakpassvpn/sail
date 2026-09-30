#!/usr/bin/env python3
# Copyright the sail authors. Licensed under the Apache License, Version 2.0.
"""Every field Mihomo's configuration takes, from a Mihomo checkout, as the
paths sail's Clash front-end reads them: `dns.nameserver`,
`proxies[vmess].ws-opts.path`, `proxy-groups[url-test].tolerance`,
`listeners[tuic].users`, `proxy-providers[*].override.skip-cert-verify`.

    tools/clash-fields/extract.py MIHOMO_CHECKOUT TAG > sail/src/config/clash/fields.json

Run by hand when Mihomo moves; the build and the tests read only the
JSON. It reads struct tags (`yaml`, `proxy`, `group`, `provider`,
`inbound`, `obfs`) and the switches that pick a struct by `type`; it copies
no code.
"""
import json
import os
import re
import sys

STRUCT = re.compile(r"^type\s+(\w+)\s+struct\s*\{", re.M)
FIELD = re.compile(r"^\s*(?:(\w+)\s+)?([^`\s][^`]*?)\s*`([^`]*)`", re.M)
TAG = re.compile(r'(\w+):"([^"]*)"')
# An embedded struct: a type alone on its line, maybe a pointer.
EMBEDDED = re.compile(r"^\s*\*?((?:\w+\.)?[A-Z]\w*)\s*(?://.*)?$")
ALIAS = re.compile(r"^type\s+(\w+)\s+(\[\]\w+|\w+)\s*$", re.M)


def load(root):
    """Structs by name (the last part of a qualified name), with their
    fields as (name, type, tags); and named non-struct types."""
    structs, aliases = {}, {}
    for dirpath, _, files in os.walk(root):
        if "/test" in dirpath or "/.git" in dirpath:
            continue
        for f in files:
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            text = open(os.path.join(dirpath, f), encoding="utf-8", errors="replace").read()
            for m in STRUCT.finditer(text):
                body, depth, i = [], 1, m.end()
                while depth and i < len(text):
                    c = text[i]
                    depth += c == "{"
                    depth -= c == "}"
                    body.append(c)
                    i += 1
                fields = []
                for line in "".join(body).splitlines():
                    if line.lstrip().startswith("//"):
                        continue
                    em = EMBEDDED.match(line)
                    if em:
                        fields.append((None, em.group(1), {}))
                        continue
                    fm = FIELD.match(line)
                    if not fm:
                        continue
                    name, typ, tags = fm.group(1), fm.group(2), dict(TAG.findall(fm.group(3)))
                    fields.append((name, typ, tags))
                # Names repeat across packages (an outbound's and a
                # listener's `VmessOption`): keep every one.
                structs.setdefault(m.group(1), []).append(fields)
            for m in ALIAS.finditer(text):
                aliases.setdefault(m.group(1), m.group(2))
    return structs, aliases


def kind(typ, structs, aliases, seen=()):
    """A JSON-ish kind for a Go type: string, bool, number, list, object,
    or ("struct", name)."""
    t = typ.lstrip("*")
    if t.startswith("[]"):
        inner = kind(t[2:], structs, aliases, seen)
        return ("list", inner)
    if t.startswith("map[") or "OrderedMap" in t:
        return "object"
    base = t.split(".")[-1]
    if base in ("string", "Prefix", "Addr", "AddrPort", "IP", "URL"):
        return "string"
    if base == "bool":
        return "bool"
    if re.fullmatch(r"u?int(8|16|32|64)?|float(32|64)|Duration", base):
        return "number"
    if base in ("any", "interface{}", "Node"):
        return "object"
    if base in structs and base not in seen:
        return ("struct", base)
    if base in aliases:
        return kind(aliases[base], structs, aliases, seen)
    return "string"


def fields_of(struct, tag, structs):
    """The fields of the struct named `struct` that is read by `tag`: of
    those so named, the one with the most fields tagged so."""
    candidates = structs.get(struct, [])
    if not candidates:
        return []
    return max(candidates, key=lambda fs: sum(1 for _, _, t in fs if tag in t))


def walk(struct, tag, prefix, structs, aliases, out, seen=()):
    """The fields of `struct` by their `tag`, embedded structs flattened."""
    for name, typ, tags in fields_of(struct, tag, structs):
        key = tags.get(tag)
        base = typ.lstrip("*").split(".")[-1]
        if key is None:
            # Embedded (no name), or `,inline`/`,squash`: its fields are ours.
            if name is None and base in structs and base not in seen:
                walk(base, tag, prefix, structs, aliases, out, seen + (base,))
            continue
        field = key.split(",")[0]
        opts = key.split(",")[1:]
        if field == "-":
            continue
        if field == "" or "inline" in opts or "squash" in opts:
            if base in structs and base not in seen:
                walk(base, tag, prefix, structs, aliases, out, seen + (base,))
            continue
        path = f"{prefix}.{field}" if prefix else field
        k = kind(typ, structs, aliases)
        if isinstance(k, tuple) and k[0] == "struct" and k[1] not in seen:
            out[path] = "object"
            walk(k[1], tag, path, structs, aliases, out, seen + (k[1],))
        elif isinstance(k, tuple) and k[0] == "list" and isinstance(k[1], tuple) and k[1][0] == "struct":
            out[path] = "list"
            walk(k[1][1], tag, path + "[]", structs, aliases, out, seen + (k[1][1],))
        elif isinstance(k, tuple) and k[0] == "list":
            out[path] = "list"
        else:
            out[path] = k if isinstance(k, str) else "object"


def switch(root, rel, pattern):
    """(type, struct) pairs from a `case "type": x := &pkg.Struct{` switch."""
    text = open(os.path.join(root, rel), encoding="utf-8").read()
    return re.findall(pattern, text, re.S)


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    root, tag = argv[1], argv[2]
    structs, aliases = load(root)
    fields = {}

    # Top level, by `yaml`; the sections parsed by other tags come after.
    top = {}
    walk("RawConfig", "yaml", "", structs, aliases, top)
    for section in ("proxies", "proxy-groups", "proxy-providers", "rule-providers", "listeners"):
        top.pop(section, None)
        for key in list(top):
            if key.startswith(section + "."):
                top.pop(key)
    fields.update(top)

    case = r'case\s+"([\w-]+)":\s*\n\s*\w+\s*:?=\s*&?(?:\w+\.)?(\w+)\{'
    for kind_, st in switch(root, "adapter/parser.go", case):
        out = {}
        walk(st, "proxy", f"proxies[{kind_}]", structs, aliases, out)
        fields.update(out)
    # The plugins' options, by plugin.
    for proxy, key, plugins in (
        ("ss", "plugin-opts", {
            "obfs": "simpleObfsOption", "v2ray-plugin": "v2rayObfsOption",
            "gost-plugin": "gostObfsOption", "shadow-tls": "shadowTLSOption",
            "restls": "restlsOption", "kcptun": "kcpTunOption",
        }),
        ("snell", "obfs-opts", {"obfs": "simpleObfsOption"}),
    ):
        for plugin, st in plugins.items():
            out = {}
            walk(st, "obfs", f"proxies[{proxy}].{key}[{plugin}]", structs, aliases, out)
            fields.update(out)

    # Groups: the options every group takes, and each type's own.
    common = {}
    walk("GroupCommonOption", "group", "proxy-groups[*]", structs, aliases, common)
    fields.update(common)
    for kind_, st in switch(root, "adapter/outboundgroup/parser.go", r'case\s+"([\w-]+)":\s*\n\s*opt\s*:=\s*(\w+)\{'):
        out = {}
        walk(st, "group", f"proxy-groups[{kind_}]", structs, aliases, out)
        fields.update(out)

    for name, st, prefix in (
        ("proxy-providers", "proxyProviderSchema", "proxy-providers[*]"),
        ("rule-providers", "ruleProviderSchema", "rule-providers[*]"),
    ):
        out = {}
        walk(st, "provider", prefix, structs, aliases, out)
        fields.update(out)

    for kind_, st in switch(root, "listener/parse.go", r'case\s+"([\w-]+)":\s*\n\s*\w+\s*:?=\s*&?(?:\w+\.)?(\w+)\{'):
        out = {}
        walk(st, "inbound", f"listeners[{kind_}]", structs, aliases, out)
        fields.update(out)

    doc = {
        "mihomo": tag,
        "note": "Generated by tools/clash-fields/extract.py from a Mihomo checkout; do not edit.",
        "fields": [{"path": p, "json": k} for p, k in sorted(fields.items())],
    }
    json.dump(doc, sys.stdout, indent=1, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
