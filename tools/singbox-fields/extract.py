#!/usr/bin/env python3
"""List every field a sing-box configuration can hold, by path.

    extract.py <sing-box checkout> [<out.json>]

Reads the checkout's JSON schema (docs/schema.json, which sing-box
generates from its option types) for the fields it documents, and the Go
option types (option/*.go) for the fields it leaves out of the schema:
deprecated fields, of which it still accepts some and rejects the rest.
Writes sail/src/config/singbox/fields.json by default.

A path names a field as sing-box's JSON nests it: `.` into an object, `[]`
into a list's entries, `[x]` into the entries of type `x`, and `[k=x]` into
those whose `k` is `x` (a rule's action), so that
`inbounds[vless].users[].flow` is the `flow` of a user of a VLESS inbound.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "sail/src/config/singbox/fields.json"

# The rules a logical rule combines: the conditions of the rule they are
# in, listed there.
NESTED_RULES = {"NestedRule", "NestedDNSRule"}


class Schema:
    def __init__(self, root: dict[str, Any]):
        self.root = root
        self.defs = root.get("$defs", {})

    def resolve(self, node: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        name = None
        while "$ref" in node:
            name = node["$ref"].rsplit("/", 1)[-1]
            node = self.defs[name]
        return node, name


def is_duration(node: dict[str, Any]) -> bool:
    return node.get("type") == "string" and "ms|s|m|h" in node.get("pattern", "")


def scalar(s: Schema, node: dict[str, Any]) -> str | None:
    """The JSON type of a value that holds no fields, or None."""
    node, _ = s.resolve(node)
    if "const" in node:
        return "string" if isinstance(node["const"], str) else "number"
    kind = node.get("type")
    if is_duration(node):
        return "duration"
    if kind == "string":
        return "string"
    if kind == "boolean":
        return "bool"
    if kind in ("integer", "number"):
        return "number"
    return None


def listable(s: Schema, node: dict[str, Any]) -> dict[str, Any] | None:
    """What a field takes one of or a list of, if it is such a field."""
    alts = node.get("anyOf")
    if not alts or len(alts) != 2:
        return None
    one, many = alts
    many, _ = s.resolve(many)
    if many.get("type") == "array" and many.get("items") == one:
        return one
    return None


def describe(s: Schema, node: dict[str, Any]) -> str:
    """The JSON type of a field, as fields.json writes it."""
    node, _ = s.resolve(node)
    item = listable(s, node)
    if item is not None:
        return "listable-" + describe(s, item)
    alts = node.get("anyOf") or (node.get("oneOf") if not objects(s, node) else None)
    if alts:
        return "|".join(dict.fromkeys(describe(s, alt) for alt in alts))
    k = scalar(s, node)
    if k:
        return k
    kind = node.get("type")
    if kind == "array":
        return "array"
    if "oneOf" in node or "allOf" in node:
        return "object"
    if kind == "object":
        if "properties" not in node and isinstance(node.get("additionalProperties"), dict):
            return "map"
        return "object"
    return "any"


def enum(s: Schema, node: dict[str, Any]) -> list[Any] | None:
    node, _ = s.resolve(node)
    item = listable(s, node)
    if item is not None:
        return enum(s, item)
    if "enum" in node:
        return [v for v in node["enum"] if v != ""]
    return None


def objects(s: Schema, node: dict[str, Any]) -> bool:
    """Whether the value has fields of its own to list."""
    node, _ = s.resolve(node)
    if "properties" in node or "oneOf" in node or "allOf" in node:
        return all(
            s.resolve(alt)[0].get("type") in ("object", None) for alt in node.get("oneOf", [])
        )
    return False


def discriminator(s: Schema, branches: list[dict[str, Any]]) -> str | None:
    """The field whose value tells a union's alternatives apart."""
    props = [props_of(s, b)[0] for b in branches]
    for key in ("type", "action", "provider"):
        if all(key in p and ("const" in p[key] or "enum" in p[key]) for p in props):
            return key
    return None


def expand(s: Schema, branches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A union's alternatives, those of a union within it included (the
    versions of one type)."""
    out = []
    for b in branches:
        node, _ = s.resolve(b)
        if "oneOf" in node and "properties" not in node and "allOf" not in node:
            out += expand(s, node["oneOf"])
        else:
            out.append(b)
    return out


def label_of(prop: dict[str, Any]) -> str:
    if "const" in prop:
        return str(prop["const"])
    return next(str(v) for v in prop["enum"] if v != "")


def props_of(
    s: Schema, node: dict[str, Any]
) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    """An object's own fields, the required ones, and the unions it is
    also one of (a rule and its action)."""
    node, _ = s.resolve(node)
    props: dict[str, Any] = {}
    required: list[str] = []
    unions: list[dict[str, Any]] = []
    for part in [node] + node.get("allOf", []):
        part, _ = s.resolve(part)
        if "oneOf" in part and part is not node:
            unions.append(part)
            continue
        props.update(part.get("properties", {}))
        required += part.get("required", [])
    return props, required, unions


class Walker:
    def __init__(self, schema: Schema, go: "GoTypes"):
        self.s = schema
        self.go = go
        self.fields: dict[str, dict[str, Any]] = {}

    def emit(self, path: str, node: dict[str, Any], required: bool) -> None:
        if path in self.fields:
            return
        entry: dict[str, Any] = {"path": path, "json": describe(self.s, node)}
        values = enum(self.s, node)
        if values:
            entry["enum"] = values
        if required:
            entry["required"] = True
        self.fields[path] = entry

    def field(self, path: str, node: dict[str, Any], required: bool, stack: tuple) -> None:
        self.emit(path, node, required)
        self.value(path, node, stack)

    def value(self, path: str, node: dict[str, Any], stack: tuple) -> None:
        """Lists the fields of what `path` holds."""
        node, name = self.s.resolve(node)
        if name in NESTED_RULES or (name and name in stack):
            return
        if name:
            stack = stack + (name,)
        item = listable(self.s, node)
        if item is not None:
            item_node, _ = self.s.resolve(item)
            if objects(self.s, item_node):
                self.entries(path + "[]", item_node, stack)
            return
        if "anyOf" in node:
            for alt in node["anyOf"]:
                alt, _ = self.s.resolve(alt)
                if alt.get("type") == "object" and "properties" in alt:
                    self.object(path, alt, stack)
            return
        if node.get("type") == "array":
            items = node.get("items", {})
            if objects(self.s, items):
                self.entries(path + "[]", items, stack)
            return
        if objects(self.s, node):
            self.entries(path, node, stack)

    def entries(self, path: str, node: dict[str, Any], stack: tuple) -> None:
        """`path` holds an object, or one of a union of objects; `path` ends
        in `[]` when it is a list's entry."""
        node, name = self.s.resolve(node)
        if name in NESTED_RULES or (name and name in stack):
            return
        if name:
            stack = stack + (name,)
        if "oneOf" in node:
            self.union(path, node, stack)
        else:
            self.object(path, node, stack)

    def union(self, path: str, node: dict[str, Any], stack: tuple) -> None:
        branches = expand(self.s, node["oneOf"])
        key = discriminator(self.s, branches)
        if key is None:
            for b in branches:
                self.object(path, b, stack)
            return
        base = path[:-2] if path.endswith("[]") else path
        labels = []
        for b in branches:
            props, _, _ = props_of(self.s, b)
            labels.append(label_of(props[key]))
        # The tag itself, once, with every type it names.
        tag = f"{base}[].{key}" if path.endswith("[]") else f"{base}.{key}"
        self.fields.setdefault(
            tag, {"path": tag, "json": "string", "enum": list(dict.fromkeys(labels))}
        )
        for b, label in zip(branches, labels):
            # A rule's default type goes without saying.
            if key == "type":
                sel = "[]" if label == "default" else f"[{label}]"
            else:
                sel = f"[{key}={label}]"
            self.object(base + sel, b, stack, skip=key, union_base=base)

    def object(
        self,
        path: str,
        node: dict[str, Any],
        stack: tuple,
        skip: str | None = None,
        union_base: str | None = None,
    ) -> None:
        props, required, unions = props_of(self.s, node)
        for key, prop in props.items():
            if key == skip:
                continue
            self.field(f"{path}.{normal(key)}", prop, key in required, stack)
        for extra in self.go.omitted(set(props)):
            p = f"{path}.{extra['json']}"
            if p not in self.fields and extra["json"] not in props:
                entry = {"path": p, "json": extra["kind"], "deprecated": True}
                self.fields[p] = entry
        for key in self.go.deprecated(set(props)):
            p = f"{path}.{key}"
            if p in self.fields:
                self.fields[p]["deprecated"] = True
        for u in unions:
            self.union((union_base or path) + "[]", u, stack)


def normal(key: str) -> str:
    """A Go field without a JSON name is matched ignoring case; sing-box
    documents it in lower case (a user's `username`)."""
    if re.fullmatch(r"[A-Z][a-z]+", key):
        return key.lower()
    return key


# ---------------------------------------------------------------------------
# Go option types: what the schema leaves out.
# ---------------------------------------------------------------------------

STRUCT = re.compile(r"^type\s+(\w+)\s+struct\s*\{\s*$")
FIELD = re.compile(r"^(\w+)\s+([^`]+?)\s*(`[^`]*`)?\s*(//.*)?$")
EMBEDDED = re.compile(r"^(\*?[\w.]+)\s*(`[^`]*`)?\s*(//.*)?$")
TAG = re.compile(r'(\w+):"([^"]*)"')


def go_kind(t: str) -> str:
    t = t.strip().lstrip("*")
    if t == "bool":
        return "bool"
    if t == "string" or t.endswith("Strategy"):
        return "string"
    if re.fullmatch(r"u?int\d*", t):
        return "number"
    if t.endswith("Duration"):
        return "duration"
    m = re.fullmatch(r"badoption\.Listable\[(.+)\]", t)
    if m:
        return "listable-" + go_kind(m.group(1))
    if t.startswith("[]"):
        return "array"
    return "object"


class GoTypes:
    def __init__(self, checkout: Path):
        self.structs: dict[str, list[dict[str, Any]]] = {}
        for path in sorted((checkout / "option").glob("*.go")):
            if not path.name.endswith("_test.go"):
                self.parse(path.read_text())
        self.aliases: dict[str, str] = {}
        for path in sorted((checkout / "option").glob("*.go")):
            for m in re.finditer(r"^type\s+(\w+)\s+(_?\w+)\s*$", path.read_text(), re.M):
                self.aliases[m.group(1)] = m.group(2)
        self.rejected = self.rejections(checkout)

    def parse(self, text: str) -> None:
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            m = STRUCT.match(lines[i])
            i += 1
            if not m:
                continue
            fields = []
            deprecated = False
            while i < len(lines) and lines[i] != "}":
                line = lines[i].strip()
                i += 1
                if line.startswith("//"):
                    deprecated = deprecated or line.startswith("// Deprecated")
                    continue
                if not line:
                    deprecated = False
                    continue
                f = FIELD.match(line)
                e = EMBEDDED.match(line)
                if e and not (f and not f.group(2).startswith("`")):
                    tags = dict(TAG.findall(e.group(2) or ""))
                    fields.append(
                        {
                            "embedded": e.group(1).lstrip("*").split(".")[-1],
                            "type": e.group(1),
                            "omit": tags.get("schema") == "omit",
                        }
                    )
                elif f:
                    tags = dict(TAG.findall(f.group(3) or ""))
                    name = tags.get("json", "").split(",")[0]
                    if name in ("", "-"):
                        deprecated = False
                        continue
                    fields.append(
                        {
                            "go": f.group(1),
                            "json": name,
                            "kind": go_kind(f.group(2)),
                            "type": f.group(2),
                            "omit": tags.get("schema") == "omit",
                            "deprecated": deprecated,
                        }
                    )
                deprecated = False
            self.structs[m.group(1)] = fields

    def struct(self, name: str) -> list[dict[str, Any]]:
        seen = set()
        while name not in self.structs and name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name]
        return self.structs.get(name, [])

    def flat(self, name: str, chain: tuple = ()) -> list[dict[str, Any]]:
        """Every field of a struct, its embedded ones' included, with the
        embedded structs each is reached through, and whether one of them
        is left out of the schema."""
        out = []
        for f in self.struct(name):
            if "embedded" in f:
                for g in self.flat(f["embedded"], chain + (f["embedded"],)):
                    g = dict(g)
                    g["omit"] = g["omit"] or f["omit"]
                    out.append(g)
            else:
                out.append(dict(f, chain=chain, owner=name))
        return out

    def matches(self, props: set[str]):
        """The structs an object of the schema with fields `props` is
        made of."""
        for name in self.structs:
            fields = self.flat(name)
            shown = {f["json"] for f in fields if not f["omit"]}
            if len(shown) >= 2 and shown <= props:
                yield fields

    def omitted(self, props: set[str]) -> list[dict[str, Any]]:
        """The fields left out of the schema of an object with fields
        `props` that sing-box still accepts."""
        out = []
        for fields in self.matches(props):
            for f in fields:
                if not f["omit"] or f["json"] in props or self.is_rejected(f):
                    continue
                out.append(f)
        return out

    def is_rejected(self, f: dict[str, Any]) -> bool:
        names = {f["go"], *f["chain"]}
        return any(
            name in names and (root is None or self.reaches(root, f["owner"]))
            for name, root in self.rejected
        )

    def reaches(self, root: str, owner: str) -> bool:
        """Whether a value of type `root` holds an `owner`, in a field or
        embedded."""
        seen, todo = set(), [root]
        while todo:
            name = todo.pop()
            if name == owner:
                return True
            if name in seen:
                continue
            seen.add(name)
            if name in self.aliases:
                todo.append(self.aliases[name])
            for f in self.structs.get(name, []):
                todo += re.findall(r"\w+", f["type"])
        return False

    def deprecated(self, props: set[str]) -> set[str]:
        return {
            f["json"]
            for fields in self.matches(props)
            for f in fields
            if f["deprecated"] and not f["omit"]
        }

    def rejections(self, checkout: Path) -> list[tuple[str, str | None]]:
        """The Go fields a check fails the configuration on for being
        deprecated or removed: each name an `if` tests whose body only
        returns such an error, with the option type the test starts from
        when the function it is in says."""
        out: list[tuple[str, str | None]] = []
        for path in sorted(checkout.rglob("*.go")):
            if path.name.endswith("_test.go"):
                continue
            lines = path.read_text(errors="replace").splitlines()
            params: dict[str, str] = {}
            for i, line in enumerate(lines):
                if line.startswith("func "):
                    head = line.split("{")[0]
                    params = {
                        var: kind
                        for var, kind in re.findall(r"(\w+)\s+\*?(?:\w+\.)?(\w+)\s*[,)]", head)
                        if kind in self.structs or kind in self.aliases
                    }
                    continue
                m = re.match(r"^(\s*)if\s(.*)$", line)
                if not m:
                    continue
                indent, cond = m.group(1), m.group(2)
                j = i
                while not cond.rstrip().endswith("{") and j + 1 < len(lines):
                    j += 1
                    cond += " " + lines[j].strip()
                body = []
                j += 1
                while j < len(lines) and not lines[j].startswith(indent + "}"):
                    body.append(lines[j].strip())
                    j += 1
                body = [b for b in body if b and not b.startswith("//")]
                if not (
                    len(body) == 1
                    and body[0].startswith("return")
                    and "E.New(" in body[0]
                    and re.search(r"deprecated|removed", body[0], re.I)
                ):
                    continue
                for root, chain in re.findall(r"\b(\w+)((?:\.\w+)+)", cond):
                    for name in chain.split(".")[1:]:
                        out.append((name, params.get(root)))
        return out


def version(checkout: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(checkout), "describe", "--tags", "--exact-match"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit(f"{checkout}: not a sing-box checkout at a release tag")


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__.split("\n\n")[1])
    checkout = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) == 3 else OUT
    schema = Schema(json.loads((checkout / "docs/schema.json").read_text()))
    walker = Walker(schema, GoTypes(checkout))
    walker.value("", schema.root, ())
    fields = [dict(f, path=f["path"].lstrip(".")) for f in walker.fields.values()]
    fields = [f for f in fields if f["path"] != "$schema"]
    doc = {
        "sing_box": version(checkout),
        "generated_by": "tools/singbox-fields/extract.py",
        "fields": fields,
    }
    # A field a line, for diffs.
    lines = ",\n".join("  " + json.dumps(f, ensure_ascii=False) for f in fields)
    head = json.dumps({k: v for k, v in doc.items() if k != "fields"}, ensure_ascii=False)
    out.write_text(head[:-1] + ', "fields": [\n' + lines + "\n]}\n")
    print(f"{out}: {len(fields)} fields of sing-box {doc['sing_box']}")


if __name__ == "__main__":
    main()
