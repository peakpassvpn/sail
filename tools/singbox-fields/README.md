# singbox-fields

Lists every field a sing-box configuration can hold, by path, into
`sail/src/config/singbox/fields.json`: the inventory the sing-box field
registry measures sail against (`sail/src/config/singbox/registry.rs`).

It is run by hand, when sail moves to a new sing-box release. Builds and
tests only read the committed `fields.json`; they need neither sing-box's
source nor Go.

## Regenerating

The inventory is of sing-box **v1.14.2**, the tag `fields.json` names in
its `sing_box` field.

```sh
git clone --depth 1 --branch v1.14.2 https://github.com/SagerNet/sing-box /tmp/sing-box
python3 tools/singbox-fields/extract.py /tmp/sing-box
SAIL_REGISTRY_UPDATE=1 cargo test -p sail registry
```

The last step measures how sail treats each field, and rewrites
`sail/src/config/singbox/fields.tiers.json` and the support tables,
`docs/compat/sing-box.md` and `docs/compat/zh/sing-box.md`. It fails on a
field sail neither implements nor lists in
`sail/src/config/singbox/upstream.rs`: give each such field a tier there,
an error (`Unsupported`) if ignoring it would route or secure traffic
otherwise than the configuration says, a warning (`Ignored`) if not, with
the reason in a line.

## What it reads

- `docs/schema.json`, the JSON schema sing-box generates from its option
  types: the fields it documents, their JSON types and values, and which
  type of inbound, outbound, DNS server, rule action... each belongs to.
- `option/*.go`, for what the schema leaves out: deprecated fields
  (`schema:"omit"`). Those sing-box still accepts are listed, marked
  `deprecated`; those it fails the configuration on are not.

Only field names and JSON types are read; no sing-box code is copied.

## Paths

A path names a field as sing-box's JSON nests it: `.` into an object, `[]`
into a list's entries, `[x]` into the entries (or the object) of type `x`,
and `[k=x]` into those whose `k` is `x`:

- `inbounds[vless].users[].flow`
- `dns.servers[https].path`
- `route.rules[].domain`, the condition of a rule
- `route.rules[action=route].outbound`, the option of an action
- `outbounds[vmess].transport[ws].path`

Fields every type of an entry shares (an outbound's dial fields) are listed
for each type. The rules a logical rule combines (`rules[logical].rules`)
take the conditions listed for the rule itself.
