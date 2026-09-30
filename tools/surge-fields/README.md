# surge-fields

Lists every field of a Surge profile that Surge's manual
(manual.nssurge.com) lists, by path, into
`sail/src/config/surge/fields.json`: the inventory the Surge field registry
measures sail against (`sail/src/config/surge/registry.rs`).

Surge is closed source; its manual is what says which keys, parameters and
sections a profile takes. The extractor is run by hand, when the manual
moves. Builds and tests only read the committed `fields.json`.

## Regenerating

The inventory is of the manual as of the date `fields.json` names in its
`surge` field.

```sh
mkdir -p manual && cd manual
curl -sSL https://manual.nssurge.com/ -o index.html
for p in $(grep -o 'href="[a-z-]*/[a-z0-9-]*\.html"' index.html | sed 's/href="//;s/"//' | sort -u); do
  mkdir -p "$(dirname "$p")" && curl -sSL "https://manual.nssurge.com/$p" -o "$p"
done
cd .. && python3 tools/surge-fields/extract.py manual > sail/src/config/surge/fields.json
SAIL_REGISTRY_UPDATE=1 cargo test -p sail surge::registry
```

The last step measures how sail treats each field, and rewrites
`sail/src/config/surge/fields.tiers.json` and the support tables,
`docs/compat/surge.md` and `docs/compat/zh/surge.md`. It fails on a field
sail lists nowhere: give each such field a tier in the tables of
`sail/src/config/surge` (`Unsupported`, an error, if ignoring it would
route or secure traffic otherwise than the profile says; `Silent` if it
means something only in Surge's interface or on its platforms; `Ignored`,
a warning, otherwise), with the reason in a line.

## What it reads

- The heading the manual gives each key and parameter, and the line under
  it that says what it takes (`Optional, Boolean, default: false`): the
  kind, and for a boolean or a choice of values one other than the
  default, which the registry measures with.
- The tables of proxy types (`policies/overview.html`), group types
  (`policy-groups/overview.html`), rule types and rule parameters
  (`rules/overview.html`), and the section names the pages write as
  `[Section]`.
- `extra.json`, hand-maintained: what the manual says only in prose (which
  types take the TLS parameters, `policy-path`, `vif-mode`...), each entry
  with the page that says it.

Only names and kinds are read; no text of the manual is copied.

## Paths

- `General.<key>`
- `Proxy[<type>]`, the type itself; `Proxy[<type>].<param>`, and
  `Proxy[<type>].server` and `.port`, the values in places of their own.
  The common policy parameters are listed for each type that takes them,
  as are the TLS and Shadow TLS ones.
- `Proxy Group[<type>]`, `Proxy Group[<type>].<param>`
- `Rule[<TYPE>]`, `Rule[<TYPE>].<param>` (`no-resolve`, `pre-matching`...)
- `WireGuard.<key>`, `WireGuard.peer.<field>` for `[WireGuard <name>]`
- `Keystore.<param>`, `SSID Setting.<param>`
- `<Section>` for a section read as a whole: `Host`, `MITM`, `Script`...
