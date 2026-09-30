# Config corpus

Configurations for sail's front-ends: `sing-box/` (JSON), `clash/`
(Clash / Mihomo YAML) and `surge/` (Surge profiles).

Each file is a synthetic rewrite of the structure of a public configuration:
its sections, keys, rule, group and protocol types, enum values, numbers,
list lengths and order are those of the original; every name, server,
credential, URL, rule payload and other free value is synthetic
(`Proxy 1`, `Group 2`, `set-3`, `s1.example.net`, `192.0.2.1`,
`https://h1.example.com/p1.list`, ...), and comments are gone. No original
file, and no value of one, is included. Files the same after rewriting, or
the same but for list lengths, are kept once.

`tools/corpus-rewrite/rewrite.py` does the rewriting.

`expected.json` holds what reading each file comes to, as `sail -T` reads
it short of building: `{"ok": true, "warnings": N}`, or the first line of
the error. Files a configuration names, such as rule-sets and includes, are
not here, and reading may fail for that; that is recorded too.
`tests/it/test_corpus.rs` compares; `SAIL_CORPUS_UPDATE=1` rewrites
`expected.json` when a change of outcome is meant.
