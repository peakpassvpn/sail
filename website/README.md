# Sail documentation

The site contains English and Chinese usage guides and generated configuration references. Rust API documentation is intentionally not published.

Run `npm ci`, then `npm run build`. Node.js and stable Rust are required.

The configuration reference (`src/content/docs/reference/` and its Chinese twin) is generated and committed. `npm run docs:config` regenerates it; `npm run build` fails, through `npm run docs:check`, when a committed page differs from what the generator makes, so rerun `docs:config` and commit after changing sail's configuration types, their doc comments, the sing-box field registry (`sail/src/config/singbox/fields.json`, `fields.tiers.json`, the registry test's `EXTENSIONS`) or the support tables in `docs/compat/`. `npm run test:config` tests the generator.

- `tools/config-extract` uses `syn` to read sail's source without building it: from `sail/src/lib.rs` down its modules, every type serde reads (derived or by hand) with the `cfg` gates on the way to it, the protocols registered under a type name with the blocks (dial fields, `tls`, `transport`, `multiplex`) and options they read, the no-argument functions that give serde defaults, and the registry test's `EXTENSIONS`.
- `scripts/reference.mjs` joins that with the registry: a page per native-format area (top level and common, DNS, inbounds, outbounds and groups, endpoints, route), objects several fields take on a shared page, and a compatibility page with the sing-box, Clash and Surge support tables' summaries. Every sing-box field gets its measured tier; sail's extensions come from the registry test's list and, for objects sing-box does not have, from the Rust types. `scripts/build-config.mjs` runs it and writes or checks the pages; `--report` lists the fields sail reads without a doc comment, and those it reads where sing-box has the object but the registry does not list them.

Edit source comments and the generator, not generated Markdown. The reference gives serde's view: types, names, omission and default declarations, and source comments; runtime defaults and cross-field rules are in the comments where they are written, and in the guides.

Build output is in `dist/`. Deploy that directory under `/sail/`; no separate rustdoc build is needed.
