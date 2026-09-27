# Sail documentation

The site contains English and Chinese usage guides and generated configuration references. Rust API documentation is intentionally not published.

Run `npm ci`, then `npm run build`. Node.js and stable Rust are required. `npm run docs:config` regenerates the reference alone.

`tools/config-extract` uses `syn` to parse top-level Serde-deserializable configuration definitions in `sail/src/config/model.rs`, `sail/src/protocol`, and `sail/src/transport`. It does not build the proxy core or its native dependencies. `scripts/build-config.mjs` renders eight reference pages (four categories in each language). Edit source comments and the generator, not generated Markdown.

References expose field types, Serde names, omission/default declarations, enum shapes, and source comments. They do not infer runtime defaults, feature availability, or cross-field validation from arbitrary Rust code. Keep usage guides and runnable examples for those semantics. Source comments retain their original language.

Build output is in `dist/`. Deploy that directory under `/sail/`; no separate rustdoc build is needed.
