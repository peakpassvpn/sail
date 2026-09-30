//! Reads sail's configuration types from its source, without building it:
//! every type serde reads (derived or by hand) in the crate's modules, with
//! the `cfg` gates on the way to it; the protocols registered under a type
//! name, the blocks they take and the options each reads; the no-argument
//! functions that give serde defaults; and the sail extensions the sing-box
//! registry test keeps. `scripts/build-config.mjs` renders the reference.

use quote::ToTokens;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use syn::visit::Visit;

#[derive(Default)]
struct Out {
    definitions: Vec<Value>,
    registrations: Vec<Value>,
    functions: Vec<Value>,
}

fn attrs(attrs: &[syn::Attribute]) -> Value {
    let docs: Vec<_> = attrs
        .iter()
        .filter_map(|a| {
            if !a.path().is_ident("doc") {
                return None;
            }
            if let syn::Meta::NameValue(n) = &a.meta {
                if let syn::Expr::Lit(l) = &n.value {
                    if let syn::Lit::Str(s) = &l.lit {
                        return Some(s.value().trim().to_owned());
                    }
                }
            }
            None
        })
        .collect();
    let metadata: Vec<_> = attrs
        .iter()
        .filter(|a| !a.path().is_ident("doc") && !a.path().is_ident("cfg"))
        .map(|a| a.meta.to_token_stream().to_string())
        .collect();
    json!({"docs": docs.join(" "), "metadata": metadata})
}

/// The conditions of an item's `cfg` attributes.
fn cfgs(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .filter_map(|a| match &a.meta {
            syn::Meta::List(l) => Some(l.tokens.to_string()),
            _ => None,
        })
        .collect()
}

fn fields(fields: &syn::Fields) -> Vec<Value> {
    fields
        .iter()
        .map(|f| {
            json!({
                "name": f.ident.as_ref().map(|x| x.to_string()).unwrap_or_default(),
                "type": f.ty.to_token_stream().to_string(),
                "attributes": attrs(&f.attrs),
                "gates": cfgs(&f.attrs),
            })
        })
        .collect()
}

fn derives_deserialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("derive") && a.to_token_stream().to_string().contains("Deserialize")
    })
}

/// The types with a `Deserialize` written by hand.
fn manual_deserialize(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(i) => {
                let (_, path, _) = i.trait_.as_ref()?;
                if path.segments.last()?.ident != "Deserialize" {
                    return None;
                }
                match &*i.self_ty {
                    syn::Type::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

const BLOCKS: [&str; 5] = ["dial", "detour", "tls", "transport", "multiplex"];

/// Which blocks a `with_blocks` argument turns on, by `Blocks`' fields.
fn blocks(expr: Option<&syn::Expr>, consts: &[(String, syn::Expr)]) -> Value {
    let named = |name: &str| -> Option<Value> {
        let set: &[&str] = match name {
            "NONE" => &[],
            "DIAL" => &["dial"],
            "DIALER" => &["dial", "detour"],
            "ALL" => &BLOCKS,
            _ => return None,
        };
        let mut v = json!({});
        for key in BLOCKS {
            v[key] = json!(set.contains(&key));
        }
        Some(v)
    };
    let none = named("NONE").unwrap();
    match expr {
        Some(syn::Expr::Path(p)) => {
            let last = p.path.segments.last().unwrap().ident.to_string();
            match named(&last) {
                Some(v) => v,
                None => match consts.iter().find(|(n, _)| *n == last) {
                    Some((_, e)) => blocks(Some(e), consts),
                    None => panic!("unknown blocks {}", last),
                },
            }
        }
        Some(syn::Expr::Struct(s)) => {
            let mut on = match &s.rest {
                Some(rest) => blocks(Some(rest), consts),
                None => none,
            };
            for f in &s.fields {
                if let (syn::Member::Named(name), syn::Expr::Lit(l)) = (&f.member, &f.expr) {
                    if let syn::Lit::Bool(b) = &l.lit {
                        on[name.to_string()] = json!(b.value);
                    }
                }
            }
            on
        }
        Some(other) => panic!("unknown blocks {}", other.to_token_stream()),
        None => none,
    }
}

/// The protocols a file registers, and the option types it reads.
#[derive(Default)]
struct Registrations {
    consts: Vec<(String, syn::Expr)>,
    found: Vec<(String, String, Value)>,
    options: Vec<String>,
}

fn last_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
        _ => None,
    }
}

fn reads_options(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Try(t) => reads_options(&t.expr),
        syn::Expr::MethodCall(m) => m.method == "options",
        syn::Expr::Call(c) => match &*c.func {
            syn::Expr::Path(p) => p
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "parse_options"),
            _ => false,
        },
        _ => false,
    }
}

/// The argument of a `with_blocks` call in a factory expression.
struct With(Option<syn::Expr>);

impl<'ast> Visit<'ast> for With {
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if m.method == "with_blocks" && m.args.len() == 1 {
            self.0 = Some(m.args[0].clone());
        }
        syn::visit::visit_expr_method_call(self, m);
    }
}

impl<'ast> Visit<'ast> for Registrations {
    // Tests register protocols of their own.
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        if !cfgs(&m.attrs).iter().any(|g| g == "test") {
            syn::visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if !f.attrs.iter().any(|a| a.path().is_ident("test")) {
            syn::visit::visit_item_fn(self, f);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "register" && call.args.len() == 2 {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(name),
                ..
            }) = &call.args[0]
            {
                let factory = call.args[1].to_token_stream().to_string();
                let registry = ["Inbound", "Outbound", "Endpoint"]
                    .into_iter()
                    .find(|k| factory.contains(&format!("{}Factory", k)));
                if let Some(registry) = registry {
                    let mut with = With(None);
                    with.visit_expr(&call.args[1]);
                    let on = blocks(with.0.as_ref(), &self.consts);
                    self.found.push((registry.to_lowercase(), name.value(), on));
                }
            }
        }
        if call.method == "options" {
            if let Some(t) = &call.turbofish {
                for arg in &t.args {
                    if let syn::GenericArgument::Type(ty) = arg {
                        self.options.extend(last_ident(ty));
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if reads_options(&init.expr) {
                let ty = match &local.pat {
                    syn::Pat::Type(t) => last_ident(&t.ty),
                    syn::Pat::Struct(s) => s.path.segments.last().map(|s| s.ident.to_string()),
                    syn::Pat::TupleStruct(s) => s.path.segments.last().map(|s| s.ident.to_string()),
                    _ => None,
                };
                self.options.extend(ty);
            }
        }
        syn::visit::visit_local(self, local);
    }
}

fn walk_file(root: &Path, file: &Path, gates: &[String], out: &mut Out) {
    let source = fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {}", file.display(), e));
    let ast = syn::parse_file(&source).unwrap_or_else(|e| panic!("{}: {}", file.display(), e));
    let stem = file.file_stem().unwrap().to_string_lossy();
    let dir = if ["lib", "main", "mod"].contains(&stem.as_ref()) {
        file.parent().unwrap().to_path_buf()
    } else {
        file.with_extension("")
    };
    let rel = file
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    walk_items(root, &ast.items, &rel, file, &dir, gates, out);

    let mut found = Registrations::default();
    for item in &ast.items {
        if let syn::Item::Const(c) = item {
            found.consts.push((c.ident.to_string(), (*c.expr).clone()));
        }
    }
    found.visit_file(&ast);
    for (registry, name, on) in &found.found {
        out.registrations.push(json!({
            "registry": registry, "name": name, "blocks": on,
            "options": found.options, "source": rel, "gates": gates,
        }));
    }
    if found.found.is_empty() && !found.options.is_empty() {
        out.registrations.push(json!({
            "registry": null, "name": null, "options": found.options,
            "source": rel, "gates": gates,
        }));
    }
}

fn walk_items(
    root: &Path,
    items: &[syn::Item],
    rel: &str,
    file: &Path,
    dir: &Path,
    gates: &[String],
    out: &mut Out,
) {
    let manual = manual_deserialize(items);
    for item in items {
        let (name, item_attrs, shape) = match item {
            syn::Item::Struct(s) => (
                s.ident.to_string(),
                &s.attrs,
                json!({"fields": fields(&s.fields)}),
            ),
            syn::Item::Enum(e) => {
                let variants: Vec<_> = e
                    .variants
                    .iter()
                    .map(|v| {
                        json!({
                            "name": v.ident.to_string(), "attributes": attrs(&v.attrs),
                            "payload": v.fields.to_token_stream().to_string(),
                            "fields": fields(&v.fields),
                        })
                    })
                    .collect();
                (e.ident.to_string(), &e.attrs, json!({"variants": variants}))
            }
            syn::Item::Fn(f) => {
                if f.sig.inputs.is_empty()
                    && f.sig.generics.params.is_empty()
                    && f.block.stmts.len() == 1
                {
                    if let syn::Stmt::Expr(e, None) = &f.block.stmts[0] {
                        out.functions.push(json!({
                            "name": f.sig.ident.to_string(), "source": rel,
                            "body": e.to_token_stream().to_string(),
                        }));
                    }
                }
                continue;
            }
            syn::Item::Mod(m) => {
                let own = cfgs(&m.attrs);
                if own.iter().any(|g| g == "test") {
                    continue;
                }
                let mut inner = gates.to_vec();
                inner.extend(own);
                let name = m.ident.to_string();
                match &m.content {
                    Some((_, items)) => {
                        walk_items(root, items, rel, file, &dir.join(&name), &inner, out)
                    }
                    None => {
                        let at = m.attrs.iter().find_map(|a| match &a.meta {
                            syn::Meta::NameValue(n) if n.path.is_ident("path") => match &n.value {
                                syn::Expr::Lit(syn::ExprLit {
                                    lit: syn::Lit::Str(s),
                                    ..
                                }) => Some(s.value()),
                                _ => None,
                            },
                            _ => None,
                        });
                        let flat = dir.join(format!("{}.rs", name));
                        let child: PathBuf = match at {
                            Some(p) => file.parent().unwrap().join(p),
                            None if flat.exists() => flat,
                            None => dir.join(&name).join("mod.rs"),
                        };
                        if child.exists() {
                            walk_file(root, &child, &inner, out);
                        }
                    }
                }
                continue;
            }
            _ => continue,
        };
        if !derives_deserialize(item_attrs) && !manual.contains(&name) {
            continue;
        }
        let mut own = gates.to_vec();
        own.extend(cfgs(item_attrs));
        out.definitions.push(json!({
            "name": name, "source": rel, "gates": own,
            "attributes": attrs(item_attrs), "shape": shape,
        }));
    }
}

/// The `EXTENSIONS` of the sing-box registry test: path, sample, what.
fn extensions(root: &Path) -> Vec<Value> {
    let file = root.join("sail/src/config/singbox/registry.rs");
    let ast = syn::parse_file(&fs::read_to_string(&file).unwrap()).unwrap();
    let strings = |e: &syn::Expr| -> Vec<String> {
        match e {
            syn::Expr::Tuple(t) => t
                .elems
                .iter()
                .filter_map(|e| match e {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) => Some(s.value()),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        }
    };
    for item in &ast.items {
        if let syn::Item::Const(c) = item {
            if c.ident != "EXTENSIONS" {
                continue;
            }
            let syn::Expr::Reference(r) = &*c.expr else {
                break;
            };
            let syn::Expr::Array(a) = &*r.expr else {
                break;
            };
            return a
                .elems
                .iter()
                .map(|e| {
                    let s = strings(e);
                    assert_eq!(s.len(), 3, "an extension is (path, sample, what)");
                    json!({"path": s[0], "sample": s[1], "what": s[2]})
                })
                .collect();
        }
    }
    panic!("no EXTENSIONS in {}", file.display());
}

fn main() {
    let root = env::args().nth(1).expect("repository root");
    let root = Path::new(&root);
    let mut out = Out::default();
    walk_file(root, &root.join("sail/src/lib.rs"), &[], &mut out);
    assert!(
        !out.definitions.is_empty(),
        "No configuration definitions extracted"
    );
    assert!(
        !out.registrations.is_empty(),
        "No protocol registrations extracted"
    );
    let result = json!({
        "definitions": out.definitions,
        "registrations": out.registrations,
        "functions": out.functions,
        "extensions": extensions(root),
    });
    println!("{}", serde_json::to_string(&result).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("config-extract-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, file: &str, text: &str) {
        let at = root.join(file);
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        fs::write(at, text).unwrap();
    }

    fn scan(root: &Path) -> Out {
        let mut out = Out::default();
        walk_file(root, &root.join("sail/src/lib.rs"), &[], &mut out);
        out
    }

    #[test]
    fn modules_carry_their_gates_to_the_types_in_them() {
        let root = temp("gates");
        write(
            &root,
            "sail/src/lib.rs",
            r#"#[cfg(feature = "a")] pub mod m; mod flat; #[cfg(test)] mod tests;"#,
        );
        write(
            &root,
            "sail/src/m/mod.rs",
            r#"#[cfg(windows)] pub mod n; mod inline { #[derive(Deserialize)] struct Inner { x: u8 } }"#,
        );
        write(
            &root,
            "sail/src/m/n.rs",
            r#"
            /// Docs,
            /// two lines.
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            pub struct Options {
                /// A field.
                #[serde(default)]
                #[cfg(unix)]
                pub a: Option<String>,
            }
            #[derive(Debug)]
            struct NotRead;
            struct ByHand { b: u8 }
            impl<'de> Deserialize<'de> for ByHand { }
            #[derive(Deserialize)]
            #[serde(tag = "type")]
            enum Shape { Ws { #[serde(default)] path: String }, Quic {} }
            "#,
        );
        write(
            &root,
            "sail/src/flat.rs",
            r#"fn default_true() -> bool { true } fn with_arg(x: u8) -> u8 { x } fn two() -> u8 { let a = 1; a }"#,
        );
        write(
            &root,
            "sail/src/tests.rs",
            "#[derive(Deserialize)] struct Test;",
        );
        let out = scan(&root);
        let names: Vec<_> = out
            .definitions
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Options", "ByHand", "Shape", "Inner"]);
        let inner = &out.definitions[3];
        assert_eq!(inner["source"], "sail/src/m/mod.rs");
        assert_eq!(inner["gates"], json!(["feature = \"a\""]));
        let options = &out.definitions[0];
        assert_eq!(options["source"], "sail/src/m/n.rs");
        assert_eq!(options["gates"], json!(["feature = \"a\"", "windows"]));
        assert_eq!(options["attributes"]["docs"], "Docs, two lines.");
        assert_eq!(
            options["attributes"]["metadata"],
            json!([
                "derive (Debug , Deserialize)",
                "serde (deny_unknown_fields)"
            ])
        );
        let a = &options["shape"]["fields"][0];
        assert_eq!(a["name"], "a");
        assert_eq!(a["type"], "Option < String >");
        assert_eq!(a["gates"], json!(["unix"]));
        assert_eq!(a["attributes"]["docs"], "A field.");
        let shape = &out.definitions[2]["shape"]["variants"];
        assert_eq!(shape[0]["name"], "Ws");
        assert_eq!(shape[0]["fields"][0]["name"], "path");
        assert_eq!(shape[1]["fields"], json!([]));
        assert_eq!(
            out.functions,
            vec![json!({"name": "default_true", "source": "sail/src/flat.rs", "body": "true"})]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registrations_name_their_options_and_blocks() {
        let root = temp("registrations");
        write(&root, "sail/src/lib.rs", "pub mod p; pub mod q; pub mod r;");
        write(
            &root,
            "sail/src/p.rs",
            r#"
            const BLOCKS: Blocks = Blocks { tls: true, ..Blocks::DIALER };
            pub fn register(registry: &mut OutboundRegistry) {
                registry.register(
                    "p",
                    OutboundFactory::standalone(build).with_blocks(BLOCKS),
                );
                registry.register("p2", InboundFactory::standalone(build).with_blocks(Blocks { multiplex: true, ..Blocks::NONE }));
                registry.register("e", EndpointFactory::new(deps, build).with_blocks(Blocks::ALL));
                registry.register("plain", OutboundFactory::standalone(build));
                other.register("not-a-protocol", 1);
            }
            fn build(ctx: &mut OutboundContext<'_>) -> Result<()> {
                let options: POptions = ctx.options()?;
                let Empty {} = ctx.options()?;
                let o = ctx.options::<Turbo>()?;
                Ok(())
            }
            #[test]
            fn t() { registry.register("t", InboundFactory::standalone(build)); }
            #[cfg(test)]
            mod tests { fn u() { registry.register("u", InboundFactory::standalone(build)); } }
            "#,
        );
        write(
            &root,
            "sail/src/q.rs",
            r#"fn f() { let o: QOptions = parse_options("dns server", tag, &options)?; }"#,
        );
        write(&root, "sail/src/r.rs", "fn f() { let o = 1; }");
        let out = scan(&root);
        let found: Vec<_> = out
            .registrations
            .iter()
            .map(|r| {
                (
                    r["registry"].clone(),
                    r["name"].clone(),
                    r["options"].clone(),
                )
            })
            .collect();
        let options = json!(["POptions", "Empty", "Turbo"]);
        assert_eq!(
            found,
            vec![
                (json!("outbound"), json!("p"), options.clone()),
                (json!("inbound"), json!("p2"), options.clone()),
                (json!("endpoint"), json!("e"), options.clone()),
                (json!("outbound"), json!("plain"), options.clone()),
                (Value::Null, Value::Null, json!(["QOptions"])),
            ]
        );
        let blocks = |i: usize| out.registrations[i]["blocks"].clone();
        assert_eq!(
            blocks(0),
            json!({"dial": true, "detour": true, "tls": true, "transport": false, "multiplex": false})
        );
        assert_eq!(
            blocks(1),
            json!({"dial": false, "detour": false, "tls": false, "transport": false, "multiplex": true})
        );
        assert_eq!(
            blocks(2),
            json!({"dial": true, "detour": true, "tls": true, "transport": true, "multiplex": true})
        );
        assert_eq!(
            blocks(3),
            json!({"dial": false, "detour": false, "tls": false, "transport": false, "multiplex": false})
        );
        assert_eq!(out.registrations[4]["source"], "sail/src/q.rs");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_registry_test_lists_the_extensions() {
        let root = temp("extensions");
        write(
            &root,
            "sail/src/config/singbox/registry.rs",
            r##"const EXTENSIONS: &[(&str, &str, &str)] = &[("api", "{}", "The control API"), ("log.format", r#""compact""#, "Compact")];"##,
        );
        assert_eq!(
            extensions(&root),
            vec![
                json!({"path": "api", "sample": "{}", "what": "The control API"}),
                json!({"path": "log.format", "sample": "\"compact\"", "what": "Compact"}),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[should_panic(expected = "no EXTENSIONS")]
    fn no_extensions_is_an_error() {
        let root = temp("no-extensions");
        write(
            &root,
            "sail/src/config/singbox/registry.rs",
            "const OTHER: u8 = 1;",
        );
        extensions(&root);
    }
}
