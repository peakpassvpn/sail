use quote::ToTokens;
use serde_json::{json, Value};
use std::{env, fs, path::Path};

fn attrs(attrs: &[syn::Attribute]) -> Value {
    let docs: Vec<_> = attrs.iter().filter_map(|a| {
        if !a.path().is_ident("doc") { return None; }
        if let syn::Meta::NameValue(n) = &a.meta {
            if let syn::Expr::Lit(l) = &n.value {
                if let syn::Lit::Str(s) = &l.lit { return Some(s.value().trim().to_owned()); }
            }
        }
        None
    }).collect();
    let metadata: Vec<_> = attrs.iter().filter(|a| !a.path().is_ident("doc"))
        .map(|a| a.meta.to_token_stream().to_string()).collect();
    json!({"docs": docs.join(" "), "metadata": metadata})
}

fn scan(root: &Path, path: &Path, out: &mut Vec<Value>) {
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for entry in entries { scan(root, &entry, out); }
        return;
    }
    if path.extension().and_then(|x| x.to_str()) != Some("rs") { return; }
    let source = fs::read_to_string(path).unwrap();
    let ast = syn::parse_file(&source).expect("valid Rust configuration source");
    for item in ast.items {
        let (name, attributes, fields) = match item {
            syn::Item::Struct(s) => {
                let fields: Vec<_> = s.fields.iter().map(|f| json!({
                    "name": f.ident.as_ref().map(|x| x.to_string()).unwrap_or_default(),
                    "type": f.ty.to_token_stream().to_string(), "attributes": attrs(&f.attrs)
                })).collect();
                (s.ident.to_string(), s.attrs, json!({"fields": fields}))
            }
            syn::Item::Enum(e) => {
                let variants: Vec<_> = e.variants.iter().map(|v| json!({
                    "name": v.ident.to_string(), "attributes": attrs(&v.attrs),
                    "payload": v.fields.to_token_stream().to_string()
                })).collect();
                (e.ident.to_string(), e.attrs, json!({"variants": variants}))
            }
            _ => continue,
        };
        if !attributes.iter().any(|a| a.path().is_ident("derive") && a.to_token_stream().to_string().contains("Deserialize")) { continue; }
        let file = path.strip_prefix(root).unwrap().to_string_lossy().to_string();
        out.push(json!({"name": name, "source": file, "attributes": attrs(&attributes), "shape": fields}));
    }
}

fn main() {
    let root = env::args().nth(1).expect("repository root");
    let root = Path::new(&root);
    let mut out = Vec::new();
    for dir in ["sail/src/config/model.rs", "sail/src/protocol", "sail/src/transport"] {
        scan(root, &root.join(dir), &mut out);
    }
    assert!(!out.is_empty(), "No configuration definitions extracted");
    println!("{}", serde_json::to_string(&out).unwrap());
}
