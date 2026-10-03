use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROTO_GEN");
    if env::var("PROTO_GEN").is_ok() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc");
        // println!("cargo:rerun-if-changed=src/config/geosite.proto");
        protobuf_codegen::Codegen::new()
            .protoc_path(&protoc)
            .out_dir("src/config")
            .includes(["src/config"])
            .inputs(["src/config/geosite.proto"])
            .customize(
                protobuf_codegen::Customize::default()
                    .generate_accessors(false)
                    .gen_mod_rs(false)
                    .lite_runtime(true),
            )
            .run()
            .expect("Protobuf code gen failed");
    }
    println!("cargo:rustc-env=SAIL_BUILD_COMMIT={}", commit());
}

/// The commit sail is built from, for `sail::embed::BUILD`: what the
/// release says, else git's, else the revision Cargo checked sail out at
/// as a git dependency, else "unknown".
fn commit() -> String {
    for var in ["SAIL_COMMIT", "CFG_COMMIT_HASH"] {
        println!("cargo:rerun-if-env-changed={}", var);
        if let Ok(commit) = env::var(var) {
            if !commit.trim().is_empty() {
                return commit.trim().to_string();
            }
        }
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // sail's workspace: the directory above the crate.
    let root = manifest.parent().unwrap_or(&manifest).to_path_buf();
    if let Some(commit) = git_commit(&root) {
        return commit;
    }
    // ~/.cargo/git/checkouts/<name>/<short rev>/sail
    let checkouts = root
        .parent()
        .and_then(Path::parent)
        .is_some_and(|p| p.file_name().is_some_and(|n| n == "checkouts"));
    if checkouts {
        if let Some(rev) = root.file_name().and_then(|n| n.to_str()) {
            if !rev.is_empty() {
                return rev.to_string();
            }
        }
    }
    "unknown".to_string()
}

/// HEAD's short hash, when `root` is the top of a git work tree; a work
/// tree further up (sail vendored into another repository) is not sail's.
/// Builds again when HEAD moves.
fn git_commit(root: &Path) -> Option<String> {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (!text.is_empty()).then_some(text)
    };
    let top = PathBuf::from(git(&["rev-parse", "--show-toplevel"])?);
    if top.canonicalize().ok()? != root.canonicalize().ok()? {
        return None;
    }
    let commit = git(&["rev-parse", "--short", "HEAD"])?;
    // HEAD, the branch it names, and packed refs: those that exist, since
    // a path that does not makes Cargo build again every time.
    let mut watched = vec![git(&["rev-parse", "--git-path", "HEAD"])];
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(git(&["rev-parse", "--git-path", &branch]));
    }
    watched.push(git(&["rev-parse", "--git-path", "packed-refs"]));
    for path in watched.into_iter().flatten() {
        let path = if Path::new(&path).is_absolute() {
            PathBuf::from(path)
        } else {
            root.join(path)
        };
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    Some(commit)
}
