use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// Bindings to the system logs of Apple platforms (asl) and Android
/// (android/log), for the platform the FFI provides.
fn generate_system_log_bindings() {
    println!("cargo:rerun-if-changed=src/wrapper.h");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mut builder = bindgen::Builder::default()
        .header("src/wrapper.h")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    if arch == "aarch64" && os == "ios" {
        // https://github.com/rust-lang/rust-bindgen/issues/1211
        let output = Command::new("xcrun")
            .args(["--sdk", "iphoneos", "--show-sdk-path"])
            .output()
            .expect("failed to execute xcrun");
        let include = Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("usr/include");
        builder = builder
            .clang_arg("--target=arm64-apple-ios")
            .clang_arg(format!("-I{}", include.display()));
    }
    let bindings = builder.generate().expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("system_log_bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "ios" || os == "macos" || os == "android" {
        generate_system_log_bindings();
    }
}
