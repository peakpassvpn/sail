use std::env;

fn main() {
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

        protobuf_codegen::Codegen::new()
            .protoc_path(&protoc)
            .out_dir("src/app/outbound")
            .includes(["src/app/outbound"])
            .inputs(["src/app/outbound/selector_cache.proto"])
            .customize(
                protobuf_codegen::Customize::default()
                    .generate_accessors(false)
                    .gen_mod_rs(false)
                    .lite_runtime(true),
            )
            .run()
            .expect("Protobuf code gen failed");
    }
}
