fn main() {
    // Find and link against libnetfilter_queue + libnfnetlink
    let libs = pkg_config::Config::new()
        .probe("libnetfilter_queue")
        .expect("Could not find libnetfilter_queue via pkg-config");

    // Generate bindings to the C API
    let mut bindgen = bindgen::Builder::default()
        .header("wrapper.h")
        // Whitelist just the NFQ symbols needed (but speeds up binding)
        .allowlist_function("nfq_.*")
        .allowlist_type("nfq_.*")
        .allowlist_var("NFQ_.*")
        .derive_debug(true)
        .derive_default(true);

    // Pass along any include paths pkg-config discovered:
    for include_path in libs.include_paths {
        bindgen = bindgen.clang_arg(format!("-I{}", include_path.display()));
    }

    // Generate the bindings
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindgen
        .generate()
        .expect("Unable to generate libnetfilter_queue bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
