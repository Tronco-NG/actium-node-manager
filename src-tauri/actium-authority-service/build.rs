fn main() {
    // Build identity is embedded through option_env! in the binary. Make Cargo
    // rebuild this crate when the canonical provenance changes between
    // builds/releases; otherwise a cached object could retain an old identity.
    println!("cargo:rerun-if-env-changed=ACTIUM_SOURCE_COMMIT");
    println!("cargo:rerun-if-env-changed=ACTIUM_BUILD_ID");
    println!("cargo:rerun-if-env-changed=ACTIUM_BUILD_KIND");
    println!("cargo:rerun-if-env-changed=ACTIUM_RELEASE_STATUS");
}
