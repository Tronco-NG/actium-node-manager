fn main() {
    // Build identity is embedded through env! in the library. Make Cargo
    // rebuild this crate when the canonical provenance changes between
    // releases; otherwise a cached object could retain an old identity.
    println!("cargo:rerun-if-env-changed=ACTIUM_SOURCE_COMMIT");
    println!("cargo:rerun-if-env-changed=ACTIUM_BUILD_ID");
}
