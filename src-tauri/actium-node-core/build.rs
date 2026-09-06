use std::env;

fn main() {
    for key in ["ACTIUM_SOURCE_COMMIT", "ACTIUM_BUILD_ID"] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    println!(
        "cargo:rustc-env=ACTIUM_SOURCE_COMMIT={}",
        env::var("ACTIUM_SOURCE_COMMIT").unwrap_or_else(|_| "unknown".to_string())
    );
    println!(
        "cargo:rustc-env=ACTIUM_BUILD_ID={}",
        env::var("ACTIUM_BUILD_ID").unwrap_or_else(|_| "unknown".to_string())
    );
}
