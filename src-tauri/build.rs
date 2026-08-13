fn main() {
    println!("cargo:rerun-if-env-changed=ACTIUM_PRODUCT_CHANNEL");
    println!("cargo:rustc-check-cfg=cfg(actium_channel_lab)");
    if std::env::var("ACTIUM_PRODUCT_CHANNEL").as_deref() == Ok("lab") {
        println!("cargo:rustc-cfg=actium_channel_lab");
    }
    tauri_build::build()
}
