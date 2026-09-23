fn main() {
    println!("cargo:rerun-if-env-changed=ACTIUM_PRODUCT_CHANNEL");
    println!("cargo:rustc-check-cfg=cfg(actium_channel_lab)");
    if std::env::var("ACTIUM_PRODUCT_CHANNEL").as_deref() == Ok("lab") {
        println!("cargo:rustc-cfg=actium_channel_lab");
    }
    for icon in [
        "icons/32x32.png",
        "icons/128x128.png",
        "icons/128x128@2x.png",
        "icons/icon.ico",
    ] {
        println!("cargo:rerun-if-changed={icon}");
    }
    tauri_build::build()
}
