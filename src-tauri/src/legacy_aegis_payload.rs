//! Explicit compatibility boundary for the legacy Aegis payload.
//!
//! The base runtime never calls this module during startup. Capability
//! installation and legacy release operations opt into it explicitly and fail
//! closed when the external bundle is absent.

use std::path::PathBuf;
use tauri::{path::BaseDirectory, AppHandle, Manager};

pub const ADAPTER_NAME: &str = "LegacyAegisPayloadAdapter";
pub const REMOVAL_CONDITION: &str = "Product Extension Bundle v1";

pub fn optional_bundle(app: &AppHandle) -> Option<PathBuf> {
    app.path()
        .resolve("node", BaseDirectory::Resource)
        .ok()
        .filter(|path| path.join("PAYLOAD.json").is_file())
}

pub fn required_bundle(app: &AppHandle) -> Result<PathBuf, String> {
    optional_bundle(app).ok_or_else(|| {
        format!(
            "PRODUCT_EXTENSION_BUNDLE_REQUIRED: {ADAPTER_NAME} necesita un bundle externo firmado; el Base Runtime no incluye PAYLOAD.json. Retiro: {REMOVAL_CONDITION}."
        )
    })
}
