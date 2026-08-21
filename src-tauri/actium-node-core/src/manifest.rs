use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PayloadFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PayloadManifestV3 {
    pub schema: u8,
    pub release_version: String,
    pub generated_at: String,
    pub site_runtime_schema: String,
    #[serde(default = "legacy_supported_profiles")]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    pub files: Vec<PayloadFile>,
    pub tree_sha256: String,
    #[serde(default)]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub source_dirty: bool,
}

fn legacy_supported_profiles() -> Vec<String> {
    [
        "site-core",
        "telemetry",
        "radio-control",
        "radio-saf",
        "radio-turn",
        "radio-livekit",
        "observability",
        "connectivity",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl PayloadManifestV3 {
    pub fn require_supported_profiles(&self, requested: &[String]) -> Result<(), String> {
        let supported = self.supported_profiles.iter().collect::<BTreeSet<_>>();
        let unsupported = requested
            .iter()
            .filter(|profile| !supported.contains(profile))
            .cloned()
            .collect::<Vec<_>>();
        if unsupported.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "RUNTIME_RELEASE_PROFILE_UNSUPPORTED: {} no soporta [{}].",
                self.release_version,
                unsupported.join(",")
            ))
        }
    }

    pub fn require_supported_features(&self, required: &[String]) -> Result<(), String> {
        let supported = self.supported_features.iter().collect::<BTreeSet<_>>();
        let unsupported = required
            .iter()
            .filter(|feature| !supported.contains(feature))
            .cloned()
            .collect::<Vec<_>>();
        if unsupported.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "RUNTIME_RELEASE_FEATURE_UNSUPPORTED: {} no soporta [{}].",
                self.release_version,
                unsupported.join(",")
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseCapabilitiesContract {
    schema: u8,
    releases: BTreeMap<String, ReleaseCapabilitiesEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseCapabilitiesEntry {
    supported_profiles: Vec<String>,
    #[serde(default)]
    supported_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPayloadManifest {
    schema: u8,
    version: String,
    content_sha256: String,
    site_runtime_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedPayload {
    Schema3(PayloadManifestV3),
    LegacyUnverified {
        version: String,
        declared_digest: String,
        site_runtime_schema: String,
    },
}

impl VerifiedPayload {
    pub fn version(&self) -> &str {
        match self {
            Self::Schema3(manifest) => &manifest.release_version,
            Self::LegacyUnverified { version, .. } => version,
        }
    }

    pub fn digest(&self) -> &str {
        match self {
            Self::Schema3(manifest) => &manifest.tree_sha256,
            Self::LegacyUnverified {
                declared_digest, ..
            } => declared_digest,
        }
    }

    pub fn schema(&self) -> u8 {
        match self {
            Self::Schema3(_) => 3,
            Self::LegacyUnverified { .. } => 2,
        }
    }
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_file(path: &Path) -> Result<(u64, String), String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("No se pudo abrir {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        size += read as u64;
        digest.update(&buffer[..read]);
    }
    Ok((size, hex_digest(digest.finalize())))
}

fn validate_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.contains('\\') || value.starts_with('/') {
        return Err(format!("Ruta de payload no canonicalizada: {value:?}."));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(format!("Ruta de payload insegura: {value:?}."));
    }
    Ok(path.to_path_buf())
}

fn collect_files(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<String, PathBuf>,
    ) -> Result<(), String> {
        let mut entries = fs::read_dir(directory)
            .map_err(|error| format!("No se pudo leer {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Entrada de payload invalida: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("No se pudo inspeccionar {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "El payload contiene un symlink o reparse point: {}.",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                visit(root, &path, files)?;
                continue;
            }
            if !metadata.is_file() {
                return Err(format!(
                    "El payload contiene una entrada no regular: {}.",
                    path.display()
                ));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "No se pudo canonicalizar una entrada del payload.".to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "PAYLOAD.json" {
                continue;
            }
            validate_relative_path(&relative)?;
            if files.insert(relative.clone(), path).is_some() {
                return Err(format!(
                    "El payload contiene una ruta duplicada: {relative}."
                ));
            }
        }
        Ok(())
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

pub fn tree_sha256(files: &[PayloadFile]) -> String {
    let mut ordered = files.to_vec();
    ordered.sort_by(|left, right| left.path.cmp(&right.path));
    let mut digest = Sha256::new();
    for file in ordered {
        digest.update(file.path.as_bytes());
        digest.update([0]);
        digest.update(file.size.to_string().as_bytes());
        digest.update([0]);
        digest.update(file.sha256.as_bytes());
        digest.update([0]);
    }
    hex_digest(digest.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn verify_schema3(root: &Path, mut manifest: PayloadManifestV3) -> Result<VerifiedPayload, String> {
    if manifest.schema != 3 {
        return Err(format!(
            "Schema de payload inesperado: {}.",
            manifest.schema
        ));
    }
    if manifest.release_version.trim().is_empty() || manifest.site_runtime_schema.trim().is_empty() {
        return Err("El manifiesto schema 3 no contiene identidad completa.".to_string());
    }
    let supported = manifest
        .supported_profiles
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if supported.len() != manifest.supported_profiles.len()
        || supported.is_empty()
        || supported.iter().any(|profile| !crate::KNOWN_PROFILES.contains(profile))
    {
        return Err("supportedProfiles contiene perfiles desconocidos o duplicados.".to_string());
    }
    let features = manifest
        .supported_features
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if features.len() != manifest.supported_features.len()
        || features
            .iter()
            .any(|feature| feature.trim().is_empty() || feature.len() > 80)
    {
        return Err("supportedFeatures contiene features invalidas o duplicadas.".to_string());
    }
    if !valid_sha256(&manifest.tree_sha256) {
        return Err("treeSha256 no es una huella SHA-256 valida.".to_string());
    }
    let version = fs::read_to_string(root.join("VERSION"))
        .map_err(|error| format!("El payload no contiene VERSION: {error}"))?;
    if version.trim() != manifest.release_version {
        return Err(format!(
            "VERSION ({}) no coincide con releaseVersion ({}).",
            version.trim(),
            manifest.release_version
        ));
    }
    manifest
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    let mut declared = BTreeSet::new();
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if !declared.insert(file.path.clone()) {
            return Err(format!("El manifiesto declara dos veces {}.", file.path));
        }
        if !valid_sha256(&file.sha256) {
            return Err(format!("{} no declara un SHA-256 valido.", file.path));
        }
    }
    let actual = collect_files(root)?;
    let actual_paths = actual.keys().cloned().collect::<BTreeSet<_>>();
    if actual_paths != declared {
        let missing = declared
            .difference(&actual_paths)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_paths
            .difference(&declared)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "El arbol del payload no coincide con el manifiesto. Ausentes={missing:?}; extras={extra:?}."
        ));
    }
    for file in &manifest.files {
        let actual_path = actual
            .get(&file.path)
            .ok_or_else(|| format!("Falta {}.", file.path))?;
        let (size, sha256) = sha256_file(actual_path)?;
        if size != file.size || sha256 != file.sha256.to_ascii_lowercase() {
            return Err(format!("Integridad rechazada para {}.", file.path));
        }
    }
    let actual_tree = tree_sha256(&manifest.files);
    if actual_tree != manifest.tree_sha256.to_ascii_lowercase() {
        return Err(format!(
            "treeSha256 no coincide: declarado={}, calculado={actual_tree}.",
            manifest.tree_sha256
        ));
    }
    let legacy_profiles = legacy_supported_profiles().into_iter().collect::<BTreeSet<_>>();
    let requires_capability_contract = manifest
        .supported_profiles
        .iter()
        .any(|profile| !legacy_profiles.contains(profile))
        || !manifest.supported_features.is_empty();
    if requires_capability_contract && !actual.contains_key("release-capabilities.json") {
        return Err(
            "RELEASE_CAPABILITIES_MISMATCH: capacidades nuevas sin release-capabilities.json hasheado."
                .to_string(),
        );
    }
    if let Some(capabilities_path) = actual.get("release-capabilities.json") {
        let capabilities = fs::read_to_string(capabilities_path)
            .map_err(|error| format!("No se pudo leer release-capabilities.json: {error}"))?;
        let capabilities = serde_json::from_str::<ReleaseCapabilitiesContract>(&capabilities)
            .map_err(|error| format!("release-capabilities.json invalido: {error}"))?;
        if capabilities.schema != 1 {
            return Err("release-capabilities.json usa un schema no soportado.".to_string());
        }
        let release = capabilities
            .releases
            .get(&manifest.release_version)
            .ok_or_else(|| {
                format!(
                    "RELEASE_CAPABILITIES_MISMATCH: falta {}.",
                    manifest.release_version
                )
            })?;
        if release.supported_profiles != manifest.supported_profiles
            || release.supported_features != manifest.supported_features
        {
            return Err(format!(
                "RELEASE_CAPABILITIES_MISMATCH: PAYLOAD.json no coincide con release-capabilities.json para {}.",
                manifest.release_version
            ));
        }
    }
    Ok(VerifiedPayload::Schema3(manifest))
}

pub fn verify_payload(root: &Path) -> Result<VerifiedPayload, String> {
    let manifest_path = root.join("PAYLOAD.json");
    let contents = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("No se pudo leer {}: {error}", manifest_path.display()))?;
    let raw: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|error| format!("PAYLOAD.json no es JSON valido: {error}"))?;
    match raw.get("schema").and_then(serde_json::Value::as_u64) {
        Some(3) => {
            let manifest = serde_json::from_value::<PayloadManifestV3>(raw)
                .map_err(|error| format!("Manifiesto schema 3 invalido: {error}"))?;
            verify_schema3(root, manifest)
        }
        Some(2) => {
            let manifest = serde_json::from_value::<LegacyPayloadManifest>(raw)
                .map_err(|error| format!("Manifiesto schema 2 invalido: {error}"))?;
            if manifest.schema != 2 || !valid_sha256(&manifest.content_sha256) {
                return Err("Manifiesto legacy invalido.".to_string());
            }
            Ok(VerifiedPayload::LegacyUnverified {
                version: manifest.version,
                declared_digest: manifest.content_sha256.to_ascii_lowercase(),
                site_runtime_schema: manifest.site_runtime_schema,
            })
        }
        schema => Err(format!("Schema de payload no soportado: {schema:?}.")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        legacy_supported_profiles, sha256_file, tree_sha256, verify_payload, PayloadFile,
        PayloadManifestV3, VerifiedPayload,
    };
    use std::fs;
    use uuid::Uuid;

    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("actium-manifest-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("fixture");
        fs::write(root.join("VERSION"), "0.7.0-lab.1\n").expect("version");
        fs::write(root.join("compose.yml"), "services: {}\n").expect("compose");
        let files = ["VERSION", "compose.yml"]
            .into_iter()
            .map(|name| {
                let (size, sha256) = sha256_file(&root.join(name)).expect("hash");
                PayloadFile {
                    path: name.to_string(),
                    size,
                    sha256,
                }
            })
            .collect::<Vec<_>>();
        let manifest = PayloadManifestV3 {
            schema: 3,
            release_version: "0.7.0-lab.1".to_string(),
            generated_at: "2026-08-13T00:00:00Z".to_string(),
            site_runtime_schema: "1.1".to_string(),
            supported_profiles: legacy_supported_profiles(),
            supported_features: Vec::new(),
            tree_sha256: tree_sha256(&files),
            files,
            source_commit: None,
            source_dirty: false,
        };
        fs::write(
            root.join("PAYLOAD.json"),
            serde_json::to_string_pretty(&manifest).expect("json"),
        )
        .expect("manifest");
        root
    }

    #[test]
    fn verifica_cada_byte_y_el_arbol() {
        let root = fixture();
        assert!(matches!(
            verify_payload(&root),
            Ok(VerifiedPayload::Schema3(_))
        ));
        fs::write(root.join("compose.yml"), "services: {x: 1}\n").expect("alterar");
        assert!(verify_payload(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rechaza_archivos_extra_y_traversal() {
        let root = fixture();
        fs::write(root.join("extra.txt"), "extra").expect("extra");
        assert!(verify_payload(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tree_sha256_comparte_vector_con_el_builder_node() {
        let files = vec![
            PayloadFile {
                path: "bootstrap.sh".to_string(),
                size: 2,
                sha256: "0".repeat(64),
            },
            PayloadFile {
                path: "README.md".to_string(),
                size: 1,
                sha256: "f".repeat(64),
            },
        ];
        assert_eq!(
            tree_sha256(&files),
            "b48dd7f386365885ec26f39d359ad647b96849c348814235c0119314b0a777a2"
        );
    }

    #[test]
    fn capacidades_nuevas_exigen_contrato_de_release_dentro_del_tree() {
        for mutate in ["profile", "feature"] {
            let root = fixture();
            let path = root.join("PAYLOAD.json");
            let mut manifest = serde_json::from_str::<PayloadManifestV3>(
                &fs::read_to_string(&path).expect("manifest"),
            )
            .expect("schema 3");
            if mutate == "profile" {
                manifest.supported_profiles.push("people".to_string());
            } else {
                manifest
                    .supported_features
                    .push("site_core_candidate_v1".to_string());
            }
            fs::write(&path, serde_json::to_vec_pretty(&manifest).expect("json"))
                .expect("write");
            let error = verify_payload(&root).expect_err("capability contract obligatorio");
            assert!(error.contains("RELEASE_CAPABILITIES_MISMATCH"), "{error}");
            let _ = fs::remove_dir_all(root);
        }
    }
}
