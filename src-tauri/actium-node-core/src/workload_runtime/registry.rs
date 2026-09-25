use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::{canonical_digest_for_value, constant_time_digest_eq};
use super::WorkloadError;
use crate::workload::profile_json_has_inline_secret_values;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadProfileRecord {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub schema_version: String,
    pub manifest_json: String,
    pub created_at: u64, // Unix epoch milliseconds UTC
}

/// Validates a workload profile manifest against the canonical actium-workload-profile@1.0.0 contract.
pub fn validate_profile_manifest_schema(parsed: &Value) -> Result<(), WorkloadError> {
    let schema = parsed.get("schema")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'schema' field in profile".into()))?;

    if schema != crate::workload::WORKLOAD_PROFILE_SCHEMA {
        return Err(WorkloadError::ValidationFailed(format!(
            "Invalid profile schema '{}', expected '{}'",
            schema,
            crate::workload::WORKLOAD_PROFILE_SCHEMA
        )));
    }

    let _profile_id = parsed.get("profileId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing or empty 'profileId'".into()))?;

    let _profile_version = parsed.get("profileVersion")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing or empty 'profileVersion'".into()))?;

    let runtime_kind = parsed.get("runtimeKind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'runtimeKind'".into()))?;
    if runtime_kind != "OCI_CONTAINER" && runtime_kind != "OCI_COMPOSE" && runtime_kind != "VM" {
        return Err(WorkloadError::ValidationFailed(format!("Invalid runtimeKind '{}'", runtime_kind)));
    }

    let arch = parsed.get("architecture")
        .and_then(|v| v.as_array())
        .filter(|arr| !arr.is_empty())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing or empty 'architecture' array".into()))?;
    for a in arch {
        let s = a.as_str().unwrap_or("");
        if s != "amd64" && s != "arm64" {
            return Err(WorkloadError::ValidationFailed(format!("Unsupported architecture '{}'", s)));
        }
    }

    let components = parsed.get("components")
        .and_then(|v| v.as_array())
        .filter(|arr| !arr.is_empty())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing or empty 'components' array".into()))?;

    for comp in components {
        let cid = comp.get("componentId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| WorkloadError::ValidationFailed("Component missing 'componentId'".into()))?;

        let _img = comp.get("image")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| WorkloadError::ValidationFailed(format!("Component '{}' missing 'image'", cid)))?;

        let _digest = comp.get("imageDigest")
            .and_then(|v| v.as_str())
            .or_else(|| {
                comp.get("image")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.split_once("@sha256:").map(|(_, _h)| s))
            })
            .ok_or_else(|| WorkloadError::ValidationFailed(format!("Component '{}' missing 'imageDigest'", cid)))?;

        let net = comp.get("network")
            .and_then(|v| v.as_str())
            .or_else(|| comp.get("networkMode").and_then(|v| v.as_str()))
            .unwrap_or("PRODUCT_INTERNAL");
        if net != "ISOLATED" && net != "SITE_INTERNAL" && net != "PRODUCT_INTERNAL" && net != "PUBLIC_HTTPS" && net != "INTERNAL" {
            return Err(WorkloadError::ValidationFailed(format!(
                "Component '{}' has invalid network policy '{}'", cid, net
            )));
        }

        let restart = comp.get("restartPolicy")
            .and_then(|v| v.as_str())
            .unwrap_or("unless-stopped");
        if restart != "no" && restart != "always" && restart != "on-failure" && restart != "unless-stopped" {
            return Err(WorkloadError::ValidationFailed(format!(
                "Component '{}' has invalid restartPolicy '{}'", cid, restart
            )));
        }

        if let Some(hc) = comp.get("healthCheck").and_then(|v| v.as_object()) {
            let p_type = hc.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if p_type != "http" && p_type != "tcp" && p_type != "exec" && p_type != "none" {
                return Err(WorkloadError::ValidationFailed(format!(
                    "Component '{}' healthCheck has invalid type '{}'", cid, p_type
                )));
            }
            if p_type == "exec" {
                let cmd = hc.get("command").and_then(|v| v.as_array());
                if cmd.map(|a| a.is_empty()).unwrap_or(true) {
                    return Err(WorkloadError::ValidationFailed(format!(
                        "Component '{}' exec healthCheck requires non-empty 'command' array", cid
                    )));
                }
            }
        }
    }

    if parsed.get("secretRequirements").and_then(|v| v.as_array()).is_none() {
        return Err(WorkloadError::ValidationFailed("Missing 'secretRequirements' array".into()));
    }
    if parsed.get("healthChecks").and_then(|v| v.as_array()).is_none() {
        return Err(WorkloadError::ValidationFailed("Missing 'healthChecks' array".into()));
    }
    if parsed.get("readinessChecks").and_then(|v| v.as_array()).is_none() {
        return Err(WorkloadError::ValidationFailed("Missing 'readinessChecks' array".into()));
    }

    let up = parsed.get("upgradePolicy").and_then(|v| v.as_object())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'upgradePolicy' object".into()))?;
    if up.get("strategy").and_then(|v| v.as_str()).is_none()
        || up.get("requiresSnapshot").and_then(|v| v.as_bool()).is_none()
        || up.get("databaseMigration").and_then(|v| v.as_str()).is_none()
        || up.get("rollbackCompatibility").and_then(|v| v.as_str()).is_none()
    {
        return Err(WorkloadError::ValidationFailed("Invalid 'upgradePolicy' fields".into()));
    }

    let rp = parsed.get("rollbackPolicy").and_then(|v| v.as_object())
        .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'rollbackPolicy' object".into()))?;
    if rp.get("runtimeRollback").and_then(|v| v.as_str()).is_none()
        || rp.get("databaseRollback").and_then(|v| v.as_str()).is_none()
    {
        return Err(WorkloadError::ValidationFailed("Invalid 'rollbackPolicy' fields".into()));
    }

    Ok(())
}

pub struct WorkloadProfileRegistry {
    conn: Mutex<Connection>,
}

impl WorkloadProfileRegistry {
    pub fn new(conn: Connection) -> Result<Self, WorkloadError> {
        let registry = Self {
            conn: Mutex::new(conn),
        };
        registry.init_schema()?;
        Ok(registry)
    }

    pub fn open(path: &std::path::Path) -> Result<Self, WorkloadError> {
        let conn = Connection::open(path)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open SQLite profile registry at {:?}: {}", path, e)))?;
        
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;

        Self::new(conn)
    }

    pub fn in_memory() -> Result<Self, WorkloadError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open in-memory SQLite: {}", e)))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;
        Self::new(conn)
    }

    fn init_schema(&self) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS workload_profiles (
                profile_id TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                profile_digest TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (profile_id, profile_version)
            )",
            [],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to initialize workload_profiles table: {}", e)))?;
        Ok(())
    }

    pub fn register_profile(&self, manifest_json: &str) -> Result<WorkloadProfileRecord, WorkloadError> {
        if profile_json_has_inline_secret_values(manifest_json) {
            return Err(WorkloadError::ValidationFailed("Inline secret values detected in profile manifest".into()));
        }

        let parsed: Value = serde_json::from_str(manifest_json)
            .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid profile JSON: {}", e)))?;

        validate_profile_manifest_schema(&parsed)?;

        let schema = parsed.get("schema")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let profile_id = parsed.get("profileId")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let profile_version = parsed.get("profileVersion")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let computed_digest = canonical_digest_for_value(&parsed)?;

        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT profile_digest, schema_version, manifest_json, created_at
             FROM workload_profiles
             WHERE profile_id = ?1 AND profile_version = ?2"
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let existing = stmt.query_row(
            params![&profile_id, &profile_version],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            }
        );

        match existing {
            Ok((existing_digest, schema_ver, manifest, created_at)) => {
                if constant_time_digest_eq(&existing_digest, &computed_digest)? {
                    Ok(WorkloadProfileRecord {
                        profile_id,
                        profile_version,
                        profile_digest: existing_digest,
                        schema_version: schema_ver,
                        manifest_json: manifest,
                        created_at,
                    })
                } else {
                    Err(WorkloadError::ProfileVersionDigestConflict {
                        profile_id,
                        profile_version,
                        existing_digest,
                        new_digest: computed_digest,
                    })
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                conn.execute(
                    "INSERT INTO workload_profiles (profile_id, profile_version, profile_digest, schema_version, manifest_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        &profile_id,
                        &profile_version,
                        &computed_digest,
                        schema,
                        manifest_json,
                        now,
                    ],
                ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to insert profile record: {}", e)))?;

                Ok(WorkloadProfileRecord {
                    profile_id,
                    profile_version,
                    profile_digest: computed_digest,
                    schema_version: schema.to_string(),
                    manifest_json: manifest_json.to_string(),
                    created_at: now,
                })
            }
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_profile(&self, profile_id: &str, profile_version: &str) -> Result<Option<WorkloadProfileRecord>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT profile_digest, schema_version, manifest_json, created_at
             FROM workload_profiles
             WHERE profile_id = ?1 AND profile_version = ?2"
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(
            params![profile_id, profile_version],
            |row| {
                Ok(WorkloadProfileRecord {
                    profile_id: profile_id.to_string(),
                    profile_version: profile_version.to_string(),
                    profile_digest: row.get(0)?,
                    schema_version: row.get(1)?,
                    manifest_json: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        );

        match res {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest(id: &str, ver: &str, digest_salt: &str) -> String {
        let hex_char = digest_salt.chars().next().unwrap_or('a');
        serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": id,
            "profileVersion": ver,
            "runtimeKind": "OCI_CONTAINER",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "app",
                    "image": "docker.io/library/alpine",
                    "imageDigest": format!("sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b2941042960{}", hex_char),
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "http", "path": "/health", "port": 8080, "timeoutSeconds": 5 }
                }
            ],
            "secretRequirements": [],
            "healthChecks": [],
            "readinessChecks": [],
            "upgradePolicy": {
                "strategy": "replace",
                "requiresSnapshot": true,
                "databaseMigration": "none",
                "rollbackCompatibility": "runtime-only"
            },
            "rollbackPolicy": {
                "runtimeRollback": "previous-profile",
                "databaseRollback": "previous-snapshot"
            }
        }).to_string()
    }

    #[test]
    fn test_profile_registry_sqlite_unique_identity_and_conflict() {
        let registry = WorkloadProfileRegistry::in_memory().unwrap();

        // 1. Initial registration succeeds
        let m1 = valid_manifest("test-service", "1.0.0", "first description");
        let rec1 = registry.register_profile(&m1).unwrap();
        assert_eq!(rec1.profile_id, "test-service");
        assert_eq!(rec1.profile_version, "1.0.0");
        assert!(rec1.profile_digest.starts_with("sha256:"));

        // 2. Lookup works
        let fetched = registry.get_profile("test-service", "1.0.0").unwrap().expect("Should exist");
        assert_eq!(fetched.profile_digest, rec1.profile_digest);

        // 3. Idempotent re-registration of exact same manifest succeeds
        let rec2 = registry.register_profile(&m1).unwrap();
        assert_eq!(rec2.profile_digest, rec1.profile_digest);

        // 4. Digest conflict fails closed: same profileId and version, different description
        let m2 = valid_manifest("test-service", "1.0.0", "tampered description");
        match registry.register_profile(&m2) {
            Err(WorkloadError::ProfileVersionDigestConflict { profile_id, profile_version, existing_digest, new_digest }) => {
                assert_eq!(profile_id, "test-service");
                assert_eq!(profile_version, "1.0.0");
                assert_eq!(existing_digest, rec1.profile_digest);
                assert_ne!(new_digest, existing_digest);
            }
            other => panic!("Expected ProfileVersionDigestConflict, got {:?}", other),
        }

        // 5. Different version for same profile succeeds
        let m3 = valid_manifest("test-service", "1.1.0", "version 1.1");
        let rec3 = registry.register_profile(&m3).unwrap();
        assert_eq!(rec3.profile_version, "1.1.0");
        assert_ne!(rec3.profile_digest, rec1.profile_digest);

        // 6. Inline secret rejection
        let secret_manifest = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "bad-profile",
            "profileVersion": "1.0.0",
            "password": "supersecretpassword"
        }).to_string();
        assert!(matches!(registry.register_profile(&secret_manifest), Err(WorkloadError::ValidationFailed(_))));

        // 7. Schema mismatch rejection
        let bad_schema = serde_json::json!({
            "schema": "actium-workload-profile@0.9.0",
            "profileId": "bad-profile",
            "profileVersion": "1.0.0"
        }).to_string();
        assert!(matches!(registry.register_profile(&bad_schema), Err(WorkloadError::ValidationFailed(_))));
    }
}
