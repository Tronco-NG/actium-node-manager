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

        let profile_id = parsed.get("profileId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'profileId' in profile".into()))?
            .to_string();

        let profile_version = parsed.get("profileVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'profileVersion' in profile".into()))?
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

    fn valid_manifest(id: &str, ver: &str, desc: &str) -> String {
        serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": id,
            "profileVersion": ver,
            "runtimeKind": "OCI_CONTAINER",
            "description": desc,
            "components": [
                {
                    "componentId": "app",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605"
                }
            ]
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
