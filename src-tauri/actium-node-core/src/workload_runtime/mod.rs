use std::fmt;

pub mod canonical;
pub mod registry;
pub mod planner;
pub mod state;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadError {
    InvalidDigestFormat(String),
    DuplicateIdentifierRejected {
        entity_type: &'static str,
        identifier: String,
    },
    SerializationError(String),
    ValidationFailed(String),
    ProfileVersionDigestConflict {
        profile_id: String,
        profile_version: String,
        existing_digest: String,
        new_digest: String,
    },
    DatabaseError(String),
    MutationBusy {
        deployment_id: String,
        active_operation_id: String,
    },
    ActiveOperationConflict {
        deployment_id: String,
        operation_id: String,
        detail: String,
    },
    StateError(String),
    ExecutionError(String),
    BackendError(String),
    HealthCheckFailed(String),
    RollbackFailed(String),
    Unauthorized(String),
    NonceReplay(String),
    GenerationRegression {
        deployment_id: String,
        target_generation: u64,
        highest_generation: u64,
    },
}

impl fmt::Display for WorkloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigestFormat(msg) => write!(f, "Invalid digest format: {}", msg),
            Self::DuplicateIdentifierRejected { entity_type, identifier } => {
                write!(f, "Duplicate {} identifier rejected: '{}'", entity_type, identifier)
            }
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
            Self::ProfileVersionDigestConflict { profile_id, profile_version, existing_digest, new_digest } => {
                write!(
                    f,
                    "Digest conflict for profile '{}@{}': existing '{}', new '{}'",
                    profile_id, profile_version, existing_digest, new_digest
                )
            }
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::MutationBusy { deployment_id, active_operation_id } => {
                write!(f, "Deployment '{}' is busy with active operation '{}'", deployment_id, active_operation_id)
            }
            Self::ActiveOperationConflict { deployment_id, operation_id, detail } => {
                write!(f, "Active operation conflict on deployment '{}' (op '{}'): {}", deployment_id, operation_id, detail)
            }
            Self::StateError(msg) => write!(f, "State error: {}", msg),
            Self::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            Self::BackendError(msg) => write!(f, "Backend error: {}", msg),
            Self::HealthCheckFailed(msg) => write!(f, "Health check failed: {}", msg),
            Self::RollbackFailed(msg) => write!(f, "Rollback failed: {}", msg),
            Self::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            Self::NonceReplay(nonce) => write!(f, "Nonce replay detected: '{}'", nonce),
            Self::GenerationRegression { deployment_id, target_generation, highest_generation } => {
                write!(
                    f,
                    "Generation regression on deployment '{}': target {} < highest {}",
                    deployment_id, target_generation, highest_generation
                )
            }
        }
    }
}

impl std::error::Error for WorkloadError {}
