//! Shared storage IPC client used by Tauri and the headless Manager.
use crate::{EnrollmentApplyRequest, StorageGrantApprovalRequest, StoragePreflightRequest, StorageTransportDiscoveryRequest, SupervisorClient, SupervisorCommand, SupervisorReply};
use std::{path::PathBuf, thread, time::{Duration, Instant}};

#[derive(Clone)]
pub struct StorageBackend { client: SupervisorClient }
impl StorageBackend {
    pub fn new(socket: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self { Self { client: SupervisorClient::new(socket, key) } }
    pub fn discover(&self) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageDiscover) }
    pub fn enrollment_status(&self) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::EnrollmentStatus) }
    pub fn apply_enrollment(&self, request: EnrollmentApplyRequest) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::EnrollmentApplySignedPackage(request)) }
    pub fn preflight(&self, request: StoragePreflightRequest) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageGrantPreflight(request)) }
    pub fn apply_approval(&self, request: StorageGrantApprovalRequest) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageGrantApplySignedApproval(request)) }
    pub fn list(&self) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageGrantList) }
    pub fn sign_discovery(&self, request: StorageTransportDiscoveryRequest) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageTransportSignDiscovery(request)) }
    pub fn sign_intent(&self, intent_id: String) -> Result<SupervisorReply, String> { self.client.request(SupervisorCommand::StorageTransportSignIntent { intent_id }) }
    pub fn wait_for_reconnect(&self, timeout: Duration) -> Result<SupervisorReply, String> {
        let deadline = Instant::now() + timeout;
        let mut last_error = String::from("MANAGER_HEALTH_TIMEOUT");
        while Instant::now() < deadline {
            match self.list() {
                Ok(reply @ SupervisorReply::StorageGrantList { .. }) => return Ok(reply),
                Ok(_) => last_error = "MANAGER_UNEXPECTED_REPLY".into(),
                Err(error) => last_error = error,
            }
            thread::sleep(Duration::from_millis(250));
        }
        Err(last_error)
    }
}
