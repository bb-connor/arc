use chio_kernel::stop::{ResumeRequestBody, StopRequestBody, StopStatus};

use super::super::*;
use crate::trust_control::{EMERGENCY_RESUME_PATH, EMERGENCY_STATUS_PATH, EMERGENCY_STOP_PATH};

impl TrustControlClient {
    /// Stop admissions on this trust-control node's kernel scope.
    pub fn emergency_stop(&self, request: &StopRequestBody) -> Result<StopStatus, CliError> {
        self.post_json(EMERGENCY_STOP_PATH, request)
    }

    /// Resume the stopped head the operator named.
    pub fn emergency_resume(&self, request: &ResumeRequestBody) -> Result<StopStatus, CliError> {
        self.post_json(EMERGENCY_RESUME_PATH, request)
    }

    pub fn emergency_status(&self) -> Result<StopStatus, CliError> {
        self.get_json(EMERGENCY_STATUS_PATH)
    }
}
