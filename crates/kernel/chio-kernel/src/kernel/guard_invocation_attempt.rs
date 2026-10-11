//! Kernel-owned identity for one guard admission attempt.

use super::admission_coordinator::DurableToolAdmission;
use crate::session::InflightRequest;

#[derive(Clone)]
pub(crate) struct GuardInvocationAttempt {
    identity: String,
}

impl GuardInvocationAttempt {
    pub(super) fn fresh() -> Self {
        Self {
            identity: format!("evaluation:{}", uuid::Uuid::new_v4()),
        }
    }

    /// Called only while an acquired ToolRequestClaim owns or validates the retry.
    pub(super) fn for_session_claim(request: &InflightRequest) -> Self {
        Self {
            identity: format!("session-request:{}", request.guard_invocation_attempt_id()),
        }
    }

    pub(super) fn for_evaluation(
        durable_admission: Option<&DurableToolAdmission>,
        session_claim: Option<Self>,
    ) -> Self {
        if let Some(admission) = durable_admission {
            return Self {
                identity: format!("admission-operation:{}", admission.operation_id()),
            };
        }
        session_claim.unwrap_or_else(Self::fresh)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.identity
    }
}
