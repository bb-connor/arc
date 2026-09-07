//! Deterministic internal budget identity, not a second admission or tenant.

use super::*;

/// Reserved budget-operation prefix. Only the owning preflight participant may
/// create these holds; they can be reversed but never captured for execution.
pub const NONCE_PREFLIGHT_BUDGET_PREFIX: &str = "nonce-preflight-budget:";

/// Identity data only. Construction does not authorize a hold or qualify cleanup.
/// The parent remains the sole admission operation in its authenticated namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionNoncePreflightIdentityV1 {
    parent_operation_id: AdmissionOperationId,
    budget_operation_id: AdmissionIdentifier,
    hold_id: AdmissionIdentifier,
    authorization_event_id: AdmissionIdentifier,
    grant_index: u32,
}

impl AdmissionNoncePreflightIdentityV1 {
    pub fn for_operation(
        operation: &AdmissionOperationV1,
        grant_index: u32,
    ) -> Result<Self, AdmissionOperationError> {
        if operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || !operation
                .binding()
                .participant_requirements()
                .execution_nonce
        {
            return Err(AdmissionOperationError::WrongOperation);
        }
        let parent_operation_id = operation.binding().operation_id().clone();
        let bytes = canonical_json_bytes(&serde_json::json!({
            "schema": "chio.admission-nonce-preflight-budget-identity.v1",
            "parent_operation_id": parent_operation_id.as_str(),
        }))
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        let digest = sha256_hex(&bytes);
        Ok(Self {
            parent_operation_id,
            budget_operation_id: AdmissionIdentifier::try_new(
                "preflight_budget_operation_id",
                format!("{NONCE_PREFLIGHT_BUDGET_PREFIX}{digest}"),
            )?,
            hold_id: AdmissionIdentifier::try_new(
                "preflight_hold_id",
                format!("nonce-preflight-hold:{digest}:{grant_index}"),
            )?,
            authorization_event_id: AdmissionIdentifier::try_new(
                "preflight_authorization_event_id",
                format!("nonce-preflight-authorize:{digest}:{grant_index}"),
            )?,
            grant_index,
        })
    }

    pub fn parent_operation_id(&self) -> &AdmissionOperationId {
        &self.parent_operation_id
    }

    pub fn budget_operation_id(&self) -> &AdmissionIdentifier {
        &self.budget_operation_id
    }

    pub fn hold_id(&self) -> &AdmissionIdentifier {
        &self.hold_id
    }

    pub fn authorization_event_id(&self) -> &AdmissionIdentifier {
        &self.authorization_event_id
    }

    pub fn grant_index(&self) -> u32 {
        self.grant_index
    }
}

/// Durable physical disposition of the internal preflight hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionNoncePreflightHoldDisposition {
    /// The hold still reserves budget and must be reversed before issuance.
    Reserved,
    /// The hold was reversed through the durable budget authority.
    Reversed,
}

/// Fenced recovery data for one owned preflight participant. It names the
/// exact hold and its authorization commit so a lost acknowledgement can replay
/// the deterministic cleanup; it is neither fresh authorization nor proof that
/// cleanup completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionNoncePreflightRecoveryV1 {
    identity: AdmissionNoncePreflightIdentityV1,
    authorization_commit_index: u64,
    hold: AdmissionNoncePreflightHoldDisposition,
}

impl AdmissionNoncePreflightRecoveryV1 {
    pub fn new(
        identity: AdmissionNoncePreflightIdentityV1,
        authorization_commit_index: u64,
        hold: AdmissionNoncePreflightHoldDisposition,
    ) -> Result<Self, AdmissionOperationError> {
        validate_positive_ijson(
            "preflight_authorization_commit_index",
            authorization_commit_index,
        )?;
        Ok(Self {
            identity,
            authorization_commit_index,
            hold,
        })
    }

    pub fn identity(&self) -> &AdmissionNoncePreflightIdentityV1 {
        &self.identity
    }

    /// Budget commit index of the preflight authorization event. Cleanup derives
    /// its deterministic rollback event from this index.
    pub fn authorization_commit_index(&self) -> u64 {
        self.authorization_commit_index
    }

    pub fn hold(&self) -> AdmissionNoncePreflightHoldDisposition {
        self.hold
    }
}
