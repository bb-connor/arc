use chio_core::{canonical_json_bytes, sha256_hex};
use chio_security_types::ResponsePlan;
use serde::Serialize;

use crate::admission_operation::{
    AdmissionOperation, AdmissionOperationState, AdmissionRequestBindingInput,
    AdmissionRequestBindingParts,
};

use super::active_response_coordinator::{
    active_response_denied, active_response_internal, digest_hex,
};
use super::{ActiveResponseExecutorAuthorityIdentity, KernelError};

const ACTIVE_RESPONSE_OPERATION_SEED_DOMAIN: &[u8] = b"chio.active-response-operation-seed.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ActiveResponseOperationAnchor {
    pub(super) plan_hash: String,
    pub(super) executor_authority_id: String,
    pub(super) executor_authority_generation: u64,
    pub(super) authorized_at_unix_ms: u64,
    pub(super) authorization_capability_hash: String,
    pub(super) governed_intent_hash: String,
    pub(super) policy_decision_hash: String,
    pub(super) approval_set_hash: String,
}

impl ActiveResponseOperationAnchor {
    pub(super) fn matches_except_authorized_at(&self, other: &Self) -> bool {
        self.plan_hash == other.plan_hash
            && self.executor_authority_id == other.executor_authority_id
            && self.executor_authority_generation == other.executor_authority_generation
            && self.authorization_capability_hash == other.authorization_capability_hash
            && self.governed_intent_hash == other.governed_intent_hash
            && self.policy_decision_hash == other.policy_decision_hash
            && self.approval_set_hash == other.approval_set_hash
    }

    pub(super) fn is_valid(&self) -> bool {
        self.executor_authority_generation != 0
            && self.authorized_at_unix_ms != 0
            && [
                self.plan_hash.as_str(),
                self.executor_authority_id.as_str(),
                self.authorization_capability_hash.as_str(),
                self.governed_intent_hash.as_str(),
                self.policy_decision_hash.as_str(),
                self.approval_set_hash.as_str(),
            ]
            .iter()
            .all(|value| canonical_nonzero_digest(value))
    }
}

fn canonical_nonzero_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
}

pub(super) fn active_response_dispatch_operation_version(
    operation: &AdmissionOperation,
) -> Result<u64, KernelError> {
    match operation.state() {
        AdmissionOperationState::Prepared => operation.version().checked_add(2),
        AdmissionOperationState::ApprovalReserved => operation.version().checked_add(1),
        AdmissionOperationState::DispatchCommitted => Some(operation.version()),
        AdmissionOperationState::Completed => operation.version().checked_sub(1),
        _ => None,
    }
    .filter(|version| *version > 0)
    .ok_or_else(|| {
        active_response_internal(
            "active-response operation cannot derive its stable dispatch version",
        )
    })
}

pub(super) fn build_active_response_operation_anchor(
    response_plan: &ResponsePlan,
    executor_authority: &ActiveResponseExecutorAuthorityIdentity,
    authorized_at_unix_ms: u64,
    authorization_capability_hash: &str,
    governed_intent_hash: &str,
    policy_decision_hash: &str,
    approval_set_hash: &str,
) -> Result<ActiveResponseOperationAnchor, KernelError> {
    if authorized_at_unix_ms < response_plan.created_at_unix_ms
        || authorized_at_unix_ms >= response_plan.expires_at_unix_ms
    {
        return Err(active_response_denied(
            "active-response operation anchor time is outside the plan window",
        ));
    }
    Ok(ActiveResponseOperationAnchor {
        plan_hash: digest_hex(&response_plan.plan_hash),
        executor_authority_id: executor_authority.authority_id().to_string(),
        executor_authority_generation: executor_authority.generation(),
        authorized_at_unix_ms,
        authorization_capability_hash: authorization_capability_hash.to_string(),
        governed_intent_hash: governed_intent_hash.to_string(),
        policy_decision_hash: policy_decision_hash.to_string(),
        approval_set_hash: approval_set_hash.to_string(),
    })
}

pub(super) fn derive_active_response_operation_request_binding_hash(
    plan_hash: &str,
    executor_authority_id: &str,
    executor_authority_generation: u64,
    authorization_capability_hash: &str,
    governed_intent_hash: &str,
    approval_set_hash: &str,
    policy_hash: &str,
) -> Result<String, KernelError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationSeed<'a> {
        plan_hash: &'a str,
        executor_authority_id: &'a str,
        executor_authority_generation: u64,
        authorization_capability_hash: &'a str,
        governed_intent_hash: &'a str,
        approval_set_hash: &'a str,
    }

    let canonical = canonical_json_bytes(&OperationSeed {
        plan_hash,
        executor_authority_id,
        executor_authority_generation,
        authorization_capability_hash,
        governed_intent_hash,
        approval_set_hash,
    })
    .map_err(|error| {
        active_response_denied(format!(
            "active-response operation seed canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ACTIVE_RESPONSE_OPERATION_SEED_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ACTIVE_RESPONSE_OPERATION_SEED_DOMAIN);
    preimage.extend_from_slice(&canonical);
    let action_hash = sha256_hex(&preimage);
    AdmissionRequestBindingInput::new(AdmissionRequestBindingParts {
        action_hash,
        policy_hash: policy_hash.to_string(),
        governed_intent_hash: Some(governed_intent_hash.to_string()),
        threshold_proposal_hash: None,
        verified_approval_set_hash: Some(approval_set_hash.to_string()),
        approval_token_digests: Vec::new(),
        budget_hold_reference: None,
        supplemental_authorization_reference: None,
        supplemental_authorization_digest: None,
        execution_nonce_reference: None,
    })
    .and_then(|binding| binding.derive_hash())
    .map_err(|error| active_response_denied(format!("request binding failed: {error}")))
}
