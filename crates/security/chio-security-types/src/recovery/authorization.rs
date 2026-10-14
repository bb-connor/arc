//! Unsigned requirements precede action, review, coverage and signed authority.
use super::{
    ApprovalIntentRef, AuthorityDomainId, AuthorityScopeDigest, AuthorizationRequirementsDigest,
    BasisDigest, CapabilityBodyDigest, ChallengeId, ContinuationId, ContractDigest, ContractError,
    CoverageDigest, IntentDigest, IsolationLineageId, IssuerId, NonEmptyBoundedList, OfferDigest,
    OutputDispositionDigest, PlanDigest, PolicyDigest, ProcessId, RecoveryAttachmentProfile,
    RecoveryScopeV1, RequestId, RequestNamespaceDigest, ReviewDigest, SafeInteger,
    SemanticRequestDigest, SourceDigest, StepId, VersionV1, WorkflowId,
};
use crate::flow::{Compartment, DeclassificationPurpose, InformationLabel, PrincipalId};
use crate::ports::{DestinationId, RecordId};
use serde::{Deserialize, Serialize};

pub const MAX_RECOVERY_OBLIGATIONS: usize = 64;

macro_rules! schema {
    ($name:ident, $wire:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename=$wire)]
            V1,
        }
    };
}
schema!(
    AuthorizationRequirementsSchema,
    "chio.recovery.authorization-requirements.v1"
);
schema!(ActionIntentSchema, "chio.recovery.action-intent.v1");
schema!(RecoveryGrantBindingSchema, "chio.recovery.grant-binding.v1");
schema!(ApprovalIntentSchema, "chio.recovery.approval-intent.v1");
schema!(
    AuthorityCoverageSchema,
    "chio.recovery.authority-coverage.v1"
);

/// Each power has an independent scope. An owner release cannot endorse integrity.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityObligationV1 {
    OwnerRelease { owner: PrincipalId },
    CompartmentRelease { compartment: Compartment },
    UserAcceptance { principal: PrincipalId },
    IntegrityEndorsement { principal: PrincipalId },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequirementsV1 {
    pub schema: AuthorizationRequirementsSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub source_label: InformationLabel,
    pub admitted_target: InformationLabel,
    pub source_join: SourceDigest,
    pub influence_basis: SourceDigest,
    pub recipient: DestinationId,
    pub purpose: DeclassificationPurpose,
    pub obligations: NonEmptyBoundedList<AuthorityObligationV1, MAX_RECOVERY_OBLIGATIONS>,
    pub issuer_scope: AuthorityScopeDigest,
    pub validity_ceiling_unix_ms: SafeInteger,
    pub attachment_profile: RecoveryAttachmentProfile,
}

/// An exact materialized action. The semantic request digest is computed only
/// from the owning kernel's exhaustive projection, not from tool arguments alone.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionIntentV1 {
    pub schema: ActionIntentSchema,
    pub version: VersionV1,
    /// Legacy history may omit the origin. Fresh materialization and capture
    /// require its independently verified native closure and process binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<super::RecoveryOriginV1>,
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
    pub request_id: RequestId,
    pub request_namespace: RequestNamespaceDigest,
    pub capability_id: RecordId,
    pub capability_body: CapabilityBodyDigest,
    pub semantic_request: SemanticRequestDigest,
    pub authorization_requirements: AuthorizationRequirementsV1,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub authority_scope: AuthorityScopeDigest,
    pub basis: BasisDigest,
    pub source_generation: SafeInteger,
    pub output_disposition: OutputDispositionDigest,
    pub isolation_lineage: IsolationLineageId,
    pub isolation_epoch: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGrantBindingV1 {
    pub schema: RecoveryGrantBindingSchema,
    pub version: VersionV1,
    pub authority_domain: AuthorityDomainId,
    pub workflow_id: WorkflowId,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
    pub process_id: ProcessId,
    pub request_namespace: RequestNamespaceDigest,
    pub request_id: RequestId,
    pub action_intent: IntentDigest,
    pub authorization_requirements: AuthorizationRequirementsDigest,
    pub selected_offer: OfferDigest,
    pub approved_plan: PlanDigest,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub authority_scope: AuthorityScopeDigest,
    pub isolation_lineage: IsolationLineageId,
    #[serde(deserialize_with = "deserialize_positive_epoch")]
    pub isolation_epoch: SafeInteger,
    pub output_disposition: OutputDispositionDigest,
    pub coverage_digest: CoverageDigest,
    pub approval_intent: ApprovalIntentRef,
    pub challenge: ChallengeId,
}

fn deserialize_positive_epoch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SafeInteger, D::Error> {
    let epoch = SafeInteger::deserialize(deserializer)?;
    if epoch == SafeInteger::ZERO {
        return Err(serde::de::Error::custom(ContractError::InvalidState));
    }
    Ok(epoch)
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalIntentV1 {
    pub schema: ApprovalIntentSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub approval_intent: ApprovalIntentRef,
    pub challenge: ChallengeId,
    pub action_intent: IntentDigest,
    pub authorization_requirements: AuthorizationRequirementsDigest,
    pub offer: OfferDigest,
    pub plan: PlanDigest,
    pub preview: ReviewDigest,
    pub recipient: DestinationId,
    pub purpose: DeclassificationPurpose,
    pub obligations: NonEmptyBoundedList<AuthorityObligationV1, MAX_RECOVERY_OBLIGATIONS>,
    pub reviewer: PrincipalId,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCoverageAttestationV1 {
    pub schema: AuthorityCoverageSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub approval_intent: ApprovalIntentRef,
    pub challenge: ChallengeId,
    pub action_intent: IntentDigest,
    pub authorization_requirements: AuthorizationRequirementsDigest,
    pub source_basis: BasisDigest,
    pub issuer_id: IssuerId,
    pub principal: PrincipalId,
    pub obligations: NonEmptyBoundedList<AuthorityObligationV1, MAX_RECOVERY_OBLIGATIONS>,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+};
}
redacted_debug!(
    AuthorityObligationV1,
    AuthorizationRequirementsV1,
    ActionIntentV1,
    RecoveryGrantBindingV1,
    ApprovalIntentV1,
    AuthorityCoverageAttestationV1
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_binding_requires_a_positive_epoch_without_reinterpreting_legacy_actions(
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error>> {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/vectors/recovery/v1/authority-positive.json"
        ))?;
        let mut binding = corpus["grant"]["body"]["recovery"].clone();
        let positive: RecoveryGrantBindingV1 = serde_json::from_value(binding.clone())?;
        assert!(positive.isolation_epoch.get() > 0);
        assert_eq!(serde_json::to_value(positive)?, binding);

        let mut legacy_action = corpus["action"].clone();
        legacy_action["isolation_epoch"] = serde_json::json!(0);
        legacy_action["source_generation"] = serde_json::json!(0);
        let action: ActionIntentV1 = serde_json::from_value(legacy_action.clone())?;
        assert_eq!(action.isolation_epoch, SafeInteger::ZERO);
        assert_eq!(action.source_generation, SafeInteger::ZERO);
        assert_eq!(serde_json::to_value(action)?, legacy_action);

        binding["isolation_epoch"] = serde_json::json!(0);
        assert!(serde_json::from_value::<RecoveryGrantBindingV1>(binding).is_err());
        Ok(())
    }
}
