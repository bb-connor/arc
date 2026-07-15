//! Closed monetary-release authority and immutable evidence bundles.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use super::*;
use crate::admission_operation::{
    AdmissionAttachment, AdmissionAttachmentKind, AdmissionOperationState,
};
use chio_core_types::provider_attempt::{
    ProviderAttemptCheckpointV1, ProviderAttemptPhaseV1, ProviderCancellationBindingV1,
};

mod persistence;
pub use persistence::*;
mod terminal;
pub use terminal::*;
mod transport;

#[allow(dead_code)]
fn release_id(
    field: &'static str,
    value: impl Into<String>,
) -> Result<AdmissionIdentifier, ToolOutcomeError> {
    AdmissionIdentifier::try_new(field, value)
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
}

#[allow(dead_code)]
fn imported_digest(
    field: &'static str,
    value: impl Into<String>,
) -> Result<AdmissionDigest, ToolOutcomeError> {
    AdmissionDigest::try_new(field, value)
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEvidenceArtifactKindV1 {
    ParticipantQuerySnapshot,
    SignedTransportStatus,
    MonotonicAttemptCheckpoint,
    TerminalToolOutcome,
    TerminalPostReturnEvaluation,
    VerifierPolicy,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImmutableReleaseArtifactV1 {
    pub(super) kind: ReleaseEvidenceArtifactKindV1,
    pub(super) evidence_id: AdmissionIdentifier,
    pub(super) digest: AdmissionDigest,
    pub(super) value: Value,
}

impl ImmutableReleaseArtifactV1 {
    #[allow(dead_code)]
    fn new(
        kind: ReleaseEvidenceArtifactKindV1,
        evidence_id: AdmissionIdentifier,
        value: Value,
    ) -> Result<Self, ToolOutcomeError> {
        let bytes = bounded(
            "release_artifact.value",
            &value,
            MAX_EVIDENCE_ARTIFACT_BYTES,
        )?;
        Ok(Self {
            kind,
            evidence_id,
            digest: digest_bytes("release_artifact.digest", &bytes)?,
            value,
        })
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        let digest = digest_bytes(
            "release_artifact.digest",
            &bounded(
                "release_artifact.value",
                &self.value,
                MAX_EVIDENCE_ARTIFACT_BYTES,
            )?,
        )?;
        if digest != self.digest {
            return Err(ToolOutcomeError::Binding("release_artifact.digest"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierPolicyArtifactV1 {
    policy: Value,
}

fn parse_artifact_value<T>(artifact: &ImmutableReleaseArtifactV1) -> Result<T, ToolOutcomeError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let parsed = serde_json::from_value::<T>(artifact.value.clone())
        .map_err(|_| ToolOutcomeError::Invalid("release_artifact.value"))?;
    let encoded = serde_json::to_value(&parsed)
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    if encoded != artifact.value {
        return Err(ToolOutcomeError::Invalid(
            "release_artifact.noncanonical_value",
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReleaseParticipantV1 {
    Broker,
    Budget,
    Approval,
    Nonce,
    OutcomeEligibility,
    Payment,
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ParticipantNoEffectDispositionV1 {
    NeverAcquired,
    ReleasedBeforeDispatch,
    NotDispatched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantQueryRecordV1 {
    source_record_id: AdmissionIdentifier,
    source_record_digest: AdmissionDigest,
    source_record_version: u64,
    source_store_fence: StoreMutationFence,
    source_commit_index: u64,
    observed_at_unix_ms: u64,
    source_attachments: Vec<AdmissionAttachment>,
}

impl ParticipantQueryRecordV1 {
    #[cfg(test)]
    fn for_test(
        source_record_id: AdmissionIdentifier,
        source_record_digest: AdmissionDigest,
        source_attachments: Vec<AdmissionAttachment>,
        observed_at_unix_ms: u64,
    ) -> Self {
        Self {
            source_record_id,
            source_record_digest,
            source_record_version: 1,
            source_store_fence: StoreMutationFence {
                store_uuid: "store-1".to_owned(),
                lease_id: "store-lease-1".to_owned(),
                owner_epoch: 9,
            },
            source_commit_index: 1,
            observed_at_unix_ms,
            source_attachments,
        }
    }

    fn validate(
        &self,
        verification_store_fence: &StoreMutationFence,
        verified_at_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        positive(
            "participant_query.source_record_version",
            self.source_record_version,
        )?;
        positive(
            "participant_query.source_commit_index",
            self.source_commit_index,
        )?;
        positive("participant_query.observed_at", self.observed_at_unix_ms)?;
        validate_successor_fence(&self.source_store_fence, verification_store_fence)?;
        if self.observed_at_unix_ms > verified_at_unix_ms {
            return Err(ToolOutcomeError::Binding("participant_query.trusted_time"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedParticipantNoEffectEvidenceV1 {
    participant: ReleaseParticipantV1,
    disposition: ParticipantNoEffectDispositionV1,
    operation_id: AdmissionOperationId,
    operation_version: u64,
    observed_state: AdmissionOperationState,
    source_record: ParticipantQueryRecordV1,
    pub(super) evidence_digest: AdmissionDigest,
}

#[derive(Serialize)]
struct ParticipantNoEffectEvidenceBody<'a> {
    participant: ReleaseParticipantV1,
    disposition: ParticipantNoEffectDispositionV1,
    operation_id: &'a AdmissionOperationId,
    operation_version: u64,
    observed_state: AdmissionOperationState,
    source_record: &'a ParticipantQueryRecordV1,
}

impl VerifiedParticipantNoEffectEvidenceV1 {
    fn body(&self) -> ParticipantNoEffectEvidenceBody<'_> {
        ParticipantNoEffectEvidenceBody {
            participant: self.participant,
            disposition: self.disposition,
            operation_id: &self.operation_id,
            operation_version: self.operation_version,
            observed_state: self.observed_state,
            source_record: &self.source_record,
        }
    }

    #[cfg(test)]
    fn from_verified_source(
        operation: &AdmissionOperationV1,
        participant: ReleaseParticipantV1,
        disposition: ParticipantNoEffectDispositionV1,
        source_record: ParticipantQueryRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        let operation_id = operation.binding().operation_id().clone();
        let operation_version = operation.version();
        let observed_state = operation.state();
        let evidence_digest = domain_digest(
            "chio.participant-no-effect-evidence.v1",
            &ParticipantNoEffectEvidenceBody {
                participant,
                disposition,
                operation_id: &operation_id,
                operation_version,
                observed_state,
                source_record: &source_record,
            },
        )?;
        Ok(Self {
            participant,
            disposition,
            operation_id,
            operation_version,
            observed_state,
            source_record,
            evidence_digest,
        })
    }

    fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        participant: ReleaseParticipantV1,
        disposition: ParticipantNoEffectDispositionV1,
        verification_store_fence: &StoreMutationFence,
        verified_at_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        self.source_record
            .validate(verification_store_fence, verified_at_unix_ms)?;
        let expected_attachments = participant_attachments(operation, participant);
        let attachments_match = match disposition {
            ParticipantNoEffectDispositionV1::NeverAcquired
            | ParticipantNoEffectDispositionV1::NotDispatched => {
                self.source_record.source_attachments.is_empty()
            }
            ParticipantNoEffectDispositionV1::ReleasedBeforeDispatch => {
                !expected_attachments.is_empty()
                    && self.source_record.source_attachments == expected_attachments
            }
        };
        if self.participant != participant
            || self.disposition != disposition
            || self.operation_id != *operation.binding().operation_id()
            || self.operation_version != operation.version()
            || self.observed_state != operation.state()
            || !attachments_match
            || self.evidence_digest
                != domain_digest("chio.participant-no-effect-evidence.v1", &self.body())?
        {
            return Err(ToolOutcomeError::Binding(
                "predispatch.participant_evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum VerifiedParticipantNoEffectV1 {
    NotRequired,
    NeverAcquired {
        evidence: VerifiedParticipantNoEffectEvidenceV1,
    },
    ReleasedBeforeDispatch {
        evidence: VerifiedParticipantNoEffectEvidenceV1,
    },
    NotDispatched {
        evidence: VerifiedParticipantNoEffectEvidenceV1,
    },
}

impl VerifiedParticipantNoEffectV1 {
    #[cfg(test)]
    fn never_acquired(
        operation: &AdmissionOperationV1,
        participant: ReleaseParticipantV1,
        source_record: ParticipantQueryRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        Ok(Self::NeverAcquired {
            evidence: VerifiedParticipantNoEffectEvidenceV1::from_verified_source(
                operation,
                participant,
                ParticipantNoEffectDispositionV1::NeverAcquired,
                source_record,
            )?,
        })
    }

    #[cfg(test)]
    fn released_before_dispatch(
        operation: &AdmissionOperationV1,
        participant: ReleaseParticipantV1,
        source_record: ParticipantQueryRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        Ok(Self::ReleasedBeforeDispatch {
            evidence: VerifiedParticipantNoEffectEvidenceV1::from_verified_source(
                operation,
                participant,
                ParticipantNoEffectDispositionV1::ReleasedBeforeDispatch,
                source_record,
            )?,
        })
    }

    #[cfg(test)]
    fn not_dispatched(
        operation: &AdmissionOperationV1,
        source_record: ParticipantQueryRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        Ok(Self::NotDispatched {
            evidence: VerifiedParticipantNoEffectEvidenceV1::from_verified_source(
                operation,
                ReleaseParticipantV1::Transport,
                ParticipantNoEffectDispositionV1::NotDispatched,
                source_record,
            )?,
        })
    }

    fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        participant: ReleaseParticipantV1,
        required: bool,
        verification_store_fence: &StoreMutationFence,
        verified_at_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        let attached = !participant_attachments(operation, participant).is_empty();
        match self {
            Self::NotRequired if !required => Ok(()),
            Self::NeverAcquired { evidence } if required && !attached => evidence.validate_for(
                operation,
                participant,
                ParticipantNoEffectDispositionV1::NeverAcquired,
                verification_store_fence,
                verified_at_unix_ms,
            ),
            Self::ReleasedBeforeDispatch { evidence } if required && attached => evidence
                .validate_for(
                    operation,
                    participant,
                    ParticipantNoEffectDispositionV1::ReleasedBeforeDispatch,
                    verification_store_fence,
                    verified_at_unix_ms,
                ),
            Self::NotDispatched { evidence }
                if participant == ReleaseParticipantV1::Transport
                    && required
                    && operation.dispatch_commit().is_none() =>
            {
                evidence.validate_for(
                    operation,
                    participant,
                    ParticipantNoEffectDispositionV1::NotDispatched,
                    verification_store_fence,
                    verified_at_unix_ms,
                )
            }
            _ => Err(ToolOutcomeError::Binding(
                "predispatch.participant_disposition",
            )),
        }
    }
}

fn participant_attachments(
    operation: &AdmissionOperationV1,
    participant: ReleaseParticipantV1,
) -> Vec<AdmissionAttachment> {
    let kinds: &[AdmissionAttachmentKind] = match participant {
        ReleaseParticipantV1::Broker => &[AdmissionAttachmentKind::BrokerAttempt],
        ReleaseParticipantV1::Budget => &[AdmissionAttachmentKind::BudgetHold],
        ReleaseParticipantV1::Approval => &[
            AdmissionAttachmentKind::ThresholdProposal,
            AdmissionAttachmentKind::ApprovalSet,
        ],
        ReleaseParticipantV1::Nonce => &[AdmissionAttachmentKind::ExecutionNonce],
        ReleaseParticipantV1::OutcomeEligibility => &[AdmissionAttachmentKind::OutcomeEligibility],
        ReleaseParticipantV1::Payment => &[AdmissionAttachmentKind::PaymentParticipant],
        ReleaseParticipantV1::Transport => &[],
    };
    kinds
        .iter()
        .filter_map(|kind| operation.attachment(*kind).cloned())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreDispatchParticipantDispositionsV1 {
    broker: VerifiedParticipantNoEffectV1,
    budget: VerifiedParticipantNoEffectV1,
    approval: VerifiedParticipantNoEffectV1,
    nonce: VerifiedParticipantNoEffectV1,
    outcome_eligibility: VerifiedParticipantNoEffectV1,
    payment: VerifiedParticipantNoEffectV1,
    transport: VerifiedParticipantNoEffectV1,
}

impl PreDispatchParticipantDispositionsV1 {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn from_verified_parts(
        broker: VerifiedParticipantNoEffectV1,
        budget: VerifiedParticipantNoEffectV1,
        approval: VerifiedParticipantNoEffectV1,
        nonce: VerifiedParticipantNoEffectV1,
        outcome_eligibility: VerifiedParticipantNoEffectV1,
        payment: VerifiedParticipantNoEffectV1,
        transport: VerifiedParticipantNoEffectV1,
    ) -> Self {
        Self {
            broker,
            budget,
            approval,
            nonce,
            outcome_eligibility,
            payment,
            transport,
        }
    }

    fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        verification_store_fence: &StoreMutationFence,
        verified_at_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        let required = operation.binding().participant_requirements();
        self.broker.validate_for(
            operation,
            ReleaseParticipantV1::Broker,
            required.broker_attempt,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.budget.validate_for(
            operation,
            ReleaseParticipantV1::Budget,
            required.budget_capture,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.approval.validate_for(
            operation,
            ReleaseParticipantV1::Approval,
            required.approval,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.nonce.validate_for(
            operation,
            ReleaseParticipantV1::Nonce,
            required.execution_nonce,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.outcome_eligibility.validate_for(
            operation,
            ReleaseParticipantV1::OutcomeEligibility,
            required.outcome_eligibility,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.payment.validate_for(
            operation,
            ReleaseParticipantV1::Payment,
            required.payment,
            verification_store_fence,
            verified_at_unix_ms,
        )?;
        self.transport.validate_for(
            operation,
            ReleaseParticipantV1::Transport,
            true,
            verification_store_fence,
            verified_at_unix_ms,
        )
    }
}

fn required_release_participants(operation: &AdmissionOperationV1) -> Vec<ReleaseParticipantV1> {
    let required = operation.binding().participant_requirements();
    [
        (required.broker_attempt, ReleaseParticipantV1::Broker),
        (required.budget_capture, ReleaseParticipantV1::Budget),
        (required.approval, ReleaseParticipantV1::Approval),
        (required.execution_nonce, ReleaseParticipantV1::Nonce),
        (
            required.outcome_eligibility,
            ReleaseParticipantV1::OutcomeEligibility,
        ),
        (required.payment, ReleaseParticipantV1::Payment),
        (true, ReleaseParticipantV1::Transport),
    ]
    .into_iter()
    .filter_map(|(required, participant)| required.then_some(participant))
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreDispatchParticipantManifestV1 {
    request_binding_hash: AdmissionDigest,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    verification_store_fence: StoreMutationFence,
    verified_at_unix_ms: u64,
    required_participants: Vec<ReleaseParticipantV1>,
    participant_dispositions: PreDispatchParticipantDispositionsV1,
}

impl PreDispatchParticipantManifestV1 {
    fn validate_for(&self, operation: &AdmissionOperationV1) -> Result<(), ToolOutcomeError> {
        positive("predispatch.verified_at", self.verified_at_unix_ms)?;
        positive(
            "predispatch.coordinator_lease_epoch",
            self.coordinator_lease_epoch,
        )?;
        validate_store_fence(&self.verification_store_fence)?;
        if self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.required_participants != required_release_participants(operation)
        {
            return Err(ToolOutcomeError::Binding(
                "predispatch.participant_manifest",
            ));
        }
        self.participant_dispositions.validate_for(
            operation,
            &self.verification_store_fence,
            self.verified_at_unix_ms,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct PreDispatchNoEffectSnapshotV1 {
    operation_id: AdmissionOperationId,
    operation_version: u64,
    request_binding_hash: AdmissionDigest,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    verification_store_fence: StoreMutationFence,
    verified_at_unix_ms: u64,
    participant_manifest: PreDispatchParticipantManifestV1,
    complete_participant_query_root: AdmissionDigest,
    verifier_policy_digest: AdmissionDigest,
    artifacts: Vec<ImmutableReleaseArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifiedPreDispatchNoEffect {
    snapshot: Box<PreDispatchNoEffectSnapshotV1>,
}

impl VerifiedPreDispatchNoEffect {
    #[cfg(test)]
    fn from_verified_snapshot(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        participant_dispositions: PreDispatchParticipantDispositionsV1,
        verifier_policy: Value,
    ) -> Result<Self, ToolOutcomeError> {
        validate_pre_dispatch_context(operation, context)?;
        let operation_id = operation.binding().operation_id().clone();
        let participant_manifest = PreDispatchParticipantManifestV1 {
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            verification_store_fence: context.store_fence.clone(),
            verified_at_unix_ms: context.trusted_time_unix_ms,
            required_participants: required_release_participants(operation),
            participant_dispositions,
        };
        participant_manifest.validate_for(operation)?;
        let query = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::ParticipantQuerySnapshot,
            release_id(
                "participant_query_evidence_id",
                format!("{}:participant-query", operation_id.as_str()),
            )?,
            serde_json::to_value(&participant_manifest)
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let policy = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            release_id(
                "verifier_policy_evidence_id",
                format!("{}:verifier-policy", operation_id.as_str()),
            )?,
            serde_json::to_value(VerifierPolicyArtifactV1 {
                policy: verifier_policy,
            })
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let snapshot = PreDispatchNoEffectSnapshotV1 {
            operation_id,
            operation_version: operation.version(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            verification_store_fence: context.store_fence.clone(),
            verified_at_unix_ms: context.trusted_time_unix_ms,
            participant_manifest,
            complete_participant_query_root: query.digest.clone(),
            verifier_policy_digest: policy.digest.clone(),
            artifacts: vec![query, policy],
        };
        let proof = Self {
            snapshot: Box::new(snapshot),
        };
        proof.validate_against(operation, context)?;
        Ok(proof)
    }

    pub(crate) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), ToolOutcomeError> {
        validate_pre_dispatch_context(operation, context)?;
        self.snapshot.participant_manifest.validate_for(operation)?;
        validate_successor_fence(
            &self.snapshot.verification_store_fence,
            &context.store_fence,
        )?;
        if self.snapshot.operation_id != *operation.binding().operation_id()
            || self.snapshot.operation_version != operation.version()
            || self.snapshot.operation_version != context.expected_operation_version
            || self.snapshot.request_binding_hash != *operation.binding().request_binding_hash()
            || self.snapshot.coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.snapshot.verified_at_unix_ms > context.trusted_time_unix_ms
            || (self.snapshot.verification_store_fence == context.store_fence
                && self.snapshot.coordinator_lease_id != context.coordinator_lease_id)
            || self.snapshot.participant_manifest.request_binding_hash
                != self.snapshot.request_binding_hash
            || self.snapshot.participant_manifest.coordinator_lease_id
                != self.snapshot.coordinator_lease_id
            || self.snapshot.participant_manifest.coordinator_lease_epoch
                != self.snapshot.coordinator_lease_epoch
            || self.snapshot.participant_manifest.verification_store_fence
                != self.snapshot.verification_store_fence
            || self.snapshot.participant_manifest.verified_at_unix_ms
                != self.snapshot.verified_at_unix_ms
            || self.snapshot.artifacts.len() != 2
            || self.snapshot.artifacts[0].kind
                != ReleaseEvidenceArtifactKindV1::ParticipantQuerySnapshot
            || self.snapshot.artifacts[1].kind != ReleaseEvidenceArtifactKindV1::VerifierPolicy
            || self.snapshot.complete_participant_query_root != self.snapshot.artifacts[0].digest
            || self.snapshot.verifier_policy_digest != self.snapshot.artifacts[1].digest
        {
            return Err(ToolOutcomeError::Binding("predispatch.projection_context"));
        }
        let artifact_manifest: PreDispatchParticipantManifestV1 =
            parse_artifact_value(&self.snapshot.artifacts[0])?;
        let _: VerifierPolicyArtifactV1 = parse_artifact_value(&self.snapshot.artifacts[1])?;
        if self.snapshot.participant_manifest != artifact_manifest {
            return Err(ToolOutcomeError::Binding(
                "predispatch.participant_artifact",
            ));
        }
        self.snapshot
            .artifacts
            .iter()
            .try_for_each(ImmutableReleaseArtifactV1::validate)
    }
}

mod predispatch_authority_sealed {
    pub trait Sealed {}
}

#[allow(dead_code)]
pub(crate) trait QualifiedPreDispatchNoEffectAuthority:
    predispatch_authority_sealed::Sealed + Send + Sync
{
    fn verify_no_effect(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<VerifiedPreDispatchNoEffect, ToolOutcomeError>;
}

fn validate_pre_dispatch_context(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> Result<(), ToolOutcomeError> {
    context
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    operation
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    if operation.dispatch_commit().is_some()
        || !matches!(
            operation.state(),
            crate::admission_operation::AdmissionOperationState::Prepared
                | crate::admission_operation::AdmissionOperationState::BrokerAttemptRegistered
                | crate::admission_operation::AdmissionOperationState::BudgetAuthorized
                | crate::admission_operation::AdmissionOperationState::ApprovalReserved
                | crate::admission_operation::AdmissionOperationState::ReadyToDispatch
                | crate::admission_operation::AdmissionOperationState::CapturePending
        )
        || context.operation_id != *operation.binding().operation_id()
        || context.request_id != operation.replay_key().request_id
        || context.expected_operation_version != operation.version()
        || context.coordinator_lease_epoch != operation.coordinator_lease_epoch()
    {
        return Err(ToolOutcomeError::Binding("predispatch.operation_context"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedTransportStatusArtifactV1 {
    cancellation: ProviderCancellationBindingV1,
    no_acceptance_proof_base64: String,
    qualification_digest: AdmissionDigest,
    observed_at_unix_ms: u64,
    verifier_identity: AdmissionIdentifier,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedTransportNotAccepted {
    operation_id: AdmissionOperationId,
    operation_version: u64,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    dispatch_operation_version: u64,
    dispatch_fence: u64,
    projection_coordinator_lease_id: AdmissionIdentifier,
    projection_coordinator_lease_epoch: u64,
    projection_store_fence: StoreMutationFence,
    transport_attempt_id: AdmissionIdentifier,
    transport_identity: AdmissionIdentifier,
    transport_key_epoch: u64,
    signed_status_digest: AdmissionDigest,
    qualification_digest: AdmissionDigest,
    cancellation_fence: u64,
    verified_at_unix_ms: u64,
    verifier_identity: AdmissionIdentifier,
    monotonic_checkpoint_digest: AdmissionDigest,
    verifier_policy_digest: AdmissionDigest,
    artifacts: Vec<ImmutableReleaseArtifactV1>,
}

impl VerifiedTransportNotAccepted {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_provider(
        status: &VerifiedProviderNotAccepted,
        qualification: &QualifiedDispatchStatusProvider,
        query: &DispatchStatusQuery,
        operation: &AdmissionOperationV1,
        commit: &AdmissionDispatchCommitBindingV1,
        context: &AdmissionProjectionContext,
        verifier_identity: AdmissionIdentifier,
        verifier_policy: Value,
    ) -> Result<Self, ToolOutcomeError> {
        query
            .validate()
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        status
            .checkpoint()
            .validate()
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        status
            .cancellation()
            .validate()
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        positive("transport_not_accepted.observed_at", query.observed_at)?;
        positive(
            "transport_not_accepted.cancelled_at",
            status.cancellation().cancelled_at,
        )?;
        positive(
            "transport_not_accepted.cancellation_fence",
            status.cancellation().cancellation_fence,
        )?;
        validate_retained_dispatch_commit(operation, commit)?;
        validate_projection_context(operation, context)?;
        let attempt = &status.checkpoint().attempt;
        let invocation_blob = status.checkpoint().phase.invocation_blob();
        let ProviderAttemptPhaseV1::Cancelled {
            cancellation: checkpoint_cancellation,
            ..
        } = &status.checkpoint().phase
        else {
            return Err(ToolOutcomeError::Binding(
                "transport_not_accepted.checkpoint_phase",
            ));
        };
        if query.attempt != *attempt
            || status.cancellation() != checkpoint_cancellation
            || query.observed_at < status.cancellation().cancelled_at
            || query.observed_at > context.trusted_time_unix_ms
            || attempt.operation_id != operation.binding().operation_id().as_str()
            || operation.provider_attempt() != Some(attempt)
            || invocation_blob.request_digest != operation.binding().request_binding_hash().as_str()
            || attempt.transport_id != qualification.transport_id()
            || attempt.transport_key_epoch != qualification.transport_key_epoch()
            || status.qualification_digest() != qualification.qualification_digest()
        {
            return Err(ToolOutcomeError::Binding("transport_not_accepted.provider"));
        }
        let operation_id = operation.binding().operation_id().clone();
        let cancellation_digest = imported_digest(
            "transport_not_accepted.signed_status_digest",
            status
                .cancellation()
                .digest()
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let qualification_digest = imported_digest(
            "transport_not_accepted.qualification_digest",
            status.qualification_digest().to_owned(),
        )?;
        let signed_status = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::SignedTransportStatus,
            release_id(
                "signed_transport_status_evidence_id",
                status.cancellation().cancellation_ref.clone(),
            )?,
            serde_json::to_value(SignedTransportStatusArtifactV1 {
                cancellation: status.cancellation().clone(),
                no_acceptance_proof_base64: BASE64.encode(status.proof()),
                qualification_digest: qualification_digest.clone(),
                observed_at_unix_ms: query.observed_at,
                verifier_identity: verifier_identity.clone(),
            })
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let checkpoint = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::MonotonicAttemptCheckpoint,
            release_id(
                "checkpoint_evidence_id",
                format!("{}:checkpoint", attempt.attempt_id),
            )?,
            serde_json::to_value(status.checkpoint())
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let policy = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            release_id(
                "verifier_policy_evidence_id",
                format!("{}:verifier-policy", operation_id.as_str()),
            )?,
            serde_json::to_value(VerifierPolicyArtifactV1 {
                policy: verifier_policy,
            })
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let proof = Self {
            operation_id,
            operation_version: operation.version(),
            request_id: operation.replay_key().request_id,
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            dispatch_operation_version: commit.committed_version,
            dispatch_fence: commit.store_fence.owner_epoch,
            projection_coordinator_lease_id: context.coordinator_lease_id.clone(),
            projection_coordinator_lease_epoch: context.coordinator_lease_epoch,
            projection_store_fence: context.store_fence.clone(),
            transport_attempt_id: release_id("transport_attempt_id", attempt.attempt_id.clone())?,
            transport_identity: release_id("transport_identity", attempt.transport_id.clone())?,
            transport_key_epoch: attempt.transport_key_epoch,
            signed_status_digest: cancellation_digest,
            qualification_digest,
            cancellation_fence: status.cancellation().cancellation_fence,
            verified_at_unix_ms: context.trusted_time_unix_ms,
            verifier_identity,
            monotonic_checkpoint_digest: imported_digest(
                "transport_not_accepted.checkpoint_digest",
                status.checkpoint_digest().to_owned(),
            )?,
            verifier_policy_digest: policy.digest.clone(),
            artifacts: vec![signed_status, checkpoint, policy],
        };
        proof.validate_against(operation, context)?;
        Ok(proof)
    }

    pub(crate) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), ToolOutcomeError> {
        validate_projection_context(operation, context)?;
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding(
                "transport_not_accepted.dispatch_commit",
            ))?;
        validate_retained_dispatch_commit(operation, commit)?;
        validate_successor_fence(&self.projection_store_fence, &context.store_fence)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.operation_id != context.operation_id
            || self.request_id != operation.replay_key().request_id
            || self.request_id != context.request_id
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.operation_version != operation.version()
            || self.operation_version != context.expected_operation_version
            || self.dispatch_operation_version != commit.committed_version
            || self.dispatch_fence != commit.store_fence.owner_epoch
            || self.projection_coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.verified_at_unix_ms == 0
            || self.verified_at_unix_ms > context.trusted_time_unix_ms
            || (self.projection_store_fence == context.store_fence
                && self.projection_coordinator_lease_id != context.coordinator_lease_id)
            || self.artifacts.len() != 3
            || self.artifacts[0].kind != ReleaseEvidenceArtifactKindV1::SignedTransportStatus
            || self.artifacts[1].kind != ReleaseEvidenceArtifactKindV1::MonotonicAttemptCheckpoint
            || self.artifacts[2].kind != ReleaseEvidenceArtifactKindV1::VerifierPolicy
            || self.verifier_policy_digest != self.artifacts[2].digest
        {
            return Err(ToolOutcomeError::Binding(
                "transport_not_accepted.projection_context",
            ));
        }
        let evidence = transport::validate_artifacts(&self.artifacts, self.verified_at_unix_ms)?;
        let signed = &evidence.signed;
        let checkpoint = &evidence.checkpoint;
        let attempt = &checkpoint.attempt;
        let invocation_blob = checkpoint.phase.invocation_blob();
        if signed.verifier_identity != self.verifier_identity
            || signed.qualification_digest != self.qualification_digest
            || evidence.cancellation_digest != self.signed_status_digest
            || signed.cancellation.cancellation_fence != self.cancellation_fence
            || evidence.checkpoint_digest != self.monotonic_checkpoint_digest
            || attempt.operation_id != self.operation_id.as_str()
            || attempt.attempt_id != self.transport_attempt_id.as_str()
            || operation.provider_attempt() != Some(attempt)
            || attempt.transport_id != self.transport_identity.as_str()
            || attempt.transport_key_epoch != self.transport_key_epoch
            || invocation_blob.request_digest != self.request_binding_hash.as_str()
        {
            return Err(ToolOutcomeError::Binding(
                "transport_not_accepted.artifacts",
            ));
        }
        self.artifacts
            .iter()
            .try_for_each(ImmutableReleaseArtifactV1::validate)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedContractualZeroCharge {
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    pub(super) operation_version: u64,
    pub(super) outcome_version: u64,
    projection_coordinator_lease_id: AdmissionIdentifier,
    projection_coordinator_lease_epoch: u64,
    projection_store_fence: StoreMutationFence,
    verified_at_unix_ms: u64,
    tool_outcome_id: AdmissionDigest,
    evaluation_id: AdmissionDigest,
    pricing_verdict_digest: AdmissionDigest,
    currency: String,
    verifier_policy_digest: AdmissionDigest,
    artifacts: Vec<ImmutableReleaseArtifactV1>,
}

impl VerifiedContractualZeroCharge {
    pub(crate) fn from_records(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        outcome: &ToolOutcomeRecordV1,
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Self, ToolOutcomeError> {
        validate_projection_context(operation, context)?;
        outcome.validate_against(operation)?;
        ToolOutcomeTerminalEvidenceV1::from_records(operation, context, outcome, evaluation)?;
        let ResolvedToolOutcomeV1::Resolved {
            pricing_verdict_digest,
            settlement_disposition: SettlementDispositionV1::ContractualZeroCharge { currency },
            ..
        } = &outcome.disposition
        else {
            return Err(ToolOutcomeError::Invalid("zero_charge.disposition"));
        };
        let outcome_artifact = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::TerminalToolOutcome,
            release_id(
                "terminal_tool_outcome_evidence_id",
                format!("{}:outcome", outcome.outcome_id.as_str()),
            )?,
            serde_json::to_value(outcome.to_persisted())
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let evaluation_artifact = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::TerminalPostReturnEvaluation,
            release_id(
                "terminal_evaluation_evidence_id",
                format!("{}:evaluation", evaluation.evaluation_id.as_str()),
            )?,
            serde_json::to_value(evaluation.to_persisted())
                .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let policy = ImmutableReleaseArtifactV1::new(
            ReleaseEvidenceArtifactKindV1::VerifierPolicy,
            release_id(
                "verifier_policy_evidence_id",
                format!("{}:policy", evaluation.plan_digest.as_str()),
            )?,
            serde_json::to_value(VerifierPolicyArtifactV1 {
                policy: serde_json::json!({ "plan_digest": evaluation.plan_digest }),
            })
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?,
        )?;
        let proof = Self {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.replay_key().request_id,
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            operation_version: operation.version(),
            outcome_version: outcome.version,
            projection_coordinator_lease_id: context.coordinator_lease_id.clone(),
            projection_coordinator_lease_epoch: context.coordinator_lease_epoch,
            projection_store_fence: context.store_fence.clone(),
            verified_at_unix_ms: context.trusted_time_unix_ms,
            tool_outcome_id: outcome.outcome_id.clone(),
            evaluation_id: evaluation.evaluation_id.clone(),
            pricing_verdict_digest: pricing_verdict_digest.clone(),
            currency: currency.clone(),
            verifier_policy_digest: policy.digest.clone(),
            artifacts: vec![outcome_artifact, evaluation_artifact, policy],
        };
        proof.validate_against(operation, context)?;
        Ok(proof)
    }

    #[allow(dead_code)]
    pub(crate) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), ToolOutcomeError> {
        validate_projection_context(operation, context)?;
        validate_successor_fence(&self.projection_store_fence, &context.store_fence)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.request_id != operation.replay_key().request_id
            || self.request_id != context.request_id
            || self.request_binding_hash != *operation.binding().request_binding_hash()
            || self.operation_version != operation.version()
            || self.operation_version != context.expected_operation_version
            || self.outcome_version == 0
            || self.projection_coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.verified_at_unix_ms == 0
            || self.verified_at_unix_ms > context.trusted_time_unix_ms
            || (self.projection_store_fence == context.store_fence
                && self.projection_coordinator_lease_id != context.coordinator_lease_id)
            || self.artifacts.len() != 3
            || self.artifacts[0].kind != ReleaseEvidenceArtifactKindV1::TerminalToolOutcome
            || self.artifacts[1].kind != ReleaseEvidenceArtifactKindV1::TerminalPostReturnEvaluation
            || self.artifacts[2].kind != ReleaseEvidenceArtifactKindV1::VerifierPolicy
            || self.verifier_policy_digest != self.artifacts[2].digest
        {
            return Err(ToolOutcomeError::Binding("zero_charge.projection_context"));
        }
        let outcome_persisted: PersistedToolOutcomeRecordV1 =
            parse_artifact_value(&self.artifacts[0])?;
        let evaluation_persisted: PersistedPostReturnEvaluationRecordV1 =
            parse_artifact_value(&self.artifacts[1])?;
        let _: VerifierPolicyArtifactV1 = parse_artifact_value(&self.artifacts[2])?;
        let outcome = ToolOutcomeRecordV1::from_persisted(outcome_persisted)?;
        let evaluation = PostReturnEvaluationRecordV1::from_persisted(evaluation_persisted)?;
        outcome.validate_against(operation)?;
        evaluation.validate_against(operation, &outcome)?;
        let ResolvedToolOutcomeV1::Resolved {
            evaluation_id,
            pricing_verdict_digest,
            settlement_disposition: SettlementDispositionV1::ContractualZeroCharge { currency },
            ..
        } = &outcome.disposition
        else {
            return Err(ToolOutcomeError::Binding(
                "zero_charge.artifact_disposition",
            ));
        };
        if outcome.operation_id != self.operation_id
            || outcome.request_id != self.request_id
            || outcome.outcome_id != self.tool_outcome_id
            || outcome.version != self.outcome_version
            || outcome.recorded_at_unix_ms > self.verified_at_unix_ms
            || evaluation.operation_id != self.operation_id
            || evaluation.tool_outcome_id != self.tool_outcome_id
            || evaluation.evaluation_id != self.evaluation_id
            || evaluation.trusted_time_unix_ms > self.verified_at_unix_ms
            || evaluation_id != &self.evaluation_id
            || pricing_verdict_digest != &self.pricing_verdict_digest
            || currency != &self.currency
        {
            return Err(ToolOutcomeError::Binding("zero_charge.artifacts"));
        }
        self.artifacts
            .iter()
            .try_for_each(ImmutableReleaseArtifactV1::validate)
    }
}

fn validate_projection_context(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> Result<(), ToolOutcomeError> {
    context
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    operation
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    if let Some(commit) = operation.dispatch_commit() {
        validate_successor_fence(&commit.store_fence, &context.store_fence)?;
    }
    if context.operation_id != *operation.binding().operation_id()
        || context.request_id != operation.replay_key().request_id
        || context.expected_operation_version != operation.version()
        || context.coordinator_lease_epoch != operation.coordinator_lease_epoch()
    {
        return Err(ToolOutcomeError::Binding("release.projection_context"));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifiedNoEffectProof {
    BeforeDispatch(VerifiedPreDispatchNoEffect),
    NotAcceptedAfterDispatch(Box<VerifiedTransportNotAccepted>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MonetaryReleaseAuthority {
    NoEffect(VerifiedNoEffectProof),
    ContractualZeroCharge(Box<VerifiedContractualZeroCharge>),
}

#[cfg(test)]
mod tests;
