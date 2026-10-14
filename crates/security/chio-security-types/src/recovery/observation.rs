use super::{
    AdmissionIntentRef, AuthorityDomainId, ContinuationId, ContractError, EvidenceRef,
    KnowledgeDigest, NativeAdmissionDigest, OperationId, ProcessId, RecoveryTenantId, ReleaseId,
    RequestId, SafeInteger, StepId, VersionV1, WorkflowId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryScopeV1 {
    pub authority_domain: AuthorityDomainId,
    pub tenant_id: RecoveryTenantId,
    pub process_id: ProcessId,
}
impl RecoveryScopeV1 {
    /// The expected scope comes from authenticated host authority, never the
    /// incoming envelope. Matching data still does not create a live owner.
    pub fn ensure_matches(&self, expected: &Self) -> Result<(), ContractError> {
        if self != expected {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationRef {
    operation_id: OperationId,
    native_admission_digest: NativeAdmissionDigest,
    operation_version: SafeInteger,
}
impl OperationRef {
    pub fn new(
        operation_id: OperationId,
        native_admission_digest: NativeAdmissionDigest,
        operation_version: SafeInteger,
    ) -> Result<Self, ContractError> {
        if operation_version.get() == 0 {
            return Err(ContractError::InvalidState);
        }
        Ok(Self {
            operation_id,
            native_admission_digest,
            operation_version,
        })
    }
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    pub const fn native_admission_digest(&self) -> NativeAdmissionDigest {
        self.native_admission_digest
    }
    pub const fn operation_version(&self) -> SafeInteger {
        self.operation_version
    }
}
impl<'de> Deserialize<'de> for OperationRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            operation_id: OperationId,
            native_admission_digest: NativeAdmissionDigest,
            operation_version: SafeInteger,
        }
        let Wire {
            operation_id,
            native_admission_digest,
            operation_version,
        } = Wire::deserialize(d)?;
        Self::new(operation_id, native_admission_digest, operation_version)
            .map_err(serde::de::Error::custom)
    }
}

/// Claims about the original denial, included in exact-action review. Only the
/// owning native authority can establish its effect-free closure and exclusive
/// continuation ownership; decoding these references grants no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOriginV1 {
    pub operation: OperationRef,
    pub request_id: RequestId,
    pub closure: EvidenceRef,
}

/// Claimed effect facts, never derived from a receipt verdict. Authentication
/// and irreversible closure remain the owning kernel's responsibility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectObservationV1 {
    NeverAdmitted,
    AdmissionUnresolved {
        admission_intent: AdmissionIntentRef,
    },
    ClosedBeforeEffect {
        operation: OperationRef,
        closure: EvidenceRef,
    },
    AwaitingApproval {
        operation: OperationRef,
    },
    InFlight {
        operation: OperationRef,
    },
    AwaitingCallerReport {
        operation: OperationRef,
    },
    Unknown {
        operation: OperationRef,
    },
    Complete {
        operation: OperationRef,
        effect_count: SafeInteger,
    },
    Partial {
        operation: OperationRef,
        applied_effects: SafeInteger,
    },
    FailedAfterEffect {
        operation: OperationRef,
        applied_effects: SafeInteger,
    },
}
impl EffectObservationV1 {
    pub fn operation(&self) -> Option<&OperationRef> {
        match self {
            Self::NeverAdmitted | Self::AdmissionUnresolved { .. } => None,
            Self::ClosedBeforeEffect { operation, .. }
            | Self::AwaitingApproval { operation }
            | Self::InFlight { operation }
            | Self::AwaitingCallerReport { operation }
            | Self::Unknown { operation }
            | Self::Complete { operation, .. }
            | Self::Partial { operation, .. }
            | Self::FailedAfterEffect { operation, .. } => Some(operation),
        }
    }
    pub const fn is_settled(&self) -> bool {
        matches!(
            self,
            Self::ClosedBeforeEffect { .. }
                | Self::Complete { .. }
                | Self::Partial { .. }
                | Self::FailedAfterEffect { .. }
        )
    }
    pub fn applied_effects(&self) -> Option<SafeInteger> {
        match self {
            Self::NeverAdmitted | Self::ClosedBeforeEffect { .. } => Some(SafeInteger::ZERO),
            Self::Complete { effect_count, .. } => Some(*effect_count),
            Self::Partial {
                applied_effects, ..
            }
            | Self::FailedAfterEffect {
                applied_effects, ..
            } => Some(*applied_effects),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReleaseDispositionV1 {
    NotAvailable,
    Pending { release_id: ReleaseId },
    Withheld { evidence: EvidenceRef },
    Released { release_id: ReleaseId },
    Denied { reason: RefusalCode },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowControlV1 {
    Active,
    CancelRequested,
    Cancelled,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    InvalidEvidence,
    UnsupportedProfile,
    StaleBasis,
    Revoked,
    Expired,
    BudgetUnavailable,
    UnknownEffect,
    AudienceDenied,
    ResourceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryObservationSchema {
    #[serde(rename = "chio.recovery.observation.v1")]
    V1,
}

/// Private state prevents construction of contradictory effect/release claims.
/// This is still untrusted evidence, including after successful decoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryObservationV1 {
    schema: RecoveryObservationSchema,
    version: VersionV1,
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    step_id: StepId,
    continuation_id: ContinuationId,
    revision: SafeInteger,
    effect: EffectObservationV1,
    release: ReleaseDispositionV1,
    control: WorkflowControlV1,
    knowledge_digest: KnowledgeDigest,
}

/// Constructor input is data. It cannot certify kernel effect truth.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservationInput {
    pub schema: RecoveryObservationSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
    pub revision: SafeInteger,
    pub effect: EffectObservationV1,
    pub release: ReleaseDispositionV1,
    pub control: WorkflowControlV1,
    pub knowledge_digest: KnowledgeDigest,
}

impl RecoveryObservationV1 {
    pub fn new(input: RecoveryObservationInput) -> Result<Self, ContractError> {
        let RecoveryObservationInput {
            schema,
            version,
            scope,
            workflow_id,
            step_id,
            continuation_id,
            revision,
            effect,
            release,
            control,
            knowledge_digest,
        } = input;
        if matches!(&effect, EffectObservationV1::Partial { applied_effects, .. }
            | EffectObservationV1::FailedAfterEffect { applied_effects, .. } if applied_effects.get() == 0)
        {
            return Err(ContractError::InvalidState);
        }
        if !matches!(release, ReleaseDispositionV1::NotAvailable)
            && !matches!(
                effect,
                EffectObservationV1::Complete { .. }
                    | EffectObservationV1::Partial { .. }
                    | EffectObservationV1::FailedAfterEffect { .. }
            )
        {
            return Err(ContractError::InvalidState);
        }
        Ok(Self {
            schema,
            version,
            scope,
            workflow_id,
            step_id,
            continuation_id,
            revision,
            effect,
            release,
            control,
            knowledge_digest,
        })
    }
    pub fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }
    pub fn step_id(&self) -> &StepId {
        &self.step_id
    }
    pub fn continuation_id(&self) -> &ContinuationId {
        &self.continuation_id
    }
    pub const fn revision(&self) -> SafeInteger {
        self.revision
    }
    pub fn effect(&self) -> &EffectObservationV1 {
        &self.effect
    }
    pub fn release(&self) -> &ReleaseDispositionV1 {
        &self.release
    }
    pub const fn control(&self) -> WorkflowControlV1 {
        self.control
    }
    pub const fn knowledge_digest(&self) -> KnowledgeDigest {
        self.knowledge_digest
    }
}
impl<'de> Deserialize<'de> for RecoveryObservationV1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(RecoveryObservationInput::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
