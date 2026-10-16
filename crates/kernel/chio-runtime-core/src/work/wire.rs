//! `chio.work.v1` wire envelopes. Every type is a closed shape: unknown
//! fields and variants are refused, and enums are `kind`-tagged.

use chio_security_types::knowledge::ArtifactVersionRefV1;
use chio_security_types::recovery::{
    ContinuationId, ContractDigest, DeploymentDigest, EffectObservationV1, EvidenceRef, IssuerId,
    OperationRef, PolicyGeneration, ProfileDigest, RecoveryObservationSchema, RecoveryScopeV1,
    ReleaseDispositionV1, RequestId, SafeInteger, StepId, VersionV1, WorkflowControlV1, WorkflowId,
};
use chio_swarm_authority::{SwarmGraphEdge, SwarmGraphJoin};
use chio_workflow::delegation::{
    DispatchBinding, DispatchPermit, Selection, Signed, Subdivision, WorkOffer, WorkSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::{WorkBindingFieldV1, WorkRejectionCodeV1};
use super::ids::*;

macro_rules! schema_id {
    ($name:ident, $id:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $id)]
            V1,
        }
    };
}

schema_id!(WorkRequestSchema, "chio.work.request.v1");
schema_id!(WorkResponseSchema, "chio.work.response.v1");
schema_id!(WorkPreparationSchema, "chio.work.preparation.v1");
schema_id!(WorkCommandSchema, "chio.work.command.v1");
schema_id!(WorkJoinInputsSchema, "chio.work.join-inputs.v1");

/// Native identity of one delegated invocation. A reference, not a permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkHandleV1 {
    pub program_id: WorkProgramId,
    pub slot_id: WorkSlotId,
    pub allocation_hash: WorkAllocationDigest,
    pub receiver_kernel_id: WorkReceiverKernelId,
    pub request_id: RequestId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPreparationRefV1 {
    pub program_id: WorkProgramId,
    pub preparation_id: WorkPreparationId,
    pub command_digest: WorkCommandDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCommandRefV1 {
    pub program_id: WorkProgramId,
    pub command_id: WorkCommandId,
    pub command_digest: WorkCommandDigest,
}

/// An owner-retained unsigned graph draft against an expected base.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkGraphDraftRefV1 {
    pub draft_id: WorkDraftId,
    pub graph_sha256: WorkGraphDigest,
}

/// An owner-retained unsigned join draft against an expected base.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkJoinDraftRefV1 {
    pub draft_id: WorkDraftId,
    pub graph_sha256: WorkGraphDigest,
}

/// The owning operation a pending result waits on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOwnerOperationRefV1 {
    pub operation: OperationRef,
    pub scope: RecoveryScopeV1,
}

/// The caller's intended terms, resolved against owner-retained sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProfileRefV1 {
    pub owner: WorkOwnerId,
    pub catalog_entry: WorkCatalogEntryId,
    pub deployment_digest: DeploymentDigest,
    pub policy_generation: PolicyGeneration,
    pub profile_digest: ProfileDigest,
}

/// The configured rail, agreement and reserve. Naming them proves no funding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkFundingRefV1 {
    pub rail: WorkRailId,
    pub agreement_digest: WorkAgreementDigest,
    pub reserve_ref: WorkReserveRef,
}

/// Links one delegated invocation to its sealed permit, terms, custody and
/// graph. It defines no signing domain of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCommitmentV1 {
    pub handle: WorkHandleV1,
    pub permit: Signed<DispatchPermit>,
    pub profile_ref: WorkProfileRefV1,
    pub invocation_ref: WorkInvocationDigest,
    pub graph_ref: WorkGraphDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<WorkFundingRefV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkAgreementTermsV1 {
    Unpaid {
        terms_reference: WorkTermsReference,
    },
    Funded {
        funding_profile_id: WorkFundingProfileId,
        terms_reference: WorkTermsReference,
    },
}

/// A new task an extension proposes. Its signed node is produced by the
/// graph issuer, never by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkNewTaskV1 {
    pub task_id: WorkTaskId,
    pub handle: WorkHandleV1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkProposalV1 {
    Delegate {
        parent_id: WorkSlotId,
        parent_allocation_hash: WorkAllocationDigest,
        child: WorkSlot,
    },
    Offer {
        slot_id: WorkSlotId,
        allocation_hash: WorkAllocationDigest,
        profile_ref: WorkProfileRefV1,
        receiver_kernel_id: WorkReceiverKernelId,
        server_id: WorkServerId,
        tool_name: WorkToolName,
        arguments: Value,
        request_id: RequestId,
    },
    Select {
        offer: Box<Signed<WorkOffer>>,
        request_id: RequestId,
        capability_hash: WorkCapabilityDigest,
        expected_revision: SafeInteger,
    },
    Extend {
        expected_bundle_sha256: WorkBundleDigest,
        new_work: Vec<WorkNewTaskV1>,
        dependencies: Vec<SwarmGraphEdge>,
        join_draft_refs: Vec<WorkJoinDraftRefV1>,
    },
    Join {
        expected_bundle_sha256: WorkBundleDigest,
        join: SwarmGraphJoin,
        parents: Vec<WorkHandleV1>,
    },
    Agreement {
        commitment: Box<WorkCommitmentV1>,
        terms: WorkAgreementTermsV1,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPreparationV1 {
    pub schema: WorkPreparationSchema,
    pub version: VersionV1,
    pub program_id: WorkProgramId,
    pub command_id: WorkCommandId,
    pub proposal: WorkProposalV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkPreparedArtifactV1 {
    Subdivision {
        subdivision: Box<Signed<Subdivision>>,
    },
    Offer {
        offer: Box<Signed<WorkOffer>>,
        invocation_ref: WorkInvocationDigest,
    },
    Selection {
        selection: Box<Signed<Selection>>,
    },
    GraphDraft {
        draft_ref: WorkGraphDraftRefV1,
    },
    JoinDraft {
        draft_ref: WorkJoinDraftRefV1,
    },
    Agreement {
        agreement_digest: WorkAgreementDigest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkPreparedV1 {
    Prepared {
        preparation_ref: WorkPreparationRefV1,
        artifact: Box<WorkPreparedArtifactV1>,
    },
    Pending {
        preparation_ref: WorkPreparationRefV1,
        owner_operation_ref: WorkOwnerOperationRefV1,
    },
    Refused {
        preparation_ref: WorkPreparationRefV1,
        rejection: WorkRejectionV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkActionV1 {
    Delegate {
        subdivision: Box<Signed<Subdivision>>,
    },
    Select {
        selection: Box<Signed<Selection>>,
    },
    Seal {
        binding: Box<DispatchBinding>,
    },
    Extend {
        expected_bundle_sha256: WorkBundleDigest,
        draft_ref: WorkGraphDraftRefV1,
    },
    Submit {
        commitment: Box<WorkCommitmentV1>,
    },
    Reconcile {
        handle: WorkHandleV1,
    },
    Cancel {
        handle: WorkHandleV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCommandV1 {
    pub schema: WorkCommandSchema,
    pub version: VersionV1,
    pub program_id: WorkProgramId,
    pub command_id: WorkCommandId,
    pub action: WorkActionV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkAppliedV1 {
    Delegated {
        slot: Box<WorkSlot>,
    },
    Selected {
        revision: SafeInteger,
    },
    Sealed {
        permit: Box<Signed<DispatchPermit>>,
    },
    Extended {
        bundle_sha256: WorkBundleDigest,
    },
    Submitted {
        owner_operation_ref: WorkOwnerOperationRefV1,
    },
    Reconciled {
        view: Box<WorkViewV1>,
    },
    CancelObserved {
        control: WorkflowControlV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkCommandOutcomeV1 {
    Applied {
        revision: SafeInteger,
        result: Box<WorkAppliedV1>,
    },
    Pending {
        owner_operation_ref: WorkOwnerOperationRefV1,
    },
    Refused {
        rejection: WorkRejectionV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCommandResultV1 {
    pub command_ref: WorkCommandRefV1,
    pub outcome: WorkCommandOutcomeV1,
}

/// A catalog continuation, bound to the caller scope and catalog generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCatalogCursorV1 {
    pub catalog_generation: PolicyGeneration,
    pub position: WorkCursorDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCatalogRefV1 {
    pub owner: WorkOwnerId,
    pub catalog_id: WorkCatalogId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkQueryV1 {
    Work {
        handle: WorkHandleV1,
    },
    Command {
        command_ref: WorkCommandRefV1,
    },
    Preparation {
        preparation_ref: WorkPreparationRefV1,
    },
    Catalog {
        catalog_ref: WorkCatalogRefV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<WorkCatalogCursorV1>,
    },
    Profile {
        profile_ref: WorkProfileRefV1,
    },
}

/// Where an advertised condition comes from and who enforces it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkEnforcementV1 {
    Local,
    Remote,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkConditionV1 {
    pub source: WorkSourceId,
    pub enforcement: WorkEnforcementV1,
    pub statement_digest: WorkEvidenceDigest,
}

/// Supported recovery operations, named after REC-0a's command kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkRecoveryOperationV1 {
    InspectWorkflow,
    SelectOffer,
    SubmitApproval,
    ResumeWorkflow,
    CancelWorkflow,
}

/// The audience-scoped resolved view of one catalog entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProfileV1 {
    pub profile_ref: WorkProfileRefV1,
    pub server_id: WorkServerId,
    pub tool_name: WorkToolName,
    pub tool_schema_digest: WorkEvidenceDigest,
    pub implementation_digest: WorkEvidenceDigest,
    pub max_units: SafeInteger,
    pub currency: WorkSourceId,
    pub acceptance_procedure: WorkProcedureDigest,
    pub recovery_operations: Vec<WorkRecoveryOperationV1>,
    pub valid_until_unix_ms: SafeInteger,
    pub conditions: Vec<WorkConditionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_profile_id: Option<WorkFundingProfileId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkCatalogPageV1 {
    pub catalog_ref: WorkCatalogRefV1,
    pub entries: Vec<WorkProfileRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<WorkCatalogCursorV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAcceptanceDecisionV1 {
    Accepted,
    Rejected,
}

/// An evaluator's decision over the exact artifact a producer returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAcceptanceV1 {
    pub handle: WorkHandleV1,
    pub producer: OperationRef,
    pub artifact: ArtifactVersionRefV1,
    pub artifact_digest: WorkArtifactDigest,
    pub contract_digest: ContractDigest,
    pub procedure_digest: WorkProcedureDigest,
    pub evaluator: IssuerId,
    pub decision: WorkAcceptanceDecisionV1,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkResultReferenceV1 {
    pub artifact: ArtifactVersionRefV1,
    pub release: ReleaseDispositionV1,
}

/// A link into the owning recovery workflow. It carries no command body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRecoveryLinkV1 {
    pub schema: RecoveryObservationSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub workflow_id: WorkflowId,
    pub step_id: StepId,
    pub continuation_id: ContinuationId,
    pub control: WorkflowControlV1,
    pub available: Vec<WorkRecoveryOperationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSettlementRefV1 {
    pub rail: WorkRailId,
    pub agreement_digest: WorkAgreementDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkDeliveryStateV1 {
    Retained,
    Delivered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkDeliveryRefV1 {
    pub envelope_digest: WorkEnvelopeDigest,
    pub state: WorkDeliveryStateV1,
}

/// One observation of an owning authority at one revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkObservationV1<T> {
    NotApplicable,
    Pending {
        owner_ref: WorkOwnerOperationRefV1,
    },
    Available {
        source: WorkSourceId,
        revision: SafeInteger,
        observed_at: SafeInteger,
        value: T,
    },
    Unavailable {
        code: WorkRejectionCodeV1,
    },
}

/// Independent observations; not a globally atomic snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkViewV1 {
    pub handle: WorkHandleV1,
    pub execution: WorkObservationV1<EffectObservationV1>,
    pub acceptance: WorkObservationV1<WorkAcceptanceV1>,
    pub result_reference: WorkObservationV1<WorkResultReferenceV1>,
    pub recovery: WorkObservationV1<WorkRecoveryLinkV1>,
    pub settlement: WorkObservationV1<WorkSettlementRefV1>,
    pub bilateral_delivery: WorkObservationV1<WorkDeliveryRefV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkQueryResultV1 {
    Work { view: Box<WorkViewV1> },
    Command { result: Box<WorkCommandResultV1> },
    Preparation { prepared: Box<WorkPreparedV1> },
    Catalog { page: WorkCatalogPageV1 },
    Profile { profile: Box<WorkProfileV1> },
    Unavailable { code: WorkRejectionCodeV1 },
}

/// A refusal with the binding that failed and the authorized reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRejectionV1 {
    pub code: WorkRejectionCodeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<WorkBindingFieldV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<WorkCommandRefV1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkRequestBodyV1 {
    Prepare { preparation: Box<WorkPreparationV1> },
    Submit { command: Box<WorkCommandV1> },
    Query { query: Box<WorkQueryV1> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRequestV1 {
    pub schema: WorkRequestSchema,
    pub version: VersionV1,
    pub body: WorkRequestBodyV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkResponseBodyV1 {
    Prepared { prepared: Box<WorkPreparedV1> },
    Command { result: Box<WorkCommandResultV1> },
    Query { result: Box<WorkQueryResultV1> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkResponseV1 {
    pub schema: WorkResponseSchema,
    pub version: VersionV1,
    pub body: WorkResponseBodyV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkJoinParentV1 {
    pub task_id: WorkTaskId,
    pub receipt_id: WorkReceiptId,
    pub artifact_ref: ArtifactVersionRefV1,
    pub artifact_digest: WorkArtifactDigest,
    pub acceptance_evidence_digest: WorkEvidenceDigest,
}

/// The canonical metadata manifest whose RFC 8785 digest is the S1
/// `result_digest` of a join.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkJoinInputsV1 {
    pub schema: WorkJoinInputsSchema,
    pub version: VersionV1,
    pub graph_sha256: WorkGraphDigest,
    pub join_id: WorkJoinId,
    pub next_task_id: WorkTaskId,
    pub parents: Vec<WorkJoinParentV1>,
}

/// Rejection used when the request names a binding that no longer holds.
#[must_use]
pub const fn binding_rejection(field: WorkBindingFieldV1) -> WorkRejectionV1 {
    WorkRejectionV1 {
        code: WorkRejectionCodeV1::BindingMismatch,
        field: Some(field),
        reference: None,
    }
}
