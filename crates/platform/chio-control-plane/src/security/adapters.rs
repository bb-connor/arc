pub mod effect_port;
mod flow_dispatch;
mod flow_policy;
mod native_evidence;
mod native_flow;

use chio_core::crypto::PublicKey;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DeclassificationConsumptionReceiptBody, DeclassificationOutcomeReceiptBody,
    FlowDenialReceiptBody,
};
use chio_data_guards::{FindingLocation, StructuredClassifier};
use chio_flow::{
    canonical_request_hash, information_label_hash, prepare_egress_fence, prepare_pre_invocation,
    verify_declassification, CategoryLabelMap, DeclassificationDispatchOutcome,
    DeclassificationError, DeclassificationVerificationRequest, FlowAdmission, FlowDenial,
    InformationFlowLattice, PostInvocationFlow, ResolvedFlowRequest,
};
use chio_manifest::{AdmittedToolSecurity, BridgeSecurityMetadata, VerifiedManifestRegistry};
use chio_security_kernel::{
    Clock, FlowDispatchOutcomeRecorder, FlowPostInvocationInput, FlowPostInvocationResolver,
    FlowPreDispatchInput, FlowPreDispatchPort, FlowPreInvocationInput, FlowPreInvocationPort,
    FlowPreInvocationResolver, SystemClock,
};
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::ports::{
    derive_declassification_event_id, derive_declassification_transition_id, BoundedVec, ByteRange,
    CanonicalBody, ClassificationFinding, ClassificationPort, ClassificationRequest,
    ClassificationResult, ClassifierId, ClassifierVersion, DeclassificationCompactionQuery,
    DeclassificationCompactionRequest, DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePhase,
    DeclassificationEvidenceQuery, DeclassificationEvidenceRecord,
    DeclassificationEvidenceRetryRequest, DeclassificationOutcomeEvidenceCommit,
    DeclassificationOutcomeRequest, DeclassificationTransitionBinding, DeclassificationUseQuery,
    DeclassificationUseState, DeclassificationUseStore, DestinationId, Digest32, EgressFenceCommit,
    ErrorCode, EventId, ExactReceiptRecord, ExactSecurityReceiptSink, FlowJoinRequest,
    FlowStateKey, FlowStateSnapshot, FlowStateStore, GrantId, OpaqueReceiptRef, PortError,
    PortErrorKind, PortResult, ReceiptAppendRequest, RecordId, RequestId, SecurityReceiptSink,
    TenantId, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
use chio_security_types::InformationLabel;
pub use flow_dispatch::PreparedFlowDispatch;
pub use native_evidence::{
    AlertDispatchReport, AlertOutboxConfig, NativeActiveResponseFindingAuthority,
    NativeFindingAuthorityConfigError, NativeSchedulerHealthPort, NativeSecurityReceiptSink,
    SqliteSiemOutbox,
};
pub use native_flow::{
    NativeFlowCustody, NativeFlowError, NativeFlowPolicyEvidence, NativeFlowResolver,
    PreparedNativeFlowDispatch,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[cfg(test)]
#[path = "adapters/test_clocks.rs"]
mod test_clocks;

mod classification;
pub use classification::StructuredClassificationAdapter;

mod flow_resolution;
pub use flow_resolution::FlowResolverConfigError;
use flow_resolution::{
    flow_key, flow_transition_id, map_declassification_error, non_egress_declaration,
};

mod declassification_outbox;
use declassification_outbox::append_and_ack_exact_evidence;
pub use declassification_outbox::{
    DeclassificationCompactionReport, DeclassificationReceiptDrainReport,
    DeclassificationReceiptOutboxDrainer, DeclassificationReconciliationReport,
};

mod declassification_outcome;
use declassification_outcome::{
    commit_terminal_declassification_evidence, prepare_declassification_outcome_evidence,
    PendingDeclassificationOutcome,
};

mod flow_denial;
use flow_denial::FlowDenialReceiptContext;

mod receipt_projection;
use receipt_projection::{
    active_defense_header, active_defense_receipt_request, append_active_defense_body,
    append_exact_receipt, canonical_body, declassification_consumption_body,
    declassification_grant_hash, declassification_outcome_body, digest, event_id, transition_id,
};

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct FlowResolverConfig {
    operator_input_floor: InformationLabel,
    category_labels: CategoryLabelMap,
    trusted_declassification_authorities: BTreeMap<RecordId, PublicKey>,
    fence_ttl_ms: u64,
    declassification_evidence: Option<DeclassificationEvidenceConfig>,
    receipt_evidence: Option<FlowReceiptEvidenceConfig>,
}

#[derive(Clone)]
pub(super) struct DeclassificationEvidenceConfig {
    store: Arc<dyn DeclassificationEvidenceCommitStore>,
    sink: Arc<dyn ExactSecurityReceiptSink>,
    policy: ActiveDefensePolicyBinding,
}

#[derive(Clone)]
pub(super) struct FlowReceiptEvidenceConfig {
    sink: Arc<dyn SecurityReceiptSink>,
    policy: ActiveDefensePolicyBinding,
}

pub struct PersistentFlowResolver {
    manifests: Arc<VerifiedManifestRegistry>,
    state: Arc<dyn FlowStateStore>,
    classifier: Arc<dyn ClassificationPort>,
    clock: Arc<dyn Clock>,
    config: FlowResolverConfig,
}

pub(super) struct AtomicDeclassificationConsumptionStore {
    store: Arc<dyn DeclassificationEvidenceCommitStore>,
    commit: DeclassificationConsumptionEvidenceCommit,
}

pub(super) struct PersistentDeclassificationOutcomeRecorder {
    evidence: DeclassificationEvidenceConfig,
    consumption: DeclassificationConsumptionEvidenceCommit,
    grant_hash: Digest32,
    released: DeclassificationTransitionBinding,
    dispatch_failed: DeclassificationTransitionBinding,
    outcome_unknown_after_dispatch: DeclassificationTransitionBinding,
    clock: Arc<dyn Clock>,
    pending_outcome: Option<PendingDeclassificationOutcome>,
    completed_outcome: Option<DeclassificationDispatchOutcome>,
}

pub(super) struct DeclassificationOutcomeBodyInput {
    tenant_id: TenantId,
    prior_receipt_id: OpaqueReceiptRef,
    policy: ActiveDefensePolicyBinding,
    grant_id: GrantId,
    grant_hash: Digest32,
    request_hash: Digest32,
    occurred_at_unix_ms: u64,
    to_state: DeclassificationUseState,
}
