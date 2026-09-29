#[cfg(test)]
#[path = "event_consumer/tenant_isolation_tests.rs"]
mod tenant_isolation_tests;
#[cfg(test)]
#[path = "event_consumer/test_clocks.rs"]
mod test_clocks;
use super::AttestedCorrelationWriter;
use chio_core::capability::governance::{GovernedApprovalToken, GovernedTransactionIntent};
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::ToolCallAction;
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::SignedSecurityEvent;
use chio_kernel::threshold_approval::{authorization_capability_hash, ThresholdApprovalProposal};
use chio_kernel::{
    active_response_admission_artifact_payload_digest, active_response_submission_proof_digest,
    ActiveResponseAdmissionRequest, ActiveResponseArtifactAuthorityAttestation,
    ActiveResponseAuthorizationRequest, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionOutcome, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseFindingAuthority, ActiveResponseFindingAuthorityError,
    ActiveResponseSubmissionProof, AuthoritativeCorrelatedFindingEvidence, ChioKernel,
    DispatchCommittedActiveResponseResume, KernelError, PreDispatchActiveResponseReconstruction,
    PreparedActiveResponseAdmission,
};
use chio_quarantine::{
    build_response_plan, opaque_admission_artifact, ApprovalCoordinatorError, CorrelationOutcome,
    CorrelationPolicy, CorrelationStatus, ResponseApprovalCoordinator, TemporalCorrelator,
    TemporalRule,
};
use chio_security_kernel::{Clock, SecurityEventIngress};
use chio_security_types::ports::{
    derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, validate_attested_finding_batch_body,
    AdmissionArtifactRef, ApprovalVerifierPort, AttestedFindingBatchBinding,
    AttestedFindingBatchBindings, AttestedFindingBatchBody, AttestedFindingBatchKey,
    AttestedFindingBatchPublication, AttestedFindingBatchStore,
    AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
    AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxHealth,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
    AttestedFindingResponsePlanBody, AttestedFindingResponsePlanPublication,
    AttestedFindingResponsePlanningState, CanonicalBody, CorrelationIngressStore, Digest32,
    ErrorCode, EventPartitionScan, GovernedApprovalRequest, GovernedApprovalReservation,
    GovernedApprovalReservationMutation, OpaqueReceiptRef, PortError, PortErrorKind, PortResult,
    PreparedActiveResponseDispatchBinding, ProducerId, ProducerTrustClass, RecordId, RuleId,
    SecurityEventStore, SecurityEventVerificationRecord, SecurityEventVerifierPort, TenantId,
    UnverifiedSecurityEvent, ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
    ATTESTED_FINDING_RESPONSE_INITIAL_RETRY_MS, ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS,
    ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION, MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN,
};
#[cfg(test)]
use chio_security_types::ports::{
    ResponseDispatchApproval, PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectSpec, ResponsePlan,
    ResponsePlanInput, SecurityEventBody,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

mod verification;
pub use verification::{
    SecurityEventReceiptProjection, SecurityEventVerifierConfigError, TrustedSecurityEventProducer,
    TrustedSecurityEventReceiptProducer, SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
};

mod finding_publication;
pub use finding_publication::AttestedFindingBatchPlanner;
use finding_publication::{
    build_attested_finding_batch_publication, build_attested_finding_response_plan_publication,
    validate_authoritative_finding_binding,
};

mod ingress;
use ingress::CorrelationEventVerifier;
pub(crate) use ingress::DurableCorrelationIngress;
pub use ingress::VerifiedSecurityEventIngress;

mod correlation;
#[cfg(test)]
use correlation::{
    CorrelationAttestor, CorrelationPort, RuleCorrelationOutcome, SqliteTemporalCorrelationPort,
};
pub use correlation::{
    CorrelationConsumerReport, CorrelationRuleReport, ProductionCorrelationConsumer,
};

mod admission;
#[cfg(test)]
use admission::digest_from_canonical_hex;
use admission::governed_approval_request_from_native;
pub use admission::{AttestedFindingAdmissionArtifacts, AttestedFindingResponsePolicySelection};

mod reservation;
use reservation::build_reserved_response_plan;
pub use reservation::{
    AttestedFindingResponsePolicyPlanner, ReservedAttestedFindingResponseBatch,
    ReservedAttestedFindingResponsePlan,
};

mod coordinator;
use coordinator::map_approval_coordinator_error;
#[cfg(test)]
use coordinator::KernelActiveResponseApprovalVerifier;
pub use coordinator::KernelAttestedFindingResponseCoordinator;
#[cfg(test)]
pub(crate) use coordinator::PreparedAttestedFindingResponse;
pub(crate) use coordinator::{
    AttestedFindingDispatchCommittedResume, AttestedFindingPreDispatchReconstruction,
    AttestedFindingResponseCompletionProof, AttestedFindingResponseCoordinator,
};

mod recovery;
#[cfg(test)]
use recovery::response_recovery_backlog;
pub use recovery::DurableAttestedFindingBatchPlanner;

#[cfg(test)]
mod tests;

/// Hard operational bounds for synchronous startup reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestedFindingResponseRecoveryLimits {
    max_records_per_pass: u32,
    max_startup_records: u64,
    max_startup_wall_clock_ms: u64,
}

pub struct NativeSecurityEventVerifier {
    clock: Arc<dyn Clock>,
    trusted: BTreeMap<(TenantId, ProducerId), TrustedSecurityEventProducer>,
    trusted_receipts: BTreeMap<(TenantId, ProducerId), TrustedSecurityEventReceiptProducer>,
    max_event_age_ms: u64,
    max_future_skew_ms: u64,
}

pub(super) use coordinator::map_active_response_kernel_error;

pub(super) struct CorrelationConsumption {
    report: CorrelationConsumerReport,
    finalized: bool,
}
