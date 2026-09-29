pub use crate::deception::{
    DecoyArtifactLookup, DecoyScan, SealedDecoyCasRequest, SealedDecoyPage, SealedDecoyRecord,
    SealedMarkerLookup, SealedPublicRefLookup, WatermarkObservation, WatermarkObservationResult,
    WatermarkSequenceReservation, WatermarkSequenceReservationResult,
};
pub use crate::response_domains::{
    RESPONSE_AFFECTED_SET_DOMAIN, RESPONSE_EFFECT_ID_DOMAIN, RESPONSE_REQUEST_ID_DOMAIN,
    RESPONSE_TRANSITION_ID_DOMAIN,
};
use crate::{InformationLabel, ResponseEffectKind, ResponseTarget};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use alloc::{format, vec};
use core::fmt;
use serde::de::{SeqAccess, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize};
mod alerts;
#[cfg(feature = "std")]
pub use alerts::SecurityAlertPort;
pub use alerts::{AlertDeliveryQuery, AlertDeliveryStatus, SecurityAlert};

mod approval;
#[cfg(feature = "std")]
pub use approval::ApprovalVerifierPort;
pub use approval::{
    GovernedApprovalRequest, GovernedApprovalReservation, GovernedApprovalReservationMutation,
    OpaqueApprovalAdmissionArtifact, OpaqueApprovalAdmissionArtifactBody,
    OPAQUE_APPROVAL_ADMISSION_ARTIFACT_SCHEMA_VERSION,
};

mod bounded;
pub use bounded::{
    BodyError, BoundedVec, CanonicalBody, CanonicalSetError, CollectionError, Digest32,
    EgressDeniedDestinations, EgressDestinationSet, EgressRestrictionEffectIds, RecordIdSet,
    RecordIdSetError,
};

#[cfg(feature = "std")]
mod canonical;
#[cfg(feature = "std")]
use canonical::{issuance_freeze_domain_hash, sort_json_object_keys};

mod classification;
pub use classification::{
    ByteRange, ClassificationFinding, ClassificationFindings, ClassificationRequest,
    ClassificationResult, TripwireDecision, TripwireInput, TripwireKind,
};
#[cfg(feature = "std")]
pub use classification::{ClassificationPort, TripwireDetectorPort};

mod containment;
#[cfg(feature = "std")]
pub use containment::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, containment_target, predict_containment_overlay_apply,
    predict_containment_overlay_remove, validate_containment_overlay_snapshot,
    ContainmentOverlayStore,
};
pub use containment::{
    ContainmentOverlayCommand, ContainmentTargetKind, OverlayApplyRequest, OverlayContribution,
    OverlayContributions, OverlayRemoveRequest, OverlaySnapshot,
    CONTAINMENT_INSTALLED_CONTRIBUTION_DOMAIN, CONTAINMENT_OVERLAY_VERSION_DOMAIN,
    CONTAINMENT_TARGET_DOMAIN,
};

mod deception;
#[cfg(feature = "std")]
pub use deception::{SealedDecoyRegistryStore, WatermarkObservationStore, WatermarkSequenceStore};

mod declassification;
pub use declassification::{
    declassification_retain_until_unix_ms, DeclassificationCompactionCandidate,
    DeclassificationCompactionQuery, DeclassificationCompactionRequest, DeclassificationConsume,
    DeclassificationConsumeRequest, DeclassificationConsumptionEvidenceCommit,
    DeclassificationEvidenceAckRequest, DeclassificationEvidencePendingQuery,
    DeclassificationEvidencePhase, DeclassificationEvidenceQuery, DeclassificationEvidenceRecord,
    DeclassificationEvidenceRetryRequest, DeclassificationEvidenceTombstone,
    DeclassificationOutcomeEvidenceCommit, DeclassificationOutcomeRequest,
    DeclassificationTransitionBinding, DeclassificationUseQuery, DeclassificationUseRecord,
    DeclassificationUseState, DECLASSIFICATION_CONSUMPTION_EVENT_DOMAIN,
    DECLASSIFICATION_CONSUMPTION_TRANSITION_DOMAIN, DECLASSIFICATION_DISPATCH_FAILED_EVENT_DOMAIN,
    DECLASSIFICATION_DISPATCH_FAILED_TRANSITION_DOMAIN, DECLASSIFICATION_EVIDENCE_INITIAL_RETRY_MS,
    DECLASSIFICATION_EVIDENCE_MAX_RETRY_MS, DECLASSIFICATION_EVIDENCE_RETENTION_MS,
    DECLASSIFICATION_EVIDENCE_SCHEMA_VERSION,
    DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_EVENT_DOMAIN,
    DECLASSIFICATION_OUTCOME_UNKNOWN_AFTER_DISPATCH_TRANSITION_DOMAIN,
    DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_EVENT_DOMAIN,
    DECLASSIFICATION_RECEIPT_PERSISTENCE_FAILED_TRANSITION_DOMAIN,
    DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_EVENT_DOMAIN,
    DECLASSIFICATION_RECOVERY_OUTCOME_UNKNOWN_TRANSITION_DOMAIN,
    DECLASSIFICATION_RECOVERY_UNDELIVERED_EVENT_DOMAIN,
    DECLASSIFICATION_RECOVERY_UNDELIVERED_TRANSITION_DOMAIN,
    DECLASSIFICATION_RELEASED_EVENT_DOMAIN, DECLASSIFICATION_RELEASED_TRANSITION_DOMAIN,
    MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
#[cfg(feature = "std")]
pub use declassification::{
    declassification_retry_deadline_unix_ms, derive_declassification_event_id,
    derive_declassification_transition_id, DeclassificationEvidenceCommitStore,
    DeclassificationUseStore,
};

mod dispatch;
#[cfg(feature = "std")]
pub use dispatch::ResponseDispatchStore;
pub use dispatch::{
    AutomaticResponseDispatchFenceOutcome, AutomaticResponseDispatchFenceRecord,
    AutomaticResponseDispatchFenceRequest, ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode, ResponseDispatchCommitOutcome,
    ResponseDispatchCommitRequest, ResponseDispatchKey, ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecord, ResponseDispatchRecoveryOutcome,
    ResponseDispatchRecoveryRequest, RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};

mod effects;
#[cfg(feature = "std")]
pub use effects::EffectPort;
pub use effects::{
    EffectExecutionStatus, EffectOperation, EffectRequest, EffectResult, EffectResultQuery,
};

mod egress;
#[cfg(feature = "std")]
pub use egress::EgressRestrictionStore;
pub use egress::{
    EgressDestinationQuery, EgressRestrictionApplyRequest, EgressRestrictionCommand,
    EgressRestrictionContribution, EgressRestrictionContributions, EgressRestrictionDecision,
    EgressRestrictionRemoveRequest, EgressRestrictionSessionKey, EgressRestrictionSnapshot,
};

mod events;
pub use events::{
    AdvisorySecurityEvent, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventAdmission, CorrelationEventAdmissionRequest, CorrelationEventIndexRequest,
    CorrelationOutcomeCommitRequest, CorrelationOutcomeKey, CorrelationOutcomePublication,
    CorrelationOutcomeStatus, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, EventAppend, EventPartitionScan, ProducerTrustClass,
    SecurityEventVerificationRecord, UnverifiedEventBatch, UnverifiedSecurityEvent,
    VerifiedEventBatch,
};
#[cfg(feature = "std")]
pub use events::{CorrelationIngressStore, SecurityEventStore, SecurityEventVerifierPort};

mod findings;
#[cfg(feature = "std")]
pub use findings::{
    derive_attested_finding_action_id, derive_attested_finding_batch_id,
    derive_attested_finding_reservation_id, validate_attested_finding_batch_body,
    AttestedFindingBatchStore,
};
pub use findings::{
    AttestedFindingBatchBinding, AttestedFindingBatchBindings, AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication, ATTESTED_FINDING_ACTION_ID_DOMAIN,
    ATTESTED_FINDING_BATCH_ID_DOMAIN, ATTESTED_FINDING_BATCH_SCHEMA_VERSION,
    ATTESTED_FINDING_RESERVATION_ID_DOMAIN, MAX_ATTESTED_FINDING_BATCH_SIZE,
};

mod flow;
pub use flow::{
    CommittedEgressFence, EgressFence, EgressFenceCommit, EgressFenceRequest, FlowJoinRequest,
    FlowStateKey, FlowStateSnapshot, IsolationEpochTransition, IsolationVerificationRecord,
    TenantScopedId,
};
#[cfg(feature = "std")]
pub use flow::{FlowStateStore, IsolationEpochEvidenceVerifierPort};

mod identifiers;
pub use identifiers::{
    ActionId, AdmissionArtifactRef, ArtifactId, ClassifierId, ClassifierVersion, DestinationId,
    EffectId, ErrorCode, EventId, GrantId, IdError, IsolationEpochId, LeaseOwnerId, LineageId,
    OpaqueReceiptRef, PortError, PortErrorKind, PortResult, ProducerId, PurposeId, RecordId,
    RequestId, RuleId, SessionId, TenantId,
};

mod issuance;
#[cfg(feature = "std")]
pub use issuance::IssuanceFreezeStore;
pub use issuance::{
    CapabilityIssuanceOperation, IssuanceFreezeAdmissionDecision, IssuanceFreezeAdmissionQuery,
    IssuanceFreezeApplyRequest, IssuanceFreezeCommand, IssuanceFreezeContribution,
    IssuanceFreezeContributions, IssuanceFreezeKey, IssuanceFreezeMatch, IssuanceFreezeMatches,
    IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease, IssuanceFreezeRemoveRequest,
    IssuanceFreezeSnapshot, IssuanceFreezeSpec, ISSUANCE_FREEZE_INSTALLED_CONTRIBUTION_DOMAIN,
    ISSUANCE_FREEZE_VERSION_DOMAIN,
};

mod lineage;
pub use lineage::{
    BlastRadiusFenceAcquisition, BlastRadiusIncompleteReason, BlastRadiusQueryBounds,
    BlastRadiusRequest, BlastRadiusResult, BlastRadiusSeeds, BlastRadiusSnapshotMetadata,
    CausalLineageCommitMetadata, CausalLineageCommitRequest, CausalLineageEdge,
    CausalLineageEdgeKind, CausalLineageEdges, CausalLineageFenceRequest, CausalLineageNode,
    CausalLineageNodeKind, CausalLineageNodes, CausalLineageSnapshot, CausalLineageSnapshotRequest,
    IssuanceFreezeFenceMaintenanceRequest, LineageFence, LineageFenceMaintenanceOutcome,
    LineageFenceMaintenanceRequest, LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest,
    LineageFenceTakeover, MaintainedLineageFence, LINEAGE_FENCE_MAX_LEASE_MS,
    LINEAGE_FENCE_RENEWAL_MARGIN_MS,
};
#[cfg(feature = "std")]
pub use lineage::{
    BlastRadiusPort, CausalLineageCommitStore, CausalLineageFenceStore, CausalLineageStore,
    LineageFenceStore,
};

mod outbox;
#[cfg(feature = "std")]
pub use outbox::AttestedFindingResponseOutboxStore;
pub use outbox::{
    AttestedFindingResponseAdmissionState, AttestedFindingResponseCompletionOutcome,
    AttestedFindingResponseCompletionState, AttestedFindingResponseOutboxHealth,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponseOutboxTransition, AttestedFindingResponsePlanBody,
    AttestedFindingResponsePlanPublication, AttestedFindingResponsePlanningState,
    PreparedActiveResponseDispatchBinding, PreparedActiveResponseDispatchBindingError,
    ATTESTED_FINDING_RESPONSE_INITIAL_RETRY_MS, ATTESTED_FINDING_RESPONSE_MAX_ATTEMPTS,
    ATTESTED_FINDING_RESPONSE_MAX_RETRY_MS, ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION,
    MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
};

mod receipts;
pub use receipts::{ExactReceiptRecord, ReceiptAppendRequest};
#[cfg(feature = "std")]
pub use receipts::{ExactSecurityReceiptSink, SecurityReceiptSink};

mod response;
#[cfg(feature = "std")]
pub use response::ResponseStore;
pub use response::{
    ResponseCasRequest, ResponseEffectCasRequest, ResponseEffectKey, ResponseEffectRecord,
    ResponsePlanKey, ResponsePlanRecord, ResponseReceiptCursor, ResponseReceiptCursorCasRequest,
    ResponseScheduledMutationCasRequest,
};

mod scheduler;
#[cfg(feature = "std")]
pub use scheduler::{ResponseSchedulerStore, SchedulerHealthPort};
pub use scheduler::{
    ScheduledWork, SchedulerClaimRequest, SchedulerHealthAckRequest, SchedulerHealthPageRequest,
    SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest, SchedulerRetryRequest,
    SchedulerRetryState, SchedulerWorkKey,
};

mod suspension;
#[cfg(feature = "std")]
pub use suspension::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    empty_capability_set_suspension_snapshot, predict_capability_set_suspension_apply,
    predict_capability_set_suspension_remove, response_affected_set_hash,
    validate_capability_set_suspension_snapshot, validate_capability_suspension_decision,
    CapabilitySetSuspensionStore,
};
pub use suspension::{
    CapabilitySetSuspensionApplyRequest, CapabilitySetSuspensionCommand,
    CapabilitySetSuspensionContribution, CapabilitySetSuspensionContributions,
    CapabilitySetSuspensionKey, CapabilitySetSuspensionMatch, CapabilitySetSuspensionMatches,
    CapabilitySetSuspensionRemoveRequest, CapabilitySetSuspensionSnapshot,
    CapabilitySetSuspensionSpec, CapabilitySuspensionDecision, CapabilitySuspensionQuery,
    CAPABILITY_SET_SUSPENSION_INSTALLED_CONTRIBUTION_DOMAIN,
    CAPABILITY_SET_SUSPENSION_VERSION_DOMAIN,
};

mod throttle;
#[cfg(feature = "std")]
pub use egress::{
    egress_snapshot_version_hash, empty_egress_restriction_snapshot, predict_egress_apply,
    predict_egress_removal, validate_egress_restriction_snapshot,
};
#[cfg(feature = "std")]
pub use issuance::{
    empty_issuance_freeze_snapshot, issuance_freeze_installed_version_hash,
    issuance_freeze_version_hash, predict_issuance_freeze_apply, predict_issuance_freeze_remove,
    validate_issuance_freeze_admission_decision, validate_issuance_freeze_contribution,
    validate_issuance_freeze_snapshot,
};
#[cfg(feature = "std")]
pub use throttle::{
    empty_session_throttle_snapshot, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, session_throttle_window_identity,
    validate_session_throttle_snapshot, SessionThrottleStore,
};
pub use throttle::{
    SessionThrottleApplyRequest, SessionThrottleCommand, SessionThrottleConsumeRequest,
    SessionThrottleContribution, SessionThrottleContributions, SessionThrottleDecision,
    SessionThrottleKey, SessionThrottleLimits, SessionThrottleRemoveRequest,
    SessionThrottleSnapshot, SessionThrottleWindowIdentity, SessionThrottleWindowUsage,
    SessionThrottleWindowUsages, SESSION_THROTTLE_INSTALLED_CONTRIBUTION_DOMAIN,
    SESSION_THROTTLE_MAX_INVOCATIONS, SESSION_THROTTLE_MAX_WINDOW_MS,
    SESSION_THROTTLE_VERSION_DOMAIN, SESSION_THROTTLE_WINDOW_DOMAIN,
};
