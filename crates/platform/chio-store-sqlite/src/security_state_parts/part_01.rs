use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::encrypted_blob::SqliteEncryptedBlobStore;
use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::security::{
    validate_response_snapshot_lifecycle, ActiveDefenseReceiptBody,
};
use chio_core::SignedSecurityEvent;
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, declassification_retain_until_unix_ms,
    declassification_retry_deadline_unix_ms, derive_declassification_event_id,
    derive_declassification_transition_id, predict_containment_overlay_apply,
    predict_containment_overlay_remove, predict_session_throttle_apply,
    predict_session_throttle_remove, session_throttle_installed_version_hash,
    session_throttle_version_hash, session_throttle_window_identity,
    validate_attested_finding_batch_body, validate_containment_overlay_snapshot,
    validate_session_throttle_snapshot, ActionId, AdvisorySecurityEvent, AttestedFindingBatchBody,
    AttestedFindingBatchKey, AttestedFindingBatchPublication,
    AttestedFindingBatchStore, AttestedFindingResponseAdmissionState,
    AttestedFindingResponseCompletionOutcome, AttestedFindingResponseCompletionState,
    AttestedFindingResponseOutboxHealth,
    AttestedFindingResponseOutboxKey, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponseOutboxStore, AttestedFindingResponseOutboxTransition,
    AttestedFindingResponsePlanBody, AttestedFindingResponsePlanPublication,
    AttestedFindingResponsePlanningState, CanonicalBody, CapabilitySetSuspensionStore,
    CommittedEgressFence, AutomaticResponseDispatchFenceOutcome,
    AutomaticResponseDispatchFenceRecord, AutomaticResponseDispatchFenceRequest,
    ContainmentOverlayCommand, ContainmentOverlayStore, CorrelationCasRequest,
    CorrelationDeleteRequest, CorrelationEventAdmission, CorrelationEventAdmissionRequest,
    CorrelationEventIndexRequest, CorrelationIngressStore, CorrelationOutcomeCommitRequest,
    CorrelationOutcomeKey, CorrelationOutcomePublication, CorrelationOutcomeStatus,
    CorrelationPartial,
    CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, DeclassificationCompactionCandidate, DeclassificationCompactionQuery,
    DeclassificationCompactionRequest, DeclassificationConsume,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePendingQuery,
    DeclassificationEvidencePhase, DeclassificationEvidenceQuery, DeclassificationEvidenceRecord,
    DeclassificationEvidenceRetryRequest, DeclassificationEvidenceTombstone,
    DeclassificationOutcomeEvidenceCommit, DeclassificationTransitionBinding,
    DeclassificationUseQuery, DeclassificationUseRecord, DeclassificationUseState, DestinationId,
    Digest32, EffectExecutionStatus, EffectId, EffectOperation, EffectRequest, EffectResult,
    EffectResultQuery, EgressDeniedDestinations, EgressDestinationQuery, EgressDestinationSet,
    EgressFence, EgressFenceCommit, EgressFenceRequest, EgressRestrictionApplyRequest,
    EgressRestrictionCommand, EgressRestrictionContribution, EgressRestrictionContributions,
    EgressRestrictionDecision, EgressRestrictionEffectIds, EgressRestrictionRemoveRequest,
    EgressRestrictionSessionKey, EgressRestrictionSnapshot, EgressRestrictionStore, ErrorCode,
    EventAppend, EventId, EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateSnapshot,
    FlowStateStore, GrantId, IsolationEpochEvidenceVerifierPort, IsolationEpochTransition,
    IssuanceFreezeStore, LeaseOwnerId, LineageFence, LineageFenceRelease, LineageFenceRenewal,
    LineageFenceRequest, LineageFenceStore, LineageFenceTakeover, OpaqueReceiptRef,
    OverlayApplyRequest, OverlayContribution, OverlayContributions, OverlayRemoveRequest,
    OverlaySnapshot, PortError, PortResult, ProducerId, ProducerTrustClass, ReceiptAppendRequest,
    PreparedActiveResponseDispatchBinding, RecordId, ResponseCasRequest,
    ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode,
    ResponseDispatchCommitOutcome, ResponseDispatchCommitRequest, ResponseDispatchKey,
    ResponseDispatchLease,
    ResponseDispatchLoadOutcome, ResponseDispatchRecord, ResponseDispatchRecoveryOutcome,
    ResponseDispatchRecoveryRequest, ResponseDispatchStore, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord,
    ResponseReceiptCursor, ResponseReceiptCursorCasRequest, ResponseScheduledMutationCasRequest,
    ResponseSchedulerStore, ResponseStore, RuleId, ScheduledWork, SchedulerClaimRequest,
    SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest,
    SchedulerLeaseRenewRequest, SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey,
    SecurityEventStore, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleConsumeRequest, SessionThrottleContribution, SessionThrottleContributions,
    SessionThrottleDecision, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleRemoveRequest, SessionThrottleSnapshot, SessionThrottleStore,
    SessionThrottleWindowUsage, SessionThrottleWindowUsages, TenantId, TenantScopedId,
    UnverifiedEventBatch, UnverifiedSecurityEvent, VerifiedEventBatch,
    VerifiedIsolationEvidence, VerifiedSecurityEvent,
    ATTESTED_FINDING_RESPONSE_PLAN_SCHEMA_VERSION, LINEAGE_FENCE_RENEWAL_MARGIN_MS,
    MAX_ATTESTED_FINDING_RESPONSE_OUTBOX_SCAN, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    InformationLabel, ResponseApprovalRequirement, ResponseEffectKind, ResponseMutationRecord,
    ResponseSnapshot, ResponseState, ResponseTarget, ResponseTransitionCause,
    RESPONSE_STATE_SCHEMA_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

const SECURITY_STATE_STORE_SCHEMA_KEY: &str = "security_state";
const SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const SECURITY_STATE_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &[
    "security_transitions",
    "security_flow_contexts",
    "security_response_effects",
    "security_scheduler_retries",
    "chio_tool_receipts",
];
const MAX_EVENT_SCAN_RESULTS: u32 = 4_096;
const MAX_SCHEDULER_CLAIMS: u32 = 1_024;
const MAX_CLOCK_SKEW_MS: u64 = 5_000;
const EVENT_EVIDENCE_HASH_DOMAIN: &[u8] = b"chio.verified-security-event-evidence.v1\0";
const RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN: &[u8] =
    b"chio.verified-security-event-receipt-evidence.v1\0";
const DECLASSIFICATION_READINESS_CURSOR: &str = "declassification-evidence-schema-v2";
const DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_lifecycle (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    readiness_cursor TEXT NOT NULL,
    reconciliation_active INTEGER NOT NULL DEFAULT 0
        CHECK (reconciliation_active IN (0, 1)),
    live_dispatch_sealed INTEGER NOT NULL DEFAULT 0
        CHECK (live_dispatch_sealed IN (0, 1)),
    compaction_active INTEGER NOT NULL DEFAULT 0
        CHECK (compaction_active IN (0, 1)),
    CHECK (reconciliation_active = 0 OR live_dispatch_sealed = 0)
)
"#;
const DECLASSIFICATION_USES_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_uses (
    grant_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    state TEXT NOT NULL CHECK (
        state IN (
            'consumed_pending_dispatch', 'released', 'dispatch_failed',
            'outcome_unknown'
        )
    ),
    consumed_at INTEGER NOT NULL,
    grant_expires_at INTEGER NOT NULL,
    retain_until INTEGER NOT NULL,
    consumption_binding BLOB NOT NULL CHECK (length(consumption_binding) <= 4096),
    outcome_binding BLOB CHECK (length(outcome_binding) <= 4096),
    transition_id TEXT,
    CHECK (
        grant_expires_at > consumed_at AND retain_until >= grant_expires_at
    ),
    CHECK (
        (state = 'consumed_pending_dispatch' AND transition_id IS NULL
            AND outcome_binding IS NULL)
        OR
        (state IN ('released', 'dispatch_failed', 'outcome_unknown')
            AND transition_id IS NOT NULL AND outcome_binding IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, grant_id)
)
"#;
const DECLASSIFICATION_IDENTITY_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_evidence_identity (
    evidence_id TEXT NOT NULL,
    transition_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, evidence_id),
    UNIQUE (tenant_id, transition_id)
)
"#;
const DECLASSIFICATION_OUTBOX_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_receipt_outbox (
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    phase_ordinal INTEGER NOT NULL CHECK (phase_ordinal IN (0, 1)),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    state TEXT NOT NULL CHECK (
        state IN (
            'consumed_pending_dispatch', 'released', 'dispatch_failed',
            'outcome_unknown'
        )
    ),
    transition_binding BLOB NOT NULL CHECK (length(transition_binding) <= 4096),
    evidence_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    canonical_body BLOB NOT NULL CHECK (length(canonical_body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    transition_id TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    predecessor_evidence_id TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    acknowledged_at INTEGER,
    durable_sink_record_hash BLOB CHECK (length(durable_sink_record_hash) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    last_error_code TEXT,
    CHECK (
        (acknowledged = 0 AND acknowledged_at IS NULL
            AND durable_sink_record_hash IS NULL)
        OR (acknowledged = 1 AND acknowledged_at IS NOT NULL
            AND durable_sink_record_hash IS NOT NULL)
    ),
    CHECK (
        (phase = 'consumption' AND phase_ordinal = 0
            AND state = 'consumed_pending_dispatch'
            AND predecessor_evidence_id IS NULL)
        OR
        (phase = 'outcome' AND phase_ordinal = 1
            AND state IN ('released', 'dispatch_failed', 'outcome_unknown')
            AND predecessor_evidence_id IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, grant_id, phase_ordinal),
    FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES security_declassification_evidence_identity (
            tenant_id, evidence_id
        ),
    FOREIGN KEY (tenant_id, grant_id)
        REFERENCES security_declassification_uses (tenant_id, grant_id)
)
"#;
const DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_tombstones (
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN ('released', 'dispatch_failed')
    ),
    consumption_evidence_id TEXT NOT NULL,
    consumption_body_hash BLOB NOT NULL CHECK (length(consumption_body_hash) = 32),
    consumption_transition_id TEXT NOT NULL,
    consumption_occurred_at INTEGER NOT NULL,
    consumption_sink_record_hash BLOB NOT NULL
        CHECK (length(consumption_sink_record_hash) = 32),
    outcome_evidence_id TEXT NOT NULL,
    outcome_body_hash BLOB NOT NULL CHECK (length(outcome_body_hash) = 32),
    outcome_transition_id TEXT NOT NULL,
    outcome_occurred_at INTEGER NOT NULL,
    outcome_sink_record_hash BLOB NOT NULL
        CHECK (length(outcome_sink_record_hash) = 32),
    policy_hash BLOB NOT NULL CHECK (length(policy_hash) = 32),
    compacted_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, grant_id),
    FOREIGN KEY (tenant_id, consumption_evidence_id)
        REFERENCES security_declassification_evidence_identity (
            tenant_id, evidence_id
        ),
    FOREIGN KEY (tenant_id, outcome_evidence_id)
        REFERENCES security_declassification_evidence_identity (
            tenant_id, evidence_id
        )
)
"#;
const DECLASSIFICATION_IDENTITY_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_evidence_identity (
    evidence_id TEXT NOT NULL PRIMARY KEY,
    transition_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32)
)
"#;
const DECLASSIFICATION_OUTBOX_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_receipt_outbox (
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    phase_ordinal INTEGER NOT NULL CHECK (phase_ordinal IN (0, 1)),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    state TEXT NOT NULL CHECK (
        state IN (
            'consumed_pending_dispatch', 'released', 'dispatch_failed',
            'outcome_unknown'
        )
    ),
    transition_binding BLOB NOT NULL CHECK (length(transition_binding) <= 4096),
    evidence_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    canonical_body BLOB NOT NULL CHECK (length(canonical_body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    transition_id TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    predecessor_evidence_id TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    acknowledged_at INTEGER,
    durable_sink_record_hash BLOB CHECK (length(durable_sink_record_hash) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    last_error_code TEXT,
    CHECK (
        (acknowledged = 0 AND acknowledged_at IS NULL
            AND durable_sink_record_hash IS NULL)
        OR (acknowledged = 1 AND acknowledged_at IS NOT NULL
            AND durable_sink_record_hash IS NOT NULL)
    ),
    CHECK (
        (phase = 'consumption' AND phase_ordinal = 0
            AND state = 'consumed_pending_dispatch'
            AND predecessor_evidence_id IS NULL)
        OR
        (phase = 'outcome' AND phase_ordinal = 1
            AND state IN ('released', 'dispatch_failed', 'outcome_unknown')
            AND predecessor_evidence_id IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, grant_id, phase_ordinal),
    FOREIGN KEY (evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id),
    FOREIGN KEY (tenant_id, grant_id)
        REFERENCES security_declassification_uses (tenant_id, grant_id)
)
"#;
const DECLASSIFICATION_TOMBSTONE_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_tombstones (
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN ('released', 'dispatch_failed')
    ),
    consumption_evidence_id TEXT NOT NULL,
    consumption_body_hash BLOB NOT NULL CHECK (length(consumption_body_hash) = 32),
    consumption_transition_id TEXT NOT NULL,
    consumption_occurred_at INTEGER NOT NULL,
    consumption_sink_record_hash BLOB NOT NULL
        CHECK (length(consumption_sink_record_hash) = 32),
    outcome_evidence_id TEXT NOT NULL,
    outcome_body_hash BLOB NOT NULL CHECK (length(outcome_body_hash) = 32),
    outcome_transition_id TEXT NOT NULL,
    outcome_occurred_at INTEGER NOT NULL,
    outcome_sink_record_hash BLOB NOT NULL
        CHECK (length(outcome_sink_record_hash) = 32),
    policy_hash BLOB NOT NULL CHECK (length(policy_hash) = 32),
    compacted_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, grant_id),
    FOREIGN KEY (consumption_evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id),
    FOREIGN KEY (outcome_evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id)
)
"#;
const ATTESTED_FINDING_BATCH_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_batches (
    batch_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, batch_id)
)
"#;

const CORRELATION_INGRESS_CANONICAL_DDL: &str = r#"
CREATE TABLE security_correlation_ingress (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    producer_id TEXT NOT NULL,
    event_time INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    source_evidence BLOB NOT NULL CHECK (length(source_evidence) <= 1048576),
    evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES security_verified_events (tenant_id, event_id)
)
"#;
const CORRELATION_INGRESS_PENDING_INDEX_DDL: &str = r#"
CREATE INDEX security_correlation_ingress_pending
ON security_correlation_ingress (acknowledged, event_time, sequence)
"#;
const CORRELATION_INGRESS_LEGACY_PENDING_INDEX_DDL: &str = r#"
CREATE INDEX security_correlation_ingress_pending
ON security_correlation_ingress (acknowledged, sequence)
"#;
const CORRELATION_INGRESS_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_ingress_immutable
BEFORE UPDATE ON security_correlation_ingress
WHEN OLD.sequence != NEW.sequence
    OR OLD.tenant_id != NEW.tenant_id
    OR OLD.event_id != NEW.event_id
    OR OLD.producer_id != NEW.producer_id
    OR OLD.event_time != NEW.event_time
    OR OLD.received_at != NEW.received_at
    OR OLD.body != NEW.body
    OR OLD.body_hash != NEW.body_hash
    OR OLD.source_evidence != NEW.source_evidence
    OR OLD.evidence_hash != NEW.evidence_hash
    OR OLD.acknowledged = 1
    OR NEW.acknowledged != 1
BEGIN
    SELECT RAISE(ABORT, 'correlation ingress mutation is rejected');
END
"#;
const CORRELATION_INGRESS_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_ingress_delete_rejected
BEFORE DELETE ON security_correlation_ingress
BEGIN
    SELECT RAISE(ABORT, 'correlation ingress deletion is rejected');
END
"#;
const CORRELATION_OUTCOMES_CANONICAL_DDL: &str = r#"
CREATE TABLE security_correlation_outcomes (
    tenant_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'accepted', 'advisory_only', 'duplicate', 'irrelevant', 'matched',
        'suppressed', 'too_late'
    )),
    watermark INTEGER NOT NULL CHECK (watermark >= 0),
    rule_version_hash BLOB NOT NULL CHECK (length(rule_version_hash) = 32),
    event_body_hash BLOB NOT NULL CHECK (length(event_body_hash) = 32),
    event_evidence_hash BLOB NOT NULL CHECK (length(event_evidence_hash) = 32),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, rule_id, event_id),
    FOREIGN KEY (tenant_id, event_id)
        REFERENCES security_verified_events (tenant_id, event_id)
)
"#;
const CORRELATION_OUTCOMES_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_outcomes_immutable
BEFORE UPDATE ON security_correlation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'correlation outcome mutation is rejected');
END
"#;
const CORRELATION_OUTCOMES_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_correlation_outcomes_delete_rejected
BEFORE DELETE ON security_correlation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'correlation outcome deletion is rejected');
END
"#;
const ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_batch_items (
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (
        length(finding_hash) = 32 AND finding_hash != zeroblob(32)
    ),
    action_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, batch_id, ordinal),
    UNIQUE (tenant_id, evidence_id),
    UNIQUE (tenant_id, finding_id),
    UNIQUE (tenant_id, action_id),
    UNIQUE (tenant_id, reservation_id),
    FOREIGN KEY (tenant_id, batch_id)
        REFERENCES security_attested_finding_batches (tenant_id, batch_id)
)
"#;
const ATTESTED_FINDING_BATCH_LEGACY_DDL: &str = r#"
CREATE TABLE security_attested_finding_batches (
    batch_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
    body BLOB NOT NULL CHECK (length(body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (batch_id)
)
"#;
const ATTESTED_FINDING_BATCH_ITEM_LEGACY_DDL: &str = r#"
CREATE TABLE security_attested_finding_batch_items (
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (length(finding_hash) = 32),
    action_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    PRIMARY KEY (batch_id, ordinal),
    UNIQUE (tenant_id, evidence_id),
    UNIQUE (tenant_id, finding_id),
    UNIQUE (tenant_id, action_id),
    UNIQUE (tenant_id, reservation_id),
    FOREIGN KEY (batch_id)
        REFERENCES security_attested_finding_batches (batch_id)
)
"#;

const ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_response_outbox (
    tenant_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
    evidence_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    finding_hash BLOB NOT NULL CHECK (
        length(finding_hash) = 32 AND finding_hash != zeroblob(32)
    ),
    action_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    planning_state TEXT NOT NULL CHECK (planning_state IN ('pending', 'planned', 'failed')),
    admission_state TEXT NOT NULL CHECK (
        admission_state IN ('pending', 'prepared', 'rejected', 'expired')
    ),
    completion_state TEXT NOT NULL CHECK (
        completion_state IN ('not_started', 'pending', 'outcome_unknown_after_dispatch', 'completed')
    ),
    execution_dispatch_id TEXT CHECK (
        execution_dispatch_id IS NULL OR trim(execution_dispatch_id, '0') != ''
    ),
    prepared_dispatch_binding BLOB CHECK (
        prepared_dispatch_binding IS NULL
        OR length(prepared_dispatch_binding) <= 1048576
    ),
    prepared_dispatch_binding_hash BLOB CHECK (
        prepared_dispatch_binding_hash IS NULL
        OR (length(prepared_dispatch_binding_hash) = 32
            AND prepared_dispatch_binding_hash != zeroblob(32))
    ),
    completion_outcome TEXT CHECK (
        completion_outcome IS NULL OR completion_outcome IN (
            'activated', 'failed_before_effect', 'rolled_back_after_partial'
        )
    ),
    completion_evidence_id TEXT CHECK (
        completion_evidence_id IS NULL OR trim(completion_evidence_id, '0') != ''
    ),
    completion_evidence_body_hash BLOB CHECK (
        completion_evidence_body_hash IS NULL
        OR (length(completion_evidence_body_hash) = 32
            AND completion_evidence_body_hash != zeroblob(32))
    ),
    plan_body BLOB CHECK (plan_body IS NULL OR length(plan_body) <= 1048576),
    plan_body_hash BLOB CHECK (
        plan_body_hash IS NULL
        OR (length(plan_body_hash) = 32 AND plan_body_hash != zeroblob(32))
    ),
    admission_artifact_ref TEXT CHECK (
        admission_artifact_ref IS NULL OR trim(admission_artifact_ref, '0') != ''
    ),
    admission_artifact_digest BLOB CHECK (
        admission_artifact_digest IS NULL
        OR (length(admission_artifact_digest) = 32
            AND admission_artifact_digest != zeroblob(32))
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 1000000),
    next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    last_error_code TEXT,
    CHECK (
        (planning_state = 'pending' AND plan_body IS NULL AND plan_body_hash IS NULL
            AND admission_artifact_ref IS NULL AND admission_artifact_digest IS NULL)
        OR (planning_state = 'planned' AND plan_body IS NOT NULL AND plan_body_hash IS NOT NULL
            AND admission_artifact_ref IS NOT NULL)
        OR (planning_state = 'failed' AND plan_body IS NULL AND plan_body_hash IS NULL
            AND admission_artifact_ref IS NULL AND admission_artifact_digest IS NULL)
    ),
    CHECK (
        (admission_state = 'pending' AND execution_dispatch_id IS NULL
            AND prepared_dispatch_binding IS NULL AND completion_state = 'not_started')
        OR (admission_state = 'prepared' AND execution_dispatch_id IS NOT NULL
            AND prepared_dispatch_binding IS NOT NULL AND admission_artifact_digest IS NOT NULL
            AND completion_state IN ('pending', 'outcome_unknown_after_dispatch', 'completed'))
        OR (admission_state IN ('rejected', 'expired') AND execution_dispatch_id IS NULL
            AND prepared_dispatch_binding IS NULL AND completion_state = 'not_started')
        OR (admission_state = 'expired' AND execution_dispatch_id IS NOT NULL
            AND prepared_dispatch_binding IS NOT NULL AND admission_artifact_digest IS NOT NULL
            AND completion_state = 'not_started')
    ),
    CHECK (
        (prepared_dispatch_binding IS NULL AND prepared_dispatch_binding_hash IS NULL)
        OR (prepared_dispatch_binding IS NOT NULL
            AND prepared_dispatch_binding_hash IS NOT NULL)
    ),
    CHECK (planning_state = 'planned' OR admission_state != 'prepared'),
    CHECK (
        (completion_state = 'completed' AND completion_outcome IS NOT NULL
            AND completion_evidence_id IS NOT NULL
            AND completion_evidence_body_hash IS NOT NULL)
        OR (completion_state != 'completed' AND completion_outcome IS NULL
            AND completion_evidence_id IS NULL
            AND completion_evidence_body_hash IS NULL)
    ),
    PRIMARY KEY (tenant_id, action_id),
    UNIQUE (tenant_id, batch_id, ordinal),
    UNIQUE (tenant_id, reservation_id),
    UNIQUE (tenant_id, execution_dispatch_id),
    FOREIGN KEY (tenant_id, batch_id, ordinal)
        REFERENCES security_attested_finding_batch_items (tenant_id, batch_id, ordinal)
)
"#;
const ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL: &str = r#"
CREATE INDEX security_attested_finding_response_outbox_due
ON security_attested_finding_response_outbox (
    planning_state, admission_state, completion_state,
    next_attempt_at, attempts, tenant_id, action_id
)
"#;
const ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_attested_finding_response_outbox_immutable
BEFORE UPDATE ON security_attested_finding_response_outbox
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.batch_id IS NOT OLD.batch_id
  OR NEW.ordinal IS NOT OLD.ordinal
  OR NEW.evidence_id IS NOT OLD.evidence_id
  OR NEW.finding_id IS NOT OLD.finding_id
  OR NEW.finding_hash IS NOT OLD.finding_hash
  OR NEW.action_id IS NOT OLD.action_id
  OR NEW.reservation_id IS NOT OLD.reservation_id
  OR (OLD.plan_body IS NOT NULL
      AND NEW.plan_body IS NOT OLD.plan_body)
  OR (OLD.plan_body_hash IS NOT NULL
      AND NEW.plan_body_hash IS NOT OLD.plan_body_hash)
  OR (OLD.admission_artifact_ref IS NOT NULL
      AND NEW.admission_artifact_ref IS NOT OLD.admission_artifact_ref)
  OR (OLD.admission_artifact_digest IS NOT NULL
      AND NEW.admission_artifact_digest IS NOT OLD.admission_artifact_digest)
  OR (OLD.execution_dispatch_id IS NOT NULL
      AND NEW.execution_dispatch_id IS NOT OLD.execution_dispatch_id)
  OR (OLD.prepared_dispatch_binding IS NOT NULL
      AND NEW.prepared_dispatch_binding IS NOT OLD.prepared_dispatch_binding)
  OR (OLD.prepared_dispatch_binding_hash IS NOT NULL
      AND NEW.prepared_dispatch_binding_hash IS NOT OLD.prepared_dispatch_binding_hash)
  OR (OLD.completion_outcome IS NOT NULL
      AND NEW.completion_outcome IS NOT OLD.completion_outcome)
  OR (OLD.completion_evidence_id IS NOT NULL
      AND NEW.completion_evidence_id IS NOT OLD.completion_evidence_id)
  OR (OLD.completion_evidence_body_hash IS NOT NULL
      AND NEW.completion_evidence_body_hash IS NOT OLD.completion_evidence_body_hash)
  OR NEW.attempts < OLD.attempts
  OR (OLD.planning_state IN ('planned', 'failed')
      AND NEW.planning_state IS NOT OLD.planning_state)
  OR (OLD.admission_state = 'prepared'
      AND NEW.admission_state NOT IN ('prepared', 'expired'))
  OR (OLD.admission_state IN ('rejected', 'expired')
      AND NEW.admission_state IS NOT OLD.admission_state)
  OR (OLD.completion_state = 'pending'
      AND NEW.completion_state NOT IN ('pending', 'outcome_unknown_after_dispatch', 'completed')
      AND NOT (NEW.admission_state = 'expired' AND NEW.completion_state = 'not_started'))
  OR (OLD.completion_state = 'outcome_unknown_after_dispatch'
      AND NEW.completion_state NOT IN ('outcome_unknown_after_dispatch', 'completed')
      AND NOT (NEW.admission_state = 'expired' AND NEW.completion_state = 'not_started'))
  OR (OLD.completion_state = 'completed'
      AND NEW.completion_state != 'completed')
BEGIN
    SELECT RAISE(ABORT, 'attested finding response outbox state is immutable or monotonic');
END
"#;
const ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_attested_finding_response_outbox_delete_rejected
BEFORE DELETE ON security_attested_finding_response_outbox
BEGIN
    SELECT RAISE(ABORT, 'attested finding response outbox deletion is rejected');
END
"#;

/// Trusted time source for security-state lease and recovery decisions.
///
/// Production callers should use [`SqliteSecurityStateStore::open`], which is
/// pinned to the system clock. The explicit constructor exists for runtimes
/// that already own an authenticated clock and for deterministic tests. This
/// boundary must never be implemented from request-controlled timestamps.
pub trait SecurityStateClock: Send + Sync {
    fn now_unix_ms(&self) -> PortResult<u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemSecurityStateClock;

impl SecurityStateClock for SystemSecurityStateClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PortError::unavailable())?;
        u64::try_from(duration.as_millis()).map_err(|_| PortError::unavailable())
    }
}

pub struct SqliteSecurityStateStore {
    connection: Mutex<Connection>,
    isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
    clock: Arc<dyn SecurityStateClock>,
    #[cfg(unix)]
    database_path: PathBuf,
    #[cfg(unix)]
    database_identity: SecurityStateDatabaseFileIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityStateDatabaseFileIdentity {
    device: u64,
    inode: u64,
}

/// Store-bound proof that the caller retains the exclusive lifecycle-owner
/// lease for this exact security-state database file.
#[cfg(unix)]
#[derive(Debug)]
pub struct SecurityStateLifecycleOwnerProof {
    locked_database_file: File,
    database_identity: SecurityStateDatabaseFileIdentity,
    #[cfg(target_os = "macos")]
    locked_lifecycle_file: File,
    #[cfg(target_os = "macos")]
    lifecycle_lock_identity: SecurityStateDatabaseFileIdentity,
}

/// Exact durable contribution counts that must reach zero before the
/// production active-defense services can be unpublished.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActiveDefenseOverlayInventory {
    pub containment_contributions: u64,
    pub session_throttle_contributions: u64,
    pub capability_suspension_contributions: u64,
    pub issuance_freeze_contributions: u64,
    pub egress_restriction_contributions: u64,
}

impl ActiveDefenseOverlayInventory {
    #[must_use]
    pub const fn has_active_contributions(self) -> bool {
        self.containment_contributions != 0
            || self.session_throttle_contributions != 0
            || self.capability_suspension_contributions != 0
            || self.issuance_freeze_contributions != 0
            || self.egress_restriction_contributions != 0
    }
}

struct DenyIsolationEpochEvidence;

impl IsolationEpochEvidenceVerifierPort for DenyIsolationEpochEvidence {
    fn verify(&self, _: &IsolationEpochTransition) -> PortResult<VerifiedIsolationEvidence> {
        Err(PortError::invalid_data())
    }
}

impl SqliteSecurityStateStore {
    pub fn open(path: impl AsRef<Path>) -> PortResult<Self> {
        Self::open_with_dependencies(
            path,
            Arc::new(DenyIsolationEpochEvidence),
            Arc::new(SystemSecurityStateClock),
        )
    }

    pub fn open_with_isolation_epoch_verifier(
        path: impl AsRef<Path>,
        isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
    ) -> PortResult<Self> {
        Self::open_with_dependencies(
            path,
            isolation_epoch_verifier,
            Arc::new(SystemSecurityStateClock),
        )
    }

    pub fn open_with_trusted_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn SecurityStateClock>,
    ) -> PortResult<Self> {
        Self::open_with_dependencies(path, Arc::new(DenyIsolationEpochEvidence), clock)
    }

    fn open_with_dependencies(
        path: impl AsRef<Path>,
        isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
        clock: Arc<dyn SecurityStateClock>,
    ) -> PortResult<Self> {
        let path = path.as_ref();
        let path_text = path.as_os_str().to_string_lossy();
        if path.as_os_str().is_empty()
            || path == Path::new(":memory:")
            || path_text.to_ascii_lowercase().starts_with("file:")
            || path_text.contains('?')
            || path_text.contains('#')
        {
            return Err(PortError::invalid_data());
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| PortError::unavailable())?;
            }
        }
        let connection = Connection::open(path).map_err(sqlite_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_error)?;
        migrate(&connection)?;
        SqliteEncryptedBlobStore::open(path).map_err(|_| PortError::unavailable())?;
        #[cfg(unix)]
        let database_path = absolute_database_path(path)?;
        #[cfg(unix)]
        let database_identity = security_state_database_path_identity(&database_path)?;
        Ok(Self {
            connection: Mutex::new(connection),
            isolation_epoch_verifier,
            clock,
            #[cfg(unix)]
            database_path,
            #[cfg(unix)]
            database_identity,
        })
    }

    /// Bind a retained, exclusively locked descriptor to this store's exact
    /// opened main-database identity. The returned proof retains the lock.
    #[cfg(unix)]
    pub fn security_state_lifecycle_owner_proof(
        &self,
        locked_database_file: File,
        #[cfg(target_os = "macos")] locked_lifecycle_file: File,
    ) -> PortResult<SecurityStateLifecycleOwnerProof> {
        validate_security_state_database_binding(
            &self.database_path,
            self.database_identity,
            &locked_database_file,
        )?;
        #[cfg(not(target_os = "macos"))]
        rustix::fs::flock(
            &locked_database_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock_path = security_state_lifecycle_lock_path(&self.database_path)?;
        #[cfg(target_os = "macos")]
        let lifecycle_lock_identity =
            security_state_database_path_identity(&lifecycle_lock_path)?;
        #[cfg(target_os = "macos")]
        validate_security_state_database_binding(
            &lifecycle_lock_path,
            lifecycle_lock_identity,
            &locked_lifecycle_file,
        )?;
        #[cfg(target_os = "macos")]
        rustix::fs::flock(
            &locked_lifecycle_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        let proof = SecurityStateLifecycleOwnerProof {
            locked_database_file,
            database_identity: self.database_identity,
            #[cfg(target_os = "macos")]
            locked_lifecycle_file,
            #[cfg(target_os = "macos")]
            lifecycle_lock_identity,
        };
        self.validate_security_state_lifecycle_owner_proof(&proof)?;
        Ok(proof)
    }

    #[cfg(unix)]
    fn validate_security_state_lifecycle_owner_proof(
        &self,
        proof: &SecurityStateLifecycleOwnerProof,
    ) -> PortResult<()> {
        if proof.database_identity != self.database_identity {
            return Err(PortError::conflict());
        }
        #[cfg(not(target_os = "macos"))]
        rustix::fs::flock(
            &proof.locked_database_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| PortError::conflict())?;
        validate_security_state_database_binding(
            &self.database_path,
            self.database_identity,
            &proof.locked_database_file,
        )?;
        #[cfg(target_os = "macos")]
        {
            let lifecycle_lock_path = security_state_lifecycle_lock_path(&self.database_path)?;
            let current_lock_identity =
                security_state_database_path_identity(&lifecycle_lock_path)?;
            if proof.lifecycle_lock_identity != current_lock_identity {
                return Err(PortError::conflict());
            }
            rustix::fs::flock(
                &proof.locked_lifecycle_file,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .map_err(|_| PortError::conflict())?;
            validate_security_state_database_binding(
                &lifecycle_lock_path,
                proof.lifecycle_lock_identity,
                &proof.locked_lifecycle_file,
            )?;
        }
        Ok(())
    }

    /// Reset process-owned declassification lifecycle flags only while the
    /// caller retains a store-bound exclusive lifecycle-owner proof.
    #[cfg(unix)]
    pub fn reset_declassification_lifecycle_for_owner_takeover(
        &self,
        proof: &SecurityStateLifecycleOwnerProof,
    ) -> PortResult<()> {
        self.validate_security_state_lifecycle_owner_proof(proof)?;

        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_declassification_lifecycle
                SET reconciliation_active = 0,
                    live_dispatch_sealed = 0,
                    compaction_active = 0
                WHERE singleton = 1
                "#,
                [],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::integrity_failure());
        }
        self.validate_security_state_lifecycle_owner_proof(proof)?;
        transaction.commit().map_err(sqlite_error)?;
        self.validate_security_state_lifecycle_owner_proof(proof)
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| PortError::unavailable())
    }

    fn trusted_now_unix_ms(&self) -> PortResult<u64> {
        self.clock.now_unix_ms()
    }

    /// Validate every durable restrictive overlay family and return one
    /// point-in-time contribution inventory. Expired rows remain active for
    /// lifecycle purposes until the durable scheduler removes them.
    pub fn active_defense_overlay_inventory(&self) -> PortResult<ActiveDefenseOverlayInventory> {
        <Self as ContainmentOverlayStore>::ensure_containment_overlays_ready(self)?;
        <Self as SessionThrottleStore>::ensure_session_throttles_ready(self)?;
        <Self as CapabilitySetSuspensionStore>::ensure_capability_set_suspensions_ready(self)?;
        <Self as IssuanceFreezeStore>::ensure_issuance_freezes_ready(self)?;
        <Self as EgressRestrictionStore>::ensure_egress_restrictions_ready(self)?;

        let connection = self.connection()?;
        let quick_check: String = connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if quick_check != "ok" {
            return Err(PortError::integrity_failure());
        }
        let mut foreign_key_check = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(sqlite_error)?;
        if foreign_key_check
            .query([])
            .map_err(sqlite_error)?
            .next()
            .map_err(sqlite_error)?
            .is_some()
        {
            return Err(PortError::integrity_failure());
        }
        drop(foreign_key_check);

        let counts: (i64, i64, i64, i64, i64) = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM security_effect_contributions),
                    (SELECT COUNT(*) FROM security_session_throttle_effects),
                    (SELECT COUNT(*) FROM security_capability_set_suspension_effects),
                    (SELECT COUNT(*) FROM security_issuance_freeze_effects),
                    (SELECT COUNT(*) FROM security_egress_restriction_effects)
                "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
        Ok(ActiveDefenseOverlayInventory {
            containment_contributions: from_i64(counts.0)?,
            session_throttle_contributions: from_i64(counts.1)?,
            capability_suspension_contributions: from_i64(counts.2)?,
            issuance_freeze_contributions: from_i64(counts.3)?,
            egress_restriction_contributions: from_i64(counts.4)?,
        })
    }
}

#[cfg(unix)]
fn absolute_database_path(path: &Path) -> PortResult<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|_| PortError::unavailable())
}

#[cfg(target_os = "macos")]
fn security_state_lifecycle_lock_path(path: &Path) -> PortResult<PathBuf> {
    let file_name = path.file_name().ok_or_else(PortError::invalid_data)?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lifecycle.lock");
    Ok(path.with_file_name(lock_name))
}

#[cfg(unix)]
fn security_state_database_path_identity(
    path: &Path,
) -> PortResult<SecurityStateDatabaseFileIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PortError::unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() != 1
    {
        return Err(PortError::invalid_data());
    }
    Ok(SecurityStateDatabaseFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn validate_security_state_database_binding(
    path: &Path,
    expected_identity: SecurityStateDatabaseFileIdentity,
    file: &File,
) -> PortResult<()> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| PortError::conflict())?;
    let file_metadata = file.metadata().map_err(|_| PortError::conflict())?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || path_metadata.dev() != expected_identity.device
        || path_metadata.ino() != expected_identity.inode
        || file_metadata.dev() != expected_identity.device
        || file_metadata.ino() != expected_identity.inode
    {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn prepare_declassification_schema_migration(connection: &Connection) -> PortResult<()> {
    let current_tables = [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ];
    let legacy_tables = [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_LEGACY_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_LEGACY_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_LEGACY_DDL,
        ),
    ];
    let mut present_tables = 0_usize;
    let mut current_exact_tables = 0_usize;
    let mut legacy_exact_tables = 0_usize;
    for ((table, current_sql), (legacy_table, legacy_sql)) in
        current_tables.iter().zip(legacy_tables.iter())
    {
        if table != legacy_table {
            return Err(PortError::integrity_failure());
        }
        let existing: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing_sql) = existing {
            present_tables = present_tables
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
            let normalized = normalize_sql(&existing_sql);
            if normalized == normalize_sql(current_sql) {
                current_exact_tables = current_exact_tables
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
            if normalized == normalize_sql(legacy_sql) {
                legacy_exact_tables = legacy_exact_tables
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
        }
    }
    if present_tables == 0 {
        return Ok(());
    }
    if current_exact_tables == current_tables.len() {
        return Ok(());
    }
    if legacy_exact_tables == legacy_tables.len() {
        return migrate_declassification_tenant_keys(connection);
    }
    for table in [
        "security_declassification_uses",
        "security_declassification_evidence_identity",
        "security_declassification_receipt_outbox",
        "security_declassification_tombstones",
    ] {
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if exists != 0 {
            let count_sql = format!("SELECT COUNT(*) FROM {table}");
            let count = connection
                .query_row(&count_sql, [], |row| row.get::<_, i64>(0))
                .map_err(|_| PortError::integrity_failure())?;
            if count != 0 {
                return Err(PortError::integrity_failure());
            }
        }
    }
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS security_declassification_use_immutable;
            DROP TRIGGER IF EXISTS security_declassification_use_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_outcome_predecessor_insert;
            DROP TRIGGER IF EXISTS security_declassification_evidence_use_binding_insert;
            DROP TRIGGER IF EXISTS security_declassification_outcome_ack_order;
            DROP TRIGGER IF EXISTS security_declassification_evidence_immutable;
            DROP TRIGGER IF EXISTS security_declassification_evidence_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_identity_immutable;
            DROP TRIGGER IF EXISTS security_declassification_identity_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_immutable;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_replay_rejected;
            DROP INDEX IF EXISTS security_declassification_receipt_pending;
            DROP TABLE IF EXISTS security_declassification_tombstones;
            DROP TABLE IF EXISTS security_declassification_receipt_outbox;
            DROP TABLE IF EXISTS security_declassification_evidence_identity;
            DROP TABLE IF EXISTS security_declassification_uses;
            DROP TABLE IF EXISTS security_declassification_lifecycle;
            "#,
        )
        .map_err(sqlite_error)
}

fn migrate_declassification_tenant_keys(connection: &Connection) -> PortResult<()> {
    validate_declassification_evidence_integrity(connection)?;
    const IDENTITY_STAGING: &str = "security_declassification_evidence_identity_tenant_migration";
    const OUTBOX_STAGING: &str = "security_declassification_receipt_outbox_tenant_migration";
    const TOMBSTONE_STAGING: &str = "security_declassification_tombstones_tenant_migration";
    let identity_staging_ddl = DECLASSIFICATION_IDENTITY_CANONICAL_DDL.replace(
        "security_declassification_evidence_identity",
        IDENTITY_STAGING,
    );
    let outbox_staging_ddl = DECLASSIFICATION_OUTBOX_CANONICAL_DDL
        .replace("security_declassification_receipt_outbox", OUTBOX_STAGING)
        .replace(
            "security_declassification_evidence_identity",
            IDENTITY_STAGING,
        );
    let tombstone_staging_ddl = DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL
        .replace("security_declassification_tombstones", TOMBSTONE_STAGING)
        .replace(
            "security_declassification_evidence_identity",
            IDENTITY_STAGING,
        );
    connection
        .execute_batch(&format!(
            "{identity_staging_ddl};\n{outbox_staging_ddl};\n{tombstone_staging_ddl};"
        ))
        .map_err(sqlite_error)?;
    connection
        .execute_batch(
            r#"
            INSERT INTO security_declassification_evidence_identity_tenant_migration (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            )
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM security_declassification_evidence_identity;

            INSERT INTO security_declassification_receipt_outbox_tenant_migration (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body,
                body_hash, transition_id, occurred_at, predecessor_evidence_id,
                acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                next_attempt_at, last_error_code
            )
            SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                   transition_binding, evidence_type, evidence_id, canonical_body,
                   body_hash, transition_id, occurred_at, predecessor_evidence_id,
                   acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                   next_attempt_at, last_error_code
            FROM security_declassification_receipt_outbox;

            INSERT INTO security_declassification_tombstones_tenant_migration (
                tenant_id, grant_id, request_hash, terminal_state,
                consumption_evidence_id, consumption_body_hash,
                consumption_transition_id, consumption_occurred_at,
                consumption_sink_record_hash, outcome_evidence_id,
                outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                outcome_sink_record_hash, policy_hash, compacted_at
            )
            SELECT tenant_id, grant_id, request_hash, terminal_state,
                   consumption_evidence_id, consumption_body_hash,
                   consumption_transition_id, consumption_occurred_at,
                   consumption_sink_record_hash, outcome_evidence_id,
                   outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                   outcome_sink_record_hash, policy_hash, compacted_at
            FROM security_declassification_tombstones;
            "#,
        )
        .map_err(sqlite_error)?;
    let staged_counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_evidence_identity_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_tombstones_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
    );
    for table in [OUTBOX_STAGING, TOMBSTONE_STAGING] {
        let mut statement = connection
            .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        if rows.next().map_err(sqlite_error)?.is_some() {
            return Err(PortError::integrity_failure());
        }
    }
    connection
        .execute_batch(
            r#"
            DROP TABLE security_declassification_tombstones;
            DROP TABLE security_declassification_receipt_outbox;
            DROP TABLE security_declassification_evidence_identity;
            "#,
        )
        .map_err(sqlite_error)?;
    connection
        .execute_batch(&format!(
            "{};\n{};\n{};",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ))
        .map_err(sqlite_error)?;
    connection
        .execute_batch(
            r#"
            INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            )
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM security_declassification_evidence_identity_tenant_migration;

            INSERT INTO security_declassification_receipt_outbox (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body,
                body_hash, transition_id, occurred_at, predecessor_evidence_id,
                acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                next_attempt_at, last_error_code
            )
            SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                   transition_binding, evidence_type, evidence_id, canonical_body,
                   body_hash, transition_id, occurred_at, predecessor_evidence_id,
                   acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                   next_attempt_at, last_error_code
            FROM security_declassification_receipt_outbox_tenant_migration;

            INSERT INTO security_declassification_tombstones (
                tenant_id, grant_id, request_hash, terminal_state,
                consumption_evidence_id, consumption_body_hash,
                consumption_transition_id, consumption_occurred_at,
                consumption_sink_record_hash, outcome_evidence_id,
                outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                outcome_sink_record_hash, policy_hash, compacted_at
            )
            SELECT tenant_id, grant_id, request_hash, terminal_state,
                   consumption_evidence_id, consumption_body_hash,
                   consumption_transition_id, consumption_occurred_at,
                   consumption_sink_record_hash, outcome_evidence_id,
                   outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                   outcome_sink_record_hash, policy_hash, compacted_at
            FROM security_declassification_tombstones_tenant_migration;
            "#,
        )
        .map_err(sqlite_error)?;
    let migrated_counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_evidence_identity",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_tombstones",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
    );
    if migrated_counts != staged_counts {
        return Err(PortError::integrity_failure());
    }
    for table in [
        "security_declassification_receipt_outbox",
        "security_declassification_tombstones",
    ] {
        let mut statement = connection
            .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        if rows.next().map_err(sqlite_error)?.is_some() {
            return Err(PortError::integrity_failure());
        }
    }
    for (table, expected_sql) in [
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(PortError::integrity_failure());
        }
    }
    validate_declassification_evidence_integrity(connection)?;
    connection
        .execute_batch(
            r#"
            DROP TABLE security_declassification_tombstones_tenant_migration;
            DROP TABLE security_declassification_receipt_outbox_tenant_migration;
            DROP TABLE security_declassification_evidence_identity_tenant_migration;
            "#,
        )
        .map_err(sqlite_error)
}
