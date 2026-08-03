use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_control_plane::security::{
    DeclassificationReceiptOutboxDrainer, FlowResolverConfig, PersistentFlowResolver,
};
use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DeclassificationConsumptionReceiptBody, DeclassificationOutcomeReceiptBody,
};
use chio_core_types::SignedDeclassificationGrant;
use chio_flow::{
    canonical_request_hash, information_label_hash, CategoryLabelMap,
    DeclassificationDispatchOutcome,
};
use chio_kernel::{SecurityInvocationContextV1, ToolCallRequest};
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_kernel::{FlowPreInvocationInput, SecurityClock};
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::ports::{
    declassification_retain_until_unix_ms, derive_declassification_event_id,
    derive_declassification_transition_id, CanonicalBody, ClassificationPort,
    ClassificationRequest, ClassificationResult, ClassifierId, ClassifierVersion,
    CommittedEgressFence, DeclassificationCompactionQuery, DeclassificationCompactionRequest,
    DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationConsumptionEvidenceCommit, DeclassificationEvidenceAckRequest,
    DeclassificationEvidenceCommitStore, DeclassificationEvidencePendingQuery,
    DeclassificationEvidencePhase, DeclassificationOutcomeEvidenceCommit,
    DeclassificationOutcomeRequest, DeclassificationTransitionBinding, DeclassificationUseQuery,
    DeclassificationUseState, DestinationId, Digest32, EgressFence, EgressFenceCommit,
    EgressFenceRequest, ExactReceiptRecord, ExactSecurityReceiptSink, FlowJoinRequest,
    FlowStateKey, FlowStateSnapshot, FlowStateStore, GrantId, IsolationEpochTransition, LineageId,
    OpaqueReceiptRef, PortError, PortErrorKind, PortResult, ReceiptAppendRequest, RecordId,
    RequestId, SecurityReceiptSink, SessionId, TenantId, MAX_DECLASSIFICATION_EVIDENCE_BATCH,
};
use chio_security_types::{
    Compartment, DeclassificationGrantBody, DeclassificationGrantClaims, InformationLabel,
    PrincipalId,
};
#[cfg(target_os = "linux")]
use chio_store_sqlite::security_state::SecurityStateLifecycleOwnerProof;
use chio_store_sqlite::SqliteSecurityStateStore;
use rusqlite::{params, Connection};
use tempfile::tempdir;

const NOW_UNIX_MS: u64 = 150_000;

fn sqlite_integer(value: u64, field: &str) -> i64 {
    i64::try_from(value)
        .unwrap_or_else(|_| panic!("{field} exceeds the SQLite INTEGER range: {value}"))
}

fn tenant() -> TenantId {
    tenant_named("tenant-a")
}

fn tenant_named(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn grant() -> GrantId {
    grant_named("grant-a")
}

fn grant_named(value: &str) -> GrantId {
    GrantId::new(value).unwrap_or_else(|error| panic!("grant id: {error}"))
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn durable_receipt_hash(receipt: &ReceiptAppendRequest) -> Digest32 {
    let canonical = chio_core::canonical_json_bytes(receipt)
        .unwrap_or_else(|error| panic!("canonical durable receipt: {error}"));
    Digest32::new(*chio_core::sha256(&canonical).as_bytes())
}

fn seal_live(store: &SqliteSecurityStateStore) {
    store
        .seal_declassification_live_dispatch()
        .unwrap_or_else(|error| panic!("seal declassification live dispatch: {error:?}"));
}

#[cfg(target_os = "linux")]
fn open_store_for_owner_takeover(
    path: &Path,
) -> (SqliteSecurityStateStore, SecurityStateLifecycleOwnerProof) {
    let locked_database_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open lifecycle owner file: {error}"));
    rustix::fs::flock(
        &locked_database_file,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap_or_else(|error| panic!("lock lifecycle owner file: {error}"));
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("open lifecycle-owned store: {error:?}"));
    let proof = store
        .security_state_lifecycle_owner_proof(locked_database_file)
        .unwrap_or_else(|error| panic!("bind lifecycle owner proof: {error:?}"));
    store
        .reset_declassification_lifecycle_for_owner_takeover(&proof)
        .unwrap_or_else(|error| panic!("reset lifecycle for owner takeover: {error:?}"));
    (store, proof)
}

fn rewrite_declassification_evidence_keys_as_legacy(path: &Path) {
    let connection = Connection::open(path)
        .unwrap_or_else(|error| panic!("open declassification schema: {error}"));
    connection
        .execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;
            BEGIN IMMEDIATE;

            CREATE TEMP TABLE identity_legacy_copy AS
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM security_declassification_evidence_identity;
            CREATE TEMP TABLE outbox_legacy_copy AS
            SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                   transition_binding, evidence_type, evidence_id, canonical_body,
                   body_hash, transition_id, occurred_at, predecessor_evidence_id,
                   acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                   next_attempt_at, last_error_code
            FROM security_declassification_receipt_outbox;
            CREATE TEMP TABLE tombstone_legacy_copy AS
            SELECT tenant_id, grant_id, request_hash, terminal_state,
                   consumption_evidence_id, consumption_body_hash,
                   consumption_transition_id, consumption_occurred_at,
                   consumption_sink_record_hash, outcome_evidence_id,
                   outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                   outcome_sink_record_hash, policy_hash, compacted_at
            FROM security_declassification_tombstones;

            DROP TABLE security_declassification_tombstones;
            DROP TABLE security_declassification_receipt_outbox;
            DROP TABLE security_declassification_evidence_identity;

            CREATE TABLE security_declassification_evidence_identity (
                evidence_id TEXT NOT NULL PRIMARY KEY,
                transition_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32)
            );

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
            );

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
            );

            INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            )
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM identity_legacy_copy;
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
            FROM outbox_legacy_copy;
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
            FROM tombstone_legacy_copy;

            DROP TABLE tombstone_legacy_copy;
            DROP TABLE outbox_legacy_copy;
            DROP TABLE identity_legacy_copy;
            COMMIT;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .unwrap_or_else(|error| panic!("rewrite legacy declassification schema: {error}"));
}

fn table_primary_key_columns(connection: &Connection, table: &str) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .unwrap_or_else(|error| panic!("prepare {table} columns: {error}"));
    let mut columns = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(5)?, row.get::<_, String>(1)?))
        })
        .unwrap_or_else(|error| panic!("query {table} columns: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("read {table} columns: {error}"));
    columns.retain(|(position, _)| *position > 0);
    columns.sort_by_key(|(position, _)| *position);
    columns.into_iter().map(|(_, column)| column).collect()
}

fn policy() -> ActiveDefensePolicyBinding {
    policy_with_version("flow-policy-v1")
}

fn policy_with_version(version: &str) -> ActiveDefensePolicyBinding {
    ActiveDefensePolicyBinding {
        policy_version: record(version),
        policy_hash: digest(format!("policy-hash:{version}").as_bytes()),
    }
}

fn use_query() -> DeclassificationUseQuery {
    DeclassificationUseQuery {
        tenant_id: tenant(),
        grant_id: grant(),
    }
}

fn pending_query(max_records: u32) -> DeclassificationEvidencePendingQuery {
    pending_query_for(tenant(), grant(), max_records)
}

fn pending_query_for(
    tenant_id: TenantId,
    grant_id: GrantId,
    max_records: u32,
) -> DeclassificationEvidencePendingQuery {
    DeclassificationEvidencePendingQuery {
        tenant_id,
        grant_id,
        now_unix_ms: u64::MAX,
        max_records,
    }
}

fn consumption_binding_for(
    tenant_id: TenantId,
    grant_id: GrantId,
) -> DeclassificationTransitionBinding {
    DeclassificationTransitionBinding::Consumption {
        tenant_id,
        grant_id,
        request_hash: Digest32::new([31_u8; 32]),
        request_id: RequestId::new("declassification-test-request")
            .unwrap_or_else(|error| panic!("declassification test request id: {error}")),
    }
}

fn outcome_binding_for(
    tenant_id: TenantId,
    grant_id: GrantId,
    state: DeclassificationUseState,
) -> DeclassificationTransitionBinding {
    let request_id = RequestId::new("declassification-test-request")
        .unwrap_or_else(|error| panic!("declassification test request id: {error}"));
    let dispatch_commitment_id = record("declassification-test-dispatch");
    match state {
        DeclassificationUseState::Released => DeclassificationTransitionBinding::Released {
            tenant_id,
            grant_id,
            request_hash: Digest32::new([31_u8; 32]),
            request_id,
            dispatch_commitment_id,
        },
        DeclassificationUseState::DispatchFailed => {
            DeclassificationTransitionBinding::DispatchFailed {
                tenant_id,
                grant_id,
                request_hash: Digest32::new([31_u8; 32]),
                request_id,
                dispatch_commitment_id,
            }
        }
        DeclassificationUseState::ConsumedPendingDispatch
        | DeclassificationUseState::OutcomeUnknown => {
            panic!("test helper requires a live terminal state")
        }
    }
}

fn test_consumption_receipt(
    event_id: &str,
    transition_id: &str,
    sequence: u8,
) -> ReceiptAppendRequest {
    test_consumption_receipt_for(
        tenant(),
        grant(),
        event_id,
        transition_id,
        sequence,
        "flow-policy-v1",
    )
}

fn test_consumption_receipt_for(
    tenant_id: TenantId,
    grant_id: GrantId,
    _event_id: &str,
    _transition_id: &str,
    sequence: u8,
    policy_version: &str,
) -> ReceiptAppendRequest {
    let binding = consumption_binding_for(tenant_id.clone(), grant_id.clone());
    let transition_id = derive_declassification_transition_id(&binding)
        .unwrap_or_else(|error| panic!("derive consumption transition id: {error}"));
    let event_id = derive_declassification_event_id(&binding)
        .unwrap_or_else(|error| panic!("derive consumption event id: {error}"));
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                NOW_UNIX_MS.saturating_add(u64::from(sequence)),
                tenant_id.clone(),
                transition_id,
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("consumption receipt header: {error}")),
            policy: policy_with_version(policy_version),
            grant_id: grant_id.clone(),
            grant_hash: digest(
                format!("grant-hash:{}:{}", tenant_id.as_str(), grant_id.as_str()).as_bytes(),
            ),
            request_hash: Digest32::new([31_u8; 32]),
            event_id,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    );
    receipt_request(body)
}

fn test_outcome_receipt(
    _event_id: &str,
    _transition_id: &str,
    sequence: u8,
    predecessor_evidence_id: OpaqueReceiptRef,
    to_state: DeclassificationUseState,
) -> ReceiptAppendRequest {
    let tenant_id = tenant();
    let grant_id = grant();
    let binding = outcome_binding_for(tenant_id.clone(), grant_id.clone(), to_state);
    test_outcome_receipt_for_binding(&binding, sequence, predecessor_evidence_id, to_state)
}

fn test_outcome_receipt_for_binding(
    binding: &DeclassificationTransitionBinding,
    sequence: u8,
    predecessor_evidence_id: OpaqueReceiptRef,
    to_state: DeclassificationUseState,
) -> ReceiptAppendRequest {
    let tenant_id = binding.tenant_id().clone();
    let grant_id = binding.grant_id().clone();
    let transition_id = derive_declassification_transition_id(binding)
        .unwrap_or_else(|error| panic!("derive outcome transition id: {error}"));
    let event_id = derive_declassification_event_id(binding)
        .unwrap_or_else(|error| panic!("derive outcome event id: {error}"));
    let body =
        ActiveDefenseReceiptBody::DeclassificationOutcome(DeclassificationOutcomeReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                NOW_UNIX_MS.saturating_add(u64::from(sequence)),
                tenant_id.clone(),
                transition_id,
                vec![predecessor_evidence_id],
            )
            .unwrap_or_else(|error| panic!("outcome receipt header: {error}")),
            policy: policy(),
            grant_id: grant_id.clone(),
            grant_hash: digest(
                format!("grant-hash:{}:{}", tenant_id.as_str(), grant_id.as_str()).as_bytes(),
            ),
            request_hash: Digest32::new([31_u8; 32]),
            event_id,
            from_state: DeclassificationUseState::ConsumedPendingDispatch,
            to_state,
        });
    receipt_request(body)
}

fn receipt_request(body: ActiveDefenseReceiptBody) -> ReceiptAppendRequest {
    body.validate()
        .unwrap_or_else(|error| panic!("active-defense receipt body: {error}"));
    let canonical = chio_core::canonical_json_bytes(&body)
        .unwrap_or_else(|error| panic!("canonical active-defense receipt body: {error}"));
    ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: record(body.kind().as_str()),
        evidence_id: body
            .evidence_id()
            .unwrap_or_else(|error| panic!("active-defense evidence id: {error}")),
        canonical_body: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("canonical receipt body: {error}")),
        body_hash: body
            .body_digest()
            .unwrap_or_else(|error| panic!("active-defense body digest: {error}")),
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    }
}

fn consumption_commit(receipt: ReceiptAppendRequest) -> DeclassificationConsumptionEvidenceCommit {
    consumption_commit_for(tenant(), grant(), receipt)
}

fn consumption_commit_for(
    tenant_id: TenantId,
    grant_id: GrantId,
    receipt: ReceiptAppendRequest,
) -> DeclassificationConsumptionEvidenceCommit {
    let consumed_at_unix_ms = receipt.occurred_at_unix_ms;
    DeclassificationConsumptionEvidenceCommit {
        transition_binding: consumption_binding_for(tenant_id.clone(), grant_id.clone()),
        consumption: DeclassificationConsumeRequest {
            tenant_id,
            grant_id,
            request_hash: Digest32::new([31_u8; 32]),
            consumed_at_unix_ms,
            grant_expires_at_unix_ms: consumed_at_unix_ms.saturating_add(60_000),
        },
        receipt,
    }
}

fn outcome_commit(
    state: DeclassificationUseState,
    receipt: ReceiptAppendRequest,
    predecessor_evidence_id: OpaqueReceiptRef,
) -> DeclassificationOutcomeEvidenceCommit {
    DeclassificationOutcomeEvidenceCommit {
        transition_binding: outcome_binding_for(tenant(), grant(), state),
        outcome: DeclassificationOutcomeRequest {
            tenant_id: tenant(),
            grant_id: grant(),
            request_hash: Digest32::new([31_u8; 32]),
            expected_state: DeclassificationUseState::ConsumedPendingDispatch,
            new_state: state,
            transition_id: receipt.transition_id.clone(),
        },
        predecessor_evidence_id,
        receipt,
    }
}

#[derive(Default)]
struct ScriptedReceiptSink {
    state: Mutex<ScriptedReceiptSinkState>,
}

#[derive(Default)]
struct ScriptedReceiptSinkState {
    attempts: Vec<ReceiptAppendRequest>,
    accepted: BTreeMap<OpaqueReceiptRef, ReceiptAppendRequest>,
    accepted_order: Vec<ReceiptAppendRequest>,
    fail_attempts: BTreeSet<usize>,
    returned_evidence_id: Option<OpaqueReceiptRef>,
}

impl ScriptedReceiptSink {
    fn fail_attempts(attempts: impl IntoIterator<Item = usize>) -> Self {
        Self {
            state: Mutex::new(ScriptedReceiptSinkState {
                fail_attempts: attempts.into_iter().collect(),
                ..ScriptedReceiptSinkState::default()
            }),
        }
    }

    fn allow_all(&self) {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt sink lock"))
            .fail_attempts
            .clear();
    }

    fn returning_evidence_id(evidence_id: OpaqueReceiptRef) -> Self {
        Self {
            state: Mutex::new(ScriptedReceiptSinkState {
                returned_evidence_id: Some(evidence_id),
                ..ScriptedReceiptSinkState::default()
            }),
        }
    }

    fn attempts(&self) -> Vec<ReceiptAppendRequest> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt sink lock"))
            .attempts
            .clone()
    }

    fn accepted(&self) -> Vec<ReceiptAppendRequest> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt sink lock"))
            .accepted_order
            .clone()
    }
}

impl SecurityReceiptSink for ScriptedReceiptSink {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let body: ActiveDefenseReceiptBody =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
        let canonical =
            chio_core::canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        if canonical.as_slice() != request.canonical_body.as_bytes()
            || body.header().tenant_id != request.tenant_id
            || body.header().transition_id != request.transition_id
            || body.header().occurred_at_unix_ms != request.occurred_at_unix_ms
            || body.kind().as_str() != request.evidence_type.as_str()
            || body.body_digest().map_err(|_| PortError::invalid_data())? != request.body_hash
            || body.evidence_id().map_err(|_| PortError::invalid_data())? != request.evidence_id
        {
            return Err(PortError::integrity_failure());
        }
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        state.attempts.push(request.clone());
        let attempt = state.attempts.len();
        if state.fail_attempts.contains(&attempt) {
            return Err(PortError::unavailable());
        }
        if let Some(existing) = state.accepted.get(&request.evidence_id) {
            if existing != request {
                return Err(PortError::conflict());
            }
        } else {
            state
                .accepted
                .insert(request.evidence_id.clone(), request.clone());
            state.accepted_order.push(request.clone());
        }
        Ok(state
            .returned_evidence_id
            .clone()
            .unwrap_or_else(|| request.evidence_id.clone()))
    }
}

impl ExactSecurityReceiptSink for ScriptedReceiptSink {
    fn load_exact(&self, evidence_id: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        let state = self.state.lock().map_err(|_| PortError::unavailable())?;
        let Some(receipt) = state.accepted.get(evidence_id).cloned() else {
            return Ok(None);
        };
        let canonical =
            chio_core::canonical_json_bytes(&receipt).map_err(|_| PortError::invalid_data())?;
        Ok(Some(ExactReceiptRecord {
            receipt,
            durable_record_hash: Digest32::new(*chio_core::sha256(&canonical).as_bytes()),
        }))
    }
}

struct AppendWithoutExactReadback;

impl SecurityReceiptSink for AppendWithoutExactReadback {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        Ok(request.evidence_id.clone())
    }
}

impl ExactSecurityReceiptSink for AppendWithoutExactReadback {
    fn load_exact(&self, _: &OpaqueReceiptRef) -> PortResult<Option<ExactReceiptRecord>> {
        Ok(None)
    }
}

struct FixedClock;

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(NOW_UNIX_MS)
    }
}

#[cfg(target_os = "linux")]
struct RecoveryClock;

#[cfg(target_os = "linux")]
impl SecurityClock for RecoveryClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(NOW_UNIX_MS.saturating_add(10_000))
    }
}

struct SequenceClock {
    values: Mutex<Vec<u64>>,
}

impl SequenceClock {
    fn new(values: Vec<u64>) -> Self {
        Self {
            values: Mutex::new(values),
        }
    }
}

impl SecurityClock for SequenceClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        let mut values = self.values.lock().map_err(|_| PortError::unavailable())?;
        if values.is_empty() {
            return Err(PortError::unavailable());
        }
        Ok(values.remove(0))
    }
}

struct EmptyClassifier;

impl ClassificationPort for EmptyClassifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: ClassifierId::new("classifier.empty").map_err(PortError::from)?,
            classifier_version: ClassifierVersion::new("1").map_err(PortError::from)?,
            findings: chio_security_types::ports::BoundedVec::new(Vec::new())
                .map_err(|_| PortError::invalid_data())?,
        })
    }
}

struct FlowStore {
    snapshot: Mutex<FlowStateSnapshot>,
}

impl FlowStore {
    fn new(snapshot: FlowStateSnapshot) -> Self {
        Self {
            snapshot: Mutex::new(snapshot),
        }
    }
}

impl FlowStateStore for FlowStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        Ok((snapshot.key == *key).then(|| snapshot.clone()))
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let mut snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key != request.key {
            return Err(PortError::invalid_data());
        }
        snapshot.principal_label = snapshot
            .principal_label
            .join_restrictions(&request.principal_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.lineage_label = snapshot
            .lineage_label
            .join_restrictions(&request.lineage_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.session_label = snapshot
            .session_label
            .join_restrictions(&request.session_join)
            .map_err(|_| PortError::invalid_data())?;
        snapshot.context_generation = snapshot
            .context_generation
            .checked_add(1)
            .ok_or_else(PortError::invalid_data)?;
        Ok(snapshot.clone())
    }

    fn open_isolation_epoch(&self, _: &IsolationEpochTransition) -> PortResult<FlowStateSnapshot> {
        Err(PortError::invalid_data())
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key != request.key
            || snapshot.context_generation != request.expected_context_generation
        {
            return Err(PortError::conflict());
        }
        Ok(EgressFence {
            fence_id: record("fence-a"),
            key: request.key.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash,
            context_generation: request.expected_context_generation,
            expires_at_unix_ms: request.expires_at_unix_ms,
        })
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let snapshot = self.snapshot.lock().map_err(|_| PortError::unavailable())?;
        if snapshot.key == fence.key && snapshot.context_generation == fence.context_generation {
            Ok(())
        } else {
            Err(PortError::conflict())
        }
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        self.validate_egress_fence(&commitment.fence)?;
        Ok(CommittedEgressFence {
            fence_id: commitment.fence.fence_id.clone(),
            request_id: commitment.fence.request_id.clone(),
            request_hash: commitment.fence.request_hash,
            context_generation: commitment.fence.context_generation,
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
            committed_at_unix_ms: commitment.committed_at_unix_ms,
        })
    }
}

fn restricted_label() -> InformationLabel {
    InformationLabel::try_known(
        BTreeMap::new(),
        BTreeSet::from([
            Compartment::new("restricted").unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("restricted label: {error}"))
}

fn flow_key() -> FlowStateKey {
    FlowStateKey {
        tenant_id: tenant(),
        principal_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new("lineage-a")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("session-a")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch-a")
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
    }
}

fn flow_snapshot() -> FlowStateSnapshot {
    FlowStateSnapshot {
        key: flow_key(),
        principal_label: InformationLabel::bottom(),
        lineage_label: InformationLabel::bottom(),
        session_label: InformationLabel::bottom(),
        context_generation: 7,
    }
}

fn registry(purpose: &DeclassificationPurpose) -> Arc<VerifiedManifestRegistry> {
    let signer = Keypair::from_seed(&[73_u8; 32]);
    let flow = ToolFlowDeclaration::new(
        None,
        Some(InformationLabel::bottom()),
        true,
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("flow declaration: {error}"));
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "server-a".to_string(),
        name: "Flow server".to_string(),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "send".to_string(),
            description: "Send".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: false,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(flow),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed =
        sign_manifest(&manifest, &signer).unwrap_or_else(|error| panic!("sign manifest: {error}"));
    let tool_policy = AuthoritativeToolPolicy::new(
        vec![InformationLabel::bottom()],
        InformationLabel::bottom(),
        BTreeSet::from([purpose.clone()]),
    )
    .unwrap_or_else(|error| panic!("tool policy: {error}"));
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(
            signed,
            &signer.public_key(),
            &BTreeMap::from([("send".to_string(), tool_policy)]),
            &BTreeMap::from([("send".to_string(), RuntimeToolTopology::remote())]),
        )
        .unwrap_or_else(|error| panic!("register manifest: {error}"));
    Arc::new(registry)
}

fn request(authority: &Keypair, purpose: &DeclassificationPurpose) -> ToolCallRequest {
    let keypair = Keypair::from_seed(&[74_u8; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-a".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &keypair,
    )
    .unwrap_or_else(|error| panic!("sign capability: {error}"));
    let mut request = ToolCallRequest {
        request_id: "request-a".to_string(),
        capability,
        tool_name: "send".to_string(),
        server_id: "server-a".to_string(),
        agent_id: "agent-a".to_string(),
        arguments: serde_json::json!({"safe": true}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let canonical = CanonicalBody::new(
        chio_core::canonical_json_bytes(&request.arguments)
            .unwrap_or_else(|error| panic!("canonical request: {error}")),
    )
    .unwrap_or_else(|error| panic!("canonical request body: {error}"));
    let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
        grant_id: grant(),
        capability_id: record("capability-a"),
        tenant_id: tenant(),
        subject_id: PrincipalId::new("principal-a")
            .unwrap_or_else(|error| panic!("subject id: {error}")),
        agent_id: record("agent-a"),
        session_id: SessionId::new("session-a")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        source_label_hash: information_label_hash(&restricted_label())
            .unwrap_or_else(|error| panic!("source label hash: {error}")),
        target_label: InformationLabel::bottom(),
        destination_id: DestinationId::new("server-a")
            .unwrap_or_else(|error| panic!("destination id: {error}")),
        tool_name: record("send"),
        purpose: purpose.clone(),
        request_hash: canonical_request_hash(&canonical)
            .unwrap_or_else(|error| panic!("request hash: {error}")),
        issued_at_unix_seconds: 100,
        expires_at_unix_seconds: 200,
        authority_key_id: record("authority-a"),
    })
    .unwrap_or_else(|error| panic!("grant body: {error}"));
    request.declassification_grant = Some(
        SignedDeclassificationGrant::sign(body, authority)
            .unwrap_or_else(|error| panic!("sign grant: {error}")),
    );
    request
}

fn resolver(
    path: &Path,
    sink: Arc<dyn ExactSecurityReceiptSink>,
) -> (
    PersistentFlowResolver,
    Arc<SqliteSecurityStateStore>,
    SecurityInvocationContextV1,
    ToolCallRequest,
) {
    resolver_with_clock(path, sink, Arc::new(FixedClock))
}

fn resolver_with_clock(
    path: &Path,
    sink: Arc<dyn ExactSecurityReceiptSink>,
    clock: Arc<dyn SecurityClock>,
) -> (
    PersistentFlowResolver,
    Arc<SqliteSecurityStateStore>,
    SecurityInvocationContextV1,
    ToolCallRequest,
) {
    let authority = Keypair::from_seed(&[75_u8; 32]);
    let purpose = DeclassificationPurpose::new("support")
        .unwrap_or_else(|error| panic!("declassification purpose: {error}"));
    let evidence_store = Arc::new(
        SqliteSecurityStateStore::open(path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    let config = FlowResolverConfig::new(
        restricted_label(),
        CategoryLabelMap::new(
            ClassifierId::new("classifier.empty")
                .unwrap_or_else(|error| panic!("classifier id: {error}")),
            ClassifierVersion::new("1")
                .unwrap_or_else(|error| panic!("classifier version: {error}")),
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("category map: {error}")),
        BTreeMap::from([(record("authority-a"), authority.public_key())]),
        10_000,
    )
    .unwrap_or_else(|error| panic!("flow resolver config: {error}"))
    .with_declassification_evidence(
        evidence_store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        sink,
        policy(),
    )
    .unwrap_or_else(|error| panic!("declassification evidence config: {error:?}"));
    let key = flow_key();
    let context = SecurityInvocationContextV1::new(
        key.tenant_id,
        key.session_id,
        key.principal_id,
        key.isolation_epoch_id,
        key.lineage_id,
        7,
    );
    (
        PersistentFlowResolver::new(
            registry(&purpose),
            Arc::new(FlowStore::new(flow_snapshot())),
            Arc::new(EmptyClassifier),
            clock,
            config,
        ),
        evidence_store,
        context,
        request(&authority, &purpose),
    )
}

fn drain(
    store: Arc<SqliteSecurityStateStore>,
    sink: Arc<dyn ExactSecurityReceiptSink>,
    max_receipts: u32,
) -> chio_control_plane::security::DeclassificationReceiptDrainReport {
    DeclassificationReceiptOutboxDrainer::new(
        store as Arc<dyn DeclassificationEvidenceCommitStore>,
        sink,
    )
    .unwrap_or_else(|error| panic!("construct declassification drainer: {error:?}"))
    .drain_once(max_receipts)
    .unwrap_or_else(|error| panic!("drain declassification receipt outbox: {error:?}"))
}

#[test]
fn consumption_sink_failure_blocks_dispatch_and_restart_drains_consumption_before_failure_outcome()
{
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("consumption-sink-failure.sqlite");
    let failing_sink = Arc::new(ScriptedReceiptSink::fail_attempts([1]));
    let (resolver, store, context, request) = resolver_with_clock(
        &path,
        failing_sink.clone(),
        Arc::new(SequenceClock::new(vec![
            NOW_UNIX_MS,
            NOW_UNIX_MS.saturating_add(1),
            NOW_UNIX_MS.saturating_add(10),
        ])),
    );
    let connector_calls = AtomicUsize::new(0);

    let dispatch = resolver.commit_dispatch(
        &FlowPreInvocationInput {
            security_context: &context,
            request: &request,
        },
        record("dispatch-consumption-sink-failure"),
    );
    if dispatch.is_ok() {
        connector_calls.fetch_add(1, Ordering::SeqCst);
    }
    assert!(dispatch.is_err());
    assert_eq!(connector_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load declassification use: {error:?}"))
            .unwrap_or_else(|| panic!("declassification use missing"))
            .state,
        DeclassificationUseState::DispatchFailed
    );
    let pending = store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load pending declassification evidence: {error:?}"));
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].phase, DeclassificationEvidencePhase::Consumption);
    assert_eq!(pending[1].phase, DeclassificationEvidencePhase::Outcome);
    assert_eq!(
        pending[1].receipt.occurred_at_unix_ms,
        NOW_UNIX_MS.saturating_add(10)
    );
    assert!(pending[1].receipt.occurred_at_unix_ms > pending[0].receipt.occurred_at_unix_ms);
    assert_eq!(
        pending[1].predecessor_evidence_id.as_ref(),
        Some(&pending[0].receipt.evidence_id)
    );

    drop(resolver);
    drop(store);
    let reopened = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen security state store: {error:?}")),
    );
    let recovered_sink = Arc::new(ScriptedReceiptSink::default());
    let first = drain(reopened.clone(), recovered_sink.clone(), 1);
    assert_eq!(first.appended, 1);
    assert_eq!(first.acknowledged, 1);
    assert_eq!(first.remaining, 1);
    let first_body: ActiveDefenseReceiptBody =
        serde_json::from_slice(recovered_sink.accepted()[0].canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("decode consumption receipt: {error}"));
    assert!(matches!(
        first_body,
        ActiveDefenseReceiptBody::DeclassificationConsumption(_)
    ));

    let second = drain(reopened.clone(), recovered_sink.clone(), 1);
    assert_eq!(second.appended, 1);
    assert_eq!(second.acknowledged, 1);
    assert_eq!(second.remaining, 0);
    let bodies = recovered_sink
        .accepted()
        .into_iter()
        .map(|request| {
            serde_json::from_slice::<ActiveDefenseReceiptBody>(request.canonical_body.as_bytes())
                .unwrap_or_else(|error| panic!("decode recovered receipt: {error}"))
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        bodies.as_slice(),
        [
            ActiveDefenseReceiptBody::DeclassificationConsumption(_),
            ActiveDefenseReceiptBody::DeclassificationOutcome(_)
        ]
    ));
    let ActiveDefenseReceiptBody::DeclassificationOutcome(outcome) = &bodies[1] else {
        panic!("second recovered receipt is not an outcome");
    };
    assert_eq!(outcome.to_state, DeclassificationUseState::DispatchFailed);
}

#[test]
fn terminal_outcome_uses_post_dispatch_trusted_time() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("post-dispatch-outcome-time.sqlite");
    let sink = Arc::new(ScriptedReceiptSink::default());
    let (resolver, _store, context, request) = resolver_with_clock(
        &path,
        sink.clone(),
        Arc::new(SequenceClock::new(vec![
            NOW_UNIX_MS,
            NOW_UNIX_MS.saturating_add(1),
            NOW_UNIX_MS.saturating_add(10),
            NOW_UNIX_MS.saturating_add(20),
        ])),
    );
    let mut recorder = resolver
        .commit_dispatch(
            &FlowPreInvocationInput {
                security_context: &context,
                request: &request,
            },
            record("dispatch-post-time"),
        )
        .unwrap_or_else(|error| panic!("commit declassification dispatch: {error}"))
        .unwrap_or_else(|| panic!("declassification outcome recorder missing"));

    recorder
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("record released outcome: {error}"));

    let receipts = sink.accepted();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].occurred_at_unix_ms, NOW_UNIX_MS);
    assert_eq!(
        receipts[1].occurred_at_unix_ms,
        NOW_UNIX_MS.saturating_add(20)
    );
    assert!(receipts[1].occurred_at_unix_ms > receipts[0].occurred_at_unix_ms);
}

#[test]
fn released_state_and_terminal_receipt_survive_sink_failure_and_restart() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("release-sink-failure.sqlite");
    let sink = Arc::new(ScriptedReceiptSink::fail_attempts([2]));
    let (resolver, store, context, request) = resolver(&path, sink.clone());
    let connector_calls = AtomicUsize::new(0);
    let mut recorder = resolver
        .commit_dispatch(
            &FlowPreInvocationInput {
                security_context: &context,
                request: &request,
            },
            record("dispatch-release-sink-failure"),
        )
        .unwrap_or_else(|error| panic!("commit declassification dispatch: {error}"))
        .unwrap_or_else(|| panic!("declassification outcome recorder missing"));
    connector_calls.fetch_add(1, Ordering::SeqCst);
    assert!(recorder
        .record(DeclassificationDispatchOutcome::Released)
        .is_err());
    assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.accepted().len(), 1);
    assert!(matches!(
        serde_json::from_slice::<ActiveDefenseReceiptBody>(
            sink.accepted()[0].canonical_body.as_bytes()
        )
        .unwrap_or_else(|error| panic!("decode accepted consumption receipt: {error}")),
        ActiveDefenseReceiptBody::DeclassificationConsumption(_)
    ));
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load released use: {error:?}"))
            .unwrap_or_else(|| panic!("released use missing"))
            .state,
        DeclassificationUseState::Released
    );
    let pending = store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load pending release receipt: {error:?}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].phase, DeclassificationEvidencePhase::Outcome);

    drop(recorder);
    drop(resolver);
    drop(store);
    sink.allow_all();
    let reopened = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen security state store: {error:?}")),
    );
    let report = drain(reopened.clone(), sink.clone(), 8);
    assert_eq!(report.appended, 1);
    assert_eq!(report.acknowledged, 1);
    assert_eq!(report.remaining, 0);
    assert_eq!(sink.accepted().len(), 2);
    let terminal: ActiveDefenseReceiptBody =
        serde_json::from_slice(sink.accepted()[1].canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("decode recovered release receipt: {error}"));
    let ActiveDefenseReceiptBody::DeclassificationOutcome(terminal) = terminal else {
        panic!("recovered terminal receipt is not a declassification outcome");
    };
    assert_eq!(terminal.to_state, DeclassificationUseState::Released);
    assert_eq!(
        reopened
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load reopened release state: {error:?}"))
            .unwrap_or_else(|| panic!("reopened release state missing"))
            .state,
        DeclassificationUseState::Released
    );
}

#[test]
fn receipt_ack_loss_retry_is_idempotent() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("receipt-ack-loss.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let receipt = test_consumption_receipt(
        "declassification-consumption-ack-loss",
        "declassification-consumption-ack-loss-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(receipt.clone()))
        .unwrap_or_else(|error| panic!("commit consumption evidence: {error:?}"));
    let sink = Arc::new(ScriptedReceiptSink::default());
    sink.sign_and_append(&receipt)
        .unwrap_or_else(|error| panic!("append before simulated ack loss: {error:?}"));

    drop(store);
    let reopened = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen security state store: {error:?}")),
    );
    let report = drain(reopened.clone(), sink.clone(), 8);
    assert_eq!(report.appended, 1);
    assert_eq!(report.acknowledged, 1);
    assert_eq!(report.remaining, 0);
    assert_eq!(sink.attempts().len(), 1);
    assert_eq!(sink.accepted().len(), 1);
    assert!(reopened
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load pending evidence after retry: {error:?}"))
        .is_empty());
}

#[test]
fn crash_after_atomic_state_and_outbox_commit_is_recoverable() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("state-outbox-crash.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let consumption = test_consumption_receipt(
        "declassification-consumption-crash",
        "declassification-consumption-crash-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(consumption.clone()))
        .unwrap_or_else(|error| panic!("commit consumption before crash: {error:?}"));
    let outcome = test_outcome_receipt(
        "declassification-outcome-crash",
        "declassification-outcome-crash-transition",
        1,
        consumption.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    store
        .commit_declassification_outcome_evidence(&outcome_commit(
            DeclassificationUseState::Released,
            outcome,
            consumption.evidence_id,
        ))
        .unwrap_or_else(|error| panic!("commit outcome before crash: {error:?}"));
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load committed state: {error:?}"))
            .unwrap_or_else(|| panic!("committed state missing"))
            .state,
        DeclassificationUseState::Released
    );
    drop(store);

    let reopened = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("reopen security state store: {error:?}")),
    );
    let sink = Arc::new(ScriptedReceiptSink::default());
    let first = drain(reopened.clone(), sink.clone(), 1);
    assert_eq!((first.appended, first.remaining), (1, 1));
    let second = drain(reopened.clone(), sink.clone(), 1);
    assert_eq!((second.appended, second.remaining), (1, 0));
    assert_eq!(sink.accepted().len(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn quiescent_startup_reconciles_acknowledged_consumption_without_outcome() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("stranded-consumption.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let consumption_receipt = test_consumption_receipt(
        "declassification-consumption-stranded",
        "declassification-consumption-stranded-transition",
        0,
    );
    let consumption = consumption_commit(consumption_receipt.clone());
    store
        .commit_declassification_consumption_evidence(&consumption)
        .unwrap_or_else(|error| panic!("commit stranded consumption: {error:?}"));
    store
        .acknowledge_declassification_evidence(&DeclassificationEvidenceAckRequest {
            tenant_id: tenant(),
            grant_id: grant(),
            phase: DeclassificationEvidencePhase::Consumption,
            evidence_id: consumption_receipt.evidence_id.clone(),
            body_hash: consumption_receipt.body_hash,
            transition_id: consumption_receipt.transition_id.clone(),
            durable_sink_record_hash: durable_receipt_hash(&consumption_receipt),
            verified_at_unix_ms: NOW_UNIX_MS.saturating_add(1),
        })
        .unwrap_or_else(|error| panic!("acknowledge stranded consumption: {error:?}"));
    drop(store);

    let (reopened, _lifecycle_owner) = open_store_for_owner_takeover(&path);
    let reopened = Arc::new(reopened);
    let sink = Arc::new(ScriptedReceiptSink::default());
    let drainer = DeclassificationReceiptOutboxDrainer::new_with_clock(
        reopened.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        sink.clone(),
        Arc::new(RecoveryClock),
    )
    .unwrap_or_else(|error| panic!("construct recovery drainer: {error:?}"));
    let reconciliation = drainer
        .reconcile_stranded(1)
        .unwrap_or_else(|error| panic!("reconcile stranded consumption: {error:?}"));
    assert_eq!(
        (reconciliation.reconciled, reconciliation.remaining),
        (1, 0)
    );
    assert_eq!(
        reopened
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load reconciled use: {error:?}"))
            .unwrap_or_else(|| panic!("reconciled use missing"))
            .state,
        DeclassificationUseState::OutcomeUnknown
    );
    let pending = reopened
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load reconciled outcome: {error:?}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].phase, DeclassificationEvidencePhase::Outcome);
    let persisted_outcome = pending[0].receipt.clone();
    assert_eq!(
        persisted_outcome.occurred_at_unix_ms,
        NOW_UNIX_MS.saturating_add(10_000)
    );
    assert!(persisted_outcome.occurred_at_unix_ms >= consumption_receipt.occurred_at_unix_ms);
    let retry = drainer
        .reconcile_stranded(1)
        .unwrap_or_else(|error| panic!("retry stranded reconciliation: {error:?}"));
    assert_eq!((retry.reconciled, retry.remaining), (0, 0));
    drainer
        .seal_live_dispatch()
        .unwrap_or_else(|error| panic!("seal after reconciliation: {error:?}"));
    assert_eq!(
        reopened
            .commit_declassification_consumption_evidence(&consumption)
            .unwrap_or_else(|error| panic!("retry reconciled consumption: {error:?}")),
        DeclassificationConsume::AlreadyConsumed {
            request_hash: consumption.consumption.request_hash,
            state: DeclassificationUseState::OutcomeUnknown,
        }
    );
    let report = drainer
        .drain_once(8)
        .unwrap_or_else(|error| panic!("drain reconciled outcome: {error:?}"));
    assert_eq!(
        (report.appended, report.acknowledged, report.remaining),
        (1, 1, 0)
    );
    assert_eq!(
        sink.accepted(),
        vec![consumption_receipt, persisted_outcome]
    );
    assert_eq!(sink.attempts().len(), 2);
    let readiness_cursor = reopened
        .declassification_evidence_readiness_cursor()
        .unwrap_or_else(|error| panic!("load unknown-outcome readiness cursor: {error:?}"));
    let candidates = reopened
        .load_declassification_compaction_candidates(&DeclassificationCompactionQuery {
            readiness_cursor,
            now_unix_ms: u64::MAX,
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        })
        .unwrap_or_else(|error| panic!("load unknown-outcome compaction candidates: {error:?}"));
    assert!(candidates.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn quiescent_startup_marks_unacknowledged_consumption_dispatch_failed() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("stranded-undelivered-consumption.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let consumption_receipt = test_consumption_receipt(
        "declassification-consumption-stranded-undelivered",
        "declassification-consumption-stranded-undelivered-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(
            consumption_receipt.clone(),
        ))
        .unwrap_or_else(|error| panic!("commit undelivered consumption: {error:?}"));
    drop(store);

    let (reopened, _lifecycle_owner) = open_store_for_owner_takeover(&path);
    let reopened = Arc::new(reopened);
    let drainer = DeclassificationReceiptOutboxDrainer::new_with_clock(
        reopened.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        Arc::new(ScriptedReceiptSink::default()),
        Arc::new(RecoveryClock),
    )
    .unwrap_or_else(|error| panic!("construct undelivered recovery drainer: {error:?}"));
    let reconciliation = drainer
        .reconcile_stranded(1)
        .unwrap_or_else(|error| panic!("reconcile undelivered consumption: {error:?}"));
    assert_eq!(
        (reconciliation.reconciled, reconciliation.remaining),
        (1, 0)
    );
    assert_eq!(
        reopened
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load undelivered recovered use: {error:?}"))
            .unwrap_or_else(|| panic!("undelivered recovered use missing"))
            .state,
        DeclassificationUseState::DispatchFailed
    );
    let pending = reopened
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load undelivered recovery evidence: {error:?}"));
    assert_eq!(pending.len(), 2);
    assert!(matches!(
        pending[1].transition_binding,
        DeclassificationTransitionBinding::RecoveryUndeliveredConsumption { .. }
    ));
}
