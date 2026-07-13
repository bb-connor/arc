use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::encrypted_blob::SqliteEncryptedBlobStore;
use chio_core::canonical::canonical_json_bytes;
use chio_core::hashing::sha256;
use chio_security_types::ports::{
    ActionId, AdvisorySecurityEvent, ApprovalReservationCreate, ApprovalReservationMutation,
    ApprovalReservationState, ApprovalReservationStore, CanonicalBody, CommittedEgressFence,
    ContainmentOverlayStore, CorrelationCasRequest, CorrelationDeleteRequest,
    CorrelationEventIndexRequest, CorrelationPartial, CorrelationPartitionKey, CorrelationScan,
    CreateOutcome, DeclassificationConsume, DeclassificationConsumeRequest,
    DeclassificationOutcomeRequest, DeclassificationUseState, DeclassificationUseStore, Digest32,
    EffectId, EgressFence, EgressFenceCommit, EgressFenceRequest, ErrorCode, EventAppend, EventId,
    EventPartitionScan, FlowJoinRequest, FlowStateKey, FlowStateSnapshot, FlowStateStore,
    IsolationEpochEvidenceVerifierPort, IsolationEpochTransition, LineageFence,
    LineageFenceRelease, LineageFenceRequest, LineageFenceStore, OverlayApplyRequest,
    OverlayContribution, OverlayContributions, OverlayRemoveRequest, OverlaySnapshot, PortError,
    PortResult, ProducerId, ProducerTrustClass, RecordId, ResponseCasRequest,
    ResponseEffectCasRequest, ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey,
    ResponsePlanRecord, ResponseSchedulerStore, ResponseStore, ScheduledWork,
    SchedulerClaimRequest, SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest,
    SchedulerLeaseRenewRequest, SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey,
    SecurityEventStore, StoredApprovalReservation, TenantScopedId, VerifiedEventBatch,
    VerifiedIsolationEvidence, VerifiedSecurityEvent,
};
use chio_security_types::InformationLabel;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const MAX_EVENT_SCAN_RESULTS: u32 = 4_096;
const MAX_SCHEDULER_CLAIMS: u32 = 1_024;
const MAX_CLOCK_SKEW_MS: u64 = 5_000;

pub struct SqliteSecurityStateStore {
    connection: Mutex<Connection>,
    isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
}

struct DenyIsolationEpochEvidence;

impl IsolationEpochEvidenceVerifierPort for DenyIsolationEpochEvidence {
    fn verify(&self, _: &IsolationEpochTransition) -> PortResult<VerifiedIsolationEvidence> {
        Err(PortError::invalid_data())
    }
}

impl SqliteSecurityStateStore {
    pub fn open(path: impl AsRef<Path>) -> PortResult<Self> {
        Self::open_with_isolation_epoch_verifier(path, Arc::new(DenyIsolationEpochEvidence))
    }

    pub fn open_with_isolation_epoch_verifier(
        path: impl AsRef<Path>,
        isolation_epoch_verifier: Arc<dyn IsolationEpochEvidenceVerifierPort>,
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
        SqliteEncryptedBlobStore::open(path).map_err(|_| PortError::unavailable())?;
        let connection = Connection::open(path).map_err(sqlite_error)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_error)?;
        migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            isolation_epoch_verifier,
        })
    }

    fn connection(&self) -> PortResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| PortError::unavailable())
    }
}

fn migrate(connection: &Connection) -> PortResult<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS security_isolation_epochs (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                previous_isolation_epoch_id TEXT,
                evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
                evidence_verifier_id TEXT,
                evidence_receipt_ref TEXT,
                transition_id TEXT NOT NULL,
                effective_at INTEGER NOT NULL,
                CHECK (
                    (evidence_verifier_id IS NULL AND evidence_receipt_ref IS NULL)
                    OR (evidence_verifier_id IS NOT NULL AND evidence_receipt_ref IS NOT NULL)
                ),
                PRIMARY KEY (tenant_id, principal_id, lineage_id, isolation_epoch_id),
                UNIQUE (tenant_id, transition_id)
            );

            CREATE TABLE IF NOT EXISTS security_principal_flow_state (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_lineage_flow_state (
                tenant_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, lineage_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_flow_state (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, session_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_memberships (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, session_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_flow_contexts (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                PRIMARY KEY (
                    tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
                )
            );

            CREATE TABLE IF NOT EXISTS security_flow_sequences (
                tenant_id TEXT NOT NULL,
                last_generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id)
            );

            CREATE TABLE IF NOT EXISTS security_egress_fences (
                fence_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                context_generation INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                dispatch_commitment_id TEXT,
                committed_at INTEGER,
                PRIMARY KEY (tenant_id, fence_id),
                UNIQUE (tenant_id, request_id)
            );

            CREATE TABLE IF NOT EXISTS security_declassification_uses (
                grant_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                state TEXT NOT NULL,
                consumed_at INTEGER NOT NULL,
                transition_id TEXT,
                PRIMARY KEY (tenant_id, grant_id)
            );

            CREATE TABLE IF NOT EXISTS security_event_ids (
                event_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                event_class TEXT NOT NULL,
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_verified_events (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                producer_id TEXT NOT NULL,
                trust_class TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE INDEX IF NOT EXISTS security_verified_event_partition
                ON security_verified_events (tenant_id, event_time, event_id);

            CREATE TABLE IF NOT EXISTS security_advisory_events (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                producer_id TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_events (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                event_id TEXT NOT NULL,
                transition_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash, event_id),
                UNIQUE (tenant_id, rule_id, event_id),
                UNIQUE (tenant_id, transition_id),
                FOREIGN KEY (tenant_id, event_id)
                    REFERENCES security_verified_events (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_partition_heads (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_partials (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                generation INTEGER NOT NULL,
                watermark INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                transition_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash),
                UNIQUE (tenant_id, transition_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_plans (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                due_at INTEGER,
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_approvals (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                approval_set_hash BLOB NOT NULL CHECK (length(approval_set_hash) = 32),
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (tenant_id, action_id),
                UNIQUE (tenant_id, reservation_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_effects (
                effect_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                scheduler_fencing_token INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                encrypted_rollback_ref TEXT,
                PRIMARY KEY (tenant_id, effect_id),
                FOREIGN KEY (encrypted_rollback_ref) REFERENCES chio_encrypted_blobs (blob_id)
            );

            CREATE TABLE IF NOT EXISTS security_effect_contributions (
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                posture_rank INTEGER NOT NULL,
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER,
                PRIMARY KEY (tenant_id, target_id, effect_id),
                UNIQUE (tenant_id, effect_id)
            );

            CREATE TABLE IF NOT EXISTS security_overlay_state (
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                effective_posture_rank INTEGER NOT NULL,
                highest_fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, target_id)
            );

            CREATE TABLE IF NOT EXISTS security_lineage_fences (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                commit_index INTEGER NOT NULL,
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                fencing_token INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_claims (
                tenant_id TEXT NOT NULL,
                claim_id TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                result_count INTEGER NOT NULL,
                committed_at INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, claim_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_leases (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                claim_id TEXT NOT NULL,
                claim_ordinal INTEGER NOT NULL,
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE INDEX IF NOT EXISTS security_scheduler_leases_claim
                ON security_scheduler_leases (tenant_id, claim_id, action_id);

            CREATE TABLE IF NOT EXISTS security_scheduler_fence_sequences (
                tenant_id TEXT NOT NULL,
                last_fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_retries (
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                first_failure_at INTEGER NOT NULL,
                not_before INTEGER NOT NULL,
                health_event_id TEXT,
                health_event_delivered INTEGER NOT NULL CHECK (health_event_delivered IN (0, 1)),
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_transitions (
                transition_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                transition_kind TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                PRIMARY KEY (tenant_id, transition_id)
            );
            "#,
        )
        .map_err(sqlite_error)?;
    ensure_response_effect_generation_column(connection)?;
    ensure_scheduler_retry_health_columns(connection)?;
    Ok(())
}

fn ensure_response_effect_generation_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_response_effects)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut generation_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        if name == "generation" {
            generation_exists = true;
            break;
        }
    }
    drop(rows);
    drop(statement);
    if !generation_exists {
        connection
            .execute(
                "ALTER TABLE security_response_effects ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn ensure_scheduler_retry_health_columns(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_scheduler_retries)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut first_failure_exists = false;
    let mut health_event_id_exists = false;
    let mut health_event_delivered_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        match name.as_str() {
            "first_failure_at" => first_failure_exists = true,
            "health_event_id" => health_event_id_exists = true,
            "health_event_delivered" => health_event_delivered_exists = true,
            _ => {}
        }
    }
    drop(rows);
    drop(statement);
    if !first_failure_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN first_failure_at INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_id_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_id TEXT",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_delivered_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_delivered INTEGER NOT NULL DEFAULT 0 CHECK (health_event_delivered IN (0, 1))",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn sqlite_error(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            PortError::conflict()
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..) => PortError::integrity_failure(),
        rusqlite::Error::ToSqlConversionFailure(_) => PortError::invalid_data(),
        _ => PortError::unavailable(),
    }
}

fn to_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn from_i64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

fn now_unix_ms() -> PortResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PortError::unavailable())?;
    u64::try_from(duration.as_millis()).map_err(|_| PortError::unavailable())
}

fn body_hash(body: &[u8]) -> [u8; 32] {
    let hash = sha256(body);
    let mut result = [0_u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn validate_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    if body_hash(body.as_bytes()).as_slice() != expected.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_canonical_json_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    validate_body(body, expected)?;
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn decode_digest(bytes: Vec<u8>) -> PortResult<Digest32> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Digest32::new(value))
}

fn canonical_request_hash<T: serde::Serialize>(value: &T) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    Ok(body_hash(canonical.as_ref()))
}

fn validate_encrypted_blob_reference(
    connection: &Connection,
    tenant_id: &str,
    reference: &RecordId,
) -> PortResult<()> {
    let lengths: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT length(nonce), length(ciphertext) FROM chio_encrypted_blobs
            WHERE blob_id = ?1 AND tenant_id = ?2
            "#,
            params![reference.as_str(), tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((nonce_length, ciphertext_length)) = lengths else {
        return Err(PortError::invalid_data());
    };
    if nonce_length != 12 || ciphertext_length < 16 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn encode_label(label: &InformationLabel) -> PortResult<(Vec<u8>, [u8; 32])> {
    let body = canonical_json_bytes(label).map_err(|_| PortError::invalid_data())?;
    let hash = body_hash(body.as_ref());
    Ok((body, hash))
}

fn decode_label(body: Vec<u8>, stored_hash: Vec<u8>) -> PortResult<InformationLabel> {
    let hash = decode_digest(stored_hash)?;
    if body_hash(&body).as_slice() != hash.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    let label: InformationLabel =
        serde_json::from_slice(&body).map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&label).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_slice() {
        return Err(PortError::integrity_failure());
    }
    Ok(label)
}

fn transition_status(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    let existing: Option<(String, String, Vec<u8>)> = transaction
        .query_row(
            "SELECT tenant_id, transition_kind, request_hash FROM security_transitions WHERE tenant_id = ?1 AND transition_id = ?2",
            params![tenant_id, transition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((existing_tenant, existing_kind, existing_hash)) = existing {
        if existing_tenant == tenant_id
            && existing_kind == kind
            && existing_hash.as_slice() == request_hash
        {
            return Ok(true);
        }
        return Err(PortError::conflict());
    }
    Ok(false)
}

fn record_transition(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    transaction
        .execute(
            "INSERT INTO security_transitions (transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4)",
            params![transition_id, tenant_id, kind, request_hash.as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredLabel = (Vec<u8>, Vec<u8>, i64);

fn load_principal_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_principal_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_lineage_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_lineage_flow_state
            WHERE tenant_id = ?1 AND lineage_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_session_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_session_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2
              AND session_id = ?3 AND isolation_epoch_id = ?4
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_context_generation(connection: &Connection, key: &FlowStateKey) -> PortResult<Option<u64>> {
    let generation: Option<i64> = connection
        .query_row(
            r#"
            SELECT generation FROM security_flow_contexts
            WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    generation.map(from_i64).transpose()
}

fn session_membership_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_session_memberships
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn isolation_epoch_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn load_flow_snapshot(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<FlowStateSnapshot>> {
    let epoch_exists = isolation_epoch_exists(connection, key)?;
    let principal = load_principal_label(connection, key)?;
    let lineage = load_lineage_label(connection, key)?;
    let session = load_session_label(connection, key)?;
    let session_membership = session_membership_exists(connection, key)?;
    let context_generation = load_context_generation(connection, key)?;
    if !epoch_exists {
        if principal.is_some()
            || session.is_some()
            || session_membership
            || context_generation.is_some()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(None);
    }
    if session.is_some() != session_membership {
        return Err(PortError::integrity_failure());
    }
    let (principal_label, principal_generation) =
        principal.ok_or_else(PortError::integrity_failure)?;
    let (lineage_label, lineage_generation) = lineage.ok_or_else(PortError::integrity_failure)?;
    let Some(context_generation) = context_generation else {
        if session.is_some() {
            return Err(PortError::integrity_failure());
        }
        let session_label = principal_label
            .join_restrictions(&lineage_label)
            .map_err(|_| PortError::integrity_failure())?;
        return Ok(Some(FlowStateSnapshot {
            key: key.clone(),
            principal_label,
            lineage_label,
            session_label,
            context_generation: principal_generation.max(lineage_generation),
        }));
    };
    let (stored_session_label, session_generation) =
        session.ok_or_else(PortError::integrity_failure)?;
    if principal_generation > context_generation
        || lineage_generation > context_generation
        || session_generation > context_generation
    {
        return Err(PortError::integrity_failure());
    }
    let session_label = stored_session_label
        .join_restrictions(&principal_label)
        .and_then(|label| label.join_restrictions(&lineage_label))
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Some(FlowStateSnapshot {
        key: key.clone(),
        principal_label,
        lineage_label,
        session_label,
        context_generation,
    }))
}

fn next_flow_generation(transaction: &Transaction<'_>, tenant_id: &str) -> PortResult<u64> {
    let sequence_generation: Option<i64> = transaction
        .query_row(
            "SELECT last_generation FROM security_flow_sequences WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored_generation: Option<i64> = transaction
        .query_row(
            r#"
            SELECT MAX(generation) FROM (
                SELECT generation FROM security_principal_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_lineage_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_session_flow_state WHERE tenant_id = ?1
                UNION ALL
                SELECT generation FROM security_flow_contexts WHERE tenant_id = ?1
            )
            "#,
            params![tenant_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = sequence_generation
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(stored_generation.map(from_i64).transpose()?.unwrap_or(0));
    let next = current
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_flow_sequences (tenant_id, last_generation)
            VALUES (?1, ?2)
            ON CONFLICT (tenant_id) DO UPDATE SET last_generation = excluded.last_generation
            "#,
            params![tenant_id, to_i64(next)?],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn invalidate_related_flow_contexts(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    generation: u64,
    principal_changed: bool,
    lineage_changed: bool,
    session_changed: bool,
) -> PortResult<()> {
    let generation = to_i64(generation)?;
    if principal_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?4
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    if lineage_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?3
                WHERE tenant_id = ?1 AND lineage_id = ?2
                "#,
                params![key.tenant_id.as_str(), key.lineage_id.as_str(), generation],
            )
            .map_err(sqlite_error)?;
    }
    if session_changed {
        transaction
            .execute(
                r#"
                UPDATE security_flow_contexts SET generation = ?5
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
                "#,
                params![
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.session_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                    generation
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn store_principal_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_principal_flow_state (
                tenant_id, principal_id, isolation_epoch_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (tenant_id, principal_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_lineage_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_lineage_flow_state (
                tenant_id, lineage_id, label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (tenant_id, lineage_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.lineage_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_session_label(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    label: &InformationLabel,
    generation: u64,
) -> PortResult<()> {
    let (body, hash) = encode_label(label)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_session_memberships (
                tenant_id, principal_id, session_id, isolation_epoch_id
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO NOTHING
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_session_flow_state (
                tenant_id, principal_id, session_id, isolation_epoch_id,
                label_json, label_hash, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (tenant_id, principal_id, session_id, isolation_epoch_id) DO UPDATE SET
                label_json = excluded.label_json,
                label_hash = excluded.label_hash,
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                body,
                hash.as_slice(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn store_context_generation(
    transaction: &Transaction<'_>,
    key: &FlowStateKey,
    generation: u64,
) -> PortResult<()> {
    transaction
        .execute(
            r#"
            INSERT INTO security_flow_contexts (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id, generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (
                tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
            )
            DO UPDATE SET generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
                to_i64(generation)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn ensure_epoch_for_join(
    transaction: &Transaction<'_>,
    request: &FlowJoinRequest,
) -> PortResult<()> {
    let exact: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.lineage_id.as_str(),
                request.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if exact {
        if load_principal_label(transaction, &request.key)?.is_none()
            || load_lineage_label(transaction, &request.key)?.is_none()
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(());
    }

    let principal_epoch_exists: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            )
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if principal_epoch_exists {
        if load_principal_label(transaction, &request.key)?.is_none() {
            return Err(PortError::integrity_failure());
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                )
                SELECT tenant_id, principal_id, ?3, isolation_epoch_id,
                       previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                       evidence_receipt_ref, ?5, effective_at
                FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?4
                ORDER BY lineage_id
                LIMIT 1
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.principal_id.as_str(),
                    request.key.lineage_id.as_str(),
                    request.key.isolation_epoch_id.as_str(),
                    request.transition_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(PortError::integrity_failure());
        }
        return Ok(());
    }
    let prior_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM security_isolation_epochs WHERE tenant_id = ?1 AND principal_id = ?2",
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if prior_count != 0 {
        return Err(PortError::invalid_data());
    }
    transaction
        .execute(
            r#"
            INSERT INTO security_isolation_epochs (
                tenant_id, principal_id, lineage_id, isolation_epoch_id,
                previous_isolation_epoch_id, evidence_hash, transition_id, effective_at
            ) VALUES (?1, ?2, ?3, ?4, NULL, zeroblob(32), ?5, 0)
            "#,
            params![
                request.key.tenant_id.as_str(),
                request.key.principal_id.as_str(),
                request.key.lineage_id.as_str(),
                request.key.isolation_epoch_id.as_str(),
                request.transition_id.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

impl FlowStateStore for SqliteSecurityStateStore {
    fn load(&self, key: &FlowStateKey) -> PortResult<Option<FlowStateSnapshot>> {
        let connection = self.connection()?;
        load_flow_snapshot(&connection, key)
    }

    fn join(&self, request: &FlowJoinRequest) -> PortResult<FlowStateSnapshot> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "flow_join",
            &request_hash,
        )? {
            let snapshot = load_flow_snapshot(&transaction, &request.key)?
                .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        ensure_epoch_for_join(&transaction, request)?;
        let principal_stored = load_principal_label(&transaction, &request.key)?;
        let lineage_stored = load_lineage_label(&transaction, &request.key)?;
        let session_stored = load_session_label(&transaction, &request.key)?;
        let session_membership = session_membership_exists(&transaction, &request.key)?;
        let context_stored = load_context_generation(&transaction, &request.key)?;
        if session_stored.is_some() != session_membership
            || context_stored.is_some()
                && (principal_stored.is_none()
                    || lineage_stored.is_none()
                    || session_stored.is_none())
        {
            return Err(PortError::integrity_failure());
        }
        let principal_current = principal_stored
            .as_ref()
            .map(|value| value.0.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let lineage_current = lineage_stored
            .as_ref()
            .map(|value| value.0.clone())
            .unwrap_or_else(InformationLabel::bottom);
        let session_current = match session_stored.as_ref() {
            Some(value) => value.0.clone(),
            None => principal_current
                .join_restrictions(&lineage_current)
                .map_err(|_| PortError::invalid_data())?,
        };
        let principal_label = principal_current
            .join_restrictions(&request.principal_join)
            .map_err(|_| PortError::invalid_data())?;
        let lineage_label = lineage_current
            .join_restrictions(&request.lineage_join)
            .map_err(|_| PortError::invalid_data())?;
        let session_label = session_current
            .join_restrictions(&request.session_join)
            .and_then(|label| label.join_restrictions(&principal_label))
            .and_then(|label| label.join_restrictions(&lineage_label))
            .map_err(|_| PortError::invalid_data())?;
        let principal_changed = principal_label != principal_current;
        let lineage_changed = lineage_label != lineage_current;
        let session_changed = session_label != session_current;
        let generation = next_flow_generation(&transaction, request.key.tenant_id.as_str())?;
        invalidate_related_flow_contexts(
            &transaction,
            &request.key,
            generation,
            principal_changed,
            lineage_changed,
            session_changed,
        )?;
        if principal_stored.is_none() || principal_changed {
            store_principal_label(&transaction, &request.key, &principal_label, generation)?;
        }
        if lineage_stored.is_none() || lineage_changed {
            store_lineage_label(&transaction, &request.key, &lineage_label, generation)?;
        }
        if session_stored.is_none() || session_changed {
            store_session_label(&transaction, &request.key, &session_label, generation)?;
        }
        store_context_generation(&transaction, &request.key, generation)?;
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "flow_join",
            &request_hash,
        )?;
        let snapshot = FlowStateSnapshot {
            key: request.key.clone(),
            principal_label,
            lineage_label,
            session_label,
            context_generation: generation,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn open_isolation_epoch(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<FlowStateSnapshot> {
        if transition.previous_isolation_epoch_id == transition.new_isolation_epoch_id
            || transition
                .verification_evidence_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(transition)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            transition.tenant_id.as_str(),
            transition.transition_id.as_str(),
            "isolation_epoch",
            &request_hash,
        )? {
            let key = FlowStateKey {
                tenant_id: transition.tenant_id.clone(),
                principal_id: transition.principal_id.clone(),
                lineage_id: transition.lineage_id.clone(),
                session_id: transition.new_session_id.clone(),
                isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            };
            let snapshot =
                load_flow_snapshot(&transaction, &key)?.ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(snapshot);
        }
        let verified_evidence = self.isolation_epoch_verifier.verify(transition)?;
        let prior_key = FlowStateKey {
            tenant_id: transition.tenant_id.clone(),
            principal_id: transition.principal_id.clone(),
            lineage_id: transition.lineage_id.clone(),
            session_id: transition.new_session_id.clone(),
            isolation_epoch_id: transition.previous_isolation_epoch_id.clone(),
        };
        if load_principal_label(&transaction, &prior_key)?.is_none() {
            return Err(PortError::invalid_data());
        }
        let key = FlowStateKey {
            isolation_epoch_id: transition.new_isolation_epoch_id.clone(),
            ..prior_key
        };
        if load_principal_label(&transaction, &key)?.is_some() {
            return Err(PortError::conflict());
        }
        let lineage_label = load_lineage_label(&transaction, &key)?
            .map(|value| value.0)
            .ok_or_else(PortError::integrity_failure)?;
        let generation = next_flow_generation(&transaction, transition.tenant_id.as_str())?;
        let principal_label = InformationLabel::bottom();
        let session_label = lineage_label.clone();
        transaction
            .execute(
                r#"
                INSERT INTO security_isolation_epochs (
                    tenant_id, principal_id, lineage_id, isolation_epoch_id,
                    previous_isolation_epoch_id, evidence_hash, evidence_verifier_id,
                    evidence_receipt_ref, transition_id, effective_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    transition.tenant_id.as_str(),
                    transition.principal_id.as_str(),
                    transition.lineage_id.as_str(),
                    transition.new_isolation_epoch_id.as_str(),
                    transition.previous_isolation_epoch_id.as_str(),
                    transition.verification_evidence_hash.as_bytes().as_slice(),
                    verified_evidence.verifier_id.as_str(),
                    verified_evidence.receipt_ref.as_str(),
                    transition.transition_id.as_str(),
                    to_i64(transition.effective_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        store_principal_label(&transaction, &key, &principal_label, generation)?;
        store_session_label(&transaction, &key, &session_label, generation)?;
        store_context_generation(&transaction, &key, generation)?;
        record_transition(
            &transaction,
            transition.tenant_id.as_str(),
            transition.transition_id.as_str(),
            "isolation_epoch",
            &request_hash,
        )?;
        let snapshot = FlowStateSnapshot {
            key,
            principal_label,
            lineage_label,
            session_label,
            context_generation: generation,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn acquire_egress_fence(&self, request: &EgressFenceRequest) -> PortResult<EgressFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let snapshot =
            load_flow_snapshot(&transaction, &request.key)?.ok_or_else(PortError::invalid_data)?;
        if snapshot.context_generation != request.expected_context_generation
            || request.expires_at_unix_ms <= now_unix_ms()?
        {
            return Err(PortError::conflict());
        }
        let fence_hash = canonical_request_hash(request)?;
        let fence_id = RecordId::new(format!("ef:{}", hex::encode(fence_hash)))
            .map_err(|_| PortError::invalid_data())?;
        let existing: Option<(String, Vec<u8>, i64, i64)> = transaction
            .query_row(
                "SELECT fence_id, request_hash, context_generation, expires_at FROM security_egress_fences WHERE tenant_id = ?1 AND request_id = ?2",
                params![request.key.tenant_id.as_str(), request.request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((stored_id, stored_hash, stored_generation, stored_expiry)) = existing {
            if stored_id != fence_id.as_str()
                || decode_digest(stored_hash)? != request.request_hash
                || from_i64(stored_generation)? != request.expected_context_generation
                || from_i64(stored_expiry)? != request.expires_at_unix_ms
            {
                return Err(PortError::conflict());
            }
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO security_egress_fences (
                        fence_id, tenant_id, principal_id, lineage_id, session_id,
                        isolation_epoch_id, request_id, request_hash, context_generation, expires_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                    params![
                        fence_id.as_str(),
                        request.key.tenant_id.as_str(),
                        request.key.principal_id.as_str(),
                        request.key.lineage_id.as_str(),
                        request.key.session_id.as_str(),
                        request.key.isolation_epoch_id.as_str(),
                        request.request_id.as_str(),
                        request.request_hash.as_bytes().as_slice(),
                        to_i64(request.expected_context_generation)?,
                        to_i64(request.expires_at_unix_ms)?
                    ],
                )
                .map_err(sqlite_error)?;
        }
        let fence = EgressFence {
            fence_id,
            key: request.key.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash,
            context_generation: request.expected_context_generation,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn validate_egress_fence(&self, fence: &EgressFence) -> PortResult<()> {
        let connection = self.connection()?;
        validate_fence(&connection, fence)
    }

    fn commit_egress_fence(
        &self,
        commitment: &EgressFenceCommit,
    ) -> PortResult<CommittedEgressFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        type StoredFenceCommitment = (
            String,
            String,
            String,
            String,
            String,
            Vec<u8>,
            i64,
            i64,
            Option<String>,
            Option<i64>,
        );
        let existing: Option<StoredFenceCommitment> = transaction
            .query_row(
                r#"
                SELECT principal_id, lineage_id, session_id, isolation_epoch_id, request_id,
                       request_hash, context_generation, expires_at, dispatch_commitment_id, committed_at
                FROM security_egress_fences WHERE tenant_id = ?1 AND fence_id = ?2
                "#,
                params![
                    commitment.fence.key.tenant_id.as_str(),
                    commitment.fence.fence_id.as_str()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let existing = existing.ok_or_else(PortError::invalid_data)?;
        if existing.0 != commitment.fence.key.principal_id.as_str()
            || existing.1 != commitment.fence.key.lineage_id.as_str()
            || existing.2 != commitment.fence.key.session_id.as_str()
            || existing.3 != commitment.fence.key.isolation_epoch_id.as_str()
            || existing.4 != commitment.fence.request_id.as_str()
            || decode_digest(existing.5.clone())? != commitment.fence.request_hash
            || from_i64(existing.6)? != commitment.fence.context_generation
            || from_i64(existing.7)? != commitment.fence.expires_at_unix_ms
        {
            return Err(PortError::conflict());
        }
        if let Some(existing_id) = existing.8 {
            let existing_time = existing
                .9
                .ok_or_else(PortError::integrity_failure)
                .and_then(from_i64)?;
            if existing_id != commitment.dispatch_commitment_id.as_str()
                || existing_time != commitment.committed_at_unix_ms
            {
                return Err(PortError::conflict());
            }
            let committed = CommittedEgressFence {
                fence_id: commitment.fence.fence_id.clone(),
                request_id: commitment.fence.request_id.clone(),
                request_hash: commitment.fence.request_hash,
                context_generation: commitment.fence.context_generation,
                dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
                committed_at_unix_ms: commitment.committed_at_unix_ms,
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(committed);
        }
        if existing.9.is_some() {
            return Err(PortError::integrity_failure());
        }
        validate_fence(&transaction, &commitment.fence)?;
        let trusted_now = now_unix_ms()?;
        if commitment.committed_at_unix_ms > commitment.fence.expires_at_unix_ms
            || commitment.committed_at_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
        {
            return Err(PortError::invalid_data());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_egress_fences
                SET dispatch_commitment_id = ?2, committed_at = ?3
                WHERE fence_id = ?1 AND tenant_id = ?4
                  AND dispatch_commitment_id IS NULL
                "#,
                params![
                    commitment.fence.fence_id.as_str(),
                    commitment.dispatch_commitment_id.as_str(),
                    to_i64(commitment.committed_at_unix_ms)?,
                    commitment.fence.key.tenant_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        let committed = CommittedEgressFence {
            fence_id: commitment.fence.fence_id.clone(),
            request_id: commitment.fence.request_id.clone(),
            request_hash: commitment.fence.request_hash,
            context_generation: commitment.fence.context_generation,
            dispatch_commitment_id: commitment.dispatch_commitment_id.clone(),
            committed_at_unix_ms: commitment.committed_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(committed)
    }
}

fn validate_fence(connection: &Connection, fence: &EgressFence) -> PortResult<()> {
    type StoredFence = (
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        i64,
        i64,
    );
    let stored: Option<StoredFence> = connection
        .query_row(
            r#"
            SELECT tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id,
                   request_id, request_hash, context_generation, expires_at
            FROM security_egress_fences WHERE tenant_id = ?1 AND fence_id = ?2
            "#,
            params![fence.key.tenant_id.as_str(), fence.fence_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        tenant,
        principal,
        lineage,
        session,
        epoch,
        request,
        request_hash,
        generation,
        expiry,
    )) = stored
    else {
        return Err(PortError::invalid_data());
    };
    if tenant != fence.key.tenant_id.as_str()
        || principal != fence.key.principal_id.as_str()
        || lineage != fence.key.lineage_id.as_str()
        || session != fence.key.session_id.as_str()
        || epoch != fence.key.isolation_epoch_id.as_str()
        || request != fence.request_id.as_str()
        || decode_digest(request_hash)? != fence.request_hash
        || from_i64(generation)? != fence.context_generation
        || from_i64(expiry)? != fence.expires_at_unix_ms
        || fence.expires_at_unix_ms <= now_unix_ms()?
    {
        return Err(PortError::conflict());
    }
    let current =
        load_flow_snapshot(connection, &fence.key)?.ok_or_else(PortError::integrity_failure)?;
    if current.context_generation != fence.context_generation {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn declassification_state_name(state: DeclassificationUseState) -> &'static str {
    match state {
        DeclassificationUseState::ConsumedPendingDispatch => "consumed_pending_dispatch",
        DeclassificationUseState::Released => "released",
        DeclassificationUseState::DispatchFailed => "dispatch_failed",
    }
}

fn parse_declassification_state(value: &str) -> PortResult<DeclassificationUseState> {
    match value {
        "consumed_pending_dispatch" => Ok(DeclassificationUseState::ConsumedPendingDispatch),
        "released" => Ok(DeclassificationUseState::Released),
        "dispatch_failed" => Ok(DeclassificationUseState::DispatchFailed),
        _ => Err(PortError::integrity_failure()),
    }
}

impl DeclassificationUseStore for SqliteSecurityStateStore {
    fn consume(
        &self,
        request: &DeclassificationConsumeRequest,
    ) -> PortResult<DeclassificationConsume> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing: Option<(String, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT tenant_id, request_hash, state FROM security_declassification_uses WHERE tenant_id = ?1 AND grant_id = ?2",
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((tenant_id, request_hash, state)) = existing {
            if tenant_id != request.tenant_id.as_str() {
                return Err(PortError::conflict());
            }
            let request_hash = decode_digest(request_hash)?;
            if request_hash != request.request_hash {
                return Err(PortError::conflict());
            }
            let outcome = DeclassificationConsume::AlreadyConsumed {
                request_hash,
                state: parse_declassification_state(&state)?,
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(outcome);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_declassification_uses (
                    grant_id, tenant_id, request_hash, state, consumed_at
                ) VALUES (?1, ?2, ?3, 'consumed_pending_dispatch', ?4)
                "#,
                params![
                    request.grant_id.as_str(),
                    request.tenant_id.as_str(),
                    request.request_hash.as_bytes().as_slice(),
                    to_i64(request.consumed_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(DeclassificationConsume::Consumed)
    }

    fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()> {
        if request.expected_state != DeclassificationUseState::ConsumedPendingDispatch
            || !matches!(
                request.new_state,
                DeclassificationUseState::Released | DeclassificationUseState::DispatchFailed
            )
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.tenant_id.as_str(),
            request.transition_id.as_str(),
            "declassification_outcome",
            &request_hash,
        )? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let current: Option<(String, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT tenant_id, request_hash, state FROM security_declassification_uses WHERE tenant_id = ?1 AND grant_id = ?2",
                params![request.tenant_id.as_str(), request.grant_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((tenant_id, stored_hash, state)) = current else {
            return Err(PortError::invalid_data());
        };
        if tenant_id != request.tenant_id.as_str()
            || decode_digest(stored_hash)? != request.request_hash
            || parse_declassification_state(&state)? != request.expected_state
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_declassification_uses
                SET state = ?4, transition_id = ?5
                WHERE grant_id = ?1 AND tenant_id = ?2 AND request_hash = ?3
                  AND state = 'consumed_pending_dispatch'
                "#,
                params![
                    request.grant_id.as_str(),
                    request.tenant_id.as_str(),
                    request.request_hash.as_bytes().as_slice(),
                    declassification_state_name(request.new_state),
                    request.transition_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.tenant_id.as_str(),
            request.transition_id.as_str(),
            "declassification_outcome",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

fn load_lineage_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<(LineageFence, bool)>> {
    type StoredFence = (String, i64, Vec<u8>, i64, i64, String);
    let stored: Option<StoredFence> = connection
        .query_row(
            r#"
            SELECT tenant_id, commit_index, affected_set_hash, fencing_token, expires_at, state
            FROM security_lineage_fences WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(tenant_id, commit_index, affected_set_hash, fencing_token, expires_at, state)| {
                let active = match state.as_str() {
                    "active" => true,
                    "released" => false,
                    _ => return Err(PortError::integrity_failure()),
                };
                Ok((
                    LineageFence {
                        tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        action_id: ActionId::new(action_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        commit_index: from_i64(commit_index)?,
                        affected_set_hash: decode_digest(affected_set_hash)?,
                        fencing_token: from_i64(fencing_token)?,
                        expires_at_unix_ms: from_i64(expires_at)?,
                    },
                    active,
                ))
            },
        )
        .transpose()
}

impl LineageFenceStore for SqliteSecurityStateStore {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let trusted_now = now_unix_ms()?;
        if request.expires_at_unix_ms <= trusted_now {
            return Err(PortError::invalid_data());
        }
        let existing = load_lineage_fence(
            &transaction,
            request.tenant_id.as_str(),
            request.action_id.as_str(),
        )?;
        let fencing_token = if let Some((existing, active)) = existing.as_ref() {
            if !active {
                return Err(PortError::conflict());
            }
            if existing.commit_index != request.expected_commit_index
                || existing.affected_set_hash != request.expected_affected_set_hash
            {
                return Err(PortError::conflict());
            }
            if existing.expires_at_unix_ms > trusted_now {
                if existing.expires_at_unix_ms != request.expires_at_unix_ms {
                    return Err(PortError::conflict());
                }
                transaction.commit().map_err(sqlite_error)?;
                return Ok(existing.clone());
            }
            existing
                .fencing_token
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        } else {
            1
        };
        transaction
            .execute(
                r#"
                INSERT INTO security_lineage_fences (
                    action_id, tenant_id, commit_index, affected_set_hash,
                    fencing_token, expires_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active')
                ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                    fencing_token = excluded.fencing_token,
                    expires_at = excluded.expires_at,
                    state = 'active'
                "#,
                params![
                    request.action_id.as_str(),
                    request.tenant_id.as_str(),
                    to_i64(request.expected_commit_index)?,
                    request.expected_affected_set_hash.as_bytes().as_slice(),
                    to_i64(fencing_token)?,
                    to_i64(request.expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        let fence = LineageFence {
            tenant_id: request.tenant_id.clone(),
            action_id: request.action_id.clone(),
            commit_index: request.expected_commit_index,
            affected_set_hash: request.expected_affected_set_hash,
            fencing_token,
            expires_at_unix_ms: request.expires_at_unix_ms,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(fence)
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        let connection = self.connection()?;
        let stored =
            load_lineage_fence(&connection, action.tenant_id.as_str(), action.id.as_str())?;
        let trusted_now = now_unix_ms()?;
        let Some((fence, active)) = stored else {
            return Ok(None);
        };
        if !active || fence.expires_at_unix_ms <= trusted_now {
            return Ok(None);
        }
        Ok(Some(fence))
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let existing = load_lineage_fence(
            &transaction,
            release.tenant_id.as_str(),
            release.action_id.as_str(),
        )?;
        let Some((existing, active)) = existing else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        };
        if existing.fencing_token != release.fencing_token {
            return Err(PortError::conflict());
        }
        if !active {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        if existing.expires_at_unix_ms <= now_unix_ms()? {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                "UPDATE security_lineage_fences SET state = 'released', expires_at = 0 WHERE tenant_id = ?1 AND action_id = ?2 AND fencing_token = ?3 AND state = 'active'",
                params![
                    release.tenant_id.as_str(),
                    release.action_id.as_str(),
                    to_i64(release.fencing_token)?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

fn approval_reservation_state_name(value: ApprovalReservationState) -> &'static str {
    match value {
        ApprovalReservationState::Reserved => "reserved",
        ApprovalReservationState::Committed => "committed",
        ApprovalReservationState::Cancelled => "cancelled",
    }
}

fn parse_approval_reservation_state(value: &str) -> PortResult<ApprovalReservationState> {
    match value {
        "reserved" => Ok(ApprovalReservationState::Reserved),
        "committed" => Ok(ApprovalReservationState::Committed),
        "cancelled" => Ok(ApprovalReservationState::Cancelled),
        _ => Err(PortError::integrity_failure()),
    }
}

fn load_approval_reservation(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<StoredApprovalReservation>> {
    type StoredApproval = (String, String, Vec<u8>, i64, String);
    let stored: Option<StoredApproval> = connection
        .query_row(
            r#"
            SELECT tenant_id, reservation_id, approval_set_hash, expires_at, state
            FROM security_response_approvals WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
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
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(tenant_id, reservation_id, approval_set_hash, expires_at, state)| {
                Ok(StoredApprovalReservation {
                    reservation: chio_security_types::ports::ApprovalReservation {
                        tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        action_id: ActionId::new(action_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        reservation_id: RecordId::new(reservation_id)
                            .map_err(|_| PortError::integrity_failure())?,
                        approval_set_hash: decode_digest(approval_set_hash)?,
                        expires_at_unix_ms: from_i64(expires_at)?,
                    },
                    state: parse_approval_reservation_state(&state)?,
                })
            },
        )
        .transpose()
}

impl ApprovalReservationStore for SqliteSecurityStateStore {
    fn reserve(&self, request: &ApprovalReservationCreate) -> PortResult<CreateOutcome> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.reservation.tenant_id.as_str(),
            request.transition_id.as_str(),
            "approval_reserve",
            &request_hash,
        )? {
            let stored = load_approval_reservation(
                &transaction,
                request.reservation.tenant_id.as_str(),
                request.reservation.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if stored.reservation != request.reservation {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        if request.reservation.expires_at_unix_ms <= now_unix_ms()? {
            return Err(PortError::invalid_data());
        }
        if let Some(stored) = load_approval_reservation(
            &transaction,
            request.reservation.tenant_id.as_str(),
            request.reservation.action_id.as_str(),
        )? {
            if stored.reservation != request.reservation
                || stored.state != ApprovalReservationState::Reserved
            {
                return Err(PortError::conflict());
            }
            record_transition(
                &transaction,
                request.reservation.tenant_id.as_str(),
                request.transition_id.as_str(),
                "approval_reserve",
                &request_hash,
            )?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_approvals (
                    action_id, tenant_id, reservation_id, approval_set_hash, expires_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'reserved')
                "#,
                params![
                    request.reservation.action_id.as_str(),
                    request.reservation.tenant_id.as_str(),
                    request.reservation.reservation_id.as_str(),
                    request.reservation.approval_set_hash.as_bytes().as_slice(),
                    to_i64(request.reservation.expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        record_transition(
            &transaction,
            request.reservation.tenant_id.as_str(),
            request.transition_id.as_str(),
            "approval_reserve",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn load_reservation(
        &self,
        action: &TenantScopedId,
    ) -> PortResult<Option<StoredApprovalReservation>> {
        let connection = self.connection()?;
        load_approval_reservation(&connection, action.tenant_id.as_str(), action.id.as_str())
    }

    fn commit_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()> {
        mutate_approval_reservation(self, mutation, ApprovalReservationState::Committed)
    }

    fn cancel_reservation(&self, mutation: &ApprovalReservationMutation) -> PortResult<()> {
        mutate_approval_reservation(self, mutation, ApprovalReservationState::Cancelled)
    }
}

fn mutate_approval_reservation(
    store: &SqliteSecurityStateStore,
    mutation: &ApprovalReservationMutation,
    new_state: ApprovalReservationState,
) -> PortResult<()> {
    let request_hash = canonical_request_hash(mutation)?;
    let transition_kind = match new_state {
        ApprovalReservationState::Committed => "approval_commit",
        ApprovalReservationState::Cancelled => "approval_cancel",
        ApprovalReservationState::Reserved => return Err(PortError::invalid_data()),
    };
    let mut connection = store.connection()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    if transition_status(
        &transaction,
        mutation.reservation.tenant_id.as_str(),
        mutation.transition_id.as_str(),
        transition_kind,
        &request_hash,
    )? {
        let stored = load_approval_reservation(
            &transaction,
            mutation.reservation.tenant_id.as_str(),
            mutation.reservation.action_id.as_str(),
        )?
        .ok_or_else(PortError::integrity_failure)?;
        if stored.reservation != mutation.reservation || stored.state != new_state {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        return Ok(());
    }
    let stored = load_approval_reservation(
        &transaction,
        mutation.reservation.tenant_id.as_str(),
        mutation.reservation.action_id.as_str(),
    )?
    .ok_or_else(PortError::invalid_data)?;
    if stored.reservation != mutation.reservation
        || stored.state != ApprovalReservationState::Reserved
        || new_state == ApprovalReservationState::Committed
            && stored.reservation.expires_at_unix_ms <= now_unix_ms()?
    {
        return Err(PortError::conflict());
    }
    let updated = transaction
        .execute(
            r#"
            UPDATE security_response_approvals SET state = ?3
            WHERE tenant_id = ?1 AND action_id = ?2 AND state = 'reserved'
            "#,
            params![
                mutation.reservation.tenant_id.as_str(),
                mutation.reservation.action_id.as_str(),
                approval_reservation_state_name(new_state)
            ],
        )
        .map_err(sqlite_error)?;
    if updated != 1 {
        return Err(PortError::conflict());
    }
    record_transition(
        &transaction,
        mutation.reservation.tenant_id.as_str(),
        mutation.transition_id.as_str(),
        transition_kind,
        &request_hash,
    )?;
    transaction.commit().map_err(sqlite_error)?;
    Ok(())
}

fn trust_class_name(value: ProducerTrustClass) -> &'static str {
    match value {
        ProducerTrustClass::InternalDetector => "internal_detector",
        ProducerTrustClass::VerifiedReceipt => "verified_receipt",
    }
}

fn parse_trust_class(value: &str) -> PortResult<ProducerTrustClass> {
    match value {
        "internal_detector" => Ok(ProducerTrustClass::InternalDetector),
        "verified_receipt" => Ok(ProducerTrustClass::VerifiedReceipt),
        _ => Err(PortError::integrity_failure()),
    }
}

impl SecurityEventStore for SqliteSecurityStateStore {
    fn append_verified(&self, event: &VerifiedSecurityEvent) -> PortResult<EventAppend> {
        validate_canonical_json_body(&event.canonical_body, &event.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some((tenant_id, event_class, body_hash)) = load_event_identity(
            &transaction,
            event.tenant_id.as_str(),
            event.event_id.as_str(),
        )? {
            if tenant_id != event.tenant_id.as_str()
                || event_class != "verified"
                || decode_digest(body_hash)? != event.body_hash
            {
                return Err(PortError::conflict());
            }
            let stored: (String, String, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>) = transaction
                .query_row(
                    "SELECT producer_id, trust_class, event_time, received_at, body, body_hash, evidence_hash FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2",
                    params![event.tenant_id.as_str(), event.event_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
                )
                .map_err(sqlite_error)?;
            let stored_body_hash = decode_digest(stored.5)?;
            let stored_body =
                CanonicalBody::new(stored.4.clone()).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&stored_body, &stored_body_hash)
                .map_err(|_| PortError::integrity_failure())?;
            if stored.0 != event.producer_id.as_str()
                || parse_trust_class(&stored.1)? != event.trust_class
                || from_i64(stored.2)? != event.event_time_unix_ms
                || from_i64(stored.3)? != event.received_at_unix_ms
                || stored.4.as_slice() != event.canonical_body.as_bytes()
                || stored_body_hash != event.body_hash
                || decode_digest(stored.6)? != event.evidence_hash
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(EventAppend::Duplicate);
        }
        insert_event_identity(
            &transaction,
            event.event_id.as_str(),
            event.tenant_id.as_str(),
            "verified",
            &event.body_hash,
        )?;
        transaction
            .execute(
                r#"
                INSERT INTO security_verified_events (
                    tenant_id, event_id, producer_id, trust_class, event_time, received_at,
                    body, body_hash, evidence_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    event.tenant_id.as_str(),
                    event.event_id.as_str(),
                    event.producer_id.as_str(),
                    trust_class_name(event.trust_class),
                    to_i64(event.event_time_unix_ms)?,
                    to_i64(event.received_at_unix_ms)?,
                    event.canonical_body.as_bytes(),
                    event.body_hash.as_bytes().as_slice(),
                    event.evidence_hash.as_bytes().as_slice()
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(EventAppend::Inserted)
    }

    fn append_advisory(&self, event: &AdvisorySecurityEvent) -> PortResult<EventAppend> {
        validate_canonical_json_body(&event.canonical_body, &event.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some((tenant_id, event_class, body_hash)) = load_event_identity(
            &transaction,
            event.tenant_id.as_str(),
            event.event_id.as_str(),
        )? {
            if tenant_id != event.tenant_id.as_str()
                || event_class != "advisory"
                || decode_digest(body_hash)? != event.body_hash
            {
                return Err(PortError::conflict());
            }
            let stored: (String, i64, Vec<u8>, Vec<u8>) = transaction
                .query_row(
                    "SELECT producer_id, event_time, body, body_hash FROM security_advisory_events WHERE tenant_id = ?1 AND event_id = ?2",
                    params![event.tenant_id.as_str(), event.event_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(sqlite_error)?;
            let stored_body_hash = decode_digest(stored.3)?;
            let stored_body =
                CanonicalBody::new(stored.2.clone()).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&stored_body, &stored_body_hash)
                .map_err(|_| PortError::integrity_failure())?;
            if stored.0 != event.producer_id.as_str()
                || from_i64(stored.1)? != event.event_time_unix_ms
                || stored.2.as_slice() != event.canonical_body.as_bytes()
                || stored_body_hash != event.body_hash
            {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(EventAppend::Duplicate);
        }
        insert_event_identity(
            &transaction,
            event.event_id.as_str(),
            event.tenant_id.as_str(),
            "advisory",
            &event.body_hash,
        )?;
        transaction
            .execute(
                r#"
                INSERT INTO security_advisory_events (
                    tenant_id, event_id, producer_id, event_time, body, body_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    event.tenant_id.as_str(),
                    event.event_id.as_str(),
                    event.producer_id.as_str(),
                    to_i64(event.event_time_unix_ms)?,
                    event.canonical_body.as_bytes(),
                    event.body_hash.as_bytes().as_slice()
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(EventAppend::Inserted)
    }

    fn index_partition_event(&self, request: &CorrelationEventIndexRequest) -> PortResult<()> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_event_index",
            &request_hash,
        )? {
            let indexed: bool = transaction
                .query_row(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM security_correlation_events
                        WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
                          AND event_id = ?4
                    )
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.rule_id.as_str(),
                        request.key.partition_hash.as_bytes().as_slice(),
                        request.event_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if !indexed {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let identity = load_event_identity(
            &transaction,
            request.key.tenant_id.as_str(),
            request.event_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if identity.1 != "verified" {
            return Err(PortError::conflict());
        }
        let event_time: i64 = transaction
            .query_row(
                "SELECT event_time FROM security_verified_events WHERE tenant_id = ?1 AND event_id = ?2",
                params![request.key.tenant_id.as_str(), request.event_id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let event_time = from_i64(event_time)?;
        if load_correlation_partial(&transaction, &request.key)?
            .is_some_and(|partial| event_time <= partial.watermark_unix_ms)
        {
            return Err(PortError::conflict());
        }
        let existing_partition: Option<Vec<u8>> = transaction
            .query_row(
                r#"
                SELECT partition_hash FROM security_correlation_events
                WHERE tenant_id = ?1 AND rule_id = ?2 AND event_id = ?3
                "#,
                params![
                    request.key.tenant_id.as_str(),
                    request.key.rule_id.as_str(),
                    request.event_id.as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(partition_hash) = existing_partition {
            if decode_digest(partition_hash)? != request.key.partition_hash {
                return Err(PortError::conflict());
            }
        } else {
            transaction
                .execute(
                    r#"
                    INSERT INTO security_correlation_events (
                        tenant_id, rule_id, partition_hash, event_id, transition_id
                    ) VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.rule_id.as_str(),
                        request.key.partition_hash.as_bytes().as_slice(),
                        request.event_id.as_str(),
                        request.transition_id.as_str()
                    ],
                )
                .map_err(sqlite_error)?;
            bump_correlation_partition_head(&transaction, &request.key)?;
        }
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_event_index",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }

    fn scan_partition(&self, scan: &EventPartitionScan) -> PortResult<CorrelationScan> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let key = CorrelationPartitionKey {
            tenant_id: scan.tenant_id.clone(),
            rule_id: scan.rule_id.clone(),
            partition_hash: scan.partition_hash,
        };
        let partition_generation = load_correlation_partition_generation(&transaction, &key)?;
        let (events, truncated) = scan_verified_partition(&transaction, scan)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CorrelationScan {
            events,
            partition_generation,
            truncated,
        })
    }

    fn load_correlation(
        &self,
        key: &CorrelationPartitionKey,
    ) -> PortResult<Option<CorrelationPartial>> {
        let connection = self.connection()?;
        load_correlation_partial(&connection, key)
    }

    fn compare_and_swap_correlation(
        &self,
        request: &CorrelationCasRequest,
    ) -> PortResult<CorrelationPartial> {
        if request.scan.tenant_id != request.partial.key.tenant_id
            || request.scan.rule_id != request.partial.key.rule_id
            || request.scan.partition_hash != request.partial.key.partition_hash
            || request.scan.through_event_time_unix_ms != request.partial.watermark_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        validate_canonical_json_body(&request.partial.canonical_body, &request.partial.body_hash)?;
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.partial.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_cas",
            &request_hash,
        )? {
            let stored = load_correlation_partial(&transaction, &request.partial.key)?
                .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        let partition_generation =
            load_correlation_partition_generation(&transaction, &request.partial.key)?;
        if partition_generation != request.observed_partition_generation {
            return Err(PortError::conflict());
        }
        let current = load_correlation_partial(&transaction, &request.partial.key)?;
        match (current.as_ref(), request.expected_generation) {
            (None, None) if request.partial.generation == 0 => {}
            (Some(current), Some(expected))
                if current.generation == expected
                    && request.partial.watermark_unix_ms >= current.watermark_unix_ms
                    && request.partial.generation
                        == expected
                            .checked_add(1)
                            .ok_or_else(PortError::integrity_failure)? => {}
            _ => return Err(PortError::conflict()),
        }
        let covers_next_interval = match current.as_ref() {
            None => {
                request.scan.after_event_time_unix_ms.is_none()
                    && request.scan.after_event_id.is_none()
            }
            Some(current) => {
                request.scan.after_event_time_unix_ms == Some(current.watermark_unix_ms)
                    && request.scan.after_event_id.is_none()
            }
        };
        if !covers_next_interval {
            return Err(PortError::conflict());
        }
        let (_, truncated) = scan_verified_partition(&transaction, &request.scan)?;
        if truncated {
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_correlation_partials (
                    tenant_id, rule_id, partition_hash, generation, watermark,
                    expires_at, body, body_hash, transition_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT (tenant_id, rule_id, partition_hash) DO UPDATE SET
                    generation = excluded.generation,
                    watermark = excluded.watermark,
                    expires_at = excluded.expires_at,
                    body = excluded.body,
                    body_hash = excluded.body_hash,
                    transition_id = excluded.transition_id
                "#,
                params![
                    request.partial.key.tenant_id.as_str(),
                    request.partial.key.rule_id.as_str(),
                    request.partial.key.partition_hash.as_bytes().as_slice(),
                    to_i64(request.partial.generation)?,
                    to_i64(request.partial.watermark_unix_ms)?,
                    to_i64(request.partial.expires_at_unix_ms)?,
                    request.partial.canonical_body.as_bytes(),
                    request.partial.body_hash.as_bytes().as_slice(),
                    request.transition_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        record_transition(
            &transaction,
            request.partial.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.partial.clone())
    }

    fn delete_correlation(&self, request: &CorrelationDeleteRequest) -> PortResult<()> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_delete",
            &request_hash,
        )? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let deleted = transaction
            .execute(
                "DELETE FROM security_correlation_partials WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3 AND generation = ?4",
                params![
                    request.key.tenant_id.as_str(),
                    request.key.rule_id.as_str(),
                    request.key.partition_hash.as_bytes().as_slice(),
                    to_i64(request.expected_generation)?
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "correlation_delete",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

fn scan_verified_partition(
    connection: &Connection,
    scan: &EventPartitionScan,
) -> PortResult<(VerifiedEventBatch, bool)> {
    if scan.max_results == 0
        || scan.max_results > MAX_EVENT_SCAN_RESULTS
        || scan.after_event_id.is_some() && scan.after_event_time_unix_ms.is_none()
        || scan
            .after_event_time_unix_ms
            .is_some_and(|after| scan.through_event_time_unix_ms < after)
    {
        return Err(PortError::invalid_data());
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT events.event_id, events.producer_id, events.trust_class,
                   events.event_time, events.received_at, events.body,
                   events.body_hash, events.evidence_hash
            FROM security_correlation_events AS correlation
            INNER JOIN security_verified_events AS events
                ON events.tenant_id = correlation.tenant_id
               AND events.event_id = correlation.event_id
            WHERE correlation.tenant_id = ?1 AND correlation.rule_id = ?2
              AND correlation.partition_hash = ?3
              AND (
                  ?4 IS NULL
                  OR (?4 IS NOT NULL AND ?5 IS NULL AND events.event_time > ?4)
                  OR (
                      ?4 IS NOT NULL AND ?5 IS NOT NULL
                      AND (
                          events.event_time > ?4
                          OR (events.event_time = ?4 AND events.event_id > ?5)
                      )
                  )
              )
              AND events.event_time <= ?6
            ORDER BY events.event_time, events.event_id
            LIMIT ?7
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                scan.tenant_id.as_str(),
                scan.rule_id.as_str(),
                scan.partition_hash.as_bytes().as_slice(),
                scan.after_event_time_unix_ms.map(to_i64).transpose()?,
                scan.after_event_id.as_ref().map(EventId::as_str),
                to_i64(scan.through_event_time_unix_ms)?,
                i64::from(scan.max_results) + 1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut events = Vec::new();
    for row in rows {
        let (event_id, producer_id, trust_class, event_time, received_at, body, hash, evidence) =
            row.map_err(sqlite_error)?;
        let body_hash = decode_digest(hash)?;
        let canonical_body =
            CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
        validate_canonical_json_body(&canonical_body, &body_hash)
            .map_err(|_| PortError::integrity_failure())?;
        events.push(VerifiedSecurityEvent {
            tenant_id: scan.tenant_id.clone(),
            event_id: EventId::new(event_id).map_err(|_| PortError::integrity_failure())?,
            producer_id: ProducerId::new(producer_id)
                .map_err(|_| PortError::integrity_failure())?,
            trust_class: parse_trust_class(&trust_class)?,
            event_time_unix_ms: from_i64(event_time)?,
            received_at_unix_ms: from_i64(received_at)?,
            canonical_body,
            body_hash,
            evidence_hash: decode_digest(evidence)?,
        });
    }
    let truncated = events.len() > scan.max_results as usize;
    if truncated {
        events.pop();
    }
    let events = VerifiedEventBatch::new(events).map_err(|_| PortError::integrity_failure())?;
    Ok((events, truncated))
}

fn load_correlation_partition_generation(
    connection: &Connection,
    key: &CorrelationPartitionKey,
) -> PortResult<u64> {
    let generation: Option<i64> = connection
        .query_row(
            r#"
            SELECT generation FROM security_correlation_partition_heads
            WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(generation.map(from_i64).transpose()?.unwrap_or(0))
}

fn bump_correlation_partition_head(
    transaction: &Transaction<'_>,
    key: &CorrelationPartitionKey,
) -> PortResult<u64> {
    let next = load_correlation_partition_generation(transaction, key)?
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_correlation_partition_heads (
                tenant_id, rule_id, partition_hash, generation
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT (tenant_id, rule_id, partition_hash) DO UPDATE SET
                generation = excluded.generation
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice(),
                to_i64(next)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn load_event_identity(
    connection: &Connection,
    tenant_id: &str,
    event_id: &str,
) -> PortResult<Option<(String, String, Vec<u8>)>> {
    connection
        .query_row(
            "SELECT tenant_id, event_class, body_hash FROM security_event_ids WHERE tenant_id = ?1 AND event_id = ?2",
            params![tenant_id, event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn insert_event_identity(
    transaction: &Transaction<'_>,
    event_id: &str,
    tenant_id: &str,
    event_class: &str,
    hash: &Digest32,
) -> PortResult<()> {
    transaction
        .execute(
            "INSERT INTO security_event_ids (event_id, tenant_id, event_class, body_hash) VALUES (?1, ?2, ?3, ?4)",
            params![event_id, tenant_id, event_class, hash.as_bytes().as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredCorrelation = (i64, i64, i64, Vec<u8>, Vec<u8>);

fn load_correlation_partial(
    connection: &Connection,
    key: &CorrelationPartitionKey,
) -> PortResult<Option<CorrelationPartial>> {
    let stored: Option<StoredCorrelation> = connection
        .query_row(
            r#"
            SELECT generation, watermark, expires_at, body, body_hash
            FROM security_correlation_partials
            WHERE tenant_id = ?1 AND rule_id = ?2 AND partition_hash = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.rule_id.as_str(),
                key.partition_hash.as_bytes().as_slice()
            ],
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
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(generation, watermark, expires_at, body, stored_hash)| {
            let body_hash = decode_digest(stored_hash)?;
            let canonical_body =
                CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
            validate_canonical_json_body(&canonical_body, &body_hash)
                .map_err(|_| PortError::integrity_failure())?;
            Ok(CorrelationPartial {
                key: key.clone(),
                generation: from_i64(generation)?,
                watermark_unix_ms: from_i64(watermark)?,
                expires_at_unix_ms: from_i64(expires_at)?,
                canonical_body,
                body_hash,
            })
        })
        .transpose()
}

impl ResponseStore for SqliteSecurityStateStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let connection = self.connection()?;
        load_response_plan(&connection, key.tenant_id.as_str(), key.action_id.as_str())
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_response_plan(
            &transaction,
            record.tenant_id.as_str(),
            record.action_id.as_str(),
        )? {
            if existing == *record {
                transaction.commit().map_err(sqlite_error)?;
                return Ok(CreateOutcome::Existing);
            }
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_plans (
                    action_id, tenant_id, generation, state, body, body_hash, due_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    record.action_id.as_str(),
                    record.tenant_id.as_str(),
                    to_i64(record.generation)?,
                    record.state.as_str(),
                    record.canonical_body.as_bytes(),
                    record.body_hash.as_bytes().as_slice(),
                    record.due_at_unix_ms.map(to_i64).transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        validate_canonical_json_body(&request.record.canonical_body, &request.record.body_hash)?;
        if request.record.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_cas",
            &request_hash,
        )? {
            let existing = load_response_plan(
                &transaction,
                request.record.tenant_id.as_str(),
                request.record.action_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let current = load_response_plan(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.action_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_plans
                SET generation = ?4, state = ?5, body = ?6, body_hash = ?7, due_at = ?8
                WHERE action_id = ?1 AND tenant_id = ?2 AND generation = ?3
                "#,
                params![
                    request.record.action_id.as_str(),
                    request.record.tenant_id.as_str(),
                    to_i64(request.expected_generation)?,
                    to_i64(request.record.generation)?,
                    request.record.state.as_str(),
                    request.record.canonical_body.as_bytes(),
                    request.record.body_hash.as_bytes().as_slice(),
                    request.record.due_at_unix_ms.map(to_i64).transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.record.clone())
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        let connection = self.connection()?;
        load_response_effect(&connection, key.tenant_id.as_str(), key.effect_id.as_str())
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        if record.generation != 0 {
            return Err(PortError::invalid_data());
        }
        validate_canonical_json_body(&record.canonical_body, &record.body_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(reference) = record.encrypted_rollback_ref.as_ref() {
            validate_encrypted_blob_reference(&transaction, record.tenant_id.as_str(), reference)?;
        }
        validate_scheduler_fence(
            &transaction,
            record.tenant_id.as_str(),
            record.action_id.as_str(),
            record.scheduler_fencing_token,
        )?;
        if let Some(existing) = load_response_effect(
            &transaction,
            record.tenant_id.as_str(),
            record.effect_id.as_str(),
        )? {
            if existing != *record {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(CreateOutcome::Existing);
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_response_effects (
                    effect_id, tenant_id, action_id, generation, scheduler_fencing_token,
                    state, body, body_hash, encrypted_rollback_ref
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    record.effect_id.as_str(),
                    record.tenant_id.as_str(),
                    record.action_id.as_str(),
                    to_i64(record.generation)?,
                    to_i64(record.scheduler_fencing_token)?,
                    record.state.as_str(),
                    record.canonical_body.as_bytes(),
                    record.body_hash.as_bytes().as_slice(),
                    record.encrypted_rollback_ref.as_ref().map(RecordId::as_str)
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(CreateOutcome::Created)
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        validate_canonical_json_body(&request.record.canonical_body, &request.record.body_hash)?;
        if request.record.generation
            != request
                .expected_generation
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(reference) = request.record.encrypted_rollback_ref.as_ref() {
            validate_encrypted_blob_reference(
                &transaction,
                request.record.tenant_id.as_str(),
                reference,
            )?;
        }
        validate_scheduler_fence(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.action_id.as_str(),
            request.record.scheduler_fencing_token,
        )?;
        if transition_status(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_effect_cas",
            &request_hash,
        )? {
            let existing = load_response_effect(
                &transaction,
                request.record.tenant_id.as_str(),
                request.record.effect_id.as_str(),
            )?
            .ok_or_else(PortError::integrity_failure)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let current = load_response_effect(
            &transaction,
            request.record.tenant_id.as_str(),
            request.record.effect_id.as_str(),
        )?
        .ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.action_id != request.record.action_id
            || current.effect_id != request.record.effect_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        let updated = transaction
            .execute(
                r#"
                UPDATE security_response_effects
                SET generation = ?4, scheduler_fencing_token = ?5, state = ?6,
                    body = ?7, body_hash = ?8, encrypted_rollback_ref = ?9
                WHERE effect_id = ?1 AND tenant_id = ?2 AND generation = ?3
                "#,
                params![
                    request.record.effect_id.as_str(),
                    request.record.tenant_id.as_str(),
                    to_i64(request.expected_generation)?,
                    to_i64(request.record.generation)?,
                    to_i64(request.record.scheduler_fencing_token)?,
                    request.record.state.as_str(),
                    request.record.canonical_body.as_bytes(),
                    request.record.body_hash.as_bytes().as_slice(),
                    request
                        .record
                        .encrypted_rollback_ref
                        .as_ref()
                        .map(RecordId::as_str)
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.record.tenant_id.as_str(),
            request.transition_id.as_str(),
            "response_effect_cas",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(request.record.clone())
    }

    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        let trusted_now = now_unix_ms()?;
        if request.max_claims == 0
            || request.max_claims > MAX_SCHEDULER_CLAIMS
            || request.lease_expires_at_unix_ms <= trusted_now
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(claimed) =
            load_scheduler_claim(&transaction, request, &request_hash, trusted_now)?
        {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(claimed);
        }
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS {
            return Err(PortError::invalid_data());
        }
        let trusted_now_sql = to_i64(trusted_now)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT plans.action_id
                FROM security_response_plans AS plans
                LEFT JOIN security_scheduler_leases AS leases
                  ON leases.action_id = plans.action_id
                 AND leases.tenant_id = plans.tenant_id
                LEFT JOIN security_scheduler_retries AS retries
                  ON retries.action_id = plans.action_id
                 AND retries.tenant_id = plans.tenant_id
                WHERE plans.tenant_id = ?1
                  AND plans.due_at IS NOT NULL
                  AND plans.due_at <= ?2
                  AND (retries.action_id IS NULL OR retries.not_before <= ?2)
                  AND (leases.action_id IS NULL OR leases.lease_expires_at <= ?2)
                ORDER BY
                  CASE
                    WHEN retries.not_before IS NOT NULL
                     AND retries.not_before > plans.due_at
                    THEN retries.not_before
                    ELSE plans.due_at
                  END,
                  plans.action_id
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let action_rows = statement
            .query_map(
                params![
                    request.tenant_id.as_str(),
                    trusted_now_sql,
                    i64::from(request.max_claims)
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut action_ids = Vec::new();
        for row in action_rows {
            action_ids.push(row.map_err(sqlite_error)?);
        }
        drop(statement);
        let mut claimed = Vec::new();
        for (claim_ordinal, action_id) in action_ids.into_iter().enumerate() {
            let plan = load_response_plan(&transaction, request.tenant_id.as_str(), &action_id)?
                .ok_or_else(PortError::integrity_failure)?;
            if plan
                .due_at_unix_ms
                .is_none_or(|due_at| due_at > trusted_now)
            {
                return Err(PortError::integrity_failure());
            }
            let fencing_token =
                next_scheduler_fencing_token(&transaction, request.tenant_id.as_str())?;
            transaction
                .execute(
                    r#"
                    INSERT INTO security_scheduler_leases (
                        action_id, tenant_id, claim_id, claim_ordinal,
                        lease_owner_id, lease_expires_at, fencing_token
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                        claim_id = excluded.claim_id,
                        claim_ordinal = excluded.claim_ordinal,
                        lease_owner_id = excluded.lease_owner_id,
                        lease_expires_at = excluded.lease_expires_at,
                        fencing_token = excluded.fencing_token
                    "#,
                    params![
                        action_id,
                        request.tenant_id.as_str(),
                        request.claim_id.as_str(),
                        to_i64(claim_ordinal as u64)?,
                        request.lease_owner_id.as_str(),
                        to_i64(request.lease_expires_at_unix_ms)?,
                        to_i64(fencing_token)?
                    ],
                )
                .map_err(sqlite_error)?;
            claimed.push(ScheduledWork {
                tenant_id: request.tenant_id.clone(),
                action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
                lease_owner_id: request.lease_owner_id.clone(),
                lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
                fencing_token,
            });
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_scheduler_claims (
                    tenant_id, claim_id, request_hash, lease_owner_id,
                    lease_expires_at, result_count, committed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.tenant_id.as_str(),
                    request.claim_id.as_str(),
                    request_hash.as_slice(),
                    request.lease_owner_id.as_str(),
                    to_i64(request.lease_expires_at_unix_ms)?,
                    to_i64(claimed.len() as u64)?,
                    trusted_now_sql
                ],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(claimed)
    }
}

impl ResponseSchedulerStore for SqliteSecurityStateStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        let connection = self.connection()?;
        load_scheduler_retry(&connection, key)
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        let connection = self.connection()?;
        validate_scheduler_work(&connection, work)
    }

    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        let trusted_now = now_unix_ms()?;
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.lease_expires_at_unix_ms <= trusted_now
            || request.lease_expires_at_unix_ms <= request.work.lease_expires_at_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_renew",
            &request_hash,
        )? {
            let renewed = load_scheduler_lease(
                &transaction,
                &SchedulerWorkKey {
                    tenant_id: request.work.tenant_id.clone(),
                    action_id: request.work.action_id.clone(),
                },
            )?
            .ok_or_else(PortError::integrity_failure)?;
            if renewed.lease_owner_id != request.work.lease_owner_id
                || renewed.fencing_token != request.work.fencing_token
                || renewed.lease_expires_at_unix_ms != request.lease_expires_at_unix_ms
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(renewed);
        }
        validate_scheduler_work(&transaction, &request.work)?;
        let updated = transaction
            .execute(
                r#"
                UPDATE security_scheduler_leases
                SET lease_expires_at = ?5
                WHERE tenant_id = ?1 AND action_id = ?2 AND lease_owner_id = ?3
                  AND fencing_token = ?4
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str(),
                    request.work.lease_owner_id.as_str(),
                    to_i64(request.work.fencing_token)?,
                    to_i64(request.lease_expires_at_unix_ms)?
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_renew",
            &request_hash,
        )?;
        let renewed = ScheduledWork {
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            ..request.work.clone()
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(renewed)
    }

    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        let trusted_now = now_unix_ms()?;
        if request.now_unix_ms.abs_diff(trusted_now) > MAX_CLOCK_SKEW_MS
            || request.not_before_unix_ms <= trusted_now
            || request.first_failure_at_unix_ms > request.now_unix_ms
        {
            return Err(PortError::invalid_data());
        }
        let next_attempts = request
            .expected_attempts
            .checked_add(1)
            .ok_or_else(PortError::invalid_data)?;
        let request_hash = canonical_request_hash(request)?;
        let key = SchedulerWorkKey {
            tenant_id: request.work.tenant_id.clone(),
            action_id: request.work.action_id.clone(),
        };
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_retry",
            &request_hash,
        )? {
            let stored = load_scheduler_retry(&transaction, &key)?
                .ok_or_else(PortError::integrity_failure)?;
            if stored.attempts != next_attempts
                || stored.last_error != request.error_code
                || stored.first_failure_at_unix_ms != request.first_failure_at_unix_ms
                || stored.not_before_unix_ms != request.not_before_unix_ms
                || stored.health_event_id != request.health_event_id
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        validate_scheduler_work(&transaction, &request.work)?;
        let current = load_scheduler_retry(&transaction, &key)?;
        let current_attempts = current.as_ref().map(|retry| retry.attempts).unwrap_or(0);
        if current_attempts != request.expected_attempts {
            return Err(PortError::conflict());
        }
        if let Some(current) = current.as_ref() {
            if current.first_failure_at_unix_ms != request.first_failure_at_unix_ms
                || current
                    .health_event_id
                    .as_ref()
                    .is_some_and(|event_id| Some(event_id) != request.health_event_id.as_ref())
                || current.health_event_delivered && request.health_event_id.is_none()
            {
                return Err(PortError::conflict());
            }
        } else if request.first_failure_at_unix_ms != request.now_unix_ms {
            return Err(PortError::invalid_data());
        }
        let health_event_delivered = current
            .as_ref()
            .is_some_and(|retry| retry.health_event_delivered);
        transaction
            .execute(
                r#"
                INSERT INTO security_scheduler_retries (
                    tenant_id, action_id, attempts, last_error, first_failure_at,
                    not_before, health_event_id, health_event_delivered
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT (tenant_id, action_id) DO UPDATE SET
                    attempts = excluded.attempts,
                    last_error = excluded.last_error,
                    first_failure_at = excluded.first_failure_at,
                    not_before = excluded.not_before,
                    health_event_id = excluded.health_event_id
                "#,
                params![
                    request.work.tenant_id.as_str(),
                    request.work.action_id.as_str(),
                    i64::from(next_attempts),
                    request.error_code.as_str(),
                    to_i64(request.first_failure_at_unix_ms)?,
                    to_i64(request.not_before_unix_ms)?,
                    request.health_event_id.as_ref().map(RecordId::as_str),
                    i64::from(health_event_delivered)
                ],
            )
            .map_err(sqlite_error)?;
        delete_scheduler_lease(&transaction, &request.work)?;
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_retry",
            &request_hash,
        )?;
        let retry = SchedulerRetryState {
            key,
            attempts: next_attempts,
            last_error: request.error_code.clone(),
            first_failure_at_unix_ms: request.first_failure_at_unix_ms,
            not_before_unix_ms: request.not_before_unix_ms,
            health_event_id: request.health_event_id.clone(),
            health_event_delivered,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(retry)
    }

    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_health_ack",
            &request_hash,
        )? {
            let stored = load_scheduler_retry(&transaction, &request.key)?
                .ok_or_else(PortError::integrity_failure)?;
            if stored.health_event_id.as_ref() != Some(&request.event_id)
                || !stored.health_event_delivered
            {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(stored);
        }
        let current = load_scheduler_retry(&transaction, &request.key)?
            .ok_or_else(PortError::invalid_data)?;
        if current.health_event_id.as_ref() != Some(&request.event_id) {
            return Err(PortError::conflict());
        }
        if !current.health_event_delivered {
            let updated = transaction
                .execute(
                    r#"
                    UPDATE security_scheduler_retries
                    SET health_event_delivered = 1
                    WHERE tenant_id = ?1 AND action_id = ?2 AND health_event_id = ?3
                      AND health_event_delivered = 0
                    "#,
                    params![
                        request.key.tenant_id.as_str(),
                        request.key.action_id.as_str(),
                        request.event_id.as_str()
                    ],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(PortError::conflict());
            }
        }
        record_transition(
            &transaction,
            request.key.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_health_ack",
            &request_hash,
        )?;
        let stored = load_scheduler_retry(&transaction, &request.key)?
            .ok_or_else(PortError::integrity_failure)?;
        if !stored.health_event_delivered {
            return Err(PortError::integrity_failure());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(stored)
    }

    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        let request_hash = canonical_request_hash(request)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if transition_status(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_release",
            &request_hash,
        )? {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        validate_scheduler_work(&transaction, &request.work)?;
        delete_scheduler_lease(&transaction, &request.work)?;
        if request.clear_retry_state {
            transaction
                .execute(
                    "DELETE FROM security_scheduler_retries WHERE tenant_id = ?1 AND action_id = ?2",
                    params![request.work.tenant_id.as_str(), request.work.action_id.as_str()],
                )
                .map_err(sqlite_error)?;
        }
        record_transition(
            &transaction,
            request.work.tenant_id.as_str(),
            request.transition_id.as_str(),
            "scheduler_lease_release",
            &request_hash,
        )?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }
}

fn load_scheduler_retry(
    connection: &Connection,
    key: &SchedulerWorkKey,
) -> PortResult<Option<SchedulerRetryState>> {
    type StoredRetry = (i64, String, i64, i64, Option<String>, i64);
    let stored: Option<StoredRetry> = connection
        .query_row(
            r#"
            SELECT attempts, last_error, first_failure_at, not_before,
                   health_event_id, health_event_delivered
            FROM security_scheduler_retries
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.action_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                attempts,
                last_error,
                first_failure_at,
                not_before,
                health_event_id,
                health_event_delivered,
            )| {
                let health_event_delivered = match health_event_delivered {
                    0 => false,
                    1 => true,
                    _ => return Err(PortError::integrity_failure()),
                };
                let health_event_id = health_event_id
                    .map(RecordId::new)
                    .transpose()
                    .map_err(|_| PortError::integrity_failure())?;
                if health_event_delivered && health_event_id.is_none() {
                    return Err(PortError::integrity_failure());
                }
                Ok(SchedulerRetryState {
                    key: key.clone(),
                    attempts: u32::try_from(from_i64(attempts)?)
                        .map_err(|_| PortError::integrity_failure())?,
                    last_error: ErrorCode::new(last_error)
                        .map_err(|_| PortError::integrity_failure())?,
                    first_failure_at_unix_ms: from_i64(first_failure_at)?,
                    not_before_unix_ms: from_i64(not_before)?,
                    health_event_id,
                    health_event_delivered,
                })
            },
        )
        .transpose()
}

fn load_scheduler_lease(
    connection: &Connection,
    key: &SchedulerWorkKey,
) -> PortResult<Option<ScheduledWork>> {
    type StoredLease = (String, String, i64, i64);
    let stored: Option<StoredLease> = connection
        .query_row(
            r#"
            SELECT action_id, lease_owner_id, lease_expires_at, fencing_token
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.action_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(action_id, lease_owner_id, lease_expires_at, fencing_token)| {
                Ok(ScheduledWork {
                    tenant_id: key.tenant_id.clone(),
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(lease_owner_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    lease_expires_at_unix_ms: from_i64(lease_expires_at)?,
                    fencing_token: from_i64(fencing_token)?,
                })
            },
        )
        .transpose()
}

fn validate_scheduler_work(connection: &Connection, work: &ScheduledWork) -> PortResult<()> {
    let stored = load_scheduler_lease(
        connection,
        &SchedulerWorkKey {
            tenant_id: work.tenant_id.clone(),
            action_id: work.action_id.clone(),
        },
    )?
    .ok_or_else(PortError::conflict)?;
    if stored != *work || stored.lease_expires_at_unix_ms <= now_unix_ms()? {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn delete_scheduler_lease(connection: &Connection, work: &ScheduledWork) -> PortResult<()> {
    let deleted = connection
        .execute(
            r#"
            DELETE FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND action_id = ?2 AND lease_owner_id = ?3
              AND lease_expires_at = ?4 AND fencing_token = ?5
            "#,
            params![
                work.tenant_id.as_str(),
                work.action_id.as_str(),
                work.lease_owner_id.as_str(),
                to_i64(work.lease_expires_at_unix_ms)?,
                to_i64(work.fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    if deleted != 1 {
        return Err(PortError::conflict());
    }
    Ok(())
}

fn load_scheduler_claim(
    connection: &Connection,
    request: &SchedulerClaimRequest,
    request_hash: &[u8; 32],
    trusted_now: u64,
) -> PortResult<Option<Vec<ScheduledWork>>> {
    type StoredClaim = (Vec<u8>, String, i64, i64);
    let stored: Option<StoredClaim> = connection
        .query_row(
            r#"
            SELECT request_hash, lease_owner_id, lease_expires_at, result_count
            FROM security_scheduler_claims
            WHERE tenant_id = ?1 AND claim_id = ?2
            "#,
            params![request.tenant_id.as_str(), request.claim_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((stored_hash, stored_owner, stored_expiry, stored_count)) = stored else {
        return Ok(None);
    };
    let stored_expiry = from_i64(stored_expiry)?;
    if stored_hash.as_slice() != request_hash
        || stored_owner != request.lease_owner_id.as_str()
        || stored_expiry != request.lease_expires_at_unix_ms
    {
        return Err(PortError::conflict());
    }
    if stored_expiry <= trusted_now {
        return Err(PortError::conflict());
    }
    let expected_count =
        usize::try_from(from_i64(stored_count)?).map_err(|_| PortError::integrity_failure())?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT action_id, lease_owner_id, lease_expires_at, fencing_token
            FROM security_scheduler_leases
            WHERE tenant_id = ?1 AND claim_id = ?2
            ORDER BY claim_ordinal
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![request.tenant_id.as_str(), request.claim_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut claimed = Vec::with_capacity(expected_count);
    for row in rows {
        let (action_id, lease_owner_id, lease_expires_at, fencing_token) =
            row.map_err(sqlite_error)?;
        if lease_owner_id != request.lease_owner_id.as_str()
            || from_i64(lease_expires_at)? != request.lease_expires_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        claimed.push(ScheduledWork {
            tenant_id: request.tenant_id.clone(),
            action_id: ActionId::new(action_id).map_err(|_| PortError::integrity_failure())?,
            lease_owner_id: request.lease_owner_id.clone(),
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            fencing_token: from_i64(fencing_token)?,
        });
    }
    if claimed.len() != expected_count {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(claimed))
}

fn next_scheduler_fencing_token(transaction: &Transaction<'_>, tenant_id: &str) -> PortResult<u64> {
    let sequence_token: Option<i64> = transaction
        .query_row(
            "SELECT last_fencing_token FROM security_scheduler_fence_sequences WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let lease_token: Option<i64> = transaction
        .query_row(
            "SELECT MAX(fencing_token) FROM security_scheduler_leases WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let current = sequence_token
        .map(from_i64)
        .transpose()?
        .unwrap_or(0)
        .max(lease_token.map(from_i64).transpose()?.unwrap_or(0));
    let next = current
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_scheduler_fence_sequences (tenant_id, last_fencing_token)
            VALUES (?1, ?2)
            ON CONFLICT (tenant_id) DO UPDATE SET
                last_fencing_token = excluded.last_fencing_token
            "#,
            params![tenant_id, to_i64(next)?],
        )
        .map_err(sqlite_error)?;
    Ok(next)
}

fn load_response_plan(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
) -> PortResult<Option<ResponsePlanRecord>> {
    type StoredPlan = (String, i64, String, Vec<u8>, Vec<u8>, Option<i64>);
    let stored: Option<StoredPlan> = connection
        .query_row(
            r#"
            SELECT tenant_id, generation, state, body, body_hash, due_at
            FROM security_response_plans WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            params![tenant_id, action_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(tenant_id, generation, state, body, stored_hash, due_at)| {
                let body_hash = decode_digest(stored_hash)?;
                let canonical_body =
                    CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
                validate_canonical_json_body(&canonical_body, &body_hash)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(ResponsePlanRecord {
                    tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    generation: from_i64(generation)?,
                    state: RecordId::new(state).map_err(|_| PortError::integrity_failure())?,
                    canonical_body,
                    body_hash,
                    due_at_unix_ms: due_at.map(from_i64).transpose()?,
                })
            },
        )
        .transpose()
}

fn load_response_effect(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<ResponseEffectRecord>> {
    type StoredEffect = (
        String,
        String,
        String,
        i64,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
    );
    let stored: Option<StoredEffect> = connection
        .query_row(
            r#"
            SELECT tenant_id, action_id, effect_id, generation, scheduler_fencing_token,
                   state, body, body_hash, encrypted_rollback_ref
            FROM security_response_effects WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(
            |(
                tenant_id,
                action_id,
                effect_id,
                generation,
                scheduler_fencing_token,
                state,
                body,
                stored_hash,
                encrypted_rollback_ref,
            )| {
                let body_hash = decode_digest(stored_hash)?;
                let canonical_body =
                    CanonicalBody::new(body).map_err(|_| PortError::integrity_failure())?;
                validate_canonical_json_body(&canonical_body, &body_hash)
                    .map_err(|_| PortError::integrity_failure())?;
                Ok(ResponseEffectRecord {
                    tenant_id: chio_security_types::ports::TenantId::new(tenant_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    action_id: ActionId::new(action_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    effect_id: EffectId::new(effect_id)
                        .map_err(|_| PortError::integrity_failure())?,
                    generation: from_i64(generation)?,
                    scheduler_fencing_token: from_i64(scheduler_fencing_token)?,
                    state: RecordId::new(state).map_err(|_| PortError::integrity_failure())?,
                    canonical_body,
                    body_hash,
                    encrypted_rollback_ref: encrypted_rollback_ref
                        .map(RecordId::new)
                        .transpose()
                        .map_err(|_| PortError::integrity_failure())?,
                })
            },
        )
        .transpose()
}

fn validate_scheduler_fence(
    connection: &Connection,
    tenant_id: &str,
    action_id: &str,
    fencing_token: u64,
) -> PortResult<()> {
    let stored: Option<(String, i64, i64)> = connection
        .query_row(
            "SELECT tenant_id, fencing_token, lease_expires_at FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
            params![tenant_id, action_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((stored_tenant, stored_token, stored_expiry)) = stored else {
        return Err(PortError::invalid_data());
    };
    if stored_tenant != tenant_id
        || from_i64(stored_token)? != fencing_token
        || from_i64(stored_expiry)? <= now_unix_ms()?
    {
        return Err(PortError::conflict());
    }
    Ok(())
}

impl ContainmentOverlayStore for SqliteSecurityStateStore {
    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.target.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
        )?;
        if let Some((target_id, action_id)) = load_contribution_binding(
            &transaction,
            request.target.tenant_id.as_str(),
            request.contribution.effect_id.as_str(),
        )? {
            if target_id != request.target.id.as_str() || action_id != request.action_id.as_str() {
                return Err(PortError::conflict());
            }
        }
        let current = load_overlay_snapshot(&transaction, &request.target)?;
        if let Some(existing) = current
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            let stored_action_id: String = transaction
                .query_row(
                    r#"
                    SELECT action_id FROM security_effect_contributions
                    WHERE tenant_id = ?1 AND target_id = ?2 AND effect_id = ?3
                    "#,
                    params![
                        request.target.tenant_id.as_str(),
                        request.target.id.as_str(),
                        request.contribution.effect_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if stored_action_id != request.action_id.as_str() || existing != &request.contribution {
                return Err(PortError::conflict());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        transaction
            .execute(
                r#"
                INSERT INTO security_effect_contributions (
                    tenant_id, target_id, effect_id, action_id,
                    posture_rank, contribution_hash, expires_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.target.tenant_id.as_str(),
                    request.target.id.as_str(),
                    request.contribution.effect_id.as_str(),
                    request.action_id.as_str(),
                    i64::from(request.contribution.posture_rank),
                    request.contribution.contribution_hash.as_bytes().as_slice(),
                    request
                        .contribution
                        .expires_at_unix_ms
                        .map(to_i64)
                        .transpose()?
                ],
            )
            .map_err(sqlite_error)?;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_overlay_state(
            &transaction,
            &request.target,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_overlay_snapshot(&transaction, &request.target)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_scheduler_fence(
            &transaction,
            request.target.tenant_id.as_str(),
            request.action_id.as_str(),
            request.scheduler_fencing_token,
        )?;
        let binding = load_contribution_binding(
            &transaction,
            request.target.tenant_id.as_str(),
            request.effect_id.as_str(),
        )?;
        if let Some((target_id, action_id)) = binding.as_ref() {
            if target_id != request.target.id.as_str() || action_id != request.action_id.as_str() {
                return Err(PortError::conflict());
            }
        }
        let current = load_overlay_snapshot(&transaction, &request.target)?;
        if !current
            .active_contributions
            .as_slice()
            .iter()
            .any(|entry| entry.effect_id == request.effect_id)
        {
            if binding.is_some() {
                return Err(PortError::integrity_failure());
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(current);
        }
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let deleted = transaction
            .execute(
                "DELETE FROM security_effect_contributions WHERE tenant_id = ?1 AND target_id = ?2 AND effect_id = ?3 AND action_id = ?4",
                params![
                    request.target.tenant_id.as_str(),
                    request.target.id.as_str(),
                    request.effect_id.as_str(),
                    request.action_id.as_str()
                ],
            )
            .map_err(sqlite_error)?;
        if deleted != 1 {
            return Err(PortError::conflict());
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        persist_overlay_state(
            &transaction,
            &request.target,
            generation,
            current
                .highest_fencing_token
                .max(request.scheduler_fencing_token),
        )?;
        let snapshot = load_overlay_snapshot(&transaction, &request.target)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM security_overlay_state WHERE tenant_id = ?1 AND target_id = ?2)",
                params![target.tenant_id.as_str(), target.id.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !exists {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(None);
        }
        let snapshot = load_overlay_snapshot(&transaction, target)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(Some(snapshot))
    }
}

fn load_contribution_binding(
    connection: &Connection,
    tenant_id: &str,
    effect_id: &str,
) -> PortResult<Option<(String, String)>> {
    connection
        .query_row(
            r#"
            SELECT target_id, action_id FROM security_effect_contributions
            WHERE tenant_id = ?1 AND effect_id = ?2
            "#,
            params![tenant_id, effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

fn load_overlay_snapshot(
    connection: &Connection,
    target: &TenantScopedId,
) -> PortResult<OverlaySnapshot> {
    let state: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT generation, effective_posture_rank, highest_fencing_token FROM security_overlay_state WHERE tenant_id = ?1 AND target_id = ?2",
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let state_exists = state.is_some();
    let (generation, effective_posture_rank, highest_fencing_token) = state.unwrap_or((0, 0, 0));
    let mut statement = connection
        .prepare(
            r#"
            SELECT effect_id, posture_rank, contribution_hash, expires_at
            FROM security_effect_contributions
            WHERE tenant_id = ?1 AND target_id = ?2
            ORDER BY effect_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let mut contributions = Vec::new();
    for row in rows {
        let (effect_id, posture_rank, contribution_hash, expires_at) = row.map_err(sqlite_error)?;
        contributions.push(OverlayContribution {
            effect_id: EffectId::new(effect_id).map_err(|_| PortError::integrity_failure())?,
            posture_rank: u32::try_from(posture_rank)
                .map_err(|_| PortError::integrity_failure())?,
            contribution_hash: decode_digest(contribution_hash)?,
            expires_at_unix_ms: expires_at.map(from_i64).transpose()?,
        });
    }
    if !state_exists && !contributions.is_empty() {
        return Err(PortError::integrity_failure());
    }
    let stored_posture =
        u32::try_from(effective_posture_rank).map_err(|_| PortError::integrity_failure())?;
    let recomputed_posture = contributions
        .iter()
        .map(|contribution| contribution.posture_rank)
        .max()
        .unwrap_or(0);
    if stored_posture != recomputed_posture {
        return Err(PortError::integrity_failure());
    }
    Ok(OverlaySnapshot {
        target: target.clone(),
        generation: from_i64(generation)?,
        effective_posture_rank: stored_posture,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: from_i64(highest_fencing_token)?,
    })
}

fn persist_overlay_state(
    transaction: &Transaction<'_>,
    target: &TenantScopedId,
    generation: u64,
    fencing_token: u64,
) -> PortResult<()> {
    let posture: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(posture_rank), 0) FROM security_effect_contributions WHERE tenant_id = ?1 AND target_id = ?2",
            params![target.tenant_id.as_str(), target.id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
            INSERT INTO security_overlay_state (
                tenant_id, target_id, generation, effective_posture_rank, highest_fencing_token
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT (tenant_id, target_id) DO UPDATE SET
                generation = excluded.generation,
                effective_posture_rank = excluded.effective_posture_rank,
                highest_fencing_token = excluded.highest_fencing_token
            "#,
            params![
                target.tenant_id.as_str(),
                target.id.as_str(),
                to_i64(generation)?,
                posture,
                to_i64(fencing_token)?
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
