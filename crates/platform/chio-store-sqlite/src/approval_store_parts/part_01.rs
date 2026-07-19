use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use chio_core::capability::governance::GovernedApprovalToken;
use chio_core::capability::threshold_approval::ThresholdApprovalProposal;
use chio_core::{canonical_json_bytes, canonical_json_bytes_from_str, PublicKey};
use chio_kernel::approval::{
    ThresholdApprovalCollectorStatus, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalRecord, ThresholdApprovalProposalRegistration,
    ThresholdApprovalVoteRecord,
};
use chio_kernel::{
    ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest, ApprovalReservation,
    ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStore, ApprovalStoreError,
    ApprovalStoreProfile, ReplayReservationState, ResolvedApproval,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};

const MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES: usize = 262_144;
const MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES: usize = 262_144;
const APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const APPROVAL_STORE_SCHEMA_KEY: &str = "approval";
const APPROVAL_STORE_OWN_ANCHOR_TABLES: &[&str] = &["chio_hitl_pending"];
const APPROVAL_STORE_COLOCATED_ANCHOR_TABLES: &[&str] = &[
    "chio_hitl_pending",
    "http_receipts",
    "tool_receipts",
    "chio_tool_receipts",
];

/// SQLite-backed `ApprovalStore`.
///
/// Schema is created on `open`. Migrations are additive and idempotent
/// via `CREATE TABLE IF NOT EXISTS`.
pub struct SqliteApprovalStore {
    pool: Pool<SqliteConnectionManager>,
    authority_profile: ApprovalStoreProfile,
}

impl SqliteApprovalStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        Self::open_with_anchor_tables(path, APPROVAL_STORE_OWN_ANCHOR_TABLES)
    }

    /// Open an approval store in the receipt store's shared sidecar database.
    pub fn open_colocated_with_receipt_store(
        path: impl AsRef<Path>,
    ) -> Result<Self, ApprovalStoreError> {
        Self::open_with_anchor_tables(path, APPROVAL_STORE_COLOCATED_ANCHOR_TABLES)
    }

    fn open_with_anchor_tables(
        path: impl AsRef<Path>,
        anchor_tables: &[&str],
    ) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        reject_volatile_database_path(path)?;
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)
                .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self {
            pool,
            authority_profile: ApprovalStoreProfile::SingleNodeDurable,
        };
        store.run_migrations(anchor_tables)?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, ApprovalStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self {
            pool,
            authority_profile: ApprovalStoreProfile::EphemeralLocal,
        };
        store.run_migrations(APPROVAL_STORE_OWN_ANCHOR_TABLES)?;
        Ok(store)
    }

    fn run_migrations(&self, anchor_tables: &[&str]) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        crate::check_schema_version(
            &conn,
            APPROVAL_STORE_SCHEMA_KEY,
            APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
            anchor_tables,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_hitl_consumed_tokens (
                token_id TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                token_digest TEXT
                    CHECK (token_digest IS NULL OR (length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*')),
                consumed_at INTEGER NOT NULL,
                PRIMARY KEY (token_id, parameter_hash)
            );
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration preflight: {e}")))?;
        let has_legacy_token_digest = {
            let mut statement = conn
                .prepare("PRAGMA table_info(chio_hitl_consumed_tokens)")
                .map_err(|e| ApprovalStoreError::Backend(format!("migration inspect: {e}")))?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| ApprovalStoreError::Backend(format!("migration inspect: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ApprovalStoreError::Backend(format!("migration inspect: {e}")))?;
            columns.iter().any(|column| column == "token_digest")
        };
        if !has_legacy_token_digest {
            conn.execute_batch(
                r#"
                ALTER TABLE chio_hitl_consumed_tokens ADD COLUMN token_digest TEXT
                    CHECK (token_digest IS NULL OR (length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'));
                "#,
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("migration alter: {e}")))?;
        }
        conn.execute_batch(
            r#"
            DROP TRIGGER IF EXISTS chio_hitl_consumed_token_operation_exclusion;
            DROP TRIGGER IF EXISTS chio_hitl_operation_token_legacy_exclusion;
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration trigger refresh: {e}")))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS chio_hitl_pending (
                approval_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_pending_subject
                ON chio_hitl_pending(subject_id);
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_pending_expires
                ON chio_hitl_pending(expires_at);

            CREATE TABLE IF NOT EXISTS chio_hitl_resolved (
                approval_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                resolved_at INTEGER NOT NULL,
                approver_hex TEXT NOT NULL,
                token_id TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_resolved_counts
                ON chio_hitl_resolved(subject_id, policy_id, outcome);

            CREATE TABLE IF NOT EXISTS chio_hitl_consumed_tokens (
                token_id TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                token_digest TEXT
                    CHECK (token_digest IS NULL OR (length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*')),
                consumed_at INTEGER NOT NULL,
                PRIMARY KEY (token_id, parameter_hash)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_chio_hitl_consumed_token_id
                ON chio_hitl_consumed_tokens(token_id);

            CREATE TABLE IF NOT EXISTS chio_hitl_operation_reservations (
                operation_id TEXT PRIMARY KEY
                    CHECK (length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
                approval_set_hash TEXT NOT NULL UNIQUE
                    CHECK (length(approval_set_hash) = 64 AND approval_set_hash NOT GLOB '*[^0-9a-f]*'),
                members_json TEXT NOT NULL
                    CHECK (
                        length(CAST(members_json AS BLOB)) BETWEEN 2 AND 262144
                    ),
                proposal_deadline INTEGER NOT NULL CHECK (proposal_deadline > 0),
                state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'cancelled'))
            );

            CREATE TABLE IF NOT EXISTS chio_hitl_operation_reservation_tokens (
                token_id TEXT PRIMARY KEY
                    CHECK (
                        length(CAST(token_id AS BLOB)) BETWEEN 1 AND 512
                        AND instr(token_id, char(0)) = 0
                    ),
                token_digest TEXT NOT NULL UNIQUE
                    CHECK (length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'),
                operation_id TEXT NOT NULL REFERENCES chio_hitl_operation_reservations(operation_id),
                position INTEGER NOT NULL CHECK (position >= 0),
                UNIQUE (operation_id, position)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_chio_hitl_operation_approval_set_hash
                ON chio_hitl_operation_reservations(approval_set_hash);

            CREATE TRIGGER IF NOT EXISTS chio_hitl_consumed_token_operation_exclusion
            BEFORE INSERT ON chio_hitl_consumed_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = NEW.token_id
                   OR (NEW.token_digest IS NOT NULL AND token_digest = NEW.token_digest)
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token is operation-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_token_legacy_exclusion
            BEFORE INSERT ON chio_hitl_operation_reservation_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_consumed_tokens
                WHERE token_id = NEW.token_id OR token_digest = NEW.token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token was consumed by the legacy registry');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_reservation_identity_immutable
            BEFORE UPDATE OF operation_id, approval_set_hash, members_json, proposal_deadline
            ON chio_hitl_operation_reservations
            BEGIN
                SELECT RAISE(ABORT, 'immutable approval reservation ownership');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_reservation_delete_forbidden
            BEFORE DELETE ON chio_hitl_operation_reservations
            BEGIN
                SELECT RAISE(ABORT, 'approval reservation tombstones cannot be deleted');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_reservation_transition_guard
            BEFORE UPDATE OF state ON chio_hitl_operation_reservations
            WHEN NOT (
                OLD.state = 'reserved'
                AND NEW.state IN ('committed', 'cancelled')
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid approval reservation transition');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_reservation_token_immutable
            BEFORE UPDATE ON chio_hitl_operation_reservation_tokens
            BEGIN
                SELECT RAISE(ABORT, 'immutable approval reservation token ownership');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_reservation_token_delete_forbidden
            BEFORE DELETE ON chio_hitl_operation_reservation_tokens
            BEGIN
                SELECT RAISE(ABORT, 'approval reservation token tombstones cannot be deleted');
            END;

            CREATE TABLE IF NOT EXISTS chio_hitl_threshold_proposals (
                proposal_id TEXT PRIMARY KEY
                    CHECK (length(CAST(proposal_id AS BLOB)) BETWEEN 1 AND 512 AND instr(proposal_id, char(0)) = 0),
                request_id TEXT NOT NULL UNIQUE
                    CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 512 AND instr(request_id, char(0)) = 0),
                server_id TEXT NOT NULL
                    CHECK (length(CAST(server_id AS BLOB)) BETWEEN 1 AND 512 AND instr(server_id, char(0)) = 0),
                tool_name TEXT NOT NULL
                    CHECK (length(CAST(tool_name AS BLOB)) BETWEEN 1 AND 512 AND instr(tool_name, char(0)) = 0),
                governed_intent_hash TEXT NOT NULL
                    CHECK (length(governed_intent_hash) = 64 AND governed_intent_hash NOT GLOB '*[^0-9a-f]*'),
                subject_key TEXT NOT NULL,
                authorization_capability_hash TEXT NOT NULL
                    CHECK (length(authorization_capability_hash) = 64 AND authorization_capability_hash NOT GLOB '*[^0-9a-f]*'),
                policy_hash TEXT NOT NULL
                    CHECK (length(policy_hash) = 64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
                required INTEGER NOT NULL CHECK (required > 0 AND required <= 32),
                eligible_set_digest TEXT NOT NULL
                    CHECK (length(eligible_set_digest) = 64 AND eligible_set_digest NOT GLOB '*[^0-9a-f]*'),
                proposal_created_at INTEGER NOT NULL CHECK (proposal_created_at >= 0),
                proposal_deadline INTEGER NOT NULL CHECK (proposal_deadline > proposal_created_at),
                policy_authority_key TEXT NOT NULL,
                canonical_proposal_json TEXT NOT NULL
                    CHECK (length(CAST(canonical_proposal_json AS BLOB)) BETWEEN 2 AND 262144),
                canonical_eligible_approvers_json TEXT NOT NULL
                    CHECK (length(CAST(canonical_eligible_approvers_json AS BLOB)) BETWEEN 2 AND 262144),
                submitter_fingerprint TEXT,
                separation_of_duties INTEGER NOT NULL CHECK (separation_of_duties IN (0, 1)),
                status TEXT NOT NULL CHECK (status IN ('collecting', 'satisfied', 'delivered', 'expired')),
                satisfied_at INTEGER,
                delivered_at INTEGER,
                CHECK (
                    (status = 'collecting' AND satisfied_at IS NULL AND delivered_at IS NULL)
                    OR (status = 'satisfied' AND satisfied_at IS NOT NULL AND delivered_at IS NULL)
                    OR (status = 'delivered' AND satisfied_at IS NOT NULL AND delivered_at IS NOT NULL)
                    OR (status = 'expired' AND delivered_at IS NULL)
                )
            );
            CREATE INDEX IF NOT EXISTS idx_chio_hitl_threshold_proposal_deadline
                ON chio_hitl_threshold_proposals(status, proposal_deadline);

            CREATE TABLE IF NOT EXISTS chio_hitl_threshold_votes (
                proposal_id TEXT NOT NULL REFERENCES chio_hitl_threshold_proposals(proposal_id),
                position INTEGER NOT NULL CHECK (position >= 0 AND position < 32),
                token_id TEXT NOT NULL UNIQUE
                    CHECK (length(CAST(token_id AS BLOB)) BETWEEN 1 AND 512 AND instr(token_id, char(0)) = 0),
                approver_fingerprint TEXT NOT NULL,
                canonical_token_digest TEXT NOT NULL UNIQUE
                    CHECK (length(canonical_token_digest) = 64 AND canonical_token_digest NOT GLOB '*[^0-9a-f]*'),
                canonical_token_json TEXT NOT NULL
                    CHECK (length(CAST(canonical_token_json AS BLOB)) BETWEEN 2 AND 262144),
                received_at INTEGER NOT NULL CHECK (received_at >= 0),
                PRIMARY KEY (proposal_id, position),
                UNIQUE (proposal_id, approver_fingerprint),
                UNIQUE (proposal_id, canonical_token_digest),
                UNIQUE (proposal_id, token_id)
            );

            CREATE TABLE IF NOT EXISTS chio_hitl_threshold_operation_transfers (
                operation_id TEXT PRIMARY KEY REFERENCES chio_hitl_operation_reservations(operation_id),
                proposal_id TEXT NOT NULL UNIQUE REFERENCES chio_hitl_threshold_proposals(proposal_id)
            );

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_proposal_identity_immutable
            BEFORE UPDATE OF proposal_id, request_id, server_id, tool_name,
                governed_intent_hash, subject_key,
                authorization_capability_hash, policy_hash, required, eligible_set_digest,
                proposal_created_at, proposal_deadline, policy_authority_key,
                canonical_proposal_json, canonical_eligible_approvers_json,
                submitter_fingerprint, separation_of_duties
            ON chio_hitl_threshold_proposals
            BEGIN
                SELECT RAISE(ABORT, 'immutable threshold proposal bindings');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_proposal_delete_forbidden
            BEFORE DELETE ON chio_hitl_threshold_proposals
            BEGIN
                SELECT RAISE(ABORT, 'threshold proposal tombstones cannot be deleted');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_proposal_transition_guard
            BEFORE UPDATE OF status, satisfied_at, delivered_at ON chio_hitl_threshold_proposals
            WHEN NOT (
                (OLD.status = 'collecting' AND NEW.status IN ('satisfied', 'expired'))
                OR (OLD.status = 'satisfied' AND NEW.status IN ('delivered', 'expired'))
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid threshold proposal transition');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_vote_immutable
            BEFORE UPDATE ON chio_hitl_threshold_votes
            BEGIN
                SELECT RAISE(ABORT, 'immutable threshold vote');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_vote_delete_forbidden
            BEFORE DELETE ON chio_hitl_threshold_votes
            BEGIN
                SELECT RAISE(ABORT, 'threshold vote tombstones cannot be deleted');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_vote_legacy_exclusion
            BEFORE INSERT ON chio_hitl_threshold_votes
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_consumed_tokens
                WHERE token_id = NEW.token_id OR token_digest = NEW.canonical_token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token was consumed by the legacy registry');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_vote_operation_exclusion
            BEFORE INSERT ON chio_hitl_threshold_votes
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = NEW.token_id OR token_digest = NEW.canonical_token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token is operation-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_consumed_token_threshold_exclusion
            BEFORE INSERT ON chio_hitl_consumed_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_threshold_votes
                WHERE token_id = NEW.token_id
                   OR (
                        NEW.token_digest IS NOT NULL
                        AND canonical_token_digest = NEW.token_digest
                   )
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token is threshold-proposal-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_token_threshold_transfer_guard
            BEFORE INSERT ON chio_hitl_operation_reservation_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_threshold_votes
                WHERE token_id = NEW.token_id OR canonical_token_digest = NEW.token_digest
            ) AND NOT EXISTS (
                SELECT 1
                FROM chio_hitl_threshold_operation_transfers AS transfer
                INNER JOIN chio_hitl_threshold_votes AS vote
                    ON vote.proposal_id = transfer.proposal_id
                WHERE transfer.operation_id = NEW.operation_id
                  AND vote.token_id = NEW.token_id
                  AND vote.canonical_token_digest = NEW.token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token threshold ownership transfer is invalid');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_transfer_immutable
            BEFORE UPDATE ON chio_hitl_threshold_operation_transfers
            BEGIN
                SELECT RAISE(ABORT, 'immutable threshold ownership transfer');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_threshold_transfer_delete_forbidden
            BEFORE DELETE ON chio_hitl_threshold_operation_transfers
            BEGIN
                SELECT RAISE(ABORT, 'threshold ownership transfer tombstones cannot be deleted');
            END;
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration: {e}")))?;
        conn.execute_batch(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_chio_hitl_consumed_token_digest
                ON chio_hitl_consumed_tokens(token_digest)
                WHERE token_digest IS NOT NULL;
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration index: {e}")))?;
        let dual_owner = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_hitl_consumed_tokens AS legacy
                INNER JOIN chio_hitl_operation_reservation_tokens AS operation
                    ON operation.token_id = legacy.token_id
                    OR operation.token_digest = legacy.token_digest
                LIMIT 1
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("migration audit: {e}")))?;
        if dual_owner.is_some() {
            return Err(ApprovalStoreError::Backend(
                "migration audit: approval token has legacy and operation ownership".to_string(),
            ));
        }
        let invalid_threshold_owner = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_hitl_threshold_votes AS vote
                LEFT JOIN chio_hitl_consumed_tokens AS legacy
                    ON legacy.token_id = vote.token_id
                    OR legacy.token_digest = vote.canonical_token_digest
                LEFT JOIN chio_hitl_operation_reservation_tokens AS operation
                    ON operation.token_id = vote.token_id
                    OR operation.token_digest = vote.canonical_token_digest
                LEFT JOIN chio_hitl_threshold_operation_transfers AS transfer
                    ON transfer.operation_id = operation.operation_id
                    AND transfer.proposal_id = vote.proposal_id
                WHERE legacy.token_id IS NOT NULL
                   OR (
                        operation.token_id IS NOT NULL
                        AND (
                            transfer.operation_id IS NULL
                            OR operation.token_id <> vote.token_id
                            OR operation.token_digest <> vote.canonical_token_digest
                        )
                   )
                LIMIT 1
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("migration audit: {e}")))?;
        if invalid_threshold_owner.is_some() {
            return Err(ApprovalStoreError::Backend(
                "migration audit: threshold approval token has conflicting replay ownership"
                    .to_string(),
            ));
        }
        crate::stamp_schema_version(
            &conn,
            APPROVAL_STORE_SCHEMA_KEY,
            APPROVAL_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        Ok(())
    }

    fn transition_approval_reservation(
        &self,
        operation_id: &str,
        target: ReplayReservationState,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        validate_reservation_operation_id(operation_id)?;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin reservation tx: {e}")))?;
        let current = load_approval_reservation(&tx, operation_id)?.ok_or_else(|| {
            ApprovalStoreError::NotFound(format!(
                "approval reservation for operation {operation_id}"
            ))
        })?;
        if current.state() == target {
            tx.rollback().map_err(|e| {
                ApprovalStoreError::Backend(format!("rollback reservation read: {e}"))
            })?;
            return Ok(current);
        }
        if current.state() != ReplayReservationState::Reserved {
            return Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` approval reservation cannot transition from {} to {}",
                current.state().as_str(),
                target.as_str()
            )));
        }
        if target == ReplayReservationState::Reserved {
            return Err(ApprovalStoreError::Replay(
                "approval reservation transition target must be terminal".to_string(),
            ));
        }
        let updated = tx
            .execute(
                r#"
                UPDATE chio_hitl_operation_reservations
                SET state = ?2
                WHERE operation_id = ?1 AND state = 'reserved'
                "#,
                params![operation_id, target.as_str()],
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("transition reservation: {e}")))?;
        if updated != 1 {
            return Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` approval reservation changed concurrently"
            )));
        }
        let transitioned = ApprovalReservation::from_persisted_parts(
            current.operation_id().to_string(),
            current.approval_set().clone(),
            target,
        )?;
        tx.commit().map_err(|e| {
            ApprovalStoreError::Backend(format!("commit reservation transition: {e}"))
        })?;
        Ok(transitioned)
    }
}

fn configure_reservation_connection(connection: &Connection) -> Result<(), ApprovalStoreError> {
    connection
        .execute_batch(
            r#"
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("configure reservation DB: {e}")))?;
    Ok(())
}

fn validate_reservation_operation_id(operation_id: &str) -> Result<(), ApprovalStoreError> {
    if operation_id.len() != 64
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ApprovalStoreError::Invalid(
            "operation_id must be lowercase SHA-256 hex".to_string(),
        ));
    }
    Ok(())
}

fn serialize_reservation_members(
    members: &[ApprovalReservationMember],
) -> Result<String, ApprovalStoreError> {
    let serialized = serde_json::to_string(members)
        .map_err(|e| ApprovalStoreError::Serialization(e.to_string()))?;
    if serialized.len() > MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES {
        return Err(ApprovalStoreError::Invalid(
            "serialized approval reservation members exceed the storage limit".to_string(),
        ));
    }
    Ok(serialized)
}

fn load_approval_reservation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
    let row = connection
        .query_row(
            r#"
            SELECT approval_set_hash, members_json, proposal_deadline, state
            FROM chio_hitl_operation_reservations
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| ApprovalStoreError::Backend(format!("load approval reservation: {e}")))?;
    let Some((approval_set_hash, members_json, proposal_deadline, state)) = row else {
        return Ok(None);
    };
    if members_json.len() > MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES {
        return Err(ApprovalStoreError::Serialization(
            "persisted approval reservation members exceed the storage limit".to_string(),
        ));
    }
    let members = serde_json::from_str::<Vec<ApprovalReservationMember>>(&members_json)
        .map_err(|e| ApprovalStoreError::Serialization(e.to_string()))?;
    let state = ReplayReservationState::parse(&state).ok_or_else(|| {
        ApprovalStoreError::Serialization("unknown approval reservation state".to_string())
    })?;
    let proposal_deadline = u64::try_from(proposal_deadline).map_err(|_| {
        ApprovalStoreError::Serialization(
            "approval reservation proposal deadline is negative".to_string(),
        )
    })?;
    let approval_set = ApprovalSetReservationInput::from_persisted_parts(
        approval_set_hash,
        members,
        proposal_deadline,
    )?;
    let reservation =
        ApprovalReservation::from_persisted_parts(operation_id.to_string(), approval_set, state)?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT position, token_id, token_digest
            FROM chio_hitl_operation_reservation_tokens
            WHERE operation_id = ?1
            ORDER BY position ASC
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("prepare reservation tokens: {e}")))?;
    let rows = statement
        .query_map(params![operation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| ApprovalStoreError::Backend(format!("query reservation tokens: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApprovalStoreError::Backend(format!("read reservation tokens: {e}")))?;
    let mut persisted_members = Vec::with_capacity(rows.len());
    for (expected_position, (position, token_id, token_digest)) in rows.into_iter().enumerate() {
        if position != expected_position as i64 {
            return Err(ApprovalStoreError::Serialization(
                "approval reservation token positions are not contiguous".to_string(),
            ));
        }
        persisted_members.push(
            ApprovalReservationMember::new(token_id, token_digest).map_err(|error| {
                ApprovalStoreError::Serialization(format!(
                    "persisted approval reservation token is invalid: {error}"
                ))
            })?,
        );
    }
    if persisted_members != reservation.approval_set().members() {
        return Err(ApprovalStoreError::Serialization(
            "approval reservation token ownership diverges from its member set".to_string(),
        ));
    }
    Ok(Some(reservation))
}

fn sqlite_u64(value: i64, field: &str) -> Result<u64, ApprovalStoreError> {
    u64::try_from(value).map_err(|_| {
        ApprovalStoreError::Serialization(format!(
            "persisted threshold proposal field `{field}` is negative"
        ))
    })
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, ApprovalStoreError> {
    i64::try_from(value).map_err(|_| {
        ApprovalStoreError::Invalid(format!(
            "threshold proposal field `{field}` exceeds SQLite INTEGER"
        ))
    })
}

fn canonical_artifact_json<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<String, ApprovalStoreError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        ApprovalStoreError::Invalid(format!("{label} canonicalization failed: {error}"))
    })?;
    if canonical.len() > MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES {
        return Err(ApprovalStoreError::Invalid(format!(
            "{label} exceeds the collector storage limit"
        )));
    }
    String::from_utf8(canonical).map_err(|error| {
        ApprovalStoreError::Invalid(format!("{label} canonical JSON is not UTF-8: {error}"))
    })
}

fn decode_canonical_artifact<T: DeserializeOwned + Serialize>(
    raw: &str,
    label: &str,
) -> Result<T, ApprovalStoreError> {
    if raw.len() > MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES {
        return Err(ApprovalStoreError::Serialization(format!(
            "persisted {label} exceeds the collector storage limit"
        )));
    }
    let strict = canonical_json_bytes_from_str(raw).map_err(|error| {
        ApprovalStoreError::Serialization(format!(
            "persisted {label} is not strict I-JSON: {error}"
        ))
    })?;
    if strict.as_slice() != raw.as_bytes() {
        return Err(ApprovalStoreError::Serialization(format!(
            "persisted {label} is not canonical JSON"
        )));
    }
    let value = serde_json::from_slice::<T>(&strict).map_err(|error| {
        ApprovalStoreError::Serialization(format!("persisted {label} cannot be decoded: {error}"))
    })?;
    let typed = canonical_json_bytes(&value).map_err(|error| {
        ApprovalStoreError::Serialization(format!(
            "persisted {label} cannot be recanonicalized: {error}"
        ))
    })?;
    if typed != strict {
        return Err(ApprovalStoreError::Serialization(format!(
            "persisted {label} contains non-schema fields"
        )));
    }
    Ok(value)
}

fn load_threshold_proposal(
    connection: &Connection,
    proposal_id: &str,
) -> Result<Option<ThresholdApprovalProposalRecord>, ApprovalStoreError> {
    type ProposalRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        String,
        String,
        String,
        Option<String>,
        i64,
        String,
        Option<i64>,
        Option<i64>,
    );
    let row: Option<ProposalRow> = connection
        .query_row(
            r#"
            SELECT proposal_id, request_id, server_id, tool_name,
                   governed_intent_hash, subject_key,
                   authorization_capability_hash, policy_hash, required,
                   eligible_set_digest, proposal_created_at, proposal_deadline,
                   policy_authority_key, canonical_proposal_json,
                   canonical_eligible_approvers_json, submitter_fingerprint,
                   separation_of_duties, status, satisfied_at, delivered_at
            FROM chio_hitl_threshold_proposals
            WHERE proposal_id = ?1
            "#,
            params![proposal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, Option<String>>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, Option<i64>>(18)?,
                    row.get::<_, Option<i64>>(19)?,
                ))
            },
        )
        .optional()
        .map_err(|error| {
            ApprovalStoreError::Backend(format!("load threshold proposal: {error}"))
        })?;
    let Some((
        stored_proposal_id,
        request_id,
        server_id,
        tool_name,
        governed_intent_hash,
        subject_key,
        authorization_capability_hash,
        policy_hash,
        required,
        eligible_set_digest,
        proposal_created_at,
        proposal_deadline,
        policy_authority_key,
        canonical_proposal_json,
        canonical_eligible_approvers_json,
        submitter_fingerprint,
        separation_of_duties,
        status,
        satisfied_at,
        delivered_at,
    )) = row
    else {
        return Ok(None);
    };

    let proposal = decode_canonical_artifact::<ThresholdApprovalProposal>(
        &canonical_proposal_json,
        "threshold proposal",
    )?;
    let eligible_approvers = decode_canonical_artifact::<BTreeMap<String, PublicKey>>(
        &canonical_eligible_approvers_json,
        "threshold eligible approvers",
    )?;
    let body = proposal.body();
    let required = u32::try_from(required).map_err(|_| {
        ApprovalStoreError::Serialization(
            "persisted threshold proposal requirement is out of range".to_string(),
        )
    })?;
    if stored_proposal_id != body.proposal_id()
        || request_id != body.request_id()
        || governed_intent_hash != body.governed_intent_hash()
        || subject_key != body.subject().to_hex()
        || authorization_capability_hash != body.authorization_capability_hash()
        || policy_hash != body.policy_hash()
        || required != body.required()
        || eligible_set_digest != body.eligible_set_digest()
        || sqlite_u64(proposal_created_at, "proposal_created_at")? != body.proposal_created_at()
        || sqlite_u64(proposal_deadline, "proposal_deadline")? != body.proposal_deadline()
        || policy_authority_key != proposal.policy_authority().to_hex()
    {
        return Err(ApprovalStoreError::Serialization(
            "persisted threshold proposal metadata diverges from its signed proposal".to_string(),
        ));
    }
    let separation_of_duties = match separation_of_duties {
        0 => false,
        1 => true,
        _ => {
            return Err(ApprovalStoreError::Serialization(
                "persisted separation-of-duties flag is invalid".to_string(),
            ))
        }
    };
    let registration = ThresholdApprovalProposalRegistration::from_persisted_parts(
        proposal,
        server_id,
        tool_name,
        eligible_approvers,
        submitter_fingerprint,
        separation_of_duties,
    )?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT position, token_id, approver_fingerprint,
                   canonical_token_digest, canonical_token_json, received_at
            FROM chio_hitl_threshold_votes
            WHERE proposal_id = ?1
            ORDER BY position ASC
            "#,
        )
        .map_err(|error| {
            ApprovalStoreError::Backend(format!("prepare threshold votes: {error}"))
        })?;
    let rows = statement
        .query_map(params![stored_proposal_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| ApprovalStoreError::Backend(format!("query threshold votes: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ApprovalStoreError::Backend(format!("read threshold votes: {error}")))?;
    let mut votes = Vec::with_capacity(rows.len());
    for (expected_position, row) in rows.into_iter().enumerate() {
        let (position, token_id, approver_fingerprint, token_digest, token_json, received_at) = row;
        if position != expected_position as i64 {
            return Err(ApprovalStoreError::Serialization(
                "persisted threshold vote positions are not contiguous".to_string(),
            ));
        }
        let token = decode_canonical_artifact::<GovernedApprovalToken>(
            &token_json,
            "threshold approval token",
        )?;
        if token.id != token_id {
            return Err(ApprovalStoreError::Serialization(
                "persisted threshold vote token ID diverges from its signed token".to_string(),
            ));
        }
        votes.push(ThresholdApprovalVoteRecord::from_persisted_parts(
            &registration,
            token,
            token_digest,
            approver_fingerprint,
            sqlite_u64(received_at, "vote_received_at")?,
        )?);
    }

    let status = ThresholdApprovalCollectorStatus::parse(&status).ok_or_else(|| {
        ApprovalStoreError::Serialization(
            "persisted threshold proposal has an unknown status".to_string(),
        )
    })?;
    ThresholdApprovalProposalRecord::from_persisted_parts(
        registration,
        status,
        votes,
        satisfied_at
            .map(|value| sqlite_u64(value, "satisfied_at"))
            .transpose()?,
        delivered_at
            .map(|value| sqlite_u64(value, "delivered_at"))
            .transpose()?,
    )
    .map(Some)
}

fn persist_threshold_expiry(
    connection: &Connection,
    proposal_id: &str,
    status: ThresholdApprovalCollectorStatus,
    now: u64,
    deadline: u64,
) -> Result<bool, ApprovalStoreError> {
    if matches!(
        status,
        ThresholdApprovalCollectorStatus::Collecting | ThresholdApprovalCollectorStatus::Satisfied
    ) && now >= deadline
    {
        let updated = connection
            .execute(
                r#"
                UPDATE chio_hitl_threshold_proposals
                SET status = 'expired'
                WHERE proposal_id = ?1 AND status = ?2
                "#,
                params![proposal_id, status.as_str()],
            )
            .map_err(|error| {
                ApprovalStoreError::Backend(format!("persist threshold expiry: {error}"))
            })?;
        if updated != 1 {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal state changed concurrently".to_string(),
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

fn threshold_transfer_proposal(
    connection: &Connection,
    approval_set: &ApprovalSetReservationInput,
) -> Result<Option<String>, ApprovalStoreError> {
    let mut proposal_id: Option<String> = None;
    let mut matched = 0usize;
    for member in approval_set.members() {
        let owner = connection
            .query_row(
                r#"
                SELECT proposal_id, token_id, canonical_token_digest
                FROM chio_hitl_threshold_votes
                WHERE token_id = ?1 OR canonical_token_digest = ?2
                LIMIT 1
                "#,
                params![member.token_id(), member.token_digest()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| {
                ApprovalStoreError::Backend(format!(
                    "query threshold token transfer owner: {error}"
                ))
            })?;
        let Some((owner, token_id, token_digest)) = owner else {
            if proposal_id.is_some() {
                return Err(ApprovalStoreError::Replay(
                    "approval set only partially belongs to a threshold proposal".to_string(),
                ));
            }
            continue;
        };
        if token_id != member.token_id() || token_digest != member.token_digest() {
            return Err(ApprovalStoreError::Replay(
                "approval set rebinds a threshold-owned token identity".to_string(),
            ));
        }
        if let Some(expected) = proposal_id.as_deref() {
            if expected != owner {
                return Err(ApprovalStoreError::Replay(
                    "approval set spans more than one threshold proposal".to_string(),
                ));
            }
        } else {
            proposal_id = Some(owner);
        }
        matched += 1;
    }
    let Some(proposal_id) = proposal_id else {
        return Ok(None);
    };
    if matched != approval_set.members().len() {
        return Err(ApprovalStoreError::Replay(
            "approval set only partially belongs to a threshold proposal".to_string(),
        ));
    }
    let record = load_threshold_proposal(connection, &proposal_id)?.ok_or_else(|| {
        ApprovalStoreError::Serialization(
            "threshold token owner references a missing proposal".to_string(),
        )
    })?;
    if !matches!(
        record.status(),
        ThresholdApprovalCollectorStatus::Satisfied | ThresholdApprovalCollectorStatus::Delivered
    ) {
        return Err(ApprovalStoreError::Replay(
            "threshold-owned approval tokens require an exact satisfied-proposal transfer"
                .to_string(),
        ));
    }
    let expected = record.reservation_input()?;
    if &expected != approval_set {
        return Err(ApprovalStoreError::Replay(
            "approval set does not exactly match its satisfied threshold proposal".to_string(),
        ));
    }
    Ok(Some(proposal_id))
}

fn serialize_payload(request: &ApprovalRequest) -> Result<String, ApprovalStoreError> {
    serde_json::to_string(request).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}

fn deserialize_payload(raw: &str) -> Result<ApprovalRequest, ApprovalStoreError> {
    serde_json::from_str(raw).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}
