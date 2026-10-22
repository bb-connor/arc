//! SQLite-backed HITL approval store.
//!
//! Pending requests survive kernel restart because every `store_pending`
//! call persists into a WAL-journaled SQLite database. Duplicate ids are
//! idempotent only when the serialized payload matches exactly; mismatched
//! retries are rejected so in-flight HITL state cannot be silently
//! overwritten. Resolved approvals and consumed tokens live in the same
//! database so the replay registry survives alongside the pending log.
//!
//! The store is synchronous; it uses a small r2d2 pool to keep the
//! hot-path query against a cheap connection pool rather than opening a
//! new file handle per call.

use std::fs;
use std::path::Path;

use chio_kernel::approval::{
    ApprovalReservation, ApprovalReservationMember, ApprovalSetReservationInput,
    ApprovalStoreProfile,
};
use chio_kernel::security_admission_operation::ReplayReservationState;
use chio_kernel::{
    ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest, ApprovalStore,
    ApprovalStoreError, ResolvedApproval,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES: usize = 262_144;

mod threshold_collector;

/// SQLite-backed `ApprovalStore`.
///
pub struct SqliteApprovalStore {
    pool: Pool<SqliteConnectionManager>,
}

const APPROVAL_STORE_SCHEMA_KEY: &str = "approval";
pub(crate) const APPROVAL_SCHEMA: &str = r#"

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

            CREATE TABLE IF NOT EXISTS chio_hitl_decision_artifacts (
                approval_id TEXT PRIMARY KEY REFERENCES chio_hitl_resolved(approval_id),
                request_json TEXT NOT NULL,
                token_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_hitl_consumed_tokens (
                token_id TEXT NOT NULL,
                parameter_hash TEXT NOT NULL,
                token_digest TEXT NOT NULL
                    CHECK (typeof(token_digest) = 'text' AND length(token_digest) = 64 AND instr(token_digest, char(0)) = 0 AND octet_length(token_digest) <= 256 AND token_digest NOT GLOB '*[^0-9a-f]*'),
                consumed_at INTEGER NOT NULL,
                PRIMARY KEY (token_id, parameter_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_hitl_operation_reservations (
                operation_id TEXT PRIMARY KEY
                    CHECK (length(operation_id) = 64 AND instr(operation_id, char(0)) = 0 AND octet_length(operation_id) <= 256 AND operation_id NOT GLOB '*[^0-9a-f]*'),
                approval_set_hash TEXT NOT NULL UNIQUE
                    CHECK (typeof(approval_set_hash) = 'text' AND length(approval_set_hash) = 64 AND instr(approval_set_hash, char(0)) = 0 AND octet_length(approval_set_hash) <= 256 AND approval_set_hash NOT GLOB '*[^0-9a-f]*'),
                members_json TEXT NOT NULL
                    CHECK (octet_length(members_json) BETWEEN 2 AND 262144),
                proposal_deadline INTEGER NOT NULL CHECK (proposal_deadline > 0),
                state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'cancelled'))
            );

            CREATE TABLE IF NOT EXISTS chio_hitl_operation_reservation_tokens (
                token_id TEXT PRIMARY KEY
                    CHECK (octet_length(token_id) BETWEEN 1 AND 512 AND instr(token_id, char(0)) = 0),
                token_digest TEXT NOT NULL UNIQUE
                    CHECK (typeof(token_digest) = 'text' AND length(token_digest) = 64 AND instr(token_digest, char(0)) = 0 AND octet_length(token_digest) <= 256 AND token_digest NOT GLOB '*[^0-9a-f]*'),
                operation_id TEXT NOT NULL REFERENCES chio_hitl_operation_reservations(operation_id),
                position INTEGER NOT NULL CHECK (position >= 0),
                UNIQUE (operation_id, position)
            );

            CREATE TRIGGER IF NOT EXISTS chio_hitl_consumed_token_operation_exclusion
            BEFORE INSERT ON chio_hitl_consumed_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = NEW.token_id OR token_digest = NEW.token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token is operation-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_token_resolution_exclusion
            BEFORE INSERT ON chio_hitl_operation_reservation_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_consumed_tokens
                WHERE token_id = NEW.token_id OR token_digest = NEW.token_digest
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token was consumed by a pending-request resolution');
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
            WHEN NOT (OLD.state = 'reserved' AND NEW.state IN ('committed', 'cancelled'))
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

            CREATE TABLE IF NOT EXISTS chio_threshold_approval_collectors (
                proposal_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                governed_intent_hash TEXT NOT NULL,
                subject_fingerprint TEXT NOT NULL,
                authorizing_capability_digest TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                threshold INTEGER NOT NULL CHECK (threshold > 0),
                eligible_set_digest TEXT NOT NULL,
                proposal_created_at INTEGER NOT NULL,
                proposal_deadline INTEGER NOT NULL,
                submitter_fingerprint TEXT,
                require_submitter_separation INTEGER NOT NULL CHECK (
                    require_submitter_separation IN (0, 1)
                ),
                state TEXT NOT NULL CHECK (
                    state IN ('collecting', 'ready', 'delivered', 'cancelled')
                ),
                version INTEGER NOT NULL CHECK (version >= 0),
                updated_at INTEGER NOT NULL,
                proposal_json BLOB NOT NULL,
                requirement_json BLOB NOT NULL,
                record_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_threshold_approval_collector_votes (
                proposal_id TEXT NOT NULL,
                token_id TEXT NOT NULL,
                approver_fingerprint TEXT NOT NULL,
                canonical_token_digest TEXT NOT NULL UNIQUE,
                token_json BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (proposal_id, token_id),
                UNIQUE (proposal_id, approver_fingerprint),
                UNIQUE (proposal_id, canonical_token_digest),
                FOREIGN KEY (proposal_id)
                    REFERENCES chio_threshold_approval_collectors(proposal_id)
            );
            "#;

impl SqliteApprovalStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        Self::open_with_mode(path, false)
    }

    pub fn open_colocated_with_receipt_store(
        path: impl AsRef<Path>,
    ) -> Result<Self, ApprovalStoreError> {
        Self::open_with_mode(path, true)
    }

    fn open_with_mode(path: impl AsRef<Path>, colocated: bool) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        // Derive the directory from the resolved filesystem path: a co-located
        // approval store opens the same `file:` URI as the receipt store (for
        // example `file:/var/lib/chio/receipts.db?mode=rwc`), whose scheme and
        // query a raw `parent()` would fold into a bogus directory, leaving the
        // real one uncreated so SQLite fails to open the database.
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(&parent)
                .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = crate::pool::sqlite_pool_builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.open_schema(colocated)?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, ApprovalStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = crate::pool::sqlite_pool_builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.open_schema(false)?;
        Ok(store)
    }

    fn open_schema(&self, colocated: bool) -> Result<(), ApprovalStoreError> {
        let mut connection = self
            .pool
            .get()
            .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        if colocated {
            let snapshot = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
            let state = crate::schema_version::inspect_schema(&snapshot, &["receipt", "approval"])
                .map_err(ApprovalStoreError::from)?;
            if state != crate::SchemaState::Current {
                return Err(crate::SchemaVersionError::CreationNotAllowed.into());
            }
            crate::receipt_store::validate_receipt_catalog(&snapshot, true)
                .map_err(crate::schema_version::receipt_schema_error_to_approval)?;
            snapshot
                .commit()
                .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        } else {
            let schema = crate::schema_version::SchemaTransaction::begin(
                &mut connection,
                &[APPROVAL_STORE_SCHEMA_KEY],
            )
            .map_err(ApprovalStoreError::from)?;
            if schema.is_fresh() {
                schema
                    .connection()
                    .execute_batch(APPROVAL_SCHEMA)
                    .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
                schema
                    .stamp(APPROVAL_STORE_SCHEMA_KEY)
                    .map_err(ApprovalStoreError::from)?;
            }
            schema
                .validate_catalog(APPROVAL_SCHEMA)
                .map_err(ApprovalStoreError::from)?;
            schema.commit().map_err(ApprovalStoreError::from)?;
        }
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;")
            .map_err(|error| ApprovalStoreError::Backend(error.to_string()))?;
        Ok(())
    }
}

fn serialize_payload(request: &ApprovalRequest) -> Result<String, ApprovalStoreError> {
    let bytes = chio_core::canonical_json_bytes(request)
        .map_err(|error| ApprovalStoreError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| ApprovalStoreError::Serialization(error.to_string()))
}

fn deserialize_payload(raw: &str) -> Result<ApprovalRequest, ApprovalStoreError> {
    chio_core::canonical::UntrustedJsonText::from_wire((raw).as_bytes(), 64 * 1024 * 1024)
        .and_then(|input| input.decode_signed())
        .map_err(ApprovalStoreError::from)
}

impl ApprovalStore for SqliteApprovalStore {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        ApprovalStoreProfile::SingleNodeDurable
    }

    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let payload = serialize_payload(request)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let returned_payload = conn
            .query_row(
                r#"
            INSERT INTO chio_hitl_pending (approval_id, policy_id, subject_id, tool_server, tool_name, parameter_hash, expires_at, created_at, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(approval_id) DO UPDATE SET payload = excluded.payload WHERE chio_hitl_pending.payload = excluded.payload RETURNING payload
            "#,
                params![
                    request.approval_id,
                    request.policy_id,
                    request.subject_id,
                    request.tool_server,
                    request.tool_name,
                    request.parameter_hash,
                    crate::integer::checked::<_, i64>(request.expires_at)?,
                    crate::integer::checked::<_, i64>(request.created_at)?,
                    payload,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("insert pending: {e}")))?;
        if returned_payload.is_none() {
            return Err(ApprovalStoreError::Backend(format!(
                "approval_id {} already exists with different payload",
                request.approval_id
            )));
        }
        Ok(())
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<String> = conn
            .query_row(
                "SELECT payload FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select pending: {e}")))?;
        match row {
            Some(raw) => Ok(Some(deserialize_payload(&raw)?)),
            None => Ok(None),
        }
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let mut sql = String::from("SELECT payload FROM chio_hitl_pending WHERE 1=1");
        if filter.subject_id.is_some() {
            sql.push_str(" AND subject_id = :subject_id");
        }
        if filter.tool_server.is_some() {
            sql.push_str(" AND tool_server = :tool_server");
        }
        if filter.tool_name.is_some() {
            sql.push_str(" AND tool_name = :tool_name");
        }
        if filter.not_expired_at.is_some() {
            sql.push_str(" AND expires_at > :not_expired_at");
        }
        sql.push_str(" ORDER BY created_at ASC");
        if filter.limit.is_some() {
            sql.push_str(" LIMIT :limit");
        }

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ApprovalStoreError::Backend(format!("prepare list: {e}")))?;

        let mut params_vec: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();
        if let Some(s) = &filter.subject_id {
            params_vec.push((":subject_id", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_server {
            params_vec.push((":tool_server", Box::new(s.clone())));
        }
        if let Some(s) = &filter.tool_name {
            params_vec.push((":tool_name", Box::new(s.clone())));
        }
        if let Some(t) = &filter.not_expired_at {
            params_vec.push((
                ":not_expired_at",
                Box::new(crate::integer::checked::<_, i64>(*t)?),
            ));
        }
        if let Some(limit) = &filter.limit {
            params_vec.push((
                ":limit",
                Box::new(crate::integer::checked::<_, i64>(*limit)?),
            ));
        }

        let refs: Vec<(&str, &dyn rusqlite::ToSql)> = params_vec
            .iter()
            .map(|(name, value)| (*name, value.as_ref()))
            .collect();

        let rows = stmt
            .query_map(refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|e| ApprovalStoreError::Backend(format!("query list: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| ApprovalStoreError::Backend(format!("row: {e}")))?;
            out.push(deserialize_payload(&raw)?);
        }
        Ok(out)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin tx: {e}")))?;

        // Pull pending record inside the tx to avoid TOCTOU races.
        let pending: Option<(String, String, String)> = tx
            .query_row(
                "SELECT policy_id, parameter_hash, CASE WHEN typeof(payload) = 'text' AND octet_length(payload) <= 1048576 THEN payload ELSE NULL END FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select: {e}")))?;
        let (policy_id, parameter_hash, request_json) = match pending {
            Some(p) => p,
            None => return Err(ApprovalStoreError::NotFound(id.to_string())),
        };

        let pending_request = deserialize_payload(&request_json)?;
        let approval_token = chio_kernel::ApprovalToken::from_decision(decision);
        let verified = approval_token
            .verify_against(&pending_request, decision.received_at)
            .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?;
        let approved = matches!(
            verified,
            chio_core::capability::governance::GovernedApprovalDecision::Approved
        );
        if approved != (decision.outcome == ApprovalOutcome::Approved) {
            return Err(ApprovalStoreError::Invalid(
                "signed decision disagrees with resolution".into(),
            ));
        }
        let token_json = chio_core::canonical_json_bytes(&decision.token)
            .map_err(|error| ApprovalStoreError::Serialization(error.to_string()))?;
        let token_json = String::from_utf8(token_json)
            .map_err(|error| ApprovalStoreError::Serialization(error.to_string()))?;
        let token_digest = decision
            .token
            .artifact_digest()
            .map_err(|error| ApprovalStoreError::Serialization(error.to_string()))?;

        // Replay guard: the bound token must not already be consumed.
        let already: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 AND parameter_hash = ?2",
                params![decision.token.id, parameter_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("replay check: {e}")))?;
        if already.is_some() {
            return Err(ApprovalStoreError::Replay(id.to_string()));
        }

        // Idempotency: if already resolved, treat as AlreadyResolved.
        let already_resolved: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_resolved WHERE approval_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("resolved check: {e}")))?;
        if already_resolved.is_some() {
            return Err(ApprovalStoreError::AlreadyResolved(id.to_string()));
        }

        let outcome = match decision.outcome {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Denied => "denied",
        };

        tx.execute(
            r#"INSERT INTO chio_hitl_resolved (
                approval_id, policy_id, subject_id, outcome, resolved_at,
                approver_hex, token_id
            ) SELECT approval_id, policy_id, subject_id, ?2, ?3, ?4, ?5
            FROM chio_hitl_pending WHERE approval_id = ?1"#,
            params![
                id,
                outcome,
                crate::integer::checked::<_, i64>(decision.received_at)?,
                decision.approver.to_hex(),
                decision.token.id,
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert resolved: {e}")))?;

        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, token_digest, consumed_at) VALUES (?1, ?2, ?3, ?4)",
            params![decision.token.id, parameter_hash, token_digest, crate::integer::checked::<_, i64>(decision.received_at)?],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;

        tx.execute(
            "INSERT INTO chio_hitl_decision_artifacts (approval_id, request_json, token_json) VALUES (?1, ?2, ?3)",
            params![id, request_json, token_json],
        ).map_err(|error| ApprovalStoreError::Backend(format!("retain decision artifacts: {error}")))?;

        tx.execute(
            "DELETE FROM chio_hitl_pending WHERE approval_id = ?1",
            params![id],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("delete pending: {e}")))?;

        tx.commit()
            .map_err(|e| ApprovalStoreError::Backend(format!("commit: {e}")))?;

        // policy_id is part of the trait signature but unused on this path.
        let _ = policy_id;
        Ok(())
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_hitl_resolved WHERE subject_id = ?1 AND policy_id = ?2 AND outcome = 'approved'",
                params![subject_id, policy_id],
                |row| row.get(0),
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("count: {e}")))?;
        Ok(u64::try_from(count.max(0)).unwrap_or_default())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 AND parameter_hash = ?2",
                params![token_id, parameter_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("is_consumed: {e}")))?;
        Ok(row.is_some())
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<(String, String, i64, String, String)> = conn
            .query_row(
                r#"SELECT approval_id, outcome, resolved_at, approver_hex, token_id
                   FROM chio_hitl_resolved WHERE approval_id = ?1"#,
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("get_resolution: {e}")))?;
        match row {
            Some((approval_id, outcome_str, resolved_at, approver_hex, token_id)) => {
                let outcome = match outcome_str.as_str() {
                    "approved" => ApprovalOutcome::Approved,
                    "denied" => ApprovalOutcome::Denied,
                    other => {
                        return Err(ApprovalStoreError::Serialization(format!(
                            "unknown outcome: {other}"
                        )))
                    }
                };
                let artifacts: Option<(String, String)> = conn.query_row(
                    "SELECT CASE WHEN octet_length(request_json) <= 1048576 THEN request_json ELSE NULL END, CASE WHEN octet_length(token_json) <= 1048576 THEN token_json ELSE NULL END FROM chio_hitl_decision_artifacts WHERE approval_id = ?1",
                    params![id], |row| Ok((row.get(0)?, row.get(1)?)),
                ).optional().map_err(|error| ApprovalStoreError::Backend(format!("load decision artifacts: {error}")))?;
                let Some((request, token)) = artifacts else {
                    return Err(ApprovalStoreError::Serialization(format!(
                        "resolved approval {approval_id} has no retained request and signed decision"
                    )));
                };
                let request = deserialize_payload(&request)?;
                let token = chio_core::canonical::UntrustedJsonText::from_wire(
                    token.as_bytes(),
                    1024 * 1024,
                )
                .and_then(|input| input.decode_signed())?;
                Ok(Some(ResolvedApproval {
                    request,
                    token,
                    approval_id,
                    outcome,
                    resolved_at: u64::try_from(resolved_at.max(0)).unwrap_or_default(),
                    approver_hex,
                    token_id,
                }))
            }
            None => Ok(None),
        }
    }

    fn reserve_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        let requested = ApprovalReservation::new(operation_id.to_string(), approval_set.clone())?;
        let members_json = serialize_reservation_members(requested.approval_set().members())?;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin reservation tx: {e}")))?;

        if let Some(existing) = load_approval_reservation(&tx, operation_id)? {
            if existing.approval_set() == requested.approval_set() {
                tx.rollback().map_err(|e| {
                    ApprovalStoreError::Backend(format!("rollback reservation retry: {e}"))
                })?;
                return Ok(existing);
            }
            return Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` is already bound to a different approval-token set"
            )));
        }

        for member in requested.approval_set().members() {
            let resolution_consumed = tx
                .query_row(
                    r#"
                    SELECT 1 FROM chio_hitl_consumed_tokens
                    WHERE token_id = ?1 OR token_digest = ?2
                    LIMIT 1
                    "#,
                    params![member.token_id(), member.token_digest()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|e| {
                    ApprovalStoreError::Backend(format!("query resolution token replay: {e}"))
                })?;
            if resolution_consumed.is_some() {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token `{}` was already consumed",
                    member.token_id()
                )));
            }

            let owner = tx
                .query_row(
                    r#"
                    SELECT operation_id FROM chio_hitl_operation_reservation_tokens
                    WHERE token_id = ?1 OR token_digest = ?2
                    LIMIT 1
                    "#,
                    params![member.token_id(), member.token_digest()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| ApprovalStoreError::Backend(format!("query token owner: {e}")))?;
            if let Some(owner) = owner {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token is already owned by operation `{owner}`"
                )));
            }
        }

        tx.execute(
            r#"
            INSERT INTO chio_hitl_operation_reservations (
                operation_id, approval_set_hash, members_json, proposal_deadline, state
            ) VALUES (?1, ?2, ?3, ?4, 'reserved')
            "#,
            params![
                operation_id,
                requested.approval_set().approval_set_hash(),
                members_json,
                i64::try_from(requested.approval_set().proposal_deadline()).map_err(|_| {
                    ApprovalStoreError::Backend(
                        "approval reservation proposal deadline exceeds SQLite INTEGER".to_string(),
                    )
                })?
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert reservation: {e}")))?;
        for (position, member) in requested.approval_set().members().iter().enumerate() {
            tx.execute(
                r#"
                INSERT INTO chio_hitl_operation_reservation_tokens (
                    token_id, token_digest, operation_id, position
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    member.token_id(),
                    member.token_digest(),
                    operation_id,
                    i64::try_from(position).map_err(|_| ApprovalStoreError::Backend(
                        "approval reservation token position exceeds SQLite INTEGER".to_string(),
                    ))?
                ],
            )
            .map_err(|e| ApprovalStoreError::Backend(format!("insert reservation token: {e}")))?;
        }
        tx.commit().map_err(|e| {
            ApprovalStoreError::Backend(format!("commit approval reservation: {e}"))
        })?;
        Ok(requested)
    }

    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        transition_approval_reservation(self, operation_id, ReplayReservationState::Committed)
    }

    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        transition_approval_reservation(self, operation_id, ReplayReservationState::Cancelled)
    }

    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        load_approval_reservation(&conn, operation_id)
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
        .map_err(|e| ApprovalStoreError::Backend(format!("configure reservation DB: {e}")))
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

#[allow(
    clippy::indexing_slicing,
    reason = "Short-circuit length equality proves every enumerated stored row has a corresponding approval member."
)]
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
    let members = chio_core::canonical::UntrustedJsonText::from_wire(
        members_json.as_bytes(),
        MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES,
    )
    .and_then(|input| input.decode_signed::<Vec<ApprovalReservationMember>>())?;
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
    let stored = statement
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
    if stored.len() != reservation.approval_set().members().len()
        || stored.iter().enumerate().any(|(position, row)| {
            let expected = &reservation.approval_set().members()[position];
            row.0 != i64::try_from(position).unwrap_or(i64::MAX)
                || row.1 != expected.token_id()
                || row.2 != expected.token_digest()
        })
    {
        return Err(ApprovalStoreError::Serialization(
            "persisted approval reservation token ownership is inconsistent".to_string(),
        ));
    }
    Ok(Some(reservation))
}

fn transition_approval_reservation(
    store: &SqliteApprovalStore,
    operation_id: &str,
    target: ReplayReservationState,
) -> Result<ApprovalReservation, ApprovalStoreError> {
    let mut conn = store
        .pool
        .get()
        .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
    configure_reservation_connection(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| ApprovalStoreError::Backend(format!("begin reservation tx: {e}")))?;
    let current = load_approval_reservation(&tx, operation_id)?.ok_or_else(|| {
        ApprovalStoreError::NotFound(format!("approval reservation for operation {operation_id}"))
    })?;
    if current.state() == target {
        tx.rollback()
            .map_err(|e| ApprovalStoreError::Backend(format!("rollback reservation read: {e}")))?;
        return Ok(current);
    }
    if current.state() != ReplayReservationState::Reserved
        || target == ReplayReservationState::Reserved
    {
        return Err(ApprovalStoreError::Replay(format!(
            "operation `{operation_id}` approval reservation cannot transition from {} to {}",
            current.state().as_str(),
            target.as_str()
        )));
    }
    let updated = tx
        .execute(
            "UPDATE chio_hitl_operation_reservations SET state = ?2 WHERE operation_id = ?1 AND state = 'reserved'",
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
    tx.commit()
        .map_err(|e| ApprovalStoreError::Backend(format!("commit reservation transition: {e}")))?;
    Ok(transitioned)
}

#[cfg(test)]
#[path = "approval_store/decision_tests.rs"]
mod decision_tests;

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        ThresholdApprovalProposal, ThresholdApprovalProposalBody,
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
    };
    use chio_core::capability::threshold_approval::{
        ThresholdApprovalRequirement, ThresholdApproverIdentity,
    };
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_kernel::approval::{
        ThresholdApprovalProposalCreationContext, ThresholdApprovalProposalCreationParameters,
    };
    use chio_kernel::ThresholdApprovalContextResolver;
    use chio_kernel::{ThresholdApprovalCollector, ThresholdApprovalCollectorState};
    use std::sync::Arc;

    #[test]
    fn explicit_pair_creation_supports_a_file_uri_with_query() {
        let directory = tempfile::tempdir().expect("temporary approval directory");
        let base = directory.path();
        let db = base.join("nested").join("receipts.db");
        let parent = db.parent().expect("db path has a parent");
        assert!(
            !parent.exists(),
            "precondition: the parent dir must not exist yet"
        );

        // The co-located approval store opens the receipt store's `file:` URI,
        // whose query and scheme a raw `parent()` would fold into a bogus
        // relative directory, leaving the real parent uncreated so SQLite would
        // fail to open the database.
        let uri = format!("file:{}?mode=rwc", db.display());
        crate::initialize_receipt_approval_database(uri.as_str()).unwrap();
        let store = SqliteApprovalStore::open_colocated_with_receipt_store(uri.as_str())
            .expect("open colocated approval store from a file: URI");
        // The store must be usable once its real parent directory exists.
        store
            .store_pending(&sample_request("uri-1", "hash-uri"))
            .expect("store a pending approval");

        assert!(
            parent.exists(),
            "the real parent directory must be created before SQLite opens the URI"
        );
    }

    fn sample_request(id: &str, hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: id.into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            action: "invoke".into(),
            parameter_hash: hash.into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 42,
            summary: "unit".into(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    fn reservation_input(marker: &str) -> ApprovalSetReservationInput {
        ApprovalSetReservationInput::new(
            marker.repeat(32),
            vec![
                ApprovalReservationMember::new("approval-token-a".to_string(), "aa".repeat(32))
                    .unwrap(),
                ApprovalReservationMember::new("approval-token-b".to_string(), "bb".repeat(32))
                    .unwrap(),
            ],
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn operation_owned_reservations_survive_restart_and_retain_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval-reservations.sqlite3");
        let operation_id = "11".repeat(32);
        let conflicting_operation_id = "22".repeat(32);
        let approval_set = reservation_input("cc");

        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            let reserved = store
                .reserve_approval_set(&operation_id, &approval_set)
                .unwrap();
            assert_eq!(reserved.state(), ReplayReservationState::Reserved);
            assert_eq!(
                store
                    .reserve_approval_set(&operation_id, &approval_set)
                    .unwrap(),
                reserved
            );
        }

        let store = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            store.get_approval_reservation(&operation_id).unwrap(),
            Some(ApprovalReservation::new(operation_id.clone(), approval_set.clone()).unwrap())
        );
        assert!(matches!(
            store.reserve_approval_set(&conflicting_operation_id, &approval_set),
            Err(ApprovalStoreError::Replay(_))
        ));

        let committed = store.commit_approval_reservation(&operation_id).unwrap();
        assert_eq!(committed.state(), ReplayReservationState::Committed);
        assert_eq!(
            store.commit_approval_reservation(&operation_id).unwrap(),
            committed
        );
        assert!(matches!(
            store.cancel_approval_reservation(&operation_id),
            Err(ApprovalStoreError::Replay(_))
        ));
    }

    #[test]
    fn store_and_list_round_trip() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let r1 = sample_request("a-1", "h-1");
        let r2 = sample_request("a-2", "h-2");
        store.store_pending(&r1).unwrap();
        store.store_pending(&r2).unwrap();

        let all = store.list_pending(&ApprovalFilter::default()).unwrap();
        assert_eq!(all.len(), 2);

        let fetched = store.get_pending("a-1").unwrap().unwrap();
        assert_eq!(fetched.approval_id, "a-1");
        assert_eq!(fetched.parameter_hash, "h-1");
    }

    #[test]
    fn duplicate_pending_insert_is_idempotent_only_when_payload_matches() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let original = sample_request("dup-1", "hash-a");
        let identical = original.clone();
        let mut mismatched = original.clone();
        mismatched.parameter_hash = "hash-b".into();

        store.store_pending(&original).unwrap();
        store.store_pending(&identical).unwrap();

        let err = store.store_pending(&mismatched).unwrap_err();
        match err {
            ApprovalStoreError::Backend(message) => {
                assert!(message.contains("already exists with different payload"));
            }
            other => panic!("expected Backend mismatch error, got {other:?}"),
        }

        let fetched = store.get_pending("dup-1").unwrap().unwrap();
        assert_eq!(fetched.parameter_hash, "hash-a");
    }

    #[test]
    fn standalone_open_refuses_a_declared_receipt_approval_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar.sqlite3");
        crate::initialize_receipt_approval_database(&path).unwrap();

        assert!(
            SqliteApprovalStore::open(&path).is_err(),
            "standalone approval open must refuse a declared pair"
        );

        let store = SqliteApprovalStore::open_colocated_with_receipt_store(&path)
            .expect("co-located open must validate the declared pair");
        store
            .store_pending(&sample_request("pair-1", "hash-pair"))
            .unwrap();
        assert!(store.get_pending("pair-1").unwrap().is_some());
    }

    #[test]
    fn standalone_open_reopens_a_genuine_approval_database() {
        // A real approval database carries the approval anchor, so the standalone
        // open reopens it across restarts without co-location.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval.sqlite3");
        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            store
                .store_pending(&sample_request("reopen-1", "hash-reopen"))
                .unwrap();
        }
        let store = SqliteApprovalStore::open(&path)
            .expect("a genuine approval database must reopen standalone");
        assert!(store.get_pending("reopen-1").unwrap().is_some());
    }

    #[test]
    fn approval_schema_other_than_current_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval-stale.sqlite3");
        drop(SqliteApprovalStore::open(&path).unwrap());
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA ignore_check_constraints = ON; UPDATE chio_store_schema_versions SET version = 4 WHERE store_key = 'approval'; PRAGMA ignore_check_constraints = OFF;").unwrap();
        drop(connection);

        let error = SqliteApprovalStore::open(&path).err().unwrap();
        assert!(matches!(
            error,
            ApprovalStoreError::Schema(chio_security_types::schema::SchemaRefusal::StaleSchema {
                found: 4,
                current: 1
            })
        ));
    }

    #[test]
    fn unstamped_provisioned_approval_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approval-unstamped.sqlite3");
        drop(SqliteApprovalStore::open(&path).unwrap());
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "DELETE FROM chio_store_schema_versions WHERE store_key = ?1",
                [APPROVAL_STORE_SCHEMA_KEY],
            )
            .unwrap();
        drop(connection);

        let error = SqliteApprovalStore::open(&path).err().unwrap();
        assert!(
            matches!(error, ApprovalStoreError::Schema(chio_security_types::schema::SchemaRefusal::MissingSchema { store_key }) if store_key == "approval")
        );
    }

    #[test]
    fn threshold_collector_recovers_votes_and_persists_delivery_before_return() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("threshold.sqlite3");
        let authority = Keypair::generate();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let subject = Keypair::generate();
        let policy_hash = sha256_hex(b"threshold-policy");
        let requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            2,
            vec![
                ThresholdApproverIdentity {
                    identifier: "alice".to_string(),
                    public_key: alice.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "bob".to_string(),
                    public_key: bob.public_key(),
                },
            ],
            "directory-v1".to_string(),
            100,
        )
        .unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: "durable-proposal".to_string(),
                request_id: "durable-request".to_string(),
                governed_intent_hash: sha256_hex(b"durable-intent"),
                subject: subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"durable-capability"),
                policy_hash: policy_hash.clone(),
                threshold: 2,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )
        .unwrap();
        let second_proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: "durable-proposal-b".to_string(),
                request_id: "durable-request-b".to_string(),
                governed_intent_hash: sha256_hex(b"durable-intent-b"),
                subject: subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"durable-capability-b"),
                policy_hash: policy_hash.clone(),
                threshold: 2,
                eligible_set_digest: requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: authority.public_key(),
            },
            &authority,
        )
        .unwrap();
        let contexts = [&proposal, &second_proposal].map(|proposal| {
            ThresholdApprovalProposalCreationContext::new(
                ThresholdApprovalProposalCreationParameters {
                    matched_request:
                        chio_core::capability::threshold_approval::ThresholdApprovalRequest::new(
                            &proposal.body.request_id,
                            "server",
                            "tool",
                        )
                        .unwrap(),
                    requirement: requirement.clone(),
                    subject: subject.public_key(),
                    governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                    authorization_capability_hash: proposal
                        .body
                        .authorizing_capability_digest
                        .clone(),
                    authorizing_capability_expires_at: 200,
                    governed_operation_expires_at: 200,
                    submitter: None,
                    separation_of_duties: false,
                },
            )
            .unwrap()
        });
        let resolver: Arc<dyn ThresholdApprovalContextResolver> =
            Arc::new(move |request_id: &str, _: u64| {
                contexts
                    .iter()
                    .find(|context| context.matched_request().request_id() == request_id)
                    .cloned()
                    .ok_or_else(|| ApprovalStoreError::NotFound(request_id.to_string()))
            });
        let make_token = |proposal: &ThresholdApprovalProposal,
                          approver: &Keypair,
                          id: &str,
                          expires_at: u64| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_string(),
                    approver: approver.public_key(),
                    subject: proposal.body.subject.clone(),
                    governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                    request_id: proposal.body.request_id.clone(),
                    threshold_proposal_hash: Some(proposal.artifact_digest().unwrap()),
                    issued_at: 101,
                    expires_at,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        };

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
                Arc::clone(&resolver),
            );
            collector.create_proposal(proposal.clone(), 100).unwrap();
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
                Arc::clone(&resolver),
            );
            assert!(collector
                .get_proposal("durable-proposal", 180)
                .unwrap()
                .is_some());
            collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &alice, "token-alice", 120),
                    110,
                )
                .unwrap();
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
                Arc::clone(&resolver),
            );
            let recovered = collector
                .get_proposal("durable-proposal", 180)
                .unwrap()
                .unwrap();
            assert_eq!(recovered.tokens.len(), 1);
            let ready = collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &bob, "token-bob", 199),
                    111,
                )
                .unwrap();
            assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
        }

        {
            let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
            let collector = ThresholdApprovalCollector::new(
                store,
                policy_hash.clone(),
                vec![authority.public_key()],
                Arc::clone(&resolver),
            );
            let ready = collector
                .get_proposal("durable-proposal", 180)
                .unwrap()
                .unwrap();
            assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
            assert!(collector.deliver("durable-proposal", 150).is_err());
            let refreshed = collector
                .submit_token(
                    "durable-proposal",
                    make_token(&proposal, &alice, "token-alice-fresh", 199),
                    150,
                )
                .unwrap();
            assert_eq!(refreshed.state, ThresholdApprovalCollectorState::Ready);
            assert_eq!(refreshed.tokens.len(), 2);
            let delivered = collector.deliver("durable-proposal", 151).unwrap();
            assert_eq!(delivered.tokens.len(), 2);
            assert!(delivered
                .tokens
                .iter()
                .any(|token| token.id == "token-alice-fresh"));
        }

        let store = Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let collector = ThresholdApprovalCollector::new(
            store,
            policy_hash,
            vec![authority.public_key()],
            resolver,
        );
        assert_eq!(
            collector
                .get_proposal("durable-proposal", 180)
                .unwrap()
                .unwrap()
                .state,
            ThresholdApprovalCollectorState::Delivered
        );
        collector
            .create_proposal(second_proposal.clone(), 100)
            .unwrap();
        collector
            .submit_token(
                "durable-proposal-b",
                make_token(&second_proposal, &alice, "token-alice-fresh", 199),
                110,
            )
            .unwrap();
        let second_ready = collector
            .submit_token(
                "durable-proposal-b",
                make_token(&second_proposal, &bob, "token-bob", 199),
                111,
            )
            .unwrap();
        assert_eq!(second_ready.state, ThresholdApprovalCollectorState::Ready);
    }
}
