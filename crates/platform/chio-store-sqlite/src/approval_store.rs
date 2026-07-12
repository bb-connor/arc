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

use chio_kernel::{
    ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest, ApprovalReservation,
    ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStore, ApprovalStoreError,
    ReplayReservationState, ResolvedApproval,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const MAX_PERSISTED_APPROVAL_MEMBERS_JSON_BYTES: usize = 262_144;

/// SQLite-backed `ApprovalStore`.
///
/// Schema is created on `open`. Migrations are additive and idempotent
/// via `CREATE TABLE IF NOT EXISTS`.
pub struct SqliteApprovalStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteApprovalStore {
    /// Open the store at the given path. Creates the parent directory
    /// if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| ApprovalStoreError::Backend(format!("create dir: {e}")))?;
            }
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory store for tests.
    pub fn open_in_memory() -> Result<Self, ApprovalStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| ApprovalStoreError::Backend(format!("pool build: {e}")))?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
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
            )
            BEGIN
                SELECT RAISE(ABORT, 'approval token is operation-owned');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_hitl_operation_token_legacy_exclusion
            BEFORE INSERT ON chio_hitl_operation_reservation_tokens
            WHEN EXISTS (
                SELECT 1 FROM chio_hitl_consumed_tokens
                WHERE token_id = NEW.token_id
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
            "#,
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("migration: {e}")))?;
        let dual_owner = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_hitl_consumed_tokens AS legacy
                INNER JOIN chio_hitl_operation_reservation_tokens AS operation
                    ON operation.token_id = legacy.token_id
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

fn serialize_payload(request: &ApprovalRequest) -> Result<String, ApprovalStoreError> {
    serde_json::to_string(request).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}

fn deserialize_payload(raw: &str) -> Result<ApprovalRequest, ApprovalStoreError> {
    serde_json::from_str(raw).map_err(|e| ApprovalStoreError::Serialization(e.to_string()))
}

impl ApprovalStore for SqliteApprovalStore {
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
                    request.expires_at as i64,
                    request.created_at as i64,
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
            params_vec.push((":not_expired_at", Box::new(*t as i64)));
        }
        if let Some(limit) = &filter.limit {
            params_vec.push((":limit", Box::new(*limit as i64)));
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
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin tx: {e}")))?;

        // Pull pending record inside the tx to avoid TOCTOU races.
        let pending: Option<(String, String)> = tx
            .query_row(
                "SELECT policy_id, parameter_hash FROM chio_hitl_pending WHERE approval_id = ?1",
                params![id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("select: {e}")))?;
        let (policy_id, parameter_hash) = match pending {
            Some(p) => p,
            None => return Err(ApprovalStoreError::NotFound(id.to_string())),
        };

        let reservation_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1
                "#,
                params![decision.token.id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("reservation replay check: {e}")))?;
        if let Some(owner) = reservation_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by operation `{owner}`"
            )));
        }

        // Replay guard: the bound token must not already be consumed.
        let already: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 LIMIT 1",
                params![decision.token.id],
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
                decision.received_at as i64,
                decision.approver.to_hex(),
                decision.token.id,
            ],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert resolved: {e}")))?;

        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, consumed_at) VALUES (?1, ?2, ?3)",
            params![decision.token.id, parameter_hash, decision.received_at as i64],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;

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
        Ok(count.max(0) as u64)
    }

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ApprovalStoreError::Backend(format!("begin consumed tx: {e}")))?;
        let reservation_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1
                "#,
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("reservation replay check: {e}")))?;
        if let Some(owner) = reservation_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token is already owned by operation `{owner}`"
            )));
        }
        let already_consumed: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM chio_hitl_consumed_tokens WHERE token_id = ?1 LIMIT 1",
                params![token_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("legacy replay check: {e}")))?;
        if already_consumed.is_some() {
            return Err(ApprovalStoreError::Replay(format!(
                "token {token_id} already consumed"
            )));
        }
        tx.execute(
            "INSERT INTO chio_hitl_consumed_tokens (token_id, parameter_hash, consumed_at) VALUES (?1, ?2, ?3)",
            params![token_id, parameter_hash, now as i64],
        )
        .map_err(|e| ApprovalStoreError::Backend(format!("insert consumed: {e}")))?;
        tx.commit()
            .map_err(|e| ApprovalStoreError::Backend(format!("commit consumed tx: {e}")))?;
        Ok(())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        _parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        let row: Option<i64> = conn
            .query_row(
                r#"
                SELECT 1
                FROM chio_hitl_consumed_tokens
                WHERE token_id = ?1
                UNION ALL
                SELECT 1
                FROM chio_hitl_operation_reservation_tokens
                WHERE token_id = ?1
                LIMIT 1
                "#,
                params![token_id],
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
                Ok(Some(ResolvedApproval {
                    approval_id,
                    outcome,
                    resolved_at: resolved_at.max(0) as u64,
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

        let hash_owner = tx
            .query_row(
                r#"
                SELECT operation_id
                FROM chio_hitl_operation_reservations
                WHERE approval_set_hash = ?1
                LIMIT 1
                "#,
                params![requested.approval_set().approval_set_hash()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| ApprovalStoreError::Backend(format!("query approval set owner: {e}")))?;
        if let Some(owner) = hash_owner {
            return Err(ApprovalStoreError::Replay(format!(
                "approval set hash is already owned by operation `{owner}`"
            )));
        }

        for member in requested.approval_set().members() {
            let legacy_consumed = tx
                .query_row(
                    r#"
                    SELECT 1
                    FROM chio_hitl_consumed_tokens
                    WHERE token_id = ?1
                    LIMIT 1
                    "#,
                    params![member.token_id()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(|e| {
                    ApprovalStoreError::Backend(format!("query legacy token replay: {e}"))
                })?;
            if legacy_consumed.is_some() {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token `{}` was already consumed",
                    member.token_id()
                )));
            }

            let owner = tx
                .query_row(
                    r#"
                    SELECT operation_id
                    FROM chio_hitl_operation_reservation_tokens
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
                    position as i64
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
        self.transition_approval_reservation(operation_id, ReplayReservationState::Committed)
    }

    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition_approval_reservation(operation_id, ReplayReservationState::Cancelled)
    }

    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        validate_reservation_operation_id(operation_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|e| ApprovalStoreError::Backend(format!("pool get: {e}")))?;
        configure_reservation_connection(&conn)?;
        load_approval_reservation(&conn, operation_id)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

    fn operation_id(hex_pair: &str) -> String {
        hex_pair.repeat(32)
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

    fn approval_set(hash_hex_pair: &str, members: &[(&str, &str)]) -> ApprovalSetReservationInput {
        ApprovalSetReservationInput::new(
            hash_hex_pair.repeat(32),
            members
                .iter()
                .map(|(token_id, digest_hex_pair)| {
                    ApprovalReservationMember::new(
                        (*token_id).to_string(),
                        digest_hex_pair.repeat(32),
                    )
                    .unwrap()
                })
                .collect(),
            10_000,
        )
        .unwrap()
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
    fn operation_reservation_schema_bounds_member_payloads() {
        let store = SqliteApprovalStore::open_in_memory().unwrap();
        let connection = store.pool.get().unwrap();
        let oversized_members = "x".repeat(262_145);
        assert!(connection
            .execute(
                r#"
                INSERT INTO chio_hitl_operation_reservations (
                    operation_id, approval_set_hash, members_json, proposal_deadline, state
                ) VALUES (?1, ?2, ?3, ?4, 'reserved')
                "#,
                params![
                    operation_id("20"),
                    "aa".repeat(32),
                    oversized_members,
                    10_000
                ],
            )
            .is_err());
    }

    #[test]
    fn operation_approval_reservations_survive_restart_and_reject_rebinding() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-reservation-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first_set = approval_set(
            "aa",
            &[("approval-token-2", "22"), ("approval-token-1", "11")],
        );
        let committed = {
            let store = SqliteApprovalStore::open(&path).unwrap();
            let reserved = store
                .reserve_approval_set(operation_id("01").as_str(), &first_set)
                .unwrap();
            assert_eq!(reserved.state(), ReplayReservationState::Reserved);
            assert_eq!(reserved.approval_set().proposal_deadline(), 10_000);
            assert_eq!(
                reserved
                    .approval_set()
                    .members()
                    .iter()
                    .map(ApprovalReservationMember::token_id)
                    .collect::<Vec<_>>(),
                vec!["approval-token-1", "approval-token-2"]
            );
            assert_eq!(
                store
                    .reserve_approval_set(operation_id("01").as_str(), &first_set)
                    .unwrap(),
                reserved
            );
            let changed_deadline = ApprovalSetReservationInput::new(
                first_set.approval_set_hash().to_string(),
                first_set.members().to_vec(),
                10_001,
            )
            .unwrap();
            assert!(matches!(
                store.reserve_approval_set(operation_id("01").as_str(), &changed_deadline),
                Err(ApprovalStoreError::Replay(_))
            ));
            let overlapping = approval_set("bb", &[("approval-token-3", "11")]);
            assert!(matches!(
                store.reserve_approval_set(operation_id("02").as_str(), &overlapping),
                Err(ApprovalStoreError::Replay(_))
            ));
            let duplicate_hash = approval_set("aa", &[("approval-token-hash", "55")]);
            assert!(matches!(
                store.reserve_approval_set(operation_id("05").as_str(), &duplicate_hash),
                Err(ApprovalStoreError::Replay(_))
            ));
            store
                .commit_approval_reservation(operation_id("01").as_str())
                .unwrap()
        };
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_approval_reservation(operation_id("01").as_str())
                .unwrap(),
            Some(committed.clone())
        );
        assert_eq!(
            reopened
                .commit_approval_reservation(operation_id("01").as_str())
                .unwrap(),
            committed
        );
        assert!(matches!(
            reopened.cancel_approval_reservation(operation_id("01").as_str()),
            Err(ApprovalStoreError::Replay(_))
        ));
        let cancellation_set = approval_set("cc", &[("approval-token-4", "33")]);
        let cancelled = reopened
            .reserve_approval_set(operation_id("03").as_str(), &cancellation_set)
            .and_then(|_| reopened.cancel_approval_reservation(operation_id("03").as_str()))
            .unwrap();
        drop(reopened);
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .cancel_approval_reservation(operation_id("03").as_str())
                .unwrap(),
            cancelled
        );
        assert!(matches!(
            reopened.reserve_approval_set(operation_id("04").as_str(), &cancellation_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_and_operation_approval_replay_paths_interlock_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-interlock-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let legacy_member_set = approval_set("aa", &[("legacy-token", "11")]);
        let operation_member_set = approval_set("bb", &[("operation-token", "22")]);
        {
            let store = SqliteApprovalStore::open(&path).unwrap();
            store
                .record_consumed("legacy-token", "parameter-a", 1)
                .unwrap();
            assert!(matches!(
                store.record_consumed("legacy-token", "parameter-b", 2),
                Err(ApprovalStoreError::Replay(_))
            ));
            assert!(store.is_consumed("legacy-token", "parameter-b").unwrap());
            assert!(matches!(
                store.reserve_approval_set(operation_id("06").as_str(), &legacy_member_set),
                Err(ApprovalStoreError::Replay(_))
            ));
            store
                .reserve_approval_set(operation_id("07").as_str(), &operation_member_set)
                .unwrap();
        }
        let reopened = SqliteApprovalStore::open(&path).unwrap();
        assert!(matches!(
            reopened.record_consumed("operation-token", "parameter-b", 2),
            Err(ApprovalStoreError::Replay(_))
        ));
        assert!(reopened
            .is_consumed("operation-token", "parameter-b")
            .unwrap());
        assert!(matches!(
            reopened.reserve_approval_set(operation_id("06").as_str(), &legacy_member_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_approval_reservations_have_one_token_owner() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-reservation-race-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let second = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let shared_set = approval_set("aa", &[("race-token", "44")]);
        let spawn = |store: std::sync::Arc<SqliteApprovalStore>, operation_id: String| {
            let barrier = std::sync::Arc::clone(&barrier);
            let shared_set = shared_set.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.reserve_approval_set(&operation_id, &shared_set)
            })
        };
        let first_thread = spawn(std::sync::Arc::clone(&first), operation_id("08"));
        let second_thread = spawn(std::sync::Arc::clone(&second), operation_id("09"));
        barrier.wait();
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApprovalStoreError::Replay(_))))
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_legacy_and_operation_paths_have_one_token_owner() {
        let path = std::env::temp_dir().join(format!(
            "chio-approval-cross-path-race-{}.sqlite3",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let reservation_store = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let legacy_store = std::sync::Arc::new(SqliteApprovalStore::open(&path).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let set = approval_set("aa", &[("cross-path-token", "55")]);
        let reservation_thread = {
            let store = std::sync::Arc::clone(&reservation_store);
            let barrier = std::sync::Arc::clone(&barrier);
            let reservation_operation_id = operation_id("10");
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .reserve_approval_set(&reservation_operation_id, &set)
                    .map(|_| ())
            })
        };
        let legacy_thread = {
            let store = std::sync::Arc::clone(&legacy_store);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.record_consumed("cross-path-token", "parameter", 1)
            })
        };
        barrier.wait();
        let results = [
            reservation_thread.join().unwrap(),
            legacy_thread.join().unwrap(),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApprovalStoreError::Replay(_))))
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }
}
