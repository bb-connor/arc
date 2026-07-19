use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_kernel::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationError,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
    AdmissionOperationStoreProfile, PersistedAdmissionCleanupAction, PersistedAdmissionOperation,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct SqliteAdmissionOperationStore {
    connection: Mutex<Connection>,
    authority_profile: AdmissionOperationStoreProfile,
}

impl SqliteAdmissionOperationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AdmissionOperationError> {
        let path = path.as_ref();
        reject_volatile_database_path(path)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    AdmissionOperationError::Unavailable(format!(
                        "failed to prepare admission operation directory: {error}"
                    ))
                })?;
            }
        }
        let connection = Connection::open(path).map_err(sqlite_error)?;
        Self::from_connection(
            connection,
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )
    }

    pub fn open_in_memory() -> Result<Self, AdmissionOperationError> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        Self::from_connection(connection, AdmissionOperationStoreProfile::EphemeralLocal)
    }

    fn from_connection(
        connection: Connection,
        authority_profile: AdmissionOperationStoreProfile,
    ) -> Result<Self, AdmissionOperationError> {
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS admission_operations (
                    operation_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    coordinator_authority_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    authorization_capability_hash TEXT NOT NULL,
                    request_binding_hash TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    broker_attempt_id TEXT,
                    budget_hold_id TEXT,
                    approval_set_hash TEXT,
                    execution_nonce_id TEXT,
                    state TEXT NOT NULL,
                    dispatch_state TEXT NOT NULL,
                    coordinator_lease_epoch INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    last_error TEXT,
                    updated_at INTEGER NOT NULL,
                    CHECK (coordinator_lease_epoch >= 0),
                    CHECK (version >= 0)
                );

                CREATE INDEX IF NOT EXISTS idx_admission_operations_state
                    ON admission_operations(state, updated_at);

                CREATE TABLE IF NOT EXISTS admission_cleanup_actions (
                    action_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    request_binding_hash TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    claim_token TEXT,
                    claim_deadline_unix_ms INTEGER,
                    version INTEGER NOT NULL,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE (operation_id, kind),
                    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
                    CHECK (version >= 0),
                    CHECK (claim_deadline_unix_ms IS NULL OR claim_deadline_unix_ms >= 0),
                    CHECK (
                        (state = 'claimed' AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
                        OR
                        (state IN ('pending', 'completed') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_admission_cleanup_pending
                    ON admission_cleanup_actions(state, operation_id, updated_at);
                "#,
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
            authority_profile,
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationError> {
        self.connection.lock().map_err(|_| {
            AdmissionOperationError::Unavailable(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })
    }

    fn mutate_claimed_cleanup_action<F>(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        mutation: F,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError>
    where
        F: FnOnce(
            &AdmissionCleanupAction,
        ) -> Result<AdmissionCleanupAction, AdmissionOperationError>,
    {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_cleanup_action(&transaction, action_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionCasOutcome::Missing);
        };
        if current.version() != expected_version || current.claim_token() != Some(claim_token) {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionCasOutcome::Conflict(current));
        }
        let next = mutation(&current)?;
        persist_cleanup_transition(&transaction, &current, &next, Some(claim_token))?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionCasOutcome::Applied(next))
    }
}

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.authority_profile
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        if operation.state() != AdmissionOperationState::Prepared
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.version() != 0
        {
            return Err(AdmissionOperationError::Invalid(
                "new admission operation is not Prepared at version zero".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_operation(&transaction, operation.operation_id())? {
            transaction.rollback().map_err(sqlite_error)?;
            if existing.has_same_prepared_binding(&operation) {
                return Ok(AdmissionOperationCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Invalid(
                "operation_id is already bound to different input".to_string(),
            ));
        }
        insert_operation(&transaction, &operation)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCreateOutcome::Created(operation))
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        let connection = self.connection()?;
        load_operation(&connection, operation_id)
    }

    fn list_unresolved(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "unresolved admission operation inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let operation_ids = if let Some(kind) = kind {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT operation_id
                    FROM admission_operations
                    WHERE kind = ?1
                      AND state NOT IN ('completed', 'compensated_before_dispatch')
                    ORDER BY updated_at ASC, operation_id ASC
                    LIMIT ?2
                    "#,
                )
                .map_err(sqlite_error)?;
            let operation_ids = statement
                .query_map(params![kind.as_str(), limit], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            operation_ids
        } else {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT operation_id
                    FROM admission_operations
                    WHERE state NOT IN ('completed', 'compensated_before_dispatch')
                    ORDER BY updated_at ASC, operation_id ASC
                    LIMIT ?1
                    "#,
                )
                .map_err(sqlite_error)?;
            let operation_ids = statement
                .query_map(params![limit], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            operation_ids
        };
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during unresolved inventory".to_string(),
                    )
                })
            })
            .collect()
    }

    fn claim_recovery(
        &self,
        operation_id: &str,
        expected_version: u64,
        expected_coordinator_lease_epoch: u64,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != expected_coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let claimed = current.claim_recovery_checked()?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET coordinator_lease_epoch = ?4,
                    version = ?5,
                    updated_at = ?6
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(
                        expected_coordinator_lease_epoch,
                        "expected coordinator lease epoch"
                    )?,
                    sqlite_integer(
                        claimed.coordinator_lease_epoch(),
                        "claimed coordinator lease epoch"
                    )?,
                    sqlite_integer(claimed.version(), "claimed version")?,
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during recovery claim".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(claimed))
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM admission_operations
                WHERE kind = ?1
                  AND coordinator_authority_id = ?2
                  AND state NOT IN ('completed', 'compensated_before_dispatch')
                "#,
                params![kind.as_str(), coordinator_authority_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        u64::try_from(count).map_err(|_| {
            AdmissionOperationError::Invalid(
                "sqlite returned a negative nonterminal operation count".to_string(),
            )
        })
    }

    fn count_unresolved(
        &self,
        kind: AdmissionOperationKind,
    ) -> Result<u64, AdmissionOperationError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM admission_operations
                WHERE kind = ?1
                  AND state NOT IN ('completed', 'compensated_before_dispatch')
                "#,
                params![kind.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        u64::try_from(count).map_err(|_| {
            AdmissionOperationError::Invalid(
                "sqlite returned a negative nonterminal operation count".to_string(),
            )
        })
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if request.next_state == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal()
        {
            return Err(AdmissionOperationError::Invalid(
                "compensation and terminal admission transitions require an atomic terminal receipt action"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET state = ?4,
                    dispatch_state = ?5,
                    coordinator_lease_epoch = ?6,
                    version = ?7,
                    last_error = ?8,
                    updated_at = ?9
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(coordinator_lease_epoch, "coordinator lease epoch")?,
                    next.state().as_str(),
                    next.dispatch_state().as_str(),
                    sqlite_integer(
                        next.coordinator_lease_epoch(),
                        "next coordinator lease epoch"
                    )?,
                    sqlite_integer(next.version(), "next version")?,
                    next.last_error(),
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during compare-and-swap".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action is not Pending at version zero".to_string(),
            ));
        }
        let terminal_receipt_required = request.next_state
            == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal();
        if terminal_receipt_required
            != (action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission transition has the wrong cleanup action kind for its target state"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        if action.operation_id() != operation_id {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action references a different operation".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        if current.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action request binding differs from its operation"
                    .to_string(),
            ));
        }
        let existing =
            load_cleanup_action_by_participant(&transaction, action.operation_id(), action.kind())?;
        if existing
            .as_ref()
            .is_some_and(|existing| existing != &action)
        {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal participant is already bound to a different payload"
                    .to_string(),
            ));
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET state = ?4,
                    dispatch_state = ?5,
                    coordinator_lease_epoch = ?6,
                    version = ?7,
                    last_error = ?8,
                    updated_at = ?9
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(coordinator_lease_epoch, "coordinator lease epoch")?,
                    next.state().as_str(),
                    next.dispatch_state().as_str(),
                    sqlite_integer(
                        next.coordinator_lease_epoch(),
                        "next coordinator lease epoch"
                    )?,
                    sqlite_integer(next.version(), "next version")?,
                    next.last_error(),
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during atomic journal transition".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        if existing.is_none() {
            insert_cleanup_action(&transaction, &action)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "new admission cleanup action is not Pending at version zero".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let operation = load_operation(&transaction, action.operation_id())?.ok_or_else(|| {
            AdmissionOperationError::Invalid(
                "cleanup action references a missing admission operation".to_string(),
            )
        })?;
        if operation.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "cleanup action request binding differs from its operation".to_string(),
            ));
        }
        if let Some(existing) =
            load_cleanup_action_by_participant(&transaction, action.operation_id(), action.kind())?
        {
            transaction.rollback().map_err(sqlite_error)?;
            if existing == action {
                return Ok(AdmissionCleanupActionCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Invalid(
                "cleanup participant is already bound to a different immutable projection"
                    .to_string(),
            ));
        }
        insert_cleanup_action(&transaction, &action)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionCreateOutcome::Created(action))
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT action_id, operation_id, request_binding_hash, kind,
                       payload_json, payload_hash, state, claim_token,
                       claim_deadline_unix_ms, version, last_error
                FROM admission_cleanup_actions
                WHERE operation_id = ?1
                ORDER BY kind ASC
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![operation_id], cleanup_action_row)
            .map_err(sqlite_error)?;
        let mut actions = Vec::new();
        for row in rows {
            actions.push(parse_cleanup_action(row.map_err(sqlite_error)?)?);
        }
        Ok(actions)
    }

    fn list_compensated_with_pending_cleanup(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow("cleanup recovery limit exceeds i64".to_string())
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT DISTINCT operation.operation_id
                FROM admission_operations AS operation
                INNER JOIN admission_cleanup_actions AS cleanup
                    ON cleanup.operation_id = operation.operation_id
                WHERE operation.state IN (
                    'compensation_pending',
                    'compensated_before_dispatch'
                )
                  AND cleanup.state != 'completed'
                  AND (?1 IS NULL OR operation.kind = ?1)
                ORDER BY operation.updated_at ASC, operation.operation_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![kind.map(AdmissionOperationKind::as_str), limit],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut operation_ids = Vec::new();
        for row in rows {
            operation_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(operation_ids)
    }

    fn list_operations_with_pending_cleanup_action(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "pending admission journal inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT DISTINCT operation.operation_id
                FROM admission_operations AS operation
                INNER JOIN admission_cleanup_actions AS cleanup
                    ON cleanup.operation_id = operation.operation_id
                WHERE operation.kind = ?1
                  AND cleanup.kind = ?2
                  AND cleanup.state != 'completed'
                ORDER BY operation.updated_at ASC, operation.operation_id ASC
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![operation_kind.as_str(), action_kind.as_str(), limit],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut operation_ids = Vec::new();
        for row in rows {
            operation_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(operation_ids)
    }

    fn claim_cleanup_action(
        &self,
        action_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<AdmissionCleanupActionClaimOutcome, AdmissionOperationError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_cleanup_action(&transaction, action_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Missing);
        };
        if current.state() == AdmissionCleanupActionState::Completed {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Completed(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() != Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Busy(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() == Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Claimed(current));
        }
        let next =
            current.claim_checked(claim_token.to_string(), now_unix_ms, claim_deadline_unix_ms)?;
        persist_cleanup_transition(&transaction, &current, &next, current.claim_token())?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionClaimOutcome::Claimed(next))
    }

    fn acknowledge_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        self.mutate_claimed_cleanup_action(
            action_id,
            expected_version,
            claim_token,
            AdmissionCleanupAction::acknowledge_checked,
        )
    }

    fn abandon_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: String,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        self.mutate_claimed_cleanup_action(action_id, expected_version, claim_token, |action| {
            action.abandon_checked(last_error)
        })
    }
}

fn insert_operation(
    connection: &Connection,
    operation: &AdmissionOperation,
) -> Result<(), AdmissionOperationError> {
    connection
        .execute(
            r#"
            INSERT INTO admission_operations (
                operation_id, kind, coordinator_authority_id, request_id,
                capability_id, authorization_capability_hash,
                request_binding_hash, policy_hash, broker_attempt_id,
                budget_hold_id, approval_set_hash, execution_nonce_id,
                state, dispatch_state, coordinator_lease_epoch,
                version, last_error, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
            )
            "#,
            params![
                operation.operation_id(),
                operation.kind().as_str(),
                operation.coordinator_authority_id(),
                operation.request_id(),
                operation.capability_id(),
                operation.authorization_capability_hash(),
                operation.request_binding_hash(),
                operation.policy_hash(),
                operation.broker_attempt_id(),
                operation.budget_hold_id(),
                operation.approval_set_hash(),
                operation.execution_nonce_id(),
                operation.state().as_str(),
                operation.dispatch_state().as_str(),
                sqlite_integer(
                    operation.coordinator_lease_epoch(),
                    "coordinator lease epoch"
                )?,
                sqlite_integer(operation.version(), "version")?,
                operation.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn load_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
    type StoredOperation = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        i64,
        i64,
        Option<String>,
    );
    let row: Option<StoredOperation> = connection
        .query_row(
            r#"
            SELECT operation_id, kind, coordinator_authority_id, request_id,
                   capability_id, authorization_capability_hash,
                   request_binding_hash, policy_hash, broker_attempt_id,
                   budget_hold_id, approval_set_hash, execution_nonce_id,
                   state, dispatch_state, coordinator_lease_epoch,
                   version, last_error
            FROM admission_operations
            WHERE operation_id = ?1
            "#,
            params![operation_id],
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
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let kind = AdmissionOperationKind::parse(&row.1).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted operation kind `{}`", row.1))
    })?;
    let state = AdmissionOperationState::parse(&row.12).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted admission state `{}`", row.12))
    })?;
    let dispatch_state = AdmissionDispatchState::parse(&row.13).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted dispatch state `{}`", row.13))
    })?;
    let coordinator_lease_epoch = nonnegative_u64(row.14, "coordinator_lease_epoch")?;
    let version = nonnegative_u64(row.15, "version")?;
    Ok(Some(AdmissionOperation::from_persisted_parts(
        PersistedAdmissionOperation {
            kind,
            operation_id: row.0,
            coordinator_authority_id: row.2,
            request_id: row.3,
            capability_id: row.4,
            authorization_capability_hash: row.5,
            request_binding_hash: row.6,
            policy_hash: row.7,
            broker_attempt_id: row.8,
            budget_hold_id: row.9,
            approval_set_hash: row.10,
            execution_nonce_id: row.11,
            state,
            dispatch_state,
            coordinator_lease_epoch,
            version,
            last_error: row.16,
        },
    )?))
}

type StoredCleanupAction = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    i64,
    Option<String>,
);

fn cleanup_action_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCleanupAction> {
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
        row.get(10)?,
    ))
}

fn parse_cleanup_action(
    row: StoredCleanupAction,
) -> Result<AdmissionCleanupAction, AdmissionOperationError> {
    let kind = AdmissionCleanupActionKind::parse(&row.3).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!(
            "unknown persisted admission cleanup kind `{}`",
            row.3
        ))
    })?;
    let state = AdmissionCleanupActionState::parse(&row.6).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!(
            "unknown persisted admission cleanup state `{}`",
            row.6
        ))
    })?;
    let claim_deadline_unix_ms = row
        .8
        .map(|value| nonnegative_u64(value, "cleanup claim_deadline_unix_ms"))
        .transpose()?;
    let version = nonnegative_u64(row.9, "cleanup version")?;
    AdmissionCleanupAction::from_persisted_parts(PersistedAdmissionCleanupAction {
        action_id: row.0,
        operation_id: row.1,
        request_binding_hash: row.2,
        kind,
        payload_json: row.4,
        payload_hash: row.5,
        state,
        claim_token: row.7,
        claim_deadline_unix_ms,
        version,
        last_error: row.10,
    })
}

fn load_cleanup_action(
    connection: &Connection,
    action_id: &str,
) -> Result<Option<AdmissionCleanupAction>, AdmissionOperationError> {
    let row = connection
        .query_row(
            r#"
            SELECT action_id, operation_id, request_binding_hash, kind,
                   payload_json, payload_hash, state, claim_token,
                   claim_deadline_unix_ms, version, last_error
            FROM admission_cleanup_actions
            WHERE action_id = ?1
            "#,
            params![action_id],
            cleanup_action_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(parse_cleanup_action).transpose()
}

fn load_cleanup_action_by_participant(
    connection: &Connection,
    operation_id: &str,
    kind: AdmissionCleanupActionKind,
) -> Result<Option<AdmissionCleanupAction>, AdmissionOperationError> {
    let row = connection
        .query_row(
            r#"
            SELECT action_id, operation_id, request_binding_hash, kind,
                   payload_json, payload_hash, state, claim_token,
                   claim_deadline_unix_ms, version, last_error
            FROM admission_cleanup_actions
            WHERE operation_id = ?1 AND kind = ?2
            "#,
            params![operation_id, kind.as_str()],
            cleanup_action_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(parse_cleanup_action).transpose()
}

fn insert_cleanup_action(
    connection: &Connection,
    action: &AdmissionCleanupAction,
) -> Result<(), AdmissionOperationError> {
    connection
        .execute(
            r#"
            INSERT INTO admission_cleanup_actions (
                action_id, operation_id, request_binding_hash, kind,
                payload_json, payload_hash, state, claim_token,
                claim_deadline_unix_ms, version, last_error,
                created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12
            )
            "#,
            params![
                action.action_id(),
                action.operation_id(),
                action.request_binding_hash(),
                action.kind().as_str(),
                action.payload_json(),
                action.payload_hash(),
                action.state().as_str(),
                action.claim_token(),
                action
                    .claim_deadline_unix_ms()
                    .map(|value| sqlite_integer(value, "cleanup claim deadline"))
                    .transpose()?,
                sqlite_integer(action.version(), "cleanup version")?,
                action.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn persist_cleanup_transition(
    connection: &Connection,
    current: &AdmissionCleanupAction,
    next: &AdmissionCleanupAction,
    expected_claim_token: Option<&str>,
) -> Result<(), AdmissionOperationError> {
    let updated = connection
        .execute(
            r#"
            UPDATE admission_cleanup_actions
            SET state = ?4,
                claim_token = ?5,
                claim_deadline_unix_ms = ?6,
                version = ?7,
                last_error = ?8,
                updated_at = ?9
            WHERE action_id = ?1
              AND version = ?2
              AND claim_token IS ?3
            "#,
            params![
                current.action_id(),
                sqlite_integer(current.version(), "cleanup expected version")?,
                expected_claim_token,
                next.state().as_str(),
                next.claim_token(),
                next.claim_deadline_unix_ms()
                    .map(|value| sqlite_integer(value, "cleanup claim deadline"))
                    .transpose()?,
                sqlite_integer(next.version(), "cleanup next version")?,
                next.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    if updated != 1 {
        return Err(AdmissionOperationError::Unavailable(
            "cleanup action changed during fenced transition".to_string(),
        ));
    }
    Ok(())
}

fn sqlite_integer(value: u64, label: &str) -> Result<i64, AdmissionOperationError> {
    i64::try_from(value)
        .map_err(|_| AdmissionOperationError::Overflow(format!("{label} exceeds SQLite INTEGER")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, AdmissionOperationError> {
    u64::try_from(value)
        .map_err(|_| AdmissionOperationError::Invalid(format!("persisted {label} is negative")))
}

fn sqlite_error(error: rusqlite::Error) -> AdmissionOperationError {
    AdmissionOperationError::Unavailable(format!("sqlite admission operation error: {error}"))
}

fn reject_volatile_database_path(path: &Path) -> Result<(), AdmissionOperationError> {
    let path = path.to_string_lossy();
    let lower = path.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path.is_empty() || path == ":memory:" || memory_uri || lower.starts_with("file::memory:") {
        return Err(AdmissionOperationError::Invalid(
            "volatile SQLite admission-operation paths are not durable; use open_in_memory for an explicitly ephemeral store"
                .to_string(),
        ));
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_kernel::{
        AdmissionOperationCompareAndSwap, AdmissionOperationKind, PreparedAdmissionOperation,
    };

    fn cas_request<'a>(
        operation_id: &'a str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> AdmissionOperationCompareAndSwap<'a> {
        AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        }
    }

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn operation() -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::ToolDispatch,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "request-1".to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: Some("attempt-1".to_string()),
            budget_hold_id: Some("hold-1".to_string()),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: Some("nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    fn governed_response_operation() -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::GovernedActiveResponse,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "response-request-1".to_string(),
            capability_id: "response-capability-1".to_string(),
            authorization_capability_hash: "55".repeat(32),
            request_binding_hash: "66".repeat(32),
            policy_hash: "77".repeat(32),
            broker_attempt_id: None,
            budget_hold_id: None,
            approval_set_hash: Some("88".repeat(32)),
            execution_nonce_id: None,
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    #[test]
    fn admission_operation_survives_restart_and_exact_create_retry() {
        let path = unique_db_path("chio-admission-operation-restart");
        let operation = operation();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            assert_eq!(
                store.authority_profile(),
                AdmissionOperationStoreProfile::SingleNodeDurable
            );
            assert!(matches!(
                store.create_prepared(operation.clone()).unwrap(),
                AdmissionOperationCreateOutcome::Created(_)
            ));
        }
        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(operation.operation_id()).unwrap(),
            Some(operation.clone())
        );
        assert!(matches!(
            reopened.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Existing(_)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_profile_reflects_instance_durability() {
        let memory = SqliteAdmissionOperationStore::open_in_memory().unwrap();
        assert_eq!(
            memory.authority_profile(),
            AdmissionOperationStoreProfile::EphemeralLocal
        );
        assert!(SqliteAdmissionOperationStore::open(":memory:").is_err());
        assert!(SqliteAdmissionOperationStore::open("file::memory:?cache=shared").is_err());
        assert!(
            SqliteAdmissionOperationStore::open("file:admission?mode=memory&cache=shared").is_err()
        );
    }

    #[test]
    fn admission_operation_compare_and_swap_is_durable_and_fenced() {
        let path = unique_db_path("chio-admission-operation-cas");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let applied = store
            .compare_and_swap(cas_request(
                &operation_id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap();
        assert!(matches!(applied, AdmissionOperationCasOutcome::Applied(_)));
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
        drop(store);
        assert_eq!(
            SqliteAdmissionOperationStore::open(&path)
                .unwrap()
                .load(&operation_id)
                .unwrap()
                .unwrap()
                .version(),
            1
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn recovery_inventory_and_epoch_claim_survive_restart() {
        let path = unique_db_path("chio-admission-operation-recovery-claim");
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation).unwrap();
            let inventory = store
                .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 1)
                .unwrap();
            assert_eq!(inventory.len(), 1);
            let AdmissionOperationCasOutcome::Applied(claimed) =
                store.claim_recovery(&operation_id, 0, 7).unwrap()
            else {
                panic!("recovery claim should apply");
            };
            assert_eq!(claimed.state(), AdmissionOperationState::Prepared);
            assert_eq!(claimed.coordinator_lease_epoch(), 8);
            assert_eq!(claimed.version(), 1);
            assert!(matches!(
                store.claim_recovery(&operation_id, 0, 7).unwrap(),
                AdmissionOperationCasOutcome::Conflict(_)
            ));
        }
        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        let claimed = reopened.load(&operation_id).unwrap().unwrap();
        assert_eq!(claimed.coordinator_lease_epoch(), 8);
        assert_eq!(claimed.version(), 1);
        assert_eq!(reopened.list_unresolved(None, 1).unwrap(), vec![claimed]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unresolved_authority_count_includes_unknown_post_dispatch_outcome() {
        let path = unique_db_path("chio-admission-operation-unresolved-authority");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = governed_response_operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();

        for (expected_version, state, dispatch_state) in [
            (
                0,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
            ),
            (
                1,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
            ),
            (
                2,
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown,
            ),
        ] {
            let outcome = if state.is_terminal() {
                let current = store.load(&operation_id).unwrap().unwrap();
                let action = AdmissionCleanupAction::pending(
                    &current,
                    AdmissionCleanupActionKind::TerminalReceipt,
                    &serde_json::json!({"terminal": state.as_str()}),
                )
                .unwrap();
                store.compare_and_swap_with_cleanup_action(
                    cas_request(
                        &operation_id,
                        expected_version,
                        7,
                        state,
                        dispatch_state,
                        7,
                        None,
                    ),
                    action,
                )
            } else {
                store.compare_and_swap(cas_request(
                    &operation_id,
                    expected_version,
                    7,
                    state,
                    dispatch_state,
                    7,
                    None,
                ))
            };
            assert!(matches!(
                outcome.unwrap(),
                AdmissionOperationCasOutcome::Applied(_)
            ));
        }

        assert_eq!(
            store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::GovernedActiveResponse,
                    "coordinator-1",
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::ToolDispatch,
                    "coordinator-1",
                )
                .unwrap(),
            0
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn advanced_admission_operation_accepts_deterministic_create_retry() {
        let path = unique_db_path("chio-admission-operation-advanced-retry");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let prepared = operation();
        let operation_id = prepared.operation_id().to_string();
        store.create_prepared(prepared.clone()).unwrap();
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));

        let retry = store.create_prepared(prepared).unwrap();
        let AdmissionOperationCreateOutcome::Existing(existing) = retry else {
            panic!("deterministic retry must return the advanced operation");
        };
        assert_eq!(existing.state(), AdmissionOperationState::BudgetAuthorized);
        assert_eq!(existing.version(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn participant_stages_survive_restart_and_resume_linearly() {
        let path = unique_db_path("chio-admission-operation-participant-restart");
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation).unwrap();
            for (expected_version, state) in [
                (0, AdmissionOperationState::BudgetAuthorized),
                (1, AdmissionOperationState::DelegatedBudgetReserved),
                (2, AdmissionOperationState::PaymentAuthorized),
            ] {
                assert!(matches!(
                    store
                        .compare_and_swap(cas_request(
                            &operation_id,
                            expected_version,
                            7,
                            state,
                            AdmissionDispatchState::NotStarted,
                            7,
                            None,
                        ))
                        .unwrap(),
                    AdmissionOperationCasOutcome::Applied(_)
                ));
            }
        }

        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        let recovered = reopened.load(&operation_id).unwrap().unwrap();
        assert_eq!(
            recovered.state(),
            AdmissionOperationState::PaymentAuthorized
        );
        assert_eq!(recovered.version(), 3);
        assert!(matches!(
            reopened
                .compare_and_swap(cas_request(
                    &operation_id,
                    recovered.version(),
                    recovered.coordinator_lease_epoch(),
                    AdmissionOperationState::ApprovalReserved,
                    AdmissionDispatchState::NotStarted,
                    recovered.coordinator_lease_epoch(),
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_rejects_corrupted_state() {
        let path = unique_db_path("chio-admission-operation-corrupt");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE admission_operations SET state = 'future_state' WHERE operation_id = ?1",
                params![operation_id],
            )
            .unwrap();
        assert!(matches!(
            store.load(&operation_id),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cleanup_action_retries_require_the_exact_payload_and_state() {
        let path = unique_db_path("chio-admission-cleanup-exact-retry");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        store.create_prepared(operation.clone()).unwrap();
        let action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 1}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(action.clone()).unwrap(),
            AdmissionCleanupActionCreateOutcome::Created(_)
        ));
        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(action.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("cleanup action should be claimable");
        };
        assert!(matches!(
            store
                .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
                .unwrap(),
            AdmissionCleanupActionCasOutcome::Applied(_)
        ));

        assert!(matches!(
            store.create_cleanup_action(action.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                action.clone(),
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(
            store.load(operation.operation_id()).unwrap(),
            Some(operation.clone())
        );

        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE admission_cleanup_actions SET payload_json = ?2 WHERE action_id = ?1",
                params![action.action_id(), r#"{"participant":"budget","value":2}"#],
            )
            .unwrap();
        assert!(matches!(
            store.create_cleanup_action(action.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                action,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn completed_terminal_action_cannot_finalize_compensation_pending_operation() {
        let path = unique_db_path("chio-admission-terminal-action-state");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        store.create_prepared(operation.clone()).unwrap();
        let terminal_action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(terminal_action.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("terminal action should be claimable");
        };
        store
            .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
            .unwrap();
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    compensation_pending.operation_id(),
                    compensation_pending.version(),
                    compensation_pending.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensatedBeforeDispatch,
                    AdmissionDispatchState::NotStarted,
                    compensation_pending.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(
            store.load(operation.operation_id()).unwrap(),
            Some(compensation_pending)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cleanup_journal_survives_each_participant_crash_window() {
        let path = unique_db_path("chio-admission-cleanup-restart");
        let operation = operation();
        let kinds = [
            AdmissionCleanupActionKind::Budget,
            AdmissionCleanupActionKind::Payment,
            AdmissionCleanupActionKind::DelegatedBudget,
            AdmissionCleanupActionKind::Approval,
            AdmissionCleanupActionKind::ExecutionNonce,
            AdmissionCleanupActionKind::Broker,
        ];
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation.clone()).unwrap();
            for kind in kinds {
                let action = AdmissionCleanupAction::pending(
                    &operation,
                    kind,
                    &serde_json::json!({
                        "operationId": operation.operation_id(),
                        "participant": kind.as_str(),
                    }),
                )
                .unwrap();
                store.create_cleanup_action(action).unwrap();
            }
            let terminal_action = AdmissionCleanupAction::pending(
                &operation,
                AdmissionCleanupActionKind::TerminalReceipt,
                &serde_json::json!({"terminal": "compensated_before_dispatch"}),
            )
            .unwrap();
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        operation.operation_id(),
                        operation.version(),
                        operation.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensationPending,
                        AdmissionDispatchState::NotStarted,
                        operation.coordinator_lease_epoch(),
                        Some("deny".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap();
            let first = store
                .load_cleanup_actions(operation.operation_id())
                .unwrap()
                .remove(0);
            assert!(matches!(
                store
                    .claim_cleanup_action(first.action_id(), "crashed-worker", 100, 200)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Claimed(_)
            ));
        }

        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .list_compensated_with_pending_cleanup(None, 4)
                .unwrap(),
            vec![operation.operation_id().to_string()]
        );
        for action in reopened
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
        {
            let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = reopened
                .claim_cleanup_action(action.action_id(), "recovery-worker", 200, 300)
                .unwrap()
            else {
                panic!("recovery worker should own the action");
            };
            assert!(matches!(
                reopened
                    .claim_cleanup_action(action.action_id(), "concurrent-worker", 250, 350)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Busy(_)
            ));
            reopened
                .acknowledge_cleanup_action(
                    claimed.action_id(),
                    claimed.version(),
                    "recovery-worker",
                )
                .unwrap();
            assert!(matches!(
                reopened
                    .acknowledge_cleanup_action(
                        claimed.action_id(),
                        claimed.version(),
                        "recovery-worker",
                    )
                    .unwrap(),
                AdmissionCleanupActionCasOutcome::Conflict(current)
                    if current.state() == AdmissionCleanupActionState::Completed
            ));
        }
        drop(reopened);

        let reopened_after_ack_loss = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert!(reopened_after_ack_loss
            .list_compensated_with_pending_cleanup(None, 8)
            .unwrap()
            .is_empty());
        assert!(reopened_after_ack_loss
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
            .iter()
            .all(|action| action.state() == AdmissionCleanupActionState::Completed));
        let _ = fs::remove_file(path);
    }
}
