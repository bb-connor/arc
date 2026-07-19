use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::budget_store::{
    BudgetAuthorityProfile, BudgetCommitMetadata, BudgetEventAuthority, BudgetGuaranteeLevel,
    BudgetMeteringProfile, BudgetStoreError,
};
use chio_kernel::{
    AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureDenial,
    AdmissionCaptureError, AdmissionCaptureMetadata, AdmissionCaptureMetadataInput,
    AdmissionCaptureRequest, RevocationStore, RevocationStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::budget_store::SqliteBudgetStore;
use crate::revocation_store::{configure_revocation_connection, ensure_revocation_schema};

pub(crate) const COMBINED_AUTHORITY_MODE: &str = "combined-admission-capture-v1";
const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;

const INSTALL_REVOCATION_WRITE_GUARDS: &str = r#"
    CREATE TRIGGER IF NOT EXISTS admission_revocation_insert_requires_authority
    BEFORE INSERT ON revoked_capabilities
    BEGIN
        SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
    END;

    CREATE TRIGGER IF NOT EXISTS admission_revocation_update_requires_authority
    BEFORE UPDATE ON revoked_capabilities
    BEGIN
        SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
    END;

    CREATE TRIGGER IF NOT EXISTS admission_revocation_delete_requires_authority
    BEFORE DELETE ON revoked_capabilities
    BEGIN
        SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
    END;
"#;

const REMOVE_REVOCATION_WRITE_GUARDS: &str = r#"
    DROP TRIGGER IF EXISTS admission_revocation_insert_requires_authority;
    DROP TRIGGER IF EXISTS admission_revocation_update_requires_authority;
    DROP TRIGGER IF EXISTS admission_revocation_delete_requires_authority;
"#;

/// Durable result of a routed revocation write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteRevocationWriteOutcome {
    was_present: bool,
    changed: bool,
    revoked_at: i64,
    revocation_commit_index: u64,
    authority_commit_index: u64,
}

/// One transactionally consistent read of broker revocation members and the
/// combined authority heads that fenced the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteCombinedRevocationSnapshot {
    revoked_ids: Vec<String>,
    revocation_commit_index: u64,
    authority_commit_index: u64,
}

impl SqliteCombinedRevocationSnapshot {
    pub fn revoked_ids(&self) -> &[String] {
        &self.revoked_ids
    }

    pub fn revocation_commit_index(&self) -> u64 {
        self.revocation_commit_index
    }

    pub fn authority_commit_index(&self) -> u64 {
        self.authority_commit_index
    }
}

impl SqliteRevocationWriteOutcome {
    pub fn was_present(&self) -> bool {
        self.was_present
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn revoked_at(&self) -> i64 {
        self.revoked_at
    }

    pub fn revocation_commit_index(&self) -> u64 {
        self.revocation_commit_index
    }

    pub fn authority_commit_index(&self) -> u64 {
        self.authority_commit_index
    }
}

/// Same-database authority for revocation checking and composite quota capture.
///
/// Every admission attempt uses one `BEGIN IMMEDIATE` transaction on the file
/// containing both the revocation stream and the composite budget state.
pub struct SqliteAdmissionCaptureAuthority {
    connection: Mutex<Connection>,
}

fn with_revocation_savepoint<T>(
    transaction: &Transaction<'_>,
    apply: impl FnOnce() -> Result<T, RevocationStoreError>,
) -> Result<T, RevocationStoreError> {
    const NAME: &str = "chio_upsert_revocation";
    transaction.execute_batch(&format!("SAVEPOINT {NAME}"))?;
    match apply() {
        Ok(value) => {
            transaction.execute_batch(&format!("RELEASE {NAME}"))?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback_error) =
                transaction.execute_batch(&format!("ROLLBACK TO {NAME}; RELEASE {NAME}"))
            {
                return Err(RevocationStoreError::Sync(format!(
                    "revocation savepoint rollback failed after `{error}`: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

fn with_capture_savepoint<T>(
    transaction: &Transaction<'_>,
    apply: impl FnOnce() -> Result<T, AdmissionCaptureError>,
) -> Result<T, AdmissionCaptureError> {
    const NAME: &str = "chio_capture_admission";
    transaction
        .execute_batch(&format!("SAVEPOINT {NAME}"))
        .map_err(BudgetStoreError::from)?;
    match apply() {
        Ok(value) => {
            transaction
                .execute_batch(&format!("RELEASE {NAME}"))
                .map_err(BudgetStoreError::from)?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback_error) =
                transaction.execute_batch(&format!("ROLLBACK TO {NAME}; RELEASE {NAME}"))
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "admission capture savepoint rollback failed after `{error}`: {rollback_error}"
                ))
                .into());
            }
            Err(error)
        }
    }
}

impl SqliteAdmissionCaptureAuthority {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AdmissionCaptureError> {
        let path = path.as_ref();
        Self::open_with_paths(path, path)
    }

    /// Open an authority only when both logical stores resolve to one file.
    ///
    /// This constructor exists to make accidental split-store wiring fail at
    /// startup rather than degrading the atomicity contract at runtime.
    pub fn open_with_paths(
        budget_path: impl AsRef<Path>,
        revocation_path: impl AsRef<Path>,
    ) -> Result<Self, AdmissionCaptureError> {
        let budget_path = normalized_database_path(budget_path.as_ref())?;
        let revocation_path = normalized_database_path(revocation_path.as_ref())?;
        if budget_path != revocation_path {
            return Err(AdmissionCaptureError::InvalidRequest(
                "combined admission authority requires identical budget and revocation database paths"
                    .to_string(),
            ));
        }

        // Reuse the production budget initializer. The authority then owns a
        // separate connection to the same file for the combined transaction.
        drop(SqliteBudgetStore::open(&budget_path)?);
        let mut connection = Connection::open(&budget_path).map_err(RevocationStoreError::from)?;
        configure_revocation_connection(&connection)?;
        ensure_revocation_schema(&connection)?;

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(RevocationStoreError::from)?;
        ensure_admission_authority_schema(&transaction)?;
        backfill_legacy_revocations(&transaction)?;
        validate_authority_state(&transaction)?;
        transaction
            .execute_batch(REMOVE_REVOCATION_WRITE_GUARDS)
            .map_err(RevocationStoreError::from)?;
        transaction
            .execute_batch(INSTALL_REVOCATION_WRITE_GUARDS)
            .map_err(RevocationStoreError::from)?;
        transaction.commit().map_err(RevocationStoreError::from)?;

        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn capture_connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionCaptureError> {
        self.connection.lock().map_err(|_| {
            AdmissionCaptureError::Unavailable(
                "sqlite admission capture authority lock poisoned".to_string(),
            )
        })
    }

    fn revocation_connection(&self) -> Result<MutexGuard<'_, Connection>, RevocationStoreError> {
        self.connection.lock().map_err(|_| {
            RevocationStoreError::Sync(
                "sqlite admission capture authority lock poisoned".to_string(),
            )
        })
    }

    /// Route a revocation through the combined authority and assign both
    /// monotonic stream indices in the same transaction as the base row.
    pub fn revoke(
        &self,
        capability_id: &str,
    ) -> Result<SqliteRevocationWriteOutcome, RevocationStoreError> {
        validate_revocation_identifier(capability_id)?;
        let mut connection = self.revocation_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some((revoked_at, revocation_index, authority_index)) = transaction
            .query_row(
                r#"
                SELECT revoked_at, revocation_commit_index, authority_commit_index
                FROM admission_revocation_commits
                WHERE capability_id = ?1
                "#,
                params![capability_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        {
            let outcome = SqliteRevocationWriteOutcome {
                was_present: true,
                changed: false,
                revoked_at,
                revocation_commit_index: nonnegative_u64(
                    revocation_index,
                    "revocation commit index",
                )?,
                authority_commit_index: nonnegative_u64(authority_index, "authority commit index")?,
            };
            transaction.rollback()?;
            return Ok(outcome);
        }

        let unindexed_base_row = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if unindexed_base_row {
            return Err(RevocationStoreError::Sync(format!(
                "revocation `{capability_id}` exists without a combined-authority index"
            )));
        }

        let (authority_commit_index, revocation_commit_index) =
            allocate_authority_indices(&transaction, true)?;
        let revoked_at = unix_now();
        transaction.execute_batch(REMOVE_REVOCATION_WRITE_GUARDS)?;
        transaction.execute(
            "INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES (?1, ?2)",
            params![capability_id, revoked_at],
        )?;
        insert_authority_commit(
            &transaction,
            authority_commit_index,
            "revocation",
            None,
            None,
            Some(capability_id),
            revocation_commit_index,
            None,
            revoked_at,
        )?;
        transaction.execute(
            r#"
            INSERT INTO admission_revocation_commits (
                capability_id, revoked_at, revocation_commit_index,
                authority_commit_index
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                capability_id,
                revoked_at,
                sqlite_i64(revocation_commit_index, "revocation commit index")?,
                sqlite_i64(authority_commit_index, "authority commit index")?,
            ],
        )?;
        transaction.execute_batch(INSTALL_REVOCATION_WRITE_GUARDS)?;
        transaction.commit()?;
        Ok(SqliteRevocationWriteOutcome {
            was_present: false,
            changed: true,
            revoked_at,
            revocation_commit_index,
            authority_commit_index,
        })
    }

    /// Import or merge a timestamped revocation through the combined authority.
    ///
    /// The effective timestamp follows the legacy store's monotonic `MAX`
    /// rule. Each distinct `(capability_id, requested revoked_at)` input has a
    /// durable frozen outcome, including no-op imports, so later imports cannot
    /// change the result returned by an exact retry.
    pub fn upsert_revocation(
        &self,
        record: &chio_kernel::RevocationRecord,
    ) -> Result<SqliteRevocationWriteOutcome, RevocationStoreError> {
        let mut connection = self.revocation_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::upsert_revocation_in_transaction(&transaction, record)?;
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn upsert_revocation_in_transaction(
        transaction: &Transaction<'_>,
        record: &chio_kernel::RevocationRecord,
    ) -> Result<SqliteRevocationWriteOutcome, RevocationStoreError> {
        with_revocation_savepoint(transaction, || {
            Self::upsert_revocation_in_transaction_unchecked(transaction, record)
        })
    }

    fn upsert_revocation_in_transaction_unchecked(
        transaction: &Transaction<'_>,
        record: &chio_kernel::RevocationRecord,
    ) -> Result<SqliteRevocationWriteOutcome, RevocationStoreError> {
        validate_authority_state(transaction)?;
        validate_revocation_identifier(&record.capability_id)?;

        if let Some(outcome) =
            load_revocation_upsert_outcome(transaction, &record.capability_id, record.revoked_at)?
        {
            return Ok(outcome);
        }

        let existing = transaction
            .query_row(
                r#"
                SELECT revoked.revoked_at, indexed.revocation_commit_index,
                       indexed.authority_commit_index
                FROM revoked_capabilities AS revoked
                LEFT JOIN admission_revocation_commits AS indexed
                  ON indexed.capability_id = revoked.capability_id
                WHERE revoked.capability_id = ?1
                "#,
                params![record.capability_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?;
        let was_present = existing.is_some();
        let (existing_revoked_at, revocation_commit_index) = match existing {
            Some((revoked_at, Some(revocation_index), Some(_))) => (
                Some(revoked_at),
                nonnegative_u64(revocation_index, "revocation commit index")?,
            ),
            Some(_) => {
                return Err(RevocationStoreError::Sync(format!(
                    "revocation `{}` exists without a complete combined-authority index",
                    record.capability_id
                )));
            }
            None => (None, 0),
        };
        let changed = existing_revoked_at.is_none_or(|stored| record.revoked_at > stored);
        let effective_revoked_at =
            existing_revoked_at.map_or(record.revoked_at, |stored| stored.max(record.revoked_at));
        let (authority_commit_index, allocated_revocation_index) =
            allocate_authority_indices(transaction, !was_present)?;
        let revocation_commit_index = if was_present {
            revocation_commit_index
        } else {
            allocated_revocation_index
        };
        let recorded_at = unix_now();

        insert_authority_commit(
            transaction,
            authority_commit_index,
            "revocation-upsert",
            None,
            None,
            Some(&record.capability_id),
            revocation_commit_index,
            None,
            recorded_at,
        )?;
        if !was_present {
            transaction.execute_batch(REMOVE_REVOCATION_WRITE_GUARDS)?;
            transaction.execute(
                "INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES (?1, ?2)",
                params![record.capability_id, record.revoked_at],
            )?;
            transaction.execute_batch(INSTALL_REVOCATION_WRITE_GUARDS)?;
            transaction.execute(
                r#"
                INSERT INTO admission_revocation_commits (
                    capability_id, revoked_at, revocation_commit_index,
                    authority_commit_index
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    record.capability_id,
                    record.revoked_at,
                    sqlite_i64(revocation_commit_index, "revocation commit index")?,
                    sqlite_i64(authority_commit_index, "authority commit index")?,
                ],
            )?;
        } else if changed {
            transaction.execute_batch(REMOVE_REVOCATION_WRITE_GUARDS)?;
            transaction.execute(
                "UPDATE revoked_capabilities SET revoked_at = ?2 WHERE capability_id = ?1",
                params![record.capability_id, effective_revoked_at],
            )?;
            transaction.execute_batch(INSTALL_REVOCATION_WRITE_GUARDS)?;
            transaction.execute(
                r#"
                UPDATE admission_revocation_commits
                SET revoked_at = ?2, authority_commit_index = ?3
                WHERE capability_id = ?1
                "#,
                params![
                    record.capability_id,
                    effective_revoked_at,
                    sqlite_i64(authority_commit_index, "authority commit index")?,
                ],
            )?;
        }

        let outcome = SqliteRevocationWriteOutcome {
            was_present,
            changed,
            revoked_at: effective_revoked_at,
            revocation_commit_index,
            authority_commit_index,
        };
        persist_revocation_upsert_outcome(
            transaction,
            &record.capability_id,
            record.revoked_at,
            &outcome,
            recorded_at,
        )?;
        Ok(outcome)
    }

    pub fn revocation_head(&self) -> Result<u64, RevocationStoreError> {
        let connection = self.revocation_connection()?;
        let (_, revocation_head) = load_authority_heads(&connection)?;
        Ok(revocation_head)
    }

    pub fn authority_head(&self) -> Result<u64, RevocationStoreError> {
        let connection = self.revocation_connection()?;
        let (authority_head, _) = load_authority_heads(&connection)?;
        Ok(authority_head)
    }

    pub fn broker_revocation_snapshot(
        &self,
        capability_ids: &[String],
    ) -> Result<SqliteCombinedRevocationSnapshot, RevocationStoreError> {
        if capability_ids.is_empty() || capability_ids.len() > 128 {
            return Err(RevocationStoreError::Sync(
                "broker revocation snapshot member count is invalid".to_string(),
            ));
        }
        let mut canonical_ids = capability_ids.to_vec();
        for capability_id in &canonical_ids {
            validate_revocation_identifier(capability_id)?;
        }
        canonical_ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if canonical_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RevocationStoreError::Sync(
                "broker revocation snapshot contains duplicate members".to_string(),
            ));
        }
        let mut connection = self.revocation_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let mut revoked_ids = Vec::new();
        for capability_id in canonical_ids {
            let revoked = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                params![capability_id],
                |row| row.get::<_, i64>(0),
            )? != 0;
            if revoked {
                revoked_ids.push(capability_id);
            }
        }
        let (authority_commit_index, revocation_commit_index) = load_authority_heads(&transaction)?;
        transaction.rollback()?;
        Ok(SqliteCombinedRevocationSnapshot {
            revoked_ids,
            revocation_commit_index,
            authority_commit_index,
        })
    }

    pub fn validate_capture_request(
        &self,
        request: &AdmissionCaptureRequest,
    ) -> Result<(), AdmissionCaptureError> {
        let mut connection = self.capture_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(BudgetStoreError::from)?;
        if let Some(stored) = load_admission_event(&transaction, request.operation_id())? {
            if !stored.matches(request)? {
                return Err(AdmissionCaptureError::InvalidRequest(format!(
                    "operation_id or request_binding_hash for `{}` was reused for a different admission capture",
                    request.operation_id()
                )));
            }
            restore_admission_decision(&transaction, request, &stored)?;
            transaction.rollback().map_err(BudgetStoreError::from)?;
            return Ok(());
        }
        let capture_event_id = request.budget().event_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "admission capture event_id is required".to_string(),
            )
        })?;
        if let Some(existing_operation) = transaction
            .query_row(
                "SELECT operation_id FROM admission_capture_events WHERE capture_event_id = ?1",
                params![capture_event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(BudgetStoreError::from)?
        {
            return Err(AdmissionCaptureError::InvalidRequest(format!(
                "capture event `{capture_event_id}` is already owned by operation `{existing_operation}`"
            )));
        }
        validate_authorization_bindings(&transaction, request)?;
        let (_, revocation_head) = load_authority_heads(&transaction)?;
        if request
            .last_observed_revocation_index()
            .is_some_and(|observed| observed > revocation_head)
        {
            return Err(AdmissionCaptureError::InvalidRequest(format!(
                "last-observed revocation index exceeds authority head {revocation_head}"
            )));
        }
        transaction.rollback().map_err(BudgetStoreError::from)?;
        Ok(())
    }
}

impl AdmissionCaptureAuthority for SqliteAdmissionCaptureAuthority {
    fn query_admission_capture(
        &self,
        request: &AdmissionCaptureRequest,
    ) -> Result<Option<AdmissionCaptureDecision>, AdmissionCaptureError> {
        let mut connection = self.capture_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(BudgetStoreError::from)?;
        let Some(stored) = load_admission_event(&transaction, request.operation_id())? else {
            transaction.rollback().map_err(BudgetStoreError::from)?;
            return Ok(None);
        };
        if !stored.matches(request)? {
            return Err(AdmissionCaptureError::InvalidRequest(format!(
                "operation_id or request_binding_hash for `{}` was reused for a different admission capture",
                request.operation_id()
            )));
        }
        let decision = restore_admission_decision(&transaction, request, &stored)?;
        transaction.rollback().map_err(BudgetStoreError::from)?;
        Ok(Some(decision))
    }

    fn capture_admission(
        &self,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        let mut connection = self.capture_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(BudgetStoreError::from)?;
        let decision = Self::capture_admission_in_transaction(&transaction, request)?;
        transaction.commit().map_err(BudgetStoreError::from)?;
        Ok(decision)
    }
}

impl SqliteAdmissionCaptureAuthority {
    pub fn capture_admission_in_transaction(
        transaction: &Transaction<'_>,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        with_capture_savepoint(transaction, || {
            Self::capture_admission_in_transaction_unchecked(transaction, request)
        })
    }

    fn capture_admission_in_transaction_unchecked(
        transaction: &Transaction<'_>,
        request: AdmissionCaptureRequest,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        validate_authority_state(transaction)?;
        if let Some(stored) = load_admission_event(transaction, request.operation_id())? {
            if !stored.matches(&request)? {
                return Err(AdmissionCaptureError::InvalidRequest(format!(
                    "operation_id or request_binding_hash for `{}` was reused for a different admission capture",
                    request.operation_id()
                )));
            }
            let decision = restore_admission_decision(transaction, &request, &stored)?;
            return Ok(decision);
        }

        let capture_event_id = request.budget().event_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "admission capture event_id is required".to_string(),
            )
        })?;
        if let Some(existing_operation) = transaction
            .query_row(
                "SELECT operation_id FROM admission_capture_events WHERE capture_event_id = ?1",
                params![capture_event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(BudgetStoreError::from)?
        {
            return Err(AdmissionCaptureError::InvalidRequest(format!(
                "capture event `{capture_event_id}` is already owned by operation `{existing_operation}`"
            )));
        }

        validate_authorization_bindings(transaction, &request)?;
        let (_, revocation_head) = load_authority_heads(transaction)?;
        if request
            .last_observed_revocation_index()
            .is_some_and(|observed| observed > revocation_head)
        {
            return Err(AdmissionCaptureError::InvalidRequest(format!(
                "last-observed revocation index exceeds authority head {revocation_head}"
            )));
        }

        let revoked_ids = load_revoked_ids(transaction, request.revocation_set().ids())?;
        let now = unix_now();
        if !revoked_ids.is_empty() {
            let (authority_commit_index, checked_revocation_index) =
                allocate_authority_indices(transaction, false)?;
            if checked_revocation_index != revocation_head {
                return Err(AdmissionCaptureError::Unavailable(
                    "revocation head changed inside one immediate transaction".to_string(),
                ));
            }
            insert_authority_commit(
                transaction,
                authority_commit_index,
                "capture-denied",
                Some(request.operation_id()),
                Some(capture_event_id),
                Some(&request.budget().capability_id),
                revocation_head,
                None,
                now,
            )?;
            persist_admission_event(
                transaction,
                &request,
                "denied-revoked",
                Some(&revoked_ids),
                revocation_head,
                authority_commit_index,
                None,
                now,
            )?;
            let budget_commit = denial_budget_metadata(&request);
            let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: request.bound_revocation_set_digest().to_string(),
                aggregate_root_capability_id: request
                    .aggregate_root_capability_id()
                    .map(ToOwned::to_owned),
                aggregate_root_binding_digest: request
                    .aggregate_root_binding_digest()
                    .map(ToOwned::to_owned),
                budget_commit,
                revocation_commit_index: revocation_head,
                authority_commit_index,
                leader_epoch: None,
            })?;
            let decision = AdmissionCaptureDecision::Denied(AdmissionCaptureDenial::revoked(
                revoked_ids,
                metadata,
            )?);
            return Ok(decision);
        }

        let budget =
            SqliteBudgetStore::capture_composite_invocation_reservations_in_transaction_unchecked(
                transaction,
                request.budget(),
            )?;
        let budget_commit_index = budget.metadata.budget_commit_index.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "composite capture did not persist a budget commit index".to_string(),
            )
        })?;
        let (authority_commit_index, checked_revocation_index) =
            allocate_authority_indices(transaction, false)?;
        if checked_revocation_index != revocation_head {
            return Err(AdmissionCaptureError::Unavailable(
                "revocation head changed inside one immediate transaction".to_string(),
            ));
        }
        insert_authority_commit(
            transaction,
            authority_commit_index,
            "capture",
            Some(request.operation_id()),
            Some(capture_event_id),
            Some(&request.budget().capability_id),
            revocation_head,
            Some(budget_commit_index),
            now,
        )?;
        persist_admission_event(
            transaction,
            &request,
            "captured",
            None,
            revocation_head,
            authority_commit_index,
            Some(budget_commit_index),
            now,
        )?;
        let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
            operation_id: request.operation_id().to_string(),
            checked_revocation_set_digest: request.bound_revocation_set_digest().to_string(),
            aggregate_root_capability_id: request
                .aggregate_root_capability_id()
                .map(ToOwned::to_owned),
            aggregate_root_binding_digest: request
                .aggregate_root_binding_digest()
                .map(ToOwned::to_owned),
            budget_commit: budget.metadata.clone(),
            revocation_commit_index: revocation_head,
            authority_commit_index,
            leader_epoch: None,
        })?;
        let decision = AdmissionCaptureDecision::Captured {
            budget: Box::new(budget),
            metadata,
        };
        Ok(decision)
    }
}

impl RevocationStore for SqliteAdmissionCaptureAuthority {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        validate_revocation_identifier(capability_id)?;
        let connection = self.revocation_connection()?;
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(!SqliteAdmissionCaptureAuthority::revoke(self, capability_id)?.was_present())
    }
}

fn ensure_admission_authority_schema(
    transaction: &Transaction<'_>,
) -> Result<(), RevocationStoreError> {
    transaction.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS admission_authority_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            mode TEXT NOT NULL,
            authority_commit_index INTEGER NOT NULL DEFAULT 0 CHECK (authority_commit_index >= 0),
            revocation_commit_index INTEGER NOT NULL DEFAULT 0 CHECK (revocation_commit_index >= 0)
        );

        CREATE TABLE IF NOT EXISTS admission_authority_commits (
            authority_commit_index INTEGER PRIMARY KEY CHECK (authority_commit_index > 0),
            kind TEXT NOT NULL CHECK (kind IN (
                'revocation', 'revocation-upsert', 'capture', 'capture-denied'
            )),
            operation_id TEXT,
            capture_event_id TEXT,
            capability_id TEXT,
            revocation_commit_index INTEGER NOT NULL CHECK (revocation_commit_index >= 0),
            budget_commit_index INTEGER CHECK (budget_commit_index IS NULL OR budget_commit_index > 0),
            recorded_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admission_revocation_commits (
            capability_id TEXT PRIMARY KEY REFERENCES revoked_capabilities(capability_id),
            revoked_at INTEGER NOT NULL,
            revocation_commit_index INTEGER NOT NULL UNIQUE CHECK (revocation_commit_index > 0),
            authority_commit_index INTEGER NOT NULL UNIQUE
                REFERENCES admission_authority_commits(authority_commit_index)
        );

        CREATE TABLE IF NOT EXISTS admission_capture_events (
            operation_id TEXT PRIMARY KEY,
            request_binding_hash TEXT NOT NULL,
            capture_event_id TEXT NOT NULL UNIQUE,
            hold_id TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            grant_index INTEGER NOT NULL CHECK (grant_index >= 0),
            authority_id TEXT,
            lease_id TEXT,
            lease_epoch INTEGER CHECK (lease_epoch IS NULL OR lease_epoch >= 0),
            revocation_set_digest TEXT NOT NULL,
            revocation_ids_json TEXT NOT NULL,
            artifact_digests_json TEXT NOT NULL,
            aggregate_root_capability_id TEXT,
            aggregate_root_binding_digest TEXT,
            last_observed_revocation_index INTEGER
                CHECK (last_observed_revocation_index IS NULL OR last_observed_revocation_index >= 0),
            outcome TEXT NOT NULL CHECK (outcome IN ('captured', 'denied-revoked')),
            revoked_ids_json TEXT,
            revocation_commit_index INTEGER NOT NULL CHECK (revocation_commit_index >= 0),
            authority_commit_index INTEGER NOT NULL UNIQUE
                REFERENCES admission_authority_commits(authority_commit_index),
            budget_commit_index INTEGER CHECK (budget_commit_index IS NULL OR budget_commit_index > 0),
            recorded_at INTEGER NOT NULL,
            CHECK (
                (authority_id IS NULL AND lease_id IS NULL AND lease_epoch IS NULL)
                OR
                (authority_id IS NOT NULL AND lease_id IS NOT NULL AND lease_epoch IS NOT NULL)
            ),
            CHECK (
                (aggregate_root_capability_id IS NULL AND aggregate_root_binding_digest IS NULL)
                OR
                (aggregate_root_capability_id IS NOT NULL AND aggregate_root_binding_digest IS NOT NULL)
            ),
            CHECK (
                (outcome = 'captured' AND revoked_ids_json IS NULL AND budget_commit_index IS NOT NULL)
                OR
                (outcome = 'denied-revoked' AND revoked_ids_json IS NOT NULL AND budget_commit_index IS NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS admission_revocation_upsert_events (
            capability_id TEXT NOT NULL,
            requested_revoked_at INTEGER NOT NULL,
            was_present INTEGER NOT NULL CHECK (was_present IN (0, 1)),
            changed INTEGER NOT NULL CHECK (changed IN (0, 1)),
            effective_revoked_at INTEGER NOT NULL,
            revocation_commit_index INTEGER NOT NULL CHECK (revocation_commit_index > 0),
            authority_commit_index INTEGER NOT NULL UNIQUE
                REFERENCES admission_authority_commits(authority_commit_index),
            recorded_at INTEGER NOT NULL,
            PRIMARY KEY (capability_id, requested_revoked_at),
            CHECK (was_present = 1 OR changed = 1)
        );

        INSERT INTO admission_authority_meta (
            singleton, mode, authority_commit_index, revocation_commit_index
        ) VALUES (1, 'combined-admission-capture-v1', 0, 0)
        ON CONFLICT(singleton) DO NOTHING;
        "#,
    )?;
    let mut statement = transaction.prepare("PRAGMA table_info(admission_capture_events)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if !columns
        .iter()
        .any(|column| column == "request_binding_hash")
    {
        transaction.execute(
            "ALTER TABLE admission_capture_events ADD COLUMN request_binding_hash TEXT",
            [],
        )?;
    }
    for column in [
        "aggregate_root_capability_id",
        "aggregate_root_binding_digest",
    ] {
        if !columns.iter().any(|existing| existing == column) {
            transaction.execute(
                &format!("ALTER TABLE admission_capture_events ADD COLUMN {column} TEXT"),
                [],
            )?;
        }
    }
    transaction.execute_batch(
        r#"
        CREATE TRIGGER IF NOT EXISTS admission_capture_event_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON admission_capture_events
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable admission capture owner');
        END;

        CREATE TRIGGER IF NOT EXISTS admission_capture_event_aggregate_evidence_immutable
        BEFORE UPDATE OF aggregate_root_capability_id, aggregate_root_binding_digest
        ON admission_capture_events
        WHEN OLD.aggregate_root_capability_id IS NOT NEW.aggregate_root_capability_id
          OR OLD.aggregate_root_binding_digest IS NOT NEW.aggregate_root_binding_digest
        BEGIN
            SELECT RAISE(ABORT, 'immutable admission capture aggregate evidence');
        END;
        "#,
    )?;
    let mode = transaction.query_row(
        "SELECT mode FROM admission_authority_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    if mode != COMBINED_AUTHORITY_MODE {
        return Err(RevocationStoreError::Sync(format!(
            "unsupported admission authority database mode `{mode}`"
        )));
    }
    Ok(())
}

fn backfill_legacy_revocations(transaction: &Transaction<'_>) -> Result<(), RevocationStoreError> {
    let rows = {
        let mut statement = transaction.prepare(
            r#"
            SELECT revoked.capability_id, revoked.revoked_at
            FROM revoked_capabilities AS revoked
            LEFT JOIN admission_revocation_commits AS indexed
              ON indexed.capability_id = revoked.capability_id
            WHERE indexed.capability_id IS NULL
            ORDER BY revoked.revoked_at ASC, revoked.capability_id ASC
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    if !rows.is_empty() {
        let (authority_head, revocation_head) = load_authority_heads(transaction)?;
        if authority_head != 0 || revocation_head != 0 {
            return Err(RevocationStoreError::Sync(
                "unindexed revocations cannot be backfilled after authority history exists"
                    .to_string(),
            ));
        }
    }
    for (capability_id, revoked_at) in rows {
        let (authority_commit_index, revocation_commit_index) =
            allocate_authority_indices(transaction, true)?;
        insert_authority_commit(
            transaction,
            authority_commit_index,
            "revocation",
            None,
            None,
            Some(&capability_id),
            revocation_commit_index,
            None,
            revoked_at,
        )?;
        transaction.execute(
            r#"
            INSERT INTO admission_revocation_commits (
                capability_id, revoked_at, revocation_commit_index,
                authority_commit_index
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                capability_id,
                revoked_at,
                sqlite_i64(revocation_commit_index, "revocation commit index")?,
                sqlite_i64(authority_commit_index, "authority commit index")?,
            ],
        )?;
    }
    Ok(())
}

fn validate_authority_state(transaction: &Transaction<'_>) -> Result<(), RevocationStoreError> {
    let (authority_head, revocation_head) = load_authority_heads(transaction)?;
    let (authority_count, authority_max) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(MAX(authority_commit_index), 0) FROM admission_authority_commits",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let (revocation_count, revocation_max) = transaction.query_row(
        "SELECT COUNT(*), COALESCE(MAX(revocation_commit_index), 0) FROM admission_revocation_commits",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let base_count =
        transaction.query_row("SELECT COUNT(*) FROM revoked_capabilities", [], |row| {
            row.get::<_, i64>(0)
        })?;
    let revocation_mismatches = transaction.query_row(
        r#"
        SELECT COUNT(*)
        FROM admission_revocation_commits AS indexed
        JOIN revoked_capabilities AS revoked
          ON revoked.capability_id = indexed.capability_id
        LEFT JOIN admission_authority_commits AS authority
          ON authority.authority_commit_index = indexed.authority_commit_index
        WHERE indexed.revoked_at != revoked.revoked_at
           OR authority.authority_commit_index IS NULL
           OR authority.kind NOT IN ('revocation', 'revocation-upsert')
           OR authority.operation_id IS NOT NULL
           OR authority.capture_event_id IS NOT NULL
           OR authority.capability_id IS NOT indexed.capability_id
           OR authority.revocation_commit_index != indexed.revocation_commit_index
           OR authority.budget_commit_index IS NOT NULL
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let capture_mismatches = transaction.query_row(
        r#"
        SELECT COUNT(*)
        FROM admission_capture_events AS capture
        LEFT JOIN admission_authority_commits AS authority
          ON authority.authority_commit_index = capture.authority_commit_index
        LEFT JOIN budget_mutation_events AS budget
          ON budget.event_id = capture.capture_event_id
        LEFT JOIN budget_composite_authorizations AS authorization
          ON authorization.hold_id = capture.hold_id
        LEFT JOIN budget_composite_holds AS composite_hold
          ON composite_hold.hold_id = capture.hold_id
        LEFT JOIN budget_authorization_holds AS base_hold
          ON base_hold.hold_id = capture.hold_id
        WHERE authority.authority_commit_index IS NULL
           OR authority.kind != CASE capture.outcome
               WHEN 'captured' THEN 'capture'
               ELSE 'capture-denied'
              END
           OR authority.operation_id IS NOT capture.operation_id
           OR authority.capture_event_id IS NOT capture.capture_event_id
           OR authority.capability_id IS NOT capture.capability_id
           OR authority.revocation_commit_index != capture.revocation_commit_index
           OR authority.budget_commit_index IS NOT capture.budget_commit_index
           OR capture.request_binding_hash IS NULL
           OR (capture.aggregate_root_capability_id IS NULL)
                != (capture.aggregate_root_binding_digest IS NULL)
           OR capture.aggregate_root_capability_id
                IS NOT authorization.aggregate_root_capability_id
           OR capture.aggregate_root_binding_digest
                IS NOT authorization.aggregate_root_binding_digest
           OR authorization.operation_id IS NOT capture.operation_id
           OR authorization.request_binding_hash IS NOT capture.request_binding_hash
           OR composite_hold.operation_id IS NOT capture.operation_id
           OR composite_hold.request_binding_hash IS NOT capture.request_binding_hash
           OR base_hold.operation_id IS NOT capture.operation_id
           OR base_hold.request_binding_hash IS NOT capture.request_binding_hash
           OR (capture.outcome = 'captured' AND (
                budget.event_id IS NULL
                OR budget.kind != 'capture_invocations'
                OR budget.event_seq IS NOT capture.budget_commit_index
                OR budget.hold_id IS NOT capture.hold_id
                OR budget.capability_id IS NOT capture.capability_id
                OR budget.grant_index != capture.grant_index
                OR budget.operation_id IS NOT capture.operation_id
                OR budget.request_binding_hash IS NOT capture.request_binding_hash
           ))
           OR (capture.outcome = 'denied-revoked' AND budget.event_id IS NOT NULL)
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let upsert_mismatches = transaction.query_row(
        r#"
        SELECT COUNT(*)
        FROM admission_revocation_upsert_events AS upsert
        LEFT JOIN admission_authority_commits AS authority
          ON authority.authority_commit_index = upsert.authority_commit_index
        WHERE authority.authority_commit_index IS NULL
           OR authority.kind != 'revocation-upsert'
           OR authority.operation_id IS NOT NULL
           OR authority.capture_event_id IS NOT NULL
           OR authority.capability_id IS NOT upsert.capability_id
           OR authority.revocation_commit_index != upsert.revocation_commit_index
           OR authority.budget_commit_index IS NOT NULL
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if authority_count < 0
        || revocation_count < 0
        || base_count < 0
        || u64::try_from(authority_count).ok() != Some(authority_head)
        || nonnegative_u64(authority_max, "maximum authority commit index")? != authority_head
        || u64::try_from(revocation_count).ok() != Some(revocation_head)
        || nonnegative_u64(revocation_max, "maximum revocation commit index")? != revocation_head
        || revocation_count != base_count
        || revocation_mismatches != 0
        || capture_mismatches != 0
        || upsert_mismatches != 0
    {
        return Err(RevocationStoreError::Sync(
            "combined admission authority indices are missing, sparse, or divergent".to_string(),
        ));
    }
    Ok(())
}

fn allocate_authority_indices(
    transaction: &Transaction<'_>,
    advances_revocation: bool,
) -> Result<(u64, u64), RevocationStoreError> {
    let (authority_head, revocation_head) = load_authority_heads(transaction)?;
    let next_authority = authority_head
        .checked_add(1)
        .ok_or_else(|| RevocationStoreError::Sync("authority commit index overflow".to_string()))?;
    let next_revocation = if advances_revocation {
        revocation_head.checked_add(1).ok_or_else(|| {
            RevocationStoreError::Sync("revocation commit index overflow".to_string())
        })?
    } else {
        revocation_head
    };
    let updated = transaction.execute(
        r#"
        UPDATE admission_authority_meta
        SET authority_commit_index = ?1, revocation_commit_index = ?2
        WHERE singleton = 1 AND mode = ?3
        "#,
        params![
            sqlite_i64(next_authority, "authority commit index")?,
            sqlite_i64(next_revocation, "revocation commit index")?,
            COMBINED_AUTHORITY_MODE,
        ],
    )?;
    if updated != 1 {
        return Err(RevocationStoreError::Sync(
            "combined admission authority metadata row is missing".to_string(),
        ));
    }
    Ok((next_authority, next_revocation))
}

fn load_authority_heads(connection: &Connection) -> Result<(u64, u64), RevocationStoreError> {
    let (authority, revocation) = connection.query_row(
        r#"
        SELECT authority_commit_index, revocation_commit_index
        FROM admission_authority_meta
        WHERE singleton = 1 AND mode = ?1
        "#,
        params![COMBINED_AUTHORITY_MODE],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((
        nonnegative_u64(authority, "authority commit index")?,
        nonnegative_u64(revocation, "revocation commit index")?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn insert_authority_commit(
    transaction: &Transaction<'_>,
    authority_commit_index: u64,
    kind: &str,
    operation_id: Option<&str>,
    capture_event_id: Option<&str>,
    capability_id: Option<&str>,
    revocation_commit_index: u64,
    budget_commit_index: Option<u64>,
    recorded_at: i64,
) -> Result<(), RevocationStoreError> {
    transaction.execute(
        r#"
        INSERT INTO admission_authority_commits (
            authority_commit_index, kind, operation_id, capture_event_id,
            capability_id, revocation_commit_index, budget_commit_index,
            recorded_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            sqlite_i64(authority_commit_index, "authority commit index")?,
            kind,
            operation_id,
            capture_event_id,
            capability_id,
            sqlite_i64(revocation_commit_index, "revocation commit index")?,
            budget_commit_index
                .map(|value| sqlite_i64(value, "budget commit index"))
                .transpose()?,
            recorded_at,
        ],
    )?;
    Ok(())
}

fn validate_authorization_bindings(
    transaction: &Transaction<'_>,
    request: &AdmissionCaptureRequest,
) -> Result<(), BudgetStoreError> {
    type AuthorizationRow = (
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<i64>,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let admission_operation = request
        .budget()
        .admission_operation
        .as_ref()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "admission capture requires an admission operation binding".to_string(),
            )
        })?;
    let hold_id = request.budget().hold_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("admission capture requires hold_id".to_string())
    })?;
    let row: AuthorizationRow = transaction
        .query_row(
            r#"
            SELECT capability_id, grant_index, authority_id, lease_id, lease_epoch,
                   allowed, revocation_set_digest, revocation_ids_json,
                   operation_id, request_binding_hash,
                   aggregate_root_capability_id, aggregate_root_binding_digest
            FROM budget_composite_authorizations
            WHERE hold_id = ?1
            "#,
            params![hold_id],
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
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "missing composite budget authorization for hold `{hold_id}`"
            ))
        })?;
    let stored_authority = stored_budget_authority(row.2, row.3, row.4)?;
    if row.8.as_deref() != Some(admission_operation.operation_id()) {
        return Err(BudgetStoreError::Conflict(format!(
            "budget hold `{hold_id}` belongs to a different admission operation_id"
        )));
    }
    if row.9.as_deref() != Some(admission_operation.request_binding_hash()) {
        return Err(BudgetStoreError::Conflict(format!(
            "budget hold `{hold_id}` belongs to a different admission request_binding_hash"
        )));
    }
    let expected_revocation_ids =
        serde_json::to_string(request.revocation_set().ids()).map_err(|error| {
            BudgetStoreError::Invariant(format!("failed to encode revocation set: {error}"))
        })?;
    if row.0 != request.budget().capability_id
        || nonnegative_usize(row.1, "composite grant index")? != request.budget().grant_index
        || stored_authority.as_ref() != request.budget().authority.as_ref()
        || row.5 != 1
        || row.6 != request.bound_revocation_set_digest()
        || row.7 != expected_revocation_ids
        || row.10.as_deref() != request.aggregate_root_capability_id()
        || row.11.as_deref() != request.aggregate_root_binding_digest()
    {
        return Err(BudgetStoreError::Invariant(format!(
            "admission capture bindings do not match budget hold `{hold_id}`"
        )));
    }

    let mut statement = transaction.prepare(
        r#"
        SELECT position, artifact_digest
        FROM budget_composite_authorization_artifacts
        WHERE hold_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let artifact_rows = statement
        .query_map(params![hold_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let artifact_digests = artifact_rows
        .iter()
        .enumerate()
        .map(|(expected_position, (position, digest))| {
            if *position != expected_position as i64 {
                return Err(BudgetStoreError::Invariant(
                    "persisted authorization artifact positions are not contiguous".to_string(),
                ));
            }
            Ok(digest.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if artifact_digests != request.authorization_artifact_digests() {
        return Err(BudgetStoreError::Invariant(format!(
            "authorization artifacts do not match budget hold `{hold_id}`"
        )));
    }

    type CompositeHoldRow = (String, String, String, Option<String>, Option<String>);
    let (invocation_state, hold_digest, hold_ids, hold_operation_id, hold_binding_hash):
        CompositeHoldRow = transaction
        .query_row(
            r#"
            SELECT invocation_state, revocation_set_digest, revocation_ids_json,
                   operation_id, request_binding_hash
            FROM budget_composite_holds WHERE hold_id = ?1
            "#,
            params![hold_id],
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
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "missing composite state for budget hold `{hold_id}`"
            ))
        })?;
    if hold_operation_id.as_deref() != Some(admission_operation.operation_id()) {
        return Err(BudgetStoreError::Conflict(format!(
            "composite budget hold `{hold_id}` belongs to a different admission operation_id"
        )));
    }
    if hold_binding_hash.as_deref() != Some(admission_operation.request_binding_hash()) {
        return Err(BudgetStoreError::Conflict(format!(
            "composite budget hold `{hold_id}` belongs to a different admission request_binding_hash"
        )));
    }
    if invocation_state != "authorized"
        || hold_digest != request.bound_revocation_set_digest()
        || hold_ids != expected_revocation_ids
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` is not an open authorized invocation reservation"
        )));
    }

    let base_hold_matches = transaction.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM budget_authorization_holds
            WHERE hold_id = ?1 AND capability_id = ?2 AND grant_index = ?3
              AND disposition = 'open'
              AND authority_id IS ?4 AND lease_id IS ?5 AND lease_epoch IS ?6
              AND operation_id = ?7 AND request_binding_hash = ?8
        )
        "#,
        params![
            hold_id,
            request.budget().capability_id,
            sqlite_i64(
                u64::try_from(request.budget().grant_index).map_err(|_| {
                    BudgetStoreError::Overflow("capture grant index exceeds u64".to_string())
                })?,
                "capture grant index",
            )
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?,
            request
                .budget()
                .authority
                .as_ref()
                .map(|authority| authority.authority_id.as_str()),
            request
                .budget()
                .authority
                .as_ref()
                .map(|authority| authority.lease_id.as_str()),
            request
                .budget()
                .authority
                .as_ref()
                .map(|authority| i64::try_from(authority.lease_epoch))
                .transpose()
                .map_err(|_| BudgetStoreError::Overflow(
                    "lease epoch exceeds SQLite integer".to_string()
                ))?,
            admission_operation.operation_id(),
            admission_operation.request_binding_hash(),
        ],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if !base_hold_matches {
        return Err(BudgetStoreError::Invariant(format!(
            "base budget hold `{hold_id}` does not match admission capture"
        )));
    }

    let capture_event_id = request.budget().event_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("admission capture requires event_id".to_string())
    })?;
    let budget_event_collision = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE event_id = ?1)",
        params![capture_event_id],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if budget_event_collision {
        return Err(BudgetStoreError::Invariant(format!(
            "budget capture event `{capture_event_id}` already exists without an admission outcome"
        )));
    }
    Ok(())
}

fn load_revoked_ids(
    transaction: &Transaction<'_>,
    ids: &[String],
) -> Result<Vec<String>, RevocationStoreError> {
    let mut revoked = Vec::new();
    let mut statement = transaction
        .prepare("SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)")?;
    for id in ids {
        if statement.query_row(params![id], |row| row.get::<_, i64>(0))? != 0 {
            revoked.push(id.clone());
        }
    }
    Ok(revoked)
}

fn load_revocation_upsert_outcome(
    transaction: &Transaction<'_>,
    capability_id: &str,
    requested_revoked_at: i64,
) -> Result<Option<SqliteRevocationWriteOutcome>, RevocationStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT was_present, changed, effective_revoked_at,
                   revocation_commit_index, authority_commit_index
            FROM admission_revocation_upsert_events
            WHERE capability_id = ?1 AND requested_revoked_at = ?2
            "#,
            params![capability_id, requested_revoked_at],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((was_present, changed, revoked_at, revocation_index, authority_index)) = row else {
        return Ok(None);
    };
    if !matches!(was_present, 0 | 1) || !matches!(changed, 0 | 1) {
        return Err(RevocationStoreError::Sync(
            "persisted revocation upsert outcome has invalid boolean state".to_string(),
        ));
    }
    Ok(Some(SqliteRevocationWriteOutcome {
        was_present: was_present != 0,
        changed: changed != 0,
        revoked_at,
        revocation_commit_index: nonnegative_u64(revocation_index, "revocation commit index")?,
        authority_commit_index: nonnegative_u64(authority_index, "authority commit index")?,
    }))
}

fn persist_revocation_upsert_outcome(
    transaction: &Transaction<'_>,
    capability_id: &str,
    requested_revoked_at: i64,
    outcome: &SqliteRevocationWriteOutcome,
    recorded_at: i64,
) -> Result<(), RevocationStoreError> {
    transaction.execute(
        r#"
        INSERT INTO admission_revocation_upsert_events (
            capability_id, requested_revoked_at, was_present, changed,
            effective_revoked_at, revocation_commit_index,
            authority_commit_index, recorded_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            capability_id,
            requested_revoked_at,
            i64::from(outcome.was_present),
            i64::from(outcome.changed),
            outcome.revoked_at,
            sqlite_i64(outcome.revocation_commit_index, "revocation commit index")?,
            sqlite_i64(outcome.authority_commit_index, "authority commit index")?,
            recorded_at,
        ],
    )?;
    Ok(())
}

#[derive(Debug)]
struct StoredAdmissionEvent {
    request_binding_hash: String,
    capture_event_id: String,
    hold_id: String,
    capability_id: String,
    grant_index: i64,
    authority: Option<BudgetEventAuthority>,
    revocation_set_digest: String,
    revocation_ids_json: String,
    artifact_digests_json: String,
    aggregate_root_capability_id: Option<String>,
    aggregate_root_binding_digest: Option<String>,
    last_observed_revocation_index: Option<i64>,
    outcome: String,
    revoked_ids_json: Option<String>,
    revocation_commit_index: i64,
    authority_commit_index: i64,
    budget_commit_index: Option<i64>,
}

impl StoredAdmissionEvent {
    fn matches(&self, request: &AdmissionCaptureRequest) -> Result<bool, BudgetStoreError> {
        let admission_operation =
            request
                .budget()
                .admission_operation
                .as_ref()
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "admission capture requires an admission operation binding".to_string(),
                    )
                })?;
        let revocation_ids_json =
            serde_json::to_string(request.revocation_set().ids()).map_err(|error| {
                BudgetStoreError::Invariant(format!("failed to encode revocation set: {error}"))
            })?;
        let artifact_digests_json = serde_json::to_string(request.authorization_artifact_digests())
            .map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "failed to encode authorization artifacts: {error}"
                ))
            })?;
        let last_observed = request
            .last_observed_revocation_index()
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    BudgetStoreError::Overflow(
                        "last-observed revocation index exceeds SQLite integer".to_string(),
                    )
                })
            })
            .transpose()?;
        Ok(
            self.request_binding_hash == admission_operation.request_binding_hash()
                && self.capture_event_id
                    == request.budget().event_id.as_deref().unwrap_or_default()
                && self.hold_id == request.budget().hold_id.as_deref().unwrap_or_default()
                && self.capability_id == request.budget().capability_id
                && nonnegative_usize(self.grant_index, "stored admission grant index")?
                    == request.budget().grant_index
                && self.authority.as_ref() == request.budget().authority.as_ref()
                && self.revocation_set_digest == request.bound_revocation_set_digest()
                && self.revocation_ids_json == revocation_ids_json
                && self.artifact_digests_json == artifact_digests_json
                && self.aggregate_root_capability_id.as_deref()
                    == request.aggregate_root_capability_id()
                && self.aggregate_root_binding_digest.as_deref()
                    == request.aggregate_root_binding_digest()
                && self.last_observed_revocation_index == last_observed,
        )
    }
}
