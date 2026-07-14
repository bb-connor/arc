use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionCommandResult, AdmissionIdentifier, AdmissionOperationCommand,
    AdmissionOperationError, AdmissionOperationId, AdmissionOperationState,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionProjectionCapabilities, AdmissionProjectionManifestV1, AdmissionProjectionRecordKind,
    AdmissionReplayClassification, AdmissionReplayKey, AdmissionTerminal,
    AdmissionTerminalProjection, AdmissionTerminalReplay, CanonicalAdmissionProjectionRecord,
    CanonicalAdmissionTerminalProjection, PersistedAdmissionOperationV1,
    QualifiedAdmissionOperationStore, UntrustedAdmissionRecoveryClaim,
};
use chio_kernel::receipt_store::{
    AuthorizationReceiptConsumption, PendingSettlementObservation, ReceiptStore, ReceiptStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod commit_chain;

use commit_chain::append_operation_commit;
pub(crate) use commit_chain::{
    load_admission_commit_head, verify_admission_commit_chain, verify_admission_commit_suffix,
    AdmissionCommitHead, GENESIS_CHAIN_DIGEST,
};

const ADMISSION_OPERATION_SCHEMA_KEY: &str = "admission_operation";
pub(crate) const ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION: i32 = 2;
const ADMISSION_OPERATION_SCHEMA_ANCHORS: &[&str] = &[
    "admission_operations",
    "chio_serving_owner",
    "capability_grant_budgets",
];
const MAX_PERSISTED_OPERATION_BYTES: usize = 256 * 1024;
const MAX_TERMINAL_PROJECTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_TERMINAL_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_TERMINAL_RECORD_BYTES: usize = 1024 * 1024;
const MAX_TERMINAL_RECORDS: usize = 32;
const MAX_RECOVERY_BATCH: usize = 256;
const MAX_TRUSTED_UNIX_MS: u64 = (1_u64 << 53) - 1;
const MAX_TRUSTED_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_RECOVERY_LEASE_DURATION_MS: u64 = 5 * 60 * 1_000;

const ADMISSION_OPERATION_SCHEMA: &str = include_str!("admission_operation_store.sql");

#[derive(Clone)]
pub struct SqliteAdmissionOperationStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteAdmissionOperationStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationStoreError> {
        self.connection.lock().map_err(|_| {
            AdmissionOperationStoreError::Invariant(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, fence)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn sync_after_write(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(map_owner_error)
    }

    fn commit_write(
        &self,
        transaction: Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        transaction.commit().map_err(|error| {
            map_owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite admission operation commit outcome is unknown: {error}"
            )))
        })
    }

    pub fn commit_terminal_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        let canonical = projection.canonical_projection()?;
        validate_canonical_projection_size(&canonical)?;
        let context = projection.context();
        context.validate()?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(&context.store_fence))?;
        verify_trusted_time(&transaction, context.trusted_time_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, &context.operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;

        if stored.operation.state().is_terminal() {
            let terminal = verify_exact_terminal_replay(
                &transaction,
                &stored.operation,
                projection,
                &canonical,
            )?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(terminal);
        }
        if context.request_id != stored.operation.replay_key().request_id
            || context.expected_operation_version != stored.operation.version()
            || context.coordinator_lease_epoch != stored.operation.coordinator_lease_epoch()
            || context.trusted_time_unix_ms < stored.updated_at_unix_ms
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        let recovery_claim = stored
            .recovery_claim
            .as_ref()
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        if recovery_claim.coordinator_lease_id() != &context.coordinator_lease_id
            || recovery_claim.coordinator_lease_epoch() != context.coordinator_lease_epoch
            || recovery_claim.store_fence() != &context.store_fence
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            recovery_claim,
            context.trusted_time_unix_ms,
            &context.store_fence,
        )?;
        ensure_projection_absent(&transaction, &context.operation_id)?;

        let capabilities = full_projection_capabilities();
        let updated = stored
            .operation
            .apply_terminal_projection(projection, &capabilities)?;
        if updated
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != canonical.projection_digest())
        {
            return Err(invariant(
                "terminal operation does not retain its exact projection digest",
            ));
        }
        let encoded = encode_operation(&updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = 1,
                    coordinator_lease_epoch = ?3, version = ?4,
                    updated_at_unix_ms = ?5
                WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
                "#,
                params![
                    &encoded,
                    state_name(updated.state()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "terminal_operation_version")?,
                    sqlite_i64(context.trusted_time_unix_ms, "trusted_now_unix_ms")?,
                    context.operation_id.as_str(),
                    sqlite_i64(stored.operation.version(), "expected_operation_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        insert_terminal_projection(&transaction, projection, &canonical, &updated)?;
        append_operation_commit(
            &transaction,
            &updated,
            &encoded,
            Some(recovery_claim),
            "compare_and_swap",
            &self.serving_owner,
            context.trusted_time_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        terminal_from_operation(&updated)
    }
}

fn full_projection_capabilities() -> AdmissionProjectionCapabilities {
    AdmissionProjectionCapabilities {
        operation_terminal: true,
        incident_terminal: true,
        tool_outcome: true,
        payment_terminal: true,
        authorization_consumption: true,
        outcome_eligibility: true,
        observation_attempt_zero: true,
        obligation: true,
        economic_mutation_terminal: true,
    }
}

fn validate_canonical_projection_size(
    projection: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    if projection.projection_bytes().is_empty()
        || projection.projection_bytes().len() > MAX_TERMINAL_PROJECTION_BYTES
        || projection.manifest_bytes().is_empty()
        || projection.manifest_bytes().len() > MAX_TERMINAL_MANIFEST_BYTES
        || projection.records().is_empty()
        || projection.records().len() > MAX_TERMINAL_RECORDS
        || projection.records().iter().any(|record| {
            record.canonical_bytes().is_empty()
                || record.canonical_bytes().len() > MAX_TERMINAL_RECORD_BYTES
        })
    {
        return Err(invariant("terminal projection exceeds its storage bounds"));
    }
    Ok(())
}

fn ensure_projection_absent(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<(), AdmissionOperationStoreError> {
    let present: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM admission_operation_terminal_projections
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_terminal_records
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_authorization_consumptions
                WHERE operation_id = ?1
                UNION ALL
                SELECT 1 FROM admission_operation_observer_attempts
                WHERE operation_id = ?1
            )
            "#,
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if present {
        return Err(invariant(
            "nonterminal admission operation has a partial terminal projection",
        ));
    }
    Ok(())
}

fn insert_terminal_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
    terminal_operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let context = projection.context();
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO admission_operation_terminal_projections (
                operation_id, source_operation_version, terminal_operation_version,
                terminal_state, projection_body_digest, projection_digest,
                projection_json, manifest_json, record_count, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                context.operation_id.as_str(),
                sqlite_i64(
                    context.expected_operation_version,
                    "source_operation_version"
                )?,
                sqlite_i64(terminal_operation.version(), "terminal_operation_version")?,
                state_name(terminal_operation.state()),
                canonical.manifest().projection_body_digest().as_str(),
                canonical.projection_digest().as_str(),
                canonical.projection_bytes(),
                canonical.manifest_bytes(),
                i64::try_from(canonical.records().len())
                    .map_err(|_| invariant("terminal record count overflow"))?,
                sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?,
                &context.store_fence.store_uuid,
                &context.store_fence.lease_id,
                sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "terminal projection did not insert exactly one row",
        ));
    }

    for record in canonical.records() {
        let commitment = record.commitment();
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admission_operation_terminal_records (
                    operation_id, record_kind, record_id, record_digest, record_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    context.operation_id.as_str(),
                    commitment.kind().as_str(),
                    commitment.record_id().as_str(),
                    commitment.record_digest().as_str(),
                    record.canonical_bytes(),
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "terminal projection record did not insert exactly one row",
            ));
        }
    }

    if let AdmissionTerminalProjection::Completed(completed) = projection {
        if let Some(authorization) = &completed.authorization {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::AuthorizationConsumption,
            )?;
            let consumption = authorization.consumption();
            let inserted = transaction
                .execute(
                    r#"
                    INSERT INTO admission_operation_authorization_consumptions (
                        operation_id, authorization_receipt_id, consumer_receipt_id,
                        request_id, session_id, tool_call_id, tenant_id,
                        parameter_hash, consumed_at_unix_ms, record_digest, record_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                    "#,
                    params![
                        context.operation_id.as_str(),
                        &consumption.authorization_receipt_id,
                        &consumption.consumer_receipt_id,
                        &consumption.request_id,
                        &consumption.session_id,
                        &consumption.tool_call_id,
                        consumption.tenant_id.as_deref(),
                        &consumption.parameter_hash,
                        sqlite_i64(consumption.consumed_at_unix_ms, "consumed_at_unix_ms")?,
                        record.commitment().record_digest().as_str(),
                        record.canonical_bytes(),
                    ],
                )
                .map_err(sqlite_error)?;
            if inserted != 1 {
                return Err(invariant(
                    "authorization consumption did not insert exactly one row",
                ));
            }
        }
        if let Some(observer) = &completed.observer_work {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::ObservationAttemptZero,
            )?;
            let inserted = transaction
                .execute(
                    r#"
                    INSERT INTO admission_operation_observer_attempts (
                        operation_id, receipt_id, work_state, attempts,
                        next_visible_at_unix_ms, row_version, last_error,
                        record_digest, record_json, created_at_unix_ms,
                        updated_at_unix_ms, store_uuid, store_lease_id,
                        store_owner_epoch
                    ) VALUES (?1, ?2, 'pending', 0, ?3, 0, NULL, ?4, ?5,
                              ?6, ?6, ?7, ?8, ?9)
                    "#,
                    params![
                        context.operation_id.as_str(),
                        &completed.receipt.receipt().id,
                        sqlite_i64(
                            observer.pending().next_visible_at_ms,
                            "observer_next_visible_at_unix_ms"
                        )?,
                        record.commitment().record_digest().as_str(),
                        record.canonical_bytes(),
                        sqlite_i64(context.trusted_time_unix_ms, "observer_created_at_unix_ms")?,
                        &context.store_fence.store_uuid,
                        &context.store_fence.lease_id,
                        sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?,
                    ],
                )
                .map_err(sqlite_error)?;
            if inserted != 1 {
                return Err(invariant(
                    "observer attempt zero did not insert exactly one row",
                ));
            }
        }
    }
    Ok(())
}

fn require_canonical_record(
    projection: &CanonicalAdmissionTerminalProjection,
    kind: AdmissionProjectionRecordKind,
) -> Result<&CanonicalAdmissionProjectionRecord, AdmissionOperationStoreError> {
    let mut matches = projection
        .records()
        .iter()
        .filter(|record| record.commitment().kind() == kind);
    let record = matches
        .next()
        .ok_or_else(|| invariant(format!("terminal projection lacks {}", kind.as_str())))?;
    if matches.next().is_some() {
        return Err(invariant(format!(
            "terminal projection repeats {}",
            kind.as_str()
        )));
    }
    Ok(record)
}

fn terminal_from_operation(
    operation: &AdmissionOperationV1,
) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
    if !operation.state().is_terminal() {
        return Err(invariant("admission operation is not terminal"));
    }
    let replay = operation
        .terminal_replay()
        .cloned()
        .ok_or_else(|| invariant("terminal admission operation lacks replay evidence"))?;
    Ok(AdmissionTerminal {
        operation_id: operation.binding().operation_id().clone(),
        state: operation.state(),
        replay,
    })
}

struct StoredTerminalProjection {
    source_operation_version: i64,
    terminal_operation_version: i64,
    terminal_state: String,
    projection_body_digest: String,
    projection_digest: String,
    projection_json: Vec<u8>,
    manifest_json: Vec<u8>,
    record_count: i64,
    committed_at_unix_ms: i64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: i64,
}

fn load_terminal_projection_tx(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredTerminalProjection>, AdmissionOperationStoreError> {
    connection
        .query_row(
            r#"
            SELECT source_operation_version, terminal_operation_version,
                   terminal_state, projection_body_digest, projection_digest,
                   projection_json, manifest_json, record_count,
                   committed_at_unix_ms, store_uuid, store_lease_id,
                   store_owner_epoch
            FROM admission_operation_terminal_projections
            WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            |row| {
                Ok(StoredTerminalProjection {
                    source_operation_version: row.get(0)?,
                    terminal_operation_version: row.get(1)?,
                    terminal_state: row.get(2)?,
                    projection_body_digest: row.get(3)?,
                    projection_digest: row.get(4)?,
                    projection_json: row.get(5)?,
                    manifest_json: row.get(6)?,
                    record_count: row.get(7)?,
                    committed_at_unix_ms: row.get(8)?,
                    store_uuid: row.get(9)?,
                    store_lease_id: row.get(10)?,
                    store_owner_epoch: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)
}

fn verify_exact_terminal_replay(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
    let context = projection.context();
    if context.operation_id != *operation.binding().operation_id()
        || context.request_id != operation.replay_key().request_id
        || context
            .expected_operation_version
            .checked_add(1)
            .is_none_or(|version| version != operation.version())
        || projected_terminal_state(projection) != operation.state()
        || operation
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != canonical.projection_digest())
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }

    let stored = load_terminal_projection_tx(transaction, operation.binding().operation_id())?
        .ok_or_else(|| invariant("terminal admission operation lacks its projection"))?;
    if stored.source_operation_version
        != sqlite_i64(
            context.expected_operation_version,
            "source_operation_version",
        )?
        || stored.terminal_operation_version
            != sqlite_i64(operation.version(), "terminal_operation_version")?
        || stored.terminal_state != state_name(operation.state())
        || stored.projection_body_digest != canonical.manifest().projection_body_digest().as_str()
        || stored.projection_digest != canonical.projection_digest().as_str()
        || stored.projection_json != canonical.projection_bytes()
        || stored.manifest_json != canonical.manifest_bytes()
        || stored.record_count
            != i64::try_from(canonical.records().len())
                .map_err(|_| invariant("terminal record count overflow"))?
        || stored.committed_at_unix_ms
            != sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?
        || stored.store_uuid != context.store_fence.store_uuid
        || stored.store_lease_id != context.store_fence.lease_id
        || stored.store_owner_epoch
            != sqlite_i64(context.store_fence.owner_epoch, "store_owner_epoch")?
    {
        return Err(invariant(
            "terminal admission operation projection differs from its replay",
        ));
    }
    verify_exact_terminal_records(transaction, &context.operation_id, canonical)?;
    verify_exact_typed_projection_rows(transaction, projection, canonical)?;
    terminal_from_operation(operation)
}

fn projected_terminal_state(projection: &AdmissionTerminalProjection) -> AdmissionOperationState {
    match projection {
        AdmissionTerminalProjection::Completed(_) => AdmissionOperationState::Completed,
        AdmissionTerminalProjection::CompensatedBeforeDispatch { .. } => {
            AdmissionOperationState::CompensatedBeforeDispatch
        }
        AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit { .. } => {
            AdmissionOperationState::NotAcceptedAfterDispatchCommit
        }
        AdmissionTerminalProjection::OutcomeUnknownAfterDispatch { .. } => {
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        }
        AdmissionTerminalProjection::EconomicMutationApplied { .. } => {
            AdmissionOperationState::EconomicMutationApplied
        }
        AdmissionTerminalProjection::EconomicMutationNotApplied { .. } => {
            AdmissionOperationState::EconomicMutationNotApplied
        }
    }
}

fn verify_exact_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            "#,
        )
        .map_err(sqlite_error)?;
    let stored = statement
        .query_map([operation_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if stored.len() != canonical.records().len()
        || stored
            .iter()
            .zip(canonical.records())
            .any(|(stored, expected)| {
                let commitment = expected.commitment();
                stored.0 != commitment.kind().as_str()
                    || stored.1 != commitment.record_id().as_str()
                    || stored.2 != commitment.record_digest().as_str()
                    || stored.3 != expected.canonical_bytes()
            })
    {
        return Err(invariant(
            "terminal projection records differ from their manifest",
        ));
    }
    Ok(())
}

fn verify_exact_typed_projection_rows(
    connection: &Connection,
    projection: &AdmissionTerminalProjection,
    canonical: &CanonicalAdmissionTerminalProjection,
) -> Result<(), AdmissionOperationStoreError> {
    let context = projection.context();
    let authorization = connection
        .query_row(
            r#"
            SELECT authorization_receipt_id, consumer_receipt_id, request_id,
                   session_id, tool_call_id, tenant_id, parameter_hash,
                   consumed_at_unix_ms, record_digest, record_json
            FROM admission_operation_authorization_consumptions
            WHERE operation_id = ?1
            "#,
            [context.operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let observer = connection
        .query_row(
            r#"
            SELECT receipt_id, work_state, attempts, next_visible_at_unix_ms,
                   row_version, last_error, record_digest, record_json,
                   created_at_unix_ms, updated_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_observer_attempts
            WHERE operation_id = ?1
            "#,
            [context.operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;

    let AdmissionTerminalProjection::Completed(completed) = projection else {
        if authorization.is_some() || observer.is_some() {
            return Err(invariant(
                "non-completed projection has completed-only sidecars",
            ));
        }
        return Ok(());
    };
    match (&completed.authorization, authorization) {
        (None, None) => {}
        (Some(expected), Some(stored)) => {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::AuthorizationConsumption,
            )?;
            let expected = expected.consumption();
            if stored.0 != expected.authorization_receipt_id
                || stored.1 != expected.consumer_receipt_id
                || stored.2 != expected.request_id
                || stored.3 != expected.session_id
                || stored.4 != expected.tool_call_id
                || stored.5 != expected.tenant_id
                || stored.6 != expected.parameter_hash
                || stored_u64(stored.7, "consumed_at_unix_ms")? != expected.consumed_at_unix_ms
                || stored.8 != record.commitment().record_digest().as_str()
                || stored.9 != record.canonical_bytes()
            {
                return Err(invariant(
                    "authorization consumption differs from terminal projection",
                ));
            }
        }
        _ => {
            return Err(invariant(
                "authorization consumption presence differs from terminal projection",
            ));
        }
    }
    match (&completed.observer_work, observer) {
        (None, None) => {}
        (Some(_), Some(stored)) => {
            let record = require_canonical_record(
                canonical,
                AdmissionProjectionRecordKind::ObservationAttemptZero,
            )?;
            let committed_at = sqlite_i64(context.trusted_time_unix_ms, "committed_at_unix_ms")?;
            if stored.0 != completed.receipt.receipt().id
                || stored.6 != record.commitment().record_digest().as_str()
                || stored.7 != record.canonical_bytes()
                || stored.8 != committed_at
                || stored.10 != context.store_fence.store_uuid
            {
                return Err(invariant(
                    "observer attempt zero differs from terminal projection",
                ));
            }
        }
        _ => {
            return Err(invariant(
                "observer attempt presence differs from terminal projection",
            ));
        }
    }
    Ok(())
}

struct StoredProjectionRecord {
    kind: String,
    record_id: String,
    record_digest: String,
    record_json: Vec<u8>,
}

fn load_terminal_records(
    connection: &Connection,
    operation_id: &AdmissionOperationId,
) -> Result<Vec<StoredProjectionRecord>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records
            WHERE operation_id = ?1
            ORDER BY record_kind, record_id
            "#,
        )
        .map_err(sqlite_error)?;
    let records = statement
        .query_map([operation_id.as_str()], |row| {
            Ok(StoredProjectionRecord {
                kind: row.get(0)?,
                record_id: row.get(1)?,
                record_digest: row.get(2)?,
                record_json: row.get(3)?,
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(records)
}

fn verify_stored_terminal_projection(
    connection: &Connection,
    stored_operation: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let operation = &stored_operation.operation;
    let projection = load_terminal_projection_tx(connection, operation.binding().operation_id())?;
    if !operation.state().is_terminal() {
        if projection.is_some() || projection_sidecar_count(connection, operation)? != 0 {
            return Err(invariant(
                "nonterminal admission operation has terminal projection rows",
            ));
        }
        return Ok(());
    }
    let projection = projection
        .ok_or_else(|| invariant("terminal admission operation lacks its projection row"))?;
    if projection.projection_json.is_empty()
        || projection.projection_json.len() > MAX_TERMINAL_PROJECTION_BYTES
        || projection.manifest_json.is_empty()
        || projection.manifest_json.len() > MAX_TERMINAL_MANIFEST_BYTES
    {
        return Err(invariant("stored terminal projection exceeds its bounds"));
    }
    let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(&projection.manifest_json)?;
    manifest.verify_projection_body(&projection.projection_json)?;
    let projection_digest = manifest.projection_digest()?;
    let replay_digest = operation
        .terminal_replay()
        .ok_or_else(|| invariant("terminal operation lacks replay evidence"))?
        .projection_digest();
    let source_version = operation
        .version()
        .checked_sub(1)
        .ok_or_else(|| invariant("terminal operation version underflow"))?;
    let exact_lease: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
            "#,
            params![
                &projection.store_uuid,
                projection.store_owner_epoch,
                &projection.store_lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if stored_u64(
        projection.source_operation_version,
        "source_operation_version",
    )? != source_version
        || stored_u64(
            projection.terminal_operation_version,
            "terminal_operation_version",
        )? != operation.version()
        || projection.terminal_state != state_name(operation.state())
        || projection.projection_body_digest != manifest.projection_body_digest().as_str()
        || projection.projection_digest != projection_digest.as_str()
        || replay_digest != &projection_digest
        || stored_u64(projection.record_count, "terminal_record_count")?
            != u64::try_from(manifest.records().len())
                .map_err(|_| invariant("terminal record count overflow"))?
        || stored_u64(
            projection.committed_at_unix_ms,
            "projection_committed_at_unix_ms",
        )? != stored_operation.updated_at_unix_ms
        || exact_lease != 1
    {
        return Err(invariant(
            "terminal projection does not match its admission operation",
        ));
    }

    let records = load_terminal_records(connection, operation.binding().operation_id())?;
    if records.len() != manifest.records().len() {
        return Err(invariant(
            "terminal projection record count differs from its manifest",
        ));
    }
    for (record, commitment) in records.iter().zip(manifest.records()) {
        let value: serde_json::Value = serde_json::from_slice(&record.record_json)
            .map_err(|error| invariant(format!("terminal record is invalid: {error}")))?;
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| invariant(format!("terminal record encoding failed: {error}")))?;
        if record.record_json.is_empty()
            || record.record_json.len() > MAX_TERMINAL_RECORD_BYTES
            || canonical != record.record_json
            || sha256_hex(&record.record_json) != record.record_digest
            || record.kind != commitment.kind().as_str()
            || record.record_id != commitment.record_id().as_str()
            || record.record_digest != commitment.record_digest().as_str()
        {
            return Err(invariant(
                "terminal projection record differs from its commitment",
            ));
        }
    }
    verify_stored_authorization_projection(connection, operation, &records)?;
    verify_stored_observer_projection(connection, operation, &projection, &records)?;
    Ok(())
}

fn projection_sidecar_count(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<i64, AdmissionOperationStoreError> {
    connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM admission_operation_terminal_records
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM admission_operation_authorization_consumptions
                 WHERE operation_id = ?1)
              + (SELECT COUNT(*) FROM admission_operation_observer_attempts
                 WHERE operation_id = ?1)
            "#,
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn projection_record(
    records: &[StoredProjectionRecord],
    kind: AdmissionProjectionRecordKind,
) -> Result<Option<&StoredProjectionRecord>, AdmissionOperationStoreError> {
    let mut matches = records.iter().filter(|record| record.kind == kind.as_str());
    let first = matches.next();
    if matches.next().is_some() {
        return Err(invariant(format!(
            "terminal projection repeats {}",
            kind.as_str()
        )));
    }
    Ok(first)
}

fn verify_stored_authorization_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    records: &[StoredProjectionRecord],
) -> Result<(), AdmissionOperationStoreError> {
    let record = projection_record(
        records,
        AdmissionProjectionRecordKind::AuthorizationConsumption,
    )?;
    let stored = connection
        .query_row(
            r#"
            SELECT authorization_receipt_id, consumer_receipt_id, request_id,
                   session_id, tool_call_id, tenant_id, parameter_hash,
                   consumed_at_unix_ms, record_digest, record_json
            FROM admission_operation_authorization_consumptions
            WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    match (record, stored) {
        (None, None) => Ok(()),
        (Some(record), Some(stored)) => {
            let consumption: AuthorizationReceiptConsumption =
                serde_json::from_slice(&record.record_json).map_err(|error| {
                    invariant(format!("authorization consumption is invalid: {error}"))
                })?;
            if stored.0 != consumption.authorization_receipt_id
                || stored.0 != record.record_id
                || stored.1 != consumption.consumer_receipt_id
                || stored.2 != consumption.request_id
                || stored.2 != operation.replay_key().request_id.as_str()
                || stored.3 != consumption.session_id
                || stored.4 != consumption.tool_call_id
                || stored.5 != consumption.tenant_id
                || stored.6 != consumption.parameter_hash
                || stored_u64(stored.7, "consumed_at_unix_ms")? != consumption.consumed_at_unix_ms
                || stored.8 != record.record_digest
                || stored.9 != record.record_json
            {
                return Err(invariant(
                    "authorization consumption projection is inconsistent",
                ));
            }
            Ok(())
        }
        _ => Err(invariant("authorization consumption projection is partial")),
    }
}

fn verify_stored_observer_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    projection: &StoredTerminalProjection,
    records: &[StoredProjectionRecord],
) -> Result<(), AdmissionOperationStoreError> {
    let record = projection_record(
        records,
        AdmissionProjectionRecordKind::ObservationAttemptZero,
    )?;
    let stored = connection
        .query_row(
            r#"
            SELECT receipt_id, work_state, attempts, next_visible_at_unix_ms,
                   row_version, last_error, record_digest, record_json,
                   created_at_unix_ms, updated_at_unix_ms, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_observer_attempts
            WHERE operation_id = ?1
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    match (record, stored) {
        (None, None) => Ok(()),
        (Some(record), Some(stored)) => {
            let pending: PendingSettlementObservation = serde_json::from_slice(&record.record_json)
                .map_err(|error| invariant(format!("observer attempt zero is invalid: {error}")))?;
            let lease_exists: i64 = connection
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM chio_serving_leases
                    WHERE store_uuid = ?1 AND lease_id = ?2 AND owner_epoch = ?3
                    "#,
                    params![&stored.10, &stored.11, stored.12],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let created_at = stored_u64(stored.8, "observer_created_at_unix_ms")?;
            let updated_at = stored_u64(stored.9, "observer_updated_at_unix_ms")?;
            let row_version = stored_u64(stored.4, "observer_row_version")?;
            if stored.0 != record.record_id
                || stored.6 != record.record_digest
                || stored.7 != record.record_json
                || created_at
                    != stored_u64(
                        projection.committed_at_unix_ms,
                        "projection_committed_at_unix_ms",
                    )?
                || updated_at < created_at
                || stored.10 != projection.store_uuid
                || lease_exists != 1
                || (row_version == 0
                    && (stored.1 != "pending"
                        || stored.2 != 0
                        || stored_u64(stored.3, "observer_next_visible_at_unix_ms")?
                            != pending.next_visible_at_ms
                        || stored.5.is_some()))
            {
                return Err(invariant("observer attempt projection is inconsistent"));
            }
            Ok(())
        }
        _ => Err(invariant("observer attempt projection is partial")),
    }
}

impl QualifiedAdmissionOperationStore for SqliteAdmissionOperationStore {}

impl ReceiptStore for SqliteAdmissionOperationStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "receipts must be committed through an admission terminal projection".to_string(),
        ))
    }

    fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities {
        full_projection_capabilities()
    }

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError> {
        self.commit_terminal_projection(projection)
            .map_err(receipt_projection_error)
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let receipt_id = AdmissionIdentifier::try_new("receipt_id", receipt_id.to_owned())
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let mut connection = self.connection().map_err(receipt_projection_error)?;
        let transaction = self
            .begin_read(&mut connection)
            .map_err(receipt_projection_error)?;
        let stored = transaction
            .query_row(
                r#"
                SELECT operation_id, record_json
                FROM admission_operation_terminal_records
                WHERE record_kind = 'receipt' AND record_id = ?1
                "#,
                [receipt_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let receipt = match stored {
            None => None,
            Some((operation_id, bytes)) => {
                let operation_id = AdmissionOperationId::from_persisted(operation_id)
                    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
                load_by_operation_id_tx(&transaction, &operation_id)
                    .map_err(receipt_projection_error)?
                    .ok_or_else(|| {
                        ReceiptStoreError::Conflict(
                            "admission receipt references a missing operation".to_string(),
                        )
                    })?;
                Some(decode_projection_receipt(bytes)?)
            }
        };
        transaction.commit()?;
        Ok(receipt)
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "child receipts are not admission terminal projections".to_string(),
        ))
    }
}

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        operation.validate()?;
        if operation.state() != AdmissionOperationState::Prepared || operation.version() != 1 {
            return Err(invariant("begin requires a version-one Prepared operation"));
        }
        if operation.coordinator_lease_epoch() != fence.owner_epoch {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(operation)?;
        let replay_key = operation.replay_key();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;

        if let Some(existing) = load_by_replay_key_tx(&transaction, &replay_key)? {
            let result = match existing.operation.classify_replay(operation) {
                AdmissionReplayClassification::Exact { terminal_replay } => {
                    AdmissionBeginResult::ExactReplay {
                        operation: existing.operation,
                        terminal_replay,
                    }
                }
                AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                    existing_operation_id: existing.operation.binding().operation_id().clone(),
                },
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }
        if load_by_operation_id_tx(&transaction, operation.binding().operation_id())?.is_some() {
            return Err(invariant(
                "operation id is already bound to a different replay key",
            ));
        }

        let changed = transaction
            .execute(
                r#"
                INSERT INTO admission_operations (
                    operation_id, request_namespace_digest, request_id,
                    operation_json, state, terminal, coordinator_lease_epoch,
                    version, created_at_unix_ms, updated_at_unix_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?8)
                "#,
                params![
                    operation.binding().operation_id().as_str(),
                    replay_key.request_namespace_digest.as_str(),
                    replay_key.request_id.as_str(),
                    encoded,
                    state_name(operation.state()),
                    sqlite_i64(
                        operation.coordinator_lease_epoch(),
                        "coordinator_lease_epoch"
                    )?,
                    sqlite_i64(operation.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "created_at_unix_ms")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("begin did not insert exactly one operation"));
        }
        append_operation_commit(
            &transaction,
            operation,
            &encoded,
            None,
            "begin",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionBeginResult::Created(operation.clone()))
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation =
            load_by_operation_id_tx(&transaction, operation_id)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation = load_by_replay_key_tx(&transaction, replay_key)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let fence = command.recovery_lease().store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            command.recovery_lease().untrusted_claim(),
            trusted_now_unix_ms,
            fence,
        )?;

        let result = stored
            .operation
            .apply_command(command, trusted_now_unix_ms)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        let encoded = encode_operation(&updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = ?3,
                    coordinator_lease_epoch = ?4, version = ?5,
                    updated_at_unix_ms = ?6
                WHERE operation_id = ?7 AND version = ?8
                "#,
                params![
                    encoded,
                    state_name(updated.state()),
                    i64::from(updated.state().is_terminal()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(stored.operation.version(), "expected_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        append_operation_commit(
            &transaction,
            &updated,
            &encoded,
            stored.recovery_claim.as_ref(),
            "compare_and_swap",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        validate_trusted_now(trusted_now_unix_ms, "trusted_now_unix_ms")?;
        validate_trusted_time(expires_at_unix_ms, "expires_at_unix_ms")?;
        if expected_version == 0 {
            return Err(AdmissionOperationError::ZeroVersionOrEpoch.into());
        }
        if trusted_now_unix_ms >= expires_at_unix_ms {
            return Err(AdmissionOperationError::LeaseExpired.into());
        }
        if expires_at_unix_ms - trusted_now_unix_ms > MAX_RECOVERY_LEASE_DURATION_MS {
            return Err(invariant("recovery lease exceeds its maximum duration"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation.state().is_terminal() {
            return Err(invariant("terminal operation cannot be recovery-claimed"));
        }
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        if stored.operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: stored.operation.version(),
            }
            .into());
        }

        let coordinator_lease_id = coordinator_lease_id_for_epoch(
            &transaction,
            &self.serving_owner,
            stored.operation.coordinator_lease_epoch(),
        )?;
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            coordinator_lease_id,
            stored.operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        if let Some(active) = stored
            .recovery_claim
            .as_ref()
            .filter(|active| active.expires_at_unix_ms() > trusted_now_unix_ms)
        {
            if active.store_fence() == fence {
                let same_claimant = active.claimant_id() == claimant_id
                    && active.coordinator_lease_id() == claim.coordinator_lease_id()
                    && active.coordinator_lease_epoch() == claim.coordinator_lease_epoch();
                if same_claimant && active.claimed_version() == expected_version {
                    let active = active.clone();
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(active);
                }
                if !same_claimant || active.claimed_version() >= expected_version {
                    return Err(AdmissionOperationStoreError::Fenced);
                }
            }
        }

        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET recovery_claimant_id = ?1,
                    recovery_coordinator_lease_id = ?2,
                    recovery_coordinator_lease_epoch = ?3,
                    recovery_claimed_version = ?4,
                    recovery_expires_at_unix_ms = ?5,
                    recovery_store_uuid = ?6,
                    recovery_store_lease_id = ?7,
                    recovery_store_owner_epoch = ?8,
                    updated_at_unix_ms = ?9
                WHERE operation_id = ?10 AND version = ?4 AND terminal = 0
                "#,
                params![
                    claimant_id.as_str(),
                    claim.coordinator_lease_id().as_str(),
                    sqlite_i64(claim.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(expected_version, "claimed_version")?,
                    sqlite_i64(expires_at_unix_ms, "expires_at_unix_ms")?,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    operation_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(&stored.operation)?;
        append_operation_commit(
            &transaction,
            &stored.operation,
            &encoded,
            Some(&claim),
            "recovery_claim",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(current_store_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, claim.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation != *operation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        if limit > MAX_RECOVERY_BATCH {
            return Err(invariant("recovery batch limit exceeds 256"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT operation_id, request_namespace_digest, request_id,
                       operation_json, state, terminal, coordinator_lease_epoch,
                       version, created_at_unix_ms, updated_at_unix_ms,
                       recovery_claimant_id, recovery_coordinator_lease_id,
                       recovery_coordinator_lease_epoch, recovery_claimed_version,
                       recovery_expires_at_unix_ms, recovery_store_uuid,
                       recovery_store_lease_id, recovery_store_owner_epoch
                FROM admission_operations
                WHERE terminal = 0
                  AND (recovery_expires_at_unix_ms IS NULL
                       OR recovery_expires_at_unix_ms <= ?1
                       OR recovery_store_uuid <> ?2
                       OR recovery_store_lease_id <> ?3
                       OR recovery_store_owner_epoch <> ?4)
                ORDER BY updated_at_unix_ms, operation_id
                LIMIT ?5
                "#,
            )
            .map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                sqlite_i64(not_after_unix_ms, "not_after_unix_ms")?,
                &self.serving_owner.fence.store_uuid,
                &self.serving_owner.fence.lease_id,
                sqlite_i64(self.serving_owner.fence.owner_epoch, "store_owner_epoch")?,
                i64::try_from(limit).map_err(|_| invariant("recovery limit overflow"))?,
            ])
            .map_err(sqlite_error)?;
        let mut operations = Vec::with_capacity(limit);
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
            verify_latest_commit(&transaction, &stored)?;
            operations.push(stored.operation);
        }
        drop(rows);
        drop(statement);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operations)
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let replay = load_by_replay_key_tx(&transaction, replay_key)?
            .and_then(|stored| stored.operation.terminal_replay().cloned());
        transaction.commit().map_err(sqlite_error)?;
        Ok(replay)
    }
}

pub(crate) fn initialize_admission_operation_schema(
    connection: &mut Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION {
        return verify_admission_operation_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_admission_operation_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_admission_operation_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    if admission_operation_schema_catalog(connection)?
        != admission_operation_schema_catalog(&expected)?
    {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }

    let (head, high_water, commit_count, max_commit, max_recorded_at): (i64, i64, i64, i64, i64) =
        connection
            .query_row(
                r#"
            SELECT
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_operation_commits),
                (SELECT COALESCE(MAX(commit_sequence), 0)
                 FROM admission_operation_commits),
                (SELECT COALESCE(MAX(recorded_at_unix_ms), 0)
                 FROM admission_operation_commits)
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
    let serving_leases_exist: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'chio_serving_leases'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let invalid_lease = if serving_leases_exist {
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM admission_operation_commits AS committed
                    WHERE NOT EXISTS (
                        SELECT 1 FROM chio_serving_leases AS lease
                        WHERE lease.store_uuid = committed.store_uuid
                          AND lease.owner_epoch = committed.store_owner_epoch
                          AND lease.lease_id = committed.store_lease_id
                    )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?
    } else {
        commit_count != 0
    };
    if head < 0
        || high_water < 0
        || u64::try_from(high_water).map_or(true, |value| value > MAX_TRUSTED_UNIX_MS)
        || high_water != max_recorded_at
        || (head == 0) != (high_water == 0)
        || commit_count != head
        || max_commit != head
        || invalid_lease
    {
        return Err(invariant(
            "admission operation commit log is not a dense fenced sequence",
        ));
    }
    let invalid_commit_order: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT mutation_kind, operation_version, recorded_at_unix_ms,
                           LAG(operation_version) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_version,
                           LAG(recorded_at_unix_ms) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE (previous_version IS NULL
                       AND (mutation_kind <> 'begin' OR operation_version <> 1))
                   OR (previous_version IS NOT NULL
                       AND (mutation_kind = 'begin'
                            OR (mutation_kind = 'recovery_claim'
                                AND operation_version <> previous_version)
                            OR (mutation_kind = 'compare_and_swap'
                                AND operation_version <> previous_version + 1)
                            OR recorded_at_unix_ms < previous_time))
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid_commit_order {
        return Err(invariant(
            "admission operation commits regress version or trusted time",
        ));
    }
    let global_time_regression: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT recorded_at_unix_ms,
                           LAG(recorded_at_unix_ms) OVER (
                               ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE previous_time IS NOT NULL
                  AND recorded_at_unix_ms < previous_time
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if global_time_regression {
        return Err(invariant(
            "admission operation trusted time regresses across commits",
        ));
    }
    verify_admission_commit_chain(connection)?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        verify_latest_commit(connection, &stored)?;
        verify_stored_terminal_projection(connection, &stored)?;
    }
    Ok(())
}

fn verify_trusted_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_now(trusted_now_unix_ms, "trusted_now_unix_ms")?;
    let high_water: i64 = transaction
        .query_row(
            r#"
            SELECT trusted_time_high_water_unix_ms
            FROM admission_operation_commit_meta WHERE singleton = 1
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")? < high_water {
        return Err(invariant("trusted admission operation time regressed"));
    }
    Ok(())
}

fn validate_trusted_now(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_time(value, field)?;
    let system_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invariant("system clock precedes the Unix epoch"))?
        .as_millis();
    let system_now = u64::try_from(system_now)
        .map_err(|_| invariant("system clock exceeds the persisted trusted-time range"))?;
    if value.abs_diff(system_now) > MAX_TRUSTED_CLOCK_SKEW_MS {
        return Err(invariant(format!(
            "{field} exceeds the permitted system-clock skew"
        )));
    }
    Ok(())
}

fn validate_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    if value == 0 || value > MAX_TRUSTED_UNIX_MS {
        return Err(invariant(format!(
            "{field} is outside the persisted trusted-time range"
        )));
    }
    Ok(())
}

fn verify_latest_commit(
    connection: &Connection,
    stored: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let latest = connection
        .query_row(
            r#"
            SELECT operation_version, operation_digest, recovery_claim_digest,
                   recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence DESC
            LIMIT 1
            "#,
            [stored.operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("admission operation has no commit record"))?;
    let encoded = encode_operation(&stored.operation)?;
    let claim_digest = stored
        .recovery_claim
        .as_ref()
        .map(recovery_claim_digest)
        .transpose()?;
    if stored_u64(latest.0, "commit operation_version")? != stored.operation.version()
        || latest.1 != sha256_hex(&encoded)
        || latest.2 != claim_digest
        || stored_u64(latest.3, "commit recorded_at_unix_ms")? != stored.updated_at_unix_ms
    {
        return Err(invariant(
            "latest admission operation commit does not match its projection",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn admission_operation_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'admission_operation*'
               OR tbl_name GLOB 'admission_operation*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn recovery_claim_digest(
    claim: &UntrustedAdmissionRecoveryClaim,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct ClaimDigestBody<'a> {
        operation_id: &'a str,
        claimant_id: &'a str,
        coordinator_lease_id: &'a str,
        coordinator_lease_epoch: u64,
        claimed_version: u64,
        expires_at_unix_ms: u64,
        store_uuid: &'a str,
        store_lease_id: &'a str,
        store_owner_epoch: u64,
    }

    let body = ClaimDigestBody {
        operation_id: claim.operation_id().as_str(),
        claimant_id: claim.claimant_id().as_str(),
        coordinator_lease_id: claim.coordinator_lease_id().as_str(),
        coordinator_lease_epoch: claim.coordinator_lease_epoch(),
        claimed_version: claim.claimed_version(),
        expires_at_unix_ms: claim.expires_at_unix_ms(),
        store_uuid: &claim.store_fence().store_uuid,
        store_lease_id: &claim.store_fence().lease_id,
        store_owner_epoch: claim.store_fence().owner_epoch,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| invariant(format!("recovery claim encoding failed: {error}")))?;
    Ok(sha256_hex(&canonical))
}

fn verify_active_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    requested: Option<&StoreMutationFence>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::serving_owner::verify_budget_fence(transaction, Some(owner)).map_err(|error| {
        if matches!(error, chio_kernel::BudgetStoreError::Fenced { .. }) {
            AdmissionOperationStoreError::Fenced
        } else {
            AdmissionOperationStoreError::Unavailable(error.to_string())
        }
    })?;
    if requested.is_some_and(|fence| fence != &owner.fence) {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let active_lease: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
              AND end_head_index IS NULL
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                &owner.fence.lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active_lease != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

fn coordinator_lease_id_for_epoch(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    coordinator_lease_epoch: u64,
) -> Result<AdmissionIdentifier, AdmissionOperationStoreError> {
    let lease_id = transaction
        .query_row(
            r#"
            SELECT lease_id
            FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(coordinator_lease_epoch, "coordinator_lease_epoch")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("operation coordinator lease is absent from lease history"))?;
    AdmissionIdentifier::try_new("coordinator_lease_id", lease_id).map_err(Into::into)
}

fn verify_stored_recovery_claim(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    stored: &StoredOperation,
    claim: &UntrustedAdmissionRecoveryClaim,
    trusted_now_unix_ms: u64,
    current_store_fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(invariant("trusted operation time regressed"));
    }
    if trusted_now_unix_ms >= claim.expires_at_unix_ms() {
        return Err(AdmissionOperationError::LeaseExpired.into());
    }
    if stored.recovery_claim.as_ref() != Some(claim)
        || stored.operation.binding().operation_id() != claim.operation_id()
        || stored.operation.version() != claim.claimed_version()
        || stored.operation.coordinator_lease_epoch() != claim.coordinator_lease_epoch()
        || claim.store_fence() != current_store_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let historical_lease_id = coordinator_lease_id_for_epoch(
        transaction,
        owner,
        stored.operation.coordinator_lease_epoch(),
    )?;
    if &historical_lease_id != claim.coordinator_lease_id() {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

struct StoredOperation {
    operation: AdmissionOperationV1,
    recovery_claim: Option<UntrustedAdmissionRecoveryClaim>,
    updated_at_unix_ms: u64,
}

struct RawOperationRow {
    operation_id: String,
    request_namespace_digest: String,
    request_id: String,
    operation_json: Vec<u8>,
    state: String,
    terminal: i64,
    coordinator_lease_epoch: i64,
    version: i64,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    recovery_claimant_id: Option<String>,
    recovery_coordinator_lease_id: Option<String>,
    recovery_coordinator_lease_epoch: Option<i64>,
    recovery_claimed_version: Option<i64>,
    recovery_expires_at_unix_ms: Option<i64>,
    recovery_store_uuid: Option<String>,
    recovery_store_lease_id: Option<String>,
    recovery_store_owner_epoch: Option<i64>,
}

fn read_raw_row(row: &Row<'_>) -> rusqlite::Result<RawOperationRow> {
    Ok(RawOperationRow {
        operation_id: row.get(0)?,
        request_namespace_digest: row.get(1)?,
        request_id: row.get(2)?,
        operation_json: row.get(3)?,
        state: row.get(4)?,
        terminal: row.get(5)?,
        coordinator_lease_epoch: row.get(6)?,
        version: row.get(7)?,
        created_at_unix_ms: row.get(8)?,
        updated_at_unix_ms: row.get(9)?,
        recovery_claimant_id: row.get(10)?,
        recovery_coordinator_lease_id: row.get(11)?,
        recovery_coordinator_lease_epoch: row.get(12)?,
        recovery_claimed_version: row.get(13)?,
        recovery_expires_at_unix_ms: row.get(14)?,
        recovery_store_uuid: row.get(15)?,
        recovery_store_lease_id: row.get(16)?,
        recovery_store_owner_epoch: row.get(17)?,
    })
}

fn decode_row(raw: RawOperationRow) -> Result<StoredOperation, AdmissionOperationStoreError> {
    if raw.operation_json.is_empty() || raw.operation_json.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant("persisted admission operation size is invalid"));
    }
    let persisted: PersistedAdmissionOperationV1 = serde_json::from_slice(&raw.operation_json)
        .map_err(|error| invariant(format!("persisted admission operation is invalid: {error}")))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)?;
    let canonical = encode_operation(&operation)?;
    if canonical != raw.operation_json {
        return Err(invariant(
            "persisted admission operation encoding is not canonical",
        ));
    }
    let replay_key = operation.replay_key();
    if operation.binding().operation_id().as_str() != raw.operation_id
        || replay_key.request_namespace_digest.as_str() != raw.request_namespace_digest
        || replay_key.request_id.as_str() != raw.request_id
        || state_name(operation.state()) != raw.state
        || i64::from(operation.state().is_terminal()) != raw.terminal
        || operation.coordinator_lease_epoch()
            != stored_u64(raw.coordinator_lease_epoch, "coordinator_lease_epoch")?
        || operation.version() != stored_u64(raw.version, "version")?
    {
        return Err(invariant(
            "admission operation columns do not match the checked record",
        ));
    }
    let created_at = stored_u64(raw.created_at_unix_ms, "created_at_unix_ms")?;
    let updated_at = stored_u64(raw.updated_at_unix_ms, "updated_at_unix_ms")?;
    validate_trusted_time(created_at, "created_at_unix_ms")?;
    validate_trusted_time(updated_at, "updated_at_unix_ms")?;
    if updated_at < created_at {
        return Err(invariant("admission operation timestamp regressed"));
    }

    let recovery_claim = match (
        raw.recovery_claimant_id,
        raw.recovery_coordinator_lease_id,
        raw.recovery_coordinator_lease_epoch,
        raw.recovery_claimed_version,
        raw.recovery_expires_at_unix_ms,
        raw.recovery_store_uuid,
        raw.recovery_store_lease_id,
        raw.recovery_store_owner_epoch,
    ) {
        (None, None, None, None, None, None, None, None) => None,
        (
            Some(claimant_id),
            Some(coordinator_lease_id),
            Some(coordinator_lease_epoch),
            Some(claimed_version),
            Some(expires_at_unix_ms),
            Some(store_uuid),
            Some(store_lease_id),
            Some(store_owner_epoch),
        ) => {
            let claimed_version = stored_u64(claimed_version, "recovery_claimed_version")?;
            if claimed_version > operation.version()
                || claimed_version
                    .checked_add(1)
                    .is_some_and(|next| next < operation.version())
            {
                return Err(invariant(
                    "recovery claim is not for the current or immediately preceding version",
                ));
            }
            let expires_at_unix_ms = stored_u64(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            validate_trusted_time(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            Some(UntrustedAdmissionRecoveryClaim::new(
                operation.binding().operation_id().clone(),
                AdmissionIdentifier::try_new("recovery_claimant_id", claimant_id)?,
                AdmissionIdentifier::try_new(
                    "recovery_coordinator_lease_id",
                    coordinator_lease_id,
                )?,
                stored_u64(coordinator_lease_epoch, "recovery_coordinator_lease_epoch")?,
                claimed_version,
                expires_at_unix_ms,
                StoreMutationFence {
                    store_uuid,
                    lease_id: store_lease_id,
                    owner_epoch: stored_u64(store_owner_epoch, "recovery_store_owner_epoch")?,
                },
            )?)
        }
        _ => return Err(invariant("recovery claim tuple is partial")),
    };
    Ok(StoredOperation {
        operation,
        recovery_claim,
        updated_at_unix_ms: updated_at,
    })
}

fn load_by_operation_id_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
        verify_stored_terminal_projection(transaction, stored)?;
    }
    Ok(stored)
}

fn load_by_replay_key_tx(
    transaction: &Transaction<'_>,
    replay_key: &AdmissionReplayKey,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            WHERE request_namespace_digest = ?1 AND request_id = ?2
            "#,
            params![
                replay_key.request_namespace_digest.as_str(),
                replay_key.request_id.as_str(),
            ],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
        verify_stored_terminal_projection(transaction, stored)?;
    }
    Ok(stored)
}

fn encode_operation(
    operation: &AdmissionOperationV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    operation.validate()?;
    let encoded = canonical_json_bytes(&operation.to_persisted())
        .map_err(|error| invariant(format!("admission operation encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant(
            "persisted admission operation exceeds its size limit",
        ));
    }
    Ok(encoded)
}

fn state_name(state: AdmissionOperationState) -> &'static str {
    match state {
        AdmissionOperationState::Prepared => "prepared",
        AdmissionOperationState::BrokerAttemptRegistered => "broker_attempt_registered",
        AdmissionOperationState::BudgetAuthorized => "budget_authorized",
        AdmissionOperationState::ApprovalReserved => "approval_reserved",
        AdmissionOperationState::ReadyToDispatch => "ready_to_dispatch",
        AdmissionOperationState::CapturePending => "capture_pending",
        AdmissionOperationState::DispatchCommitted => "dispatch_committed",
        AdmissionOperationState::Finalizing => "finalizing",
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            "not_accepted_after_dispatch_commit"
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        AdmissionOperationState::MutationReady => "mutation_ready",
        AdmissionOperationState::MutationSubmitted => "mutation_submitted",
        AdmissionOperationState::EconomicMutationApplied => "economic_mutation_applied",
        AdmissionOperationState::EconomicMutationNotApplied => "economic_mutation_not_applied",
    }
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, AdmissionOperationStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, AdmissionOperationStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn invariant(detail: impl Into<String>) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.into())
}

fn receipt_projection_error(error: AdmissionOperationStoreError) -> ReceiptStoreError {
    match error {
        AdmissionOperationStoreError::Unavailable(detail) => ReceiptStoreError::Pool(detail),
        AdmissionOperationStoreError::Fenced => ReceiptStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => {
            ReceiptStoreError::NotFound("admission operation".to_string())
        }
        AdmissionOperationStoreError::Invariant(detail) => ReceiptStoreError::Conflict(detail),
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            ReceiptStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Operation(error) => {
            ReceiptStoreError::Conflict(error.to_string())
        }
    }
}

fn decode_projection_receipt(bytes: Vec<u8>) -> Result<ChioReceipt, ReceiptStoreError> {
    let receipt: ChioReceipt = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
        != bytes
        || !receipt
            .verify_signature()
            .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))?
    {
        return Err(ReceiptStoreError::Conflict(
            "persisted admission receipt is invalid".to_string(),
        ));
    }
    Ok(receipt)
}

fn map_owner_error(error: SqliteServingOwnerError) -> AdmissionOperationStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionOperationStoreError::OutcomeUnknown(detail)
        }
        error => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => AdmissionOperationStoreError::Unavailable(other.to_string()),
    }
}

impl From<AdmissionOperationStoreError> for SqliteServingOwnerError {
    fn from(error: AdmissionOperationStoreError) -> Self {
        Self::Invalid(error.to_string())
    }
}

#[cfg(test)]
#[path = "admission_operation_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
