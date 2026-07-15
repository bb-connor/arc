use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult,
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationError,
    AdmissionOperationId, AdmissionOperationState, AdmissionOperationStore,
    AdmissionOperationStoreError, AdmissionOperationV1, AdmissionProjectionCapabilities,
    AdmissionProjectionManifestV1, AdmissionProjectionRecordKind, AdmissionRecoveryLease,
    AdmissionReplayClassification, AdmissionReplayKey, AdmissionTerminal,
    AdmissionTerminalProjection, AdmissionTerminalReplay, CanonicalAdmissionProjectionRecord,
    CanonicalAdmissionTerminalProjection, PersistedAdmissionOperationV1,
    QualifiedAdmissionOperationStore, SignedAdmissionTerminalProjectionV1,
    UntrustedAdmissionRecoveryClaim, VerifiedAdmissionTerminalProjectionRecordV1,
    VerifiedAdmissionTerminalProjectionV1,
};
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetReconcileHoldRequest, BudgetStoreError,
};
use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalTransition};
use chio_kernel::receipt_store::{
    AdmissionPaymentJournalAdvance, AdmissionPaymentJournalError, AdmissionPaymentSettlement,
    AdmissionPaymentSettlementBegin, AuthorizationReceiptConsumption, PendingSettlementObservation,
    ReceiptStore, ReceiptStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod commit_chain;
mod projection;

use commit_chain::append_operation_commit;
pub(crate) use commit_chain::{
    load_admission_commit_head, verify_admission_commit_chain, verify_admission_commit_suffix,
    AdmissionCommitHead, GENESIS_CHAIN_DIGEST,
};
use projection::{
    ensure_projection_absent, full_projection_capabilities, insert_terminal_projection,
    insert_verified_terminal_projection, terminal_from_operation,
    validate_canonical_projection_size, verify_exact_signed_terminal_replay,
    verify_exact_terminal_replay, verify_stored_terminal_projection,
};

const ADMISSION_OPERATION_SCHEMA_KEY: &str = "admission_operation";
pub(crate) const ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION: i32 = 3;
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
const COMBINED_CAPTURE_OPERATION_MUTATION_KIND: &str = "compare_and_swap";

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

    pub fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (
            chio_kernel::budget_store::BudgetInvocationCaptureDecision,
            AdmissionOperationV1,
        ),
        AdmissionCaptureError,
    > {
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().capability_id().as_str() != request.capability_id
            || operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != request.hold_id)
        {
            return Err(AdmissionCaptureError::Fenced);
        }
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        budget
            .capture_composite_invocation_and_commit_dispatch(
                request,
                crate::budget_store::AdmissionCaptureBinding {
                    operation,
                    recovery_lease,
                    trusted_now_unix_ms,
                },
            )
            .map_err(map_budget_capture_error)
    }

    pub fn authorize_budget_and_commit_admission(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetAuthorizeHoldRequest,
        payment_journal: Option<PaymentJournalRecord>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(BudgetAuthorizeHoldDecision, AdmissionOperationV1), AdmissionCaptureError> {
        if active_fence != &self.serving_owner.fence || recovery_lease.store_fence() != active_fence
        {
            return Err(AdmissionCaptureError::Fenced);
        }
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        budget
            .authorize_composite_hold_and_commit_admission(
                request,
                crate::budget_store::AdmissionAuthorizationBinding {
                    operation,
                    recovery_lease,
                    payment_journal: payment_journal.as_ref(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(map_budget_capture_error)
    }

    pub fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &StoreMutationFence,
    ) -> Result<Option<PaymentJournalRecord>, AdmissionPaymentJournalError> {
        if active_fence != &self.serving_owner.fence {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_read(&mut connection)
            .map_err(map_payment_operation_error)?;
        let journal = crate::budget_store::load_payment_journal(&transaction, operation_id)
            .map_err(map_payment_budget_error)?;
        transaction
            .commit()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        Ok(journal)
    }

    pub fn advance_payment_journal(
        &self,
        advance: AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<PaymentJournalRecord, AdmissionPaymentJournalError> {
        let AdmissionPaymentJournalAdvance {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            active_fence,
            trusted_now_unix_ms,
        } = advance;
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_write(&mut connection, Some(active_fence))
            .map_err(map_payment_operation_error)?;
        verify_payment_write_context(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            active_fence,
            trusted_now_unix_ms,
        )?;
        let (updated, changed) = crate::budget_store::advance_payment_journal(
            &transaction,
            expected,
            transition,
            release_evidence,
            trusted_now_unix_ms,
        )
        .map_err(map_payment_budget_error)?;
        if changed {
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "payment_journal_transition",
                    "payment",
                    &updated.operation_id,
                    updated.journal_version,
                )
                .map_err(map_payment_owner_error)?;
        }
        self.commit_write(transaction)
            .map_err(map_payment_operation_error)?;
        if changed {
            self.sync_after_write(&connection)
                .map_err(map_payment_operation_error)?;
        }
        Ok(updated)
    }

    pub fn begin_payment_settlement(
        &self,
        begin: AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<AdmissionPaymentSettlement, AdmissionPaymentJournalError> {
        let AdmissionPaymentSettlementBegin {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            budget_reconcile,
            active_fence,
            trusted_now_unix_ms,
        } = begin;
        if active_fence != &self.serving_owner.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        validate_payment_reconcile_binding(expected, transition, &budget_reconcile)?;
        let mut connection = self.connection().map_err(map_payment_operation_error)?;
        let transaction = self
            .begin_write(&mut connection, Some(active_fence))
            .map_err(map_payment_operation_error)?;
        verify_payment_write_context(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            active_fence,
            trusted_now_unix_ms,
        )?;
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        let (budget, budget_changed) = budget
            .reconcile_composite_hold_in_transaction(&transaction, &budget_reconcile)
            .map_err(map_payment_budget_error)?;
        let (journal, payment_changed) = match transition {
            Some(transition) => crate::budget_store::advance_payment_journal(
                &transaction,
                expected,
                transition,
                release_evidence,
                trusted_now_unix_ms,
            )
            .map_err(map_payment_budget_error)?,
            None => {
                if release_evidence.is_some() {
                    return Err(AdmissionPaymentJournalError::Invariant(
                        "payment release evidence requires a journal transition".to_owned(),
                    ));
                }
                let stored = crate::budget_store::load_payment_journal(
                    &transaction,
                    operation.binding().operation_id().as_str(),
                )
                .map_err(map_payment_budget_error)?
                .ok_or_else(|| {
                    AdmissionPaymentJournalError::Invariant(
                        "payment settlement journal is absent".to_owned(),
                    )
                })?;
                if stored != *expected {
                    return Err(AdmissionPaymentJournalError::Conflict(
                        "payment settlement journal changed".to_owned(),
                    ));
                }
                (stored, false)
            }
        };
        if payment_changed {
            self.serving_owner
                .append_global_commit(
                    &transaction,
                    "payment_settlement_intent",
                    "payment",
                    &journal.operation_id,
                    journal.journal_version,
                )
                .map_err(map_payment_owner_error)?;
        }
        self.commit_write(transaction)
            .map_err(map_payment_operation_error)?;
        if budget_changed || payment_changed {
            self.sync_after_write(&connection)
                .map_err(map_payment_operation_error)?;
        }
        Ok(AdmissionPaymentSettlement {
            journal,
            budget,
            budget_already_reconciled: !budget_changed,
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
        verify_payment_terminal_source(
            &transaction,
            &stored.operation,
            context,
            canonical.records().iter().filter_map(|record| {
                (record.commitment().kind() == AdmissionProjectionRecordKind::PaymentTerminal)
                    .then_some(record.canonical_bytes())
            }),
        )?;

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

    pub fn commit_signed_terminal_projection(
        &self,
        envelope: &SignedAdmissionTerminalProjectionV1,
    ) -> Result<AdmissionTerminal, AdmissionOperationStoreError> {
        let verified = envelope.verify()?;
        let context = verified.context();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(&context.store_fence))?;
        verify_trusted_time(&transaction, context.trusted_time_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, &context.operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        verify_payment_terminal_source(
            &transaction,
            &stored.operation,
            context,
            verified.records().iter().filter_map(|record| {
                (record.kind() == AdmissionProjectionRecordKind::PaymentTerminal)
                    .then_some(record.canonical_json())
            }),
        )?;

        if stored.operation.state().is_terminal() {
            let terminal = verify_exact_signed_terminal_replay(&transaction, &stored, &verified)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(terminal);
        }
        if stored.operation != *verified.source_operation()
            || context.trusted_time_unix_ms < stored.updated_at_unix_ms
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        let recovery_claim = stored
            .recovery_claim
            .as_ref()
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        let expected_claimant = format!("kernel:{}", verified.signer_key().to_hex());
        if recovery_claim.claimant_id().as_str() != expected_claimant
            || recovery_claim.coordinator_lease_id() != &context.coordinator_lease_id
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

        let updated = verified.terminal_operation();
        let encoded = encode_operation(updated)?;
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
        insert_verified_terminal_projection(&transaction, &verified)?;
        append_operation_commit(
            &transaction,
            updated,
            &encoded,
            Some(recovery_claim),
            "compare_and_swap",
            &self.serving_owner,
            context.trusted_time_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        terminal_from_operation(updated)
    }
}

fn verify_payment_write_context(
    transaction: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionPaymentJournalError> {
    let stored = load_by_operation_id_tx(transaction, operation.binding().operation_id())
        .map_err(map_payment_operation_error)?
        .ok_or_else(|| {
            AdmissionPaymentJournalError::Invariant(
                "payment journal admission operation is absent".to_owned(),
            )
        })?;
    if stored.operation != *operation {
        return Err(AdmissionPaymentJournalError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        serving_owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        active_fence,
    )
    .map_err(map_payment_operation_error)
}

fn validate_payment_reconcile_binding(
    journal: &PaymentJournalRecord,
    transition: Option<&PaymentJournalTransition>,
    budget: &BudgetReconcileHoldRequest,
) -> Result<(), AdmissionPaymentJournalError> {
    journal
        .validate()
        .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
    budget
        .validate()
        .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
    let grant_index = usize::try_from(journal.grant_index).map_err(|_| {
        AdmissionPaymentJournalError::Invariant(
            "payment journal grant index exceeds the budget range".to_owned(),
        )
    })?;
    let hold_id = journal.hold_id.as_deref().ok_or_else(|| {
        AdmissionPaymentJournalError::Invariant("payment journal omitted hold_id".to_owned())
    })?;
    if budget.capability_id != journal.capability_id
        || budget.grant_index != grant_index
        || budget.exposed_cost_units != journal.amount_units
        || budget.hold_id.as_deref() != Some(hold_id)
        || budget.event_id.as_deref() != Some(format!("{hold_id}:reconcile").as_str())
    {
        return Err(AdmissionPaymentJournalError::Invariant(
            "budget reconciliation does not match the payment journal".to_owned(),
        ));
    }
    let realized_units = match transition {
        Some(PaymentJournalTransition::BeginCapture { amount_units }) => *amount_units,
        Some(PaymentJournalTransition::BeginRelease { .. }) => 0,
        Some(_) => {
            return Err(AdmissionPaymentJournalError::Invariant(
                "payment settlement can only begin with capture or release intent".to_owned(),
            ));
        }
        None => match (journal.rail_mode, journal.state, journal.settle_action) {
            (
                chio_kernel::payment::PaymentRailMode::PrepaidFinal,
                chio_kernel::payment::PaymentJournalState::Settled,
                None,
            ) => journal.amount_units,
            (
                chio_kernel::payment::PaymentRailMode::ReversibleHold,
                chio_kernel::payment::PaymentJournalState::Settling
                | chio_kernel::payment::PaymentJournalState::Settled,
                Some(chio_kernel::payment::PaymentSettleAction::Capture),
            ) => journal.settle_amount_units.ok_or_else(|| {
                AdmissionPaymentJournalError::Invariant(
                    "capturing payment journal omitted settlement amount".to_owned(),
                )
            })?,
            (
                chio_kernel::payment::PaymentRailMode::ReversibleHold,
                chio_kernel::payment::PaymentJournalState::Settling
                | chio_kernel::payment::PaymentJournalState::Settled,
                Some(chio_kernel::payment::PaymentSettleAction::Release),
            ) => 0,
            _ => {
                return Err(AdmissionPaymentJournalError::Invariant(
                    "payment journal has no replayable settlement intent".to_owned(),
                ));
            }
        },
    };
    if budget.realized_spend_units != realized_units {
        return Err(AdmissionPaymentJournalError::Invariant(
            "budget reconciliation spend does not match the payment intent".to_owned(),
        ));
    }
    Ok(())
}

fn verify_payment_terminal_source<'a>(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    context: &chio_kernel::admission_operation::AdmissionProjectionContext,
    records: impl Iterator<Item = &'a [u8]>,
) -> Result<(), AdmissionOperationStoreError> {
    let records = records.collect::<Vec<_>>();
    let requires_payment = operation.binding().participant_requirements().payment;
    if records.len() != usize::from(requires_payment) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    let Some(bytes) = records.first() else {
        return Ok(());
    };
    let journal = crate::budget_store::load_payment_journal(
        transaction,
        operation.binding().operation_id().as_str(),
    )
    .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?
    .ok_or_else(|| {
        AdmissionOperationStoreError::Invariant(
            "terminal payment source journal is absent".to_owned(),
        )
    })?;
    journal
        .validate()
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
    if !matches!(
        journal.state,
        chio_kernel::payment::PaymentJournalState::Settled
            | chio_kernel::payment::PaymentJournalState::Closed
    ) {
        return Err(AdmissionOperationStoreError::Invariant(
            "terminal payment source journal is not settled".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        AdmissionOperationStoreError::Invariant(format!(
            "terminal payment evidence is invalid JSON: {error}"
        ))
    })?;
    let source = value.get("source").and_then(serde_json::Value::as_object);
    let expected_source_record_id = format!("payment:{}", journal.operation_id);
    let journal_digest = sha256_hex(
        &canonical_json_bytes(&journal)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let authority_digest = sha256_hex(
        &canonical_json_bytes(&context.store_fence)
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?,
    );
    let source_recorded_at = source
        .and_then(|source| source.get("source_recorded_at_unix_ms"))
        .and_then(serde_json::Value::as_u64);
    if value
        .get("payment_participant_id")
        .and_then(serde_json::Value::as_str)
        != Some(operation.binding().operation_id().as_str())
        || source
            .and_then(|source| source.get("source_record_id"))
            .and_then(serde_json::Value::as_str)
            != Some(expected_source_record_id.as_str())
        || source
            .and_then(|source| source.get("source_record_digest"))
            .and_then(serde_json::Value::as_str)
            != Some(journal_digest.as_str())
        || source
            .and_then(|source| source.get("source_authority_digest"))
            .and_then(serde_json::Value::as_str)
            != Some(authority_digest.as_str())
        || source_recorded_at.is_none_or(|recorded_at| {
            recorded_at < journal.created_at_unix_ms || recorded_at > context.trusted_time_unix_ms
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
}

fn map_budget_capture_error(error: BudgetStoreError) -> AdmissionCaptureError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionCaptureError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => AdmissionCaptureError::OutcomeUnknown(detail),
        error => AdmissionCaptureError::Invariant(error.to_string()),
    }
}

fn map_payment_operation_error(
    error: AdmissionOperationStoreError,
) -> AdmissionPaymentJournalError {
    match error {
        AdmissionOperationStoreError::Fenced => AdmissionPaymentJournalError::Fenced,
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Unavailable(detail) => {
            AdmissionPaymentJournalError::Unavailable(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

fn map_payment_budget_error(error: BudgetStoreError) -> AdmissionPaymentJournalError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionPaymentJournalError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        BudgetStoreError::Invariant(detail) => AdmissionPaymentJournalError::Conflict(detail),
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

fn map_payment_owner_error(error: SqliteServingOwnerError) -> AdmissionPaymentJournalError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_tool_outcome_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    outcome_id: AdmissionDigest,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        vec![AdmissionAttachment::ToolOutcomeId(outcome_id.clone())],
        Some(AdmissionOperationState::Finalizing),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    if updated.state() != AdmissionOperationState::Finalizing
        || updated.tool_outcome_id() != Some(&outcome_id)
    {
        return Err(invariant(
            "tool outcome transition did not bind the finalizing operation",
        ));
    }
    let encoded = encode_operation(&updated)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET operation_json = ?1, state = ?2, terminal = 0,
                coordinator_lease_epoch = ?3, version = ?4,
                updated_at_unix_ms = ?5
            WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
            "#,
            params![
                &encoded,
                state_name(updated.state()),
                sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                sqlite_i64(updated.version(), "version")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                updated.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    commit_chain::append_operation_commit_with_participant(
        transaction,
        &updated,
        &encoded,
        stored.recovery_claim.as_ref(),
        "compare_and_swap",
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )?;
    Ok(updated)
}

pub(crate) fn advance_budget_capture_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    if expected.state() != AdmissionOperationState::CapturePending {
        return Err(invariant(
            "combined budget capture requires a CapturePending operation",
        ));
    }
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        Vec::new(),
        Some(AdmissionOperationState::DispatchCommitted),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    advance_participant_bound_operation_tx(
        transaction,
        owner,
        expected,
        recovery_lease,
        &updated,
        participant_digest,
        trusted_now_unix_ms,
    )
}

pub(crate) struct BudgetAuthorizationAdvance<'a> {
    pub(crate) expected: &'a AdmissionOperationV1,
    pub(crate) recovery_lease: &'a AdmissionRecoveryLease,
    pub(crate) hold_id: &'a str,
    pub(crate) payment_required: bool,
    pub(crate) participant_digest: &'a str,
    pub(crate) trusted_now_unix_ms: u64,
}

pub(crate) fn advance_budget_authorization_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    advance: BudgetAuthorizationAdvance<'_>,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let BudgetAuthorizationAdvance {
        expected,
        recovery_lease,
        hold_id,
        payment_required,
        participant_digest,
        trusted_now_unix_ms,
    } = advance;
    let requirements = expected.binding().participant_requirements();
    let required_state = if requirements.broker_attempt {
        AdmissionOperationState::BrokerAttemptRegistered
    } else {
        AdmissionOperationState::Prepared
    };
    if expected.state() != required_state
        || !requirements.budget_capture
        || requirements.payment != payment_required
    {
        return Err(invariant(
            "combined budget authorization does not match operation requirements",
        ));
    }
    let mut attachments = vec![AdmissionAttachment::BudgetHoldId(
        AdmissionIdentifier::try_new("budget_hold_id", hold_id)?,
    )];
    if payment_required {
        attachments.push(AdmissionAttachment::PaymentParticipantId(
            AdmissionIdentifier::try_new(
                "payment_participant_id",
                expected.binding().operation_id().as_str(),
            )?,
        ));
    }
    let command = AdmissionOperationCommand::new(
        expected.binding().operation_id().clone(),
        expected.version(),
        recovery_lease.clone(),
        attachments,
        Some(AdmissionOperationState::BudgetAuthorized),
        None,
        None,
    )?;
    let updated = expected
        .apply_command(&command, trusted_now_unix_ms)?
        .into_operation();
    advance_participant_bound_operation_tx(
        transaction,
        owner,
        expected,
        recovery_lease,
        &updated,
        participant_digest,
        trusted_now_unix_ms,
    )
}

pub(crate) fn verify_budget_authorization_replay_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    hold_id: &str,
    payment_required: bool,
    participant_digest: &str,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let requirements = operation.binding().participant_requirements();
    if !matches!(
        operation.state(),
        AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending
            | AdmissionOperationState::DispatchCommitted
            | AdmissionOperationState::Finalizing
            | AdmissionOperationState::Completed
    ) || !requirements.budget_capture
        || requirements.payment != payment_required
        || operation
            .budget_hold_id()
            .is_none_or(|bound| bound.as_str() != hold_id)
    {
        return Err(invariant(
            "combined budget authorization replay does not match operation requirements",
        ));
    }
    let exact_commit = transaction
        .query_row(
            r#"
            SELECT COUNT(*) = 1
            FROM admission_operation_commits
            WHERE operation_id = ?1 AND mutation_kind = ?2
              AND participant_digest = ?3
            "#,
            params![
                operation.binding().operation_id().as_str(),
                COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
                participant_digest,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exact_commit {
        return Err(invariant(
            "combined budget authorization replay lost its exact participant commit",
        ));
    }
    Ok(operation.clone())
}

fn advance_participant_bound_operation_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    updated: &AdmissionOperationV1,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;

    if stored.operation == *updated {
        let exact_commit = transaction
            .query_row(
                r#"
                SELECT COUNT(*) = 1
                FROM admission_operation_commits
                WHERE operation_id = ?1 AND operation_version = ?2
                  AND mutation_kind = ?3 AND participant_digest = ?4
                "#,
                params![
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(updated.version(), "operation_version")?,
                    COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
                    participant_digest,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        if !exact_commit {
            return Err(invariant(
                "participant-bound operation lost its exact projection commit",
            ));
        }
        return Ok(updated.clone());
    }
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let encoded = encode_operation(updated)?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET operation_json = ?1, state = ?2, terminal = 0,
                coordinator_lease_epoch = ?3, version = ?4,
                updated_at_unix_ms = ?5
            WHERE operation_id = ?6 AND version = ?7 AND terminal = 0
            "#,
            params![
                &encoded,
                state_name(updated.state()),
                sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                sqlite_i64(updated.version(), "operation_version")?,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                updated.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    commit_chain::append_operation_commit_with_participant(
        transaction,
        updated,
        &encoded,
        stored.recovery_claim.as_ref(),
        COMBINED_CAPTURE_OPERATION_MUTATION_KIND,
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )?;
    Ok(updated.clone())
}

pub(crate) fn append_participant_update_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    expected: &AdmissionOperationV1,
    recovery_lease: &AdmissionRecoveryLease,
    participant_digest: &str,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(transaction, expected.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if stored.operation != *expected || trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    verify_stored_recovery_claim(
        transaction,
        owner,
        &stored,
        recovery_lease.untrusted_claim(),
        trusted_now_unix_ms,
        recovery_lease.store_fence(),
    )?;
    let changed = transaction
        .execute(
            r#"
            UPDATE admission_operations
            SET updated_at_unix_ms = ?1
            WHERE operation_id = ?2 AND version = ?3 AND terminal = 0
            "#,
            params![
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                expected.binding().operation_id().as_str(),
                sqlite_i64(expected.version(), "expected_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let encoded = encode_operation(expected)?;
    commit_chain::append_operation_commit_with_participant(
        transaction,
        expected,
        &encoded,
        stored.recovery_claim.as_ref(),
        "participant_update",
        Some(participant_digest),
        owner,
        trusted_now_unix_ms,
    )
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
    if on_disk == 2 {
        migrate_admission_commit_participant_digest(&transaction)?;
    }
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

fn migrate_admission_commit_participant_digest(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, NULL,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v2
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
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
                            OR (mutation_kind = 'participant_update'
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

pub(crate) fn verify_trusted_time(
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
    let system_now = match chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        Some(fixed) => fixed.saturating_mul(1_000),
        None => {
            let system_now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invariant("system clock precedes the Unix epoch"))?
                .as_millis();
            u64::try_from(system_now)
                .map_err(|_| invariant("system clock exceeds the persisted trusted-time range"))?
        }
    };
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

pub(crate) fn verify_active_owner(
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

pub(crate) fn load_operation_for_participant_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
    load_by_operation_id_tx(transaction, operation_id)
        .map(|stored| stored.map(|stored| stored.operation))
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
