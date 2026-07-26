//! Crash reconciliation for operation-owned payment and composite budget holds.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::crypto::Keypair;
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetEventAuthority,
    BudgetHoldDispositionView, BudgetInvocationQuota, BudgetQuotaKey, BudgetStore,
};
use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};
use chio_kernel::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionKind, AdmissionDispatchState, AdmissionOperation,
    AdmissionOperationCasOutcome, AdmissionOperationCompareAndSwap,
    AdmissionOperationCreateOutcome, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, ChioKernel, DispatchIntentJournalMode, KernelConfig,
    OperationPaymentRefundRequest, PaymentAdapter, PaymentError, PaymentResult,
    PreparedAdmissionOperation, RailSettlementState, RailSettlementStatus,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::budget_store::SqliteCompositeAuthorizeInput;
use chio_store_sqlite::{SqliteAdmissionOperationStore, SqliteBudgetStore, SqliteReceiptStore};

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    chio_test_support::private_fs::unique_sqlite_path(prefix)
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: DispatchIntentJournalMode::SideEffecting,
    }
}

struct OperationOnlyRail {
    operation_id: String,
    request_binding_hash: String,
    authorization_id: String,
    operation_release_calls: AtomicUsize,
    operation_release_moves: AtomicUsize,
    operation_refund_calls: AtomicUsize,
    operation_refund_moves: AtomicUsize,
    legacy_release_calls: AtomicUsize,
    legacy_refund_calls: AtomicUsize,
    operation_state_calls: AtomicUsize,
    legacy_state_calls: AtomicUsize,
    released: AtomicBool,
    refunded: AtomicBool,
}

impl OperationOnlyRail {
    fn new(operation_id: &str, request_binding_hash: &str, authorization_id: &str) -> Self {
        Self {
            operation_id: operation_id.to_string(),
            request_binding_hash: request_binding_hash.to_string(),
            authorization_id: authorization_id.to_string(),
            operation_release_calls: AtomicUsize::new(0),
            operation_release_moves: AtomicUsize::new(0),
            operation_refund_calls: AtomicUsize::new(0),
            operation_refund_moves: AtomicUsize::new(0),
            legacy_release_calls: AtomicUsize::new(0),
            legacy_refund_calls: AtomicUsize::new(0),
            operation_state_calls: AtomicUsize::new(0),
            legacy_state_calls: AtomicUsize::new(0),
            released: AtomicBool::new(false),
            refunded: AtomicBool::new(false),
        }
    }
}

struct SharedOperationOnlyRail(Arc<OperationOnlyRail>);

impl PaymentAdapter for SharedOperationOnlyRail {
    fn rail_id(&self) -> &str {
        "operation-only"
    }

    fn authorize(
        &self,
        _request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("authorize"))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::OperationIdempotencyUnsupported("capture"))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0.legacy_release_calls.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::OperationIdempotencyUnsupported("release"))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0.legacy_refund_calls.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::OperationIdempotencyUnsupported("refund"))
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.0
            .operation_release_calls
            .fetch_add(1, Ordering::SeqCst);
        if operation_id != self.0.operation_id
            || request_binding_hash != self.0.request_binding_hash
            || authorization_id != self.0.authorization_id
        {
            return Err(PaymentError::RailError(
                "operation release binding mismatch".to_string(),
            ));
        }
        if !self.0.released.swap(true, Ordering::SeqCst) {
            self.0
                .operation_release_moves
                .fetch_add(1, Ordering::SeqCst);
            return Err(PaymentError::Unavailable(
                "release committed but its acknowledgement was lost".to_string(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: format!("release-{authorization_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.0.operation_refund_calls.fetch_add(1, Ordering::SeqCst);
        if request.operation_id != self.0.operation_id
            || request.request_binding_hash != self.0.request_binding_hash
            || request.transaction_id != "captured-operation-refund"
            || request.amount_units != 100
            || request.currency != "USD"
        {
            return Err(PaymentError::RailError(
                "operation refund binding mismatch".to_string(),
            ));
        }
        if !self.0.refunded.swap(true, Ordering::SeqCst) {
            self.0.operation_refund_moves.fetch_add(1, Ordering::SeqCst);
            return Err(PaymentError::Unavailable(
                "refund committed but its acknowledgement was lost".to_string(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: "refund-operation-reference".to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }

    fn settlement_state(
        &self,
        _reference: &str,
        _authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.0.legacy_state_calls.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::OperationIdempotencyUnsupported(
            "settlement state lookup",
        ))
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        _reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.0.operation_state_calls.fetch_add(1, Ordering::SeqCst);
        if operation_id != self.0.operation_id
            || request_binding_hash != self.0.request_binding_hash
        {
            return Err(PaymentError::RailError(
                "operation settlement lookup binding mismatch".to_string(),
            ));
        }
        let authorization_id = authorization_id.ok_or_else(|| {
            PaymentError::RailError(
                "operation-only settlement lookup requires authorization_id".to_string(),
            )
        })?;
        Ok(RailSettlementState::Held {
            authorization_id: authorization_id.to_string(),
        })
    }
}

fn operation_owned_composite_input(
    operation_id: &str,
    request_binding_hash: &str,
    hold_id: &str,
    authority: BudgetEventAuthority,
) -> SqliteCompositeAuthorizeInput {
    let quota_key = BudgetQuotaKey::grant("operation-cap", 0).expect("valid grant quota key");
    let quota =
        BudgetInvocationQuota::from_persisted_parts(quota_key, 2).expect("valid persisted quota");
    SqliteCompositeAuthorizeInput {
        operation_id: operation_id.to_string(),
        request_binding_hash: request_binding_hash.to_string(),
        capability_id: "operation-cap".to_string(),
        grant_index: 0,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: format!("{hold_id}:authorize"),
        authority: Some(authority),
        invocation_quotas: vec![quota],
        revocation_set: chio_kernel::supplemental_quota::CanonicalRevocationSet::new(
            "operation-cap",
            &[],
            &[],
        )
        .expect("valid revocation set"),
        authorization_artifact_digests: Vec::new(),
        partition_escrow_evidence: None,
    }
}

fn journal_record(
    request_id: &str,
    operation_id: &str,
    request_binding_hash: String,
    authorization_id: &str,
    hold_id: &str,
    authority: BudgetEventAuthority,
) -> Result<PaymentJournalRecord, chio_kernel::BudgetStoreError> {
    Ok(PaymentJournalRecord {
        request_id: request_id.to_string(),
        capability_id: "operation-cap".to_string(),
        grant_index: 0,
        admission_operation: Some(BudgetAdmissionOperationBinding::new(
            operation_id.to_string(),
            request_binding_hash,
        )?),
        authority: Some(authority),
        hold_id: Some(hold_id.to_string()),
        rail: "operation-only".to_string(),
        authorization_id: Some(authorization_id.to_string()),
        transaction_id: None,
        budget_exposure_units: 100,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::Authorized,
        created_at_unix_ms: 1,
        tenant_id: None,
    })
}

fn apply_state(
    store: &dyn AdmissionOperationStore,
    current: AdmissionOperation,
    next_state: AdmissionOperationState,
    next_dispatch_state: AdmissionDispatchState,
) -> AdmissionOperation {
    let prior_version = current.version();
    let outcome = store
        .compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: current.operation_id(),
            expected_version: prior_version,
            coordinator_lease_epoch: current.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: current.coordinator_lease_epoch(),
            last_error: None,
        })
        .expect("exact admission operation transition must remain available");
    let applied = match outcome {
        AdmissionOperationCasOutcome::Applied(applied) => applied,
        AdmissionOperationCasOutcome::Conflict(conflict) => {
            panic!("exact admission operation transition conflicted: {conflict:?}")
        }
        AdmissionOperationCasOutcome::Missing => {
            panic!("admission operation disappeared during exact transition")
        }
    };
    assert_eq!(applied.state(), next_state);
    assert_eq!(applied.dispatch_state(), next_dispatch_state);
    assert_eq!(applied.version(), prior_version + 1);
    applied
}

fn terminal_operation_store(
    request_id: &str,
    request_binding_hash: &str,
    hold_id: &str,
) -> Result<
    (
        std::path::PathBuf,
        Arc<SqliteAdmissionOperationStore>,
        std::path::PathBuf,
        Arc<SqliteReceiptStore>,
        AdmissionOperation,
    ),
    Box<dyn std::error::Error>,
> {
    let path = unique_db_path("operation-bound-terminal-owner");
    let store = Arc::new(SqliteAdmissionOperationStore::open(&path)?);
    let receipt_path = unique_db_path("operation-bound-terminal-receipts");
    let receipt_store = Arc::new(SqliteReceiptStore::open(&receipt_path)?);
    let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "kernel:operation-test".to_string(),
        request_id: request_id.to_string(),
        capability_id: "operation-cap".to_string(),
        authorization_capability_hash: "44".repeat(32),
        request_binding_hash: request_binding_hash.to_string(),
        policy_hash: "55".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: Some(hold_id.to_string()),
        approval_set_hash: None,
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })?;
    let operation = match store.create_prepared(prepared)? {
        AdmissionOperationCreateOutcome::Created(operation) => operation,
        AdmissionOperationCreateOutcome::Existing(operation) => {
            panic!("fresh SQLite store returned an existing operation: {operation:?}")
        }
    };
    let operation = apply_state(
        store.as_ref(),
        operation,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        store.as_ref(),
        operation,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        store.as_ref(),
        operation,
        AdmissionOperationState::CapturePending,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        store.as_ref(),
        operation,
        AdmissionOperationState::DispatchCommitted,
        AdmissionDispatchState::Committed,
    );
    let terminal_receipt = AdmissionCleanupAction::pending(
        &operation,
        AdmissionCleanupActionKind::TerminalReceipt,
        &serde_json::json!({ "requestId": request_id }),
    )?;
    let terminal_receipt_id = terminal_receipt.action_id().to_string();
    let outcome = store.compare_and_swap_with_cleanup_action(
        AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state: AdmissionOperationState::Completed,
            next_dispatch_state: AdmissionDispatchState::EffectCompleted,
            next_coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            last_error: None,
        },
        terminal_receipt,
    )?;
    let completed = match outcome {
        AdmissionOperationCasOutcome::Applied(operation) => operation,
        AdmissionOperationCasOutcome::Conflict(operation) => {
            panic!("fresh terminal transition conflicted: {operation:?}")
        }
        AdmissionOperationCasOutcome::Missing => {
            panic!("fresh operation disappeared before terminal transition")
        }
    };
    let claim_token = "terminal-operation-test-receipt";
    let claimed = match store.claim_cleanup_action(&terminal_receipt_id, claim_token, 1, 2)? {
        AdmissionCleanupActionClaimOutcome::Claimed(action) => action,
        other => panic!("fresh terminal receipt action was not claimable: {other:?}"),
    };
    match store.acknowledge_cleanup_action(&terminal_receipt_id, claimed.version(), claim_token)? {
        AdmissionCleanupActionCasOutcome::Applied(action) => {
            assert_eq!(
                action.state(),
                chio_kernel::AdmissionCleanupActionState::Completed
            );
        }
        other => panic!("fresh terminal receipt action was not acknowledged: {other:?}"),
    }
    Ok((path, store, receipt_path, receipt_store, completed))
}

#[test]
fn operation_bound_crash_reconcile_releases_rail_and_composite_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db_path = unique_db_path("operation-bound-journal-release");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let request_binding_hash = "11".repeat(32);
    let authorization_id = "auth-operation-release";
    let hold_id = "hold-operation-release";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let (operation_db_path, operation_store, receipt_db_path, receipt_store, operation) =
        terminal_operation_store("req-operation-release", &request_binding_hash, hold_id)?;
    let operation_id = operation.operation_id().to_string();
    let input = operation_owned_composite_input(
        &operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    );
    let rail = Arc::new(OperationOnlyRail::new(
        &operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    budget_store.authorize_composite_hold(input)?;
    budget_store.record_payment_journal(&journal_record(
        "req-operation-release",
        &operation_id,
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?)?;

    let report = kernel.reconcile_payment_journal(0)?;
    assert_eq!(report.resolved, 1);
    assert_eq!(report.reconcile_failed, 0);
    assert_eq!(rail.operation_state_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rail.legacy_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_calls.load(Ordering::SeqCst), 2);
    assert_eq!(rail.operation_release_moves.load(Ordering::SeqCst), 1);
    assert_eq!(rail.legacy_release_calls.load(Ordering::SeqCst), 0);
    let hold = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("composite hold must remain queryable")?;
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Reversed);
    assert_eq!(hold.remaining_exposure_units, 0);
    let usage = budget_store
        .get_usage("operation-cap", 0)?
        .ok_or("composite usage must remain queryable")?;
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units()?, 0);
    assert!(budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .is_empty());

    let retry_report = kernel.reconcile_payment_journal(0)?;
    assert_eq!(retry_report.resolved, 0);
    assert_eq!(
        rail.operation_release_moves.load(Ordering::SeqCst),
        1,
        "an exact recovery retry must not move the rail twice"
    );

    let _ = std::fs::remove_file(&budget_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    let _ = std::fs::remove_file(&receipt_db_path);
    Ok(())
}

#[test]
fn caller_reserved_operation_defers_payment_recovery_to_admission_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db_path = unique_db_path("operation-bound-journal-caller-reserved");
    let operation_db_path = unique_db_path("operation-bound-journal-caller-reserved-operations");
    let receipt_db_path = unique_db_path("operation-bound-journal-caller-reserved-receipts");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let operation_store = Arc::new(SqliteAdmissionOperationStore::open(&operation_db_path)?);
    let receipt_store = Arc::new(SqliteReceiptStore::open(&receipt_db_path)?);
    let request_id = "req-operation-caller-reserved";
    let request_binding_hash = "66".repeat(32);
    let authorization_id = "auth-operation-caller-reserved";
    let hold_id = "hold-operation-caller-reserved";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;

    let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "kernel:operation-test".to_string(),
        request_id: request_id.to_string(),
        capability_id: "operation-cap".to_string(),
        authorization_capability_hash: "44".repeat(32),
        request_binding_hash: request_binding_hash.clone(),
        policy_hash: "55".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: Some(hold_id.to_string()),
        approval_set_hash: None,
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })?;
    let operation = match operation_store.create_prepared(prepared)? {
        AdmissionOperationCreateOutcome::Created(operation) => operation,
        AdmissionOperationCreateOutcome::Existing(operation) => {
            panic!("fresh operation database returned an existing operation: {operation:?}")
        }
    };
    assert_eq!(operation.state(), AdmissionOperationState::Prepared);
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(operation.version(), 0);
    let operation = apply_state(
        operation_store.as_ref(),
        operation,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        operation_store.as_ref(),
        operation,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        operation_store.as_ref(),
        operation,
        AdmissionOperationState::CallerReservationCapturePending,
        AdmissionDispatchState::NotStarted,
    );
    let operation = apply_state(
        operation_store.as_ref(),
        operation,
        AdmissionOperationState::CallerReserved,
        AdmissionDispatchState::Committed,
    );
    let operation_id = operation.operation_id().to_string();
    let rail = Arc::new(OperationOnlyRail::new(
        &operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    let authorize = budget_store.authorize_composite_hold(operation_owned_composite_input(
        &operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    ))?;
    assert!(matches!(
        authorize,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let record = journal_record(
        request_id,
        &operation_id,
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?;
    budget_store.record_payment_journal(&record)?;

    let hold_before = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("operation-owned composite hold must remain queryable")?;
    assert_eq!(hold_before.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(hold_before.remaining_exposure_units, 100);
    let usage_before = budget_store
        .get_usage("operation-cap", 0)?
        .ok_or("operation-owned composite usage must remain queryable")?;
    assert_eq!(usage_before.invocation_count, 1);
    assert_eq!(usage_before.total_cost_exposed, 100);
    assert_eq!(usage_before.total_cost_realized_spend, 0);

    for pass in 1..=2 {
        let report = kernel.reconcile_payment_journal(0)?;
        assert_eq!(report.resolved, 0, "reconciliation pass {pass}");
        assert_eq!(report.reconcile_failed, 0, "reconciliation pass {pass}");
        assert_eq!(
            report.deferred_to_admission_operation, 1,
            "reconciliation pass {pass}"
        );
        assert_eq!(
            budget_store.list_incomplete_payment_journal(u64::MAX)?,
            vec![record.clone()],
            "reconciliation pass {pass} must leave the payment journal incomplete"
        );
        let hold_after = budget_store
            .get_budget_hold(hold_id)?
            .ok_or("operation-owned composite hold must remain queryable")?;
        assert_eq!(&hold_after, &hold_before, "reconciliation pass {pass}");
        let usage_after = budget_store
            .get_usage("operation-cap", 0)?
            .ok_or("operation-owned composite usage must remain queryable")?;
        assert_eq!(&usage_after, &usage_before, "reconciliation pass {pass}");
        let operation_after = operation_store
            .load(&operation_id)?
            .ok_or("caller-reserved operation must remain queryable")?;
        assert_eq!(
            &operation_after, &operation,
            "reconciliation pass {pass} must leave the admission operation caller-reserved"
        );
    }

    assert_eq!(rail.operation_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_moves.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_refund_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_refund_moves.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_refund_calls.load(Ordering::SeqCst), 0);
    assert!(!rail.released.load(Ordering::SeqCst));
    assert!(!rail.refunded.load(Ordering::SeqCst));
    assert_eq!(operation.state(), AdmissionOperationState::CallerReserved);
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::Committed
    );

    drop(kernel);
    drop(receipt_store);
    drop(operation_store);
    drop(budget_store);
    let _ = std::fs::remove_file(&receipt_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    let _ = std::fs::remove_file(&budget_db_path);
    Ok(())
}

#[test]
fn mismatched_operation_journal_binding_fails_closed_before_release(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db_path = unique_db_path("operation-bound-journal-mismatch");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let expected_operation_id = "operation-expected";
    let request_binding_hash = "22".repeat(32);
    let authorization_id = "auth-operation-expected";
    let hold_id = "hold-operation-mismatch";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let (operation_db_path, operation_store, receipt_db_path, receipt_store, journal_operation) =
        terminal_operation_store("req-operation-mismatch", &request_binding_hash, hold_id)?;
    let input = operation_owned_composite_input(
        expected_operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    );
    let rail = Arc::new(OperationOnlyRail::new(
        expected_operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    budget_store.authorize_composite_hold(input)?;
    budget_store.record_payment_journal(&journal_record(
        "req-operation-mismatch",
        journal_operation.operation_id(),
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?)?;

    let report = kernel.reconcile_payment_journal(0)?;
    assert_eq!(report.resolved, 0);
    assert_eq!(report.reconcile_failed, 1);
    assert_eq!(rail.operation_state_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rail.legacy_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_moves.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_release_calls.load(Ordering::SeqCst), 0);
    let hold = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("composite hold must remain queryable")?;
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(hold.remaining_exposure_units, 100);
    assert!(budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .is_empty());
    assert_eq!(
        budget_store
            .payment_journal_reconcile_failed_rail("req-operation-mismatch")?
            .as_deref(),
        Some("operation-only")
    );

    let _ = std::fs::remove_file(&budget_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    let _ = std::fs::remove_file(&receipt_db_path);
    Ok(())
}

#[test]
fn operation_bound_reconcile_rejects_configured_rail_mismatch_before_any_rail_call(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db_path = unique_db_path("operation-bound-journal-rail-mismatch");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let request_binding_hash = "77".repeat(32);
    let authorization_id = "auth-operation-rail-mismatch";
    let hold_id = "hold-operation-rail-mismatch";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let (operation_db_path, operation_store, receipt_db_path, receipt_store, operation) =
        terminal_operation_store(
            "req-operation-rail-mismatch",
            &request_binding_hash,
            hold_id,
        )?;
    let operation_id = operation.operation_id().to_string();
    let rail = Arc::new(OperationOnlyRail::new(
        &operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    budget_store.authorize_composite_hold(operation_owned_composite_input(
        &operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    ))?;
    let mut record = journal_record(
        "req-operation-rail-mismatch",
        &operation_id,
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?;
    record.rail = "different-rail".to_string();
    budget_store.record_payment_journal(&record)?;

    let report = kernel.reconcile_payment_journal(0)?;
    assert_eq!(report.resolved, 0);
    assert_eq!(report.reconcile_failed, 1);
    assert_eq!(rail.operation_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_moves.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_release_calls.load(Ordering::SeqCst), 0);
    let hold = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("rail-mismatched hold must remain queryable")?;
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(hold.remaining_exposure_units, 100);
    assert_eq!(
        budget_store
            .payment_journal_reconcile_failed_rail("req-operation-rail-mismatch")?
            .as_deref(),
        Some("different-rail")
    );

    let _ = std::fs::remove_file(&budget_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    let _ = std::fs::remove_file(&receipt_db_path);
    Ok(())
}

#[test]
fn operation_bound_reconcile_rejects_owner_request_mismatch_before_any_rail_call(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db_path = unique_db_path("operation-bound-journal-request-mismatch");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let request_binding_hash = "88".repeat(32);
    let authorization_id = "auth-operation-request-mismatch";
    let hold_id = "hold-operation-request-mismatch";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let (operation_db_path, operation_store, receipt_db_path, receipt_store, operation) =
        terminal_operation_store("req-operation-original", &request_binding_hash, hold_id)?;
    let operation_id = operation.operation_id().to_string();
    let rail = Arc::new(OperationOnlyRail::new(
        &operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    budget_store.authorize_composite_hold(operation_owned_composite_input(
        &operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    ))?;
    budget_store.record_payment_journal(&journal_record(
        "req-operation-request-mismatch",
        &operation_id,
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?)?;

    let error = kernel
        .reconcile_payment_journal(0)
        .expect_err("owner request mismatch must fail closed");
    assert!(error
        .to_string()
        .contains("does not match admission operation"));
    assert_eq!(rail.operation_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_state_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_calls.load(Ordering::SeqCst), 0);
    assert_eq!(rail.operation_release_moves.load(Ordering::SeqCst), 0);
    assert_eq!(rail.legacy_release_calls.load(Ordering::SeqCst), 0);
    let hold = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("request-mismatched hold must remain queryable")?;
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(hold.remaining_exposure_units, 100);
    assert_eq!(
        budget_store
            .list_incomplete_payment_journal(u64::MAX)?
            .len(),
        1
    );

    let _ = std::fs::remove_file(&budget_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    let _ = std::fs::remove_file(&receipt_db_path);
    Ok(())
}

#[test]
fn operation_bound_refund_intent_retries_once_and_attests_actual_reference(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::payment::PaymentSettleAction;

    let budget_db_path = unique_db_path("operation-bound-journal-refund");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_db_path)?);
    let request_binding_hash = "33".repeat(32);
    let authorization_id = "auth-operation-refund";
    let hold_id = "hold-operation-refund";
    let authority = BudgetEventAuthority {
        authority_id: "kernel:operation-test".to_string(),
        lease_id: "single-node".to_string(),
        lease_epoch: 0,
    };
    let (operation_db_path, operation_store, receipt_db_path, receipt_store, operation) =
        terminal_operation_store("req-operation-refund", &request_binding_hash, hold_id)?;
    let operation_id = operation.operation_id().to_string();
    let input = operation_owned_composite_input(
        &operation_id,
        &request_binding_hash,
        hold_id,
        authority.clone(),
    );
    let rail = Arc::new(OperationOnlyRail::new(
        &operation_id,
        &request_binding_hash,
        authorization_id,
    ));
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_payment_adapter(Box::new(SharedOperationOnlyRail(Arc::clone(&rail))))?;

    budget_store.authorize_composite_hold(input)?;
    let mut record = journal_record(
        "req-operation-refund",
        &operation_id,
        request_binding_hash,
        authorization_id,
        hold_id,
        authority,
    )?;
    record.state = PaymentJournalState::Settling;
    record.transaction_id = Some("captured-operation-refund".to_string());
    record.settle_action = Some(PaymentSettleAction::Refund);
    record.settle_amount_units = Some(100);
    budget_store.record_payment_journal(&record)?;

    let report = kernel.reconcile_payment_journal(0)?;
    assert_eq!(report.resolved, 1);
    assert_eq!(report.reconcile_failed, 0);
    assert_eq!(rail.operation_refund_calls.load(Ordering::SeqCst), 2);
    assert_eq!(rail.operation_refund_moves.load(Ordering::SeqCst), 1);
    let hold = budget_store
        .get_budget_hold(hold_id)?
        .ok_or("refunded composite hold must remain queryable")?;
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Reversed);
    assert_eq!(hold.remaining_exposure_units, 0);

    let receipt_seq = receipt_store.max_tool_receipt_seq()?;
    let (_, receipt_bytes) = receipt_store
        .receipts_canonical_bytes_range(receipt_seq, receipt_seq)?
        .into_iter()
        .next()
        .ok_or("refund reconciliation receipt must be durable")?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_bytes)?;
    assert_eq!(
        receipt["metadata"]["financial"]["payment_reference"],
        serde_json::json!("refund-operation-reference")
    );
    assert_eq!(
        receipt["metadata"]["payment_reconciliation"]["transactionId"],
        serde_json::json!("refund-operation-reference")
    );

    let retry = kernel.reconcile_payment_journal(0)?;
    assert_eq!(retry.resolved, 0);
    assert_eq!(rail.operation_refund_moves.load(Ordering::SeqCst), 1);

    let _ = std::fs::remove_file(&receipt_db_path);
    let _ = std::fs::remove_file(&budget_db_path);
    let _ = std::fs::remove_file(&operation_db_path);
    Ok(())
}
