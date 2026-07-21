//! Persisted-state restart coverage for non-MustPrepay caller reservations.
//!
//! Kernel unit tests drive threshold, ordinary aggregate, and ordinary direct
//! admission into caller-owned reservations. This integration layer persists
//! each corresponding validated SQLite projection, closes every original store
//! handle, and proves a fresh kernel leaves it untouched during startup and
//! explicit payment reconciliation.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::crypto::Keypair;
use chio_kernel::budget_store::{
    BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetCaptureInvocationRequest, BudgetHoldSnapshot, BudgetInvocationQuota, BudgetQuotaKey,
    BudgetStore, ReservedHoldEnvelope,
};
use chio_kernel::payment::{
    OperationPaymentCaptureRequest, OperationPaymentRefundRequest, PaymentAdapter,
    PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementState,
};
use chio_kernel::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionKind, AdmissionCleanupActionState, AdmissionDispatchState,
    AdmissionOperation, AdmissionOperationCasOutcome, AdmissionOperationCompareAndSwap,
    AdmissionOperationCreateOutcome, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, ChioKernel, DispatchIntentJournalMode, KernelConfig,
    PreparedAdmissionOperation, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::budget_store::SqliteCompositeAuthorizeInput;
use chio_store_sqlite::{SqliteAdmissionOperationStore, SqliteBudgetStore, SqliteReceiptStore};

#[derive(Clone, Copy)]
enum NoPaymentRestartScenario {
    Threshold,
    OrdinaryAggregate,
    OrdinaryDirect,
}

impl NoPaymentRestartScenario {
    fn label(self) -> &'static str {
        match self {
            Self::Threshold => "threshold",
            Self::OrdinaryAggregate => "ordinary-aggregate",
            Self::OrdinaryDirect => "ordinary-direct",
        }
    }

    fn operation_owned(self) -> bool {
        !matches!(self, Self::OrdinaryDirect)
    }

    fn approval_set_hash(self) -> Option<String> {
        matches!(self, Self::Threshold).then(|| "88".repeat(32))
    }
}

struct SeededNoPaymentState {
    request_id: String,
    hold_id: String,
    hold: BudgetHoldSnapshot,
    operation: Option<AdmissionOperation>,
    cleanup_actions: Vec<AdmissionCleanupAction>,
}

#[derive(Clone)]
struct NoPaymentRecoveryRail {
    calls: Arc<AtomicUsize>,
}

impl NoPaymentRecoveryRail {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls }
    }

    fn unexpected<T>(&self) -> Result<T, PaymentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::RailError(
            "non-MustPrepay restart attempted payment recovery".to_string(),
        ))
    }
}

impl PaymentAdapter for NoPaymentRecoveryRail {
    fn rail_id(&self) -> &str {
        "non-mustprepay-restart"
    }

    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.unexpected()
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn authorize_for_operation(
        &self,
        _operation_id: &str,
        _request_binding_hash: &str,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.unexpected()
    }

    fn lookup_authorization_for_operation(
        &self,
        _operation_id: &str,
        _request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.unexpected()
    }

    fn capture_for_operation(
        &self,
        _request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn release_for_operation(
        &self,
        _operation_id: &str,
        _request_binding_hash: &str,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn refund_for_operation(
        &self,
        _request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.unexpected()
    }

    fn settlement_state_for_operation(
        &self,
        _operation_id: &str,
        _request_binding_hash: &str,
        _reference: &str,
        _authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.unexpected()
    }

    fn settlement_state(
        &self,
        _reference: &str,
        _authorization_id: Option<&str>,
    ) -> Result<RailSettlementState, PaymentError> {
        self.unexpected()
    }
}

fn unique_db_path(prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
    Ok(chio_test_support::private_fs::unique_sqlite_path(prefix))
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "66".repeat(32),
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

fn apply_operation_state(
    store: &dyn AdmissionOperationStore,
    current: AdmissionOperation,
    next_state: AdmissionOperationState,
    next_dispatch_state: AdmissionDispatchState,
) -> Result<AdmissionOperation, Box<dyn Error>> {
    let outcome = store.compare_and_swap(AdmissionOperationCompareAndSwap {
        operation_id: current.operation_id(),
        expected_version: current.version(),
        coordinator_lease_epoch: current.coordinator_lease_epoch(),
        next_state,
        next_dispatch_state,
        next_coordinator_lease_epoch: current.coordinator_lease_epoch(),
        last_error: None,
    })?;
    match outcome {
        AdmissionOperationCasOutcome::Applied(operation) => Ok(operation),
        other => Err(std::io::Error::other(format!(
            "admission transition did not apply: {other:?}"
        ))
        .into()),
    }
}

fn seed_caller_reserved_operation(
    store: &SqliteAdmissionOperationStore,
    scenario: NoPaymentRestartScenario,
    request_id: &str,
    hold_id: &str,
) -> Result<AdmissionOperation, Box<dyn Error>> {
    let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: "kernel:non-mustprepay-restart".to_string(),
        request_id: request_id.to_string(),
        capability_id: "operation-cap".to_string(),
        authorization_capability_hash: "44".repeat(32),
        request_binding_hash: "55".repeat(32),
        policy_hash: "66".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: Some(hold_id.to_string()),
        approval_set_hash: scenario.approval_set_hash(),
        execution_nonce_id: Some(format!("nonce-{}", scenario.label())),
        coordinator_lease_epoch: 1,
    })?;
    let operation = match store.create_prepared(prepared)? {
        AdmissionOperationCreateOutcome::Created(operation) => operation,
        other => {
            return Err(std::io::Error::other(format!(
                "fresh admission operation was not created: {other:?}"
            ))
            .into());
        }
    };
    let operation = apply_operation_state(
        store,
        operation,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionDispatchState::NotStarted,
    )?;
    let operation = apply_operation_state(
        store,
        operation,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionDispatchState::NotStarted,
    )?;
    let capture_pending = apply_operation_state(
        store,
        operation,
        AdmissionOperationState::CallerReservationCapturePending,
        AdmissionDispatchState::NotStarted,
    )?;
    let handoff = AdmissionCleanupAction::pending(
        &capture_pending,
        AdmissionCleanupActionKind::CallerReservationHandoff,
        &serde_json::json!({
            "requestId": request_id,
            "scenario": scenario.label(),
        }),
    )?;
    let action_id = handoff.action_id().to_string();
    let caller_reserved = match store.compare_and_swap_with_cleanup_action(
        AdmissionOperationCompareAndSwap {
            operation_id: capture_pending.operation_id(),
            expected_version: capture_pending.version(),
            coordinator_lease_epoch: capture_pending.coordinator_lease_epoch(),
            next_state: AdmissionOperationState::CallerReserved,
            next_dispatch_state: AdmissionDispatchState::Committed,
            next_coordinator_lease_epoch: capture_pending.coordinator_lease_epoch(),
            last_error: None,
        },
        handoff,
    )? {
        AdmissionOperationCasOutcome::Applied(operation) => operation,
        other => {
            return Err(std::io::Error::other(format!(
                "caller reservation transition did not apply: {other:?}"
            ))
            .into());
        }
    };
    let claim_token = format!("claim-{}", scenario.label());
    let claimed = match store.claim_cleanup_action(&action_id, &claim_token, 1, 2)? {
        AdmissionCleanupActionClaimOutcome::Claimed(action) => action,
        other => {
            return Err(std::io::Error::other(format!(
                "caller reservation handoff was not claimable: {other:?}"
            ))
            .into());
        }
    };
    match store.acknowledge_cleanup_action(&action_id, claimed.version(), &claim_token)? {
        AdmissionCleanupActionCasOutcome::Applied(_) => Ok(caller_reserved),
        other => Err(std::io::Error::other(format!(
            "caller reservation handoff was not acknowledged: {other:?}"
        ))
        .into()),
    }
}

fn operation_owned_authorization(
    operation: &AdmissionOperation,
    hold_id: &str,
) -> Result<SqliteCompositeAuthorizeInput, Box<dyn Error>> {
    let quota_key = BudgetQuotaKey::grant("operation-cap", 0)?;
    let quota = BudgetInvocationQuota::from_persisted_parts(quota_key, 2)?;
    Ok(SqliteCompositeAuthorizeInput {
        operation_id: operation.operation_id().to_string(),
        request_binding_hash: operation.request_binding_hash().to_string(),
        capability_id: "operation-cap".to_string(),
        grant_index: 0,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: hold_id.to_string(),
        event_id: format!("{hold_id}:authorize"),
        authority: None,
        invocation_quotas: vec![quota],
        revocation_set: chio_kernel::supplemental_quota::CanonicalRevocationSet::new(
            "operation-cap",
            &[],
            &[],
        )?,
        authorization_artifact_digests: Vec::new(),
    })
}

fn seed_no_payment_state(
    scenario: NoPaymentRestartScenario,
    budget_path: &Path,
    operation_path: &Path,
) -> Result<SeededNoPaymentState, Box<dyn Error>> {
    let request_id = format!("request-{}-non-mustprepay-restart", scenario.label());
    let hold_id = format!("hold-{}-non-mustprepay-restart", scenario.label());
    let operation_store = SqliteAdmissionOperationStore::open(operation_path)?;
    let budget_store = SqliteBudgetStore::open(budget_path)?;
    let operation = if scenario.operation_owned() {
        let operation =
            seed_caller_reserved_operation(&operation_store, scenario, &request_id, &hold_id)?;
        let authorization = budget_store
            .authorize_composite_hold(operation_owned_authorization(&operation, &hold_id)?)?;
        assert!(matches!(
            authorization,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let binding = BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?;
        budget_store.mark_admission_operation_hold_reserved(
            &hold_id,
            &binding,
            i64::MAX,
            Some("USD"),
            None,
            &ReservedHoldEnvelope {
                budget_total: Some(1_000),
                delegation_depth: 0,
                root_budget_holder: "operation-cap".to_string(),
            },
        )?;
        budget_store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "operation-cap".to_string(),
            grant_index: 0,
            hold_id: Some(hold_id.clone()),
            event_id: Some(format!("{hold_id}:capture-invocations")),
            authority: None,
            admission_operation: Some(binding),
        })?;
        Some(operation)
    } else {
        let authorization =
            budget_store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "direct-cap".to_string(),
                0,
                Some(2),
                100,
                Some(100),
                Some(1_000),
                Some(hold_id.clone()),
                Some(format!("{hold_id}:authorize")),
                None,
            ))?;
        assert!(matches!(
            authorization,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        budget_store.mark_hold_reserved(
            &hold_id,
            i64::MAX,
            "USD",
            None,
            &ReservedHoldEnvelope {
                budget_total: Some(1_000),
                delegation_depth: 0,
                root_budget_holder: "direct-cap".to_string(),
            },
        )?;
        None
    };
    assert!(budget_store.get_payment_journal(&request_id)?.is_none());
    assert!(budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .is_empty());
    let hold = budget_store
        .get_budget_hold(&hold_id)?
        .ok_or_else(|| std::io::Error::other("seeded reserved hold is missing"))?;
    let cleanup_actions = match operation.as_ref() {
        Some(operation) => operation_store.load_cleanup_actions(operation.operation_id())?,
        None => Vec::new(),
    };
    if scenario.operation_owned() {
        assert_eq!(cleanup_actions.len(), 1);
        assert_eq!(
            cleanup_actions[0].kind(),
            AdmissionCleanupActionKind::CallerReservationHandoff
        );
        assert_eq!(
            cleanup_actions[0].state(),
            AdmissionCleanupActionState::Completed
        );
    }
    let seeded = SeededNoPaymentState {
        request_id,
        hold_id,
        hold,
        operation,
        cleanup_actions,
    };
    drop(budget_store);
    drop(operation_store);
    Ok(seeded)
}

fn assert_no_payment_recovery_effects(
    budget_store: &SqliteBudgetStore,
    operation_store: &SqliteAdmissionOperationStore,
    seeded: &SeededNoPaymentState,
    calls: &AtomicUsize,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(budget_store
        .get_payment_journal(&seeded.request_id)?
        .is_none());
    assert!(budget_store
        .list_incomplete_payment_journal(u64::MAX)?
        .is_empty());
    assert_eq!(
        budget_store.get_budget_hold(&seeded.hold_id)?,
        Some(seeded.hold.clone())
    );
    match seeded.operation.as_ref() {
        Some(operation) => {
            assert_eq!(
                operation_store.load(operation.operation_id())?,
                Some(operation.clone())
            );
            let cleanup_actions = operation_store.load_cleanup_actions(operation.operation_id())?;
            assert_eq!(cleanup_actions, seeded.cleanup_actions);
            assert!(cleanup_actions
                .iter()
                .all(|action| action.kind() != AdmissionCleanupActionKind::Payment));
        }
        None => {
            assert!(operation_store
                .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 16)?
                .is_empty());
        }
    }
    Ok(())
}

fn assert_persisted_state_restart_has_no_payment_recovery(
    scenario: NoPaymentRestartScenario,
) -> Result<(), Box<dyn Error>> {
    let budget_path = unique_db_path(&format!("{}-no-payment-budget", scenario.label()))?;
    let operation_path = unique_db_path(&format!("{}-no-payment-operation", scenario.label()))?;
    let receipt_path = unique_db_path(&format!("{}-no-payment-receipt", scenario.label()))?;
    let seeded = seed_no_payment_state(scenario, &budget_path, &operation_path)?;

    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_path)?);
    let operation_store = Arc::new(SqliteAdmissionOperationStore::open(&operation_path)?);
    let calls = Arc::new(AtomicUsize::new(0));
    assert_no_payment_recovery_effects(
        budget_store.as_ref(),
        operation_store.as_ref(),
        &seeded,
        calls.as_ref(),
    )?;
    let receipt_store = Arc::new(SqliteReceiptStore::open(&receipt_path)?);
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_receipt_store_handle(
        Arc::clone(&receipt_store) as Arc<dyn chio_kernel::ReceiptStore>
    )?;
    kernel.set_budget_store_handle(Arc::clone(&budget_store) as Arc<dyn BudgetStore>)?;
    kernel.set_admission_operation_store_handle(
        Arc::clone(&operation_store) as Arc<dyn AdmissionOperationStore>
    )?;
    // The production adapter-install path runs startup payment reconciliation
    // once both durable stores and durable receipt persistence are installed.
    kernel.set_payment_adapter(Box::new(NoPaymentRecoveryRail::new(Arc::clone(&calls))))?;

    assert_no_payment_recovery_effects(
        budget_store.as_ref(),
        operation_store.as_ref(),
        &seeded,
        calls.as_ref(),
    )?;

    assert_eq!(
        kernel.reconcile_payment_journal(0)?,
        chio_kernel::PaymentReconcileReport::default()
    );
    assert_no_payment_recovery_effects(
        budget_store.as_ref(),
        operation_store.as_ref(),
        &seeded,
        calls.as_ref(),
    )?;

    drop(kernel);
    drop(receipt_store);
    drop(operation_store);
    drop(budget_store);
    std::fs::remove_file(receipt_path)?;
    std::fs::remove_file(operation_path)?;
    std::fs::remove_file(budget_path)?;
    Ok(())
}

#[test]
fn threshold_non_mustprepay_persisted_state_restart_has_no_payment_recovery(
) -> Result<(), Box<dyn Error>> {
    assert_persisted_state_restart_has_no_payment_recovery(NoPaymentRestartScenario::Threshold)
}

#[test]
fn ordinary_aggregate_non_mustprepay_persisted_state_restart_has_no_payment_recovery(
) -> Result<(), Box<dyn Error>> {
    assert_persisted_state_restart_has_no_payment_recovery(
        NoPaymentRestartScenario::OrdinaryAggregate,
    )
}

#[test]
fn ordinary_noncomposite_non_mustprepay_persisted_state_restart_has_no_payment_recovery(
) -> Result<(), Box<dyn Error>> {
    assert_persisted_state_restart_has_no_payment_recovery(NoPaymentRestartScenario::OrdinaryDirect)
}
