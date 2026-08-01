use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetEventAuthority, BudgetHoldDispositionView, BudgetHoldMutationDecision,
    BudgetInvocationReservationState, BudgetReconcileHoldRequest, BudgetReleaseHoldRequest,
    BudgetReverseHoldRequest, BudgetUsageRecord, ReservedHoldEnvelope,
};

fn kernel_coordinator_authority_id(kernel: &ChioKernel) -> String {
    format!("kernel:{}", kernel.public_key().to_hex())
}

fn make_admission_saga_kernel() -> ChioKernel {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    make_kernel(config)
}

fn prepared_admission_operation(kernel: &ChioKernel) -> AdmissionOperation {
    prepared_admission_operation_with_nonce(kernel, None)
}

fn prepared_admission_operation_with_nonce(
    kernel: &ChioKernel,
    execution_nonce_id: Option<&str>,
) -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: kernel_coordinator_authority_id(kernel),
        request_id: "request-admission-store".to_string(),
        capability_id: "capability-admission-store".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: kernel.config.policy_hash.clone(),
        broker_attempt_id: None,
        budget_hold_id: Some("hold-admission-store".to_string()),
        approval_set_hash: None,
        execution_nonce_id: execution_nonce_id.map(str::to_string),
        coordinator_lease_epoch: 1,
    })
    .unwrap()
}

fn caller_reap_candidate(kernel: &ChioKernel, suffix: &str) -> AdmissionOperation {
    let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: kernel_coordinator_authority_id(kernel),
        request_id: format!("request-reap-{suffix}"),
        capability_id: "capability-reap".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: kernel.config.policy_hash.clone(),
        broker_attempt_id: None,
        budget_hold_id: Some(format!("hold-reap-{suffix}")),
        approval_set_hash: None,
        execution_nonce_id: Some(format!("nonce-reap-{suffix}")),
        coordinator_lease_epoch: 1,
    })
    .unwrap();
    let budget_authorized = prepared
        .transition_checked(
            AdmissionOperationState::BudgetAuthorized,
            AdmissionDispatchState::NotStarted,
            1,
            None,
        )
        .unwrap();
    let ready = budget_authorized
        .transition_checked(
            AdmissionOperationState::ReadyToDispatch,
            AdmissionDispatchState::NotStarted,
            1,
            None,
        )
        .unwrap();
    let capture_pending = ready
        .transition_checked(
            AdmissionOperationState::CallerReservationCapturePending,
            AdmissionDispatchState::NotStarted,
            1,
            None,
        )
        .unwrap();
    capture_pending
        .transition_checked(
            AdmissionOperationState::CallerReserved,
            AdmissionDispatchState::Committed,
            1,
            None,
        )
        .unwrap()
}

struct ProfiledTestStore {
    inner: InMemoryAdmissionOperationStore,
    profile: AdmissionOperationStoreProfile,
}

impl ProfiledTestStore {
    fn new(profile: AdmissionOperationStoreProfile) -> Self {
        Self {
            inner: InMemoryAdmissionOperationStore::new(),
            profile,
        }
    }
}

impl AdmissionOperationStore for ProfiledTestStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.profile
    }

    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(&self.inner)
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(operation_id)
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.inner
            .count_unresolved_by_authority(kind, coordinator_authority_id)
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        self.inner.compare_and_swap(request)
    }
}

struct ReapInventoryTestStore {
    delegate: std::sync::Arc<ProfiledTestStore>,
    operations: Vec<AdmissionOperation>,
    cleanup_actions: std::collections::HashMap<String, Vec<AdmissionCleanupAction>>,
    pages: std::sync::Mutex<Vec<(Option<String>, Vec<String>)>>,
}

impl ReapInventoryTestStore {
    fn new(
        delegate: std::sync::Arc<ProfiledTestStore>,
        mut operations: Vec<AdmissionOperation>,
        cleanup_actions: std::collections::HashMap<String, Vec<AdmissionCleanupAction>>,
    ) -> Self {
        operations.sort_unstable_by(|left, right| left.operation_id().cmp(right.operation_id()));
        Self {
            delegate,
            operations,
            cleanup_actions,
            pages: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn page_history(&self) -> Vec<(Option<String>, Vec<String>)> {
        self.pages.lock().unwrap().clone()
    }
}

impl AdmissionOperationStore for ReapInventoryTestStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        AdmissionOperationStoreProfile::SingleNodeDurable
    }

    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(self.delegate.as_ref())
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.delegate.create_prepared(operation)
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        if let Some(operation) = self.delegate.load(operation_id)? {
            return Ok(Some(operation));
        }
        Ok(self
            .operations
            .iter()
            .find(|operation| operation.operation_id() == operation_id)
            .cloned())
    }

    fn list_caller_reservation_reap_candidates(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        let page = self
            .operations
            .iter()
            .filter(|operation| {
                after_operation_id
                    .is_none_or(|after| operation.operation_id() > after)
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        self.pages.lock().unwrap().push((
            after_operation_id.map(str::to_string),
            page.iter()
                .map(|operation| operation.operation_id().to_string())
                .collect(),
        ));
        Ok(page)
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.delegate
            .count_unresolved_by_authority(kind, coordinator_authority_id)
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        self.delegate.compare_and_swap(request)
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        if let Some(actions) = self.cleanup_actions.get(operation_id) {
            return Ok(actions.clone());
        }
        self.delegate.load_cleanup_actions(operation_id)
    }
}

struct DurableRecoveryBudgetStore {
    inner: InMemoryBudgetStore,
    capture_ack_losses: std::sync::atomic::AtomicUsize,
}

impl DurableRecoveryBudgetStore {
    fn new() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
            capture_ack_losses: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn with_capture_ack_loss() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
            capture_ack_losses: std::sync::atomic::AtomicUsize::new(1),
        }
    }
}

#[derive(Clone)]
struct DurableRecoveryNonceStore {
    inner: std::sync::Arc<InMemoryExecutionNonceStore>,
}

impl DurableRecoveryNonceStore {
    fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(InMemoryExecutionNonceStore::default()),
        }
    }
}

impl ExecutionNonceStore for DurableRecoveryNonceStore {
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        ExecutionNonceStoreProfile::SingleNodeDurable
    }

    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.inner.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, expires_at: i64) -> Result<bool, KernelError> {
        self.inner.reserve_until(nonce_id, expires_at)
    }

    fn reserve_nonce_for_operation(
        &self,
        operation_id: &str,
        nonce_id: &str,
        signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner
            .reserve_nonce_for_operation(operation_id, nonce_id, signed_expires_at)
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner.commit_nonce_reservation(operation_id)
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner.cancel_nonce_reservation(operation_id)
    }

    fn get_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        self.inner.get_nonce_reservation(operation_id)
    }
}

impl BudgetStore for DurableRecoveryBudgetStore {
    fn authority_profile(&self) -> BudgetStoreProfile {
        BudgetStoreProfile::SingleNodeDurable
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        self.inner.get_mutation_event_by_id(event_id)
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.authorize_budget_hold(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.inner.reverse_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.inner.reconcile_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let captured = self.inner.capture_invocation_reservations(request)?;
        if self
            .capture_ack_losses
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(BudgetStoreError::Invariant(
                "injected capture acknowledgement loss".to_string(),
            ));
        }
        Ok(captured)
    }

    fn query_invocation_capture(
        &self,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
        self.inner.query_invocation_capture(request)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.inner.get_budget_hold(hold_id)
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.inner.mark_admission_operation_hold_reserved(
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }
}

struct CapturePendingNonceFixture {
    kernel: ChioKernel,
    operation_store: std::sync::Arc<ProfiledTestStore>,
    nonce_store: DurableRecoveryNonceStore,
    budget_store: std::sync::Arc<DurableRecoveryBudgetStore>,
    operation_id: String,
    capture_request: BudgetCaptureInvocationRequest,
    kernel_authority: String,
    reserved_until: i64,
    initial_receipt_count: usize,
}

fn mark_caller_reservation_hold_reserved(fixture: &CapturePendingNonceFixture) {
    let operation = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    let hold_id = fixture.capture_request.hold_id.as_deref().unwrap();
    let admission_binding = fixture
        .capture_request
        .admission_operation
        .as_ref()
        .unwrap();
    let reserved_until = fixture
        .nonce_store
        .get_nonce_reservation(&fixture.operation_id)
        .unwrap()
        .unwrap()
        .signed_expires_at();
    fixture
        .budget_store
        .mark_admission_operation_hold_reserved(
            hold_id,
            admission_binding,
            reserved_until,
            Some("USD"),
            None,
            &ReservedHoldEnvelope {
                budget_total: Some(1_000),
                delegation_depth: 0,
                root_budget_holder: operation.capability_id().to_string(),
            },
        )
        .unwrap();
}

fn caller_reserved_recovery_fixture() -> CapturePendingNonceFixture {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    install_durable_test_receipt_store(&mut kernel, "caller-reservation-recovery-receipts");
    let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .unwrap();
    let budget_store = std::sync::Arc::new(DurableRecoveryBudgetStore::new());
    kernel
        .set_budget_store_handle(budget_store.clone())
        .unwrap();
    let nonce_store = DurableRecoveryNonceStore::new();
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig {
                require_nonce: true,
                ..ExecutionNonceConfig::default()
            },
            Box::new(nonce_store.clone()),
        )
        .unwrap();
    kernel.enable_aggregate_invocation_admission().unwrap();

    let agent = Keypair::generate();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1_000, "USD",
        )]),
        3_600,
    );
    let capability = aggregate_limited_capability(&kernel, &capability, 2);
    let request = reserve_request("caller-reservation-recovery", &capability, &agent);
    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let reserved_until = response.execution_nonce.as_ref().unwrap().expires_at();
    let operation_id = caller_reserved_operation_id(&response).to_string();
    let operation = operation_store.load(&operation_id).unwrap().unwrap();
    assert_eq!(operation.state(), AdmissionOperationState::CallerReserved);
    let hold_id = operation.budget_hold_id().unwrap().to_string();
    let hold = budget_store.get_budget_hold(&hold_id).unwrap().unwrap();
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Open);
    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: operation.capability_id().to_string(),
        grant_index: 0,
        hold_id: Some(hold_id.clone()),
        event_id: Some(format!("{hold_id}:capture-invocations")),
        authority: hold.authority,
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new(
                operation_id.clone(),
                operation.request_binding_hash().to_string(),
            )
            .unwrap(),
        ),
    };
    let kernel_authority = kernel_coordinator_authority_id(&kernel);
    let initial_receipt_count = kernel.receipt_log().receipts().len();
    CapturePendingNonceFixture {
        kernel,
        operation_store,
        nonce_store,
        budget_store,
        operation_id,
        capture_request,
        kernel_authority,
        reserved_until,
        initial_receipt_count,
    }
}

fn assert_signed_caller_reservation_recovery_receipt(
    fixture: &CapturePendingNonceFixture,
    expected_disposition: BudgetHoldDispositionView,
) {
    let actions = fixture
        .operation_store
        .load_cleanup_actions(&fixture.operation_id)
        .unwrap();
    let terminal_action = actions
        .iter()
        .find(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        .expect("terminal receipt outbox action");
    assert_eq!(
        terminal_action.state(),
        AdmissionCleanupActionState::Completed
    );
    let payload: serde_json::Value =
        serde_json::from_str(terminal_action.payload_json()).unwrap();
    assert_eq!(
        payload["terminalState"],
        AdmissionOperationState::OutcomeUnknownAfterDispatch.as_str()
    );
    assert_eq!(
        payload["terminalDispatchState"],
        AdmissionDispatchState::OutcomeUnknown.as_str()
    );
    let receipt: ChioReceipt = serde_json::from_value(payload["receipt"].clone()).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.kernel_key, fixture.kernel.public_key());
    assert!(matches!(
        receipt.decision.as_ref(),
        Some(Decision::Incomplete { .. })
    ));
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .pointer("/caller_reservation_recovery/hold_disposition")
                    .and_then(serde_json::Value::as_str)
            }),
        Some(expected_disposition.as_str())
    );
    assert_eq!(
        receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .pointer("/protocol_admission/admission_operation/state")
                    .and_then(serde_json::Value::as_str)
            }),
        Some(AdmissionOperationState::OutcomeUnknownAfterDispatch.as_str())
    );
    assert!(fixture
        .kernel
        .receipt_log()
        .receipts()
        .iter()
        .any(|persisted| persisted.id == receipt.id));
}

#[test]
fn caller_reservation_reap_cursor_crosses_more_than_one_bounded_page() {
    let mut kernel = make_admission_saga_kernel();
    let delegate = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    let operations = (0..4_097)
        .map(|index| caller_reap_candidate(&kernel, &format!("bulk-{index:05}")))
        .collect::<Vec<_>>();
    let store = std::sync::Arc::new(ReapInventoryTestStore::new(
        delegate,
        operations,
        std::collections::HashMap::new(),
    ));
    kernel.admission_operation_store = Some(store.clone());

    let first_error = kernel
        .reap_expired_reserved_budget_holds(i64::MAX)
        .expect_err("damaged first page must fail closed")
        .to_string();
    assert!(first_error.contains("4096 failures"));
    assert!(first_error.contains("4080 additional failures omitted"));
    assert!(first_error.len() < 12_000, "diagnostic must remain bounded");

    let second_error = kernel
        .reap_expired_reserved_budget_holds(i64::MAX)
        .expect_err("final damaged row must fail closed")
        .to_string();
    assert!(second_error.contains("1 failures"));
    let pages = store.page_history();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].0, None);
    assert_eq!(pages[0].1.len(), 4_096);
    assert_eq!(pages[1].0.as_deref(), pages[0].1.last().map(String::as_str));
    assert_eq!(pages[1].1.len(), 1);
}

#[test]
fn malformed_signed_handoff_inventory_does_not_starve_a_valid_sibling() {
    let mut fixture = caller_reserved_recovery_fixture();
    let valid = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    let tampered = (0..10_000)
        .map(|index| caller_reap_candidate(&fixture.kernel, &format!("tampered-{index}")))
        .find(|candidate| candidate.operation_id() < valid.operation_id())
        .expect("find an operation id ordered before the valid sibling");
    let tampered_action = AdmissionCleanupAction::pending(
        &tampered,
        AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        &serde_json::json!({"expiresAt": i64::MIN, "tampered": true}),
    )
    .unwrap();
    let mut actions = std::collections::HashMap::new();
    actions.insert(
        tampered.operation_id().to_string(),
        vec![tampered_action],
    );
    let store = std::sync::Arc::new(ReapInventoryTestStore::new(
        fixture.operation_store.clone(),
        vec![tampered.clone(), valid],
        actions,
    ));
    fixture.kernel.admission_operation_store = Some(store);

    let error = fixture
        .kernel
        .reap_expired_reserved_budget_holds(i64::MAX)
        .expect_err("malformed handoff intent must remain visible")
        .to_string();
    assert!(error.contains("1 failures"), "{error}");
    assert_eq!(
        fixture
            .operation_store
            .load(&fixture.operation_id)
            .unwrap()
            .unwrap()
            .state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        "valid sibling terminalizes despite the earlier malformed row"
    );
    assert_eq!(
        fixture
            .kernel
            .admission_operation_store
            .as_ref()
            .unwrap()
            .load(tampered.operation_id())
            .unwrap()
            .unwrap()
            .state(),
        AdmissionOperationState::CallerReserved
    );
    assert_signed_caller_reservation_recovery_receipt(
        &fixture,
        BudgetHoldDispositionView::Expired,
    );
}

#[test]
fn expired_capture_pending_caller_reservations_converge_from_authoritative_capture_state() {
    for capture_committed in [false, true] {
        let fixture = capture_pending_nonce_fixture_with_exposure(
            false,
            100,
            AdmissionOperationState::CallerReservationCapturePending,
        );
        mark_caller_reservation_hold_reserved(&fixture);
        if capture_committed {
            let captured = fixture
                .budget_store
                .capture_invocation_reservations(fixture.capture_request.clone())
                .unwrap();
            assert_eq!(
                captured.invocation_state,
                BudgetInvocationReservationState::Captured
            );
        }

        fixture
            .kernel
            .reap_expired_reserved_budget_holds(i64::MAX)
            .unwrap();
        let operation = fixture
            .operation_store
            .load(&fixture.operation_id)
            .unwrap()
            .unwrap();
        if capture_committed {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            );
            assert_signed_caller_reservation_recovery_receipt(
                &fixture,
                BudgetHoldDispositionView::Expired,
            );
        } else {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            assert!(fixture
                .operation_store
                .load_cleanup_actions(&fixture.operation_id)
                .unwrap()
                .iter()
                .any(|action| {
                    action.kind() == AdmissionCleanupActionKind::TerminalReceipt
                        && action.state() == AdmissionCleanupActionState::Completed
                }));
        }
    }
}

#[test]
fn cold_restart_terminalizes_caller_reserved_operations_after_every_closed_hold_disposition() {
    for expected_disposition in [
        BudgetHoldDispositionView::Reconciled,
        BudgetHoldDispositionView::Released,
    ] {
        let fixture = caller_reserved_recovery_fixture();
        let hold_id = fixture.capture_request.hold_id.clone().unwrap();
        let capability_id = fixture.capture_request.capability_id.clone();
        let authority = fixture.capture_request.authority.clone();
        let admission_binding = fixture.capture_request.admission_operation.clone();
        match expected_disposition {
            BudgetHoldDispositionView::Reconciled => {
                fixture
                    .budget_store
                    .reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id,
                        grant_index: 0,
                        exposed_cost_units: 100,
                        realized_spend_units: 40,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reconcile")),
                        authority: authority.clone(),
                        admission_operation: admission_binding.clone(),
                    })
                    .unwrap();
            }
            BudgetHoldDispositionView::Released => {
                fixture
                    .budget_store
                    .release_budget_hold(BudgetReleaseHoldRequest {
                        capability_id,
                        grant_index: 0,
                        released_exposure_units: 100,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:release")),
                        authority: authority.clone(),
                        admission_operation: admission_binding.clone(),
                    })
                    .unwrap();
            }
            disposition => panic!("unexpected closed disposition: {disposition:?}"),
        }
        assert_eq!(
            fixture
                .budget_store
                .get_budget_hold(&hold_id)
                .unwrap()
                .unwrap()
                .disposition,
            expected_disposition
        );

        assert_eq!(
            fixture
                .kernel
                .recover_nonterminal_admission_kind_with_authorities(
                    fixture.operation_store.as_ref(),
                    fixture.budget_store.as_ref(),
                    None,
                    AdmissionOperationKind::ToolDispatch,
                    &fixture.kernel_authority,
                )
                .unwrap(),
            1
        );
        let recovered = fixture
            .operation_store
            .load(&fixture.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
        assert_eq!(
            recovered.dispatch_state(),
            AdmissionDispatchState::OutcomeUnknown
        );
        assert!(recovered.last_error().is_some_and(|reason| {
            reason.contains(&format!(
                "hold {hold_id} {} without an exact terminal receipt",
                expected_disposition.as_str()
            ))
        }));
        assert_signed_caller_reservation_recovery_receipt(&fixture, expected_disposition);
    }
}

#[test]
fn policy_rotation_recovers_a_closed_caller_reservation_from_its_signed_handoff() {
    let mut fixture = caller_reserved_recovery_fixture();
    let hold_id = fixture.capture_request.hold_id.clone().unwrap();
    fixture
        .budget_store
        .reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: fixture.capture_request.capability_id.clone(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 40,
            hold_id: Some(hold_id.clone()),
            event_id: Some(format!("{hold_id}:old-policy-reconcile")),
            authority: fixture.capture_request.authority.clone(),
            admission_operation: fixture.capture_request.admission_operation.clone(),
        })
        .unwrap();

    let operation_before = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    let hold_before = fixture
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .unwrap();
    let nonce_before = fixture
        .nonce_store
        .get_nonce_reservation(&fixture.operation_id)
        .unwrap();
    fixture.kernel.config.policy_hash = "44".repeat(32);
    fixture
        .kernel
        .validate_caller_reserved_handoff_with_store(
            fixture.operation_store.as_ref(),
            &operation_before,
        )
        .unwrap();

    assert_eq!(
        fixture
            .kernel
            .recover_nonterminal_admission_kind_with_authorities(
                fixture.operation_store.as_ref(),
                fixture.budget_store.as_ref(),
                None,
                AdmissionOperationKind::ToolDispatch,
                &fixture.kernel_authority,
            )
            .unwrap(),
        1
    );
    let recovered = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.policy_hash(), operation_before.policy_hash());
    assert_eq!(
        recovered.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(
        fixture
            .budget_store
            .get_budget_hold(&hold_id)
            .unwrap()
            .unwrap(),
        hold_before
    );
    assert_eq!(
        fixture
            .nonce_store
            .get_nonce_reservation(&fixture.operation_id)
            .unwrap(),
        nonce_before
    );
    assert_signed_caller_reservation_recovery_receipt(
        &fixture,
        BudgetHoldDispositionView::Reconciled,
    );
}

#[test]
fn cold_restart_retains_caller_reserved_operation_while_stamped_hold_is_open() {
    let fixture = caller_reserved_recovery_fixture();
    let hold_id = fixture.capture_request.hold_id.as_deref().unwrap();
    let hold = fixture
        .budget_store
        .get_budget_hold(hold_id)
        .unwrap()
        .unwrap();
    assert_eq!(hold.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(
        hold.reserved_until,
        Some(fixture.reserved_until)
    );

    assert_eq!(
        fixture
            .kernel
            .recover_nonterminal_admission_kind_with_authorities(
                fixture.operation_store.as_ref(),
                fixture.budget_store.as_ref(),
                None,
                AdmissionOperationKind::ToolDispatch,
                &fixture.kernel_authority,
            )
            .unwrap(),
        0
    );
    let retained = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(retained.state(), AdmissionOperationState::CallerReserved);
    assert_eq!(retained.dispatch_state(), AdmissionDispatchState::Committed);
    assert!(fixture
        .operation_store
        .load_cleanup_actions(&fixture.operation_id)
        .unwrap()
        .iter()
        .all(|action| action.kind() != AdmissionCleanupActionKind::TerminalReceipt));
    assert_eq!(
        fixture.kernel.receipt_log().receipts().len(),
        fixture.initial_receipt_count
    );
}

fn capture_pending_nonce_fixture(lose_capture_ack: bool) -> CapturePendingNonceFixture {
    capture_pending_nonce_fixture_with_exposure(
        lose_capture_ack,
        0,
        AdmissionOperationState::CapturePending,
    )
}

fn capture_pending_nonce_fixture_with_exposure(
    lose_capture_ack: bool,
    requested_exposure_units: u64,
    capture_pending_state: AdmissionOperationState,
) -> CapturePendingNonceFixture {
    let mut kernel = make_admission_saga_kernel();
    let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .unwrap();
    let nonce_store = DurableRecoveryNonceStore::new();
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(nonce_store.clone()),
        )
        .unwrap();
    let budget_store = if lose_capture_ack {
        DurableRecoveryBudgetStore::with_capture_ack_loss()
    } else {
        DurableRecoveryBudgetStore::new()
    };
    let operation =
        prepared_admission_operation_with_nonce(&kernel, Some("ordinary-capture-nonce"));
    let kernel_authority = kernel_coordinator_authority_id(&kernel);
    let operation_id = operation.operation_id().to_string();
    let request_binding_hash = operation.request_binding_hash().to_string();
    operation_store.create_prepared(operation.clone()).unwrap();

    let authority = BudgetEventAuthority {
        authority_id: "budget:test".to_string(),
        lease_id: "budget:test#1".to_string(),
        lease_epoch: 1,
    };
    let mut authorization = BudgetAuthorizeHoldRequest::legacy(
        operation.capability_id().to_string(),
        0,
        None,
        requested_exposure_units,
        (requested_exposure_units > 0).then_some(100),
        (requested_exposure_units > 0).then_some(1_000),
        operation.budget_hold_id().map(ToOwned::to_owned),
        Some("hold-admission-store:authorize".to_string()),
        Some(authority.clone()),
    );
    authorization.admission_operation = Some(
        BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash.clone())
            .unwrap(),
    );
    authorization
        .install_verified_invocation_admission(
            crate::budget_store::VerifiedInvocationAdmission::grant_only(
                operation.capability_id(),
                0,
                Some(2),
            )
            .unwrap(),
        )
        .unwrap();
    kernel
        .journal_budget_cleanup(
            &operation,
            &authorization,
            "hold-admission-store:reverse".to_string(),
            "hold-admission-store:capture-invocations".to_string(),
        )
        .unwrap();
    kernel
        .journal_nonce_cleanup(&operation, "ordinary-capture-nonce".to_string())
        .unwrap();
    assert!(budget_store
        .authorize_budget_hold(authorization)
        .unwrap()
        .is_authorized());
    nonce_store
        .reserve_nonce_for_operation(&operation_id, "ordinary-capture-nonce", 10_000)
        .unwrap();
    for (version, state) in [
        (0, AdmissionOperationState::BudgetAuthorized),
        (1, AdmissionOperationState::ReadyToDispatch),
        (2, capture_pending_state),
    ] {
        assert!(matches!(
            operation_store
                .compare_and_swap(AdmissionOperationCompareAndSwap {
                    operation_id: &operation_id,
                    expected_version: version,
                    coordinator_lease_epoch: 1,
                    next_state: state,
                    next_dispatch_state: AdmissionDispatchState::NotStarted,
                    next_coordinator_lease_epoch: 1,
                    last_error: None,
                })
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }
    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: operation.capability_id().to_string(),
        grant_index: 0,
        hold_id: operation.budget_hold_id().map(ToOwned::to_owned),
        event_id: Some("hold-admission-store:capture-invocations".to_string()),
        authority: Some(authority),
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash)
                .unwrap(),
        ),
    };
    CapturePendingNonceFixture {
        kernel,
        operation_store,
        nonce_store,
        budget_store: std::sync::Arc::new(budget_store),
        operation_id,
        capture_request,
        kernel_authority,
        reserved_until: 10_000,
        initial_receipt_count: 0,
    }
}

#[test]
fn admission_operation_requires_an_installed_store() {
    let kernel = make_admission_saga_kernel();
    let error = kernel
        .persist_prepared_admission_operation(prepared_admission_operation(&kernel))
        .unwrap_err();
    assert!(error.to_string().contains("admission operation store"));
}

#[test]
fn single_worker_persists_prepared_operation_idempotently() {
    let mut kernel = make_admission_saga_kernel();
    let store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(store.clone())
        .unwrap();
    let operation = prepared_admission_operation(&kernel);

    assert_eq!(
        kernel
            .persist_prepared_admission_operation(operation.clone())
            .unwrap(),
        operation
    );
    assert_eq!(
        kernel
            .persist_prepared_admission_operation(operation.clone())
            .unwrap(),
        operation
    );
    assert_eq!(
        store.load(operation.operation_id()).unwrap(),
        Some(operation)
    );
}

#[test]
fn kernel_rejects_ephemeral_local_operation_store_as_durable_authority() {
    let mut kernel = make_admission_saga_kernel();
    let error = kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(
            InMemoryAdmissionOperationStore::new(),
        ))
        .unwrap_err();
    assert!(error.to_string().contains("durable"));
}

#[test]
fn multi_worker_configuration_rejects_single_node_durable_operation_store() {
    let mut kernel = make_admission_saga_kernel();
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )))
        .unwrap();
    let error = kernel.set_dispatch_worker_count(2).unwrap_err();
    assert!(error.to_string().contains("shared linearizable"));
}

#[test]
fn multi_worker_configuration_accepts_shared_linearizable_operation_store() {
    let mut kernel = make_admission_saga_kernel();
    kernel
        .set_admission_operation_store_handle(std::sync::Arc::new(ProfiledTestStore::new(
            AdmissionOperationStoreProfile::SharedLinearizable,
        )))
        .unwrap();
    kernel.set_dispatch_worker_count(4).unwrap();
    assert_eq!(
        kernel
            .persist_prepared_admission_operation(prepared_admission_operation(&kernel))
            .unwrap()
            .state(),
        AdmissionOperationState::Prepared
    );
}

#[test]
fn cold_restart_before_ordinary_nonce_reservation_compensates_without_consuming_nonce() {
    let mut kernel = make_admission_saga_kernel();
    let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .unwrap();
    let nonce_store = DurableRecoveryNonceStore::new();
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(nonce_store.clone()),
        )
        .unwrap();
    let operation = prepared_admission_operation_with_nonce(&kernel, Some("ordinary-nonce-before"));
    let operation_id = operation.operation_id().to_string();
    operation_store.create_prepared(operation.clone()).unwrap();
    kernel
        .journal_nonce_cleanup(&operation, "ordinary-nonce-before".to_string())
        .unwrap();
    assert!(matches!(
        operation_store
            .compare_and_swap(AdmissionOperationCompareAndSwap {
                operation_id: &operation_id,
                expected_version: 0,
                coordinator_lease_epoch: 1,
                next_state: AdmissionOperationState::BudgetAuthorized,
                next_dispatch_state: AdmissionDispatchState::NotStarted,
                next_coordinator_lease_epoch: 1,
                last_error: None,
            })
            .unwrap(),
        AdmissionOperationCasOutcome::Applied(_)
    ));

    assert_eq!(
        kernel
            .recover_nonterminal_admission_kind_with_authorities(
                operation_store.as_ref(),
                &InMemoryBudgetStore::new(),
                None,
                AdmissionOperationKind::ToolDispatch,
                &kernel_coordinator_authority_id(&kernel),
            )
            .unwrap(),
        1
    );

    let recovered = operation_store.load(&operation_id).unwrap().unwrap();
    assert_eq!(
        recovered.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(nonce_store
        .get_nonce_reservation(&operation_id)
        .unwrap()
        .is_none());
    let new_owner = "aa".repeat(32);
    let reserved = nonce_store
        .reserve_nonce_for_operation(&new_owner, "ordinary-nonce-before", 10_000)
        .unwrap();
    assert_eq!(reserved.operation_id(), new_owner.as_str());
}

#[test]
fn cold_restart_after_ordinary_nonce_reservation_cancels_permanent_tombstone() {
    let mut kernel = make_admission_saga_kernel();
    let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .unwrap();
    let nonce_store = DurableRecoveryNonceStore::new();
    kernel
        .set_execution_nonce_store(
            ExecutionNonceConfig::default(),
            Box::new(nonce_store.clone()),
        )
        .unwrap();
    let operation = prepared_admission_operation_with_nonce(&kernel, Some("ordinary-nonce-after"));
    let operation_id = operation.operation_id().to_string();
    operation_store.create_prepared(operation.clone()).unwrap();
    kernel
        .journal_nonce_cleanup(&operation, "ordinary-nonce-after".to_string())
        .unwrap();
    assert!(matches!(
        operation_store
            .compare_and_swap(AdmissionOperationCompareAndSwap {
                operation_id: &operation_id,
                expected_version: 0,
                coordinator_lease_epoch: 1,
                next_state: AdmissionOperationState::BudgetAuthorized,
                next_dispatch_state: AdmissionDispatchState::NotStarted,
                next_coordinator_lease_epoch: 1,
                last_error: None,
            })
            .unwrap(),
        AdmissionOperationCasOutcome::Applied(_)
    ));
    nonce_store
        .reserve_nonce_for_operation(&operation_id, "ordinary-nonce-after", 10_000)
        .unwrap();

    assert_eq!(
        kernel
            .recover_nonterminal_admission_kind_with_authorities(
                operation_store.as_ref(),
                &InMemoryBudgetStore::new(),
                None,
                AdmissionOperationKind::ToolDispatch,
                &kernel_coordinator_authority_id(&kernel),
            )
            .unwrap(),
        1
    );

    let reservation = nonce_store
        .get_nonce_reservation(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(reservation.state(), ReplayReservationState::Cancelled);
    assert!(!nonce_store.reserve("ordinary-nonce-after").unwrap());
    assert!(matches!(
        nonce_store.reserve_nonce_for_operation(
            &"bb".repeat(32),
            "ordinary-nonce-after",
            10_000
        ),
        Err(ExecutionNonceReservationError::Conflict(_))
    ));
}

#[test]
fn cold_restart_recovery_compensates_predispatch_and_never_reopens_committed_dispatch() {
    let kernel = make_admission_saga_kernel();
    let kernel_authority = kernel_coordinator_authority_id(&kernel);
    let budget_store = InMemoryBudgetStore::new();

    let predispatch_store =
        ProfiledTestStore::new(AdmissionOperationStoreProfile::SingleNodeDurable);
    let predispatch = prepared_admission_operation(&kernel);
    let predispatch_id = predispatch.operation_id().to_string();
    predispatch_store.create_prepared(predispatch).unwrap();
    assert_eq!(
        kernel
            .recover_nonterminal_admission_kind_with_authorities(
                &predispatch_store,
                &budget_store,
                None,
                AdmissionOperationKind::ToolDispatch,
                &kernel_authority,
            )
            .unwrap(),
        1
    );
    let compensated = predispatch_store.load(&predispatch_id).unwrap().unwrap();
    assert_eq!(
        compensated.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        compensated.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(compensated.coordinator_lease_epoch(), 2);

    let committed_store = ProfiledTestStore::new(AdmissionOperationStoreProfile::SingleNodeDurable);
    let committed = prepared_admission_operation(&kernel);
    let committed_id = committed.operation_id().to_string();
    committed_store.create_prepared(committed).unwrap();
    for (version, state, dispatch) in [
        (
            0,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionDispatchState::NotStarted,
        ),
        (
            1,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionDispatchState::NotStarted,
        ),
        (
            2,
            AdmissionOperationState::CapturePending,
            AdmissionDispatchState::NotStarted,
        ),
        (
            3,
            AdmissionOperationState::DispatchCommitted,
            AdmissionDispatchState::Committed,
        ),
    ] {
        assert!(matches!(
            committed_store
                .compare_and_swap(AdmissionOperationCompareAndSwap {
                    operation_id: &committed_id,
                    expected_version: version,
                    coordinator_lease_epoch: 1,
                    next_state: state,
                    next_dispatch_state: dispatch,
                    next_coordinator_lease_epoch: 1,
                    last_error: None,
                })
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }
    let error = kernel
        .recover_nonterminal_admission_kind_with_authorities(
            &committed_store,
            &budget_store,
            None,
            AdmissionOperationKind::ToolDispatch,
            &kernel_authority,
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("has no signed terminal receipt outbox"));
    let reconciled = committed_store.load(&committed_id).unwrap().unwrap();
    assert_eq!(
        reconciled.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        reconciled.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(reconciled.coordinator_lease_epoch(), 2);

    let active_store = ProfiledTestStore::new(AdmissionOperationStoreProfile::SingleNodeDurable);
    let active = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: "executor:test".to_string(),
        request_id: "active-response-restart".to_string(),
        capability_id: "active-response-capability".to_string(),
        authorization_capability_hash: "55".repeat(32),
        request_binding_hash: "66".repeat(32),
        policy_hash: kernel.config.policy_hash.clone(),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some("88".repeat(32)),
        execution_nonce_id: None,
        coordinator_lease_epoch: 9,
    })
    .unwrap();
    let active_id = active.operation_id().to_string();
    active_store.create_prepared(active).unwrap();
    kernel
        .recover_nonterminal_admission_kind_with_authorities(
            &active_store,
            &budget_store,
            None,
            AdmissionOperationKind::GovernedActiveResponse,
            "executor:test",
        )
        .unwrap();
    assert_eq!(
        active_store.load(&active_id).unwrap().unwrap().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
}

#[test]
fn cold_restart_capture_pending_queries_then_finishes_without_redispatch() {
    let mut kernel = make_admission_saga_kernel();
    let operation_store = std::sync::Arc::new(ProfiledTestStore::new(
        AdmissionOperationStoreProfile::SingleNodeDurable,
    ));
    kernel
        .set_admission_operation_store_handle(operation_store.clone())
        .unwrap();
    let budget_store = DurableRecoveryBudgetStore::new();
    let operation = prepared_admission_operation(&kernel);
    let kernel_authority = kernel_coordinator_authority_id(&kernel);
    let operation_id = operation.operation_id().to_string();
    let request_binding_hash = operation.request_binding_hash().to_string();
    operation_store.create_prepared(operation.clone()).unwrap();

    let authority = BudgetEventAuthority {
        authority_id: "budget:test".to_string(),
        lease_id: "budget:test#1".to_string(),
        lease_epoch: 1,
    };
    let mut authorization = BudgetAuthorizeHoldRequest::legacy(
        operation.capability_id().to_string(),
        0,
        None,
        0,
        None,
        None,
        operation.budget_hold_id().map(ToOwned::to_owned),
        Some("hold-admission-store:authorize".to_string()),
        Some(authority.clone()),
    );
    authorization.admission_operation = Some(
        BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash.clone())
            .unwrap(),
    );
    authorization
        .install_verified_invocation_admission(
            crate::budget_store::VerifiedInvocationAdmission::grant_only(
                operation.capability_id(),
                0,
                Some(2),
            )
            .unwrap(),
        )
        .unwrap();
    kernel
        .journal_budget_cleanup(
            &operation,
            &authorization,
            "hold-admission-store:reverse".to_string(),
            "hold-admission-store:capture-invocations".to_string(),
        )
        .unwrap();
    assert!(budget_store
        .authorize_budget_hold(authorization)
        .unwrap()
        .is_authorized());
    for (version, state) in [
        (0, AdmissionOperationState::BudgetAuthorized),
        (1, AdmissionOperationState::ReadyToDispatch),
        (2, AdmissionOperationState::CapturePending),
    ] {
        assert!(matches!(
            operation_store
                .compare_and_swap(AdmissionOperationCompareAndSwap {
                    operation_id: &operation_id,
                    expected_version: version,
                    coordinator_lease_epoch: 1,
                    next_state: state,
                    next_dispatch_state: AdmissionDispatchState::NotStarted,
                    next_coordinator_lease_epoch: 1,
                    last_error: None,
                })
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }
    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: operation.capability_id().to_string(),
        grant_index: 0,
        hold_id: operation.budget_hold_id().map(ToOwned::to_owned),
        event_id: Some("hold-admission-store:capture-invocations".to_string()),
        authority: Some(authority),
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash)
                .unwrap(),
        ),
    };
    assert_eq!(
        budget_store
            .query_invocation_capture(&capture_request)
            .unwrap(),
        None
    );
    let error = kernel
        .recover_nonterminal_admission_kind_with_authorities(
            operation_store.as_ref(),
            &budget_store,
            None,
            AdmissionOperationKind::ToolDispatch,
            &kernel_authority,
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("without a signed terminal response"));
    let captured = budget_store
        .query_invocation_capture(&capture_request)
        .unwrap()
        .expect("capture recovery should persist the exact event");
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    let recovered = operation_store.load(&operation_id).unwrap().unwrap();
    assert_eq!(
        recovered.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        recovered.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(recovered.coordinator_lease_epoch(), 2);
}

#[test]
fn capture_pending_recovery_commits_reserved_ordinary_nonce_before_capture() {
    let fixture = capture_pending_nonce_fixture(false);
    assert_eq!(
        fixture
            .nonce_store
            .get_nonce_reservation(&fixture.operation_id)
            .unwrap()
            .unwrap()
            .state(),
        ReplayReservationState::Reserved
    );
    assert_eq!(
        fixture
            .budget_store
            .query_invocation_capture(&fixture.capture_request)
            .unwrap(),
        None
    );

    let recovery_error = fixture
        .kernel
        .recover_nonterminal_admission_kind_with_authorities(
            fixture.operation_store.as_ref(),
            fixture.budget_store.as_ref(),
            None,
            AdmissionOperationKind::ToolDispatch,
            &fixture.kernel_authority,
        )
        .unwrap_err();
    assert!(recovery_error
        .to_string()
        .contains("without a signed terminal response"));

    let recovered = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(recovered.dispatch_state(), AdmissionDispatchState::Committed);
    assert_eq!(
        fixture
            .nonce_store
            .get_nonce_reservation(&fixture.operation_id)
            .unwrap()
            .unwrap()
            .state(),
        ReplayReservationState::Committed
    );
    assert!(fixture
        .budget_store
        .query_invocation_capture(&fixture.capture_request)
        .unwrap()
        .is_some());
    let nonce_action = fixture
        .operation_store
        .load_cleanup_actions(&fixture.operation_id)
        .unwrap()
        .into_iter()
        .find(|action| action.kind() == AdmissionCleanupActionKind::ExecutionNonce)
        .unwrap();
    assert_eq!(nonce_action.state(), AdmissionCleanupActionState::Completed);
}

#[test]
fn capture_ack_loss_recovery_preserves_precommitted_ordinary_nonce_tombstone() {
    let fixture = capture_pending_nonce_fixture(true);
    let capture_pending = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    fixture
        .kernel
        .commit_admission_execution_nonce(&capture_pending)
        .unwrap();
    fixture
        .kernel
        .discharge_admission_cleanup_action(
            &capture_pending,
            AdmissionCleanupActionKind::ExecutionNonce,
        )
        .unwrap();
    assert_eq!(
        fixture
            .nonce_store
            .get_nonce_reservation(&fixture.operation_id)
            .unwrap()
            .unwrap()
            .state(),
        ReplayReservationState::Committed
    );

    let capture_error = fixture
        .budget_store
        .capture_invocation_reservations(fixture.capture_request.clone())
        .unwrap_err();
    assert!(capture_error
        .to_string()
        .contains("capture acknowledgement loss"));
    assert!(fixture
        .budget_store
        .query_invocation_capture(&fixture.capture_request)
        .unwrap()
        .is_some());

    let recovery_error = fixture
        .kernel
        .recover_nonterminal_admission_kind_with_authorities(
            fixture.operation_store.as_ref(),
            fixture.budget_store.as_ref(),
            None,
            AdmissionOperationKind::ToolDispatch,
            &fixture.kernel_authority,
        )
        .unwrap_err();
    assert!(recovery_error
        .to_string()
        .contains("without a signed terminal response"));

    let recovered = fixture
        .operation_store
        .load(&fixture.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state(), AdmissionOperationState::DispatchCommitted);
    assert_eq!(recovered.dispatch_state(), AdmissionDispatchState::Committed);
    assert_eq!(
        fixture
            .nonce_store
            .get_nonce_reservation(&fixture.operation_id)
            .unwrap()
            .unwrap()
            .state(),
        ReplayReservationState::Committed
    );
    let nonce_action = fixture
        .operation_store
        .load_cleanup_actions(&fixture.operation_id)
        .unwrap()
        .into_iter()
        .find(|action| action.kind() == AdmissionCleanupActionKind::ExecutionNonce)
        .unwrap();
    assert_eq!(nonce_action.state(), AdmissionCleanupActionState::Completed);
    assert!(!fixture
        .nonce_store
        .reserve("ordinary-capture-nonce")
        .unwrap());
    assert!(matches!(
        fixture.nonce_store.reserve_nonce_for_operation(
            &"cc".repeat(32),
            "ordinary-capture-nonce",
            10_000
        ),
        Err(ExecutionNonceReservationError::Conflict(_))
    ));
}
