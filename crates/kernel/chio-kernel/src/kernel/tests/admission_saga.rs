use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetEventAuthority, BudgetHoldMutationDecision, BudgetInvocationReservationState,
    BudgetReverseHoldRequest, BudgetUsageRecord,
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
}

struct CapturePendingNonceFixture {
    kernel: ChioKernel,
    operation_store: std::sync::Arc<ProfiledTestStore>,
    nonce_store: DurableRecoveryNonceStore,
    budget_store: DurableRecoveryBudgetStore,
    operation_id: String,
    capture_request: BudgetCaptureInvocationRequest,
    kernel_authority: String,
}

fn capture_pending_nonce_fixture(lose_capture_ack: bool) -> CapturePendingNonceFixture {
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
    CapturePendingNonceFixture {
        kernel,
        operation_store,
        nonce_store,
        budget_store,
        operation_id,
        capture_request,
        kernel_authority,
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
            &fixture.budget_store,
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
            &fixture.budget_store,
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
