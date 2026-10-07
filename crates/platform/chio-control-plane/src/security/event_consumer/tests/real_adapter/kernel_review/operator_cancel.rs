//! Operator cancellation of a governed preparation whose threshold approval
//! already committed, using real signed artifacts and SQLite stores.
use super::*;
use chio_kernel::security_admission_operation::{
    AdmissionCleanupActionKind, AdmissionDispatchState,
};
use chio_test_support::prelude::TestResultOk;

const OPERATOR_CANCEL_REASON: &str = "operator cancelled the governed response";

/// Fails the next DispatchCommitted transition before the store applies it.
struct DispatchCommitCasFault {
    inner: Arc<SqliteSecurityAdmissionOperationStore>,
    fail_next: Arc<AtomicBool>,
}

impl AdmissionOperationStore for DispatchCommitCasFault {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.inner.authority_profile()
    }
    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(self.inner.as_ref())
    }
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
    }
    fn load(&self, id: &str) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(id)
    }
    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        authority: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.inner.count_unresolved_by_authority(kind, authority)
    }
    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if request.next_state == AdmissionOperationState::DispatchCommitted
            && self.fail_next.swap(false, Ordering::AcqRel)
        {
            return Err(AdmissionOperationError::Unavailable(
                "injected dispatch commitment CAS failure".into(),
            ));
        }
        self.inner.compare_and_swap(request)
    }
    fn load_cleanup_actions(
        &self,
        id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        self.inner.load_cleanup_actions(id)
    }
}

fn dispatch_commit_fault_fixture(fail_next: &Arc<AtomicBool>) -> RealAdapterFixture {
    let decorate = |inner| {
        Arc::new(DispatchCommitCasFault {
            inner,
            fail_next: fail_next.clone(),
        }) as Arc<dyn AdmissionOperationStore>
    };
    real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            operations: Some(&decorate),
            ..Default::default()
        },
    )
}

fn terminal_receipt_actions(store: &SqliteSecurityAdmissionOperationStore, id: &str) -> usize {
    store
        .load_cleanup_actions(id)
        .test_unwrap()
        .iter()
        .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        .count()
}

fn approval_rows(paths: &RealAdapterPaths) -> [u64; 3] {
    [
        real_adapter_table_count(&paths.approvals, "chio_hitl_operation_reservations"),
        real_adapter_table_count(&paths.approvals, "chio_hitl_operation_reservation_tokens"),
        real_adapter_table_count(&paths.approvals, "chio_hitl_consumed_tokens"),
    ]
}

/// Prepares through the public path, commits the real threshold approval and
/// then fails only the operation DispatchCommitted CAS before it applies.
fn committed_approval_window(
    fixture: &RealAdapterFixture,
    fail_next: &AtomicBool,
) -> chio_kernel::PreparedActiveResponseAdmission {
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let id = operation_id(&prepared);
    fail_next.store(true, Ordering::Release);
    let commit = fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(request, &prepared);
    assert!(
        matches!(commit, Err(chio_kernel::KernelError::Internal(_))),
        "{commit:?}"
    );
    assert!(
        !fail_next.load(Ordering::Acquire),
        "the DispatchCommitted CAS was not reached"
    );
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(operation.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    prepared
}

#[test]
fn operator_cancel_cannot_compensate_already_committed_threshold_approval() {
    let fail_next = Arc::new(AtomicBool::new(false));
    let fixture = dispatch_commit_fault_fixture(&fail_next);
    let plan = fixture.native_request().response_plan().clone();
    let prepared = committed_approval_window(&fixture, &fail_next);
    let id = operation_id(&prepared).to_owned();
    let chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed preparation required");
    };
    let committed_approval = fixture
        .runtime
        .approvals
        .get_approval_reservation(&id)
        .test_unwrap();
    let approvals_before = approval_rows(&fixture.paths);

    let cancels = [
        fixture
            .runtime
            .kernel
            .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON),
        fixture
            .runtime
            .kernel
            .cancel_active_response_admission(reservation, OPERATOR_CANCEL_REASON),
    ];
    let operation = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DispatchCommitted,
        "public cancellation compensated an already committed approval: {cancels:?}"
    );
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(
        terminal_receipt_actions(&fixture.runtime.admission_operations, &id),
        0
    );
    for cancel in &cancels {
        assert!(
            matches!(
                cancel,
                Err(chio_kernel::KernelError::Internal(reason))
                    if reason.contains("after active-response dispatch commitment")
            ),
            "{cancel:?}"
        );
    }
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(&id)
            .test_unwrap(),
        committed_approval
    );
    assert_eq!(approval_rows(&fixture.paths), approvals_before);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);

    let binding = prepared.durable_dispatch_binding(&plan).test_unwrap();
    drop(fixture.runtime);
    let mut total_effects = 0;
    for expected_new_effects in [1, 0] {
        let cold = build_real_adapter_runtime(
            &fixture.paths,
            &fixture.operator_authority,
            &fixture.executor_signer,
            &fixture.submission_authority,
            &fixture.threshold_policy_authority,
            &fixture.threshold_requirement,
            &fixture.finding,
            &plan,
            Arc::clone(&fixture.clock),
            false,
        );
        let resumed = cold
            .kernel
            .resume_dispatch_committed_active_response(&plan, &binding)
            .unwrap_or_else(|error| panic!("resume the committed response: {error:?}"));
        let chio_kernel::DispatchCommittedActiveResponseResume::Completed(evidence) = resumed
        else {
            panic!("reopened stores lost the committed response");
        };
        assert_eq!(evidence.dispatch_id(), &binding.dispatch_id);
        assert_eq!(cold.effects.executions(), expected_new_effects);
        total_effects += cold.effects.executions();
        let completed = cold
            .admission_operations
            .load(&id)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(completed.state(), AdmissionOperationState::Completed);
        assert_eq!(
            completed.dispatch_state(),
            AdmissionDispatchState::EffectCompleted
        );
        assert_eq!(
            cold.approvals.get_approval_reservation(&id).test_unwrap(),
            committed_approval
        );
        assert_eq!(approval_rows(&fixture.paths), approvals_before);
    }
    assert_eq!(total_effects, 1);
}

/// Reports the exact approval reservation under a different approval set while
/// armed. The durable reservation is never changed.
struct SubstitutedApprovalBinding {
    inner: Arc<SqliteApprovalStore>,
    substitute: Arc<AtomicBool>,
}

impl ApprovalStore for SubstitutedApprovalBinding {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        self.inner.authority_profile()
    }
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        self.inner.store_pending(request)
    }
    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        self.inner.get_pending(id)
    }
    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        self.inner.list_pending(filter)
    }
    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        self.inner.resolve(id, decision)
    }
    fn count_approved(&self, subject: &str, policy: &str) -> Result<u64, ApprovalStoreError> {
        self.inner.count_approved(subject, policy)
    }
    fn record_consumed(&self, token: &str, hash: &str, now: u64) -> Result<(), ApprovalStoreError> {
        self.inner.record_consumed(token, hash, now)
    }
    fn is_consumed(&self, token: &str, hash: &str) -> Result<bool, ApprovalStoreError> {
        self.inner.is_consumed(token, hash)
    }
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        self.inner.get_resolution(id)
    }
    fn commit_approval_reservation(
        &self,
        id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.commit_approval_reservation(id)
    }
    fn cancel_approval_reservation(
        &self,
        id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.cancel_approval_reservation(id)
    }
    fn reserve_approval_set(
        &self,
        id: &str,
        set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.inner.reserve_approval_set(id, set)
    }
    fn get_approval_reservation(
        &self,
        id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        let reservation = self.inner.get_approval_reservation(id)?;
        if !self.substitute.load(Ordering::Acquire) {
            return Ok(reservation);
        }
        reservation
            .map(|reservation| {
                let set = reservation.approval_set();
                let substituted = ApprovalSetReservationInput::new(
                    "ab".repeat(32),
                    set.members().to_vec(),
                    set.proposal_deadline(),
                )?;
                ApprovalReservation::from_persisted_parts(
                    reservation.operation_id().to_owned(),
                    substituted,
                    reservation.state(),
                )
            })
            .transpose()
    }
}

fn reconciliation_fault_fixture(
    fail_next: &Arc<AtomicBool>,
    substitute: &Arc<AtomicBool>,
) -> RealAdapterFixture {
    let operations = |inner| {
        Arc::new(DispatchCommitCasFault {
            inner,
            fail_next: fail_next.clone(),
        }) as Arc<dyn AdmissionOperationStore>
    };
    let approvals = |inner| {
        Arc::new(SubstitutedApprovalBinding {
            inner,
            substitute: substitute.clone(),
        }) as Arc<dyn ApprovalStore>
    };
    real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            operations: Some(&operations),
            approvals: Some(&approvals),
            ..Default::default()
        },
    )
}

/// Asserts the committed window is unchanged: no compensation, no terminal
/// receipt outbox and the durable approval still committed.
fn assert_committed_window_retained(
    fixture: &RealAdapterFixture,
    id: &str,
    operation: &AdmissionOperation,
    approval: &ApprovalReservation,
) {
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(id)
            .test_unwrap()
            .as_ref(),
        Some(operation)
    );
    assert_eq!(
        terminal_receipt_actions(&fixture.runtime.admission_operations, id),
        0
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(id)
            .test_unwrap()
            .as_ref(),
        Some(approval)
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

fn assert_refused_after_reconciliation(
    fixture: &RealAdapterFixture,
    id: &str,
    cancel: Result<(), chio_kernel::KernelError>,
) {
    assert!(
        matches!(
            &cancel,
            Err(chio_kernel::KernelError::Internal(reason))
                if reason.contains("after active-response dispatch commitment")
        ),
        "{cancel:?}"
    );
    let operation = fixture
        .runtime
        .admission_operations
        .load(id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::Committed
    );
    assert_eq!(
        terminal_receipt_actions(&fixture.runtime.admission_operations, id),
        0
    );
}

#[test]
fn operator_cancel_still_compensates_an_uncommitted_reserved_approval() {
    let fixture = real_adapter_fixture();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(fixture.native_request())
        .test_unwrap();
    let id = operation_id(&prepared).to_owned();
    let chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed preparation required");
    };
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(&id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Reserved
    );
    fixture
        .runtime
        .kernel
        .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON)
        .test_unwrap();
    let compensated = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        compensated.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        terminal_receipt_actions(&fixture.runtime.admission_operations, &id),
        1
    );
    let cancelled = fixture
        .runtime
        .approvals
        .get_approval_reservation(&id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(cancelled.state(), ReplayReservationState::Cancelled);

    fixture
        .runtime
        .kernel
        .cancel_active_response_admission(reservation, OPERATOR_CANCEL_REASON)
        .test_unwrap();
    fixture
        .runtime
        .kernel
        .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON)
        .test_unwrap();
    assert_eq!(
        fixture
            .runtime
            .admission_operations
            .load(&id)
            .test_unwrap()
            .as_ref(),
        Some(&compensated)
    );
    assert_eq!(
        terminal_receipt_actions(&fixture.runtime.admission_operations, &id),
        1
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(&id)
            .test_unwrap()
            .as_ref(),
        Some(&cancelled)
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn operator_cancel_propagates_a_reconciliation_store_failure_without_compensating() {
    let fail_next = Arc::new(AtomicBool::new(false));
    let substitute = Arc::new(AtomicBool::new(false));
    let fixture = reconciliation_fault_fixture(&fail_next, &substitute);
    let prepared = committed_approval_window(&fixture, &fail_next);
    let id = operation_id(&prepared).to_owned();
    let chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed preparation required");
    };
    let operation = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    let approval = fixture
        .runtime
        .approvals
        .get_approval_reservation(&id)
        .test_unwrap()
        .test_unwrap();

    fail_next.store(true, Ordering::Release);
    let failed = fixture
        .runtime
        .kernel
        .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON);
    assert!(
        !fail_next.load(Ordering::Acquire),
        "cancellation did not attempt reconciliation"
    );
    assert!(
        matches!(&failed, Err(chio_kernel::KernelError::Internal(reason))
            if reason.contains("injected dispatch commitment CAS failure")),
        "{failed:?}"
    );
    assert_committed_window_retained(&fixture, &id, &operation, &approval);

    let refused = fixture
        .runtime
        .kernel
        .cancel_active_response_admission(reservation, OPERATOR_CANCEL_REASON);
    assert_refused_after_reconciliation(&fixture, &id, refused);
}

#[test]
fn operator_cancel_refuses_a_substituted_approval_binding_without_compensating() {
    let fail_next = Arc::new(AtomicBool::new(false));
    let substitute = Arc::new(AtomicBool::new(false));
    let fixture = reconciliation_fault_fixture(&fail_next, &substitute);
    let prepared = committed_approval_window(&fixture, &fail_next);
    let id = operation_id(&prepared).to_owned();
    let chio_kernel::PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed preparation required");
    };
    let operation = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    let approval = fixture
        .runtime
        .approvals
        .get_approval_reservation(&id)
        .test_unwrap()
        .test_unwrap();

    substitute.store(true, Ordering::Release);
    for refused in [
        fixture
            .runtime
            .kernel
            .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON),
        fixture
            .runtime
            .kernel
            .cancel_active_response_admission(reservation, OPERATOR_CANCEL_REASON),
    ] {
        assert!(
            matches!(&refused, Err(chio_kernel::KernelError::Internal(reason))
                if reason.contains("changed its exact binding")),
            "{refused:?}"
        );
        assert_committed_window_retained(&fixture, &id, &operation, &approval);
    }

    substitute.store(false, Ordering::Release);
    let refused = fixture
        .runtime
        .kernel
        .cancel_prepared_active_response_admission(&prepared, OPERATOR_CANCEL_REASON);
    assert_refused_after_reconciliation(&fixture, &id, refused);
}
