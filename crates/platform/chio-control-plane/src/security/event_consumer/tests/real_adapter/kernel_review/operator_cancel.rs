//! Operator cancellation of a governed preparation whose threshold approval
//! already committed, using real signed artifacts and SQLite stores.
use super::*;
use chio_kernel::security_admission_operation::{
    AdmissionCleanupActionKind, AdmissionDispatchState,
};

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
        .unwrap()
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
        .unwrap();
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
        .unwrap()
        .unwrap();
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
            .unwrap()
            .unwrap()
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
        .unwrap();
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
        .unwrap()
        .unwrap();
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
            .unwrap(),
        committed_approval
    );
    assert_eq!(approval_rows(&fixture.paths), approvals_before);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);

    let binding = prepared.durable_dispatch_binding(&plan).unwrap();
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
        let completed = cold.admission_operations.load(&id).unwrap().unwrap();
        assert_eq!(completed.state(), AdmissionOperationState::Completed);
        assert_eq!(
            completed.dispatch_state(),
            AdmissionDispatchState::EffectCompleted
        );
        assert_eq!(
            cold.approvals.get_approval_reservation(&id).unwrap(),
            committed_approval
        );
        assert_eq!(approval_rows(&fixture.paths), approvals_before);
    }
    assert_eq!(total_effects, 1);
}
