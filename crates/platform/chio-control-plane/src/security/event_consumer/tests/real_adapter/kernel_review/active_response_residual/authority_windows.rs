use super::*;

const SECOND_LOOKUP_OUTAGE: &str =
    "injected executor outage only after governed operation creation";

struct SecondLookupFault {
    inner: Arc<dyn ActiveResponseExecutorAuthority>,
    armed: Arc<AtomicBool>,
    readiness_calls: Arc<AtomicUsize>,
}

impl ActiveResponseExecutorAuthority for SecondLookupFault {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.inner.identity()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        if self.armed.load(Ordering::Acquire)
            && self.readiness_calls.fetch_add(1, Ordering::AcqRel) == 1
        {
            return Err(ActiveResponseExecutorError::NotReady(
                SECOND_LOOKUP_OUTAGE.to_owned(),
            ));
        }
        self.inner.ensure_ready()
    }

    fn claim_automatic_preparation(
        &self,
        response_plan: &chio_security_types::ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<PreparedActiveResponseDispatchBinding, ActiveResponseExecutorError> {
        self.inner
            .claim_automatic_preparation(response_plan, binding)
    }

    fn load_committed_active_response_dispatch(
        &self,
        tenant: &TenantId,
        dispatch: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        self.inner
            .load_committed_active_response_dispatch(tenant, dispatch)
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        plan: &chio_security_types::ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        self.inner
            .fence_uncommitted_automatic_dispatch(plan, binding)
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<chio_kernel::ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.inner.execute_active_response(request)
    }
}

#[test]
fn second_executor_identity_outage_stays_retryable_after_prepared_row_creation() {
    let armed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = |inner| {
        Arc::new(SecondLookupFault {
            inner,
            armed: Arc::clone(&armed),
            readiness_calls: Arc::clone(&calls),
        }) as Arc<dyn ActiveResponseExecutorAuthority>
    };
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            executor_authority: Some(&executor),
            ..Default::default()
        },
    );
    let replay_before = real_adapter_budget_and_replay_snapshot(&fixture.paths);
    armed.store(true, Ordering::Release);

    let refused = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .test_unwrap_err();

    assert_eq!(
        calls.load(Ordering::Acquire),
        2,
        "failure must occur only at the second readiness lookup"
    );
    assert_eq!(
        real_adapter_table_count(&fixture.paths.admission_operations, "admission_operations"),
        1
    );
    let connection = Connection::open(&fixture.paths.admission_operations).test_unwrap();
    let id: String = connection
        .query_row("SELECT operation_id FROM admission_operations", [], |row| {
            row.get(0)
        })
        .test_unwrap();
    let operation = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(operation.state(), AdmissionOperationState::Prepared);
    assert_eq!(
        operation.dispatch_state(),
        AdmissionDispatchState::NotStarted
    );
    assert_eq!(
        fixture
            .runtime
            .approvals
            .get_approval_reservation(&id)
            .test_unwrap(),
        None
    );
    assert!(fixture
        .runtime
        .admission_operations
        .load_cleanup_actions(&id)
        .test_unwrap()
        .is_empty());
    assert_eq!(
        real_adapter_budget_and_replay_snapshot(&fixture.paths),
        replay_before
    );
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_eq!(
        refused.kind(),
        PortErrorKind::Unavailable,
        "second lookup was classified as terminal: {refused:?}"
    );
    assert_eq!(refused.code().as_str(), "CHIO-KERNEL-INTERNAL");

    armed.store(false, Ordering::Release);
    let retry = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .test_unwrap();
    assert_eq!(real_adapter_prepared_operation_id(&retry), id);
    let reserved = fixture
        .runtime
        .admission_operations
        .load(&id)
        .test_unwrap()
        .test_unwrap();
    assert!(reserved.has_same_prepared_binding(&operation));
    assert_eq!(reserved.state(), AdmissionOperationState::ApprovalReserved);
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
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn exact_original_operator_capability_expiry_compensates_reserved_approval() {
    let (_initial_time, fixture) = stable_fixture(true);
    let request = fixture.native_request();
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let expires_at = request.authorization().operator_capability().expires_at;
    let _expired = chio_test_support::clock::scope_unix_secs(expires_at);
    assert_eq!(
        fixture
            .runtime
            .kernel
            .authority_clock_reading()
            .test_unwrap()
            .unix_millis()
            .get(),
        expires_at * 1_000
    );
    assert_eq!(
        request
            .response_plan()
            .operator_capability
            .expires_at_unix_ms,
        expires_at * 1_000
    );

    let refused = fixture
        .runtime
        .kernel
        .commit_prepared_active_response_admission(request, &prepared);

    let operation = fixture
        .runtime
        .admission_operations
        .load(operation_id(&prepared))
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch,
        "the original's authentic capability expiry stranded its reservation: {refused:?}"
    );
    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "{refused:?}"
    );
    assert_compensated(&fixture, &prepared);
}

fn install_fresh_revocation_view(fixture: &mut RealAdapterFixture) {
    let coordinator = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
        fixture.runtime.executor.identity(),
        Arc::clone(&fixture.clock) as Arc<dyn Clock>,
        crate::security::ActiveResponseExecutionProfile::Live,
    ));
    let previous = std::mem::replace(&mut fixture.runtime.coordinator, Arc::clone(&coordinator));
    drop(previous);
    // The installed setter supplies the concrete RevocationView type. This
    // exercises the real kernel-core cache without another crate dependency.
    let view = Arc::new(Default::default());
    Arc::get_mut(&mut fixture.runtime.kernel)
        .test_expect("exclusive fixture kernel")
        .set_revocation_view(Arc::clone(&view));
    let mut snapshot = (*view.load()).clone();
    snapshot.epoch = 1;
    snapshot.root_hash = [0x21; 32];
    snapshot.issued_at_unix_ms = fixture
        .runtime
        .kernel
        .authority_clock_reading()
        .test_unwrap()
        .unix_millis()
        .get();
    view.install_if_newer(snapshot).test_unwrap();
    coordinator
        .bind_kernel(Arc::clone(&fixture.runtime.kernel))
        .test_unwrap();
}

fn revoke_original_leaf_in_installed_view(fixture: &RealAdapterFixture) {
    let view = fixture.runtime.kernel.revocation_view().test_unwrap();
    let mut snapshot = (*view.load()).clone();
    snapshot.epoch = 2;
    snapshot.root_hash = [0x22; 32];
    let leaf = fixture
        .native_request()
        .authorization()
        .operator_capability()
        .id
        .clone();
    assert!(snapshot.revoked.insert(leaf.clone().into()));
    view.install_if_newer(snapshot).test_unwrap();
    assert_eq!(view.current_epoch(), 2);
    assert!(view.load().revoked.contains(&leaf.into()));
    let denied = fixture
        .runtime
        .kernel
        .verify_active_response_authorization(fixture.native_request().authorization())
        .test_unwrap_err();
    assert!(
        matches!(denied, KernelError::CapabilityRevoked(ref id)
        if id == &fixture.native_request().authorization().operator_capability().id),
        "{denied:?}"
    );
}

fn exercise_installed_view_leaf_revocation(governed: bool, commit: bool) {
    let (_initial_time, mut fixture) = stable_fixture(governed);
    install_fresh_revocation_view(&mut fixture);
    let request = fixture.native_request();
    assert!(request
        .authorization()
        .operator_capability()
        .delegation_chain
        .is_empty());
    let prepared = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = prepared
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    revoke_original_leaf_in_installed_view(&fixture);

    let outcome = if commit {
        fixture
            .runtime
            .kernel
            .commit_prepared_active_response_admission(request, &prepared)
    } else {
        fixture
            .runtime
            .kernel
            .terminate_never_committed_active_response(
                request.response_plan(),
                &binding,
                Some(request),
            )
    };

    if governed {
        let operation = fixture
            .runtime
            .admission_operations
            .load(operation_id(&prepared))
            .test_unwrap()
            .test_unwrap();
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch,
            "exact bound leaf revocation in the installed view was not terminalized: {outcome:?}"
        );
        assert_compensated(&fixture, &prepared);
    } else {
        assert_eq!(
            real_adapter_table_count(
                &fixture.paths.responses,
                "security_response_dispatch_fences"
            ),
            1,
            "exact bound leaf revocation in the installed view was not fenced: {outcome:?}"
        );
    }
    if commit {
        assert!(
            matches!(outcome, Err(KernelError::CapabilityRevoked(ref id))
            if id == &request.authorization().operator_capability().id),
            "{outcome:?}"
        );
    } else {
        assert!(outcome.is_ok(), "{outcome:?}");
    }
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn original_leaf_revocation_in_installed_view_compensates_governed_commit() {
    exercise_installed_view_leaf_revocation(true, true);
}

#[test]
fn original_leaf_revocation_in_installed_view_fences_automatic_termination() {
    exercise_installed_view_leaf_revocation(false, false);
}

#[test]
fn original_leaf_revocation_in_installed_view_compensates_governed_termination() {
    exercise_installed_view_leaf_revocation(true, false);
}
