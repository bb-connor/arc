use super::*;
use chio_security_types::{ResponseExecutionBinding, ResponseExecutionMode, ResponsePlan};

fn simulated_copy(plan: &ResponsePlan) -> ResponsePlan {
    let mut plan = plan.clone();
    plan.execution = ResponseExecutionBinding::new(ResponseExecutionMode::DryRun);
    let body = serde_json::to_value(plan.authorization_body())
        .unwrap_or_else(|error| panic!("dry-run authorization body: {error}"));
    plan.plan_hash = Digest32::new(
        *chio_core::capability::governance::GovernedResponsePlanIntentBody::compute_plan_body_digest(
            &body,
        )
        .unwrap_or_else(|error| panic!("dry-run authorization hash: {error}"))
        .as_bytes(),
    );
    plan
}

fn assert_mode_denied(error: chio_kernel::KernelError, boundary: &str) {
    use std::error::Error;
    assert_eq!(
        error.report().code,
        "urn:chio:error:kernel:response-dispatch-execution-mode",
        "{boundary}",
    );
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<chio_security_types::DispatchRejection>()),
        Some(&chio_security_types::DispatchRejection::ExecutionMode {
            observed: ResponseExecutionMode::DryRun,
        }),
        "{boundary}",
    );
}

#[test]
fn response_dispatch_refusal_fresh_admission_preserves_execution_mode_code_and_source() {
    let fixture = real_adapter_fixture_for_mode(ResponseExecutionMode::DryRun, true);
    let error = rejected(
        fixture
            .artifacts
            .clone()
            .into_admission_request(fixture.plan.response_plan().clone()),
        "fresh admission must refuse dry-run execution",
    );
    assert_mode_denied(error, "fresh admission");
    super::response_dry_run::assert_dry_run_untouched(&fixture);
}

#[test]
fn dry_run_committed_admission_cannot_resume_live_execution() {
    let fixture = real_adapter_fixture();
    let prepared = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .unwrap_or_else(|error| panic!("prepare live admission: {error}"));
    let binding = prepared
        .durable_dispatch_binding(fixture.plan.response_plan())
        .unwrap_or_else(|error| panic!("durable live binding: {error}"));
    let failure = rejected(
        fixture
            .runtime
            .coordinator
            .execute_prepared(&fixture.plan, prepared),
        "fixture must stop after committing admission and before dispatch",
    );
    assert_eq!(failure.kind(), PortErrorKind::Unavailable);
    assert_eq!(fixture.runtime.effects.executions(), 0);
    let before = real_adapter_mutation_snapshot(&fixture.paths);
    let calls = fixture.runtime.executor.calls();
    let simulated = simulated_copy(fixture.plan.response_plan());
    let error = rejected(
        fixture
            .runtime
            .kernel
            .resume_dispatch_committed_active_response(&simulated, &binding),
        "committed admission must reject simulated authority",
    );
    assert_mode_denied(error, "dispatch-committed resume");
    assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), before);
    assert_eq!(fixture.runtime.executor.calls(), calls);
    assert_eq!(fixture.runtime.effects.executions(), 0);

    // The durable live admission is intact and reaches its real effect once.
    let resumed = fixture
        .runtime
        .kernel
        .resume_dispatch_committed_active_response(fixture.plan.response_plan(), &binding)
        .unwrap_or_else(|error| panic!("resume original live admission: {error}"));
    assert!(matches!(
        resumed,
        chio_kernel::DispatchCommittedActiveResponseResume::Completed(_)
    ));
    assert_eq!(fixture.runtime.effects.executions(), 1);
}

#[test]
fn dry_run_committed_dispatch_cannot_recover_live_execution() {
    let fixture = real_adapter_fixture();
    fixture
        .runtime
        .executor
        .fail_before_effect_once
        .store(false, Ordering::Release);
    let prepared = fixture
        .runtime
        .coordinator
        .prepare_admission(&fixture.plan, fixture.artifacts.clone())
        .unwrap_or_else(|error| panic!("prepare live dispatch: {error}"));
    let binding = prepared
        .durable_dispatch_binding(fixture.plan.response_plan())
        .unwrap_or_else(|error| panic!("durable live dispatch binding: {error}"));
    fixture
        .runtime
        .coordinator
        .execute_prepared(&fixture.plan, prepared)
        .unwrap_or_else(|error| panic!("commit original live dispatch: {error}"));
    assert_eq!(fixture.runtime.effects.executions(), 1);
    let before = real_adapter_mutation_snapshot(&fixture.paths);
    let calls = fixture.runtime.executor.calls();
    let error = rejected(
        fixture.runtime.kernel.recover_committed_active_response(
            &simulated_copy(fixture.plan.response_plan()),
            &binding.dispatch_id,
        ),
        "committed dispatch must reject simulated authority",
    );
    assert_mode_denied(error, "committed recovery");
    assert_eq!(real_adapter_mutation_snapshot(&fixture.paths), before);
    assert_eq!(fixture.runtime.executor.calls(), calls);
    assert_eq!(fixture.runtime.effects.executions(), 1);

    let recovered = fixture
        .runtime
        .kernel
        .recover_committed_active_response(fixture.plan.response_plan(), &binding.dispatch_id)
        .unwrap_or_else(|error| panic!("recover original live dispatch: {error}"));
    assert!(recovered.is_some());
    assert_eq!(fixture.runtime.effects.executions(), 1);
}

#[test]
fn planning_outbox_rejects_execution_mode_changes_before_artifact_binding() {
    for mode in [ResponseExecutionMode::DryRun, ResponseExecutionMode::Live] {
        let fixture = real_adapter_fixture_for_mode(mode, true);
        let store = Arc::new(
            SqliteSecurityStateStore::open(&fixture.paths.responses)
                .unwrap_or_else(|error| panic!("response outbox: {error}")),
        );
        publish_recovery_batch(store.as_ref(), std::slice::from_ref(&fixture.finding));
        let publication =
            crate::security::event_consumer::build_attested_finding_response_plan_publication(
                &fixture.plan,
            )
            .unwrap_or_else(|error| panic!("response publication: {error}"));
        store
            .publish_attested_finding_response_plan(&publication)
            .unwrap_or_else(|error| panic!("publish response outbox: {error}"));
        let coordinator = match mode {
            ResponseExecutionMode::DryRun => fixture.runtime.coordinator.clone(),
            ResponseExecutionMode::Live => {
                let coordinator = Arc::new(KernelAttestedFindingResponseCoordinator::new_unbound(
                    fixture.runtime.executor.identity(),
                    fixture.clock.clone(),
                    crate::security::ActiveResponseExecutionProfile::DryRun(
                        super::response_dry_run::dry_run_service(&fixture, None),
                    ),
                ));
                coordinator
                    .bind_kernel(Arc::clone(&fixture.runtime.kernel))
                    .unwrap_or_else(|error| panic!("bind replacement host: {error}"));
                coordinator
            }
        };
        let planner = recovery_planner(
            store.clone(),
            std::slice::from_ref(&fixture.finding),
            Arc::new(super::response_dry_run::DryRunFixturePolicy {
                artifacts: fixture.artifacts.clone(),
                authority: fixture.submission_authority.public_key(),
            }),
            coordinator,
            fixture.clock.clone(),
        );
        let error = rejected(
            planner.resume_incomplete_pass(16),
            "recovery must refuse the host mode switch",
        );
        assert_eq!(error.kind(), PortErrorKind::InvalidData);
        assert_eq!(error.code(), PortError::invalid_data().code());
        let row = store
            .load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
                tenant_id: fixture.plan.response_plan().tenant_id.clone(),
                action_id: fixture.plan.response_plan().action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load rejected outbox: {error}"))
            .unwrap_or_else(|| panic!("rejected outbox missing"));
        assert_eq!(
            row.admission_state,
            AttestedFindingResponseAdmissionState::Rejected
        );
        assert_eq!(
            row.last_error_code,
            Some(PortError::invalid_data().code().clone())
        );
        assert!(
            row.admission_artifact_digest.is_none(),
            "mode switch bound admission artifacts"
        );
        assert!(row.prepared_dispatch_binding.is_none());
        assert!(row.execution_dispatch_id.is_none());
        super::response_dry_run::assert_dry_run_untouched(&fixture);
    }
}
