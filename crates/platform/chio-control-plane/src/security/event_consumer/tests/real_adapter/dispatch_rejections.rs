use super::*;
use chio_security_types::ports::ResponseDispatchLease;

#[test]
fn response_dispatch_refusal_lease_code_survives_kernel_operator_outbox_and_evidence() {
    use std::error::Error;
    let fixture = real_adapter_fixture();
    *fixture
        .runtime
        .executor
        .preparation_lease
        .lock()
        .unwrap_or_else(|error| panic!("preparation lease: {error}")) =
        Some(ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("refused-initial-lease")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            lease_expires_at_unix_ms: fixture.plan.response_plan().expires_at_unix_ms + 1,
        });
    let store = Arc::new(
        SqliteSecurityStateStore::open(&fixture.paths.responses)
            .unwrap_or_else(|error| panic!("response outbox store: {error}")),
    );
    publish_recovery_batch(store.as_ref(), std::slice::from_ref(&fixture.finding));
    let publication =
        crate::security::event_consumer::build_attested_finding_response_plan_publication(
            &fixture.plan,
        )
        .unwrap_or_else(|error| panic!("response publication: {error}"));
    store
        .publish_attested_finding_response_plan(&publication)
        .unwrap_or_else(|error| panic!("publish response plan: {error}"));
    let planner = recovery_planner(
        store.clone(),
        std::slice::from_ref(&fixture.finding),
        Arc::new(super::response_dry_run::DryRunFixturePolicy {
            artifacts: fixture.artifacts.clone(),
            authority: fixture.submission_authority.public_key(),
        }),
        fixture.runtime.coordinator.clone(),
        fixture.clock.clone(),
    );
    let error = rejected(
        planner.resume_incomplete_pass(16),
        "invalid initial lease must fail",
    );
    assert_eq!(
        error.code().as_str(),
        "urn:chio:error:kernel:response-dispatch-lease-outside-window",
    );
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    let reconciliation = error
        .source()
        .and_then(|source| {
            source.downcast_ref::<
            crate::security::event_consumer::recovery::ResponseDispatchRefusalReconciliation,
        >()
        })
        .unwrap_or_else(|| panic!("operator refusal lost reconciliation causes: {error:?}"));
    assert_eq!(reconciliation.dispatch_refusal.code(), error.code());
    assert_eq!(
        reconciliation.dispatch_refusal.kind(),
        PortErrorKind::InvalidData
    );
    assert_eq!(
        reconciliation.termination_failure.kind(),
        PortErrorKind::InvalidData
    );
    assert_eq!(
        reconciliation.termination_failure.code().as_str(),
        "CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED",
    );
    let kernel_error = reconciliation
        .dispatch_refusal
        .source()
        .and_then(|source| source.downcast_ref::<chio_kernel::KernelError>())
        .unwrap_or_else(|| panic!("operator refusal lost kernel source: {error:?}"));
    let rejection = kernel_error
        .source()
        .and_then(|source| source.downcast_ref::<chio_security_types::DispatchRejection>())
        .unwrap_or_else(|| panic!("operator refusal lost dispatch source: {kernel_error:?}"));
    assert!(
        matches!(rejection, chio_security_types::DispatchRejection::LeaseOutsideWindow {
        lease_expires_at_unix_ms,
        plan_expires_at_unix_ms,
        ..
    } if *lease_expires_at_unix_ms == fixture.plan.response_plan().expires_at_unix_ms + 1
        && *plan_expires_at_unix_ms == fixture.plan.response_plan().expires_at_unix_ms)
    );
    let row = store
        .load_attested_finding_response_outbox(&AttestedFindingResponseOutboxKey {
            tenant_id: fixture.plan.response_plan().tenant_id.clone(),
            action_id: fixture.plan.response_plan().action_id.clone(),
        })
        .unwrap_or_else(|error| panic!("refused response outbox: {error}"))
        .unwrap_or_else(|| panic!("refused response missing"));
    assert_eq!(row.last_error_code.as_ref(), Some(error.code()));
    assert_ne!(error.code().as_str(), "active_response.never_committed");
    assert!(!row.is_complete());
    // Governed admission has committed before executor preparation. The outbox
    // must retain reconciliation even though no executor dispatch has committed.
    assert_eq!(
        row.admission_state,
        AttestedFindingResponseAdmissionState::Prepared
    );
    assert_eq!(
        row.completion_state,
        AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(fixture.runtime.effects.executions(), 0);
    assert_eq!(
        real_adapter_table_count(&fixture.paths.responses, "security_response_dispatches"),
        0
    );
    assert_eq!(
        real_adapter_table_count(
            &fixture.paths.responses,
            "security_session_throttle_effects"
        ),
        0
    );
    assert_signed_refusal_projection(&fixture, error.code().clone());
}

fn assert_signed_refusal_projection(fixture: &RealAdapterFixture, error_code: ErrorCode) {
    use chio_core::receipt::security::{
        ActiveDefensePolicyBinding, ActiveDefenseReceiptHeader, ActiveDefenseResponseBinding,
        SchedulerHealthReceiptBody,
    };
    use chio_security_types::ports::{
        ExactSecurityReceiptSink, ReceiptAppendRequest, SecurityReceiptSink,
    };

    let plan = fixture.plan.response_plan();
    let body = ActiveDefenseReceiptBody::SchedulerHealth(SchedulerHealthReceiptBody {
        header: ActiveDefenseReceiptHeader::new(
            plan.created_at_unix_ms + 30_000,
            plan.tenant_id.clone(),
            record("dispatch-refusal-health-observation"),
            vec![plan.trigger_finding_receipt_id.clone()],
        )
        .unwrap_or_else(|error| panic!("refusal evidence header: {error}")),
        response: ActiveDefenseResponseBinding {
            policy: ActiveDefensePolicyBinding {
                policy_version: plan.policy_version.clone(),
                policy_hash: plan.policy_hash,
            },
            plan_hash: plan.plan_hash,
            action_id: plan.action_id.clone(),
            trigger_finding_id: plan.trigger_finding_id.clone(),
            trigger_finding_hash: plan.trigger_finding_hash,
            trigger_finding_receipt_id: plan.trigger_finding_receipt_id.clone(),
            affected_set_hash: plan.affected_set_hash,
            plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        },
        event_id: record("dispatch-refusal-health-event"),
        first_failure_at_unix_ms: plan.created_at_unix_ms + 30_000,
        attempts: 1,
        scheduler_fencing_token: 1,
        error_code,
        evidence_hash: plan.plan_hash,
    });
    let evidence_id = body
        .evidence_id()
        .unwrap_or_else(|error| panic!("refusal evidence id: {error}"));
    let store = Arc::new(
        SqliteReceiptStore::open(&fixture.paths.receipts)
            .unwrap_or_else(|error| panic!("refusal receipt store: {error}")),
    );
    let sink = NativeSecurityReceiptSink::new(
        store,
        Arc::new(Ed25519Backend::new(fixture.executor_signer.clone())),
    );
    sink.sign_and_append(&ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: record(body.kind().as_str()),
        evidence_id: evidence_id.clone(),
        canonical_body: CanonicalBody::new(
            canonical_json_bytes(&body)
                .unwrap_or_else(|error| panic!("refusal evidence bytes: {error}")),
        )
        .unwrap_or_else(|error| panic!("refusal canonical body: {error}")),
        body_hash: body
            .body_digest()
            .unwrap_or_else(|error| panic!("refusal body hash: {error}")),
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
    .unwrap_or_else(|error| panic!("sign refusal evidence: {error}"));
    let record = sink
        .load_exact(&evidence_id)
        .unwrap_or_else(|error| panic!("verified signed refusal readback: {error}"))
        .unwrap_or_else(|| panic!("signed refusal evidence missing"));
    let projected: ActiveDefenseReceiptBody =
        serde_json::from_slice(record.receipt.canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("refusal projection: {error}"));
    assert_eq!(projected, body);
    let ActiveDefenseReceiptBody::SchedulerHealth(health) = projected else {
        panic!("refusal evidence kind changed");
    };
    assert_eq!(
        health.error_code.as_str(),
        "urn:chio:error:kernel:response-dispatch-lease-outside-window"
    );
}
