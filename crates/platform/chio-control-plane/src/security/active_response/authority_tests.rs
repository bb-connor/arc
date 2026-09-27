use super::tests::{require_success, Harness};
use super::{
    ActiveResponseExecutionOrigin, ActiveResponseExecutorError, ResponseDispatchKey,
    ResponseDispatchLoadOutcome, ResponseDispatchStore,
};

#[test]
fn committed_legacy_admission_prepares_and_recovers_its_dispatch() {
    let harness = Harness::new();
    let mut request = harness.governed_request();
    request.response_plan.execution = chio_security_types::PlanProvenance::Legacy;
    let body = serde_json::to_value(request.response_plan.authorization_body())
        .unwrap_or_else(|error| panic!("legacy authorization body: {error}"));
    let hash = chio_core::capability::governance::GovernedResponsePlanIntentBody::compute_plan_body_digest(&body)
        .unwrap_or_else(|error| panic!("legacy authorization digest: {error}"));
    request.response_plan.plan_hash = chio_security_types::ports::Digest32::new(*hash.as_bytes());
    request.plan_body_hash = hash.to_hex();
    request.origin = ActiveResponseExecutionOrigin::CommittedAdmission;
    request.dispatch_id = super::derive_active_response_dispatch_id(
        &request.response_plan,
        &request.executor_authority,
        &request.authorization_capability_hash,
        &request.governed_intent_hash,
        &request.policy_decision_hash,
        request.authorized_at_unix_ms,
        &request.approval,
    )
    .unwrap_or_else(|error| panic!("legacy dispatch identity: {error}"));

    let first = require_success(
        harness.executor.execute_source(&request),
        "legacy committed admission",
    );
    request.origin = ActiveResponseExecutionOrigin::CommittedDispatch;
    let recovered = require_success(
        harness.executor.execute_source(&request),
        "legacy committed dispatch replay",
    );
    assert_eq!(recovered.proof_evidence_id(), first.proof_evidence_id());
    assert_eq!(recovered.response_record(), first.response_record());
    assert_eq!(harness.effect_executions(), 1);
}

#[test]
fn sealed_committed_dispatch_cannot_prepare_replacement_even_without_executor_readback() {
    use super::request::ActiveResponseRequestSource;
    let harness = Harness::new();
    let mut request = harness.automatic_request();
    request.origin = ActiveResponseExecutionOrigin::CommittedDispatch;
    let result = request.prepare_dispatch(
        chio_security_types::ports::ResponseDispatchLease {
            lease_owner_id: chio_security_types::ports::LeaseOwnerId::new("replacement")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            lease_expires_at_unix_ms: request.expires_at_unix_ms,
        },
        request.authorized_at_unix_ms,
    );
    assert!(
        matches!(result, Err(ActiveResponseExecutorError::OutcomeUnknown(message))
        if message == "an existing dispatch must be recovered by exact readback")
    );
    assert_eq!(harness.effect_executions(), 0);
}

#[test]
fn committed_dispatch_recovery_cannot_create_a_replacement_dispatch() {
    let harness = Harness::new();
    let mut request = harness.automatic_request();
    // The test source models a kernel request after exact committed readback,
    // followed by that record becoming unavailable before executor readback.
    request.origin = ActiveResponseExecutionOrigin::CommittedDispatch;
    let outcome = harness.executor.execute_source(&request);
    assert!(matches!(outcome,
        Err(ActiveResponseExecutorError::OutcomeUnknown(message))
            if message == "previously committed dispatch is missing during recovery"
    ));
    assert_eq!(harness.effect_executions(), 0);
    assert_eq!(
        require_success(
            harness.executor.store.load_dispatch(&ResponseDispatchKey {
                tenant_id: request.response_plan.tenant_id.clone(),
                dispatch_id: request.dispatch_id.clone(),
            }),
            "read dispatch after refused recovery"
        ),
        ResponseDispatchLoadOutcome::Missing,
    );
}

#[test]
fn committed_dispatch_origin_replays_existing_automatic_and_governed_records() {
    for governed in [false, true] {
        let harness = Harness::new();
        let mut request = if governed {
            harness.governed_request()
        } else {
            harness.automatic_request()
        };
        let first = require_success(harness.executor.execute_source(&request), "first dispatch");
        request.origin = ActiveResponseExecutionOrigin::CommittedDispatch;
        let recovered = require_success(
            harness.executor.execute_source(&request),
            "committed replay",
        );
        assert_eq!(recovered.proof_evidence_id(), first.proof_evidence_id());
        assert_eq!(recovered.response_record(), first.response_record());
        assert_eq!(harness.effect_executions(), 1);
    }
}
