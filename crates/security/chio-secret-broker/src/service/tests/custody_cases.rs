use super::*;

fn registered_and_held(
    fixture: &Fixture,
    invocation_index: usize,
) -> (BrokerExecuteRequest, AttemptRegistration) {
    let (request, trusted) = execution(fixture, invocation_index, 1);
    let registration = test_attempt_registration(
        &request,
        &trusted.admission_operation_id,
        &trusted.quotas,
        &trusted.authority_metadata_digest,
        &trusted.revocation_authority_domain,
    );
    fixture
        .service
        .register_attempt(&registration, &request, 20)
        .test_expect("register attempt");
    fixture
        .authority
        .authorize_execution_hold(&AuthorizeExecutionHoldRequest {
            operation_id: registration.ids.operation_id.clone(),
            invocation_id: request.invocation_id.clone(),
            parent_capability_id: request.capability.body.parent_capability_id.clone(),
            broker_capability_id: request.capability.body.capability_id.clone(),
            hold_id: registration.ids.hold_id.clone(),
            authorize_event_id: registration.ids.authorize_event_id.clone(),
            quotas: trusted.quotas.clone(),
            authority_metadata_digest: trusted.authority_metadata_digest.clone(),
        })
        .test_expect("kernel authorizes execution");
    (request, registration)
}

#[test]
fn prepare_dispatch_resolves_the_destination_once_before_retaining_custody() {
    let fixture = fixture(1, false, false);
    let (request, registration) = registered_and_held(&fixture, 301);
    let before = fixture.resolver_calls.load(Ordering::SeqCst);
    fixture
        .service
        .prepare_dispatch(&registration, &request, 20)
        .test_expect("prepare broker dispatch");
    assert_eq!(
        fixture.resolver_calls.load(Ordering::SeqCst) - before,
        1,
        "preparation must pin the preflight resolution instead of resolving under custody"
    );
    assert_eq!(
        fixture
            .service
            .retained_prepared_dispatch_keys()
            .test_expect("retained dispatch lock"),
        std::collections::BTreeSet::from([registration.ids.operation_id])
    );
}
