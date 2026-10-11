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

fn attempt_state(fixture: &Fixture, registration: &AttemptRegistration) -> AttemptState {
    fixture
        .attempts
        .load_attempt(&registration.ids.attempt_id)
        .test_expect("load attempt")
        .test_expect("attempt exists")
        .state
}

#[test]
fn expired_pre_capture_custody_is_tombstoned_and_reclaimed_on_prepare() {
    let fixture = fixture(1, false, false);
    let (request, registration) = registered_and_held(&fixture, 302);
    fixture
        .service
        .prepare_dispatch(&registration, &request, 20)
        .test_expect("prepare broker dispatch");
    let expiry = request.capability.body.expires_at_unix_seconds;

    assert!(matches!(
        fixture.service.prepare_dispatch(&registration, &request, expiry),
        Err(BrokerError::Conflict(message)) if message == "broker attempt cannot prepare from failed"
    ));
    assert_eq!(attempt_state(&fixture, &registration), AttemptState::Failed);
    assert!(fixture
        .service
        .retained_prepared_dispatch_keys()
        .test_expect("retained dispatch lock")
        .is_empty());
}

#[test]
fn idle_reclaim_releases_expired_pre_capture_custody_without_a_new_prepare() {
    let fixture = fixture(1, false, false);
    let (request, registration) = registered_and_held(&fixture, 303);
    fixture
        .service
        .prepare_dispatch(&registration, &request, 20)
        .test_expect("prepare broker dispatch");
    let expiry = request.capability.body.expires_at_unix_seconds;

    fixture
        .service
        .reclaim_expired_prepared_dispatches(expiry - 1)
        .test_expect("reclaim before expiry");
    assert_eq!(
        attempt_state(&fixture, &registration),
        AttemptState::Prepared
    );
    assert_eq!(
        fixture
            .service
            .retained_prepared_dispatch_keys()
            .test_expect("retained dispatch lock")
            .len(),
        1
    );

    fixture
        .service
        .reclaim_expired_prepared_dispatches(expiry)
        .test_expect("reclaim at expiry");
    assert_eq!(attempt_state(&fixture, &registration), AttemptState::Failed);
    assert!(fixture
        .service
        .retained_prepared_dispatch_keys()
        .test_expect("retained dispatch lock")
        .is_empty());
}

#[test]
fn expired_captured_custody_stays_with_its_dispatch_owner() {
    let fixture = fixture(1, false, false);
    let (request, registration) = registered_and_held(&fixture, 304);
    fixture
        .service
        .prepare_dispatch(&registration, &request, 20)
        .test_expect("prepare broker dispatch");
    fixture
        .attempts
        .transition(
            &registration.ids.attempt_id,
            AttemptState::Prepared,
            AttemptState::Captured,
            &AttemptTransitionEvidence {
                revocation_set_digest: Some("a".repeat(64)),
                budget_commit_index: Some(1),
                revocation_commit_index: Some(1),
                authority_commit_index: Some(1),
                leader_epoch: Some(1),
                response_digest: None,
            },
            21,
        )
        .test_expect("execution captures the attempt");

    fixture
        .service
        .reclaim_expired_prepared_dispatches(request.capability.body.expires_at_unix_seconds)
        .test_expect("reclaim at expiry");
    assert_eq!(
        attempt_state(&fixture, &registration),
        AttemptState::Captured
    );
    assert_eq!(
        fixture
            .service
            .retained_prepared_dispatch_keys()
            .test_expect("retained dispatch lock"),
        std::collections::BTreeSet::from([registration.ids.operation_id])
    );
}
