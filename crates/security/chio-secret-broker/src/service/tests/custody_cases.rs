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

#[test]
fn reclaim_never_fails_an_attempt_whose_execution_has_captured_authority() {
    let fixture = fixture(1, false, false);
    let (request, trusted) = execution(&fixture, 305, 1);
    let ids = register_prepared_execution(&fixture, &request, &trusted, 20);
    let expiry = request.capability.body.expires_at_unix_seconds;
    let service = Arc::downgrade(&fixture.service);
    let reclaimed = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&reclaimed);
    fixture.authority.run_after_next_capture(Box::new(move || {
        let outcome = service
            .upgrade()
            .map(|service| service.reclaim_expired_prepared_dispatches(expiry).is_ok());
        *observed.lock().test_expect("reclaim observation lock") = outcome;
    }));

    let executed = fixture.service.execute(&request, &trusted, 21);

    assert_eq!(
        *reclaimed.lock().test_expect("reclaim observation lock"),
        Some(true),
        "reclaim must run inside the capture window"
    );
    assert_eq!(fixture.authority.captured_count(), 1);
    let state = fixture
        .attempts
        .load_attempt(&ids.attempt_id)
        .test_expect("load attempt")
        .test_expect("attempt exists")
        .state;
    assert_ne!(
        state,
        AttemptState::Failed,
        "a captured hold must never belong to a Failed attempt"
    );
    assert!(executed.is_ok(), "{executed:?}");
}

#[test]
fn orphaned_custody_is_an_integrity_refusal_that_still_reclaims_the_rest() {
    let directory = crate::private_tempdir().test_expect("tempdir");
    let directory =
        std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
    let attempt_path = directory.join("attempts.sqlite3");
    let receipt_signer = Keypair::from_seed(&[3; 32]);
    let fixture = fixture_with_stores(
        1,
        false,
        false,
        Arc::new(SqliteAttemptStore::open(&attempt_path).test_expect("attempt store")),
        Arc::new(
            crate::receipt::SqliteBrokerReceiptSink::open(
                &directory.join("receipts.sqlite3"),
                receipt_signer.public_key(),
            )
            .test_expect("receipt sink"),
        ),
        Arc::new(Mutex::new(Vec::new())),
    );
    let mut prepared = [306, 308].map(|invocation_index| {
        let (request, registration) = registered_and_held(&fixture, invocation_index);
        fixture
            .service
            .prepare_dispatch(&registration, &request, 20)
            .test_expect("prepare broker dispatch");
        (request, registration)
    });
    prepared.sort_by(|left, right| left.1.ids.operation_id.cmp(&right.1.ids.operation_id));
    let [(request, orphan), (_, reclaimable)] = prepared;
    let fault_connection =
        rusqlite::Connection::open(&attempt_path).test_expect("open attempt database");
    // Inject missing durable state through this test-only connection. The store's
    // own connection keeps foreign-key enforcement enabled.
    fault_connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .test_expect("disable FK only on fault connection");
    assert_eq!(
        fault_connection
            .execute(
                "DELETE FROM broker_attempts WHERE attempt_id = ?1",
                [&orphan.ids.attempt_id],
            )
            .test_expect("drop the durable attempt"),
        1,
        "the fault must remove exactly the retained attempt"
    );

    assert!(matches!(
        fixture
            .service
            .reclaim_expired_prepared_dispatches(request.capability.body.expires_at_unix_seconds),
        Err(BrokerError::Invariant(message))
            if message == "retained custody has no durable broker attempt"
    ));
    assert_eq!(
        fixture
            .service
            .retained_prepared_dispatch_keys()
            .test_expect("retained dispatch lock"),
        std::collections::BTreeSet::from([orphan.ids.operation_id])
    );
    assert_eq!(attempt_state(&fixture, &reclaimable), AttemptState::Failed);
}

/// Runs one armed hook from inside the next destination resolution.
struct HookedResolver {
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl DestinationResolver for HookedResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
        if let Some(hook) = self.hook.lock().test_expect("resolver hook lock").take() {
            hook();
        }
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }
}

#[test]
fn reclaim_never_fails_an_attempt_whose_preparation_retry_is_in_flight() {
    let mut fixture = fixture(1, false, false);
    let resolver = Arc::new(HookedResolver {
        hook: Mutex::new(None),
    });
    Arc::get_mut(&mut fixture.service)
        .test_expect("unshared fixture service")
        .https = Arc::new(GenericHttpsExecutor::new(
        Arc::clone(&resolver) as Arc<dyn DestinationResolver>,
        Arc::new(ObservingTransport {
            observed_authorizations: Arc::clone(&fixture.observed_authorizations),
            fail: false,
            redirect: false,
        }),
        NetworkPolicy::production(),
    ));
    let (request, registration) = registered_and_held(&fixture, 307);
    fixture
        .service
        .prepare_dispatch(&registration, &request, 20)
        .test_expect("prepare broker dispatch");
    let expiry = request.capability.body.expires_at_unix_seconds;
    let service = Arc::downgrade(&fixture.service);
    let reclaimed = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&reclaimed);
    *resolver.hook.lock().test_expect("resolver hook lock") = Some(Box::new(move || {
        let outcome = service
            .upgrade()
            .map(|service| service.reclaim_expired_prepared_dispatches(expiry).is_ok());
        *observed.lock().test_expect("reclaim observation lock") = outcome;
    }));

    let retried = fixture
        .service
        .prepare_dispatch(&registration, &request, 21);

    assert_eq!(
        *reclaimed.lock().test_expect("reclaim observation lock"),
        Some(true),
        "reclaim must run inside the preparation retry"
    );
    let retained = fixture
        .service
        .retained_prepared_dispatch_keys()
        .test_expect("retained dispatch lock");
    assert!(
        !(attempt_state(&fixture, &registration) == AttemptState::Failed && !retained.is_empty()),
        "custody must never be retained for a Failed attempt"
    );
    assert!(retried.is_ok(), "{retried:?}");
}
