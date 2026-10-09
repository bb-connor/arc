use super::*;

use crate::service::custody::dispatch_claim::ClaimedCapture;
use crate::store::{AttemptIds, AttemptRecord};

/// Quota-enforcement checks inside `execute_inner`, in execution order.
const BEFORE_CLAIM: usize = 2;
const AFTER_SECOND_REVOCATION: usize = 3;
const AFTER_BOUNDARY_CAPTURE: usize = 4;
const AFTER_RETAINED_CHECK: usize = 5;
const IN_DISPATCH_AUTHORIZATION: usize = 6;

const NOW: u64 = 21;
const TERMINAL: u64 = 41;

/// Runs `action` on the `check`-th quota-enforcement check after this call.
fn at_quota_check(
    fixture: &Fixture,
    check: usize,
    action: impl FnOnce() -> Result<()> + Send + 'static,
) {
    let mut seen = 0_usize;
    let mut action = Some(action);
    fixture
        .migration_enforcer
        .on_quota_check(Box::new(move || {
            seen += 1;
            match action.take_if(|_| seen == check) {
                Some(action) => action(),
                None => Ok(()),
            }
        }))
        .test_expect("install quota check hook");
}

/// A request whose hold the authority has already captured, with the exact
/// capture evidence every later attempt transition must carry.
fn captured_execution(
    fixture: &Fixture,
    invocation_index: usize,
) -> (
    BrokerExecuteRequest,
    TrustedExecutionContext,
    AttemptIds,
    AttemptTransitionEvidence,
) {
    let (request, trusted) = execution(fixture, invocation_index, 1);
    register_execution(fixture, &request, &trusted, 20);
    let (ids, evidence) = captured_attempt_evidence(fixture, &request, &trusted);
    (request, trusted, ids, evidence)
}

fn load(fixture: &Fixture, ids: &AttemptIds) -> AttemptRecord {
    fixture
        .attempts
        .load_attempt(&ids.attempt_id)
        .test_expect("load attempt")
        .test_expect("attempt exists")
}

fn record_evidence(record: &AttemptRecord) -> AttemptTransitionEvidence {
    AttemptTransitionEvidence {
        revocation_set_digest: record.revocation_set_digest.clone(),
        budget_commit_index: record.budget_commit_index,
        revocation_commit_index: record.revocation_commit_index,
        authority_commit_index: record.authority_commit_index,
        leader_epoch: record.leader_epoch,
        response_digest: record.response_digest.clone(),
    }
}

/// The attempt holds exactly `state`, its capture evidence, no dispatch claim
/// and no response digest, last written at `updated_at`.
fn assert_settled(
    context: &str,
    fixture: &Fixture,
    ids: &AttemptIds,
    evidence: &AttemptTransitionEvidence,
    state: AttemptState,
    updated_at: u64,
) {
    let record = load(fixture, ids);
    assert_eq!(
        (
            record.state,
            record.dispatch_claim_id.as_deref(),
            record.updated_at_unix_seconds,
        ),
        (state, None, updated_at),
        "{context}: {record:?}"
    );
    assert_eq!(&record_evidence(&record), evidence, "{context}");
}

fn dispatch_count(fixture: &Fixture) -> usize {
    fixture
        .observed_authorizations
        .lock()
        .test_expect("observed lock")
        .len()
}

fn capture_projection(outcome: BrokerFailureOutcome) -> FailureProjection {
    FailureProjection {
        stage: BrokerFailureStage::Capture,
        outcome,
        dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
    }
}

#[test]
fn poisoned_retained_custody_after_claim_releases_the_claim() {
    let fixture = fixture(1, false, false);
    let (request, trusted, ids, evidence) = captured_execution(&fixture, 301);
    let service = Arc::downgrade(&fixture.service);
    at_quota_check(&fixture, AFTER_BOUNDARY_CAPTURE, move || {
        if let Some(service) = service.upgrade() {
            service.poison_retained_prepared_dispatches_for_test();
        }
        Ok(())
    });

    let failure = fixture
        .service
        .execute_inner(&request, &trusted, NOW, &|| Ok(TERMINAL))
        .test_expect_err("poisoned retained custody refuses dispatch");

    assert!(matches!(&failure.error, BrokerError::Invariant(_)));
    assert_eq!(
        failure.projection,
        Some(capture_projection(BrokerFailureOutcome::Failed))
    );
    assert_settled(
        "poisoned retained custody",
        &fixture,
        &ids,
        &evidence,
        AttemptState::Captured,
        NOW,
    );
    assert_eq!(dispatch_count(&fixture), 0);
}

type Action = Box<dyn FnOnce() -> Result<()> + Send>;
type ActionFor = fn(&Fixture, &AttemptIds) -> Action;

fn revocation_outage(fixture: &Fixture, _: &AttemptIds) -> Action {
    let unavailable = Arc::clone(&fixture.live_authority_unavailable);
    Box::new(move || {
        unavailable.store(true, Ordering::SeqCst);
        Ok(())
    })
}

fn migration_denial(_: &Fixture, _: &AttemptIds) -> Action {
    Box::new(|| {
        Err(BrokerError::AuthorizationDenied(
            "test migration denial".to_string(),
        ))
    })
}

fn boundary_capture_loss(fixture: &Fixture, ids: &AttemptIds) -> Action {
    let authority = Arc::clone(&fixture.authority);
    let hold_id = ids.hold_id.clone();
    Box::new(move || {
        authority.set_hold_state(&hold_id, ExecutionHoldState::Unknown);
        Ok(())
    })
}

fn boundary_capture_change(fixture: &Fixture, ids: &AttemptIds) -> Action {
    let authority = Arc::clone(&fixture.authority);
    let hold_id = ids.hold_id.clone();
    Box::new(move || {
        let mut state = authority.state.lock().test_expect("authority lock");
        let Some(ExecutionHoldState::Captured(commit)) = state.holds.get_mut(&hold_id) else {
            panic!("boundary hold is not captured");
        };
        commit.leader_epoch += 1;
        Ok(())
    })
}

fn retained_dispatch_loss(fixture: &Fixture, ids: &AttemptIds) -> Action {
    let service = Arc::downgrade(&fixture.service);
    let operation_id = ids.operation_id.clone();
    Box::new(move || match service.upgrade() {
        Some(service) => service.discard_prepared_dispatch(&operation_id),
        None => Ok(()),
    })
}

fn retained_dispatch_rebind(fixture: &Fixture, ids: &AttemptIds) -> Action {
    let service = Arc::downgrade(&fixture.service);
    let operation_id = ids.operation_id.clone();
    Box::new(move || match service.upgrade() {
        Some(service) => service.rebind_retained_prepared_dispatch_for_test(&operation_id),
        None => Ok(()),
    })
}

/// Hands the captured attempt's claim to a competing execution path.
fn claim_takeover(fixture: &Fixture, ids: &AttemptIds) -> Action {
    let attempts = Arc::clone(&fixture.attempts);
    let attempt_id = ids.attempt_id.clone();
    Box::new(move || {
        attempts.clear_stale_captured_attempt_claim(&attempt_id, NOW)?;
        assert!(attempts.claim_captured_attempt(&attempt_id, "competing-dispatch-claim", NOW)?);
        Ok(())
    })
}

struct ReleaseExit {
    name: &'static str,
    check: usize,
    action: ActionFor,
    error: fn(&BrokerError) -> bool,
    outcome: BrokerFailureOutcome,
}

fn release_exits() -> [ReleaseExit; 9] {
    [
        ReleaseExit {
            name: "second revocation check fails",
            check: BEFORE_CLAIM,
            action: revocation_outage,
            error: |error| matches!(error, BrokerError::AuthorityUnavailable(_)),
            outcome: BrokerFailureOutcome::Failed,
        },
        ReleaseExit {
            name: "migration denied after the claim",
            check: AFTER_SECOND_REVOCATION,
            action: migration_denial,
            error: |error| matches!(error, BrokerError::AuthorizationDenied(_)),
            outcome: BrokerFailureOutcome::Denied,
        },
        ReleaseExit {
            name: "boundary capture unavailable",
            check: AFTER_SECOND_REVOCATION,
            action: boundary_capture_loss,
            error: |error| matches!(error, BrokerError::AuthorityUnavailable(_)),
            outcome: BrokerFailureOutcome::Failed,
        },
        ReleaseExit {
            name: "boundary capture evidence changed",
            check: AFTER_SECOND_REVOCATION,
            action: boundary_capture_change,
            error: |error| matches!(error, BrokerError::Invariant(_)),
            outcome: BrokerFailureOutcome::Failed,
        },
        ReleaseExit {
            name: "migration denied after the boundary capture",
            check: AFTER_BOUNDARY_CAPTURE,
            action: migration_denial,
            error: |error| matches!(error, BrokerError::AuthorizationDenied(_)),
            outcome: BrokerFailureOutcome::Denied,
        },
        ReleaseExit {
            name: "retained dispatch disappeared",
            check: AFTER_BOUNDARY_CAPTURE,
            action: retained_dispatch_loss,
            error: |error| matches!(error, BrokerError::AuthorityUnavailable(_)),
            outcome: BrokerFailureOutcome::Failed,
        },
        ReleaseExit {
            name: "retained dispatch changed",
            check: AFTER_BOUNDARY_CAPTURE,
            action: retained_dispatch_rebind,
            error: |error| matches!(error, BrokerError::Invariant(_)),
            outcome: BrokerFailureOutcome::Failed,
        },
        ReleaseExit {
            name: "migration denied after the retained check",
            check: AFTER_RETAINED_CHECK,
            action: migration_denial,
            error: |error| matches!(error, BrokerError::AuthorizationDenied(_)),
            outcome: BrokerFailureOutcome::Denied,
        },
        ReleaseExit {
            name: "dispatch authorization refused before the commit",
            check: IN_DISPATCH_AUTHORIZATION,
            action: migration_denial,
            error: |error| matches!(error, BrokerError::AuthorizationDenied(_)),
            outcome: BrokerFailureOutcome::Denied,
        },
    ]
}

#[test]
fn every_pre_commit_exit_releases_the_claim_with_its_capture_projection() {
    for (index, exit) in release_exits().into_iter().enumerate() {
        let fixture = fixture(1, false, false);
        let (request, trusted, ids, evidence) = captured_execution(&fixture, 310 + index);
        at_quota_check(&fixture, exit.check, (exit.action)(&fixture, &ids));

        let failure = fixture
            .service
            .execute_inner(&request, &trusted, NOW, &|| Ok(TERMINAL))
            .test_expect_err(exit.name);

        assert!(
            (exit.error)(&failure.error),
            "{}: {:?}",
            exit.name,
            failure.error
        );
        assert_eq!(
            failure.projection,
            Some(capture_projection(exit.outcome)),
            "{}",
            exit.name
        );
        assert_settled(
            exit.name,
            &fixture,
            &ids,
            &evidence,
            AttemptState::Captured,
            NOW,
        );
        assert_eq!(dispatch_count(&fixture), 0, "{}", exit.name);
    }
}

const DISPATCH_UNKNOWN: FailureProjection = FailureProjection {
    stage: BrokerFailureStage::Dispatch,
    outcome: BrokerFailureOutcome::Unknown,
    dispatch_knowledge: BrokerDispatchKnowledge::Unknown,
};
const RESPONSE_FAILED: FailureProjection = FailureProjection {
    stage: BrokerFailureStage::Response,
    outcome: BrokerFailureOutcome::Failed,
    dispatch_knowledge: BrokerDispatchKnowledge::Committed,
};
const RECEIPT_PERSISTENCE_FAILED: FailureProjection = FailureProjection {
    stage: BrokerFailureStage::ReceiptPersistence,
    outcome: BrokerFailureOutcome::Failed,
    dispatch_knowledge: BrokerDispatchKnowledge::Committed,
};

fn inspecting_sink(fail_completed: bool) -> (InspectingReceiptSink, Arc<Mutex<Vec<Vec<u8>>>>) {
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let sink = InspectingReceiptSink {
        canary: b"unique-service-credential-canary".to_vec(),
        receipts: Arc::clone(&receipts),
        failures: Mutex::new(BTreeMap::new()),
        completed: Mutex::new(BTreeMap::new()),
        failure_persist_entered: None,
        failure_persist_release: None,
        fail_completed,
    };
    (sink, receipts)
}

fn in_memory_attempts() -> Arc<SqliteAttemptStore> {
    Arc::new(SqliteAttemptStore::open_in_memory().test_expect("attempt store"))
}

/// Persists completed responses but answers with a fixed receipt reference.
struct ReferenceOverrideSink {
    inner: InspectingReceiptSink,
    reference: &'static str,
}

impl BrokerReceiptSink for ReferenceOverrideSink {
    fn persist(&self, receipt: &SignedBrokerReceipt) -> Result<String> {
        self.inner.persist(receipt)
    }

    fn persist_completed(&self, response: &BrokerExecuteResponse) -> Result<String> {
        self.inner.persist_completed(response)?;
        Ok(self.reference.to_string())
    }

    fn load_completed(&self, attempt_id: &str) -> Result<Option<BrokerExecuteResponse>> {
        self.inner.load_completed(attempt_id)
    }

    fn persist_failure(&self, receipt: &SignedBrokerFailureReceipt) -> Result<String> {
        self.inner.persist_failure(receipt)
    }

    fn load_failure(&self, receipt_id: &str) -> Result<Option<SignedBrokerFailureReceipt>> {
        self.inner.load_failure(receipt_id)
    }

    fn supports_failure_receipts(&self) -> bool {
        true
    }

    fn supports_completed_replay(&self) -> bool {
        true
    }
}

fn reference_override_fixture(reference: &'static str) -> Fixture {
    let (inner, receipts) = inspecting_sink(false);
    fixture_with_stores(
        1,
        false,
        false,
        in_memory_attempts(),
        Arc::new(ReferenceOverrideSink { inner, reference }),
        receipts,
    )
}

fn default_fixture() -> Fixture {
    fixture(1, false, false)
}

fn failing_transport_fixture() -> Fixture {
    fixture(1, true, false)
}

fn redirecting_fixture() -> Fixture {
    let mut fixture = fixture(1, false, false);
    let https = Arc::new(GenericHttpsExecutor::new(
        Arc::new(PublicResolver {
            calls: Arc::clone(&fixture.resolver_calls),
        }),
        Arc::new(ObservingTransport {
            observed_authorizations: Arc::clone(&fixture.observed_authorizations),
            fail: false,
            redirect: true,
        }),
        NetworkPolicy::production(),
    ));
    Arc::get_mut(&mut fixture.service)
        .test_expect("unshared fixture service")
        .https = Arc::clone(&https);
    fixture.https = https;
    fixture
}

fn failing_signer_fixture() -> Fixture {
    let (sink, receipts) = inspecting_sink(false);
    fixture_with_receipt_signer(
        FixtureServiceOptions {
            maximum_executions: 1,
            fail_transport: false,
            deny_capture: false,
            receipt_signer: Arc::new(FailFirstSigningBackend {
                keypair: Keypair::from_seed(&[3; 32]),
                fail_next: AtomicBool::new(true),
            }),
            durable_secrets: false,
        },
        in_memory_attempts(),
        Arc::new(sink),
        receipts,
    )
}

fn failing_persistence_fixture() -> Fixture {
    let (sink, receipts) = inspecting_sink(true);
    fixture_with_stores(
        1,
        false,
        false,
        in_memory_attempts(),
        Arc::new(sink),
        receipts,
    )
}

fn malformed_reference_fixture() -> Fixture {
    reference_override_fixture(" padded-receipt-reference")
}

fn unbound_reference_fixture() -> Fixture {
    reference_override_fixture(
        "broker-receipt-sha256-0000000000000000000000000000000000000000000000000000000000000000",
    )
}

struct CommittedExit {
    name: &'static str,
    fixture: fn() -> Fixture,
    hook: Option<(usize, ActionFor)>,
    terminal_clock_fails: bool,
    error: fn(&BrokerError) -> bool,
    projection: Option<FailureProjection>,
    state: AttemptState,
    updated_at: u64,
    dispatches: usize,
}

fn committed_exits() -> [CommittedExit; 8] {
    [
        CommittedExit {
            name: "dispatch commit attempted and refused",
            fixture: default_fixture,
            hook: Some((IN_DISPATCH_AUTHORIZATION, claim_takeover)),
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::Conflict(_)),
            projection: None,
            state: AttemptState::UnknownOutcome,
            updated_at: NOW,
            dispatches: 0,
        },
        CommittedExit {
            name: "transport failure",
            fixture: failing_transport_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::Upstream(_)),
            projection: Some(DISPATCH_UNKNOWN),
            state: AttemptState::UnknownOutcome,
            updated_at: NOW,
            dispatches: 1,
        },
        CommittedExit {
            name: "response rejected",
            fixture: redirecting_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::ResponseRejected(_)),
            projection: Some(RESPONSE_FAILED),
            state: AttemptState::UnknownOutcome,
            updated_at: NOW,
            dispatches: 1,
        },
        CommittedExit {
            name: "terminal clock unavailable",
            fixture: default_fixture,
            hook: None,
            terminal_clock_fails: true,
            error: |error| matches!(error, BrokerError::AuthorityUnavailable(_)),
            projection: Some(RESPONSE_FAILED),
            state: AttemptState::DispatchCommitted,
            updated_at: TERMINAL,
            dispatches: 1,
        },
        CommittedExit {
            name: "receipt signing fails",
            fixture: failing_signer_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::Invariant(_)),
            projection: Some(RESPONSE_FAILED),
            state: AttemptState::DispatchCommitted,
            updated_at: TERMINAL,
            dispatches: 1,
        },
        CommittedExit {
            name: "completed response persistence fails",
            fixture: failing_persistence_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::Storage(_)),
            projection: Some(RECEIPT_PERSISTENCE_FAILED),
            state: AttemptState::UnknownOutcome,
            updated_at: TERMINAL,
            dispatches: 1,
        },
        CommittedExit {
            name: "receipt reference malformed",
            fixture: malformed_reference_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::InvalidRequest(_)),
            projection: Some(RECEIPT_PERSISTENCE_FAILED),
            state: AttemptState::UnknownOutcome,
            updated_at: TERMINAL,
            dispatches: 1,
        },
        CommittedExit {
            name: "receipt reference unbound",
            fixture: unbound_reference_fixture,
            hook: None,
            terminal_clock_fails: false,
            error: |error| matches!(error, BrokerError::Invariant(_)),
            projection: Some(RECEIPT_PERSISTENCE_FAILED),
            state: AttemptState::UnknownOutcome,
            updated_at: TERMINAL,
            dispatches: 1,
        },
    ]
}

#[test]
fn every_exit_after_the_commit_attempt_never_releases_the_claim() {
    for (index, exit) in committed_exits().into_iter().enumerate() {
        let fixture = (exit.fixture)();
        let (request, trusted, ids, evidence) = captured_execution(&fixture, 330 + index);
        if let Some((check, action)) = exit.hook {
            at_quota_check(&fixture, check, action(&fixture, &ids));
        }
        let clock_reads = std::cell::Cell::new(0_u32);
        let terminal_clock = || {
            clock_reads.set(clock_reads.get() + 1);
            if exit.terminal_clock_fails && clock_reads.get() == 3 {
                return Err(BrokerError::AuthorityUnavailable(
                    "test terminal clock outage".to_string(),
                ));
            }
            Ok(TERMINAL)
        };

        let failure = fixture
            .service
            .execute_inner(&request, &trusted, NOW, &terminal_clock)
            .test_expect_err(exit.name);

        assert!(
            (exit.error)(&failure.error),
            "{}: {:?}",
            exit.name,
            failure.error
        );
        assert_eq!(failure.projection, exit.projection, "{}", exit.name);
        assert_settled(
            exit.name,
            &fixture,
            &ids,
            &evidence,
            exit.state,
            exit.updated_at,
        );
        assert_eq!(dispatch_count(&fixture), exit.dispatches, "{}", exit.name);
    }
}

/// An attempt journaled as captured, ready to be claimed at `CLAIMED_AT`.
fn journaled_capture(
    fixture: &Fixture,
    invocation_index: usize,
) -> (AttemptIds, AttemptTransitionEvidence) {
    let (_request, _trusted, ids, evidence) = captured_execution(fixture, invocation_index);
    fixture
        .attempts
        .transition(
            &ids.attempt_id,
            AttemptState::Prepared,
            AttemptState::Captured,
            &evidence,
            22,
        )
        .test_expect("journal captured attempt");
    (ids, evidence)
}

const CLAIMED_AT: u64 = 23;
const COMMITTED_AT: u64 = 24;
const COMPLETED_AT: u64 = 25;
const RESPONSE_DIGEST: &str = "abababababababababababababababababababababababababababababababab";

fn claim<'s>(
    attempts: &'s dyn AttemptStore,
    ids: &AttemptIds,
    claim_id: &str,
    evidence: &AttemptTransitionEvidence,
) -> ClaimedCapture<'s> {
    ClaimedCapture::claim(
        attempts,
        &ids.attempt_id,
        claim_id.to_string(),
        evidence.clone(),
        CLAIMED_AT,
    )
    .test_expect("claim captured attempt")
}

fn denial() -> BrokerError {
    BrokerError::AuthorizationDenied("test dispatch refusal".to_string())
}

/// Runs `settle` and expects it to unwind with the given message.
fn expect_unwind(settle: impl FnOnce(), message: &str) {
    let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(settle)) else {
        panic!("settlement did not unwind");
    };
    assert_eq!(payload.downcast_ref::<&str>().copied(), Some(message));
}

fn drop_claim(claim: ClaimedCapture<'_>) {
    drop(claim);
}

struct OwnerCase {
    name: &'static str,
    settle: fn(ClaimedCapture<'_>),
    state: AttemptState,
    updated_at: u64,
    response_digest: Option<&'static str>,
}

fn owner_cases() -> [OwnerCase; 8] {
    [
        OwnerCase {
            name: "claim dropped",
            settle: drop_claim,
            state: AttemptState::Captured,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "claim refused",
            settle: |claim| {
                let failure = claim.refuse(denial());
                assert_eq!(
                    failure.projection,
                    Some(capture_projection(BrokerFailureOutcome::Denied))
                );
            },
            state: AttemptState::Captured,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "dispatch refused before the commit point",
            settle: |claim| {
                let failure = claim
                    .commit(|_point| Err(denial()))
                    .map(drop)
                    .test_expect_err("refused dispatch");
                assert!(matches!(failure.error, BrokerError::AuthorizationDenied(_)));
                assert_eq!(
                    failure.projection,
                    Some(capture_projection(BrokerFailureOutcome::Denied))
                );
            },
            state: AttemptState::Captured,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "unwind before the commit point",
            settle: |claim| {
                expect_unwind(
                    || drop(claim.commit(|_point| panic!("dispatch authorization unwound"))),
                    "dispatch authorization unwound",
                );
            },
            state: AttemptState::Captured,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "unwind after the commit point",
            settle: |claim| {
                expect_unwind(
                    || {
                        drop(claim.commit(|point| {
                            point.commit(COMMITTED_AT)?;
                            panic!("dispatch authorization unwound");
                        }))
                    },
                    "dispatch authorization unwound",
                );
            },
            state: AttemptState::UnknownOutcome,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "committed dispatch dropped",
            settle: |claim| {
                drop(
                    claim
                        .commit(|point| point.commit(COMMITTED_AT))
                        .test_expect("commit dispatch"),
                );
            },
            state: AttemptState::UnknownOutcome,
            updated_at: CLAIMED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "committed dispatch failed and retained",
            settle: |claim| {
                let failure = claim
                    .commit(|point| point.commit(COMMITTED_AT))
                    .test_expect("commit dispatch")
                    .fail_committed(denial(), RESPONSE_FAILED);
                assert_eq!(failure.projection, Some(RESPONSE_FAILED));
            },
            state: AttemptState::DispatchCommitted,
            updated_at: COMMITTED_AT,
            response_digest: None,
        },
        OwnerCase {
            name: "committed dispatch completed",
            settle: |claim| {
                claim
                    .commit(|point| point.commit(COMMITTED_AT))
                    .test_expect("commit dispatch")
                    .complete(RESPONSE_DIGEST.to_string(), COMPLETED_AT)
                    .test_expect("complete dispatch");
            },
            state: AttemptState::Completed,
            updated_at: COMPLETED_AT,
            response_digest: Some(RESPONSE_DIGEST),
        },
    ]
}

#[test]
fn each_settlement_of_a_claim_leaves_its_exact_attempt_state() {
    for (index, case) in owner_cases().into_iter().enumerate() {
        let fixture = fixture(1, false, false);
        let (ids, evidence) = journaled_capture(&fixture, 350 + index);

        (case.settle)(claim(
            fixture.attempts.as_ref(),
            &ids,
            "dispatch-claim-a",
            &evidence,
        ));

        let expected = AttemptTransitionEvidence {
            response_digest: case.response_digest.map(str::to_string),
            ..evidence
        };
        assert_settled(
            case.name,
            &fixture,
            &ids,
            &expected,
            case.state,
            case.updated_at,
        );
    }
}

#[test]
fn committed_dispatch_marked_unknown_returns_its_projection() {
    let fixture = fixture(1, false, false);
    let (ids, evidence) = journaled_capture(&fixture, 360);
    let committed = claim(
        fixture.attempts.as_ref(),
        &ids,
        "dispatch-claim-a",
        &evidence,
    )
    .commit(|point| point.commit(COMMITTED_AT))
    .test_expect("commit dispatch");

    let failure = committed.unknown(denial(), DISPATCH_UNKNOWN, COMPLETED_AT);

    assert!(matches!(failure.error, BrokerError::AuthorizationDenied(_)));
    assert_eq!(failure.projection, Some(DISPATCH_UNKNOWN));
    assert_settled(
        "committed dispatch marked unknown",
        &fixture,
        &ids,
        &evidence,
        AttemptState::UnknownOutcome,
        COMPLETED_AT,
    );
}

#[test]
fn a_held_claim_refuses_a_second_owner() {
    let fixture = fixture(1, false, false);
    let (ids, evidence) = journaled_capture(&fixture, 361);
    let first = claim(
        fixture.attempts.as_ref(),
        &ids,
        "dispatch-claim-a",
        &evidence,
    );

    let Err(second) = ClaimedCapture::claim(
        fixture.attempts.as_ref(),
        &ids.attempt_id,
        "dispatch-claim-b".to_string(),
        evidence.clone(),
        CLAIMED_AT,
    ) else {
        panic!("a second owner claimed a held attempt");
    };

    assert!(matches!(second.error, BrokerError::Conflict(_)));
    assert_eq!(second.projection, None);
    assert_eq!(
        load(&fixture, &ids).dispatch_claim_id.as_deref(),
        Some("dispatch-claim-a")
    );
    drop(first);
    assert_settled(
        "first owner released",
        &fixture,
        &ids,
        &evidence,
        AttemptState::Captured,
        CLAIMED_AT,
    );
}

#[test]
fn an_unconfirmed_release_drops_the_capture_projection() {
    let fixture = fixture(1, false, false);
    let (ids, evidence) = journaled_capture(&fixture, 362);
    let claimed = claim(
        fixture.attempts.as_ref(),
        &ids,
        "dispatch-claim-a",
        &evidence,
    );
    fixture
        .attempts
        .clear_stale_captured_attempt_claim(&ids.attempt_id, CLAIMED_AT)
        .test_expect("clear claim behind the owner");

    let failure = claimed.refuse(denial());

    assert!(matches!(failure.error, BrokerError::AuthorizationDenied(_)));
    assert_eq!(failure.projection, None);
}

#[test]
fn a_commit_that_does_not_confirm_marks_the_outcome_unknown() {
    let fixture = fixture(1, false, false);
    let (ids, evidence) = journaled_capture(&fixture, 363);
    let claimed = claim(
        fixture.attempts.as_ref(),
        &ids,
        "dispatch-claim-a",
        &evidence,
    );
    claim_takeover(&fixture, &ids)().test_expect("hand the claim to a competitor");

    let failure = claimed
        .commit(|point| point.commit(COMMITTED_AT))
        .map(drop)
        .test_expect_err("commit without the claim");

    assert!(matches!(failure.error, BrokerError::Conflict(_)));
    assert_eq!(failure.projection, None);
    assert_settled(
        "commit without the claim",
        &fixture,
        &ids,
        &evidence,
        AttemptState::UnknownOutcome,
        CLAIMED_AT,
    );
}

/// Delegates to the fixture store, and panics in the two compensating
/// transitions once `fault` is set.
struct CompensationFaultStore {
    inner: Arc<SqliteAttemptStore>,
    fault: AtomicBool,
}

impl CompensationFaultStore {
    fn inject_fault(&self) {
        if self.fault.load(Ordering::SeqCst) {
            panic!("injected compensation fault");
        }
    }
}

impl AttemptStore for CompensationFaultStore {
    fn register_intent(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome> {
        self.inner.register_intent(registration, now_unix_seconds)
    }

    fn claim_registered_attempt(&self, attempt_id: &str, now_unix_seconds: u64) -> Result<bool> {
        self.inner
            .claim_registered_attempt(attempt_id, now_unix_seconds)
    }

    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome> {
        self.inner.register_attempt(registration, now_unix_seconds)
    }

    fn load_attempt(&self, attempt_id: &str) -> Result<Option<AttemptRecord>> {
        self.inner.load_attempt(attempt_id)
    }

    fn transition(
        &self,
        attempt_id: &str,
        expected: AttemptState,
        next: AttemptState,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        self.inject_fault();
        self.inner
            .transition(attempt_id, expected, next, evidence, now_unix_seconds)
    }

    fn claim_captured_attempt(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool> {
        self.inner
            .claim_captured_attempt(attempt_id, dispatch_claim_id, now_unix_seconds)
    }

    fn release_captured_attempt_claim(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool> {
        self.inject_fault();
        self.inner
            .release_captured_attempt_claim(attempt_id, dispatch_claim_id, now_unix_seconds)
    }

    fn commit_captured_attempt_dispatch(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        self.inner.commit_captured_attempt_dispatch(
            attempt_id,
            dispatch_claim_id,
            evidence,
            now_unix_seconds,
        )
    }

    fn clear_stale_captured_attempt_claim(
        &self,
        attempt_id: &str,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        self.inner
            .clear_stale_captured_attempt_claim(attempt_id, now_unix_seconds)
    }

    fn recoverable_attempts(
        &self,
        after_attempt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AttemptRecord>> {
        self.inner.recoverable_attempts(after_attempt_id, limit)
    }
}

#[test]
fn a_panicking_compensation_stays_inside_drop_even_while_unwinding() {
    let fixture = fixture(1, false, false);
    let (ids, evidence) = journaled_capture(&fixture, 364);
    let store = CompensationFaultStore {
        inner: Arc::clone(&fixture.attempts),
        fault: AtomicBool::new(false),
    };

    let claimed = claim(&store, &ids, "dispatch-claim-a", &evidence);
    store.fault.store(true, Ordering::SeqCst);
    drop(claimed);
    let record = load(&fixture, &ids);
    assert_eq!(
        (record.state, record.dispatch_claim_id.as_deref()),
        (AttemptState::Captured, Some("dispatch-claim-a")),
        "a failed release leaves the claim for startup reconciliation"
    );

    store.fault.store(false, Ordering::SeqCst);
    fixture
        .attempts
        .clear_stale_captured_attempt_claim(&ids.attempt_id, CLAIMED_AT)
        .test_expect("reconcile the stale claim");
    let committed = claim(&store, &ids, "dispatch-claim-b", &evidence)
        .commit(|point| point.commit(COMMITTED_AT))
        .test_expect("commit dispatch");
    store.fault.store(true, Ordering::SeqCst);
    expect_unwind(
        move || {
            let _committed = committed;
            panic!("request worker unwound");
        },
        "request worker unwound",
    );
    let record = load(&fixture, &ids);
    assert_eq!(
        (record.state, record.dispatch_claim_id.as_deref()),
        (AttemptState::DispatchCommitted, None),
        "a failed unknown mark leaves the commit for exact replay"
    );
}

#[test]
fn an_unwinding_execution_settles_the_claim_by_its_commit_stage() {
    for (name, unwinding_read, state, dispatches) in [
        (
            "unwind before dispatch authorization",
            1,
            AttemptState::Captured,
            0,
        ),
        (
            "unwind inside dispatch authorization before the commit",
            2,
            AttemptState::Captured,
            0,
        ),
        (
            "unwind after the dispatch",
            3,
            AttemptState::UnknownOutcome,
            1,
        ),
    ] {
        let fixture = fixture(1, false, false);
        let (request, trusted, ids, evidence) = captured_execution(&fixture, 370 + unwinding_read);
        let clock_reads = std::cell::Cell::new(0_usize);
        let terminal_clock = || {
            clock_reads.set(clock_reads.get() + 1);
            if clock_reads.get() == unwinding_read {
                panic!("request worker unwound");
            }
            Ok(TERMINAL)
        };

        expect_unwind(
            || {
                drop(
                    fixture
                        .service
                        .execute_inner(&request, &trusted, NOW, &terminal_clock),
                )
            },
            "request worker unwound",
        );

        assert_settled(name, &fixture, &ids, &evidence, state, NOW);
        assert_eq!(dispatch_count(&fixture), dispatches, "{name}");
    }
}
