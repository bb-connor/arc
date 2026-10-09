use super::*;

use crate::store::{AttemptIds, AttemptRecord};

/// Quota-enforcement checks inside `execute_inner`, in execution order.
const AFTER_BOUNDARY_CAPTURE: usize = 4;

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
        "{record:?}"
    );
    assert_eq!(&record_evidence(&record), evidence);
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
    assert_settled(&fixture, &ids, &evidence, AttemptState::Captured, NOW);
    assert_eq!(dispatch_count(&fixture), 0);
}
