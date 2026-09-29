use super::*;

#[test]
fn durable_recovery_crosses_plan_artifact_prepare_and_completion_crash_boundaries() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("response-crashes.sqlite"))
            .unwrap_or_else(|error| panic!("recovery store: {error}")),
    );
    let findings = vec![authoritative_finding()];
    let publication = publish_recovery_batch(store.as_ref(), &findings);
    let key = recovery_outbox_key(&publication, 0);
    let clock = Arc::new(MutableClock::new(10_002));
    let effects = Arc::new(AtomicUsize::new(0));

    let plan_only = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(false, false, Arc::clone(&effects))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    let report = plan_only
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("plan-only pass: {error}"));
    assert_eq!(report.plans_published, 1);
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("planned row: {error}"))
        .unwrap_or_else(|| panic!("planned row missing"));
    assert_eq!(
        planned.planning_state,
        AttestedFindingResponsePlanningState::Planned
    );
    assert!(planned.admission_artifact_digest.is_none());

    let fail_prepare = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(true, false, Arc::clone(&effects))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    assert!(fail_prepare.resume_incomplete_pass(1).is_err());
    let artifact_bound = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("artifact-bound row: {error}"))
        .unwrap_or_else(|| panic!("artifact-bound row missing"));
    assert_eq!(
        artifact_bound.admission_artifact_digest,
        Some(Digest32::new([74_u8; 32]))
    );
    assert_eq!(
        artifact_bound.admission_state,
        AttestedFindingResponseAdmissionState::Pending
    );

    clock.set(artifact_bound.next_attempt_at_unix_ms.saturating_add(1));
    let fail_execute = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(false, true, Arc::clone(&effects))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    assert!(fail_execute.resume_incomplete_pass(1).is_err());
    let prepared = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("prepared row: {error}"))
        .unwrap_or_else(|| panic!("prepared row missing"));
    assert_eq!(
        prepared.admission_state,
        AttestedFindingResponseAdmissionState::Prepared
    );
    assert_eq!(
        prepared.completion_state,
        AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
    );

    clock.set(prepared.next_attempt_at_unix_ms.saturating_add(1));
    let recovered = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(false, false, Arc::clone(&effects))),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    recovered
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("completion recovery: {error}"));
    let completed = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("completed row: {error}"))
        .unwrap_or_else(|| panic!("completed row missing"));
    assert_eq!(
        completed.completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(effects.load(Ordering::Acquire), 1);
}
