use super::*;

#[test]
fn expired_prepared_dispatch_terminates_without_mutable_live_dependencies() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("expired-prepared.sqlite"))
            .unwrap_or_else(|error| panic!("expired prepared store: {error}")),
    );
    let findings = vec![authoritative_finding()];
    let publication = publish_recovery_batch(store.as_ref(), &findings);
    let key = recovery_outbox_key(&publication, 0);
    let effects = Arc::new(AtomicUsize::new(0));
    let initial = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(false, false, Arc::clone(&effects))),
        Arc::new(FixedClock(10_002)),
    );
    initial
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("prime expired prepared plan: {error}"));
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load expired prepared plan: {error}"))
        .unwrap_or_else(|| panic!("expired prepared plan missing"));
    let expires_at_unix_ms = planned
        .publication
        .as_ref()
        .unwrap_or_else(|| panic!("expired prepared publication missing"))
        .body
        .response_plan
        .expires_at_unix_ms;
    let bound = store
        .transition_attested_finding_response_outbox(
            &planned,
            AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                artifact_digest: Digest32::new([74_u8; 32]),
            },
        )
        .unwrap_or_else(|error| panic!("bind expired prepared artifacts: {error}"));
    let dispatch_id = RecordId::new(format!("recovery-dispatch-{}", key.action_id.as_str()))
        .unwrap_or_else(|error| panic!("expired prepared dispatch id: {error}"));
    let prepared_dispatch_binding = prepared_binding_for_outbox(&bound, dispatch_id.clone());
    store
        .transition_attested_finding_response_outbox(
            &bound,
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding: Box::new(prepared_dispatch_binding.clone()),
            },
        )
        .unwrap_or_else(|error| panic!("stage expired prepared dispatch: {error}"));

    let termination_calls = Arc::new(AtomicUsize::new(0));
    let restarted = recovery_planner(
        Arc::clone(&store),
        &[],
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: true,
        }),
        Arc::new(RecoveryCoordinator::expired_never_committed(
            Arc::clone(&effects),
            Arc::clone(&termination_calls),
        )),
        Arc::new(FixedClock(expires_at_unix_ms)),
    );
    let error = rejected(
        restarted.resume_incomplete_pass(1),
        "expired prepared dispatch must close with its typed terminal error",
    );
    assert_eq!(error.code().as_str(), "active_response.never_committed");

    let terminal = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load expired prepared result: {error}"))
        .unwrap_or_else(|| panic!("expired prepared result missing"));
    assert_eq!(
        terminal.admission_state,
        AttestedFindingResponseAdmissionState::Expired
    );
    assert_eq!(terminal.execution_dispatch_id, Some(dispatch_id));
    assert_eq!(
        terminal.prepared_dispatch_binding,
        Some(prepared_dispatch_binding)
    );
    assert_eq!(
        terminal.completion_state,
        AttestedFindingResponseCompletionState::NotStarted
    );
    assert_eq!(termination_calls.load(Ordering::Acquire), 1);
    assert_eq!(effects.load(Ordering::Acquire), 0);
}
