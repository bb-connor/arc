use super::*;

#[test]
fn authoritative_never_committed_probe_closes_prepared_dispatch_terminally() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("never-committed.sqlite"))
            .unwrap_or_else(|error| panic!("never-committed store: {error}")),
    );
    let findings = vec![authoritative_finding()];
    let publication = publish_recovery_batch(store.as_ref(), &findings);
    let key = recovery_outbox_key(&publication, 0);
    let clock = Arc::new(MutableClock::new(10_002));
    let effects = Arc::new(AtomicUsize::new(0));
    let termination_calls = Arc::new(AtomicUsize::new(0));
    let planner = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::never_committed(
            Arc::clone(&effects),
            Arc::clone(&termination_calls),
        )),
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    planner
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("prime never-committed plan: {error}"));
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load never-committed plan: {error}"))
        .unwrap_or_else(|| panic!("never-committed plan missing"));
    let bound = store
        .transition_attested_finding_response_outbox(
            &planned,
            AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                artifact_digest: Digest32::new([74_u8; 32]),
            },
        )
        .unwrap_or_else(|error| panic!("bind never-committed artifacts: {error}"));
    let dispatch_id = RecordId::new(format!("recovery-dispatch-{}", key.action_id.as_str()))
        .unwrap_or_else(|error| panic!("never-committed dispatch id: {error}"));
    let prepared_dispatch_binding = prepared_binding_for_outbox(&bound, dispatch_id.clone());
    store
        .transition_attested_finding_response_outbox(
            &bound,
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
            },
        )
        .unwrap_or_else(|error| panic!("stage never-committed prepared row: {error}"));
    let error = rejected(
        planner.resume_incomplete_pass(1),
        "authoritative never-committed proof must close with its terminal error",
    );
    assert_eq!(error.code().as_str(), "active_response.never_committed");
    let terminal = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load never-committed terminal row: {error}"))
        .unwrap_or_else(|| panic!("never-committed terminal row missing"));
    assert_eq!(
        terminal.admission_state,
        AttestedFindingResponseAdmissionState::Expired
    );
    assert_eq!(terminal.execution_dispatch_id, Some(dispatch_id));
    assert_eq!(
        terminal.completion_state,
        AttestedFindingResponseCompletionState::NotStarted
    );
    assert!(terminal.is_complete());
    assert_eq!(effects.load(Ordering::Acquire), 0);
    assert_eq!(termination_calls.load(Ordering::Acquire), 1);
}
