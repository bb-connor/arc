use super::*;

#[test]
fn rewritten_prepared_binding_resume_failure_stays_outcome_unknown() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("rewritten-binding.sqlite"))
            .unwrap_or_else(|error| panic!("rewritten binding store: {error}")),
    );
    let findings = vec![authoritative_finding()];
    let publication = publish_recovery_batch(store.as_ref(), &findings);
    let key = recovery_outbox_key(&publication, 0);
    let effects = Arc::new(AtomicUsize::new(0));
    let initial = recovery_planner(
        Arc::clone(&store),
        &findings,
        Arc::new(GovernedRecoveryPolicy {
            artifacts_unavailable: false,
        }),
        Arc::new(RecoveryCoordinator::new(false, false, Arc::clone(&effects))),
        Arc::new(FixedClock(10_002)),
    );
    initial
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("prime rewritten binding plan: {error}"));
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load rewritten binding plan: {error}"))
        .unwrap_or_else(|| panic!("rewritten binding plan missing"));
    let expires_at_unix_ms = planned
        .publication
        .as_ref()
        .unwrap_or_else(|| panic!("rewritten binding publication missing"))
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
        .unwrap_or_else(|error| panic!("bind rewritten artifacts: {error}"));
    let dispatch_id = RecordId::new(format!("recovery-dispatch-{}", key.action_id.as_str()))
        .unwrap_or_else(|error| panic!("rewritten dispatch id: {error}"));
    let mut rewritten = prepared_binding_for_outbox(&bound, dispatch_id.clone());
    rewritten.governed_intent_hash = Digest32::new([88_u8; 32]);
    rewritten.policy_decision_hash = Digest32::new([89_u8; 32]);
    store
        .transition_attested_finding_response_outbox(
            &bound,
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding: Box::new(rewritten.clone()),
            },
        )
        .unwrap_or_else(|error| panic!("stage rewritten prepared binding: {error}"));

    let resume_calls = Arc::new(AtomicUsize::new(0));
    let termination_calls = Arc::new(AtomicUsize::new(0));
    let restarted = recovery_planner(
        Arc::clone(&store),
        &[],
        Arc::new(GovernedRecoveryPolicy {
            artifacts_unavailable: true,
        }),
        Arc::new(RecoveryCoordinator::resume_integrity_failure(
            Arc::clone(&resume_calls),
            Arc::clone(&termination_calls),
            Arc::clone(&effects),
        )),
        Arc::new(FixedClock(expires_at_unix_ms)),
    );
    let error = rejected(
        restarted.resume_incomplete_pass(1),
        "rewritten operation anchor must fail closed",
    );
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);

    let retained = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load rewritten binding result: {error}"))
        .unwrap_or_else(|| panic!("rewritten binding result missing"));
    assert_eq!(
        retained.admission_state,
        AttestedFindingResponseAdmissionState::Prepared
    );
    assert_eq!(
        retained.completion_state,
        AttestedFindingResponseCompletionState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(retained.prepared_dispatch_binding, Some(rewritten));
    assert!(!retained.is_complete());
    assert_eq!(resume_calls.load(Ordering::Acquire), 1);
    assert_eq!(termination_calls.load(Ordering::Acquire), 0);
    assert_eq!(effects.load(Ordering::Acquire), 0);
}
