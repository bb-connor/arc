use super::*;

#[test]
fn operation_committed_dispatch_resumes_after_executor_readback_is_missing() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("operation-committed.sqlite"))
            .unwrap_or_else(|error| panic!("operation committed store: {error}")),
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
        .unwrap_or_else(|error| panic!("prime operation committed plan: {error}"));
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load operation committed plan: {error}"))
        .unwrap_or_else(|| panic!("operation committed plan missing"));
    let response_plan = planned
        .publication
        .as_ref()
        .unwrap_or_else(|| panic!("operation committed publication missing"))
        .body
        .response_plan
        .clone();
    let bound = store
        .transition_attested_finding_response_outbox(
            &planned,
            AttestedFindingResponseOutboxTransition::AdmissionArtifactsBound {
                artifact_digest: Digest32::new([74_u8; 32]),
            },
        )
        .unwrap_or_else(|error| panic!("bind operation committed artifacts: {error}"));
    let dispatch_id = RecordId::new(format!("recovery-dispatch-{}", key.action_id.as_str()))
        .unwrap_or_else(|error| panic!("operation committed dispatch id: {error}"));
    let prepared_dispatch_binding = prepared_binding_for_outbox(&bound, dispatch_id.clone());
    store
        .transition_attested_finding_response_outbox(
            &bound,
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
            },
        )
        .unwrap_or_else(|error| panic!("stage operation committed dispatch: {error}"));

    let resume_calls = Arc::new(AtomicUsize::new(0));
    let proof = AttestedFindingResponseCompletionProof::synthetic(
        dispatch_id.clone(),
        AttestedFindingResponseCompletionOutcome::FailedBeforeEffect,
        OpaqueReceiptRef::new("operation-committed-terminal-evidence")
            .unwrap_or_else(|error| panic!("operation committed evidence id: {error}")),
        Digest32::new([77_u8; 32]),
    );
    let restarted = recovery_planner(
        Arc::clone(&store),
        &[],
        Arc::new(GovernedRecoveryPolicy {
            artifacts_unavailable: true,
        }),
        Arc::new(RecoveryCoordinator::dispatch_committed(
            response_plan.plan_hash,
            proof,
            Arc::clone(&resume_calls),
            Arc::clone(&effects),
        )),
        Arc::new(FixedClock(10_002)),
    );
    restarted
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("resume operation committed dispatch: {error}"));

    let completed = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load operation committed result: {error}"))
        .unwrap_or_else(|| panic!("operation committed result missing"));
    assert_eq!(
        completed.completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(completed.execution_dispatch_id, Some(dispatch_id));
    assert_eq!(
        completed.completion_outcome,
        Some(AttestedFindingResponseCompletionOutcome::FailedBeforeEffect)
    );
    assert_eq!(resume_calls.load(Ordering::Acquire), 1);
    assert_eq!(effects.load(Ordering::Acquire), 0);
}
