use super::*;

#[test]
fn committed_dispatch_recovers_before_mutable_finding_policy_or_live_readiness() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("committed-recovery.sqlite"))
            .unwrap_or_else(|error| panic!("committed recovery store: {error}")),
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
        .unwrap_or_else(|error| panic!("prime committed recovery plan: {error}"));
    let planned = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load committed recovery plan: {error}"))
        .unwrap_or_else(|| panic!("committed recovery plan missing"));
    let response_plan = planned
        .publication
        .as_ref()
        .unwrap_or_else(|| panic!("committed recovery publication missing"))
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
        .unwrap_or_else(|error| panic!("bind committed recovery artifacts: {error}"));
    let dispatch_id = RecordId::new(format!("recovery-dispatch-{}", key.action_id.as_str()))
        .unwrap_or_else(|error| panic!("committed recovery dispatch id: {error}"));
    let prepared_dispatch_binding = prepared_binding_for_outbox(&bound, dispatch_id.clone());
    store
        .transition_attested_finding_response_outbox(
            &bound,
            AttestedFindingResponseOutboxTransition::AdmissionPrepared {
                prepared_dispatch_binding: Box::new(prepared_dispatch_binding),
            },
        )
        .unwrap_or_else(|error| panic!("stage committed recovery dispatch: {error}"));

    let recovery_calls = Arc::new(AtomicUsize::new(0));
    let proof = AttestedFindingResponseCompletionProof::synthetic(
        dispatch_id.clone(),
        AttestedFindingResponseCompletionOutcome::Activated,
        OpaqueReceiptRef::new("committed-recovery-evidence")
            .unwrap_or_else(|error| panic!("committed recovery evidence id: {error}")),
        Digest32::new([76_u8; 32]),
    );
    let restarted = recovery_planner(
        Arc::clone(&store),
        &[],
        Arc::new(RecoveryPolicy {
            artifacts_unavailable: true,
        }),
        Arc::new(RecoveryCoordinator::committed(
            response_plan.plan_hash,
            proof,
            Arc::clone(&recovery_calls),
            Arc::clone(&effects),
        )),
        Arc::new(FixedClock(10_002)),
    );
    restarted
        .resume_incomplete_pass(1)
        .unwrap_or_else(|error| panic!("recover committed dispatch: {error}"));

    let completed = store
        .load_attested_finding_response_outbox(&key)
        .unwrap_or_else(|error| panic!("load committed recovery result: {error}"))
        .unwrap_or_else(|| panic!("committed recovery result missing"));
    assert_eq!(
        completed.completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(completed.execution_dispatch_id, Some(dispatch_id));
    assert_eq!(recovery_calls.load(Ordering::Acquire), 1);
    assert_eq!(effects.load(Ordering::Acquire), 0);
}
