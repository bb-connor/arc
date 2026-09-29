use super::*;

#[test]
fn synchronous_batch_recovery_processes_every_binding_and_preserves_the_first_error() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("complete-batch-recovery.sqlite"))
            .unwrap_or_else(|error| panic!("complete batch store: {error}")),
    );
    let first = authoritative_finding_with_identity(
        "finding-first-terminal-failure",
        "rule-first-terminal-failure",
        93,
    );
    let second = authoritative_finding_with_identity(
        "finding-second-terminal-failure",
        "rule-second-terminal-failure",
        94,
    );
    let third =
        authoritative_finding_with_identity("finding-third-success", "rule-third-success", 95);
    let findings = vec![first.clone(), second.clone(), third.clone()];
    let publication = build_attested_finding_batch_publication(&findings)
        .unwrap_or_else(|error| panic!("complete batch publication: {error}"));
    let first_error_code = ErrorCode::new("active_response.first_terminal_failure")
        .unwrap_or_else(|error| panic!("first error code: {error}"));
    let second_error_code = ErrorCode::new("active_response.second_terminal_failure")
        .unwrap_or_else(|error| panic!("second error code: {error}"));
    let policy = Arc::new(SelectiveArtifactResponsePolicy {
        rejected: BTreeMap::from([
            (first.evidence_id().clone(), first_error_code.clone()),
            (second.evidence_id().clone(), second_error_code.clone()),
        ]),
    });
    let coordinator = Arc::new(RecordingResponseCoordinator::default());
    let planner = recovery_planner(
        Arc::clone(&store),
        &findings,
        policy,
        Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
        Arc::new(FixedClock(10_002)),
    );

    let error = rejected(
        planner.publish_attested_batch(&findings),
        "the first terminal response error must fail the batch",
    );
    let replay_error = rejected(
        planner.publish_attested_batch(&findings),
        "terminal response replay must preserve the first batch error",
    );

    assert_eq!(error.code(), &first_error_code);
    assert_eq!(replay_error.code(), &first_error_code);
    for (ordinal, expected_error_code) in
        [(0_usize, &first_error_code), (1_usize, &second_error_code)]
    {
        let rejected = store
            .load_attested_finding_response_outbox(&recovery_outbox_key(&publication, ordinal))
            .unwrap_or_else(|load_error| panic!("rejected response: {load_error}"))
            .unwrap_or_else(|| panic!("rejected response missing"));
        assert_eq!(
            rejected.admission_state,
            AttestedFindingResponseAdmissionState::Rejected
        );
        assert_eq!(rejected.last_error_code.as_ref(), Some(expected_error_code));
    }
    let completed = store
        .load_attested_finding_response_outbox(&recovery_outbox_key(&publication, 2))
        .unwrap_or_else(|error| panic!("completed response: {error}"))
        .unwrap_or_else(|| panic!("completed response missing"));
    assert_eq!(
        completed.completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    assert_eq!(
        coordinator
            .executions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len(),
        1
    );
}
