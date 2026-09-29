use super::*;

#[test]
fn synchronous_batch_recovery_targets_its_batch_instead_of_the_global_backlog() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("exact-batch-recovery.sqlite"))
            .unwrap_or_else(|error| panic!("exact batch store: {error}")),
    );
    let older = authoritative_finding_with_identity(
        "finding-older-global-backlog",
        "rule-older-global-backlog",
        91,
    );
    let current = authoritative_finding_with_identity(
        "finding-current-exact-batch",
        "rule-current-exact-batch",
        92,
    );
    let older_publication = publish_recovery_batch(store.as_ref(), std::slice::from_ref(&older));
    let current_publication =
        build_attested_finding_batch_publication(std::slice::from_ref(&current))
            .unwrap_or_else(|error| panic!("current exact publication: {error}"));
    let global_scan_called = Arc::new(AtomicBool::new(false));
    let coordinator = Arc::new(RecordingResponseCoordinator::default());
    let findings = vec![older, current.clone()];
    let planner = DurableAttestedFindingBatchPlanner::new(
        Arc::clone(&store) as Arc<dyn AttestedFindingBatchStore>,
        Arc::new(RejectingGlobalScanOutboxStore {
            inner: Arc::clone(&store),
            global_scan_called: Arc::clone(&global_scan_called),
        }),
        Arc::new(TestFindingAuthority::new(&findings)),
        Arc::new(RecordingResponsePolicy),
        Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
        Arc::new(FixedClock(10_002)),
    )
    .unwrap_or_else(|error| panic!("exact batch planner: {error}"));

    planner
        .publish_attested_batch(std::slice::from_ref(&current))
        .unwrap_or_else(|error| panic!("exact batch publication: {error}"));

    assert!(!global_scan_called.load(Ordering::Acquire));
    let current_record = store
        .load_attested_finding_response_outbox(&recovery_outbox_key(&current_publication, 0))
        .unwrap_or_else(|error| panic!("current exact response: {error}"))
        .unwrap_or_else(|| panic!("current exact response missing"));
    assert_eq!(
        current_record.completion_state,
        AttestedFindingResponseCompletionState::Completed
    );
    let older_record = store
        .load_attested_finding_response_outbox(&recovery_outbox_key(&older_publication, 0))
        .unwrap_or_else(|error| panic!("older backlog response: {error}"))
        .unwrap_or_else(|| panic!("older backlog response missing"));
    assert_eq!(
        older_record.planning_state,
        AttestedFindingResponsePlanningState::Pending
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
