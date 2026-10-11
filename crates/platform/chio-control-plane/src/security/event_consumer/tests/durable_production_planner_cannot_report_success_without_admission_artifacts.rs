use super::*;

#[test]
fn durable_production_planner_cannot_report_success_without_admission_artifacts() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("missing-admission.sqlite"))
            .unwrap_or_else(|error| panic!("admission store: {error}")),
    );
    let coordinator = Arc::new(ArtifactEnforcingCoordinator::default());
    let planner = DurableAttestedFindingBatchPlanner::new(
        Arc::clone(&store) as Arc<dyn chio_security_types::ports::AttestedFindingBatchStore>,
        Arc::clone(&store) as Arc<dyn AttestedFindingResponseOutboxStore>,
        Arc::new(TestFindingAuthority::new(std::slice::from_ref(
            &authoritative_finding(),
        ))),
        Arc::new(MissingArtifactResponsePolicy),
        Arc::clone(&coordinator) as Arc<dyn AttestedFindingResponseCoordinator>,
        Arc::new(FixedClock(10_002)),
    )
    .unwrap_or_else(|error| panic!("durable planner: {error}"));
    let finding = authoritative_finding();
    let expected = build_attested_finding_batch_publication(std::slice::from_ref(&finding))
        .unwrap_or_else(|error| panic!("expected publication: {error}"));
    planner
        .publish_attested_batch(std::slice::from_ref(&finding))
        .unwrap_or_else(|error| panic!("a durable admission refusal is acknowledgeable: {error}"));
    planner
        .publish_attested_batch(std::slice::from_ref(&finding))
        .unwrap_or_else(|error| panic!("a durable admission refusal replays as refused: {error}"));
    assert!(!coordinator.effects_applied.load(Ordering::Acquire));
    let refused = store
        .load_attested_finding_response_outbox(&recovery_outbox_key(&expected, 0))
        .unwrap_or_else(|error| panic!("refused response: {error}"))
        .unwrap_or_else(|| panic!("refused response missing"));
    assert_eq!(
        refused.admission_state,
        AttestedFindingResponseAdmissionState::Rejected
    );
    assert_eq!(
        refused.completion_state,
        AttestedFindingResponseCompletionState::NotStarted
    );
    assert_eq!(
        refused.last_error_code.as_ref(),
        Some(PortError::integrity_failure().code())
    );
    assert_eq!(
        planner
            .load_published_attested_batch(&AttestedFindingBatchKey {
                tenant_id: expected.body.tenant_id.clone(),
                batch_id: expected.body.batch_id.clone(),
            })
            .unwrap_or_else(|error| panic!("dry-run batch: {error}")),
        expected
    );
}
