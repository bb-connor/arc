use super::*;

#[test]
fn production_consumer_accepts_and_reports_the_exact_persisted_finding_batch() {
    let keypair = Keypair::from_seed(&[84_u8; 32]);
    let planner = Arc::new(RecordingPlanner::default());
    let expected_id = authoritative_finding().evidence_id().clone();
    let consumer = ProductionCorrelationConsumer::from_parts(
        Arc::new(verifier(&keypair)),
        Arc::new(OneFindingCorrelation),
        Arc::new(OneFindingAttestor),
        Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
    )
    .unwrap_or_else(|error| panic!("consumer: {error}"));

    let report = consumer
        .consume(&signed_event(&keypair))
        .unwrap_or_else(|error| panic!("persisted planner batch rejected: {error}"));
    assert_eq!(report.attested_finding_ids, vec![expected_id.clone()]);
    let batches = planner
        .batches
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].body.bindings.as_slice()[0].evidence_id,
        expected_id
    );
}
