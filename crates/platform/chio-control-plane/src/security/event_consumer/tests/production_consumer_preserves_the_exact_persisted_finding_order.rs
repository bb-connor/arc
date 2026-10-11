use super::*;

#[test]
fn production_consumer_preserves_the_exact_persisted_finding_order() {
    let keypair = Keypair::from_seed(&[85_u8; 32]);
    let planner = Arc::new(RecordingPlanner::default());
    let expected = reverse_lexicographic_findings()
        .into_iter()
        .map(|finding| finding.evidence_id().clone())
        .collect::<Vec<_>>();
    assert!(expected[0] > expected[1]);
    let consumer = ProductionCorrelationConsumer::from_parts(
        Arc::new(verifier(&keypair)),
        Arc::new(OneFindingCorrelation),
        Arc::new(ReverseLexicographicAttestor),
        Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
    )
    .unwrap_or_else(|error| panic!("consumer: {error}"));

    let report = consumer
        .consume(&signed_event(&keypair))
        .unwrap_or_else(|error| panic!("persisted planner order rejected: {error}"));
    assert_eq!(report.attested_finding_ids, expected);
}
