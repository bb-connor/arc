use super::*;

#[test]
fn production_consumer_rejects_drop_all_planner_without_read_after_write_proof() {
    let keypair = Keypair::from_seed(&[83_u8; 32]);
    let planner = Arc::new(DropAllPlanner::default());
    let consumer = ProductionCorrelationConsumer::from_parts(
        Arc::new(verifier(&keypair)),
        Arc::new(OneFindingCorrelation),
        Arc::new(OneFindingAttestor),
        Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
    )
    .unwrap_or_else(|error| panic!("consumer: {error}"));

    let error = rejected(
        consumer.consume(&signed_event(&keypair)),
        "drop-all planner must fail read-after-write verification",
    );
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::IntegrityFailure
    );
    assert!(planner.published.load(Ordering::Acquire));
}
