use super::*;


    #[test]
    fn attestation_failure_never_partially_publishes_raw_findings_to_planning() {
        let keypair = Keypair::from_seed(&[74_u8; 32]);
        let planner = Arc::new(RecordingPlanner::default());
        let attestor = Arc::new(FailSecondAttestation {
            calls: Mutex::new(0),
        });
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(TwoOutcomeCorrelation),
            Arc::clone(&attestor) as Arc<dyn CorrelationAttestor>,
            Arc::clone(&planner) as Arc<dyn AttestedFindingBatchPlanner>,
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));
        assert!(consumer.consume(&signed_event(&keypair)).is_err());
        assert_eq!(attestor.calls.lock().map_or(0, |calls| *calls), 2);
        assert!(planner
            .batches
            .lock()
            .is_ok_and(|batches| batches.is_empty()));
    }
