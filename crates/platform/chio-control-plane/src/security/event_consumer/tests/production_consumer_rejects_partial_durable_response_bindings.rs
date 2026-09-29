use super::*;


    #[test]
    fn production_consumer_rejects_partial_durable_response_bindings() {
        let keypair = Keypair::from_seed(&[87_u8; 32]);
        let consumer = ProductionCorrelationConsumer::from_parts(
            Arc::new(verifier(&keypair)),
            Arc::new(OneFindingCorrelation),
            Arc::new(ReverseLexicographicAttestor),
            Arc::new(MutatingReadbackPlanner::new(ReadbackMutation::DropLast)),
        )
        .unwrap_or_else(|error| panic!("consumer: {error}"));

        let error = rejected(
            consumer.consume(&signed_event(&keypair)),
            "missing one-to-one action and dispatch binding must fail closed",
        );
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::IntegrityFailure
        );
    }
