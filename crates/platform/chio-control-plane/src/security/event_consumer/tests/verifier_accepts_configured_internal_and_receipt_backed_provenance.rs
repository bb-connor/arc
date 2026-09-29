use super::*;


    #[test]
    fn verifier_accepts_configured_internal_and_receipt_backed_provenance() {
        let internal = Keypair::from_seed(&[75_u8; 32]);
        let receipt = Keypair::from_seed(&[76_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &receipt, Arc::new(FixedClock(10_000)));

        let internal_verified = verifier
            .verify(&signed_event(&internal))
            .unwrap_or_else(|error| panic!("internal verification: {error}"));
        let receipt_verified = verifier
            .verify(&receipt_event(
                &receipt,
                ToolOrigin::ChioInternal,
                9_900,
                10_000,
            ))
            .unwrap_or_else(|error| panic!("receipt verification: {error}"));

        assert_eq!(
            internal_verified.trust_class,
            ProducerTrustClass::InternalDetector
        );
        assert_eq!(
            receipt_verified.trust_class,
            ProducerTrustClass::VerifiedReceipt
        );
    }
