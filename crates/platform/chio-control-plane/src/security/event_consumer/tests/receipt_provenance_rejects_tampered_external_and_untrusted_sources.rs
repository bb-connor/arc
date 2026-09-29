use super::*;


    #[test]
    fn receipt_provenance_rejects_tampered_external_and_untrusted_sources() {
        let internal = Keypair::from_seed(&[77_u8; 32]);
        let trusted = Keypair::from_seed(&[78_u8; 32]);
        let untrusted = Keypair::from_seed(&[79_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &trusted, Arc::new(FixedClock(10_000)));

        let mut tampered = receipt_event(&trusted, ToolOrigin::ChioInternal, 9_900, 10_000);
        let mut receipt: ChioReceipt = serde_json::from_slice(tampered.source_evidence.as_bytes())
            .unwrap_or_else(|error| panic!("receipt decode: {error}"));
        receipt.capability_id = "external.security-event".to_string();
        tampered.source_evidence = CanonicalBody::new(
            canonical_json_bytes(&receipt)
                .unwrap_or_else(|error| panic!("tampered receipt: {error}")),
        )
        .unwrap_or_else(|error| panic!("tampered evidence: {error}"));

        assert!(verifier.verify(&tampered).is_err());
        assert!(verifier
            .verify(&receipt_event(
                &trusted,
                ToolOrigin::HostExecutedProviderReported,
                9_900,
                10_000,
            ))
            .is_err());
        assert!(verifier
            .verify(&receipt_event(
                &untrusted,
                ToolOrigin::ChioInternal,
                9_900,
                10_000,
            ))
            .is_err());
    }
