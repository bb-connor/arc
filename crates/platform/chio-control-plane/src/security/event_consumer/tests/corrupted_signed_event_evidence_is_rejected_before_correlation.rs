use super::*;


    #[test]
    fn corrupted_signed_event_evidence_is_rejected_before_correlation() {
        let keypair = Keypair::from_seed(&[71_u8; 32]);
        let verifier = verifier(&keypair);
        let mut event = signed_event(&keypair);
        let mut corrupted = event.source_evidence.as_bytes().to_vec();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 1;
        }
        event.source_evidence = CanonicalBody::new(corrupted)
            .unwrap_or_else(|error| panic!("corrupted evidence body: {error}"));
        assert!(verifier.verify(&event).is_err());
    }
