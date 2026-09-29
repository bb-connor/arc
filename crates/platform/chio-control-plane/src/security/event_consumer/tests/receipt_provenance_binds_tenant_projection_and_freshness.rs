use super::*;


    #[test]
    fn receipt_provenance_binds_tenant_projection_and_freshness() {
        let internal = Keypair::from_seed(&[80_u8; 32]);
        let receipt = Keypair::from_seed(&[81_u8; 32]);
        let verifier = verifier_with_receipts(&internal, &receipt, Arc::new(FixedClock(100_000)));
        let mut wrong_tenant = receipt_event(&receipt, ToolOrigin::ChioInternal, 99_900, 100_000);
        wrong_tenant.tenant_id =
            TenantId::new("other-tenant").unwrap_or_else(|error| panic!("tenant id: {error}"));

        assert!(verifier.verify(&wrong_tenant).is_err());
        assert!(verifier
            .verify(&receipt_event(
                &receipt,
                ToolOrigin::ChioInternal,
                10_000,
                10_000,
            ))
            .is_err());
    }
