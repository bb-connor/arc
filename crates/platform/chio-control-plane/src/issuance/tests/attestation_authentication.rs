use super::*;

#[test]
fn unsigned_matching_attestation_cannot_mint_verified_capabilities() {
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new_with_clock(
            Keypair::generate(),
            chio_test_support::clock::clock(),
        )),
        None,
        Some(test_trusted_runtime_assurance_policy()),
        None,
        None,
    );
    let subject = Keypair::generate();
    for evidence in [
        test_azure_runtime_attestation(),
        test_google_runtime_attestation(),
    ] {
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_owned(),
                tool_name: "charge".to_owned(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::GovernedIntentRequired],
                max_invocations: Some(10),
                max_cost_per_invocation: Some(MonetaryAmount {
                    units: 500,
                    currency: "USD".to_owned(),
                }),
                max_total_cost: Some(MonetaryAmount {
                    units: 5_000,
                    currency: "USD".to_owned(),
                }),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let error = authority
            .issue_capability_with_attestation(&subject.public_key(), scope, 120, Some(evidence))
            .test_expect_err("matching unsigned claims cannot unlock verified authority");
        assert!(matches!(error, KernelError::CapabilityIssuanceDenied(_)));
        assert!(error.to_string().contains("authenticated"), "{error}");
    }
}
