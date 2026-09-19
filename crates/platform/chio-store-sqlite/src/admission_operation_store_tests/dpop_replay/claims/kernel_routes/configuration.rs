use super::*;

#[test]
fn configuring_a_domain_requires_prior_activation_and_cannot_change_it() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let domain = super::super::super::activation::domain(&imported)?;
    let mut kernel = kernel(&fixture, Keypair::generate())?;
    let before = global_count(&fixture);
    let calls = source.calls();
    assert!(kernel
        .set_operation_owned_dpop_authority(domain.clone())
        .is_err());
    assert_eq!(global_count(&fixture), before);
    assert_eq!(
        source.calls(),
        calls,
        "configuration must not import or activate"
    );
    fixture
        .store
        .activate_dpop_replay_source(&domain, &source, &fixture.fence, now_ms())?;
    let calls = source.calls();
    kernel.set_operation_owned_dpop_authority(domain.clone())?;
    kernel.set_operation_owned_dpop_authority(domain.clone())?;
    assert_eq!(
        source.calls(),
        calls,
        "serving selection never reopens the retired source"
    );
    let replacement =
        DpopReplayAuthorityV1::new(chio_kernel::dpop::authority::DpopReplayAuthorityInputV1 {
            destination_store_uuid: domain.destination_store_uuid().clone(),
            dpop_authority_id: domain.dpop_authority_id().clone(),
            expectation_id: domain.expectation_id().clone(),
            proof_ttl_secs: domain.proof_ttl_secs() + 1,
            max_clock_skew_secs: domain.max_clock_skew_secs(),
        })?;
    assert!(kernel
        .set_operation_owned_dpop_authority(replacement)
        .is_err());
    kernel.set_operation_owned_dpop_authority(domain)?;
    assert_eq!(
        global_count(&fixture),
        before + 1,
        "only explicit activation may write"
    );
    Ok(())
}
