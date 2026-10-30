use super::*;

#[test]
fn required_swarm_kernel_dispatches_verified_capability_and_signs_binding() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_001);
    let fixture = BindingFixture::new()?;
    let invocations = fixture.inner.invocations.clone();
    let kernel = &fixture.kernel;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(
        response.verdict,
        chio_kernel::Verdict::Allow,
        "{response:#?}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_integrity_embedded_key()?);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| io::Error::other("missing receipt metadata"))?;
    let binding = &metadata["chio_runtime"]["verified_swarm_request_binding"];
    assert_eq!(binding["task_id"], "task-child-a");
    assert_eq!(
        binding["capability_sha256"],
        canonical_test_hash(&fixture.request.capability)?
    );
    Ok(())
}

#[test]
fn required_swarm_kernel_denies_omission_or_capability_substitution_before_tool() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_001);
    for substitution in [false, true] {
        let fixture = BindingFixture::new()?;
        let invocations = fixture.inner.invocations.clone();
        let kernel = &fixture.kernel;
        let mut request = fixture.request;
        let expected = if substitution {
            let mut body = request.capability.body();
            body.expires_at -= 1;
            request.capability = CapabilityToken::sign(body, &swarm_witness_keypair())?;
            "chio_swarm_authority_rejected"
        } else {
            request.governed_intent = None;
            "missing_chio_swarm_context"
        };
        let response = kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(swarm_route_metadata()))?;
        assert_eq!(
            response.verdict,
            chio_kernel::Verdict::Deny,
            "{response:#?}"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(response.receipt.verify_integrity_embedded_key()?);
        assert_eq!(
            response
                .receipt
                .metadata
                .ok_or_else(|| io::Error::other("missing deny metadata"))?["chio_runtime"]
                ["failure_code"],
            expected
        );
    }
    Ok(())
}
