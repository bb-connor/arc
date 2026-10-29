use super::*;

#[test]
fn treaty_epoch_unavailable_refuses_before_authority_commit() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = CombinedFixture::without_epoch_authority()?;
    let kernel = fixture.kernel(fixture.hook()?)?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Deny, "{response:#?}");
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("denial metadata")?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "treaty_epoch_unavailable"
    );
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    assert!(fixture
        .inner
        .source
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .is_none());
    let history = faults::history(&fixture.inner)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.resources().len(), 3);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    let (operation, _) = fixture.history(&history[0].reference)?;
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(
        operation.state(),
        chio_kernel::admission_operation::AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}
