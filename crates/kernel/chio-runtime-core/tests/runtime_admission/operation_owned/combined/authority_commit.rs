use super::*;

#[test]
fn treaty_epoch_missing_refuses_without_trust_floor_update() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = CombinedFixture::new()?;
    let (_, _, report, policy, weights) = signed_policy_inputs(0.1)?;
    let hook = ChioRuntimeAdmissionHook::new(
        profile(),
        SqliteRuntimeOrchestrationStore::open(fixture.inner.directory().join("runtime.sqlite3"))?,
        fixture.inner.binding.clone(),
    )
    .with_pheromone_query_report(report)
    .with_runtime_pheromone_policy(policy, weights)
    .with_swarm_graph_source(Arc::new(IssuedGraphs(
        fixture.inner.authority.work_graph_store(),
    )))
    .with_swarm_witness_keys(trusted_swarm_witness_keys());
    let kernel = fixture.kernel(hook)?;
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
        "treaty_epoch_missing"
    );
    assert!(response.receipt.verify_signature()?);
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
