//! A live fan-out uses the physical runtime participant without fixture results
//! claiming that future workers or their join have already completed.
use super::*;

#[test]
fn live_swarm_without_future_results_uses_durable_continuation_custody() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::with_request(true, |source| {
        let mut swarm = runtime_swarm_bundle(false)?;
        swarm.join_receipts.clear();
        swarm.terminal_receipts.clear();
        let mut admission = bundle();
        admission.destructive = false;
        admission.lease_id = None;
        admission.governance_receipt_id = None;
        let mut request = chio_swarm_runtime_request(
            serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
            String::new(),
            swarm_runtime_context(&swarm)?,
        )?;
        admission.binding =
            RuntimeRequestBinding::from_tool_call_request(&request, "kernel.vendor-b")?;
        request
            .governed_intent
            .as_mut()
            .and_then(|intent| intent.context.as_mut())
            .ok_or("missing governed context")?["chioAdmission"]["bundleSha256"] =
            serde_json::json!(runtime_admission_bundle_sha256(&admission)?);
        source.insert_bundle(admission)?;
        source.insert_swarm_authority_bundle(swarm)?;
        Ok(request)
    })?;
    let hook = fixture
        .hook()?
        .with_swarm_witness_keys(trusted_swarm_witness_keys());
    let mut kernel = fixture.kernel(hook, true, false)?;
    kernel.require_swarm_admission();
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    kernel.set_revocation_store(Box::new(fixture.authority.revocation_store()));
    kernel.set_receipt_store(Box::new(chio_store_sqlite::SqliteReceiptStore::open(
        fixture._directory.path().join("receipts.sqlite3"),
    )?))?;
    kernel.reconcile_durable_admission_startup()?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("missing receipt metadata")?;
    assert_eq!(
        metadata["chio_runtime"]["verified_swarm_request_binding"]["capability_sha256"],
        canonical_test_hash(&fixture.request.capability)?
    );
    let reference: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1 =
        serde_json::from_value(metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone())?;
    let history = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_history(
            reference.operation_id(),
            &fixture.authority.mutation_fence(),
            NOW,
        )?
        .ok_or("missing physical custody")?;
    assert!(history.0.dispatch_commit().is_some());
    assert_eq!(history.1.len(), 1);
    assert_eq!(
        history.1[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let resources = history.1[0].intent.resources();
    assert_eq!(resources.len(), 1);
    assert_eq!(
        resources[0].kind(),
        chio_kernel::admission_operation::RuntimeReplayParticipantKind::SwarmContinuation
    );
    let replay = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .load_runtime_participant_history(
                reference.operation_id(),
                &fixture.authority.mutation_fence(),
                NOW,
            )?
            .ok_or("missing replay custody")?,
        history
    );
    Ok(())
}
