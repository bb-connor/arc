use super::*;
use chio_kernel::admission_operation::AdmissionOperationStore;

fn revalidate(
    fixture: &Fixture,
    hook: &ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>,
    metadata: &serde_json::Value,
) -> TestResult {
    let source = fixture
        .authority
        .admission_operation_store()
        .load_runtime_source_qualification(
            &fixture.binding,
            &fixture.authority.mutation_fence(),
            NOW,
        )?;
    hook.revalidate_operation_owned_before_dispatch(
        &RuntimeAdmissionRevalidationContext {
            request: &fixture.request,
            admission_metadata: Some(metadata),
            now_unix_secs: NOW / 1000,
            now_unix_ms: NOW,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".into(),
        },
        &source,
    )?;
    Ok(())
}

#[test]
fn qualified_kernel_receipt_binds_admission_and_revalidates_original_trust() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new(true)?;
    let inputs = signed_policy_inputs(0.1)?;
    let hook = fixture.hook_with_inputs(inputs.clone())?;
    let kernel = fixture.kernel(fixture.hook_with_inputs(inputs)?, true, false)?;
    let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let metadata = response.receipt.metadata.ok_or("signed runtime metadata")?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-live-1");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert!(metadata["chio_runtime"]["operation_owned_replay"]["reference"].is_object());
    revalidate(&fixture, &hook, &metadata)
}

#[test]
fn qualified_dispatch_revalidation_refuses_advanced_trust_floor() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new(true)?;
    let inputs = signed_policy_inputs(0.1)?;
    let hook = fixture.hook_with_inputs(inputs.clone())?;
    let kernel = fixture.kernel(fixture.hook_with_inputs(inputs)?, true, false)?;
    let response = kernel.evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert!(response.receipt.verify_signature()?);
    let metadata = response.receipt.metadata.ok_or("signed runtime metadata")?;
    revalidate(&fixture, &hook, &metadata)?;
    let current = fixture
        .source
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .ok_or("committed trust floor")?;
    fixture.source.validate_and_record_runtime_trust_floor(
        RuntimeTrustFloorEntry {
            verifier_id: current.verifier_id,
            key_id: current.key_id,
            highest_version: current.highest_version + 1,
            latest_bundle_sha256: "e".repeat(64),
            latest_revocation_checkpoint_sha256: "f".repeat(64),
        },
        Some(&current.latest_bundle_sha256),
    )?;
    let error = revalidate(&fixture, &hook, &metadata)
        .err()
        .ok_or("advanced trust floor accepted")?;
    assert!(
        error.to_string().contains("runtime_trust_rollback"),
        "{error}"
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
