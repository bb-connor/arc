//! Known completed bytes remain replayable without a second native effect.
use super::*;

#[tokio::test]
async fn native_denied_semantic_delivery_replay_has_no_raw_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "read-weak-manifest")?;
    std::fs::write(directory.path().join("public-original-profile"), "selected")?;
    std::fs::write(
        directory.path().join("semantic-mismatched-output-digest"),
        "selected",
    )?;
    let f = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let (runtime, request, _) = prepare(
        &f,
        "denied-semantic-delivery",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let selected = request
        .capability
        .scope
        .grants
        .iter()
        .find(|grant| grant.server_id == request.server_id && grant.tool_name == request.tool_name)
        .ok_or("semantic capability grant absent")?;
    assert!(selected.constraints.iter().any(|constraint| matches!(
        constraint,
        chio_core::capability::scope::Constraint::OutputDigestSha256(_)
    )));
    let result = runtime
        .execute_step(&f.process, "root", "denied-semantic-delivery", &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "a genuine output digest mismatch must refuse delivery"
    );
    assert!(!format!("{result:?}").contains("provider-output-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let store = f.authority.admission_operation_store();
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("denied original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    retained.validate_request_material(&request)?;
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    let frozen = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let calls = f.process.process("root")?.tree_calls;
    let replay = runtime
        .execute_step(&f.process, "root", "denied-semantic-delivery", &request)
        .await;
    assert!(
        replay.is_err()
            || replay
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny)
    );
    assert!(!format!("{replay:?}").contains("provider-output-canary"));
    let unchanged = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("denied original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        frozen
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn native_known_completed_return_replays_exactly_without_reacquiring_execution() -> TestResult
{
    let f = native_fixture("read-weak-manifest")?;
    let (runtime, request, profile) = prepare(
        &f,
        "known-completed-return",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let original = runtime
        .execute_step(&f.process, "root", "known-completed-return", &request)
        .await?;
    assert_eq!(original.verdict, Verdict::Allow);
    let Some(chio_kernel::ToolCallOutput::Value(value)) = original.output.as_ref() else {
        return Err("known completed output absent".into());
    };
    let output = chio_core::canonical_json_bytes(value)?;
    assert!(std::str::from_utf8(&output)?.contains("provider-output-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let store = f.authority.admission_operation_store();
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("completed original absent")?;
    retained.validate_request_material(&request)?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    let frozen = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let receipt = chio_core::canonical_json_bytes(&original.receipt)?;
    let calls = f.process.process("root")?.tree_calls;
    let floor = restricted_label();
    let source = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let source = source.snapshot().ok_or("completed source absent")?;
    assert!(floor.flows_to(&source.principal_label));
    assert!(floor.flows_to(&source.lineage_label));
    assert!(floor.flows_to(&source.session_label));
    let replay = runtime
        .execute_step(&f.process, "root", "known-completed-return", &request)
        .await?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.output, original.output);
    assert_eq!(chio_core::canonical_json_bytes(&replay.receipt)?, receipt);
    let unchanged = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("completed original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        frozen
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    Ok(())
}
