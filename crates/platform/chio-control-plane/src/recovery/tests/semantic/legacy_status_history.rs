//! Modeled predecessor Withhold capture retains an unproved status channel.
use super::*;
use chio_kernel::ReceiptStore;

fn prepare_missing_status(
    fixture: &RecoveryFixture,
    key: &str,
) -> TestResult<(NativeSemanticRuntime, ToolCallRequest, SemanticFixture)> {
    let (runtime, mut request, mut profile) =
        prepare(fixture, key, SemanticOutputDispositionV1::ReturnValue)?;
    assert!(profile.package.body().operations.as_slice()[0]
        .withheld_status
        .is_none());
    assert!(profile.invocation.annotations.as_slice().is_empty());
    assert!(profile.invocation.endorsements.as_slice().is_empty());
    let mut step = profile.plan.steps.as_slice()[0].clone();
    step.output = SemanticOutputDispositionV1::Withhold;
    profile.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    profile.invocation.action.plan = runtime.accept_plan(&fixture.control, &profile.plan)?;
    profile.invocation.action.output = SemanticOutputDispositionV1::Withhold;
    request.arguments = serde_json::to_value(&profile.invocation)?;
    Ok((runtime, request, profile))
}

#[tokio::test]
async fn native_missing_status_without_predecessor_model_refuses_before_effect() -> TestResult {
    let fixture = native_fixture("read-missing-status")?;
    let key = "current-missing-status";
    let (runtime, request, _) = prepare_missing_status(&fixture, key)?;
    // A guard for the same store and capability but another exact request
    // must not disable the declaration gate for this genuine current call.
    let mut unrelated = request.clone();
    unrelated.request_id = "unrelated-missing-status-model".into();
    let unrelated_model = fixture
        .authority
        .admission_operation_store()
        .modeled_legacy_missing_status_capture_for_test(&unrelated)?;
    let result = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "fresh missing status declaration must refuse without a selected predecessor model"
    );
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    let (operation, _) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("current missing status original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    drop(unrelated_model);
    Ok(())
}

#[tokio::test]
async fn modeled_legacy_missing_status_is_unknown_without_blocking_private_finality() -> TestResult
{
    let fixture = native_fixture("read-missing-status")?;
    let store = fixture.authority.admission_operation_store();
    let key = "modeled-legacy-status";
    let (runtime, request, profile) = prepare_missing_status(&fixture, key)?;
    let legacy_status = store.modeled_legacy_missing_status_capture_for_test(&request)?;
    let legacy_input = store.modeled_legacy_semantic_input_floor_for_test(&request)?;
    let legacy_output = store.modeled_legacy_output_join_for_test()?;
    let first_delivery = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await;
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy status original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::Completed,
        "modeled predecessor did not create a captured terminal fact: {first_delivery:?}"
    );
    original.validate_request_material(&request)?;
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
    let Some(chio_kernel::admission_operation::AdmissionTerminalReplay::Receipt {
        receipt_id, ..
    }) = operation.terminal_replay()
    else {
        return Err("modeled legacy status terminal receipt absent".into());
    };
    let receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("modeled legacy status terminal receipt absent")?;
    assert!(receipt.verify_signature()?);
    let before = fixture
        .kernel
        .observe_recovery_source(&profile.plan.scope)?;
    let before = before.snapshot().ok_or("legacy status source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    let original_operation = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let original_receipt = chio_core::canonical_json_bytes(&receipt)?;
    let calls = fixture.process.process("root")?.tree_calls;
    drop(legacy_status);
    drop(legacy_input);
    drop(legacy_output);

    let (label, influence) = store
        .retained_semantic_output_influence_for_test(
            operation.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy status origin absent")?;
    assert_eq!(
        label,
        InformationLabel::Top,
        "an absent authored status audience cannot prove a finite channel floor"
    );
    assert!(
        influence.unknown,
        "the retained missing status channel must remain unknown after the model is disabled"
    );
    assert!(
        first_delivery.is_err()
            || first_delivery
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "an unauthored historical status channel must refuse the first public completion after private terminal commitment"
    );
    let replay = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await;
    assert!(
        replay.is_err()
            || replay
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "current missing status audience cannot authorize historical completion disclosure"
    );
    let unchanged = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("modeled legacy status operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        original_operation
    );
    let unchanged_receipt = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("modeled legacy status receipt disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged_receipt)?,
        original_receipt
    );
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, calls);
    Ok(())
}
