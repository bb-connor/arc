//! A captured read that omitted a selected annotator's answer has unknown origin.
use super::*;
use chio_kernel::tool_outcome::{InvocationOutputV1, ToolOutcomeStore};
use chio_kernel::{ReceiptStore, ToolCallResponse};

fn withheld(result: &Result<ToolCallResponse, KernelError>) -> bool {
    result.is_err()
        || result
            .as_ref()
            .is_ok_and(|response| response.verdict == Verdict::Deny)
}

#[tokio::test]
async fn modeled_legacy_missing_selected_annotation_refuses_completed_raw_replay() -> TestResult {
    verify_missing_annotation_delivery(false).await
}

#[tokio::test]
async fn modeled_legacy_missing_selected_annotation_refuses_the_first_public_raw_return(
) -> TestResult {
    verify_missing_annotation_delivery(true).await
}

#[tokio::test]
async fn fresh_selected_annotation_keeps_the_first_public_raw_return() -> TestResult {
    let f = native_fixture("annotated-read-weak-manifest")?;
    let key = "fresh-selected-annotation";
    let (runtime, mut request, mut p) = prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    attach_neutral_annotation(&f, &mut request, &mut p)?;
    assert_eq!(p.invocation.annotations.as_slice().len(), 1);
    let first = runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    assert_eq!(first.verdict, Verdict::Allow);
    let Some(chio_kernel::ToolCallOutput::Value(value)) = first.output.as_ref() else {
        return Err("fresh annotated first return carries no output".into());
    };
    assert!(chio_core::canonical_json_string(value)?.contains("provider-output-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let store = f.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("fresh annotated original absent")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    let (origin_label, origin) = store
        .retained_semantic_output_influence_for_test(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("fresh annotated origin absent")?;
    assert_ne!(origin_label, InformationLabel::Top);
    assert!(!origin.unknown);
    assert_eq!(
        store
            .retained_semantic_delivery_gate_for_test(
                operation.binding().operation_id(),
                &f.authority.mutation_fence(),
                now_ms()?,
            )?
            .as_str(),
        "open"
    );
    Ok(())
}

/// The historical capture is produced by the real native writer with only the
/// selected-annotator answer gates lifted. Its operation, dispatch ledger,
/// receipt and raw output are therefore genuine retained custody.
async fn verify_missing_annotation_delivery(require_first_refusal: bool) -> TestResult {
    let f = native_fixture("annotated-read-weak-manifest")?;
    let store = f.authority.admission_operation_store();
    let historical_capture = store.modeled_legacy_incomplete_annotation_capture_for_test()?;
    let key = "modeled-legacy-annotation";
    let (runtime, request, p) = prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    assert_eq!(
        p.deployment.body().routes.as_slice()[0]
            .annotators
            .as_slice()
            .len(),
        1
    );
    assert!(p.invocation.annotations.as_slice().is_empty());
    assert!(p.invocation.endorsements.as_slice().is_empty());
    let first_delivery = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    drop(historical_capture);
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("historical annotation original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::Completed,
        "the historical producer did not reach private completion: {first_delivery:?}"
    );
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    retained.validate_request_material(&request)?;
    let original_invocation: SemanticInvocationV1 =
        serde_json::from_value(retained.request_for_revalidation().arguments.clone())?;
    assert!(original_invocation.annotations.as_slice().is_empty());
    let Some(chio_kernel::admission_operation::AdmissionTerminalReplay::Receipt {
        receipt_id, ..
    }) = operation.terminal_replay()
    else {
        return Err("historical annotation receipt binding absent".into());
    };
    let original_receipt_value = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("historical annotation terminal receipt absent")?;
    assert!(original_receipt_value.verify_signature()?);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let raw = f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .ok_or("historical annotation raw output absent")?
        .to_persisted();
    assert!(matches!(raw.output, InvocationOutputV1::Value { .. }));
    assert!(store
        .load_security_participant_output(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .is_some());
    let (origin_label, origin) = store
        .retained_semantic_output_influence_for_test(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("historical annotation origin absent")?;
    assert_eq!(
        origin_label,
        InformationLabel::Top,
        "an omitted selected answer cannot prove a finite output restriction"
    );
    assert!(
        origin.unknown,
        "the omitted selected answer has unknown influence"
    );
    // The retained Top label alone would also fail the flows-to comparison
    // against any non-Top floor, so the refusing gate itself is observed.
    assert_eq!(
        store
            .retained_semantic_delivery_gate_for_test(
                operation.binding().operation_id(),
                &f.authority.mutation_fence(),
                now_ms()?,
            )?
            .as_str(),
        "unproved-origin",
        "current delivery must refuse the unknown selected-annotation origin before any flow comparison"
    );
    if require_first_refusal {
        assert!(
            withheld(&first_delivery),
            "unknown selected restrictions must refuse the first public raw return after physical terminal commitment"
        );
    }
    assert!(!format!("{first_delivery:?}").contains("provider-output-canary"));
    let source = f.kernel.observe_recovery_source(&p.plan.scope)?;
    let source = source
        .snapshot()
        .ok_or("historical annotation source absent")?;
    let floors = (
        source.principal_label.clone(),
        source.lineage_label.clone(),
        source.session_label.clone(),
    );
    let original_operation = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let original_receipt = chio_core::canonical_json_bytes(&original_receipt_value)?;
    let calls = f.process.process("root")?.tree_calls;
    let replay = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    assert!(
        withheld(&replay),
        "unknown selected annotation restrictions cannot authorize completed raw replay"
    );
    assert!(!format!("{replay:?}").contains("provider-output-canary"));
    let unchanged = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("historical annotation operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        original_operation
    );
    let receipt = store
        .load_chio_receipt(&original_receipt_value.id)?
        .ok_or("historical annotation receipt disappeared")?;
    assert_eq!(chio_core::canonical_json_bytes(&receipt)?, original_receipt);
    assert!(f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_some());
    let after = f.kernel.observe_recovery_source(&p.plan.scope)?;
    let after = after
        .snapshot()
        .ok_or("historical annotation source absent")?;
    assert_eq!(
        (
            after.principal_label.clone(),
            after.lineage_label.clone(),
            after.session_label.clone(),
        ),
        floors,
        "a refused delivery cannot lower retained flow floors"
    );
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
