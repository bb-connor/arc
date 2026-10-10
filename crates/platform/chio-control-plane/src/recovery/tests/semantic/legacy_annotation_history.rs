//! A genuine predecessor-style capture retains its missing answer for upgrade replay.
use super::*;
use chio_kernel::ReceiptStore;

#[tokio::test]
async fn modeled_legacy_missing_selected_annotation_refuses_completed_raw_replay() -> TestResult {
    verify_missing_annotation_delivery(false).await
}

#[tokio::test]
async fn modeled_legacy_missing_selected_annotation_refuses_the_first_public_raw_return(
) -> TestResult {
    verify_missing_annotation_delivery(true).await
}

async fn verify_missing_annotation_delivery(require_first_refusal: bool) -> TestResult {
    let f = empty_import::native_public_fixture_from_empty_import("annotated-read-weak-manifest")
        .await?;
    let store = f.authority.admission_operation_store();
    let legacy_capture = store.modeled_legacy_incomplete_annotation_capture_for_test()?;
    let legacy_output = store.modeled_legacy_output_join_for_test()?;
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
    let legacy_input = store.modeled_legacy_semantic_input_floor_for_test(&request)?;
    let first_delivery = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy annotation original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::Completed,
        "modeled producer did not create a captured terminal artifact: {first_delivery:?}"
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
        return Err("modeled legacy annotation receipt binding absent".into());
    };
    let original_receipt_value = store
        .load_chio_receipt(receipt_id.as_str())?
        .ok_or("modeled legacy annotation terminal receipt absent")?;
    assert!(original_receipt_value.verify_signature()?);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let output = store
        .load_security_participant_output(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy annotation output absent")?;
    assert_eq!(
        output.join.snapshot.session_label,
        InformationLabel::bottom()
    );
    let after = f.kernel.observe_recovery_source(&p.plan.scope)?;
    let after = after.snapshot().ok_or("legacy annotation source absent")?;
    assert_eq!(after.principal_label, InformationLabel::bottom());
    assert_eq!(after.lineage_label, InformationLabel::bottom());
    assert_eq!(after.session_label, InformationLabel::bottom());
    let original_operation = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let original_receipt = chio_core::canonical_json_bytes(&original_receipt_value)?;
    let calls = f.process.process("root")?.tree_calls;
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    drop(legacy_input);
    drop(legacy_capture);
    drop(legacy_output);
    let (origin_label, origin) = store
        .retained_semantic_output_influence_for_test(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy annotation origin absent")?;
    assert_eq!(
        origin_label,
        InformationLabel::Top,
        "an omitted selected answer cannot prove a finite output restriction"
    );
    assert!(
        origin.unknown,
        "the missing selected answer has unknown influence"
    );
    if require_first_refusal {
        assert!(
            first_delivery.is_err()
                || first_delivery
                    .as_ref()
                    .is_ok_and(|response| response.verdict == Verdict::Deny),
            "unknown selected restrictions must refuse the first public raw return after physical terminal commitment"
        );
    }
    let replay = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    assert!(
        replay.is_err()
            || replay
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "unknown selected annotation restrictions cannot authorize completed raw replay"
    );
    let unchanged = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("legacy annotation operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        original_operation
    );
    let receipt = store
        .load_chio_receipt(&original_receipt_value.id)?
        .ok_or("legacy annotation receipt disappeared")?;
    assert_eq!(chio_core::canonical_json_bytes(&receipt)?, original_receipt);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
