//! Modeled predecessor capture through genuine ordinary native SupportRead custody.
use super::*;
use chio_kernel::ReceiptStore;

#[tokio::test]
async fn modeled_legacy_completed_support_read_cannot_replay_below_its_signed_source() -> TestResult
{
    let fixture = native_fixture("read-weak-manifest")?;
    let before = fixture
        .kernel
        .observe_recovery_source(&fixture.runtime.scope)?;
    let before = before
        .snapshot()
        .ok_or("initial legacy read source absent")?;
    for label in [
        &before.principal_label,
        &before.lineage_label,
        &before.session_label,
    ] {
        assert_eq!(*label, InformationLabel::bottom());
    }
    let legacy = fixture
        .authority
        .admission_operation_store()
        .modeled_legacy_output_join_for_test()?;
    let key = "modeled-legacy-read";
    let (runtime, request, contract) =
        prepare(&fixture, key, SemanticOutputDispositionV1::ReturnValue)?;
    let legacy_input = fixture
        .authority
        .admission_operation_store()
        .modeled_legacy_semantic_input_floor_for_test(&request)?;
    assert_eq!(
        contract.package.body().operations.as_slice()[0].kind,
        SemanticOperationKindV1::SupportRead
    );
    assert_eq!(
        contract.package.body().operations.as_slice()[0].source_label,
        restricted_label()
    );
    assert_eq!(
        contract.invocation.audience.body().audience,
        restricted_label()
    );
    assert!(request.declassification_grant.is_none());
    let first = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await?;
    assert_eq!(first.verdict, Verdict::Allow);
    assert!(first.output.is_some());
    assert!(first.receipt.verify_signature()?);
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy ordinary original absent")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    retained.validate_request_material(&request)?;
    let output = fixture
        .authority
        .admission_operation_store()
        .load_security_participant_output(
            operation.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("modeled legacy output join absent")?;
    assert_eq!(
        output.join.snapshot.session_label,
        InformationLabel::bottom()
    );
    assert_eq!(output.join.command.session_join, InformationLabel::bottom());
    let original_operation = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let original_receipt = chio_core::canonical_json_bytes(&first.receipt)?;
    let calls = fixture.process.process("root")?.tree_calls;
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
    drop(legacy_input);
    drop(legacy);
    // Same ordinary operation and exact process key. No invented recovery WF,
    // fresh grant, changed request, current classifier or retrospective resigning.
    let replay = runtime
        .execute_step(&fixture.process, "root", key, &request)
        .await;
    if replay
        .as_ref()
        .is_ok_and(|response| response.verdict == Verdict::Allow && response.output.is_some())
    {
        let current = fixture
            .kernel
            .observe_recovery_source(&fixture.runtime.scope)?;
        let current = current
            .snapshot()
            .ok_or("current legacy read source absent")?;
        for inherited in [
            &current.principal_label,
            &current.lineage_label,
            &current.session_label,
        ] {
            assert!(
                !matches!(inherited, InformationLabel::Top),
                "completed legacy read lacked a finite current source"
            );
            assert!(
                restricted_label().flows_to(inherited),
                "completed legacy read released below its signed semantic source"
            );
        }
    }
    let unchanged = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("legacy original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        original_operation
    );
    let receipt = fixture
        .authority
        .admission_operation_store()
        .load_chio_receipt(&first.receipt.id)?
        .ok_or("legacy receipt disappeared")?;
    assert_eq!(chio_core::canonical_json_bytes(&receipt)?, original_receipt);
    assert_eq!(fixture.process.process("root")?.tree_calls, calls);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
