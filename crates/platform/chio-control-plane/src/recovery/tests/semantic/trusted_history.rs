//! Native trusted and unresolved provenance preserve independent influence flags.
use super::*;
use chio_kernel::tool_outcome::{InvocationOutputV1, ToolOutcomeStore};

#[tokio::test]
async fn native_trusted_read_history_does_not_turn_presence_into_external_influence() -> TestResult
{
    let f = native_fixture("trusted-history")?;
    let (runtime, read, source) = chains::prepare_origin_read(&f, "trusted-read-history")?;
    assert!(!source.package.body().operations.as_slice()[0].external_influence);
    assert!(!source.invocation.action.externally_influenced);
    assert!(read.model_metadata.is_none());
    let result = runtime
        .execute_step(&f.process, "root", "trusted-read-history", &read)
        .await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &read.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("trusted completed read original absent")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    let raw = f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .ok_or("genuine trusted raw output absent")?
        .to_persisted();
    assert_eq!(&raw.operation_id, operation.binding().operation_id());
    assert!(matches!(raw.output, InvocationOutputV1::Value { .. }));
    let frozen_request: ToolCallRequest = serde_json::from_str(
        raw.request_canonical_json
            .as_deref()
            .ok_or("trusted raw output original request absent")?,
    )?;
    original.validate_request_material(&frozen_request)?;
    let query_key = assert_native_query_basis(&f, &source, &original)?;
    let output = f
        .authority
        .admission_operation_store()
        .load_security_participant_output(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine trusted native Output journal absent")?;
    assert_eq!(
        output.output.operation_id(),
        operation.binding().operation_id()
    );
    assert_eq!(output.output.key(), &query_key);
    assert_eq!(output.join.snapshot.key, query_key);
    let (origin_label, origin) = f
        .authority
        .admission_operation_store()
        .retained_semantic_output_influence_for_test(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("authenticated trusted native output origin absent")?;
    assert_eq!(origin_label, restricted_label());
    assert!(!origin.externally_influenced);
    assert!(!origin.unknown);
    let observed = f
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(&source.plan.scope, &f.authority.mutation_fence(), now_ms()?)?
        .ok_or("genuine trusted native output was not recorded in the influence accumulator")?;
    assert!(!observed.externally_influenced);
    assert!(!observed.unknown);
    let (runtime, mut request, mut followup) = prepare(
        &f,
        "exact-after-trusted-read",
        SemanticOutputDispositionV1::Withhold,
    )?;
    assert!(!followup.package.body().operations.as_slice()[0].external_influence);
    assert!(request.model_metadata.is_none());
    assert!(followup.plan.steps.as_slice()[0]
        .dependencies
        .as_slice()
        .is_empty());
    assert!(followup.plan.steps.as_slice()[0]
        .inputs
        .as_slice()
        .iter()
        .all(|input| matches!(input, SemanticPlanInputV1::Exact { .. })));
    followup.invocation.action.externally_influenced = false;
    followup.invocation.action.influence =
        semantic_content_digest(&(&followup.invocation.action.inputs, false))?;
    let framed = runtime.frame_action(
        &request,
        followup.invocation.action.clone(),
        &followup.payload,
    )?;
    assert!(
        !framed.externally_influenced,
        "trusted false/false provenance must stay false despite accumulator presence"
    );
    followup.invocation.action = framed;
    chains::attach_endorsement(&mut followup, "exact-after-trusted-read-endorsement")?;
    request.arguments = serde_json::to_value(&followup.invocation)?;
    let result = runtime
        .execute_step(&f.process, "root", "exact-after-trusted-read", &request)
        .await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn native_unresolved_trusted_provider_status_keeps_unknown_influence_on_later_exact_inputs(
) -> TestResult {
    let f = native_fixture("trusted-history")?;
    std::fs::write(f.path.join("provider-error"), "enabled")?;
    let (runtime, read, source) = chains::prepare_origin_read(&f, "trusted-read-failure")?;
    assert!(!source.package.body().operations.as_slice()[0].external_influence);
    assert!(!source.invocation.action.externally_influenced);
    assert!(read.model_metadata.is_none());
    let result = runtime
        .execute_step(&f.process, "root", "trusted-read-failure", &read)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny)
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &read.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("unresolved trusted read original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert!(matches!(
        operation.terminal_replay(),
        Some(chio_kernel::admission_operation::AdmissionTerminalReplay::Incident { .. })
    ));
    assert_native_query_basis(&f, &source, &original)?;
    // This read locates the absence only. It grants no no-future-output closure
    // and cannot retire the separate outstanding Output liability.
    assert!(f
        .authority
        .admission_operation_store()
        .load_security_participant_output(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .is_none());
    let (status_label, status_origin) = f
        .authority
        .admission_operation_store()
        .load_native_status_origin_for_test(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("authenticated unresolved trusted status origin absent")?;
    assert_eq!(status_label, restricted_label());
    assert!(!status_origin.externally_influenced);
    assert!(status_origin.unknown);
    let observed = f
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(&source.plan.scope, &f.authority.mutation_fence(), now_ms()?)?
        .ok_or("genuine unresolved native status was not recorded in the influence accumulator")?;
    assert!(
        !observed.externally_influenced,
        "physical uncertainty cannot invent externally authored source content"
    );
    assert!(
        observed.unknown,
        "uncertain captured physical fate cannot produce clean trusted provenance"
    );
    let (runtime, request, mut followup) = prepare(
        &f,
        "exact-after-trusted-failure",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let step = &followup.plan.steps.as_slice()[0];
    assert!(step.dependencies.as_slice().is_empty());
    assert!(step
        .inputs
        .as_slice()
        .iter()
        .all(|input| matches!(input, SemanticPlanInputV1::Exact { .. })));
    assert!(!followup.package.body().operations.as_slice()[0].external_influence);
    assert!(request.model_metadata.is_none());
    followup.invocation.action.externally_influenced = false;
    followup.invocation.action.influence =
        semantic_content_digest(&(&followup.invocation.action.inputs, false))?;
    let framed = runtime.frame_action(&request, followup.invocation.action, &followup.payload)?;
    assert!(
        framed.externally_influenced,
        "unknown native status must conservatively affect later exact-input framing"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

fn assert_native_query_basis(
    fixture: &RecoveryFixture,
    source: &SemanticFixture,
    original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
) -> TestResult<chio_security_types::ports::FlowStateKey> {
    assert_eq!(source.plan.scope, fixture.runtime.scope);
    let deployment = fixture.kernel.recovery_deployment(&source.plan.scope)?;
    assert_eq!(
        original.native_security_authority_binding(),
        Some(&deployment.native_authority),
    );
    let key = chio_kernel::recovery::recovery_flow_key(&deployment.security_context);
    let observed = fixture.kernel.observe_recovery_source(&source.plan.scope)?;
    let snapshot = observed
        .snapshot()
        .ok_or("native source query snapshot absent")?;
    assert_eq!(snapshot.key, key);
    assert_eq!(
        source.invocation.action.native_source.key,
        semantic_content_digest(&key)?
    );
    for label in [
        &snapshot.principal_label,
        &snapshot.lineage_label,
        &snapshot.session_label,
    ] {
        assert!(source.invocation.action.source_label.flows_to(label));
    }
    Ok(key)
}
