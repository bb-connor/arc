//! Native status observations retain authored restrictions and external influence.
use super::*;

fn attach_neutral_annotation(
    f: &RecoveryFixture,
    request: &mut ToolCallRequest,
    profile: &mut SemanticFixture,
) -> TestResult<SignedSemanticAnnotationV1> {
    let neutral = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: profile.plan.scope.clone(),
            input: profile.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: false,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10_000)?,
            issued_at_unix_ms: profile.invocation.action.issued_at_unix_ms,
            valid_until_unix_ms: profile.invocation.action.valid_until_unix_ms,
        },
        &profile.annotator,
    )?;
    f.authority
        .admission_operation_store()
        .install_semantic_annotation(&neutral)?;
    profile.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        profile.invocation.action.influence,
        std::slice::from_ref(&neutral),
    )?;
    profile.invocation.annotations = BoundedList::new(vec![neutral.clone()])?;
    request.arguments = serde_json::to_value(&profile.invocation)?;
    Ok(neutral)
}

#[tokio::test]
async fn native_current_selected_annotation_keeps_the_authored_withheld_status_audience(
) -> TestResult {
    let f = native_fixture("annotated-read-weak-manifest")?;
    let (runtime, mut request, mut profile) = prepare(
        &f,
        "current-annotation-status",
        SemanticOutputDispositionV1::Withhold,
    )?;
    attach_neutral_annotation(&f, &mut request, &mut profile)?;
    let before = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let before = before.snapshot().ok_or("initial source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    let response = runtime
        .execute_step(&f.process, "root", "current-annotation-status", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let audience = &profile.package.body().operations.as_slice()[0]
        .withheld_status
        .as_ref()
        .ok_or("authored status audience absent")?
        .audience;
    let after = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let after = after.snapshot().ok_or("returned source absent")?;
    assert!(audience.flows_to(&after.principal_label));
    assert!(audience.flows_to(&after.lineage_label));
    assert!(audience.flows_to(&after.session_label));
    Ok(())
}

#[tokio::test]
async fn native_changed_selected_annotation_refusal_keeps_the_authored_status_audience(
) -> TestResult {
    let f = native_fixture("annotated-read-weak-manifest")?;
    let (runtime, mut request, mut profile) = prepare(
        &f,
        "changed-annotation-status",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let neutral = attach_neutral_annotation(&f, &mut request, &mut profile)?;
    let before = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let before = before.snapshot().ok_or("initial source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    let mut restrictive = neutral.body().clone();
    restrictive.restrictions = InformationLabel::Top;
    let issued = now_ms()?.max(
        neutral
            .body()
            .issued_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("annotation clock overflow")?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < issued {
        if std::time::Instant::now() >= deadline {
            return Err("annotation authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    restrictive.issued_at_unix_ms = SafeInteger::new(issued)?;
    restrictive.valid_until_unix_ms = SafeInteger::new(
        issued
            .checked_add(50_000)
            .ok_or("annotation deadline overflow")?,
    )?;
    let restrictive = SignedSemanticAnnotationV1::sign(restrictive, &profile.annotator)?;
    f.authority
        .admission_operation_store()
        .install_semantic_annotation(&restrictive)?;
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    let result = runtime
        .execute_step(&f.process, "root", "changed-annotation-status", &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "changed selected annotation must refuse before provider submission"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let (operation, _) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("annotation refusal original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    let audience = &profile.package.body().operations.as_slice()[0]
        .withheld_status
        .as_ref()
        .ok_or("authored status audience absent")?
        .audience;
    let after = f.kernel.observe_recovery_source(&profile.plan.scope)?;
    let after = after.snapshot().ok_or("returned source absent")?;
    assert!(
        audience.flows_to(&after.principal_label),
        "observable annotation refusal must retain its authored status audience"
    );
    assert!(audience.flows_to(&after.lineage_label));
    assert!(audience.flows_to(&after.session_label));
    assert_eq!(after.principal_label, restrictive.body().restrictions);
    assert_eq!(after.lineage_label, restrictive.body().restrictions);
    assert_eq!(after.session_label, restrictive.body().restrictions);
    Ok(())
}

#[tokio::test]
async fn native_failed_external_read_status_taints_later_exact_inputs() -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("external-history").await?;
    std::fs::write(f.path.join("provider-error"), "enabled")?;
    let (runtime, read, source) = chains::prepare_origin_read(&f, "external-read-failure")?;
    assert!(source.package.body().operations.as_slice()[0].external_influence);
    assert!(read.model_metadata.is_none());
    let result = runtime
        .execute_step(&f.process, "root", "external-read-failure", &read)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny)
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let (operation, _) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &read.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("unknown external read original absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    let (runtime, request, mut followup) = prepare(
        &f,
        "exact-after-external-failure",
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
        "an observed external provider status must survive without Output journal, FutureOutput, artifact or model claim"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_changed_annotation_refusal_taints_later_independent_exact_inputs() -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
    let store = f.authority.admission_operation_store();
    let (runtime, mut request, mut profile) = prepare(
        &f,
        "changed-external-annotation",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let neutral = attach_neutral_annotation(&f, &mut request, &mut profile)?;
    assert!(!profile.invocation.action.externally_influenced);
    assert!(request.model_metadata.is_none());
    assert!(store
        .observe_knowledge_influence(
            &profile.plan.scope,
            &f.authority.mutation_fence(),
            now_ms()?
        )?
        .is_none());
    let mut current = neutral.body().clone();
    current.externally_influenced = true;
    let issued = now_ms()?.max(
        neutral
            .body()
            .issued_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("annotation clock overflow")?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < issued {
        if std::time::Instant::now() >= deadline {
            return Err("annotation authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    current.issued_at_unix_ms = SafeInteger::new(issued)?;
    current.valid_until_unix_ms = SafeInteger::new(
        issued
            .checked_add(50_000)
            .ok_or("annotation deadline overflow")?,
    )?;
    let current = SignedSemanticAnnotationV1::sign(current, &profile.annotator)?;
    store.install_semantic_annotation(&current)?;
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    let denied = runtime
        .execute_step(&f.process, "root", "changed-external-annotation", &request)
        .await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("changed annotation refusal original absent")?;
    let deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
    original.validate_request_material(&request)?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(&deployment.security_context)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert_eq!(denied.receipt.capability_id, request.capability.id);
    assert_eq!(denied.receipt.tool_server, request.server_id);
    assert_eq!(denied.receipt.tool_name, request.tool_name);
    assert_eq!(denied.receipt.action.parameters, request.arguments);
    assert_eq!(
        denied.receipt.action.parameter_hash,
        operation.binding().action_parameter_hash().as_str()
    );
    let signed_invocation: SemanticInvocationV1 = decode_contract(
        &chio_core::canonical_json_bytes(&denied.receipt.action.parameters)?,
    )?;
    assert_eq!(
        signed_invocation.action.request_id.as_str(),
        request.request_id
    );
    assert_eq!(
        hex::encode(signed_invocation.action.request_namespace.as_bytes()),
        operation.binding().request_namespace_digest().as_str()
    );
    let (native_operation, input) = store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("changed annotation refusal native operation absent")?;
    let input = input.ok_or("changed annotation refusal native Input journal absent")?;
    input.validate()?;
    assert_eq!(native_operation, operation);
    assert_eq!(
        input.input.operation_id(),
        operation.binding().operation_id()
    );
    assert_eq!(input.join.operation_id, *operation.binding().operation_id());
    assert_eq!(input.join.binding, deployment.native_authority);
    assert_eq!(
        input.input.key(),
        &recovery_flow_key(&deployment.security_context)
    );
    let source = store.observe_security_participant_flow(
        &deployment.native_authority,
        input.input.key(),
        &f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(source.snapshot(), Some(&input.join.snapshot));
    assert!(store
        .load_security_participant_output(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .is_none());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let observed = store
        .observe_knowledge_influence(
            &profile.plan.scope,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("observed changed annotation refusal was not retained as native influence")?;
    assert!(observed.externally_influenced);
    assert!(!observed.unknown);
    let (runtime, next, mut followup) = prepare(
        &f,
        "independent-after-annotation-refusal",
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
    assert!(next.model_metadata.is_none());
    followup.invocation.action.externally_influenced = false;
    followup.invocation.action.influence =
        semantic_content_digest(&(&followup.invocation.action.inputs, false))?;
    let framed = runtime.frame_action(&next, followup.invocation.action, &followup.payload)?;
    assert!(
        framed.externally_influenced,
        "a selected annotator's observed refusal must survive without Output, FutureOutput, artifact or model provenance"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
