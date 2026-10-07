use super::*;
use chio_kernel::ToolCallResponse;

fn installation(
    f: &RecoveryFixture,
    p: &SemanticFixture,
) -> TestResult<NativeSemanticInstallationV1> {
    let native = f.kernel.recovery_deployment(&p.plan.scope)?;
    Ok(NativeSemanticInstallationV1 {
        deployment: p.deployment.clone(),
        packages: NonEmptyBoundedList::new(vec![p.package.clone()])?,
        operator_root: p.operator.public_key(),
        publisher_roots: NonEmptyBoundedList::new(vec![p.publisher.public_key()])?,
        exposed: NonEmptyBoundedList::new(vec![p.exposed.clone()])?,
        native_authority: native.native_authority,
        security_context: native.security_context,
    })
}
fn denied(result: &Result<ToolCallResponse, KernelError>) -> bool {
    result.is_err()
        || result
            .as_ref()
            .is_ok_and(|response| response.verdict == Verdict::Deny)
}

#[tokio::test]
async fn native_selected_annotator_cannot_be_omitted_from_an_endorsement_free_read() -> TestResult {
    let f = native_fixture("annotated-read")?;
    let (runtime, request, p) = prepare(
        &f,
        "omitted-annotation",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    assert!(p.invocation.endorsements.as_slice().is_empty());
    assert!(p.invocation.annotations.as_slice().is_empty());
    assert_eq!(
        p.deployment.body().routes.as_slice()[0]
            .annotators
            .as_slice()
            .len(),
        1
    );
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "omitted-annotation", &request)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_current_selected_annotation_refuses_an_older_permissive_answer() -> TestResult {
    let f = native_fixture("annotated-read")?;
    let store = f.authority.admission_operation_store();
    let (runtime, mut request, mut p) = prepare(
        &f,
        "current-neutral-annotation",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let neutral = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: p.plan.scope.clone(),
            input: p.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: false,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10_000)?,
            issued_at_unix_ms: p.invocation.action.issued_at_unix_ms,
            valid_until_unix_ms: p.invocation.action.valid_until_unix_ms,
        },
        &p.annotator,
    )?;
    store.install_semantic_annotation(&neutral)?;
    p.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        p.invocation.action.influence,
        std::slice::from_ref(&neutral),
    )?;
    p.invocation.annotations = BoundedList::new(vec![neutral.clone()])?;
    request.arguments = serde_json::to_value(&p.invocation)?;
    let response = runtime
        .execute_step(&f.process, "root", "current-neutral-annotation", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);

    let (_, mut older_request, mut older) = prepare(
        &f,
        "older-neutral-annotation",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    assert_eq!(
        older.invocation.action.inputs.as_slice()[0],
        neutral.body().input
    );
    older.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        older.invocation.action.influence,
        std::slice::from_ref(&neutral),
    )?;
    older.invocation.annotations = BoundedList::new(vec![neutral.clone()])?;
    older_request.arguments = serde_json::to_value(&older.invocation)?;
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
    restrictive.valid_until_unix_ms = SafeInteger::new(issued + 50_000)?;
    let restrictive = SignedSemanticAnnotationV1::sign(restrictive, &p.annotator)?;
    store.install_semantic_annotation(&restrictive)?;
    assert!(store.install_semantic_annotation(&neutral).is_err());
    assert!(denied(
        &runtime
            .execute_step(
                &f.process,
                "root",
                "older-neutral-annotation",
                &older_request
            )
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_framing_binds_actual_model_provenance_before_knowledge_history() -> TestResult {
    let f = native_fixture("write")?;
    let (runtime, mut request, mut p) = prepare(
        &f,
        "model-provenance",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    assert!(f
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(&f.runtime.scope, &f.authority.mutation_fence(), now_ms()?)?
        .is_none());
    let metadata = chio_core::capability::scope::ModelMetadata {
        model_id: "support-model".into(),
        safety_tier: None,
        provider: Some("support-provider".into()),
        provenance_class: Default::default(),
    };
    let base = semantic_content_digest(&(
        &p.invocation.action.inputs,
        p.package.body().operations.as_slice()[0].external_influence,
    ))?;
    p.invocation.action.influence = base;
    request.model_metadata = Some(metadata.clone());
    let framed = runtime.frame_action(&request, p.invocation.action, &p.payload)?;
    assert_eq!(
        framed.influence,
        chio_semantic_contracts::semantic_observed_influence(
            base,
            Some(semantic_content_digest(&metadata)?),
        )?,
        "native framing and capture must bind the same actual model metadata"
    );
    assert!(framed.externally_influenced);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_unresolved_effectful_plan_step_blocks_an_independent_sibling() -> TestResult {
    let f = native_fixture("error")?;
    std::fs::write(f.path.join("provider-error"), "enabled")?;
    let (runtime, mut first_request, mut first) =
        prepare(&f, "uncertain-first", SemanticOutputDispositionV1::Withhold)?;
    let (_, mut second_request, mut second) = prepare(
        &f,
        "independent-second",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(vec![
            first.plan.steps.as_slice()[0].clone(),
            second.plan.steps.as_slice()[0].clone(),
        ])?,
        ..first.plan.clone()
    };
    let digest = runtime.accept_plan(&f.control, &plan)?;
    first.invocation.action.plan = digest;
    // Preparing the sibling installs a fresher observation of the same exact
    // ACL basis. Both actions must use that current observation.
    first.invocation.audience = second.invocation.audience.clone();
    chains::attach_endorsement(&mut first, "uncertain-first-endorsement")?;
    first_request.arguments = serde_json::to_value(&first.invocation)?;
    let first_result = runtime
        .execute_step(&f.process, "root", "uncertain-first", &first_request)
        .await;
    assert!(denied(&first_result));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);

    second.invocation.action.plan = digest;
    second.invocation.action.influence = semantic_content_digest(&(
        &second.invocation.action.inputs,
        second.package.body().operations.as_slice()[0].external_influence,
    ))?;
    second.invocation.action =
        runtime.frame_action(&second_request, second.invocation.action, &second.payload)?;
    chains::attach_endorsement(&mut second, "independent-second-endorsement")?;
    second_request.arguments = serde_json::to_value(&second.invocation)?;
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "independent-second", &second_request)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_acl_subject_and_query_observations_coexist_without_eviction() -> TestResult {
    let f = native_fixture("acl-subjects")?;
    let (runtime, request, p) = prepare(
        &f,
        "first-subject-query",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let destination = &p.deployment.body().routes.as_slice()[0]
        .destinations
        .as_slice()[1];
    let mut other = p.invocation.audience.body().clone();
    other.subject_mapping = destination.subject_mapping;
    other.query = destination.acl_query;
    other.completeness = SemanticAudienceCompletenessV1::Outage;
    let observed = other
        .observed_at_unix_ms
        .get()
        .checked_add(1)
        .ok_or("ACL clock overflow")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < observed {
        if std::time::Instant::now() >= deadline {
            return Err("authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    other.observed_at_unix_ms = SafeInteger::new(observed)?;
    f.authority
        .admission_operation_store()
        .install_semantic_audience(&SignedSemanticAudienceV1::sign(other, &p.resolver)?)?;
    let response = runtime
        .execute_step(&f.process, "root", "first-subject-query", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_completed_effectful_step_releases_the_plan_for_an_independent_sibling() -> TestResult
{
    let f = native_fixture("write")?;
    let (runtime, mut first_request, mut first) =
        prepare(&f, "known-first", SemanticOutputDispositionV1::Withhold)?;
    let (_, mut second_request, mut second) = prepare(
        &f,
        "known-independent-second",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(vec![
            first.plan.steps.as_slice()[0].clone(),
            second.plan.steps.as_slice()[0].clone(),
        ])?,
        ..first.plan.clone()
    };
    let digest = runtime.accept_plan(&f.control, &plan)?;
    first.invocation.action.plan = digest;
    first.invocation.audience = second.invocation.audience.clone();
    chains::attach_endorsement(&mut first, "known-first-endorsement")?;
    first_request.arguments = serde_json::to_value(&first.invocation)?;
    let first_result = runtime
        .execute_step(&f.process, "root", "known-first", &first_request)
        .await?;
    assert_eq!(first_result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);

    second.invocation.action.plan = digest;
    second.invocation.action.influence = semantic_content_digest(&(
        &second.invocation.action.inputs,
        second.package.body().operations.as_slice()[0].external_influence,
    ))?;
    second.invocation.action =
        runtime.frame_action(&second_request, second.invocation.action, &second.payload)?;
    chains::attach_endorsement(&mut second, "known-second-endorsement")?;
    second_request.arguments = serde_json::to_value(&second.invocation)?;
    let second_result = runtime
        .execute_step(
            &f.process,
            "root",
            "known-independent-second",
            &second_request,
        )
        .await?;
    assert_eq!(second_result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn native_semantic_capacity_refusal_closes_before_dispatch_without_spending_step(
) -> TestResult {
    let f = native_fixture("saturated-write")?;
    let (runtime, request, _) =
        prepare(&f, "capacity-closed", SemanticOutputDispositionV1::Withhold)?;
    let result = runtime
        .execute_step(&f.process, "root", "capacity-closed", &request)
        .await;
    assert!(denied(&result));
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let (operation, _) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("capacity refusal original request absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    let db = rusqlite::Connection::open(f.path.join("admission.db"))?;
    let captures: i64 = db.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'semantic-capture:*'", [], |row| row.get(0))?;
    assert_eq!(
        captures, 0,
        "capacity refusal must preserve semantic evidence"
    );
    Ok(())
}

#[tokio::test]
async fn native_withheld_provider_failure_classifies_status_before_external_submission(
) -> TestResult {
    let f = native_fixture("read-weak-manifest")?;
    std::fs::write(f.path.join("provider-error"), "enabled")?;
    let (runtime, request, p) = prepare(
        &f,
        "withheld-provider-failure",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let before = f.kernel.observe_recovery_source(&p.plan.scope)?;
    let before = before.snapshot().ok_or("initial native source absent")?;
    assert_eq!(before.principal_label, InformationLabel::bottom());
    assert_eq!(before.lineage_label, InformationLabel::bottom());
    assert_eq!(before.session_label, InformationLabel::bottom());
    let status = p.package.body().operations.as_slice()[0]
        .withheld_status
        .as_ref()
        .ok_or("test package must author the withheld status channel")?;
    let result = runtime
        .execute_step(&f.process, "root", "withheld-provider-failure", &request)
        .await;
    assert!(denied(&result));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let after = f.kernel.observe_recovery_source(&p.plan.scope)?;
    let after = after.snapshot().ok_or("current native source absent")?;
    assert!(status.audience.flows_to(&after.principal_label));
    assert!(status.audience.flows_to(&after.lineage_label));
    assert!(status.audience.flows_to(&after.session_label));
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "withheld-provider-failure", &request)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_semantic_read_origin_restricts_output_when_native_manifest_floor_is_bottom(
) -> TestResult {
    let f = native_fixture("read-weak-manifest")?;
    let before = f.kernel.observe_recovery_source(&f.runtime.scope)?;
    let before = before.snapshot().ok_or("initial source absent")?;
    for label in [
        &before.principal_label,
        &before.lineage_label,
        &before.session_label,
    ] {
        assert_eq!(*label, InformationLabel::bottom());
    }
    let (runtime, request, p) = prepare(
        &f,
        "restricted-origin",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    assert_eq!(
        p.package.body().operations.as_slice()[0].source_label,
        restricted_label()
    );
    assert_eq!(p.invocation.audience.body().audience, restricted_label());
    let response = runtime
        .execute_step(&f.process, "root", "restricted-origin", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let after = f.kernel.observe_recovery_source(&f.runtime.scope)?;
    assert_eq!(
        after
            .snapshot()
            .ok_or("returned source absent")?
            .session_label,
        restricted_label()
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn native_trusted_transport_keeps_external_ticket_influence_on_later_exact_inputs(
) -> TestResult {
    let f = native_fixture("external-history")?;
    let (runtime, read, _) = chains::prepare_origin_read(&f, "customer-ticket-read")?;
    let response = runtime
        .execute_step(&f.process, "root", "customer-ticket-read", &read)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let Some(chio_kernel::ToolCallOutput::Value(value)) = response.output else {
        return Err("ticket read value absent".into());
    };
    let payload: SemanticPayloadV1 = serde_json::from_value(value)?;
    let (runtime, mut request, mut p) =
        prepare(&f, "exact-followup", SemanticOutputDispositionV1::Withhold)?;
    let material = semantic_content_digest(&payload)?;
    let input = SemanticInputVersionV1 {
        resource: ProviderResourceId::new("ticket")?,
        version: ArtifactVersionId::from_bytes(*material.as_bytes()),
        content: material,
    };
    let mut step = p.plan.steps.as_slice()[0].clone();
    assert!(step.dependencies.as_slice().is_empty());
    step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::Exact {
        resource: input.resource.clone(),
        version: input.version,
        material,
    }])?;
    p.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    p.invocation.action.plan = runtime.accept_plan(&f.control, &p.plan)?;
    p.invocation.action.inputs = NonEmptyBoundedList::new(vec![input])?;
    p.invocation.action.influence = semantic_content_digest(&(&p.invocation.action.inputs, false))?;
    p.invocation.action.externally_influenced = false;
    assert!(!p.package.body().operations.as_slice()[0].external_influence);
    assert!(request.model_metadata.is_none());
    p.payload = payload;
    p.invocation.payload = p.payload.clone();
    p.invocation.action = runtime.frame_action(&request, p.invocation.action, &p.payload)?;
    assert!(
        p.invocation.action.externally_influenced,
        "native read origin must survive without a FutureOutput edge, artifact or model claim"
    );
    chains::attach_endorsement(&mut p, "exact-followup-endorsement")?;
    request.arguments = serde_json::to_value(&p.invocation)?;
    let result = runtime
        .execute_step(&f.process, "root", "exact-followup", &request)
        .await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert_eq!(f.effects.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn native_alternate_destination_selects_exact_account_transport() -> TestResult {
    let f = native_fixture("alternate")?;
    let (runtime, request, _) =
        prepare(&f, "alternate-a", SemanticOutputDispositionV1::ReturnValue)?;
    let response = runtime
        .execute_step(&f.process, "root", "alternate-a", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let db = rusqlite::Connection::open(f.path.join("semantic-effects.db"))?;
    let actual: (String, String) = db.query_row(
        "SELECT account,resource FROM semantic_submissions",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        actual,
        ("alternate-account".into(), "alternate-queue".into())
    );
    for (key, mutation) in [("alternate-b", 0), ("alternate-c", 1)] {
        let (runtime, mut request, mut p) =
            prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
        if mutation == 0 {
            p.invocation.action.destination = SemanticDestinationId::new("unselected-account")?;
        } else {
            let mut body = p.invocation.audience.body().clone();
            body.account = ProviderAccountId::new("foreign-account")?;
            p.invocation.audience = SignedSemanticAudienceV1::sign(body, &p.resolver)?;
        }
        request.arguments = serde_json::to_value(&p.invocation)?;
        assert!(denied(
            &runtime
                .execute_step(&f.process, "root", key, &request)
                .await
        ));
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
#[tokio::test]
async fn native_authority_matrix_rejects_annotation_and_capability_escalation() -> TestResult {
    for case in [
        "annotation",
        "capability",
        "model",
        "payload",
        "version",
        "foreign-generation",
    ] {
        let f = native_fixture("write")?;
        let (runtime, mut request, mut p) =
            prepare(&f, "authority-a", SemanticOutputDispositionV1::ReturnValue)?;
        match case {
            "annotation" => {
                let body = SemanticAnnotationV1 {
                    domain_version: VersionV1,
                    scope: p.plan.scope.clone(),
                    input: p.invocation.action.inputs.as_slice()[0].clone(),
                    restrictions: restricted_label(),
                    externally_influenced: true,
                    facts: BoundedList::new(vec![SemanticFactId::new(
                        "customer-instructions-reviewed",
                    )?])?,
                    confidence_basis_points: SafeInteger::new(10000)?,
                    issued_at_unix_ms: p.invocation.action.issued_at_unix_ms,
                    valid_until_unix_ms: p.invocation.action.valid_until_unix_ms,
                };
                p.invocation.annotations =
                    BoundedList::new(vec![SignedSemanticAnnotationV1::sign(body, &p.annotator)?])?;
            }
            "capability" => {
                request.capability = f.kernel.issue_capability(
                    &request.capability.subject,
                    ChioScope::default(),
                    600,
                )?;
                p.invocation.action =
                    runtime.frame_action(&request, p.invocation.action, &p.payload)?;
                chains::attach_endorsement(&mut p, "authority-capability")?;
            }
            "model" => {
                request.model_metadata = Some(chio_core::capability::scope::ModelMetadata {
                    model_id: "unbound-model".into(),
                    safety_tier: None,
                    provider: None,
                    provenance_class: Default::default(),
                });
            }
            "payload" => {
                let mut fields = p.invocation.payload.fields.as_slice().to_vec();
                fields[0].value = SemanticValueV1::Text {
                    value: ProtectedText::new("substituted-payload")?,
                };
                p.invocation.payload.fields = NonEmptyBoundedList::new(fields)?;
            }
            "foreign-generation" => {
                let other = f.process.tool_request(
                    "root",
                    "foreign-source",
                    "server-a",
                    "send",
                    f.seed.arguments.clone(),
                )?;
                let denied = f
                    .process
                    .invoke_known_only("root", "foreign-source", &other)
                    .await?;
                assert_eq!(denied.verdict, Verdict::Deny);
            }
            _ => {
                let mut inputs = p.invocation.action.inputs.as_slice().to_vec();
                inputs[0].version = ArtifactVersionId::from_bytes([98; 32]);
                p.invocation.action.inputs = NonEmptyBoundedList::new(inputs)?;
                chains::attach_endorsement(&mut p, "authority-version")?;
            }
        }
        request.arguments = serde_json::to_value(&p.invocation)?;
        assert!(
            denied(
                &runtime
                    .execute_step(&f.process, "root", "authority-a", &request)
                    .await
            ),
            "{case}"
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
#[tokio::test]
async fn native_evidence_is_one_shot_across_distinct_actions_and_plan_revisions() -> TestResult {
    let f = native_fixture("write")?;
    let (runtime, request, first) = prepare(&f, "once-a", SemanticOutputDispositionV1::Withhold)?;
    runtime
        .execute_step(&f.process, "root", "once-a", &request)
        .await?;
    let (runtime, mut request, mut second) =
        prepare(&f, "once-b", SemanticOutputDispositionV1::ReturnValue)?;
    chains::attach_endorsement(
        &mut second,
        first.invocation.endorsements.as_slice()[0]
            .body()
            .evidence
            .as_str(),
    )?;
    request.arguments = serde_json::to_value(&second.invocation)?;
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "once-b", &request)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let (runtime, mut revised, mut p) =
        prepare(&f, "once-a", SemanticOutputDispositionV1::ReturnValue)?;
    revised.request_id = "direct-revised-action".into();
    p.invocation.action = runtime.frame_action(&revised, p.invocation.action, &p.payload)?;
    chains::attach_endorsement(&mut p, "fresh-revised-endorsement")?;
    revised.arguments = serde_json::to_value(&p.invocation)?;
    let context = f.process.recovery_security_context("root")?;
    assert!(denied(
        &f.kernel
            .evaluate_tool_call_with_security_context(&revised, &context)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_reload_is_atomic_stales_uncaptured_and_preserves_original_completed() -> TestResult
{
    let f = native_fixture("write")?;
    let (runtime, original, _) = prepare(&f, "captured-a", SemanticOutputDispositionV1::Withhold)?;
    let completed = runtime
        .execute_step(&f.process, "root", "captured-a", &original)
        .await?;
    let (runtime, pending, p) = prepare(&f, "pending-a", SemanticOutputDispositionV1::ReturnValue)?;
    let mut selected = installation(&f, &p)?;
    let mut body = selected.deployment.body().clone();
    body.generation = SafeInteger::new(2)?;
    body.exposure_binding = CanonicalPayloadDigest::from_bytes([99; 32]);
    selected.deployment = SignedSemanticDeploymentV1::sign(body.clone(), &p.operator)?;
    assert!(f
        .authority
        .admission_operation_store()
        .configure_semantic_deployment(&selected)
        .is_err());
    // Failed activation leaves generation one available to new plans.
    let (_, _, _) = prepare(
        &f,
        "after-invalid",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    body.exposure_binding = p.deployment.body().exposure_binding;
    selected.deployment = SignedSemanticDeploymentV1::sign(body, &p.operator)?;
    f.authority
        .admission_operation_store()
        .configure_semantic_deployment(&selected)?;
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "pending-a", &pending)
            .await
    ));
    let replay = runtime
        .execute_step(&f.process, "root", "captured-a", &original)
        .await?;
    assert_eq!(replay.output, completed.output);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_completed_withhold_restarts_without_effect_or_raw_release() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "write")?;
    let f = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let (runtime, request, _) = prepare(&f, "restart-a", SemanticOutputDispositionV1::Withhold)?;
    let original = runtime
        .execute_step(&f.process, "root", "restart-a", &request)
        .await?;
    drop(runtime);
    drop(f);
    let f = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(f.authority.admission_operation_store()),
        f.runtime.scope.clone(),
        f.authority.mutation_fence(),
    );
    let replay = runtime
        .execute_step(&f.process, "root", "restart-a", &request)
        .await?;
    assert_eq!(replay.output, original.output);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert!(!chio_core::canonical_json_string(&replay.receipt)?.contains("provider-output-canary"));
    Ok(())
}
#[tokio::test]
async fn native_provider_error_has_no_raw_fallback_or_replacement_attempt() -> TestResult {
    let f = native_fixture("error")?;
    std::fs::write(f.path.join("provider-error"), "enabled")?;
    let (runtime, request, _) = prepare(&f, "error-a", SemanticOutputDispositionV1::Withhold)?;
    let result = runtime
        .execute_step(&f.process, "root", "error-a", &request)
        .await;
    assert!(!format!("{result:?}").contains("provider-private-error-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let replay = runtime
        .execute_step(&f.process, "root", "error-a", &request)
        .await;
    assert!(!format!("{replay:?}").contains("provider-private-error-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_protected_semantic_inventory_tamper_fails_before_effect() -> TestResult {
    let f = native_fixture("write")?;
    let (runtime, request, _) = prepare(&f, "tamper-a", SemanticOutputDispositionV1::ReturnValue)?;
    let intact = f
        .authority
        .admission_operation_store()
        .read_semantic_installation(&f.runtime.scope, &f.authority.mutation_fence(), now_ms()?)?;
    assert_eq!(intact.deployment.body().scope, f.runtime.scope);
    let db = rusqlite::Connection::open(f.path.join("admission.db"))?;
    let affected = db.execute("UPDATE admission_operation_recovery_records SET version=version+1,payload=CAST(replace(CAST(payload AS TEXT),'issue-queue','foreign-queue') AS BLOB) WHERE record_key LIKE 'semantic-deployment:%'", [])?;
    assert_eq!(affected, 1, "tamper must reach the protected inventory");
    let observation = f
        .authority
        .admission_operation_store()
        .read_semantic_installation(&f.runtime.scope, &f.authority.mutation_fence(), now_ms()?);
    match observation {
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(
            reason,
        )) => assert_eq!(
            reason,
            "authority database changed outside its serving-owner connection"
        ),
        other => panic!("tampered protected read result: {other:?}"),
    }
    assert!(denied(
        &runtime
            .execute_step(&f.process, "root", "tamper-a", &request)
            .await
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
