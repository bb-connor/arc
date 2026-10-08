use super::*;

pub(super) fn bundle(
    scope: RecoveryScopeV1,
    now: u64,
    mode: &str,
) -> TestResult<(SemanticFixture, Option<SemanticFixture>)> {
    let mode = if mode == "held-expired" { "held" } else { mode };
    let kind = match mode {
        "read"
        | "read-reviewed-constraints"
        | "read-weak-manifest"
        | "read-missing-status"
        | "annotated-read"
        | "annotated-read-weak-manifest"
        | "trusted-annotated-read"
        | "annotated-disclosure"
        | "acl-subjects" => SemanticOperationKindV1::SupportRead,
        "project" => SemanticOperationKindV1::FieldProjection,
        _ => SemanticOperationKindV1::IssueWrite,
    };
    let mut primary = native_profile(scope.clone(), now, kind)?;
    if mode == "read-reviewed-constraints" {
        let mut package = primary.package.body().clone();
        let mut contract = package.operations.as_slice()[0].clone();
        contract.selectors = BoundedList::new(vec![
            SemanticSelectorV1::Equals {
                field: SemanticFieldId::new("title")?,
                value: SemanticValueV1::Text {
                    value: ProtectedText::new("package-only-title")?,
                },
            },
            SemanticSelectorV1::TextBytesAtMost {
                field: SemanticFieldId::new("body")?,
                bytes: SafeInteger::new(32)?,
            },
        ])?;
        package.operations = NonEmptyBoundedList::new(vec![contract])?;
        primary.package = SignedSemanticPackageV1::sign(package, &primary.publisher)?;
        let package = semantic_package_digest(primary.package.body())?;
        let mut deployment = primary.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        route.package = package;
        route.reviewed_overrides = BoundedList::new(vec![SemanticReviewedOverrideV1 {
            selector_index: SafeInteger::new(0)?,
            reason: ProtectedText::new("reviewed customer-support title exception")?,
            fixture_digests: NonEmptyBoundedList::new(vec![semantic_content_digest(
                &primary.payload,
            )?])?,
        }])?;
        route.operator_selectors = BoundedList::new(vec![SemanticSelectorV1::Equals {
            field: SemanticFieldId::new("title")?,
            value: SemanticValueV1::Text {
                value: ProtectedText::new("support ticket")?,
            },
        }])?;
        deployment.packages = NonEmptyBoundedList::new(vec![package])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
        primary.plan.registry = semantic_registry_digest(primary.deployment.body())?;
        primary.invocation.action.registry = primary.plan.registry;
    }
    if matches!(mode, "read-missing-status" | "trusted-annotated-read") {
        let mut package = primary.package.body().clone();
        let mut contract = package.operations.as_slice()[0].clone();
        if mode == "read-missing-status" {
            contract.withheld_status = None;
        } else {
            contract.external_influence = false;
            primary.invocation.action.externally_influenced = false;
            primary.invocation.action.influence =
                semantic_content_digest(&(&primary.invocation.action.inputs, false))?;
        }
        package.operations = NonEmptyBoundedList::new(vec![contract])?;
        primary.package = SignedSemanticPackageV1::sign(package, &primary.publisher)?;
        let package = semantic_package_digest(primary.package.body())?;
        let mut deployment = primary.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        route.package = package;
        deployment.packages = NonEmptyBoundedList::new(vec![package])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
        primary.plan.registry = semantic_registry_digest(primary.deployment.body())?;
        primary.invocation.action.registry = primary.plan.registry;
    }
    if mode == "acl-subjects" {
        let mut deployment = primary.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        let mut alternate = route.destinations.as_slice()[0].clone();
        alternate.destination = SemanticDestinationId::new("alternate-subject-query")?;
        alternate.subject_mapping = CanonicalPayloadDigest::from_bytes([55; 32]);
        alternate.acl_query = CanonicalPayloadDigest::from_bytes([56; 32]);
        route.destinations =
            NonEmptyBoundedList::new(vec![route.destinations.as_slice()[0].clone(), alternate])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
        primary.plan.registry = semantic_registry_digest(primary.deployment.body())?;
        primary.invocation.action.registry = primary.plan.registry;
    }
    if matches!(
        mode,
        "annotated-read"
            | "annotated-read-weak-manifest"
            | "trusted-annotated-read"
            | "annotated-disclosure"
    ) {
        let mut deployment = primary.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        route.annotators = BoundedList::new(vec![SemanticAnnotatorBindingV1 {
            key: semantic_key_digest(&primary.annotator.public_key())?,
            facts: BoundedList::new(vec![])?,
            may_attest_facts: false,
        }])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
        primary.plan.registry = semantic_registry_digest(primary.deployment.body())?;
        primary.invocation.action.registry = primary.plan.registry;
    }
    if mode == "annotated-disclosure" {
        let mut deployment = primary.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        let mut destination = route.destinations.as_slice()[0].clone();
        destination.audience = InformationLabel::bottom();
        destination.purpose = ProtectedText::new("approved-disclosure")?;
        route.destinations = NonEmptyBoundedList::new(vec![destination])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
        primary.plan.registry = semantic_registry_digest(primary.deployment.body())?;
        primary.invocation.action.registry = primary.plan.registry;
        let mut audience = primary.invocation.audience.body().clone();
        audience.audience = InformationLabel::bottom();
        primary.invocation.audience = SignedSemanticAudienceV1::sign(audience, &primary.resolver)?;
    }
    if mode == "alternate" {
        let mut body = primary.deployment.body().clone();
        let mut route = body.routes.as_slice()[0].clone();
        let mut alternate = route.destinations.as_slice()[0].clone();
        alternate.destination = SemanticDestinationId::new("tenant-alternate-queue")?;
        alternate.account = ProviderAccountId::new("alternate-account")?;
        alternate.resource = ProviderResourceId::new("alternate-queue")?;
        alternate.endpoint = ProtectedText::new("https://fixture.invalid/alternate")?;
        route.destinations =
            NonEmptyBoundedList::new(vec![route.destinations.as_slice()[0].clone(), alternate])?;
        body.routes = NonEmptyBoundedList::new(vec![route])?;
        primary.deployment = SignedSemanticDeploymentV1::sign(body, &primary.operator)?;
    }
    if !matches!(
        mode,
        "transform" | "historical" | "current" | "held" | "external-history" | "trusted-history"
    ) {
        return Ok((primary, None));
    }
    let source_kind = if mode == "transform" {
        SemanticOperationKindV1::FieldProjection
    } else {
        SemanticOperationKindV1::SupportRead
    };
    let mut source = native_profile(scope, now, source_kind)?;
    let mut source_body = source.package.body().clone();
    source_body.package = SemanticPackageId::new("source-package")?;
    let mut source_contract = source_body.operations.as_slice()[0].clone();
    source_contract.operation = SemanticOperationId::new("source-operation")?;
    if mode == "trusted-history" {
        source_contract.external_influence = false;
        source.invocation.action.externally_influenced = false;
        source.invocation.action.influence =
            semantic_content_digest(&(&source.invocation.action.inputs, false))?;
    }
    source_body.operations = NonEmptyBoundedList::new(vec![source_contract.clone()])?;
    source.package = SignedSemanticPackageV1::sign(source_body, &source.publisher)?;
    let mut source_route = source.deployment.body().routes.as_slice()[0].clone();
    source_route.package = semantic_package_digest(source.package.body())?;
    source_route.operation = source_contract.operation.clone();
    source_route.server = ProtectedText::new("semantic-source")?;
    source.exposed.server = source_route.server.clone();
    let mut primary_body = primary.package.body().clone();
    let mut primary_contract = primary_body.operations.as_slice()[0].clone();
    if matches!(mode, "external-history" | "trusted-history") {
        primary_contract.external_influence = false;
        primary.invocation.action.externally_influenced = false;
        primary.invocation.action.influence =
            semantic_content_digest(&(&primary.invocation.action.inputs, false))?;
    } else if mode == "transform" {
        primary_contract.input_fields = BoundedList::new(vec![SemanticFieldId::new("title")?])?;
    } else {
        primary_contract.prerequisites =
            BoundedList::new(vec![SemanticPrerequisiteRequirementV1 {
                fact: SemanticFactId::new("resource-reviewed")?,
                kind: prerequisite_kind(mode),
                resource: ProviderResourceId::new("ticket")?,
            }])?;
    }
    primary_body.operations = NonEmptyBoundedList::new(vec![primary_contract])?;
    primary.package = SignedSemanticPackageV1::sign(primary_body, &primary.publisher)?;
    let mut primary_route = primary.deployment.body().routes.as_slice()[0].clone();
    primary_route.package = semantic_package_digest(primary.package.body())?;
    let mut deployment = primary.deployment.body().clone();
    deployment.packages =
        NonEmptyBoundedList::new(vec![primary_route.package, source_route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![primary_route, source_route])?;
    primary.deployment = SignedSemanticDeploymentV1::sign(deployment, &primary.operator)?;
    source.deployment = primary.deployment.clone();
    for fixture in [&mut primary, &mut source] {
        fixture.plan.registry = semantic_registry_digest(fixture.deployment.body())?;
        fixture.invocation.action.registry = fixture.plan.registry;
    }
    source.invocation.action.operation = source_contract.operation;
    Ok((primary, Some(source)))
}
pub(super) fn prepare_origin_read(
    f: &RecoveryFixture,
    key: &str,
) -> TestResult<(NativeSemanticRuntime, ToolCallRequest, SemanticFixture)> {
    let mode = std::fs::read_to_string(f.path.join("semantic-kind"))?;
    let (mut primary, source) = bundle(f.runtime.scope.clone(), now_ms()?, &mode)?;
    let mut source = source.ok_or("origin read route absent")?;
    pin_deployment(
        &mut primary,
        Some(&mut source),
        &f.kernel.recovery_deployment(&f.runtime.scope)?,
    )?;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(f.authority.admission_operation_store()),
        f.runtime.scope.clone(),
        f.authority.mutation_fence(),
    );
    let mut step = source.plan.steps.as_slice()[0].clone();
    step.step = StepId::new(key)?;
    step.operation = source.invocation.action.operation.clone();
    source.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    source.invocation.action.plan = runtime.accept_plan(&f.control, &source.plan)?;
    source.invocation.action.step = StepId::new(key)?;
    let mut request = f.process.tool_request(
        "root",
        key,
        "semantic-source",
        "remedy",
        serde_json::json!({}),
    )?;
    source.invocation.action =
        runtime.frame_action(&request, source.invocation.action, &source.payload)?;
    f.authority
        .admission_operation_store()
        .install_semantic_audience(&source.invocation.audience)?;
    request.arguments = serde_json::to_value(&source.invocation)?;
    Ok((runtime, request, source))
}

fn prerequisite_kind(mode: &str) -> SemanticPrerequisiteKindV1 {
    match mode {
        "current" => SemanticPrerequisiteKindV1::CurrentPredicate,
        "held" => SemanticPrerequisiteKindV1::HeldReservation,
        _ => SemanticPrerequisiteKindV1::HistoricalFact,
    }
}
pub(super) fn attach_endorsement(p: &mut SemanticFixture, evidence: &str) -> TestResult {
    let mut body = p.invocation.endorsements.as_slice()[0].body().clone();
    body.evidence = EvidenceRef::new(evidence)?;
    body.target = SemanticEndorsementTargetV1::ExactAction {
        action: semantic_action_digest(&p.invocation.action)?,
    };
    body.influence = p.invocation.action.influence;
    body.issued_at_unix_ms = p.invocation.action.issued_at_unix_ms;
    body.valid_until_unix_ms = p.invocation.action.valid_until_unix_ms;
    p.invocation.endorsements =
        BoundedList::new(vec![SignedScopedEndorsementV1::sign(body, &p.endorser)?])?;
    Ok(())
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum PrerequisiteFailure {
    None,
    Stale,
    DelayedRevokedProof,
    ExpiredHeldProof,
    ExplicitReinstatement,
}

fn chain_phase<T, E: std::fmt::Debug>(result: Result<T, E>, phase: &str) -> TestResult<T> {
    result.map_err(|error| format!("semantic chain phase {phase}: {error:?}").into())
}

async fn chain(f: &RecoveryFixture, mode: &str, stale: bool) -> TestResult {
    chain_with_failure(
        f,
        mode,
        if stale {
            PrerequisiteFailure::Stale
        } else {
            PrerequisiteFailure::None
        },
    )
    .await
}

async fn chain_with_failure(
    f: &RecoveryFixture,
    mode: &str,
    failure: PrerequisiteFailure,
) -> TestResult {
    let stale = !matches!(
        failure,
        PrerequisiteFailure::None | PrerequisiteFailure::ExplicitReinstatement
    );
    let withheld_source = mode == "withheld-transform";
    let mode = if withheld_source { "transform" } else { mode };
    let scope = f.runtime.scope.clone();
    let (mut p, source) = bundle(scope.clone(), now_ms()?, mode)?;
    let mut source = source.ok_or("missing source fixture")?;
    pin_deployment(
        &mut p,
        Some(&mut source),
        &f.kernel.recovery_deployment(&scope)?,
    )?;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(f.authority.admission_operation_store()),
        scope,
        f.authority.mutation_fence(),
    );
    let mut source_step = source.plan.steps.as_slice()[0].clone();
    source_step.step = StepId::new("source-a")?;
    source_step.operation = source.invocation.action.operation.clone();
    if withheld_source {
        source_step.output = SemanticOutputDispositionV1::Withhold;
        source.invocation.action.output = SemanticOutputDispositionV1::Withhold;
    }
    let mut primary_step = p.plan.steps.as_slice()[0].clone();
    primary_step.step = StepId::new("dependent-a")?;
    primary_step.dependencies = BoundedList::new(vec![source_step.step.clone()])?;
    if stale && mode == "historical" {
        // The review producer reads the original version. The dependent action
        // separately materializes and pins changed bytes at the same resource.
        let mut fields = p.payload.fields.as_slice().to_vec();
        fields[0].value = SemanticValueV1::Text {
            value: ProtectedText::new("changed-after-review")?,
        };
        p.payload.fields = NonEmptyBoundedList::new(fields)?;
        let content = semantic_content_digest(&p.payload)?;
        let input = SemanticInputVersionV1 {
            resource: ProviderResourceId::new("ticket")?,
            version: ArtifactVersionId::from_bytes(*content.as_bytes()),
            content,
        };
        primary_step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::Exact {
            resource: input.resource.clone(),
            version: input.version,
            material: input.content,
        }])?;
        p.invocation.action.inputs = NonEmptyBoundedList::new(vec![input])?;
        p.invocation.action.influence = semantic_content_digest(&(
            &p.invocation.action.inputs,
            p.package.body().operations.as_slice()[0].external_influence,
        ))?;
    }
    if mode == "transform" {
        primary_step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::FutureOutput {
            step: source_step.step.clone(),
        }])?;
    }
    let mut selected_steps = vec![primary_step.clone(), source_step];
    if mode == "held" && !stale {
        primary_step.step = StepId::new("dependent-b")?;
        selected_steps.push(primary_step);
    }
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(selected_steps)?,
        ..p.plan.clone()
    };
    let digest = chain_phase(runtime.accept_plan(&f.control, &plan), "accept_plan")?;
    source.invocation.action.plan = digest;
    source.invocation.action.step = StepId::new("source-a")?;
    let mut source_request = f.process.tool_request(
        "root",
        "source-a",
        "semantic-source",
        "remedy",
        serde_json::json!({}),
    )?;
    source.invocation.action = chain_phase(
        runtime.frame_action(&source_request, source.invocation.action, &source.payload),
        "frame_source",
    )?;
    chain_phase(
        f.authority
            .admission_operation_store()
            .install_semantic_audience(&source.invocation.audience),
        "install_source_acl",
    )?;
    source_request.arguments = serde_json::to_value(&source.invocation)?;
    let response = chain_phase(
        runtime
            .execute_step(&f.process, "root", "source-a", &source_request)
            .await,
        "execute_source",
    )?;
    assert_eq!(response.verdict, Verdict::Allow);
    let operation = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("admission_operation"))
        .and_then(|metadata| metadata.get("operation_id"))
        .and_then(Value::as_str)
        .ok_or("missing source operation")?
        .to_owned();
    let producer = f
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(&operation)?,
        )?
        .ok_or("source durable operation absent")?;
    assert_eq!(
        producer.state(),
        chio_kernel::admission_operation::AdmissionOperationState::Completed,
        "a prerequisite producer must have completed before its proof is installed"
    );
    let fresh = now_ms()?;
    p.invocation.action.issued_at_unix_ms = SafeInteger::new(fresh)?;
    p.invocation.action.valid_until_unix_ms = SafeInteger::new(fresh + 50_000)?;
    let mut acl = p.invocation.audience.body().clone();
    acl.observed_at_unix_ms = SafeInteger::new(fresh)?;
    acl.valid_until_unix_ms = p.invocation.action.valid_until_unix_ms;
    p.invocation.audience = SignedSemanticAudienceV1::sign(acl, &p.resolver)?;
    chain_phase(
        f.authority
            .admission_operation_store()
            .install_semantic_audience(&p.invocation.audience),
        "install_dependent_acl",
    )?;
    p.invocation.action.plan = digest;
    p.invocation.action.step = StepId::new("dependent-a")?;
    let mut request = f.process.tool_request(
        "root",
        "dependent-a",
        "semantic-a",
        "remedy",
        serde_json::json!({}),
    )?;
    if mode == "transform" {
        let Some(chio_kernel::ToolCallOutput::Value(output)) = response.output else {
            return Err("missing projection output".into());
        };
        p.payload = if withheld_source {
            // Even correct private bytes known to a trusted fixture cannot
            // turn a withheld producer into a raw future-output release.
            chio_semantic_contracts::project_semantic_fields(
                &source.payload,
                source.package.body().operations.as_slice()[0]
                    .projection_fields
                    .as_slice(),
                &mut chio_semantic_contracts::VerificationBudget::new(4096)?,
            )?
        } else {
            serde_json::from_value(output)?
        };
        let content = semantic_content_digest(&p.payload)?;
        p.invocation.action.inputs = NonEmptyBoundedList::new(vec![SemanticInputVersionV1 {
            resource: ProviderResourceId::new("issue-queue")?,
            version: ArtifactVersionId::from_bytes(*content.as_bytes()),
            content,
        }])?;
        p.invocation.action.influence = source.invocation.action.influence;
        let body = SemanticTransformationV1 {
            domain_version: VersionV1,
            scope: p.plan.scope.clone(),
            producer: OperationId::new(&operation)?,
            producer_action: semantic_action_digest(&source.invocation.action)?,
            inputs: source.invocation.action.inputs.clone(),
            implementation: source.package.body().operations.as_slice()[0].implementation,
            configuration: semantic_content_digest(
                &source.package.body().operations.as_slice()[0].projection_fields,
            )?,
            output_schema: source.package.body().operations.as_slice()[0].output_schema,
            output: content,
            output_label: restricted_label(),
            influence: source.invocation.action.influence,
            destination: p.invocation.action.destination.clone(),
            purpose: ProtectedText::new("customer-support")?,
            disposition: p.invocation.action.output,
            issued_at_unix_ms: SafeInteger::new(now_ms()?)?,
            valid_until_unix_ms: p.invocation.action.valid_until_unix_ms,
        };
        p.invocation.transformation =
            Some(SignedSemanticTransformationV1::sign(body, &p.transformer)?);
    }
    p.invocation.action = chain_phase(
        runtime.frame_action(&request, p.invocation.action, &p.payload),
        "frame_dependent",
    )?;
    p.invocation.payload = p.payload.clone();
    attach_endorsement(&mut p, "dependent-endorsement")?;
    if mode != "transform" {
        let input = &source.invocation.action.inputs.as_slice()[0];
        let body = SemanticPrerequisiteV1 {
            domain_version: VersionV1,
            evidence: EvidenceRef::new("dependent-prerequisite")?,
            scope: p.plan.scope.clone(),
            action: semantic_action_digest(&p.invocation.action)?,
            fact: SemanticFactId::new("resource-reviewed")?,
            kind: prerequisite_kind(mode),
            resource: input.resource.clone(),
            version: input.version,
            material: input.content,
            producer: OperationId::new(&operation)?,
            lease: if mode == "held" {
                Some(SemanticLeaseId::new("held-lease-a")?)
            } else {
                None
            },
            purpose: ProtectedText::new("customer-support")?,
            issued_at_unix_ms: SafeInteger::new(now_ms()?)?,
            valid_until_unix_ms: p.invocation.action.valid_until_unix_ms,
        };
        let mut proof = SignedSemanticPrerequisiteV1::sign(body, &p.prerequisite)?;
        if mode != "historical" && !(failure == PrerequisiteFailure::Stale && mode == "held") {
            let store = f.authority.admission_operation_store();
            if let Err(error) = store.install_semantic_prerequisite(&proof) {
                let producer = store.load_by_operation_id(
                    &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                        &operation,
                    )?,
                )?;
                let observed = now_ms()?;
                return Err(format!(
                    "semantic chain phase install_current_prerequisite: {error:?}; producer_state={:?}; proof_future={}; proof_expired={}; signature_valid={}",
                    producer.as_ref().map(|producer| producer.state()),
                    proof.body().issued_at_unix_ms.get() > observed,
                    proof.body().valid_until_unix_ms.get() <= observed,
                    proof.verify_signature()?
                ).into());
            }
        }
        if failure == PrerequisiteFailure::DelayedRevokedProof {
            // Issue a newer proof before revocation, but deliver it afterwards.
            // This is an authoritative ordering check, not a network race.
            let mut delayed = proof.body().clone();
            delayed.issued_at_unix_ms = SafeInteger::new(
                delayed
                    .issued_at_unix_ms
                    .get()
                    .checked_add(1)
                    .ok_or("proof clock overflow")?,
            )?;
            let delayed = SignedSemanticPrerequisiteV1::sign(delayed, &p.prerequisite)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while now_ms()? < delayed.body().issued_at_unix_ms.get() {
                if std::time::Instant::now() >= deadline {
                    return Err("authority clock did not advance".into());
                }
                tokio::task::yield_now().await;
            }
            chain_phase(
                f.authority
                    .admission_operation_store()
                    .revoke_semantic_prerequisite(
                        &p.plan.scope,
                        &proof.body().fact,
                        &proof.body().resource,
                    ),
                "revoke_current_prerequisite",
            )?;
            assert!(f
                .authority
                .admission_operation_store()
                .install_semantic_prerequisite(&delayed)
                .is_err());
            assert_eq!(f.effects.load(Ordering::SeqCst), 1);
            return Ok(());
        }
        if failure == PrerequisiteFailure::ExplicitReinstatement {
            let store = f.authority.admission_operation_store();
            let scope = &p.plan.scope;
            let first_generation = store.revoke_semantic_prerequisite(
                scope,
                &proof.body().fact,
                &proof.body().resource,
            )?;
            let current_generation = store.revoke_semantic_prerequisite(
                scope,
                &proof.body().fact,
                &proof.body().resource,
            )?;
            assert!(current_generation > first_generation);
            let after_revocation = now_ms()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while now_ms()? <= after_revocation {
                if std::time::Instant::now() >= deadline {
                    return Err("authority clock did not advance after revocation".into());
                }
                tokio::task::yield_now().await;
            }
            let original = proof.clone();
            let mut fresh = proof.body().clone();
            fresh.evidence = EvidenceRef::new("reinstated-current-prerequisite")?;
            fresh.issued_at_unix_ms = SafeInteger::new(now_ms()?)?;
            proof = SignedSemanticPrerequisiteV1::sign(fresh, &p.prerequisite)?;
            let before = constraints::protected_counts(f)?;
            assert!(store.install_semantic_prerequisite(&proof).is_err());
            assert_eq!(constraints::protected_counts(f)?, before);

            let maintenance = constraints::issue_semantic_maintenance_capability(f)?;
            let actor = f.kernel.authenticate_recovery_actor(
                scope,
                &maintenance,
                RecoveryPermission::Maintain,
            )?;
            let select = f.kernel.authenticate_recovery_actor(
                scope,
                &f.control,
                RecoveryPermission::Select,
            )?;
            let fence = f.authority.mutation_fence();
            let before = constraints::protected_counts(f)?;
            assert!(store
                .reinstate_semantic_prerequisite(
                    &select,
                    &proof,
                    current_generation,
                    &fence,
                    now_ms()?,
                )
                .is_err());
            assert_eq!(constraints::protected_counts(f)?, before);
            assert!(store
                .reinstate_semantic_prerequisite(
                    &actor,
                    &proof,
                    first_generation,
                    &fence,
                    now_ms()?,
                )
                .is_err());
            assert_eq!(constraints::protected_counts(f)?, before);
            f.kernel.revoke_capability(&maintenance.id)?;
            let before = constraints::protected_counts(f)?;
            assert!(store
                .reinstate_semantic_prerequisite(
                    &actor,
                    &proof,
                    current_generation,
                    &fence,
                    now_ms()?,
                )
                .is_err());
            assert_eq!(constraints::protected_counts(f)?, before);

            let maintenance = constraints::issue_semantic_maintenance_capability(f)?;
            let actor = f.kernel.authenticate_recovery_actor(
                scope,
                &maintenance,
                RecoveryPermission::Maintain,
            )?;
            assert!(
                now_ms()? < proof.body().valid_until_unix_ms.get(),
                "a live reinstatement proof must reach the positive transition"
            );
            chain_phase(
                store.reinstate_semantic_prerequisite(
                    &actor,
                    &proof,
                    current_generation,
                    &fence,
                    now_ms()?,
                ),
                "explicit_current_prerequisite_reinstatement",
            )?;
            let before = constraints::protected_counts(f)?;
            store.reinstate_semantic_prerequisite(
                &actor,
                &proof,
                current_generation,
                &fence,
                now_ms()?,
            )?;
            assert_eq!(constraints::protected_counts(f)?, before);
            assert!(store.install_semantic_prerequisite(&original).is_err());
            assert_eq!(constraints::protected_counts(f)?, before);
        }
        if stale && mode == "current" {
            f.authority
                .admission_operation_store()
                .revoke_semantic_prerequisite(
                    &p.plan.scope,
                    &proof.body().fact,
                    &proof.body().resource,
                )?;
            // Replaying the original signature cannot resurrect revoked state.
            f.authority
                .admission_operation_store()
                .install_semantic_prerequisite(&proof)?;
        }
        p.invocation.prerequisites = BoundedList::new(vec![proof])?;
    }
    if stale && mode == "transform" && !withheld_source {
        let mut body = p
            .invocation
            .transformation
            .as_ref()
            .ok_or("missing transform")?
            .body()
            .clone();
        body.implementation = CanonicalPayloadDigest::from_bytes([99; 32]);
        p.invocation.transformation =
            Some(SignedSemanticTransformationV1::sign(body, &p.transformer)?);
    }
    request.arguments = serde_json::to_value(&p.invocation)?;
    let historical_deadline = if stale && mode == "historical" {
        Some(
            p.invocation
                .action
                .valid_until_unix_ms
                .get()
                .min(p.invocation.audience.body().valid_until_unix_ms.get())
                .min(
                    p.invocation.prerequisites.as_slice()[0]
                        .body()
                        .valid_until_unix_ms
                        .get(),
                ),
        )
    } else {
        None
    };
    let admission_started_at = now_ms()?;
    let dependent_deadline = p
        .invocation
        .action
        .valid_until_unix_ms
        .get()
        .min(p.invocation.audience.body().valid_until_unix_ms.get());
    let result = runtime
        .execute_step(&f.process, "root", "dependent-a", &request)
        .await;
    if let Some(deadline) = historical_deadline {
        assert!(
            now_ms()? < deadline,
            "expiration cannot stand in for a changed reviewed-version refusal"
        );
    }
    if stale {
        assert!(
            result.is_err()
                || result
                    .as_ref()
                    .is_ok_and(|response| response.verdict == Verdict::Deny)
        );
        assert_eq!(
            f.effects.load(Ordering::SeqCst),
            if mode == "transform" { 0 } else { 1 }
        );
    } else {
        let result = result?;
        assert_eq!(
            result.verdict,
            Verdict::Allow,
            "mode={mode} reason={:?}; started_current={}; completed_current={}",
            result.reason,
            admission_started_at < dependent_deadline,
            now_ms()? < dependent_deadline
        );
        assert_eq!(
            f.effects.load(Ordering::SeqCst),
            if mode == "transform" { 1 } else { 2 }
        );
        if mode == "held" {
            // A newly signed action and fact cannot transfer a spent lease to
            // a sibling step or reopen the first native effect.
            let fresh = now_ms()?;
            p.invocation.action.step = StepId::new("dependent-b")?;
            p.invocation.action.issued_at_unix_ms = SafeInteger::new(fresh)?;
            p.invocation.action.valid_until_unix_ms = SafeInteger::new(fresh + 50_000)?;
            let mut acl = p.invocation.audience.body().clone();
            acl.observed_at_unix_ms = p.invocation.action.issued_at_unix_ms;
            acl.valid_until_unix_ms = p.invocation.action.valid_until_unix_ms;
            p.invocation.audience = SignedSemanticAudienceV1::sign(acl, &p.resolver)?;
            f.authority
                .admission_operation_store()
                .install_semantic_audience(&p.invocation.audience)?;
            let mut sibling = f.process.tool_request(
                "root",
                "dependent-b",
                "semantic-a",
                "remedy",
                serde_json::json!({}),
            )?;
            p.invocation.action =
                runtime.frame_action(&sibling, p.invocation.action, &p.payload)?;
            attach_endorsement(&mut p, "sibling-endorsement")?;
            let mut proof = p.invocation.prerequisites.as_slice()[0].body().clone();
            proof.evidence = EvidenceRef::new("sibling-prerequisite")?;
            proof.action = semantic_action_digest(&p.invocation.action)?;
            proof.issued_at_unix_ms = p.invocation.action.issued_at_unix_ms;
            proof.valid_until_unix_ms = p.invocation.action.valid_until_unix_ms;
            let proof = SignedSemanticPrerequisiteV1::sign(proof, &p.prerequisite)?;
            f.authority
                .admission_operation_store()
                .install_semantic_prerequisite(&proof)?;
            p.invocation.prerequisites = BoundedList::new(vec![proof])?;
            sibling.arguments = serde_json::to_value(&p.invocation)?;
            let refused = runtime
                .execute_step(&f.process, "root", "dependent-b", &sibling)
                .await;
            assert!(refused.is_err() || refused.as_ref().is_ok_and(|r| r.verdict == Verdict::Deny));
            assert_eq!(f.effects.load(Ordering::SeqCst), 2);
        }
    }
    Ok(())
}
#[tokio::test]
async fn native_derived_bytes_have_a_separate_producer_and_fresh_dependent_authority() -> TestResult
{
    for stale in [false, true] {
        let f = native_fixture("transform")?;
        chain(&f, "transform", stale).await?;
    }
    let f = native_fixture("transform")?;
    chain(&f, "withheld-transform", true).await?;
    Ok(())
}
#[tokio::test]
async fn native_historical_current_and_held_prerequisites_are_distinct() -> TestResult {
    for mode in ["historical", "current", "held"] {
        let f = native_fixture(mode)?;
        chain(&f, mode, false).await?;
        if mode != "historical" {
            let f = native_fixture(mode)?;
            chain(&f, mode, true).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_changed_reviewed_resource_version_refuses_before_dependent_effect() -> TestResult {
    let matching = native_fixture("historical")?;
    chain(&matching, "historical", false).await?;
    let f = native_fixture("historical")?;
    chain(&f, "historical", true).await
}

#[tokio::test]
async fn native_delayed_predicate_proof_cannot_clear_local_revocation() -> TestResult {
    let f = native_fixture("current")?;
    chain_with_failure(&f, "current", PrerequisiteFailure::DelayedRevokedProof).await
}

#[tokio::test]
async fn native_prerequisite_reinstatement_requires_current_generation_and_live_maintenance(
) -> TestResult {
    let f = native_fixture("current")?;
    chain_with_failure(&f, "current", PrerequisiteFailure::ExplicitReinstatement).await
}

#[tokio::test]
async fn native_expired_held_reservation_refuses_before_provider_submission() -> TestResult {
    let f = native_fixture("held-expired")?;
    chain_with_failure(&f, "held", PrerequisiteFailure::ExpiredHeldProof).await?;
    assert!(
        f.path.join("held-capture-expired").exists(),
        "the held proof must be captured while fresh, then expire before submission"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let connection = rusqlite::Connection::open(f.path.join("admission.db"))?;
    let captures: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'semantic-capture:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        captures, 2,
        "the dependent refusal must follow real native capture"
    );
    Ok(())
}
