use chio_semantic_contracts::*;
#[path = "../../../../fixtures/recovery-semantic-profile.rs"]
mod fixture;
use chio_core_types::recovery::*;
use chio_security_types::{flow::InformationLabel, recovery::*, semantic::*};
use fixture::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn scope() -> Result<RecoveryScopeV1, ContractError> {
    Ok(RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("authority")?,
        tenant_id: RecoveryTenantId::new("tenant")?,
        process_id: ProcessId::new("root")?,
    })
}
fn compiled(f: &SemanticFixture) -> Result<CompiledSemanticRegistryV1, ContractError> {
    compile_semantic_registry(
        &f.deployment,
        core::slice::from_ref(&f.package),
        &f.operator.public_key(),
        &[f.publisher.public_key()],
        core::slice::from_ref(&f.exposed),
        &mut VerificationBudget::new(4096)?,
    )
}
fn verify(
    f: &SemanticFixture,
    invocation: &SemanticInvocationV1,
    now: u64,
) -> Result<VerifiedSemanticInvocationV1, ContractError> {
    verify_semantic_invocation(
        &compiled(f)?,
        invocation,
        &SemanticInvocationExpectationV1 {
            server: "server-a",
            tool: "send",
            request_id: "request-a",
            request_namespace: f.invocation.action.request_namespace,
            capability: f.invocation.action.capability,
            request_semantics: f.invocation.action.request_semantics,
            source_label: &InformationLabel::bottom(),
            externally_influenced: false,
            influence: f.invocation.action.influence,
            native_disclosure_target: None,
            now_unix_ms: now,
        },
        &mut VerificationBudget::new(4096)?,
    )
}

fn select_fixture_annotator(f: &mut SemanticFixture) -> TestResult {
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.annotators = BoundedList::new(vec![SemanticAnnotatorBindingV1 {
        key: semantic_key_digest(&f.annotator.public_key())?,
        facts: BoundedList::new(vec![])?,
        may_attest_facts: false,
    }])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    if !f.invocation.endorsements.as_slice().is_empty() {
        let mut invocation = f.invocation.clone();
        resign_action(f, &mut invocation)?;
        f.invocation = invocation;
    }
    Ok(())
}

#[test]
fn selected_annotator_restrictions_cannot_be_omitted_on_read_operations() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    select_fixture_annotator(&mut f)?;
    let annotation = SemanticAnnotationV1 {
        domain_version: VersionV1,
        scope: scope()?,
        input: f.invocation.action.inputs.as_slice()[0].clone(),
        restrictions: InformationLabel::Top,
        externally_influenced: true,
        facts: BoundedList::new(vec![])?,
        confidence_basis_points: SafeInteger::new(1)?,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51_000)?,
    };
    let mut restricted = f.invocation.clone();
    restricted.annotations = BoundedList::new(vec![SignedSemanticAnnotationV1::sign(
        annotation.clone(),
        &f.annotator,
    )?])?;
    restricted.action.source_label = InformationLabel::Top;
    restricted.action.influence = semantic_annotated_influence(
        f.invocation.action.influence,
        restricted.annotations.as_slice(),
    )?;
    assert!(verify(&f, &restricted, 1001).is_err());
    assert!(matches!(
        verify(&f, &f.invocation, 1001),
        Err(ContractError::MissingDependency)
    ));

    // The same selected authority can provide a complete nonrestrictive answer.
    let mut neutral = restricted;
    let mut body = annotation;
    body.restrictions = InformationLabel::bottom();
    neutral.annotations =
        BoundedList::new(vec![SignedSemanticAnnotationV1::sign(body, &f.annotator)?])?;
    neutral.action.source_label = InformationLabel::bottom();
    neutral.action.influence = semantic_annotated_influence(
        f.invocation.action.influence,
        neutral.annotations.as_slice(),
    )?;
    assert!(verify(&f, &neutral, 1001).is_ok());
    Ok(())
}

#[test]
fn reviewed_resource_proof_cannot_cover_a_different_dependent_version() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut package = f.package.body().clone();
    let mut contract = package.operations.as_slice()[0].clone();
    contract.prerequisites = BoundedList::new(vec![SemanticPrerequisiteRequirementV1 {
        fact: SemanticFactId::new("reviewed")?,
        kind: SemanticPrerequisiteKindV1::HistoricalFact,
        resource: ProviderResourceId::new("ticket")?,
    }])?;
    package.operations = NonEmptyBoundedList::new(vec![contract])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    // This case isolates prerequisite semantics from annotation completeness.
    route.annotators = BoundedList::new(vec![])?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    let input = &f.invocation.action.inputs.as_slice()[0];
    let mut proof = SemanticPrerequisiteV1 {
        domain_version: VersionV1,
        evidence: EvidenceRef::new("reviewed-resource")?,
        scope: scope()?,
        action: semantic_action_digest(&f.invocation.action)?,
        fact: SemanticFactId::new("reviewed")?,
        kind: SemanticPrerequisiteKindV1::HistoricalFact,
        resource: input.resource.clone(),
        version: input.version,
        material: input.content,
        producer: OperationId::new("completed-review")?,
        lease: None,
        purpose: ProtectedText::new("customer-support")?,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51_000)?,
    };
    let mut invocation = f.invocation.clone();
    invocation.prerequisites = BoundedList::new(vec![SignedSemanticPrerequisiteV1::sign(
        proof.clone(),
        &f.prerequisite,
    )?])?;
    assert!(verify(&f, &invocation, 1001).is_ok());
    for kind in [
        SemanticPrerequisiteKindV1::HistoricalFact,
        SemanticPrerequisiteKindV1::CurrentPredicate,
    ] {
        let mut package = f.package.body().clone();
        let mut contract = package.operations.as_slice()[0].clone();
        let mut requirement = contract.prerequisites.as_slice()[0].clone();
        requirement.kind = kind;
        contract.prerequisites = BoundedList::new(vec![requirement])?;
        package.operations = NonEmptyBoundedList::new(vec![contract])?;
        f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
        let mut deployment = f.deployment.body().clone();
        let mut route = deployment.routes.as_slice()[0].clone();
        route.package = semantic_package_digest(f.package.body())?;
        deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
        invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
        proof.action = semantic_action_digest(&invocation.action)?;
        proof.kind = kind;
        proof.version = ArtifactVersionId::from_bytes([77; 32]);
        invocation.prerequisites = BoundedList::new(vec![SignedSemanticPrerequisiteV1::sign(
            proof.clone(),
            &f.prerequisite,
        )?])?;
        assert!(matches!(
            verify(&f, &invocation, 1001),
            Err(ContractError::BindingMismatch)
        ));
    }
    Ok(())
}

#[test]
fn registry_compilation_accepts_sixteen_operations_with_sixteen_fields_and_selectors() -> TestResult
{
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let fields = (0..16)
        .map(|index| SemanticFieldId::new(&format!("field-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let selectors = fields
        .iter()
        .map(|field| SemanticSelectorV1::Present {
            field: field.clone(),
        })
        .collect::<Vec<_>>();
    let mut operations = Vec::new();
    let mut routes = Vec::new();
    let mut exposed = Vec::new();
    for index in 0..16 {
        let mut operation = f.package.body().operations.as_slice()[0].clone();
        operation.operation = SemanticOperationId::new(&format!("operation-{index}"))?;
        operation.input_fields = BoundedList::new(fields.clone())?;
        operation.selectors = BoundedList::new(selectors.clone())?;
        operations.push(operation.clone());
        let mut route = f.deployment.body().routes.as_slice()[0].clone();
        route.operation = operation.operation;
        route.tool = ProtectedText::new(&format!("tool-{index}"))?;
        route.annotators = BoundedList::new(vec![])?;
        route.operator_selectors = BoundedList::new(selectors.clone())?;
        let mut actual = f.exposed.clone();
        actual.tool = route.tool.clone();
        exposed.push(actual);
        routes.push(route);
    }
    let mut package = f.package.body().clone();
    package.operations = NonEmptyBoundedList::new(operations)?;
    let package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let digest = semantic_package_digest(package.body())?;
    for route in &mut routes {
        route.package = digest;
    }
    let mut deployment = f.deployment.body().clone();
    deployment.packages = NonEmptyBoundedList::new(vec![digest])?;
    deployment.routes = NonEmptyBoundedList::new(routes)?;
    deployment.exposure_binding = semantic_content_digest(&exposed)?;
    let deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    let registry = compile_semantic_registry(
        &deployment,
        &[package],
        &f.operator.public_key(),
        &[f.publisher.public_key()],
        &exposed,
        &mut VerificationBudget::new(4096)?,
    )?;
    assert!(registry.resolve("server-a", "tool-15").is_ok());
    Ok(())
}

#[test]
fn dense_semantic_plan_at_the_step_ceiling_fits_its_declared_budget() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut steps = Vec::new();
    for index in 0..8 {
        let mut step = f.plan.steps.as_slice()[0].clone();
        step.step = StepId::new(&format!("step-{index:02}"))?;
        step.dependencies = BoundedList::new(
            (0..index)
                .map(|prior| StepId::new(&format!("step-{prior:02}")))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        steps.push(step);
    }
    steps.reverse();
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(steps)?,
        ..f.plan
    };
    let ordered = validate_semantic_plan(&plan, &mut VerificationBudget::new(4096)?)?;
    assert_eq!(ordered.len(), 8);
    assert_eq!(ordered[0].as_str(), "step-00");
    assert_eq!(ordered[7].as_str(), "step-07");
    Ok(())
}

#[test]
fn withheld_completion_status_requires_an_explicit_contract_audience() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    // The ordinary fixture explicitly authors its status channel. Remove it
    // before signing the negative package so the omitted authority is real.
    let mut package = f.package.body().clone();
    let mut contract = package.operations.as_slice()[0].clone();
    contract.withheld_status = None;
    package.operations = NonEmptyBoundedList::new(vec![contract])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    f.invocation.action.output = SemanticOutputDispositionV1::Withhold;
    assert!(matches!(
        verify(&f, &f.invocation, 1001),
        Err(ContractError::MissingDependency)
    ));
    let mut value = serde_json::to_value(&f.package.body().operations.as_slice()[0])?;
    value
        .as_object_mut()
        .ok_or("operation contract must be an object")?
        .insert(
            "withheld_status".into(),
            serde_json::json!({"audience": InformationLabel::bottom()}),
        );
    let contract: SemanticOperationContractV1 = serde_json::from_value(value)?;
    let mut package = f.package.body().clone();
    package.operations = NonEmptyBoundedList::new(vec![contract])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    assert!(verify(&f, &f.invocation, 1001).is_ok());
    Ok(())
}

#[test]
fn fresh_semantic_plan_refuses_more_than_eight_top_level_steps() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut steps = Vec::new();
    for index in 0..9 {
        let mut step = f.plan.steps.as_slice()[0].clone();
        step.step = StepId::new(&format!("step-{index:02}"))?;
        steps.push(step);
    }
    let plan = SemanticPlanV1 {
        steps: NonEmptyBoundedList::new(steps)?,
        ..f.plan
    };
    assert!(matches!(
        validate_semantic_plan(&plan, &mut VerificationBudget::new(4096)?),
        Err(ContractError::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn absent_withheld_status_preserves_signed_contract_bytes_and_explicit_null_is_refused(
) -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut value = serde_json::to_value(&f.package.body().operations.as_slice()[0])?;
    value
        .as_object_mut()
        .ok_or("operation contract must be an object")?
        .remove("withheld_status");
    let legacy: SemanticOperationContractV1 = serde_json::from_value(value.clone())?;
    assert!(legacy.withheld_status.is_none());
    assert_eq!(
        chio_core_types::canonical_json_bytes(&legacy)?,
        chio_core_types::canonical_json_bytes(&value)?,
    );
    value
        .as_object_mut()
        .ok_or("operation contract must be an object")?
        .insert("withheld_status".into(), serde_json::Value::Null);
    assert!(serde_json::from_value::<SemanticOperationContractV1>(value).is_err());
    Ok(())
}
#[test]
fn withheld_read_status_cannot_be_classified_below_the_verified_provider_audience() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let private = InformationLabel::try_known(
        Default::default(),
        std::iter::once("support-private".parse::<chio_security_types::flow::Compartment>()?)
            .collect(),
    )?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    let mut destination = route.destinations.as_slice()[0].clone();
    destination.audience = private.clone();
    route.destinations = NonEmptyBoundedList::new(vec![destination])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    let mut audience = f.invocation.audience.body().clone();
    audience.audience = private.clone();
    f.invocation.audience = SignedSemanticAudienceV1::sign(audience, &f.resolver)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    f.invocation.action.output = SemanticOutputDispositionV1::Withhold;
    assert!(matches!(
        verify(&f, &f.invocation, 1001),
        Err(ContractError::BindingMismatch)
    ));

    let mut package = f.package.body().clone();
    let mut contract = package.operations.as_slice()[0].clone();
    contract.withheld_status = Some(SemanticWithheldStatusV1 {
        audience: private.clone(),
    });
    package.operations = NonEmptyBoundedList::new(vec![contract])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    f.invocation.action.source_label = private;
    assert!(verify(&f, &f.invocation, 1001).is_ok());
    Ok(())
}

#[test]
fn support_read_effective_source_includes_its_verified_read_audience() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let private = InformationLabel::try_known(
        Default::default(),
        std::iter::once("support-private".parse::<chio_security_types::flow::Compartment>()?)
            .collect(),
    )?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    let mut destination = route.destinations.as_slice()[0].clone();
    destination.audience = private.clone();
    route.destinations = NonEmptyBoundedList::new(vec![destination])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    let mut audience = f.invocation.audience.body().clone();
    audience.audience = private.clone();
    f.invocation.audience = SignedSemanticAudienceV1::sign(audience, &f.resolver)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    assert_eq!(
        f.invocation.action.output,
        SemanticOutputDispositionV1::ReturnValue
    );
    assert_eq!(f.invocation.action.source_label, InformationLabel::bottom());
    assert!(matches!(
        verify(&f, &f.invocation, 1001),
        Err(ContractError::BindingMismatch)
    ));

    f.invocation.action.source_label = private.clone();
    let verified = verify(&f, &f.invocation, 1001)?;
    assert_eq!(verified.effective_constraints.source_label, private);
    Ok(())
}

#[test]
fn integrity_only_endorsement_never_requires_confidentiality_downgrade() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert!(verify(&f, &f.invocation, 1001).is_ok());
    assert!(f.invocation.action.externally_influenced);
    let mut missing = f.invocation.clone();
    missing.endorsements = BoundedList::new(vec![])?;
    assert!(verify(&f, &missing, 1001).is_err());
    Ok(())
}
#[test]
fn signed_packages_cannot_install_tenant_authority_or_missing_coverage() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert!(compile_semantic_registry(
        &f.deployment,
        core::slice::from_ref(&f.package),
        &f.publisher.public_key(),
        &[f.publisher.public_key()],
        core::slice::from_ref(&f.exposed),
        &mut VerificationBudget::new(4096)?
    )
    .is_err());
    assert!(compile_semantic_registry(
        &f.deployment,
        core::slice::from_ref(&f.package),
        &f.operator.public_key(),
        &[f.publisher.public_key()],
        &[],
        &mut VerificationBudget::new(4096)?
    )
    .is_err());
    for channel in [
        SemanticChannelV1::Error,
        SemanticChannelV1::Stream,
        SemanticChannelV1::Nested,
    ] {
        let mut bad = f.exposed.clone();
        let mut channels = bad.channels.as_slice().to_vec();
        for rule in &mut channels {
            if rule.channel == channel {
                rule.enabled = !rule.enabled;
            }
        }
        bad.channels = NonEmptyBoundedList::new(channels)?;
        assert!(compile_semantic_registry(
            &f.deployment,
            core::slice::from_ref(&f.package),
            &f.operator.public_key(),
            &[f.publisher.public_key()],
            &[bad],
            &mut VerificationBudget::new(4096)?
        )
        .is_err());
    }
    Ok(())
}
#[test]
fn substitution_matrix_refuses_changed_exact_actions_and_acl_uncertainty() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let mut mutations = Vec::new();
    let mut bad = f.invocation.clone();
    bad.action.request_id = RequestId::new("request-b")?;
    mutations.push(bad);
    let mut bad = f.invocation.clone();
    bad.action.capability = CapabilityBodyDigest::from_bytes([9; 32]);
    mutations.push(bad);
    let mut bad = f.invocation.clone();
    bad.action.registry = SemanticRegistryDigest::from_bytes([9; 32]);
    mutations.push(bad);
    let mut bad = f.invocation.clone();
    bad.action.destination = SemanticDestinationId::new("other-account")?;
    mutations.push(bad);
    let mut bad = f.invocation.clone();
    bad.action.externally_influenced = false;
    mutations.push(bad);
    let mut bad = f.invocation.clone();
    bad.action.output = SemanticOutputDispositionV1::Withhold;
    mutations.push(bad);
    for completeness in [
        SemanticAudienceCompletenessV1::Partial,
        SemanticAudienceCompletenessV1::Ambiguous,
        SemanticAudienceCompletenessV1::Outage,
        SemanticAudienceCompletenessV1::RateLimited,
    ] {
        let mut bad = f.invocation.clone();
        let mut body = bad.audience.body().clone();
        body.completeness = completeness;
        bad.audience = SignedSemanticAudienceV1::sign(body, &f.resolver)?;
        mutations.push(bad);
    }
    for bad in mutations {
        assert!(verify(&f, &bad, 1001).is_err());
    }
    assert!(verify(&f, &f.invocation, 51_000).is_err());
    Ok(())
}
#[test]
fn annotator_confidence_cannot_create_facts_or_endorsement() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    select_fixture_annotator(&mut f)?;
    let annotation = SemanticAnnotationV1 {
        domain_version: VersionV1,
        scope: scope()?,
        input: f.invocation.action.inputs.as_slice()[0].clone(),
        restrictions: InformationLabel::bottom(),
        externally_influenced: false,
        facts: BoundedList::new(vec![SemanticFactId::new("customer-instructions-reviewed")?])?,
        confidence_basis_points: SafeInteger::new(10_000)?,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51_000)?,
    };
    let mut bad = f.invocation.clone();
    bad.annotations = BoundedList::new(vec![SignedSemanticAnnotationV1::sign(
        annotation,
        &f.annotator,
    )?])?;
    assert!(verify(&f, &bad, 1001).is_err());
    let mut body = f.invocation.endorsements.as_slice()[0].body().clone();
    body.target = SemanticEndorsementTargetV1::PersistentArtifact {
        artifact: ArtifactVersionId::from_bytes([0; 32]),
    };
    let mut bad = f.invocation.clone();
    bad.endorsements = BoundedList::new(vec![SignedScopedEndorsementV1::sign(body, &f.endorser)?])?;
    assert!(verify(&f, &bad, 1001).is_err());
    Ok(())
}
#[test]
fn projection_removes_exact_fields_without_mutating_source_or_influence() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::FieldProjection,
    )?;
    let fields = f.package.body().operations.as_slice()[0]
        .projection_fields
        .as_slice();
    let output = project_semantic_fields(&f.payload, fields, &mut VerificationBudget::new(4096)?)?;
    assert_eq!(output.fields.as_slice().len(), 1);
    assert!(!chio_core_types::canonical_json_string(&output)?.contains("private-canary"));
    assert_ne!(
        semantic_content_digest(&output)?,
        semantic_content_digest(&f.payload)?
    );
    assert_eq!(f.payload.fields.as_slice().len(), 2);
    assert!(project_semantic_fields(
        &f.payload,
        &[SemanticFieldId::new("missing")?],
        &mut VerificationBudget::new(4096)?
    )
    .is_err());
    Ok(())
}
#[test]
fn prerequisite_dags_refuse_cycles_duplicates_missing_and_undeclared_future_inputs() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert_eq!(
        validate_semantic_plan(&f.plan, &mut VerificationBudget::new(4096)?)?,
        vec![StepId::new("remedy")?]
    );
    for dependency in ["remedy", "missing"] {
        let mut plan = f.plan.clone();
        let mut step = plan.steps.as_slice()[0].clone();
        step.dependencies = BoundedList::new(vec![StepId::new(dependency)?])?;
        plan.steps = NonEmptyBoundedList::new(vec![step])?;
        assert!(validate_semantic_plan(&plan, &mut VerificationBudget::new(4096)?).is_err());
    }
    let mut plan = f.plan.clone();
    plan.steps = NonEmptyBoundedList::new(vec![
        plan.steps.as_slice()[0].clone(),
        plan.steps.as_slice()[0].clone(),
    ])?;
    assert!(validate_semantic_plan(&plan, &mut VerificationBudget::new(4096)?).is_err());
    assert!(verify_semantic_invocation(
        &compiled(&f)?,
        &f.invocation,
        &SemanticInvocationExpectationV1 {
            server: "server-a",
            tool: "send",
            request_id: "request-a",
            request_namespace: f.invocation.action.request_namespace,
            capability: f.invocation.action.capability,
            request_semantics: f.invocation.action.request_semantics,
            source_label: &InformationLabel::bottom(),
            externally_influenced: false,
            influence: f.invocation.action.influence,
            native_disclosure_target: None,
            now_unix_ms: 1001
        },
        &mut VerificationBudget::new(1)?
    )
    .is_err());
    Ok(())
}

fn resign_action(f: &SemanticFixture, invocation: &mut SemanticInvocationV1) -> TestResult {
    let mut body = f.invocation.endorsements.as_slice()[0].body().clone();
    body.target = SemanticEndorsementTargetV1::ExactAction {
        action: semantic_action_digest(&invocation.action)?,
    };
    body.influence = invocation.action.influence;
    invocation.endorsements =
        BoundedList::new(vec![SignedScopedEndorsementV1::sign(body, &f.endorser)?])?;
    Ok(())
}
#[test]
fn complete_pagination_and_single_strong_provider_version_are_required() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    for version in ["*", "W/\"v1\"", "\"a\",\"b\"", "\"a\r\nb\"", "\"\""] {
        assert!(validate_semantic_provider_version(version).is_err());
    }
    assert!(validate_semantic_provider_version("\"actual-resource-v1\"").is_ok());
    for mutation in 0..5 {
        let mut invocation = f.invocation.clone();
        let mut body = invocation.audience.body().clone();
        match mutation {
            0 => body.pagination.pages_observed = SafeInteger::new(0)?,
            1 => body.pagination.pages_expected = SafeInteger::new(2)?,
            2 => body.pagination.cursor = SemanticAclCursorV1::Pending,
            3 => body.account = ProviderAccountId::new("other-account")?,
            _ => body.provider_version = ProtectedText::new("\"a\",\"b\"")?,
        }
        invocation.audience = SignedSemanticAudienceV1::sign(body, &f.resolver)?;
        assert!(verify(&f, &invocation, 1001).is_err());
    }
    Ok(())
}
#[test]
fn annotation_restrictions_and_influence_are_bound_without_creating_authority() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    select_fixture_annotator(&mut f)?;
    let body = SemanticAnnotationV1 {
        domain_version: VersionV1,
        scope: scope()?,
        input: f.invocation.action.inputs.as_slice()[0].clone(),
        restrictions: InformationLabel::bottom(),
        externally_influenced: true,
        facts: BoundedList::new(vec![])?,
        confidence_basis_points: SafeInteger::new(1)?,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51000)?,
    };
    let mut invocation = f.invocation.clone();
    invocation.annotations =
        BoundedList::new(vec![SignedSemanticAnnotationV1::sign(body, &f.annotator)?])?;
    assert!(verify(&f, &invocation, 1001).is_err());
    invocation.action.influence = semantic_annotated_influence(
        f.invocation.action.influence,
        invocation.annotations.as_slice(),
    )?;
    resign_action(&f, &mut invocation)?;
    assert!(verify(&f, &invocation, 1001).is_ok());
    invocation.annotations = BoundedList::new(vec![])?;
    assert!(verify(&f, &invocation, 1001).is_err());
    let model = semantic_observed_influence(
        f.invocation.action.influence,
        Some(CanonicalPayloadDigest::from_bytes([90; 32])),
    )?;
    assert_ne!(model, f.invocation.action.influence);
    assert_eq!(semantic_observed_influence(model, None)?, model);
    Ok(())
}
#[test]
fn reviewed_package_override_preserves_operator_selector_ceiling() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let mut package = f.package.body().clone();
    let mut operation = package.operations.as_slice()[0].clone();
    operation.selectors = BoundedList::new(vec![SemanticSelectorV1::Equals {
        field: SemanticFieldId::new("title")?,
        value: SemanticValueV1::Text {
            value: ProtectedText::new("package-only-title")?,
        },
    }])?;
    package.operations = NonEmptyBoundedList::new(vec![operation])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    route.reviewed_overrides = BoundedList::new(vec![SemanticReviewedOverrideV1 {
        selector_index: SafeInteger::new(0)?,
        reason: ProtectedText::new("reviewed support title fixture")?,
        fixture_digests: NonEmptyBoundedList::new(vec![semantic_content_digest(&f.payload)?])?,
    }])?;
    route.operator_selectors = BoundedList::new(vec![SemanticSelectorV1::Equals {
        field: SemanticFieldId::new("title")?,
        value: SemanticValueV1::Text {
            value: ProtectedText::new("support ticket")?,
        },
    }])?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    let mut invocation = f.invocation.clone();
    resign_action(&f, &mut invocation)?;
    let verified = verify(&f, &invocation, 1001)?;
    let constraints = &verified.effective_constraints;
    assert!(constraints.applied_package_selectors.as_slice().is_empty());
    assert_eq!(constraints.reviewed_overrides.as_slice().len(), 1);
    assert_eq!(
        constraints.reviewed_overrides.as_slice()[0].selector_index,
        SafeInteger::new(0)?
    );
    assert_eq!(constraints.operator_selectors.as_slice().len(), 1);
    assert_eq!(constraints.destination, invocation.action.destination);
    assert_eq!(
        constraints.native_ceilings,
        SemanticNativeCeilingRequirementV1::FreshNativeAdmission
    );
    let mut fields = invocation.payload.fields.as_slice().to_vec();
    fields[0].value = SemanticValueV1::Text {
        value: ProtectedText::new("forbidden-operator-title")?,
    };
    invocation.payload.fields = NonEmptyBoundedList::new(fields)?;
    invocation.action.payload = semantic_content_digest(&invocation.payload)?;
    resign_action(&f, &mut invocation)?;
    assert!(verify(&f, &invocation, 1001).is_err());
    Ok(())
}
#[test]
fn transform_and_prerequisite_claims_bind_action_scope_output_and_role() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let mut package = f.package.body().clone();
    let mut operation = package.operations.as_slice()[0].clone();
    operation.prerequisites = BoundedList::new(vec![SemanticPrerequisiteRequirementV1 {
        fact: SemanticFactId::new("reviewed")?,
        kind: SemanticPrerequisiteKindV1::HistoricalFact,
        resource: ProviderResourceId::new("ticket")?,
    }])?;
    package.operations = NonEmptyBoundedList::new(vec![operation])?;
    f.package = SignedSemanticPackageV1::sign(package, &f.publisher)?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.package = semantic_package_digest(f.package.body())?;
    deployment.packages = NonEmptyBoundedList::new(vec![route.package])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    f.invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    let mut invocation = f.invocation.clone();
    resign_action(&f, &mut invocation)?;
    let proof = SemanticPrerequisiteV1 {
        domain_version: VersionV1,
        evidence: EvidenceRef::new("review-proof")?,
        scope: scope()?,
        action: semantic_action_digest(&invocation.action)?,
        fact: SemanticFactId::new("reviewed")?,
        kind: SemanticPrerequisiteKindV1::HistoricalFact,
        resource: ProviderResourceId::new("ticket")?,
        version: invocation.action.inputs.as_slice()[0].version,
        material: invocation.action.inputs.as_slice()[0].content,
        producer: OperationId::new("synthetic-producer")?,
        lease: None,
        purpose: ProtectedText::new("customer-support")?,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51000)?,
    };
    invocation.prerequisites = BoundedList::new(vec![SignedSemanticPrerequisiteV1::sign(
        proof.clone(),
        &f.prerequisite,
    )?])?;
    let transformation = SemanticTransformationV1 {
        domain_version: VersionV1,
        scope: scope()?,
        producer: proof.producer.clone(),
        producer_action: semantic_action_digest(&invocation.action)?,
        inputs: invocation.action.inputs.clone(),
        implementation: CanonicalPayloadDigest::from_bytes([3; 32]),
        configuration: CanonicalPayloadDigest::from_bytes([8; 32]),
        output_schema: CanonicalPayloadDigest::from_bytes([2; 32]),
        output: invocation.action.payload,
        output_label: invocation.action.source_label.clone(),
        influence: invocation.action.influence,
        destination: invocation.action.destination.clone(),
        purpose: ProtectedText::new("customer-support")?,
        disposition: invocation.action.output,
        issued_at_unix_ms: SafeInteger::new(1000)?,
        valid_until_unix_ms: SafeInteger::new(51000)?,
    };
    invocation.transformation = Some(SignedSemanticTransformationV1::sign(
        transformation.clone(),
        &f.transformer,
    )?);
    // Pure proof verification does not establish native producer completion.
    assert!(verify(&f, &invocation, 1001).is_ok());
    for mutation in 0..4 {
        let mut bad = invocation.clone();
        let mut body = transformation.clone();
        match mutation {
            0 => body.output = CanonicalPayloadDigest::from_bytes([9; 32]),
            1 => body.scope.tenant_id = RecoveryTenantId::new("foreign-tenant")?,
            2 => body.purpose = ProtectedText::new("foreign-purpose")?,
            _ => body.disposition = SemanticOutputDispositionV1::Withhold,
        }
        bad.transformation = Some(SignedSemanticTransformationV1::sign(body, &f.transformer)?);
        assert!(verify(&f, &bad, 1001).is_err());
    }
    let mut bad = invocation.clone();
    let mut proof = proof;
    proof.action = SemanticActionDigest::from_bytes([7; 32]);
    bad.prerequisites = BoundedList::new(vec![SignedSemanticPrerequisiteV1::sign(
        proof,
        &f.prerequisite,
    )?])?;
    assert!(verify(&f, &bad, 1001).is_err());
    Ok(())
}

#[test]
fn endorsement_cannot_erase_owner_policy_or_lower_confidentiality() -> TestResult {
    use chio_security_types::flow::PrincipalId;
    use std::collections::{BTreeMap, BTreeSet};
    let owner = PrincipalId::new("owner-a")?;
    let label = InformationLabel::try_known(
        BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
        BTreeSet::new(),
    )?;
    let mut f = semantic_fixture(
        scope()?,
        1000,
        label.clone(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert!(verify(&f, &f.invocation, 1001).is_ok());
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    let mut destination = route.destinations.as_slice()[0].clone();
    destination.audience = InformationLabel::bottom();
    route.destinations = NonEmptyBoundedList::new(vec![destination])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    let mut invocation = f.invocation.clone();
    invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
    let mut acl = invocation.audience.body().clone();
    acl.audience = InformationLabel::bottom();
    invocation.audience = SignedSemanticAudienceV1::sign(acl, &f.resolver)?;
    resign_action(&f, &mut invocation)?;
    assert!(verify(&f, &invocation, 1001).is_err());
    invocation.action.source_label = InformationLabel::bottom();
    resign_action(&f, &mut invocation)?;
    assert!(verify(&f, &invocation, 1001).is_err());
    assert!(!label.flows_to(&InformationLabel::bottom()));
    Ok(())
}

#[test]
fn future_inputs_require_declared_prerequisites() -> TestResult {
    let f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let mut plan = f.plan.clone();
    let mut step = plan.steps.as_slice()[0].clone();
    step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::FutureOutput {
        step: StepId::new("unaccepted-producer")?,
    }])?;
    plan.steps = NonEmptyBoundedList::new(vec![step])?;
    assert!(validate_semantic_plan(&plan, &mut VerificationBudget::new(4096)?).is_err());
    Ok(())
}

#[test]
fn aggregate_facts_share_a_limit_across_selected_annotation_and_endorsement_roles() -> TestResult {
    let mut f = semantic_fixture(
        scope()?,
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let facts = (0..8)
        .map(|index| SemanticFactId::new(&format!("selected-fact-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut deployment = f.deployment.body().clone();
    let mut route = deployment.routes.as_slice()[0].clone();
    route.annotators = BoundedList::new(vec![SemanticAnnotatorBindingV1 {
        key: semantic_key_digest(&f.annotator.public_key())?,
        facts: BoundedList::new(facts.clone())?,
        may_attest_facts: true,
    }])?;
    deployment.routes = NonEmptyBoundedList::new(vec![route])?;
    f.deployment = SignedSemanticDeploymentV1::sign(deployment, &f.operator)?;
    for (last_count, accepted) in [(7, true), (8, false)] {
        let mut invocation = f.invocation.clone();
        invocation.action.registry = semantic_registry_digest(f.deployment.body())?;
        let annotations = (0..4)
            .map(|index| {
                let count = if index == 3 { last_count } else { 8 };
                SignedSemanticAnnotationV1::sign(
                    SemanticAnnotationV1 {
                        domain_version: VersionV1,
                        scope: invocation.action.scope.clone(),
                        input: invocation.action.inputs.as_slice()[0].clone(),
                        restrictions: InformationLabel::bottom(),
                        externally_influenced: true,
                        facts: BoundedList::new(facts[..count].to_vec())?,
                        confidence_basis_points: SafeInteger::new(index)?,
                        issued_at_unix_ms: SafeInteger::new(1000)?,
                        valid_until_unix_ms: SafeInteger::new(51000)?,
                    },
                    &f.annotator,
                )
                .map_err(Box::<dyn std::error::Error>::from)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        invocation.annotations = BoundedList::new(annotations)?;
        invocation.action.influence = semantic_annotated_influence(
            f.invocation.action.influence,
            invocation.annotations.as_slice(),
        )?;
        resign_action(&f, &mut invocation)?;
        let result = verify(&f, &invocation, 1001);
        if accepted {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(ContractError::LimitExceeded)));
        }
    }
    Ok(())
}
