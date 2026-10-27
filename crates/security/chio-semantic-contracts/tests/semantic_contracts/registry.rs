use super::*;

#[test]
fn registry_requires_the_callers_exact_scope() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    f.compiled()?;
    for field in ["authority_domain", "tenant_id", "process_id"] {
        let mut value = serde_json::to_value(&f.scope)?;
        value[field] = serde_json::json!("foreign");
        let expected: RecoveryScopeV1 = serde_json::from_value(value)?;
        assert_eq!(
            f.compile_with(&expected, core::slice::from_ref(&f.exposed))
                .err(),
            Some(ContractError::BindingMismatch)
        );
    }
    Ok(())
}

#[test]
fn a_valid_operator_signature_cannot_reuse_a_package_publisher_role() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    f.compiled()?;
    let deployment = SignedSemanticDeploymentV1::sign(f.deployment.body().clone(), &f.publisher)?;
    assert_eq!(
        compile_semantic_registry(
            &deployment,
            &f.scope,
            core::slice::from_ref(&f.package),
            &f.publisher.public_key(),
            &[f.publisher.public_key()],
            core::slice::from_ref(&f.exposed),
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
        )
        .err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn signed_package_implementation_must_match_the_route_and_host_manifest() -> TestResult {
    let mut f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    f.compiled()?;
    f.rebind_operation(|operation| {
        operation.implementation = CanonicalPayloadDigest::from_bytes([91; 32])
    })?;
    assert_eq!(f.compiled().err(), Some(ContractError::BindingMismatch));
    Ok(())
}

#[test]
fn registry_compilation_accepts_sixteen_operations_with_sixteen_fields_and_selectors() -> TestResult
{
    let f = semantic_fixture(
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
        &f.scope,
        &[package],
        &f.operator.public_key(),
        &[f.publisher.public_key()],
        &exposed,
        &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
    )?;
    assert!(registry.resolve("server-a", "tool-15").is_ok());
    Ok(())
}

#[test]
fn signed_packages_cannot_install_tenant_authority_or_missing_coverage() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert_eq!(
        (compile_semantic_registry(
            &f.deployment,
            &f.scope,
            core::slice::from_ref(&f.package),
            &f.publisher.public_key(),
            &[f.publisher.public_key()],
            core::slice::from_ref(&f.exposed),
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::BindingMismatch)
    );
    assert_eq!(
        (compile_semantic_registry(
            &f.deployment,
            &f.scope,
            core::slice::from_ref(&f.package),
            &f.operator.public_key(),
            &[f.publisher.public_key()],
            &[],
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::BindingMismatch)
    );
    compile_bound_manifest(&f, core::slice::from_ref(&f.exposed))??;
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
        assert_eq!(
            compile_bound_manifest(&f, &[bad])?.err(),
            Some(ContractError::BindingMismatch)
        );
    }
    Ok(())
}

#[test]
fn reviewed_package_override_preserves_operator_selector_ceiling() -> TestResult {
    let mut f = semantic_fixture(
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
    assert_eq!(
        (verify(&f, &invocation, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn operator_bound_manifest_must_expose_the_routed_tool() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    compile_bound_manifest(&f, core::slice::from_ref(&f.exposed))??;
    let mut missing = f.exposed.clone();
    missing.tool = ProtectedText::new("different-tool")?;
    assert_eq!(
        compile_bound_manifest(&f, &[missing])?.err(),
        Some(ContractError::UnsupportedProfile)
    );
    Ok(())
}

#[test]
fn operator_bound_manifest_must_match_implementation_and_schemas() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    compile_bound_manifest(&f, core::slice::from_ref(&f.exposed))??;
    for field in 0..3 {
        let mut changed = f.exposed.clone();
        let foreign = CanonicalPayloadDigest::from_bytes([91; 32]);
        match field {
            0 => changed.implementation = foreign,
            1 => changed.input_schema = foreign,
            _ => changed.output_schema = foreign,
        }
        assert_eq!(
            compile_bound_manifest(&f, &[changed])?.err(),
            Some(ContractError::BindingMismatch)
        );
    }
    Ok(())
}

fn compile_bound_manifest(
    fixture: &SemanticFixture,
    exposed: &[ExposedSemanticToolV1],
) -> TestResult<Result<CompiledSemanticRegistryV1, ContractError>> {
    let mut body = fixture.deployment.body().clone();
    body.exposure_binding = semantic_content_digest(&exposed)?;
    let deployment = SignedSemanticDeploymentV1::sign(body, &fixture.operator)?;
    Ok(compile_semantic_registry(
        &deployment,
        &fixture.scope,
        core::slice::from_ref(&fixture.package),
        &fixture.operator.public_key(),
        &[fixture.publisher.public_key()],
        exposed,
        &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
    ))
}
