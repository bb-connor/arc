use super::*;

#[test]
fn withheld_completion_status_requires_an_explicit_contract_audience() -> TestResult {
    let mut f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
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
fn absent_withheld_status_preserves_signed_contract_bytes_and_explicit_null_is_refused(
) -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::SupportRead,
    )?;
    let mut value = serde_json::to_value(&f.package.body().operations.as_slice()[0])?;
    value
        .as_object_mut()
        .ok_or("operation contract must be an object")?
        .remove("withheld_status");
    let without_status: SemanticOperationContractV1 = serde_json::from_value(value.clone())?;
    assert!(without_status.withheld_status.is_none());
    assert_eq!(
        chio_core_types::canonical_json_bytes(&without_status)?,
        chio_core_types::canonical_json_bytes(&value)?,
    );
    value
        .as_object_mut()
        .ok_or("operation contract must be an object")?
        .insert("withheld_status".into(), serde_json::Value::Null);
    assert_eq!(
        (decode_contract::<SemanticOperationContractV1>(&chio_core_types::canonical_json_bytes(
            &value
        )?))
        .err(),
        Some(ContractError::Malformed)
    );
    Ok(())
}

#[test]
fn withheld_read_status_cannot_be_classified_below_the_verified_provider_audience() -> TestResult {
    let mut f = semantic_fixture(
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
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    assert!(verify(&f, &f.invocation, 1001).is_ok());
    assert!(f.invocation.action.externally_influenced);
    let mut missing = f.invocation.clone();
    missing.endorsements = BoundedList::new(vec![])?;
    assert_eq!(
        (verify(&f, &missing, 1001)).err(),
        Some(ContractError::MissingDependency)
    );
    Ok(())
}

#[test]
fn projection_removes_exact_fields_without_mutating_source_or_influence() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::FieldProjection,
    )?;
    let fields = f.package.body().operations.as_slice()[0]
        .projection_fields
        .as_slice();
    let output = project_semantic_fields(
        &f.payload,
        fields,
        &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
    )?;
    assert_eq!(output.fields.as_slice().len(), 1);
    assert!(!chio_core_types::canonical_json_string(&output)?.contains("private-canary"));
    assert_ne!(
        semantic_content_digest(&output)?,
        semantic_content_digest(&f.payload)?
    );
    assert_eq!(f.payload.fields.as_slice().len(), 2);
    assert_eq!(
        (project_semantic_fields(
            &f.payload,
            &[SemanticFieldId::new("missing")?],
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?
        ))
        .err(),
        Some(ContractError::MissingDependency)
    );
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
    let mut f = semantic_fixture(label.clone(), SemanticOperationKindV1::IssueWrite)?;
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
    assert_eq!(
        (verify(&f, &invocation, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    invocation.action.source_label = InformationLabel::bottom();
    resign_action(&f, &mut invocation)?;
    assert_eq!(
        (verify(&f, &invocation, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    assert!(!label.flows_to(&InformationLabel::bottom()));
    Ok(())
}
