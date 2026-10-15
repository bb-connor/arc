use super::*;

#[test]
fn selected_annotator_restrictions_cannot_be_omitted_on_read_operations() -> TestResult {
    let mut f = semantic_fixture(
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
    assert_eq!(
        (verify(&f, &restricted, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    assert!(matches!(
        verify(&f, &f.invocation, 1001),
        Err(ContractError::MissingDependency)
    ));
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
fn substitution_matrix_refuses_changed_exact_actions_and_acl_uncertainty() -> TestResult {
    let f = semantic_fixture(
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
        assert_eq!(
            (verify(&f, &bad, 1001)).err(),
            Some(ContractError::BindingMismatch)
        );
    }
    assert_eq!(
        (verify(&f, &f.invocation, 51_000)).err(),
        Some(ContractError::InvalidState)
    );
    Ok(())
}

#[test]
fn annotator_confidence_cannot_create_facts_or_endorsement() -> TestResult {
    let mut f = semantic_fixture(
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
        annotation.clone(),
        &f.annotator,
    )?])?;
    assert_eq!(
        (verify(&f, &bad, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    let mut neutral = annotation;
    neutral.facts = BoundedList::new(vec![])?;
    let mut accepted = f.invocation.clone();
    accepted.annotations = BoundedList::new(vec![SignedSemanticAnnotationV1::sign(
        neutral,
        &f.annotator,
    )?])?;
    accepted.action.influence = semantic_annotated_influence(
        f.invocation.action.influence,
        accepted.annotations.as_slice(),
    )?;
    resign_action(&f, &mut accepted)?;
    verify(&f, &accepted, 1001)?;
    let mut body = only(accepted.endorsements.as_slice())?.body().clone();
    body.target = SemanticEndorsementTargetV1::PersistentArtifact {
        artifact: ArtifactVersionId::from_bytes([0; 32]),
    };
    let mut bad = accepted;
    bad.endorsements = BoundedList::new(vec![SignedScopedEndorsementV1::sign(body, &f.endorser)?])?;
    assert_eq!(
        (verify(&f, &bad, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn signed_audience_scope_and_half_open_validity_bind_the_invocation() -> TestResult {
    let mut f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    verify(&f, &f.invocation, NOW)?;
    verify(&f, &f.invocation, VALID_UNTIL - 1)?;
    for now in [NOW - 1, VALID_UNTIL, VALID_UNTIL + 1] {
        assert_eq!(
            verify(&f, &f.invocation, now).err(),
            Some(ContractError::InvalidState)
        );
    }
    let foreign_tenant = RecoveryTenantId::new("foreign-tenant")?;
    f.rebind_audience(|audience| audience.scope.tenant_id = foreign_tenant)?;
    assert_eq!(
        verify(&f, &f.invocation, VERIFY_AT).err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn complete_pagination_and_single_strong_provider_version_are_required() -> TestResult {
    let f = semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    for version in ["*", "W/\"v1\"", "\"a\",\"b\"", "\"a\r\nb\"", "\"\""] {
        assert_eq!(
            (validate_semantic_provider_version(version)).err(),
            Some(ContractError::BindingMismatch)
        );
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
        assert_eq!(
            (verify(&f, &invocation, 1001)).err(),
            Some(ContractError::BindingMismatch)
        );
    }
    Ok(())
}

#[test]
fn annotation_restrictions_and_influence_are_bound_without_creating_authority() -> TestResult {
    let mut f = semantic_fixture(
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
    assert_eq!(
        (verify(&f, &invocation, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    invocation.action.influence = semantic_annotated_influence(
        f.invocation.action.influence,
        invocation.annotations.as_slice(),
    )?;
    resign_action(&f, &mut invocation)?;
    assert!(verify(&f, &invocation, 1001).is_ok());
    invocation.annotations = BoundedList::new(vec![])?;
    assert_eq!(
        (verify(&f, &invocation, 1001)).err(),
        Some(ContractError::MissingDependency)
    );
    let model = semantic_observed_influence(
        f.invocation.action.influence,
        Some(CanonicalPayloadDigest::from_bytes([90; 32])),
    )?;
    assert_ne!(model, f.invocation.action.influence);
    assert_eq!(semantic_observed_influence(model, None)?, model);
    Ok(())
}

#[test]
fn transform_and_prerequisite_claims_bind_action_scope_output_and_role() -> TestResult {
    let mut f = semantic_fixture(
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
        assert_eq!(
            (verify(&f, &bad, 1001)).err(),
            Some(ContractError::BindingMismatch)
        );
    }
    let mut bad = invocation.clone();
    let mut proof = proof;
    proof.action = SemanticActionDigest::from_bytes([7; 32]);
    bad.prerequisites = BoundedList::new(vec![SignedSemanticPrerequisiteV1::sign(
        proof,
        &f.prerequisite,
    )?])?;
    assert_eq!(
        (verify(&f, &bad, 1001)).err(),
        Some(ContractError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn aggregate_facts_share_a_limit_across_selected_annotation_and_endorsement_roles() -> TestResult {
    let mut f = semantic_fixture(
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
