use super::common::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::recovery::SignedRecoveryExplanationViewV1;
use chio_recovery::{evaluate_explanation, explanation_view_payload, project_explanation};
use chio_security_types::ports::DestinationId;
use chio_security_types::recovery::{
    BoundedList, ContractError, DeploymentDigest, ExplanationRef, ExplanationViewSummaryV1,
    NonEmptyBoundedList, ObservationId, RecoveryExplanationViewV1, RecoveryTenantId, SafeInteger,
    TemplateId,
};
use chio_security_types::InformationLabel;

#[derive(Clone, Copy)]
enum Damage {
    DuplicateFact,
    InvalidFactInterval,
    ForeignFactScope,
    DuplicateTemplate,
    MissingDependency,
    ExcessiveCost,
    WrongDestination,
}

fn damaged_graphs() -> Result<Vec<(Fixture, ContractError)>> {
    let mut cases = Vec::new();
    for damage in [
        Damage::DuplicateFact,
        Damage::InvalidFactInterval,
        Damage::ForeignFactScope,
        Damage::DuplicateTemplate,
        Damage::MissingDependency,
        Damage::ExcessiveCost,
        Damage::WrongDestination,
    ] {
        let mut f = Fixture::new()?;
        let mut fact = f.fact(0)?;
        fact.id = ObservationId::new("hidden-fact")?;
        fact.label = private()?;
        let mut template = f.template()?;
        template.template_id = TemplateId::new("hidden-remedy")?;
        template.classification = private()?;
        let error = match damage {
            Damage::DuplicateFact => {
                fact.id = ObservationId::new("capability")?;
                ContractError::DuplicateIdentity
            }
            Damage::InvalidFactInterval => {
                fact.expires_at_unix_ms = fact.observed_at_unix_ms;
                ContractError::InvalidState
            }
            Damage::ForeignFactScope => {
                fact.scope.tenant_id = RecoveryTenantId::new("hidden-tenant")?;
                ContractError::BindingMismatch
            }
            Damage::DuplicateTemplate => {
                template.template_id = TemplateId::new("public-remedy")?;
                ContractError::DuplicateIdentity
            }
            Damage::MissingDependency => {
                template.requirements =
                    NonEmptyBoundedList::new(vec![ObservationId::new("missing")?])?;
                ContractError::MissingDependency
            }
            Damage::ExcessiveCost => {
                template.cost.approvals = SafeInteger::new(9)?;
                ContractError::LimitExceeded
            }
            Damage::WrongDestination => {
                template.destination = DestinationId::new("wrong-destination")?;
                ContractError::BindingMismatch
            }
        };
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        facts.insert(0, fact);
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut templates = f.registry.templates.as_slice().to_vec();
        templates.insert(0, template);
        f.registry.templates = BoundedList::new(templates)?;
        cases.push((f, error));
    }
    Ok(cases)
}

fn view(f: &Fixture) -> Result<RecoveryExplanationViewV1> {
    Ok(explanation_view_payload(
        &f.snapshot,
        &f.registry,
        f.limits,
        &f.audience()?,
        &f.domain,
        &f.issuer,
        ExplanationRef::new("advice:synthetic")?,
    )?)
}

fn signed_view(f: &Fixture) -> Result<Vec<u8>> {
    Ok(canonical_json_bytes(
        &SignedRecoveryExplanationViewV1::sign(view(f)?, &f.key)?,
    )?)
}

#[test]
fn invalid_hidden_graphs_preserve_visible_projection_and_signed_view() -> Result {
    let baseline = Fixture::new()?;
    let expected = view(&baseline)?;
    let expected_signed = signed_view(&baseline)?;
    for (f, error) in damaged_graphs()? {
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, f.limits).err(),
            Some(error)
        );
        assert_eq!(f.payloads().err(), Some(error));
        assert_eq!(
            project_explanation(&f.snapshot, &f.registry, f.limits, &f.clearance)?,
            expected.projection
        );
        assert_eq!(view(&f)?, expected);
        assert_eq!(signed_view(&f)?, expected_signed);
    }
    Ok(())
}

#[test]
fn invalid_hidden_graphs_preserve_opaque_projection_and_signed_view() -> Result {
    for (context, clearance) in [
        (private()?, InformationLabel::bottom()),
        (InformationLabel::Top, InformationLabel::bottom()),
        (InformationLabel::bottom(), InformationLabel::Top),
    ] {
        let mut baseline = Fixture::new()?;
        baseline.snapshot.context_label = context.clone();
        baseline.clearance = clearance.clone();
        let expected = view(&baseline)?;
        assert_eq!(
            expected.projection.summary,
            ExplanationViewSummaryV1::AuthorizedInspectionRequired
        );
        let expected_signed = signed_view(&baseline)?;
        for (mut f, error) in damaged_graphs()? {
            f.snapshot.context_label = context.clone();
            f.clearance = clearance.clone();
            assert_eq!(f.payloads().err(), Some(error));
            assert_eq!(
                project_explanation(&f.snapshot, &f.registry, f.limits, &f.clearance)?,
                expected.projection
            );
            assert_eq!(view(&f)?, expected);
            assert_eq!(signed_view(&f)?, expected_signed);
        }
    }
    Ok(())
}

#[test]
fn visible_invalid_graphs_keep_exact_validation_refusals() -> Result {
    let baseline = Fixture::new()?;
    let expected = view(&baseline)?.projection;
    for (mut f, error) in damaged_graphs()? {
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        for fact in &mut facts {
            fact.label = InformationLabel::bottom();
        }
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut templates = f.registry.templates.as_slice().to_vec();
        for template in &mut templates {
            template.classification = InformationLabel::bottom();
        }
        f.registry.templates = BoundedList::new(templates)?;
        assert_eq!(f.payloads().err(), Some(error));
        let projected = project_explanation(&f.snapshot, &f.registry, f.limits, &f.clearance);
        if error == ContractError::MissingDependency {
            assert_eq!(projected?, expected);
        } else {
            assert_eq!(projected.err(), Some(error));
        }
    }
    Ok(())
}

#[test]
fn undisclosed_dependencies_do_not_reveal_hidden_fact_membership() -> Result {
    let mut f = Fixture::new()?;
    let expected = view(&f)?;
    let mut template = f.template()?;
    template.template_id = TemplateId::new("needs-undisclosed-fact")?;
    let mut requirements = template.requirements.as_slice().to_vec();
    requirements.push(ObservationId::new("undisclosed")?);
    template.requirements = NonEmptyBoundedList::new(requirements)?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    templates.push(template);
    f.registry.templates = BoundedList::new(templates)?;
    assert_eq!(f.payloads().err(), Some(ContractError::MissingDependency));
    assert_eq!(view(&f)?, expected);
    let mut hidden = f.fact(0)?;
    hidden.id = ObservationId::new("undisclosed")?;
    hidden.label = private()?;
    let mut facts = f.snapshot.observations.as_slice().to_vec();
    facts.push(hidden);
    f.snapshot.observations = BoundedList::new(facts)?;
    assert_eq!(view(&f)?, expected);
    assert!(f.payloads().is_ok());
    Ok(())
}

#[test]
fn opaque_contexts_hide_invalid_snapshot_and_registry_metadata() -> Result {
    let mut f = Fixture::new()?;
    f.snapshot.context_label = private()?;
    let expected = signed_view(&f)?;
    f.snapshot.expires_at_unix_ms = f.snapshot.observed_at_unix_ms;
    assert_eq!(f.payloads().err(), Some(ContractError::InvalidState));
    assert_eq!(signed_view(&f)?, expected);
    f.snapshot.expires_at_unix_ms = SafeInteger::new(EXPIRES_AT)?;
    f.registry.deployment_digest = DeploymentDigest::from_bytes([77; 32]);
    assert_eq!(f.payloads().err(), Some(ContractError::BindingMismatch));
    assert_eq!(signed_view(&f)?, expected);
    Ok(())
}
