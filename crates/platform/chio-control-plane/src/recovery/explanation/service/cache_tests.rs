use super::*;
use chio_security_types::flow::PrincipalId;
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native_inputs(
    context_label: InformationLabel,
) -> TestResult<(RecoverySnapshotV1, RecoveryRemedyRegistryV1)> {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../spec/vectors/recovery/v1/explanation-inputs.json"
    ))?;
    let mut snapshot: RecoverySnapshotV1 = serde_json::from_value(data["snapshot"].clone())?;
    let mut registry: RecoveryRemedyRegistryV1 = serde_json::from_value(data["registry"].clone())?;
    snapshot.context_label = context_label.clone();
    let facts = snapshot
        .observations
        .as_slice()
        .iter()
        .cloned()
        .map(|mut fact| {
            fact.label = context_label.clone();
            if let ExplanationFactStateV1::Known {
                evidence,
                satisfied,
                ..
            } = fact.state
            {
                fact.state = ExplanationFactStateV1::FreshnessQualified {
                    evidence,
                    satisfied,
                };
            }
            fact
        })
        .collect();
    snapshot.observations = BoundedList::new(facts)?;
    registry.classification = context_label.clone();
    let mut template = registry
        .templates
        .as_slice()
        .first()
        .ok_or("native template missing")?
        .clone();
    template.classification = context_label;
    registry.templates = BoundedList::new(vec![template])?;
    Ok((snapshot, registry))
}

fn service(scope: RecoveryScopeV1) -> TestResult<RecoveryExplanationService> {
    Ok(RecoveryExplanationService::new(
        scope,
        AuthorityDomainId::new("advisory-trust")?,
        IssuerId::new("advisory-issuer")?,
        Arc::new(Ed25519Backend::new(chio_core_types::Keypair::from_seed(
            &[84; 32],
        ))),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?)
}

fn large_native_component(component: usize) -> TestResult<InformationLabel> {
    let mut owners = BTreeMap::new();
    for index in 0..16 {
        let owner = PrincipalId::new(format!("owner:{component}:{index:02}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..123 {
            let prefix = format!("reader:{component}:{index:02}:{reader:03}:");
            readers.insert(PrincipalId::new(format!(
                "{prefix}{}",
                "\"".repeat(256 - prefix.len())
            ))?);
        }
        owners.insert(owner, readers);
    }
    let label = InformationLabel::try_known(owners, BTreeSet::new())?;
    // Every component fits the actual native source-row cell ceiling. Their
    // finite joined observation may be larger without performing a new write.
    let bytes = chio_core::canonical_json_bytes(&label)?.len();
    assert!(bytes > 900_000 && bytes < 1024 * 1024);
    Ok(label)
}

#[test]
fn supported_native_label_joins_preserve_restricted_view_and_retention() -> TestResult {
    let mut large = InformationLabel::bottom();
    for component in 0..3 {
        large = large.join_restrictions(&large_native_component(component)?)?;
    }
    assert!(chio_core::canonical_json_bytes(&large)?.len() > 2 * 1024 * 1024);
    let small = InformationLabel::try_known(
        BTreeMap::from([(
            PrincipalId::new("private-owner")?,
            BTreeSet::from([PrincipalId::new("private-owner")?]),
        )]),
        BTreeSet::new(),
    )?;
    let workflow = WorkflowId::new("retained-workflow")?;
    let actor = ActorId::new("reader")?;
    let clearance = InformationLabel::bottom();
    let (small_snapshot, small_registry) = native_inputs(small)?;
    let (large_snapshot, large_registry) = native_inputs(large)?;
    let service = service(small_snapshot.scope.clone())?;
    let audience = || -> TestResult<ExplanationAudience<'_>> {
        Ok(ExplanationAudience {
            recipient: &actor,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31_000)?,
        })
    };
    let small = service.evaluate(small_snapshot, small_registry, audience()?)?;
    let large = service.evaluate(large_snapshot, large_registry, audience()?)?;
    assert_eq!(small.view.body().projection, large.view.body().projection);
    assert_eq!(
        small.view.body().expires_at_unix_ms,
        large.view.body().expires_at_unix_ms
    );
    let small_reference = small.view.body().report_ref.clone();
    let large_reference = large.view.body().report_ref.clone();
    let expected_large_snapshot = large.snapshot.clone();
    let expected_large_registry = large.registry.clone();
    service.retain_native_graph(&workflow, small, 1000)?;
    service.retain_native_graph(&workflow, large, 1000)?;
    let retained_small = service.retained_native_graph(&workflow, &small_reference, 1000)?;
    let retained_large = service.retained_native_graph(&workflow, &large_reference, 1000)?;
    assert_eq!(retained_large.snapshot, expected_large_snapshot);
    assert_eq!(retained_large.registry, expected_large_registry);
    assert_eq!(
        retained_small.view.body().projection,
        retained_large.view.body().projection
    );
    assert!(retained_large.report.verify_signature()?);
    assert!(retained_large.view.verify_signature()?);
    assert!(!format!("{retained_large:?}").contains("reader:2:"));
    Ok(())
}

#[test]
fn retained_graph_keeps_original_identity_until_the_signed_view_expires() -> TestResult {
    let private = PrincipalId::new("private-owner")?;
    let (snapshot, registry) = native_inputs(InformationLabel::try_known(
        BTreeMap::from([(private.clone(), BTreeSet::from([private]))]),
        BTreeSet::new(),
    )?)?;
    let service = service(snapshot.scope.clone())?;
    let workflow = WorkflowId::new("retained-workflow")?;
    let actor = ActorId::new("reader")?;
    let clearance = InformationLabel::bottom();
    let artifact = service.evaluate(
        snapshot,
        registry,
        ExplanationAudience {
            recipient: &actor,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31_000)?,
        },
    )?;
    let reference = artifact.view.body().report_ref.clone();
    let expected_report = artifact.report.clone();
    let expected_view = artifact.view.clone();
    let deadline = artifact.view.body().expires_at_unix_ms.get();
    let protected_deadline = artifact.report.body().expires_at_unix_ms.get();
    assert!(protected_deadline < deadline);
    service.retain_native_graph(&workflow, artifact, 1000)?;
    let first = service.retained_native_graph(&workflow, &reference, 1000)?;
    let second = service.retained_native_graph(&workflow, &reference, 1001)?;
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first.report, expected_report);
    assert_eq!(first.view, expected_view);
    assert!(service
        .retained_native_graph(&workflow, &reference, protected_deadline)
        .is_ok());
    assert!(service
        .retained_native_graph(&WorkflowId::new("other-workflow")?, &reference, 1000)
        .is_err());
    assert!(service
        .retained_native_graph(&workflow, &ExplanationRef::new("advice:missing")?, 1000)
        .is_err());
    assert!(service
        .retained_native_graph(&workflow, &reference, deadline - 1)
        .is_ok());
    assert!(service
        .retained_native_graph(&workflow, &reference, deadline)
        .is_err());
    let restarted = self::service(service.scope.clone())?;
    assert!(restarted
        .retained_native_graph(&workflow, &reference, 1000)
        .is_err());
    Ok(())
}

fn artifact(
    service: &RecoveryExplanationService,
    actor: &ActorId,
) -> TestResult<ProtectedRecoveryExplanationV1> {
    let (snapshot, registry) = native_inputs(InformationLabel::bottom())?;
    let clearance = InformationLabel::bottom();
    Ok(service.evaluate(
        snapshot,
        registry,
        ExplanationAudience {
            recipient: actor,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31_000)?,
        },
    )?)
}

#[test]
fn cache_capacity_preserves_every_live_reference_and_reclaims_only_expired_entries() -> TestResult {
    let (snapshot, _) = native_inputs(InformationLabel::bottom())?;
    let service = service(snapshot.scope)?;
    let workflow = WorkflowId::new("retained-workflow")?;
    let mut references = Vec::new();
    let mut expiry = None;
    for actor in 0..4 {
        let actor = ActorId::new(&format!("actor:{actor}"))?;
        for _ in 0..8 {
            let artifact = artifact(&service, &actor)?;
            expiry = Some(artifact.view.body().expires_at_unix_ms.get());
            references.push(artifact.view.body().report_ref.clone());
            service.retain_native_graph(&workflow, artifact, 1000)?;
        }
        assert!(matches!(
            service.retain_native_graph(&workflow, artifact(&service, &actor)?, 1000),
            Err(RecoveryRuntimeError::Unavailable)
        ));
    }
    let next = ActorId::new("next-actor")?;
    assert!(matches!(
        service.retain_native_graph(&workflow, artifact(&service, &next)?, 1000),
        Err(RecoveryRuntimeError::Unavailable)
    ));
    for reference in &references {
        assert!(service
            .retained_native_graph(&workflow, reference, 1000)
            .is_ok());
    }
    let expiry = expiry.ok_or("missing expiry")?;
    let (mut snapshot, mut registry) = native_inputs(InformationLabel::bottom())?;
    let duration = snapshot.expires_at_unix_ms.get() - snapshot.observed_at_unix_ms.get();
    snapshot.observed_at_unix_ms = SafeInteger::new(expiry)?;
    snapshot.expires_at_unix_ms = SafeInteger::new(expiry + duration)?;
    let mut facts = snapshot.observations.as_slice().to_vec();
    for fact in &mut facts {
        fact.observed_at_unix_ms = SafeInteger::new(expiry)?;
        fact.expires_at_unix_ms = SafeInteger::new(expiry + duration)?;
    }
    snapshot.observations = BoundedList::new(facts)?;
    registry.classification = snapshot.context_label.clone();
    let clearance = InformationLabel::bottom();
    let next_artifact = service.evaluate(
        snapshot,
        registry,
        ExplanationAudience {
            recipient: &next,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(expiry + duration)?,
        },
    )?;
    service.retain_native_graph(&workflow, next_artifact, expiry)?;
    for reference in &references {
        assert!(service
            .retained_native_graph(&workflow, reference, expiry)
            .is_err());
    }
    Ok(())
}

#[test]
fn a_reference_collision_or_clock_rollback_cannot_replace_the_original_graph() -> TestResult {
    let (snapshot, _) = native_inputs(InformationLabel::bottom())?;
    let service = service(snapshot.scope)?;
    let workflow = WorkflowId::new("retained-workflow")?;
    let original = artifact(&service, &ActorId::new("reader")?)?;
    let reference = original.view.body().report_ref.clone();
    let expected = original.report.clone();
    service.retain_native_graph(&workflow, original.clone(), 1000)?;
    assert!(matches!(
        service.retain_native_graph(&WorkflowId::new("other-workflow")?, original, 1000),
        Err(RecoveryRuntimeError::Unavailable)
    ));
    assert!(service
        .retained_native_graph(&workflow, &reference, 999)
        .is_err());
    assert_eq!(
        service
            .retained_native_graph(&workflow, &reference, 1000)?
            .report,
        expected
    );
    Ok(())
}

#[test]
fn conservative_graph_classification_preserves_restricted_advice_and_original_inputs() -> TestResult
{
    let private = PrincipalId::new("private-owner")?;
    let (snapshot, mut registry) = native_inputs(InformationLabel::try_known(
        BTreeMap::from([(private.clone(), BTreeSet::from([private]))]),
        BTreeSet::new(),
    )?)?;
    let service = service(snapshot.scope.clone())?;
    let mut templates = registry.templates.as_slice().to_vec();
    templates[0].disclosure_label = InformationLabel::Top;
    registry.templates = BoundedList::new(templates)?;
    let actor = ActorId::new("reader")?;
    let clearance = InformationLabel::bottom();
    let artifact = service.evaluate(
        snapshot,
        registry,
        ExplanationAudience {
            recipient: &actor,
            clearance: &clearance,
            validity_ceiling_unix_ms: SafeInteger::new(31_000)?,
        },
    )?;
    assert!(matches!(artifact.classification, InformationLabel::Top));
    let expected = artifact.registry.clone();
    let workflow = WorkflowId::new("retained-workflow")?;
    let reference = artifact.view.body().report_ref.clone();
    service.retain_native_graph(&workflow, artifact, 1000)?;
    let retained = service.retained_native_graph(&workflow, &reference, 1000)?;
    assert_eq!(retained.registry, expected);
    assert!(matches!(retained.classification, InformationLabel::Top));
    Ok(())
}
