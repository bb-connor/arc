use super::common::*;
use chio_core_types::{canonical_json_bytes, recovery::*};
use chio_security_types::{recovery::*, InformationLabel};

#[test]
fn hidden_membership_candidates_costs_and_deadlines_have_identical_public_signatures() -> Result {
    let baseline = Fixture::new()?;
    let expected = baseline.payloads()?.0;
    let expected_signed = canonical_json_bytes(&SignedRecoveryExplanationViewV1::sign(
        expected.clone(),
        &baseline.key,
    )?)?;
    for world in 0..64 {
        let mut f = Fixture::new()?;
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        let mut hidden = facts[0].clone();
        hidden.id = ObservationId::new("secret-group-member")?;
        hidden.object = EvidenceRef::new(if world & 1 == 0 {
            "hidden:member"
        } else {
            "hidden:nonmember"
        })?;
        hidden.label = private()?;
        hidden.expires_at_unix_ms = SafeInteger::new(1001 + world)?;
        hidden.state = ExplanationFactStateV1::Known {
            version: SafeInteger::new(world + 1)?,
            evidence: EvidenceRef::new("secret:low-entropy")?,
            satisfied: world & 1 == 0,
        };
        facts.push(hidden);
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut templates = f.registry.templates.as_slice().to_vec();
        for index in 0..(world % 16) {
            let mut hidden = templates[0].clone();
            hidden.template_id = TemplateId::new(&format!("private:{index}"))?;
            hidden.classification = private()?;
            hidden.cost.budget_units = SafeInteger::new(world)?;
            hidden.satisfies_task = world & 2 == 0;
            hidden.requirements = NonEmptyBoundedList::new(vec![
                ObservationId::new("secret-group-member")?,
                ObservationId::new("policy")?,
                ObservationId::new("recipient")?,
                ObservationId::new("coverage")?,
            ])?;
            templates.push(hidden);
        }
        f.registry.templates = BoundedList::new(templates)?;
        f.registry.classification = private()?;
        let (view, report) = f.payloads()?;
        assert_eq!(view, expected, "hidden world {world}");
        assert_eq!(
            canonical_json_bytes(&SignedRecoveryExplanationViewV1::sign(view, &f.key)?)?,
            expected_signed
        );
        assert_ne!(
            report.snapshot_digest,
            baseline.payloads()?.1.snapshot_digest
        );
        let text = String::from_utf8(expected_signed.clone())?;
        for secret in [
            "secret-group",
            "low-entropy",
            "snapshot_digest",
            "evaluation_digest",
            "projection_digest",
            "registry_digest",
            "private:",
        ] {
            assert!(!text.contains(secret));
        }
    }
    Ok(())
}
#[test]
fn restricted_views_do_not_commit_to_transitive_hidden_graphs_or_their_expiry() -> Result {
    let mut f = Fixture::new()?;
    f.snapshot.context_label = private()?;
    let (expected, first) = f.payloads()?;
    assert_eq!(
        expected.projection.summary,
        ExplanationViewSummaryV1::AuthorizedInspectionRequired
    );
    for index in 0..4 {
        f.mutate_fact(index, |fact| {
            fact.label = InformationLabel::Top;
            fact.state = ExplanationFactStateV1::Gap {
                reason: ExplanationGap::Unavailable,
            };
        })?;
    }
    f.snapshot.expires_at_unix_ms = SafeInteger::new(1002)?;
    f.snapshot.intent_digest = IntentDigest::from_bytes([44; 32]);
    let intent = f.snapshot.intent_digest;
    for index in 0..2 {
        f.mutate_fact(index, |fact| {
            fact.target = ExplanationFactTargetV1::Intent { intent }
        })?;
    }
    let (second, report) = f.payloads()?;
    assert_eq!(expected, second);
    assert_ne!(first.snapshot_digest, report.snapshot_digest);
    assert_eq!(expected.expires_at_unix_ms.get(), 31000);
    Ok(())
}
#[test]
fn hidden_full_search_exhaustion_cannot_exhaust_an_authorized_projection() -> Result {
    let mut f = Fixture::new()?;
    f.limits.work = SafeInteger::new(256)?;
    let expected = f.payloads()?.0;
    let mut hidden = f.registry.templates.as_slice()[0].clone();
    hidden.classification = private()?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    for i in 0..15 {
        hidden.template_id = TemplateId::new(&format!("hidden:{i:02}"))?;
        templates.push(hidden.clone());
    }
    f.registry.templates = BoundedList::new(templates)?;
    assert_eq!(f.payloads()?.0, expected);
    Ok(())
}
#[test]
fn debug_and_wire_bounds_never_expose_classified_objects() -> Result {
    let f = Fixture::new()?;
    assert_eq!(
        format!("{:?}", f.snapshot),
        "RecoverySnapshotV1([redacted])"
    );
    let mut value = serde_json::to_value(&f.snapshot)?;
    value["observations"] = serde_json::Value::Array(vec![value["observations"][0].clone(); 33]);
    assert!(decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&value)?).is_err());
    let mut value = serde_json::to_value(&f.snapshot)?;
    value["surprise"] = serde_json::json!(true);
    assert!(decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&value)?).is_err());
    let mut value = serde_json::to_value(&f.snapshot)?;
    value["observed_at_unix_ms"] = serde_json::json!(9007199254740992u64);
    assert!(decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&value)?).is_err());
    Ok(())
}

#[test]
fn secret_disclosure_constraints_cannot_influence_public_ranking_even_with_public_candidate_label(
) -> Result {
    let mut f = Fixture::new()?;
    let expected = f.payloads()?.0;
    let mut hidden = f.registry.templates.as_slice()[0].clone();
    hidden.template_id = TemplateId::new("secret-constraint")?;
    hidden.disclosure_label = private()?;
    hidden.cost.budget_units = SafeInteger::ZERO;
    let mut templates = f.registry.templates.as_slice().to_vec();
    templates.push(hidden);
    f.registry.templates = BoundedList::new(templates)?;
    assert_eq!(f.payloads()?.0, expected);
    let evaluated = chio_recovery::evaluate_explanation(&f.snapshot, &f.registry, f.limits)?;
    assert!(!evaluated
        .classification
        .flows_to(&InformationLabel::bottom()));
    Ok(())
}
