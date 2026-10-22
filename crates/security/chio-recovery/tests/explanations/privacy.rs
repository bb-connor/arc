use super::common::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::recovery::{decode_contract, SignedRecoveryExplanationViewV1};
use chio_recovery::evaluate_explanation;
use chio_security_types::recovery::{
    BoundedList, ContractError, EvidenceRef, ExplanationFactStateV1, ExplanationFactTargetV1,
    ExplanationGap, ExplanationViewSummaryV1, IntentDigest, NonEmptyBoundedList, ObservationId,
    RecoverySnapshotV1, SafeInteger, TemplateId,
};
use chio_security_types::InformationLabel;

#[test]
fn hidden_membership_candidates_costs_and_deadlines_have_identical_public_signatures() -> Result {
    let baseline = Fixture::new()?;
    let (expected, baseline_report) = baseline.payloads()?;
    let expected_signed = canonical_json_bytes(&SignedRecoveryExplanationViewV1::sign(
        expected.clone(),
        &baseline.key,
    )?)?;
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
        assert!(!text.contains(secret), "public view names {secret}");
    }
    for world in 0..64_u64 {
        let mut f = Fixture::new()?;
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        let mut hidden = f.fact(0)?;
        hidden.id = ObservationId::new("secret-group-member")?;
        hidden.object = EvidenceRef::new(if world & 1 == 0 {
            "hidden:member"
        } else {
            "hidden:nonmember"
        })?;
        hidden.label = private()?;
        hidden.expires_at_unix_ms = SafeInteger::new(OBSERVED_AT + 1 + world)?;
        hidden.state = ExplanationFactStateV1::Known {
            version: SafeInteger::new(world + 1)?,
            evidence: EvidenceRef::new("secret:low-entropy")?,
            satisfied: world & 1 == 0,
        };
        facts.push(hidden);
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut templates = f.registry.templates.as_slice().to_vec();
        for index in 0..(world % 16) {
            let mut hidden = f.template()?;
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
            expected_signed,
            "hidden world {world}"
        );
        assert_ne!(report.snapshot_digest, baseline_report.snapshot_digest);
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
    assert!(expected.projection.candidates.as_slice().is_empty());
    for index in 0..4_usize {
        f.mutate_fact(index, |fact| {
            fact.label = InformationLabel::Top;
            fact.state = ExplanationFactStateV1::Gap {
                reason: ExplanationGap::Unavailable,
            };
        })?;
    }
    f.snapshot.expires_at_unix_ms = SafeInteger::new(OBSERVED_AT + 2)?;
    f.snapshot.intent_digest = IntentDigest::from_bytes([44; 32]);
    let intent = f.snapshot.intent_digest;
    for index in 0..2_usize {
        f.mutate_fact(index, |fact| {
            fact.target = ExplanationFactTargetV1::Intent { intent }
        })?;
    }
    let (second, report) = f.payloads()?;
    assert_eq!(expected, second);
    assert_ne!(first.snapshot_digest, report.snapshot_digest);
    assert_eq!(expected.expires_at_unix_ms.get(), VALIDITY_CEILING);
    assert_eq!(report.expires_at_unix_ms.get(), OBSERVED_AT + 2);
    Ok(())
}

#[test]
fn visible_view_expiry_is_bounded_by_the_snapshot_and_visible_facts() -> Result {
    let mut f = Fixture::new()?;
    assert_eq!(f.payloads()?.0.expires_at_unix_ms.get(), EXPIRES_AT);
    let short = SafeInteger::new(OBSERVED_AT + 500)?;
    f.mutate_fact(2, |fact| fact.expires_at_unix_ms = short)?;
    assert_eq!(f.payloads()?.0.expires_at_unix_ms.get(), OBSERVED_AT + 500);
    let mut hidden = Fixture::new()?;
    let mut secret = hidden.fact(0)?;
    secret.id = ObservationId::new("secret-deadline")?;
    secret.label = private()?;
    secret.expires_at_unix_ms = SafeInteger::new(OBSERVED_AT + 1)?;
    let mut facts = hidden.snapshot.observations.as_slice().to_vec();
    facts.push(secret);
    hidden.snapshot.observations = BoundedList::new(facts)?;
    let (view, report) = hidden.payloads()?;
    assert_eq!(view.expires_at_unix_ms.get(), EXPIRES_AT);
    assert_eq!(report.expires_at_unix_ms.get(), OBSERVED_AT + 1);
    let mut ceiling = Fixture::new()?;
    ceiling.snapshot.observed_at_unix_ms = SafeInteger::new(VALIDITY_CEILING)?;
    ceiling.snapshot.expires_at_unix_ms = SafeInteger::new(VALIDITY_CEILING + 1)?;
    let late = SafeInteger::new(VALIDITY_CEILING + 1)?;
    for index in 0..4_usize {
        ceiling.mutate_fact(index, |fact| fact.expires_at_unix_ms = late)?;
    }
    assert_eq!(ceiling.payloads().err(), Some(ContractError::InvalidState));
    Ok(())
}

#[test]
fn hidden_full_search_exhaustion_cannot_exhaust_an_authorized_projection() -> Result {
    let mut f = Fixture::new()?;
    f.limits.work = SafeInteger::new(256)?;
    let expected = f.payloads()?.0;
    assert_eq!(
        expected.projection.summary,
        ExplanationViewSummaryV1::AlternativesUnderSnapshot
    );
    let mut hidden = f.template()?;
    hidden.classification = private()?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    for i in 0..15 {
        hidden.template_id = TemplateId::new(&format!("hidden:{i:02}"))?;
        templates.push(hidden.clone());
    }
    f.registry.templates = BoundedList::new(templates)?;
    let full = evaluate_explanation(&f.snapshot, &f.registry, {
        let mut halved = f.limits;
        halved.work = SafeInteger::new(128)?;
        halved
    })?;
    assert!(
        !full.complete,
        "the hidden registry must exhaust the full search"
    );
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
    let value = serde_json::to_value(&f.snapshot)?;
    assert!(decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&value)?).is_ok());
    let mut oversized = value.clone();
    oversized["observations"] =
        serde_json::Value::Array(vec![value["observations"][0].clone(); 33]);
    assert_eq!(
        decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&oversized)?).err(),
        Some(ContractError::Malformed)
    );
    let mut surprise = value.clone();
    surprise["surprise"] = serde_json::json!(true);
    assert_eq!(
        decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&surprise)?).err(),
        Some(ContractError::Malformed)
    );
    let mut unsafe_time = value;
    unsafe_time["observed_at_unix_ms"] = serde_json::json!(9_007_199_254_740_992_u64);
    assert_eq!(
        decode_contract::<RecoverySnapshotV1>(&canonical_json_bytes(&unsafe_time)?).err(),
        Some(ContractError::UnsafeInteger)
    );
    Ok(())
}

#[test]
fn secret_disclosure_constraints_cannot_influence_public_ranking() -> Result {
    let mut f = Fixture::new()?;
    let expected = f.payloads()?.0;
    let mut hidden = f.template()?;
    hidden.template_id = TemplateId::new("secret-constraint")?;
    hidden.disclosure_label = private()?;
    hidden.cost.budget_units = SafeInteger::ZERO;
    let mut templates = f.registry.templates.as_slice().to_vec();
    templates.push(hidden);
    f.registry.templates = BoundedList::new(templates)?;
    assert_eq!(f.payloads()?.0, expected);
    let evaluated = evaluate_explanation(&f.snapshot, &f.registry, f.limits)?;
    assert!(!evaluated
        .classification
        .flows_to(&InformationLabel::bottom()));
    Ok(())
}
