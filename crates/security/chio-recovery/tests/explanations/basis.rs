use super::common::*;
use chio_recovery::*;
use chio_security_types::{recovery::*, InformationLabel};

#[test]
fn mixed_versions_and_all_truth_assignments_preserve_fail_closed_meaning() -> Result {
    for bits in 0..16 {
        let mut f = Fixture::new()?;
        for index in 0..4 {
            f.mutate_fact(index, |fact| {
                if let ExplanationFactStateV1::Known { satisfied, .. } = &mut fact.state {
                    *satisfied = bits & (1 << index) != 0;
                }
            })?;
        }
        let evaluation = evaluate_explanation(&f.snapshot, &f.registry, f.limits)?;
        let expected = if bits & 1 == 0 {
            ExplanationAssessmentV1::BlockedByCapability
        } else if bits & 6 != 6 {
            ExplanationAssessmentV1::NoRegisteredRemedy
        } else if bits & 8 == 0 {
            ExplanationAssessmentV1::RequiresExactApproval
        } else {
            ExplanationAssessmentV1::FeasibleUnderSnapshot
        };
        assert!(evaluation.complete);
        assert_eq!(evaluation.assessment, expected, "truth assignment {bits}");
    }
    Ok(())
}

#[test]
fn freshness_qualified_facts_require_live_intervals_and_never_synthesize_versions() -> Result {
    let mut f = Fixture::new()?;
    for index in 0..f.snapshot.observations.as_slice().len() {
        let state: ExplanationFactStateV1 = serde_json::from_value(serde_json::json!({
            "kind": "freshness_qualified",
            "evidence": format!("native:{index}"),
            "satisfied": true
        }))?;
        assert!(serde_json::to_value(&state)?.get("version").is_none());
        f.mutate_fact(index, |fact| fact.state = state)?;
    }
    assert_eq!(
        evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
        ExplanationAssessmentV1::FeasibleUnderSnapshot,
    );
    for index in 0..f.snapshot.observations.as_slice().len() {
        let mut expired = Fixture::new()?;
        expired.snapshot = f.snapshot.clone();
        let deadline = expired.snapshot.observed_at_unix_ms;
        expired.mutate_fact(index, |fact| {
            fact.observed_at_unix_ms = SafeInteger::ZERO;
            fact.expires_at_unix_ms = deadline;
        })?;
        assert_eq!(
            evaluate_explanation(&expired.snapshot, &expired.registry, expired.limits)?.assessment,
            ExplanationAssessmentV1::NeedsFreshEvidence,
        );
    }
    let malformed = serde_json::json!({
        "kind": "freshness_qualified", "evidence": "native:versionless",
        "satisfied": true, "version": 1
    });
    assert!(serde_json::from_value::<ExplanationFactStateV1>(malformed).is_err());
    Ok(())
}
#[test]
fn gaps_unverified_and_expired_positive_facts_never_become_feasible() -> Result {
    for index in 0..4 {
        for mutation in 0..3 {
            let mut f = Fixture::new()?;
            let expired = SafeInteger::new(1000)?;
            f.mutate_fact(index, |fact| match mutation {
                0 => {
                    fact.state = ExplanationFactStateV1::Gap {
                        reason: ExplanationGap::NotConsulted,
                    }
                }
                1 => fact.integrity = ExplanationIntegrity::Unverified,
                _ => {
                    fact.observed_at_unix_ms = SafeInteger::ZERO;
                    fact.expires_at_unix_ms = expired;
                }
            })?;
            assert_eq!(
                evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
                ExplanationAssessmentV1::NeedsFreshEvidence
            );
        }
    }
    Ok(())
}
#[test]
fn no_integrity_endorsement_is_inferred_from_native_provenance() -> Result {
    let mut f = Fixture::new()?;
    f.mutate_template(|template| template.requires_integrity = true)?;
    assert_eq!(
        evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
        ExplanationAssessmentV1::NeedsFreshEvidence
    );
    Ok(())
}
#[test]
fn unresolved_and_spent_effects_cannot_plan_a_replacement() -> Result {
    let mut f = Fixture::new()?;
    for state in [
        "admission_unresolved",
        "in_flight",
        "awaiting_approval",
        "awaiting_caller_report",
        "unknown",
        "complete",
        "partial",
        "failed_after_effect",
    ] {
        let operation = serde_json::json!({"operation_id":"original","native_admission_digest":vec![8;32],"operation_version":1});
        let mut effect = serde_json::json!({"kind":state,"operation":operation});
        if state == "complete" {
            effect["effect_count"] = serde_json::json!(1);
        }
        if matches!(state, "partial" | "failed_after_effect") {
            effect["applied_effects"] = serde_json::json!(1);
        }
        if state == "admission_unresolved" {
            effect = serde_json::json!({"kind":state,"admission_intent":"original-intent"});
        }
        f.snapshot.effect = serde_json::from_value(effect)?;
        let a = evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment;
        assert_eq!(
            a,
            if matches!(state, "complete" | "partial" | "failed_after_effect") {
                ExplanationAssessmentV1::NoRegisteredRemedy
            } else {
                ExplanationAssessmentV1::UnknownOutcome
            }
        );
    }
    Ok(())
}
#[test]
fn permutations_are_canonical_without_claiming_store_atomicity() -> Result {
    let mut f = Fixture::new()?;
    let template = f.registry.templates.as_slice()[0].clone();
    let templates = ["candidate:a", "candidate:b", "candidate:c"]
        .into_iter()
        .map(|id| {
            let mut candidate = template.clone();
            candidate.template_id = TemplateId::new(id)?;
            Ok(candidate)
        })
        .collect::<Result<Vec<_>>>()?;
    f.registry.templates = BoundedList::new(templates.clone())?;
    let original = f.payloads()?;
    assert_eq!(original.0.projection.candidates.as_slice().len(), 3);
    let mut facts = f.snapshot.observations.as_slice().to_vec();
    facts.reverse();
    f.snapshot.observations = BoundedList::new(facts)?;
    for permutation in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let permuted = permutation
            .into_iter()
            .map(|index| {
                let mut candidate = templates[index].clone();
                let mut deps = candidate.requirements.as_slice().to_vec();
                deps.reverse();
                candidate.requirements = NonEmptyBoundedList::new(deps)?;
                Ok(candidate)
            })
            .collect::<Result<Vec<_>>>()?;
        f.registry.templates = BoundedList::new(permuted)?;
        assert_eq!(original, f.payloads()?, "template order {permutation:?}");
    }
    Ok(())
}
#[test]
fn mandatory_scoped_dependencies_reject_omission_aliasing_and_wrong_targets() -> Result {
    for mutation in 0..4 {
        let mut f = Fixture::new()?;
        let coverage = NonEmptyBoundedList::new(vec![ObservationId::new("coverage")?])?;
        let foreign = ProcessId::new("foreign")?;
        let alias = ObservationId::new("capability")?;
        match mutation {
            0 => f.mutate_template(|t| t.requirements = coverage)?,
            1 => f.mutate_fact(0, |fact| {
                fact.target = ExplanationFactTargetV1::Intent {
                    intent: IntentDigest::from_bytes([9; 32]),
                }
            })?,
            2 => f.mutate_fact(1, |fact| fact.scope.process_id = foreign)?,
            _ => f.mutate_fact(1, |fact| fact.id = alias)?,
        }
        assert!(evaluate_explanation(&f.snapshot, &f.registry, f.limits).is_err());
    }
    Ok(())
}
#[test]
fn bounded_search_reports_incompleteness_and_never_no_remedy() -> Result {
    let mut f = Fixture::new()?;
    let template = f.registry.templates.as_slice()[0].clone();
    let mut templates = Vec::new();
    for i in 0..16 {
        let mut t = template.clone();
        t.template_id = TemplateId::new(&format!("candidate:{i:02}"))?;
        templates.push(t);
    }
    f.registry.templates = BoundedList::new(templates)?;
    for limit in [1, 8, 64, 128, 256, 512, 4096] {
        let limits = ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(limit)?,
        };
        let evaluation = evaluate_explanation(&f.snapshot, &f.registry, limits)?;
        assert!(evaluation.work_used.get() <= limit);
        if !evaluation.complete {
            assert_eq!(
                evaluation.assessment,
                ExplanationAssessmentV1::SearchBoundReached
            );
            assert_eq!(evaluation.classification, InformationLabel::Top);
        }
    }
    let evaluation = evaluate_explanation(
        &f.snapshot,
        &f.registry,
        ExplanationLimitsV1 {
            offers: SafeInteger::new(1)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    assert!(!evaluation.complete);
    Ok(())
}

#[test]
fn protocol_maximum_labels_remain_plannable_under_the_maximum_work_budget() -> Result {
    use chio_security_types::flow::{Compartment, PrincipalId, DEFAULT_LABEL_LIMITS};
    use std::collections::{BTreeMap, BTreeSet};

    let mut f = Fixture::new()?;
    let mut owners = BTreeMap::new();
    for index in 0..DEFAULT_LABEL_LIMITS.max_owners() {
        let owner = PrincipalId::new(format!("owner:{index:02}"))?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 1..DEFAULT_LABEL_LIMITS.max_readers_per_owner() {
            readers.insert(PrincipalId::new(format!("reader:{reader:03}"))?);
        }
        owners.insert(owner, readers);
    }
    let compartments = (0..DEFAULT_LABEL_LIMITS.max_compartments())
        .map(|index| Compartment::new(format!("compartment:{index:02}")))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let label = InformationLabel::try_known(owners, compartments)?;
    f.clearance = label.clone();
    f.snapshot.context_label = label.clone();
    f.registry.classification = label.clone();
    for index in 0..f.snapshot.observations.as_slice().len() {
        f.mutate_fact(index, |fact| fact.label = label.clone())?;
    }
    f.mutate_template(|template| {
        template.classification = label.clone();
        template.disclosure_label = label;
    })?;

    let evaluation = evaluate_explanation(&f.snapshot, &f.registry, f.limits)?;
    assert!(
        evaluation.complete,
        "valid flow labels must fit the planner ceiling"
    );
    assert_eq!(
        evaluation.assessment,
        ExplanationAssessmentV1::FeasibleUnderSnapshot
    );
    let (view, _) = f.payloads()?;
    assert_eq!(
        view.projection.summary,
        ExplanationViewSummaryV1::AlternativesUnderSnapshot
    );
    assert_eq!(view.projection.candidates.as_slice().len(), 1);
    Ok(())
}
#[test]
fn partial_order_retains_distinct_audiences_and_incomparable_labels() -> Result {
    let mut f = Fixture::new()?;
    let mut a = f.registry.templates.as_slice()[0].clone();
    let mut b = a.clone();
    b.template_id = TemplateId::new("other-remedy")?;
    b.destination = chio_security_types::ports::DestinationId::new("other-destination")?;
    let mut other = f.snapshot.observations.as_slice()[2].clone();
    other.id = ObservationId::new("other-recipient")?;
    other.target = ExplanationFactTargetV1::Destination {
        destination: b.destination.clone(),
    };
    let mut facts = f.snapshot.observations.as_slice().to_vec();
    facts.push(other);
    f.snapshot.observations = BoundedList::new(facts)?;
    let mut deps = b.requirements.as_slice().to_vec();
    deps[2] = ObservationId::new("other-recipient")?;
    b.requirements = NonEmptyBoundedList::new(deps)?;
    // A cheaper audience is still not interchangeable with the intended one.
    a.cost.budget_units = SafeInteger::ZERO;
    f.registry.templates = BoundedList::new(vec![a.clone(), b.clone()])?;
    assert_eq!(
        evaluate_explanation(&f.snapshot, &f.registry, f.limits)?
            .candidates
            .as_slice()
            .len(),
        2
    );
    b.destination = a.destination.clone();
    b.requirements = a.requirements.clone();
    f.registry.templates = BoundedList::new(vec![a.clone(), b.clone()])?;
    assert_eq!(
        evaluate_explanation(&f.snapshot, &f.registry, f.limits)?
            .candidates
            .as_slice()
            .len(),
        1
    );
    a.disclosure_label = private()?;
    b.disclosure_label = serde_json::from_value(
        serde_json::json!({"kind":"known","owners":{},"compartments":["different-group"]}),
    )?;
    f.registry.templates = BoundedList::new(vec![a, b])?;
    assert_eq!(
        evaluate_explanation(&f.snapshot, &f.registry, f.limits)?
            .candidates
            .as_slice()
            .len(),
        2
    );
    Ok(())
}

#[test]
fn transformations_and_prerequisites_require_explicit_matching_facts() -> Result {
    for (kind, fact_kind, expected) in [
        (
            ExplanationRemedyKind::Transformation,
            ExplanationFactKind::Transformation,
            ExplanationAssessmentV1::RequiresTransformation,
        ),
        (
            ExplanationRemedyKind::Prerequisite,
            ExplanationFactKind::Prerequisite,
            ExplanationAssessmentV1::RequiresPrerequisite,
        ),
    ] {
        let mut f = Fixture::new()?;
        let id = ObservationId::new("semantic-step")?;
        let mut dependency = f.snapshot.observations.as_slice()[0].clone();
        dependency.id = id.clone();
        dependency.fact = fact_kind;
        dependency.target = ExplanationFactTargetV1::Template {
            template: f.registry.templates.as_slice()[0].template_id.clone(),
        };
        dependency.state = ExplanationFactStateV1::Known {
            version: SafeInteger::new(1)?,
            evidence: EvidenceRef::new("operator:step")?,
            satisfied: false,
        };
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        facts.push(dependency);
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut deps = f.registry.templates.as_slice()[0]
            .requirements
            .as_slice()
            .to_vec();
        deps.push(id);
        let deps = NonEmptyBoundedList::new(deps)?;
        f.mutate_template(|t| {
            t.kind = kind;
            t.requirements = deps;
        })?;
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
            expected
        );
    }
    Ok(())
}
