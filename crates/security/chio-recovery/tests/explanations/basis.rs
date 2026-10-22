use super::common::*;
use chio_core_types::canonical_json_bytes;
use chio_core_types::recovery::decode_contract;
use chio_recovery::evaluate_explanation;
use chio_security_types::ports::DestinationId;
use chio_security_types::recovery::{
    BoundedList, ContractError, EvidenceRef, ExplanationAssessmentV1, ExplanationFactKind,
    ExplanationFactStateV1, ExplanationFactTargetV1, ExplanationGap, ExplanationIntegrity,
    ExplanationLimitsV1, ExplanationRemedyKind, ExplanationViewSummaryV1, IntentDigest,
    NonEmptyBoundedList, ObservationId, ProcessId, SafeInteger, TemplateId,
};
use chio_security_types::InformationLabel;

#[test]
fn every_truth_assignment_keeps_its_fail_closed_meaning() -> Result {
    for bits in 0..16_u32 {
        let mut f = Fixture::new()?;
        for index in 0..4_usize {
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
fn freshness_qualified_facts_require_live_intervals_and_never_carry_versions() -> Result {
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
    let versioned = serde_json::json!({
        "kind": "freshness_qualified",
        "evidence": "native:versionless",
        "satisfied": true,
        "version": 1
    });
    assert_eq!(
        decode_contract::<ExplanationFactStateV1>(&canonical_json_bytes(&versioned)?).err(),
        Some(ContractError::Malformed)
    );
    Ok(())
}

#[test]
fn gaps_unverified_and_expired_positive_facts_never_become_feasible() -> Result {
    for index in 0..4_usize {
        for mutation in 0..3_u8 {
            let mut f = Fixture::new()?;
            let expired = SafeInteger::new(OBSERVED_AT)?;
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
                ExplanationAssessmentV1::NeedsFreshEvidence,
                "fact {index} mutation {mutation}"
            );
        }
    }
    Ok(())
}

#[test]
fn native_provenance_never_implies_an_integrity_endorsement() -> Result {
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
    let operation = serde_json::json!({
        "operation_id": "original",
        "native_admission_digest": vec![8_u8; 32],
        "operation_version": 1
    });
    for (effect, expected) in [
        (
            serde_json::json!({"kind": "admission_unresolved", "admission_intent": "original-intent"}),
            ExplanationAssessmentV1::UnknownOutcome,
        ),
        (
            serde_json::json!({"kind": "in_flight", "operation": operation}),
            ExplanationAssessmentV1::UnknownOutcome,
        ),
        (
            serde_json::json!({"kind": "awaiting_approval", "operation": operation}),
            ExplanationAssessmentV1::UnknownOutcome,
        ),
        (
            serde_json::json!({"kind": "awaiting_caller_report", "operation": operation}),
            ExplanationAssessmentV1::UnknownOutcome,
        ),
        (
            serde_json::json!({"kind": "unknown", "operation": operation}),
            ExplanationAssessmentV1::UnknownOutcome,
        ),
        (
            serde_json::json!({"kind": "complete", "operation": operation, "effect_count": 1}),
            ExplanationAssessmentV1::NoRegisteredRemedy,
        ),
        (
            serde_json::json!({"kind": "partial", "operation": operation, "applied_effects": 1}),
            ExplanationAssessmentV1::NoRegisteredRemedy,
        ),
        (
            serde_json::json!({
                "kind": "failed_after_effect", "operation": operation, "applied_effects": 1
            }),
            ExplanationAssessmentV1::NoRegisteredRemedy,
        ),
        (
            serde_json::json!({
                "kind": "closed_before_effect", "operation": operation, "closure": "closure:native"
            }),
            ExplanationAssessmentV1::FeasibleUnderSnapshot,
        ),
    ] {
        f.snapshot.effect = serde_json::from_value(effect)?;
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
            expected
        );
    }
    Ok(())
}

#[test]
fn permuted_templates_facts_and_dependencies_produce_identical_payloads() -> Result {
    let mut f = Fixture::new()?;
    let template = f.template()?;
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
                let mut candidate = templates
                    .get(index)
                    .ok_or("permutation index is out of range")?
                    .clone();
                let mut requirements = candidate.requirements.as_slice().to_vec();
                requirements.reverse();
                candidate.requirements = NonEmptyBoundedList::new(requirements)?;
                Ok(candidate)
            })
            .collect::<Result<Vec<_>>>()?;
        f.registry.templates = BoundedList::new(permuted)?;
        assert_eq!(original, f.payloads()?, "template order {permutation:?}");
    }
    Ok(())
}

#[test]
fn mandatory_scoped_dependencies_refuse_omission_aliasing_and_wrong_targets() -> Result {
    for (mutation, expected) in [
        (0, ContractError::MissingDependency),
        (1, ContractError::BindingMismatch),
        (2, ContractError::BindingMismatch),
        (3, ContractError::DuplicateIdentity),
    ] {
        let mut f = Fixture::new()?;
        let coverage_only = NonEmptyBoundedList::new(vec![ObservationId::new("coverage")?])?;
        let foreign = ProcessId::new("foreign")?;
        let alias = ObservationId::new("capability")?;
        match mutation {
            0 => f.mutate_template(|t| t.requirements = coverage_only)?,
            1 => f.mutate_fact(0, |fact| {
                fact.target = ExplanationFactTargetV1::Intent {
                    intent: IntentDigest::from_bytes([9; 32]),
                }
            })?,
            2 => f.mutate_fact(1, |fact| fact.scope.process_id = foreign)?,
            _ => f.mutate_fact(1, |fact| fact.id = alias)?,
        }
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, f.limits).err(),
            Some(expected),
            "mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn explanation_limits_outside_protocol_ceilings_refuse() -> Result {
    let f = Fixture::new()?;
    for (offers, work, expected) in [
        (0, 4096, ContractError::LimitExceeded),
        (17, 4096, ContractError::LimitExceeded),
        (16, 0, ContractError::LimitExceeded),
        (16, 4097, ContractError::LimitExceeded),
    ] {
        let limits = ExplanationLimitsV1 {
            offers: SafeInteger::new(offers)?,
            work: SafeInteger::new(work)?,
        };
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, limits).err(),
            Some(expected),
            "offers {offers} work {work}"
        );
    }
    let mut halved = Fixture::new()?;
    halved.limits.work = SafeInteger::new(1)?;
    assert_eq!(
        halved.payloads().err(),
        Some(ContractError::WorkBudgetExceeded)
    );
    Ok(())
}

#[test]
fn bounded_search_reports_incompleteness_and_never_no_remedy() -> Result {
    let mut f = Fixture::new()?;
    let template = f.template()?;
    let mut templates = Vec::new();
    for i in 0..16 {
        let mut t = template.clone();
        t.template_id = TemplateId::new(&format!("candidate:{i:02}"))?;
        templates.push(t);
    }
    f.registry.templates = BoundedList::new(templates)?;
    let mut exhausted = 0;
    for limit in [1, 8, 64, 128, 256, 512, 4096] {
        let limits = ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(limit)?,
        };
        let evaluation = evaluate_explanation(&f.snapshot, &f.registry, limits)?;
        assert!(evaluation.work_used.get() <= limit, "work limit {limit}");
        if evaluation.complete {
            assert_ne!(
                evaluation.assessment,
                ExplanationAssessmentV1::SearchBoundReached
            );
        } else {
            exhausted += 1;
            assert_eq!(
                evaluation.assessment,
                ExplanationAssessmentV1::SearchBoundReached
            );
            assert_eq!(evaluation.classification, InformationLabel::Top);
        }
    }
    assert!(exhausted > 0, "no work limit exhausted the search");
    let evaluation = evaluate_explanation(
        &f.snapshot,
        &f.registry,
        ExplanationLimitsV1 {
            offers: SafeInteger::new(1)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    assert!(!evaluation.complete);
    assert_eq!(
        evaluation.assessment,
        ExplanationAssessmentV1::SearchBoundReached
    );
    assert_eq!(evaluation.classification, InformationLabel::Top);
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
    let mut a = f.template()?;
    let mut b = a.clone();
    b.template_id = TemplateId::new("other-remedy")?;
    b.destination = DestinationId::new("other-destination")?;
    let mut other = f.fact(2)?;
    other.id = ObservationId::new("other-recipient")?;
    other.target = ExplanationFactTargetV1::Destination {
        destination: b.destination.clone(),
    };
    let mut facts = f.snapshot.observations.as_slice().to_vec();
    facts.push(other);
    f.snapshot.observations = BoundedList::new(facts)?;
    let mut requirements = b.requirements.as_slice().to_vec();
    *requirements
        .get_mut(2)
        .ok_or("template has no destination requirement")? = ObservationId::new("other-recipient")?;
    b.requirements = NonEmptyBoundedList::new(requirements)?;
    // A cheaper audience is still not interchangeable with the intended one.
    a.cost.budget_units = SafeInteger::ZERO;
    f.registry.templates = BoundedList::new(vec![a.clone(), b.clone()])?;
    let candidates = |f: &Fixture| -> Result<usize> {
        Ok(evaluate_explanation(&f.snapshot, &f.registry, f.limits)?
            .candidates
            .as_slice()
            .len())
    };
    assert_eq!(candidates(&f)?, 2);
    b.destination = a.destination.clone();
    b.requirements = a.requirements.clone();
    f.registry.templates = BoundedList::new(vec![a.clone(), b.clone()])?;
    assert_eq!(candidates(&f)?, 1);
    a.disclosure_label = private()?;
    b.disclosure_label = serde_json::from_value(
        serde_json::json!({"kind": "known", "owners": {}, "compartments": ["different-group"]}),
    )?;
    f.registry.templates = BoundedList::new(vec![a, b])?;
    assert_eq!(candidates(&f)?, 2);
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
        let template = f.template()?;
        let id = ObservationId::new("semantic-step")?;
        let mut dependency = f.fact(0)?;
        dependency.id = id.clone();
        dependency.fact = fact_kind;
        dependency.target = ExplanationFactTargetV1::Template {
            template: template.template_id.clone(),
        };
        dependency.state = ExplanationFactStateV1::Known {
            version: SafeInteger::new(1)?,
            evidence: EvidenceRef::new("operator:step")?,
            satisfied: false,
        };
        let mut facts = f.snapshot.observations.as_slice().to_vec();
        facts.push(dependency);
        f.snapshot.observations = BoundedList::new(facts)?;
        let mut requirements = template.requirements.as_slice().to_vec();
        requirements.push(id);
        let requirements = NonEmptyBoundedList::new(requirements)?;
        f.mutate_template(|t| {
            t.kind = kind;
            t.requirements = requirements;
        })?;
        assert_eq!(
            evaluate_explanation(&f.snapshot, &f.registry, f.limits)?.assessment,
            expected
        );
        let mut missing = f;
        let kept = NonEmptyBoundedList::new(
            missing
                .template()?
                .requirements
                .as_slice()
                .iter()
                .filter(|required| required.as_str() != "semantic-step")
                .cloned()
                .collect(),
        )?;
        missing.mutate_template(|t| t.requirements = kept)?;
        assert_eq!(
            evaluate_explanation(&missing.snapshot, &missing.registry, missing.limits).err(),
            Some(ContractError::MissingDependency)
        );
    }
    Ok(())
}
