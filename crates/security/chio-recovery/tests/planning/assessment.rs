use super::*;

fn operation() -> Result<OperationRef> {
    Ok(OperationRef::new(
        OperationId::new("operation-original")?,
        NativeAdmissionDigest::from_bytes([3; 32]),
        SafeInteger::new(1)?,
    )?)
}

#[test]
fn unresolved_original_effects_never_become_feasible_candidates() -> Result {
    let original = operation()?;
    for effect in [
        EffectObservationV1::AdmissionUnresolved {
            admission_intent: AdmissionIntentRef::new("intent-original")?,
        },
        EffectObservationV1::AwaitingApproval {
            operation: original.clone(),
        },
        EffectObservationV1::InFlight {
            operation: original.clone(),
        },
        EffectObservationV1::AwaitingCallerReport {
            operation: original.clone(),
        },
        EffectObservationV1::Unknown {
            operation: original.clone(),
        },
    ] {
        let mut f = Fixture::new()?;
        f.snapshot.effect = effect.clone();
        let graph = registry(&f, 3)?;
        let PlanDecision::Candidates { plans, .. } = plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 16, 8, 4096)?,
        )?
        else {
            return Err("unresolved originals must retain unknown-outcome advice".into());
        };
        assert_eq!(plans.as_slice().len(), 1);
        for candidate in plans.as_slice() {
            assert_eq!(
                candidate.assessment(),
                ExplanationAssessmentV1::UnknownOutcome
            );
        }
        assert_eq!(f.snapshot.effect, effect);
    }
    Ok(())
}

#[test]
fn settled_original_effects_do_not_produce_another_remedy() -> Result {
    let original = operation()?;
    for effect in [
        EffectObservationV1::Complete {
            operation: original.clone(),
            effect_count: SafeInteger::new(1)?,
        },
        EffectObservationV1::Partial {
            operation: original.clone(),
            applied_effects: SafeInteger::new(1)?,
        },
        EffectObservationV1::FailedAfterEffect {
            operation: original.clone(),
            applied_effects: SafeInteger::new(1)?,
        },
    ] {
        let mut f = Fixture::new()?;
        f.snapshot.effect = effect.clone();
        let graph = registry(&f, 3)?;
        assert_eq!(
            plan(
                &f.snapshot,
                &f.registry,
                &graph,
                PlannerLimitsV1::new(16, 8, 16, 8, 4096)?
            )?,
            PlanDecision::NoRegisteredRemedy {
                classification: f.snapshot.context_label.clone()
            }
        );
        assert_eq!(f.snapshot.effect, effect);
    }
    Ok(())
}

#[test]
fn every_private_input_label_raises_the_candidate_classification() -> Result {
    let private: InformationLabel = serde_json::from_value(serde_json::json!({
        "kind": "known", "owners": {}, "compartments": ["secret-group"],
    }))?;
    for component in 0..5 {
        let mut f = Fixture::new()?;
        let mut graph = registry(&f, 3)?;
        match component {
            0 => graph.classification = private.clone(),
            1 => f.registry.classification = private.clone(),
            2 | 3 => {
                let mut templates = f.registry.templates.as_slice().to_vec();
                if component == 2 {
                    templates[0].classification = private.clone();
                } else {
                    templates[0].disclosure_label = private.clone();
                }
                f.registry.templates = BoundedList::new(templates)?;
            }
            _ => {
                let mut facts = f.snapshot.observations.as_slice().to_vec();
                facts[0].label = private.clone();
                f.snapshot.observations = BoundedList::new(facts)?;
            }
        }
        let PlanDecision::Candidates {
            plans,
            classification,
        } = plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 16, 8, 4096)?,
        )?
        else {
            return Err("classified valid inputs must produce advisory candidates".into());
        };
        assert_eq!(classification, private);
        assert_eq!(plans.as_slice().len(), 1);
        assert_eq!(
            plans.as_slice()[0].assessment(),
            ExplanationAssessmentV1::FeasibleUnderSnapshot
        );
    }
    Ok(())
}
