use super::*;

#[test]
fn every_insufficient_work_allowance_returns_only_classified_incompleteness() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    let expected = plan(
        &f.snapshot,
        &f.registry,
        &graph,
        PlannerLimitsV1::new(16, 8, 32, 8, MAX_RECOVERY_VERIFICATION_WORK)?,
    )?;
    let mut first_complete = None;
    for work in 1..=MAX_RECOVERY_VERIFICATION_WORK {
        let decision = plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 32, 8, work)?,
        )?;
        if matches!(&decision, PlanDecision::Candidates { .. }) {
            assert_eq!(decision, expected);
            first_complete = Some(work);
            break;
        }
        assert_eq!(
            decision,
            PlanDecision::SearchBoundReached {
                limit: PlannerSearchLimit::Work,
                classification: InformationLabel::Top,
            }
        );
    }
    let first_complete = first_complete.ok_or("the valid graph must fit the work ceiling")?;
    assert!(first_complete > 1);
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 32, 8, first_complete + 1)?,
        )?,
        expected
    );
    Ok(())
}

#[test]
fn prerequisite_nodes_are_assessed_even_when_the_root_is_feasible() -> Result {
    let mut f = Fixture::new()?;
    let mut graph = registry(&f, 2)?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    let mut predecessor = templates[0].clone();
    predecessor.template_id = TemplateId::new("prerequisite-needs-integrity")?;
    predecessor.requires_integrity = true;
    let mut registered = graph.plans.as_slice()[0].clone();
    let mut nodes = registered.graph.nodes.as_slice().to_vec();
    nodes[0].template_id = predecessor.template_id.clone();
    templates.push(predecessor);
    f.registry.templates = BoundedList::new(templates)?;
    registered.graph.nodes = NonEmptyBoundedList::new(nodes)?;
    graph.plans = BoundedList::new(vec![registered])?;
    let PlanDecision::Candidates { plans, .. } = plan(
        &f.snapshot,
        &f.registry,
        &graph,
        PlannerLimitsV1::new(16, 8, 32, 8, 4096)?,
    )?
    else {
        return Err("the registered graph must retain its unmet prerequisite".into());
    };
    assert_eq!(
        plans.as_slice()[0].assessment(),
        ExplanationAssessmentV1::NeedsFreshEvidence
    );
    Ok(())
}

#[test]
fn empty_plan_registries_preserve_labels_and_work_exhaustion() -> Result {
    let mut f = Fixture::new()?;
    let mut graph = registry(&f, 1)?;
    graph.plans = BoundedList::new(vec![])?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    templates[0].classification = InformationLabel::Top;
    f.registry.templates = BoundedList::new(templates)?;
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 32, 8, 4096)?,
        )?,
        PlanDecision::NoRegisteredRemedy {
            classification: InformationLabel::Top,
        }
    );
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 32, 8, 1)?,
        )?,
        PlanDecision::SearchBoundReached {
            limit: PlannerSearchLimit::Work,
            classification: InformationLabel::Top,
        }
    );
    Ok(())
}
