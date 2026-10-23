use super::*;

fn limits(work: u32) -> Result<PlannerLimitsV1> {
    Ok(PlannerLimitsV1::new(16, 8, 16, 8, work)?)
}

#[test]
fn all_six_graph_orders_and_dependency_orders_produce_the_same_candidate() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 3)?;
    let mut registered = graph.plans.as_slice()[0].clone();
    let mut nodes = registered.graph.nodes.as_slice().to_vec();
    nodes[1].dependencies = BoundedList::new(vec![])?;
    nodes[2].dependencies =
        BoundedList::new(vec![nodes[0].step_id.clone(), nodes[1].step_id.clone()])?;
    registered.graph.nodes = NonEmptyBoundedList::new(nodes.clone())?;
    graph.plans = BoundedList::new(vec![registered.clone()])?;
    let expected = plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?;
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        for reverse in [false, true] {
            let mut permuted = Vec::new();
            for index in order {
                let mut node = nodes[index].clone();
                if reverse {
                    let mut dependencies = node.dependencies.as_slice().to_vec();
                    dependencies.reverse();
                    node.dependencies = BoundedList::new(dependencies)?;
                }
                permuted.push(node);
            }
            registered.graph.nodes = NonEmptyBoundedList::new(permuted)?;
            graph.plans = BoundedList::new(vec![registered.clone()])?;
            assert_eq!(
                plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?,
                expected
            );
        }
    }
    Ok(())
}

#[test]
fn sixteen_nodes_at_eight_dense_levels_fit_the_protocol_work_budget() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 16)?;
    let mut registered = graph.plans.as_slice()[0].clone();
    let mut nodes = registered.graph.nodes.as_slice().to_vec();
    for (index, node) in nodes.iter_mut().enumerate() {
        let previous_level_end = (index / 2) * 2;
        node.dependencies = BoundedList::new(
            (0..previous_level_end)
                .map(|prior| StepId::new(&format!("step:{prior:02}")))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )?;
    }
    registered.top_level_steps = NonEmptyBoundedList::new(
        (8..16)
            .map(|i| StepId::new(&format!("step:{i:02}")))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )?;
    registered.graph.nodes = NonEmptyBoundedList::new(nodes)?;
    graph.plans = BoundedList::new(vec![registered])?;
    let PlanDecision::Candidates { plans, .. } = plan(
        &f.snapshot,
        &f.registry,
        &graph,
        limits(MAX_RECOVERY_VERIFICATION_WORK)?,
    )?
    else {
        return Err("the bounded dense graph must produce a candidate".into());
    };
    assert_eq!(plans.as_slice().len(), 1);
    let candidate = &plans.as_slice()[0];
    assert_eq!(candidate.ordered_steps().len(), 16);
    assert_eq!(
        candidate.assessment(),
        ExplanationAssessmentV1::FeasibleUnderSnapshot
    );
    assert_eq!(candidate.total_cost_units().get(), 16);
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 16, 8, 4096)?
        )?,
        plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?,
    );
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            &graph,
            PlannerLimitsV1::new(16, 8, 16, 7, 4096)?
        )?,
        PlanDecision::SearchBoundReached {
            limit: PlannerSearchLimit::Depth,
            classification: InformationLabel::Top,
        }
    );
    Ok(())
}

#[test]
fn offers_are_canonical_and_share_one_work_budget() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 1)?;
    assert!(matches!(
        plan(&f.snapshot, &f.registry, &graph, limits(100)?)?,
        PlanDecision::Candidates { .. }
    ));
    let registered = graph.plans.as_slice()[0].clone();
    let mut offered = Vec::new();
    for index in 0..16 {
        let mut candidate = registered.clone();
        candidate.plan_id = PlanId::new(&format!("plan:{index:02}"))?;
        offered.push(candidate);
    }
    graph.plans = BoundedList::new(offered.clone())?;
    let expected = plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?;
    let PlanDecision::Candidates { plans, .. } = &expected else {
        return Err("sixteen bounded offers must produce candidates".into());
    };
    assert_eq!(plans.as_slice().len(), 16);
    offered.reverse();
    graph.plans = BoundedList::new(offered)?;
    assert_eq!(
        plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?,
        expected
    );
    for (limits, bound) in [
        (
            PlannerLimitsV1::new(15, 8, 16, 8, 4096)?,
            PlannerSearchLimit::Offers,
        ),
        (limits(100)?, PlannerSearchLimit::Work),
    ] {
        assert_eq!(
            plan(&f.snapshot, &f.registry, &graph, limits)?,
            PlanDecision::SearchBoundReached {
                limit: bound,
                classification: InformationLabel::Top
            }
        );
    }
    Ok(())
}

#[test]
fn empty_registry_retains_classification_without_claiming_a_candidate() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 1)?;
    graph.plans = BoundedList::new(vec![])?;
    assert_eq!(
        plan(&f.snapshot, &f.registry, &graph, limits(4096)?)?,
        PlanDecision::NoRegisteredRemedy {
            classification: f.snapshot.context_label.clone()
        }
    );
    Ok(())
}

#[test]
fn a_bound_makes_no_validity_claim_about_unsearched_graphs() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 3)?;
    let mut first = graph.plans.as_slice()[0].clone();
    first.plan_id = PlanId::new("plan:a")?;
    first.top_level_steps =
        NonEmptyBoundedList::new(vec![StepId::new("step:01")?, StepId::new("step:02")?])?;
    let mut cyclic = graph.plans.as_slice()[0].clone();
    cyclic.plan_id = PlanId::new("plan:b")?;
    let mut nodes = cyclic.graph.nodes.as_slice().to_vec();
    nodes[0].dependencies = BoundedList::new(vec![StepId::new("step:02")?])?;
    cyclic.graph.nodes = NonEmptyBoundedList::new(nodes)?;
    graph.plans = BoundedList::new(vec![cyclic, first])?;
    for (limits, limit) in [
        (
            PlannerLimitsV1::new(16, 1, 16, 8, 4096)?,
            PlannerSearchLimit::Steps,
        ),
        (
            PlannerLimitsV1::new(1, 8, 16, 8, 4096)?,
            PlannerSearchLimit::Offers,
        ),
    ] {
        assert_eq!(
            plan(&f.snapshot, &f.registry, &graph, limits)?,
            PlanDecision::SearchBoundReached {
                limit,
                classification: InformationLabel::Top
            }
        );
    }
    assert_eq!(
        plan(&f.snapshot, &f.registry, &graph, limits(4096)?),
        Err(ContractError::DependencyCycle)
    );
    Ok(())
}
