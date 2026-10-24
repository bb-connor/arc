use super::*;

fn refuse(f: &Fixture, graph: &RecoveryPlanningRegistryV1, expected: ContractError) -> Result {
    assert_eq!(
        plan(
            &f.snapshot,
            &f.registry,
            graph,
            PlannerLimitsV1::new(16, 8, 16, 8, 4096)?
        ),
        Err(expected)
    );
    Ok(())
}

#[test]
fn every_scope_component_must_match_the_snapshot() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    for component in 0..3 {
        let mut changed = graph.clone();
        match component {
            0 => changed.scope.authority_domain = AuthorityDomainId::new("foreign")?,
            1 => changed.scope.tenant_id = RecoveryTenantId::new("foreign")?,
            _ => changed.scope.process_id = ProcessId::new("foreign")?,
        }
        refuse(&f, &changed, ContractError::BindingMismatch)?;
    }
    Ok(())
}

#[test]
fn duplicate_plans_roots_nodes_and_edges_have_exact_identity_refusals() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    let registered = graph.plans.as_slice()[0].clone();
    let mut changed = graph.clone();
    changed.plans = BoundedList::new(vec![registered.clone(), registered.clone()])?;
    refuse(&f, &changed, ContractError::DuplicateIdentity)?;
    for component in 0..3 {
        let mut candidate = registered.clone();
        let mut nodes = candidate.graph.nodes.as_slice().to_vec();
        match component {
            0 => {
                candidate.top_level_steps = NonEmptyBoundedList::new(vec![
                    nodes[2].step_id.clone(),
                    nodes[2].step_id.clone(),
                ])?
            }
            1 => nodes.push(nodes[0].clone()),
            _ => {
                nodes[2].dependencies =
                    BoundedList::new(vec![nodes[1].step_id.clone(), nodes[1].step_id.clone()])?
            }
        }
        candidate.graph.nodes = NonEmptyBoundedList::new(nodes)?;
        changed.plans = BoundedList::new(vec![candidate])?;
        refuse(&f, &changed, ContractError::DuplicateIdentity)?;
    }
    Ok(())
}

#[test]
fn missing_roots_unused_nodes_and_cost_substitution_are_refused() -> Result {
    let f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    for (mutation, expected) in [
        (0, ContractError::MissingDependency),
        (1, ContractError::InvalidState),
        (2, ContractError::BindingMismatch),
        (3, ContractError::MissingDependency),
    ] {
        let mut changed = graph.clone();
        let mut candidate = graph.plans.as_slice()[0].clone();
        let mut nodes = candidate.graph.nodes.as_slice().to_vec();
        match mutation {
            0 => {
                candidate.top_level_steps = NonEmptyBoundedList::new(vec![StepId::new("absent")?])?
            }
            1 => nodes[2].dependencies = BoundedList::new(vec![nodes[0].step_id.clone()])?,
            2 => nodes[0].estimated_cost_units = SafeInteger::new(2)?,
            _ => nodes[0].dependencies = BoundedList::new(vec![StepId::new("absent")?])?,
        }
        candidate.graph.nodes = NonEmptyBoundedList::new(nodes)?;
        changed.plans = BoundedList::new(vec![candidate])?;
        refuse(&f, &changed, expected)?;
    }
    Ok(())
}

#[test]
fn a_root_template_must_satisfy_the_task() -> Result {
    let mut f = Fixture::new()?;
    let graph = registry(&f, 3)?;
    let mut templates = f.registry.templates.as_slice().to_vec();
    templates[0].satisfies_task = false;
    f.registry.templates = BoundedList::new(templates)?;
    refuse(&f, &graph, ContractError::InvalidState)
}

#[test]
fn aggregate_cost_overflow_does_not_produce_a_partial_plan() -> Result {
    let f = Fixture::new()?;
    let mut graph = registry(&f, 3)?;
    let mut candidate = graph.plans.as_slice()[0].clone();
    let mut nodes = candidate.graph.nodes.as_slice().to_vec();
    for node in &mut nodes {
        node.estimated_cost_units = SafeInteger::new(SafeInteger::MAX)?;
    }
    candidate.graph.nodes = NonEmptyBoundedList::new(nodes)?;
    graph.plans = BoundedList::new(vec![candidate])?;
    refuse(&f, &graph, ContractError::ArithmeticOverflow)
}
