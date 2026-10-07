use chio_security_types::recovery::{
    BoundedList, ContractError, NonEmptyBoundedList, SafeInteger, StepId, TemplateId,
};
use chio_semantic_contracts::{validate_dependency_graph, DependencyNodeV1, VerificationBudget};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn node(id: &str, dependencies: &[&str], cost: u64) -> Result<DependencyNodeV1> {
    Ok(DependencyNodeV1 {
        step_id: StepId::new(id)?,
        template_id: TemplateId::new("registered-template")?,
        dependencies: BoundedList::new(
            dependencies
                .iter()
                .map(|id| StepId::new(id))
                .collect::<std::result::Result<_, _>>()?,
        )?,
        estimated_cost_units: SafeInteger::new(cost)?,
    })
}
fn validate(
    nodes: Vec<DependencyNodeV1>,
) -> std::result::Result<chio_semantic_contracts::ValidatedDependencyGraph, ContractError> {
    validate_dependency_graph(
        &NonEmptyBoundedList::new(nodes)?,
        &mut VerificationBudget::new(4096)?,
    )
}

#[test]
fn deterministic_topology_and_cost_ignore_input_insertion_order() -> Result {
    for dependencies in [["a", "b"], ["b", "a"]] {
        let nodes = [
            node("a", &[], 1)?,
            node("b", &[], 2)?,
            node("c", &dependencies, 3)?,
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let graph = validate(order.iter().map(|index| nodes[*index].clone()).collect())?;
            assert_eq!(
                graph
                    .ordered_steps()
                    .iter()
                    .map(StepId::as_str)
                    .collect::<Vec<_>>(),
                ["a", "b", "c"]
            );
            assert_eq!(graph.total_cost_units().get(), 6);
        }
    }
    Ok(())
}

#[test]
fn cycles_duplicate_identities_missing_evidence_and_unsafe_costs_fail_closed() -> Result {
    for (nodes, expected) in [
        (
            vec![node("a", &["b"], 0)?, node("b", &["a"], 0)?],
            ContractError::DependencyCycle,
        ),
        (vec![node("a", &["a"], 0)?], ContractError::DependencyCycle),
        (
            vec![node("a", &["missing"], 0)?],
            ContractError::MissingDependency,
        ),
        (
            vec![node("a", &[], 0)?, node("a", &[], 0)?],
            ContractError::DuplicateIdentity,
        ),
        (
            vec![node("a", &[], 0)?, node("b", &["a", "a"], 0)?],
            ContractError::DuplicateIdentity,
        ),
        (
            vec![node("a", &[], SafeInteger::MAX)?, node("b", &[], 1)?],
            ContractError::ArithmeticOverflow,
        ),
    ] {
        assert_eq!(validate(nodes).err(), Some(expected));
    }
    assert!(validate(vec![node("a", &[], 1)?, node("b", &["a"], 2)?]).is_ok());
    Ok(())
}

#[test]
fn repeated_expansion_consumes_shared_budget_and_exhaustion_is_irreversible() -> Result {
    let nodes = NonEmptyBoundedList::new(vec![node("a", &[], 1)?, node("b", &["a"], 2)?])?;
    let mut calibration = VerificationBudget::new(4096)?;
    validate_dependency_graph(&nodes, &mut calibration)?;
    let per_expansion = 4096 - calibration.remaining();
    assert!(per_expansion >= 3, "every node and edge must consume work");
    let mut budget = VerificationBudget::new(per_expansion * 2)?;
    validate_dependency_graph(&nodes, &mut budget)?;
    validate_dependency_graph(&nodes, &mut budget)?;
    assert_eq!(
        validate_dependency_graph(&nodes, &mut budget).err(),
        Some(ContractError::WorkBudgetExceeded)
    );
    assert_eq!(budget.remaining(), 0);
    assert_eq!(budget.charge(0), Err(ContractError::WorkBudgetExceeded));
    let mut exact = VerificationBudget::new(1)?;
    exact.charge(1)?;
    assert_eq!(exact.remaining(), 0);
    assert_eq!(exact.charge(0), Err(ContractError::WorkBudgetExceeded));
    assert!(VerificationBudget::new(4097).is_err());
    Ok(())
}

#[test]
fn full_step_ceiling_has_a_successful_bounded_positive_control() -> Result {
    let mut nodes = Vec::new();
    for index in 0..16 {
        let id = format!("step-{index:02}");
        let step = if index == 0 {
            node(&id, &[], 1)?
        } else {
            let prior = format!("step-{:02}", index - 1);
            node(&id, &[prior.as_str()], 1)?
        };
        nodes.push(step);
    }
    assert_eq!(validate(nodes)?.ordered_steps().len(), 16);
    Ok(())
}

#[test]
fn dense_dependency_graph_at_the_step_ceiling_fits_its_declared_budget() -> Result {
    let mut nodes = Vec::new();
    for index in 0..16 {
        let id = format!("step-{index:02}");
        // Two independent operations per level preserve the protocol depth
        // ceiling of eight while exercising sixteen expanded operations.
        let dependencies = (0..(index / 2) * 2)
            .map(|prior| format!("step-{prior:02}"))
            .collect::<Vec<_>>();
        let borrowed = dependencies.iter().map(String::as_str).collect::<Vec<_>>();
        nodes.push(node(&id, &borrowed, 1)?);
    }
    nodes.reverse();
    let graph = validate(nodes)?;
    assert_eq!(graph.ordered_steps().len(), 16);
    assert_eq!(graph.ordered_steps()[0].as_str(), "step-00");
    assert_eq!(graph.ordered_steps()[15].as_str(), "step-15");
    assert_eq!(graph.total_cost_units().get(), 16);
    Ok(())
}
