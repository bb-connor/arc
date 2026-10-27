use chio_core_types::{canonical_json_bytes, recovery::decode_contract};
use chio_security_types::recovery::{
    BoundedList, ContractError, NonEmptyBoundedList, SafeInteger, StepId, TemplateId, VersionV1,
    MAX_RECOVERY_VERIFICATION_WORK,
};
use chio_security_types::work::{VerificationBudget, WorkBudgetError};
use chio_semantic_contracts::{
    validate_dependency_graph, DependencyGraphSchema, DependencyGraphV1, DependencyNodeV1,
    ValidatedDependencyGraph, MAX_DEPENDENCY_GRAPH_NODES,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn node(id: &str, dependencies: &[&str], cost: u64) -> TestResult<DependencyNodeV1> {
    Ok(DependencyNodeV1 {
        step_id: StepId::new(id)?,
        template_id: TemplateId::new("registered-template")?,
        dependencies: BoundedList::new(
            dependencies
                .iter()
                .map(|id| StepId::new(id))
                .collect::<Result<_, _>>()?,
        )?,
        estimated_cost_units: SafeInteger::new(cost)?,
    })
}

fn validate(nodes: Vec<DependencyNodeV1>) -> Result<ValidatedDependencyGraph, ContractError> {
    validate_dependency_graph(
        &NonEmptyBoundedList::new(nodes)?,
        &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
    )
}

#[test]
fn deterministic_topology_and_cost_ignore_input_insertion_order() -> TestResult {
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
            let graph = validate(
                order
                    .iter()
                    .map(|index| nodes.get(*index).cloned().ok_or("permutation index"))
                    .collect::<Result<_, _>>()?,
            )?;
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
fn cycles_duplicate_identities_missing_evidence_and_unsafe_costs_fail_closed() -> TestResult {
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
    assert_eq!(
        validate(vec![node("a", &[], 1)?, node("b", &["a"], 2)?])?
            .total_cost_units()
            .get(),
        3
    );
    Ok(())
}

#[test]
fn repeated_expansion_consumes_shared_budget_and_exhaustion_is_irreversible() -> TestResult {
    let nodes = NonEmptyBoundedList::new(vec![node("a", &[], 1)?, node("b", &["a"], 2)?])?;
    let mut calibration = VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?;
    validate_dependency_graph(&nodes, &mut calibration)?;
    let per_expansion = 4096 - calibration.remaining();
    assert!(per_expansion >= 3);
    let mut budget = VerificationBudget::new(per_expansion * 2, MAX_RECOVERY_VERIFICATION_WORK)?;
    validate_dependency_graph(&nodes, &mut budget)?;
    validate_dependency_graph(&nodes, &mut budget)?;
    assert_eq!(
        validate_dependency_graph(&nodes, &mut budget).err(),
        Some(ContractError::WorkBudgetExceeded)
    );
    assert_eq!(budget.remaining(), 0);
    assert_eq!(budget.charge(0), Err(WorkBudgetError::Exhausted));
    Ok(())
}

#[test]
fn full_step_ceiling_has_a_successful_bounded_positive_control() -> TestResult {
    let mut nodes = Vec::new();
    for index in 0..MAX_DEPENDENCY_GRAPH_NODES {
        let id = format!("step-{index:02}");
        let step = if index == 0 {
            node(&id, &[], 1)?
        } else {
            node(&id, &[&format!("step-{:02}", index - 1)], 1)?
        };
        nodes.push(step);
    }
    assert_eq!(
        validate(nodes)?.ordered_steps().len(),
        MAX_DEPENDENCY_GRAPH_NODES
    );
    Ok(())
}

#[test]
fn dense_dependency_graph_at_the_step_ceiling_fits_its_declared_budget() -> TestResult {
    let mut nodes = Vec::new();
    for index in 0..MAX_DEPENDENCY_GRAPH_NODES {
        let dependencies = (0..(index / 2) * 2)
            .map(|prior| format!("step-{prior:02}"))
            .collect::<Vec<_>>();
        let borrowed = dependencies.iter().map(String::as_str).collect::<Vec<_>>();
        nodes.push(node(&format!("step-{index:02}"), &borrowed, 1)?);
    }
    nodes.reverse();
    let graph = validate(nodes)?;
    assert_eq!(graph.ordered_steps().len(), 16);
    assert_eq!(
        graph.ordered_steps().first().map(StepId::as_str),
        Some("step-00")
    );
    assert_eq!(
        graph.ordered_steps().last().map(StepId::as_str),
        Some("step-15")
    );
    assert_eq!(graph.total_cost_units().get(), 16);
    Ok(())
}

#[test]
fn graph_wire_requires_the_complete_bounded_v1_shape() -> TestResult {
    let graph = DependencyGraphV1 {
        schema: DependencyGraphSchema::V1,
        version: VersionV1,
        nodes: NonEmptyBoundedList::new(vec![node("a", &[], 1)?])?,
    };
    let value = serde_json::to_value(&graph)?;
    assert_eq!(
        decode_contract::<DependencyGraphV1>(&canonical_json_bytes(&graph)?)?,
        graph
    );
    for (field, replacement, expected) in [
        (
            "schema",
            serde_json::json!("chio.recovery.dependency-graph.v2"),
            ContractError::Malformed,
        ),
        ("version", serde_json::json!(2), ContractError::Malformed),
        ("nodes", serde_json::json!([]), ContractError::Malformed),
        (
            "nodes",
            serde_json::to_value(vec![node("a", &[], 1)?; 17])?,
            ContractError::Malformed,
        ),
        (
            "unexpected",
            serde_json::json!(true),
            ContractError::Malformed,
        ),
    ] {
        let mut invalid = value.clone();
        invalid[field] = replacement;
        assert_eq!(
            decode_contract::<DependencyGraphV1>(&canonical_json_bytes(&invalid)?).err(),
            Some(expected)
        );
    }
    assert_eq!(
        validate(Vec::new()).err(),
        Some(ContractError::InvalidState)
    );
    assert_eq!(
        validate(vec![node("a", &[], 1)?; 17]).err(),
        Some(ContractError::LimitExceeded)
    );
    Ok(())
}
