use crate::VerificationBudget;
use alloc::{vec, vec::Vec};
use chio_security_types::recovery::{
    BoundedList, ContractError, NonEmptyBoundedList, SafeInteger, StepId, TemplateId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependencyGraphSchema {
    #[serde(rename = "chio.recovery.dependency-graph.v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyGraphV1 {
    pub schema: DependencyGraphSchema,
    pub version: chio_security_types::recovery::VersionV1,
    pub nodes: NonEmptyBoundedList<DependencyNodeV1, 16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyNodeV1 {
    pub step_id: StepId,
    pub template_id: TemplateId,
    pub dependencies: BoundedList<StepId, 16>,
    pub estimated_cost_units: SafeInteger,
}

/// A validated symbolic DAG is not a materialized action or an execution permit.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedDependencyGraph {
    order: Vec<StepId>,
    total_cost_units: SafeInteger,
}
impl ValidatedDependencyGraph {
    pub fn ordered_steps(&self) -> &[StepId] {
        &self.order
    }
    pub const fn total_cost_units(&self) -> SafeInteger {
        self.total_cost_units
    }
}

/// Stable topological ordering ends in the bytewise opaque step identifier.
/// Every edge, indexed mutation and bounded search consumes the shared meter.
pub fn validate_dependency_graph(
    nodes: &NonEmptyBoundedList<DependencyNodeV1, 16>,
    budget: &mut VerificationBudget,
) -> Result<ValidatedDependencyGraph, ContractError> {
    let size = nodes.as_slice().len();
    // Conservatively account for bounded sort/comparison work before allocating.
    let sorting_work = size
        .checked_mul(size)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(ContractError::ArithmeticOverflow)?;
    budget.charge(sorting_work)?;
    let mut sorted: Vec<&DependencyNodeV1> = nodes.as_slice().iter().collect();
    sorted.sort_by(|a, b| a.step_id.cmp(&b.step_id));
    if sorted
        .windows(2)
        .any(|pair| pair[0].step_id == pair[1].step_id)
    {
        return Err(ContractError::DuplicateIdentity);
    }
    let mut total_cost = SafeInteger::ZERO;
    let size_work = u32::try_from(size).map_err(|_| ContractError::ArithmeticOverflow)?;
    budget.charge(
        size_work
            .checked_mul(3)
            .ok_or(ContractError::ArithmeticOverflow)?,
    )?;
    let mut remaining = vec![0usize; size];
    let mut dependents = vec![Vec::new(); size];
    let mut done = vec![false; size];
    let search_work = size_work
        .checked_next_power_of_two()
        .ok_or(ContractError::ArithmeticOverflow)?
        .ilog2()
        + 1;
    for (node_index, node) in sorted.iter().enumerate() {
        budget.charge(2)?;
        total_cost = total_cost.checked_add(node.estimated_cost_units)?;
        budget.charge(size_work)?;
        let mut seen = vec![false; size];
        for dependency in node.dependencies.as_slice() {
            budget.charge(search_work)?;
            let dependency_index = sorted
                .binary_search_by(|candidate| candidate.step_id.cmp(dependency))
                .map_err(|_| ContractError::MissingDependency)?;
            budget.charge(4)?;
            if seen[dependency_index] {
                return Err(ContractError::DuplicateIdentity);
            }
            seen[dependency_index] = true;
            dependents[dependency_index].push(node_index);
            remaining[node_index] = remaining[node_index]
                .checked_add(1)
                .ok_or(ContractError::ArithmeticOverflow)?;
        }
    }
    let mut order = Vec::with_capacity(size);
    while order.len() < size {
        let mut selected = None;
        for index in 0..size {
            budget.charge(1)?;
            if !done[index] && remaining[index] == 0 {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or(ContractError::DependencyCycle)?;
        budget.charge(2)?;
        done[index] = true;
        order.push(sorted[index].step_id.clone());
        for dependent in &dependents[index] {
            budget.charge(2)?;
            remaining[*dependent] = remaining[*dependent]
                .checked_sub(1)
                .ok_or(ContractError::InvalidState)?;
        }
    }
    Ok(ValidatedDependencyGraph {
        order,
        total_cost_units: total_cost,
    })
}
