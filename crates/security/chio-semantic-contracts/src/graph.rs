//! Bounded symbolic dependency graphs of registered remedy templates.
use alloc::{vec, vec::Vec};
use chio_security_types::recovery::{
    BoundedList, ContractError, NonEmptyBoundedList, SafeInteger, StepId, TemplateId, VersionV1,
};
use chio_security_types::work::VerificationBudget;
use serde::{Deserialize, Serialize};

pub const MAX_DEPENDENCY_GRAPH_NODES: usize = 16;
pub const MAX_NODE_DEPENDENCIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependencyGraphSchema {
    #[serde(rename = "chio.recovery.dependency-graph.v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyGraphV1 {
    pub schema: DependencyGraphSchema,
    pub version: VersionV1,
    pub nodes: NonEmptyBoundedList<DependencyNodeV1, MAX_DEPENDENCY_GRAPH_NODES>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyNodeV1 {
    pub step_id: StepId,
    pub template_id: TemplateId,
    pub dependencies: BoundedList<StepId, MAX_NODE_DEPENDENCIES>,
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

/// Stable topological order: among ready steps, the bytewise smallest opaque
/// step identifier comes first. The bounded sort, every edge lookup, every
/// indexed update and every ready-step search charge the shared meter before
/// the work runs.
///
/// Refusals: `DuplicateIdentity` for a repeated step or a repeated dependency
/// of one step, `MissingDependency` for an unknown dependency,
/// `DependencyCycle` when no step is ready, `ArithmeticOverflow` when the total
/// cost leaves the safe integer range and `WorkBudgetExceeded` on exhaustion.
pub fn validate_dependency_graph(
    nodes: &NonEmptyBoundedList<DependencyNodeV1, MAX_DEPENDENCY_GRAPH_NODES>,
    budget: &mut VerificationBudget,
) -> Result<ValidatedDependencyGraph, ContractError> {
    let size = nodes.as_slice().len();
    let sorting_work = size
        .checked_mul(size)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(ContractError::ArithmeticOverflow)?;
    budget.charge(sorting_work)?;
    let mut sorted: Vec<&DependencyNodeV1> = nodes.as_slice().iter().collect();
    sorted.sort_by(|a, b| a.step_id.cmp(&b.step_id));
    if sorted
        .windows(2)
        .any(|pair| matches!(pair, [first, second] if first.step_id == second.step_id))
    {
        return Err(ContractError::DuplicateIdentity);
    }
    let size_work = u32::try_from(size).map_err(|_| ContractError::ArithmeticOverflow)?;
    budget.charge(
        size_work
            .checked_mul(3)
            .ok_or(ContractError::ArithmeticOverflow)?,
    )?;
    let mut remaining = vec![0usize; size];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); size];
    let mut done = vec![false; size];
    let search_work = size_work
        .checked_next_power_of_two()
        .ok_or(ContractError::ArithmeticOverflow)?
        .ilog2()
        .checked_add(1)
        .ok_or(ContractError::ArithmeticOverflow)?;
    let mut total_cost = SafeInteger::ZERO;
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
            let observed = seen
                .get_mut(dependency_index)
                .ok_or(ContractError::InvalidState)?;
            if *observed {
                return Err(ContractError::DuplicateIdentity);
            }
            *observed = true;
            dependents
                .get_mut(dependency_index)
                .ok_or(ContractError::InvalidState)?
                .push(node_index);
            let pending = remaining
                .get_mut(node_index)
                .ok_or(ContractError::InvalidState)?;
            *pending = pending
                .checked_add(1)
                .ok_or(ContractError::ArithmeticOverflow)?;
        }
    }
    let mut order = Vec::with_capacity(size);
    while order.len() < size {
        let mut selected = None;
        for (index, (finished, pending)) in done.iter().zip(&remaining).enumerate() {
            budget.charge(1)?;
            if !finished && *pending == 0 {
                selected = Some(index);
                break;
            }
        }
        let index = selected.ok_or(ContractError::DependencyCycle)?;
        budget.charge(2)?;
        *done.get_mut(index).ok_or(ContractError::InvalidState)? = true;
        order.push(
            sorted
                .get(index)
                .ok_or(ContractError::InvalidState)?
                .step_id
                .clone(),
        );
        for dependent in dependents.get(index).ok_or(ContractError::InvalidState)? {
            budget.charge(2)?;
            let pending = remaining
                .get_mut(*dependent)
                .ok_or(ContractError::InvalidState)?;
            *pending = pending.checked_sub(1).ok_or(ContractError::InvalidState)?;
        }
    }
    Ok(ValidatedDependencyGraph {
        order,
        total_cost_units: total_cost,
    })
}
