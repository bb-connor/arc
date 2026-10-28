//! Semantic plan structure, independent of execution.
use crate::work::units;
use alloc::vec::Vec;
use chio_security_types::recovery::{ContractError, StepId};
use chio_security_types::semantic::{SemanticPlanInputV1, SemanticPlanV1};
use chio_security_types::work::VerificationBudget;

/// Stable bounded order: each round appends every ready step in identifier
/// order. The order is an explanation, never an execution permit.
///
/// Refusals: `DuplicateIdentity` for a repeated step or repeated dependency,
/// `MissingDependency` for an unknown dependency or a future input from an
/// undeclared step, `DependencyCycle` when a round has no ready step and
/// `WorkBudgetExceeded` on exhaustion.
pub fn validate_semantic_plan(
    plan: &SemanticPlanV1,
    budget: &mut VerificationBudget,
) -> Result<Vec<StepId>, ContractError> {
    let nodes = plan.steps.as_slice();
    for (index, node) in nodes.iter().enumerate() {
        budget.charge(units(&[index, 1])?)?;
        if nodes
            .iter()
            .take(index)
            .any(|prior| prior.step == node.step)
        {
            return Err(ContractError::DuplicateIdentity);
        }
        let dependencies = node.dependencies.as_slice();
        for (edge, dependency) in dependencies.iter().enumerate() {
            budget.charge(units(&[nodes.len(), edge, 1])?)?;
            if !nodes.iter().any(|candidate| candidate.step == *dependency) {
                return Err(ContractError::MissingDependency);
            }
            if dependencies
                .iter()
                .take(edge)
                .any(|prior| prior == dependency)
            {
                return Err(ContractError::DuplicateIdentity);
            }
        }
        for input in node.inputs.as_slice() {
            budget.charge(units(&[dependencies.len(), 1])?)?;
            if let SemanticPlanInputV1::FutureOutput { step } = input {
                if !dependencies.contains(step) {
                    return Err(ContractError::MissingDependency);
                }
            }
        }
    }
    let mut order = Vec::new();
    while order.len() < nodes.len() {
        let mut ready = Vec::new();
        for node in nodes {
            budget.charge(units(&[
                order.len(),
                node.dependencies.as_slice().len(),
                1,
            ])?)?;
            if !order.contains(&node.step)
                && node
                    .dependencies
                    .as_slice()
                    .iter()
                    .all(|step| order.contains(step))
            {
                ready.push(node.step.clone());
            }
        }
        if ready.is_empty() {
            return Err(ContractError::DependencyCycle);
        }
        let sorting = ready
            .len()
            .checked_mul(ready.len())
            .ok_or(ContractError::ArithmeticOverflow)?;
        budget.charge(units(&[sorting, 1])?)?;
        ready.sort();
        order.extend(ready);
    }
    Ok(order)
}
