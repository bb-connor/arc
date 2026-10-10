use crate::VerificationBudget;
use alloc::vec::Vec;
use chio_security_types::{recovery::*, semantic::*};

/// Stable bounded order is an explanation, never an execution permit.
pub fn validate_semantic_plan(
    plan: &SemanticPlanV1,
    budget: &mut VerificationBudget,
) -> Result<Vec<StepId>, ContractError> {
    let nodes = plan.steps.as_slice();
    // Retained predecessor plans remain structurally readable at sixteen, but
    // fresh acceptance never exceeds the protocol's eight top-level steps.
    if nodes.len() > 8 {
        return Err(ContractError::LimitExceeded);
    }
    for (index, node) in nodes.iter().enumerate() {
        budget.charge((index + 1) as u32)?;
        if nodes[..index].iter().any(|prior| prior.step == node.step) {
            return Err(ContractError::DuplicateIdentity);
        }
        for (edge, dependency) in node.dependencies.as_slice().iter().enumerate() {
            budget.charge((nodes.len() + edge + 1) as u32)?;
            if !nodes.iter().any(|candidate| candidate.step == *dependency) {
                return Err(ContractError::MissingDependency);
            }
            if node.dependencies.as_slice()[..edge].contains(dependency) {
                return Err(ContractError::DuplicateIdentity);
            }
        }
        for input in node.inputs.as_slice() {
            budget.charge(node.dependencies.as_slice().len() as u32 + 1)?;
            if let SemanticPlanInputV1::FutureOutput { step } = input {
                if !node.dependencies.as_slice().contains(step) {
                    return Err(ContractError::MissingDependency);
                }
            }
        }
    }
    let mut order = Vec::new();
    while order.len() < nodes.len() {
        let mut ready = Vec::new();
        for node in nodes {
            budget.charge((order.len() + node.dependencies.as_slice().len() + 1) as u32)?;
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
        budget.charge((ready.len() * ready.len() + 1) as u32)?;
        ready.sort();
        order.extend(ready);
    }
    Ok(order)
}
