//! Physical hold checks for operation-owned nonce transitions.

use super::*;
use chio_kernel::admission_operation::AdmissionOperationV1;

pub(crate) enum NonceBudgetPhase {
    Authorized,
    Released,
}

/// A compensated operation cannot leave its executable hold authorized. The
/// check covers every structured hold the operation names; an operation whose
/// hold was never physically created has nothing to leak.
pub(crate) fn verify_compensated_budget_hold_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
) -> Result<(), BudgetStoreError> {
    let Some(hold_id) = operation.budget_hold_id() else {
        return Ok(());
    };
    if load_structured_hold(transaction, hold_id.as_str())?.is_none() {
        return Ok(());
    }
    verify_nonce_budget_phase_tx(transaction, operation, NonceBudgetPhase::Released)
}

pub(crate) fn verify_nonce_budget_phase_tx(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    phase: NonceBudgetPhase,
) -> Result<(), BudgetStoreError> {
    let hold_id = operation.budget_hold_id().ok_or_else(|| {
        BudgetStoreError::Invariant("nonce transition requires its budget hold".into())
    })?;
    let hold = load_structured_hold(transaction, hold_id.as_str())?.ok_or_else(|| {
        BudgetStoreError::Invariant("nonce transition lost its physical composite hold".into())
    })?;
    if hold.admission.operation_id != operation.binding().operation_id().as_str()
        || hold.capability_id != operation.binding().capability_id().as_str()
    {
        return Err(BudgetStoreError::Invariant(
            "nonce budget hold belongs to another operation".into(),
        ));
    }
    let valid = match phase {
        NonceBudgetPhase::Authorized => hold.invocation_state == BudgetInvocationState::Authorized,
        NonceBudgetPhase::Released => {
            hold.invocation_state == BudgetInvocationState::Reversed
                && hold.remaining_exposure == 0
                && matches!(
                    hold.monetary_state,
                    BudgetMonetaryState::None | BudgetMonetaryState::Reversed
                )
        }
    };
    if !valid {
        return Err(BudgetStoreError::Invariant(
            "nonce transition disagrees with physical budget disposition".into(),
        ));
    }
    Ok(())
}
