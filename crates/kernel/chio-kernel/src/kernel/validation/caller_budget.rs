//! Combine live evaluation leases with operation-owned caller shares.

use super::*;
use crate::admission_operation::{AdmissionCallerBudgetShare, AdmissionOperationV1};
use chio_kernel_core::BudgetRegistry;

impl ChioKernel {
    /// A funded caller operation owns its share through its executable hold,
    /// so it does not also take an ephemeral evaluation lease. Other dispatches
    /// take the ordinary lease after checking the complete combined view.
    /// The store snapshot follows executable-hold authorization: concurrent
    /// funded callers cannot both overlook each other's earlier committed hold.
    pub(crate) fn admit_capability_budget_for_dispatch(
        &self,
        cap: &CapabilityToken,
        operation: Option<&AdmissionOperationV1>,
    ) -> Result<bool, String> {
        let Some(parent) = cap.delegation_chain.last() else {
            return Ok(false);
        };
        self.enforce_restart_reserved_hold_gate()?;
        let proposed_share = cap
            .budget_share_bps
            .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS);
        let owner =
            operation.filter(|operation| AdmissionCallerBudgetShare::is_owned_by(operation));
        let mut budgets = self.budget_registry.lock().map_err(|_| {
            self.record_tcb_lock_poison("budget_registry");
            "budget registry lock poisoned; failing closed".to_string()
        })?;
        // Serialize the snapshot with local lease admission. Reading first
        // would let a delayed local evaluation overlook a caller reservation
        // admitted while that evaluation waited for this registry lock.
        let shares = self.load_durable_caller_budget_shares(&parent.capability_id)?;
        let owned_share = owner
            .map(|operation| -> Result<_, String> {
                let share = shares
                    .iter()
                    .find(|share| operation.binding().operation_id() == share.operation_id())
                    .ok_or_else(|| {
                        "funded caller operation is absent from its sibling-share snapshot"
                            .to_string()
                    })?;
                if share.child_id().as_str() != cap.id
                    || share.share_bps() != proposed_share
                    || share.is_reserved_for_caller() != operation.execution_nonce_id().is_some()
                {
                    return Err(
                        "caller sibling-share owner does not match the presented operation".into(),
                    );
                }
                Ok(share)
            })
            .transpose()?;
        let already_reserved =
            owned_share.is_some_and(AdmissionCallerBudgetShare::is_reserved_for_caller);
        let mut combined = budgets
            .split(&parent.capability_id)
            .cloned()
            .ok_or_else(|| {
                chio_kernel_core::BudgetSplitError::UnknownParent {
                    parent_token_id: parent.capability_id.clone(),
                }
                .to_string()
            })?;
        for share in &shares {
            // Reconciliation must preserve an established caller reservation.
            // A competing funded claim has not yet passed share admission and
            // cannot evict an existing owner. New admissions still count every
            // pending claim, and every path counts all established owners.
            if already_reserved && !share.is_reserved_for_caller() {
                continue;
            }
            combined
                .verify_child_admission(share.child_id().as_str().to_owned(), share.share_bps())
                .map_err(|error| error.to_string())?;
        }
        combined
            .verify_child_admission(cap.id.clone(), proposed_share)
            .map_err(|error| error.to_string())?;
        if owned_share.is_some() {
            return Ok(false);
        }
        budgets
            .try_admit_child(&parent.capability_id, cap.id.clone(), proposed_share)
            .map_err(|error| error.to_string())?;
        Ok(true)
    }
}
