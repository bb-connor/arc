//! Fenced observation of an admission's original composite hold.
use super::*;
use chio_kernel::budget_store::{
    BudgetAdmissionBinding, BudgetInvocationQuota, BudgetInvocationState, BudgetMonetaryState,
};

/// Physical custody at one anchored read. This observation grants no authority
/// to authorize, capture, reverse or refund the original hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionBudgetCustodySnapshot {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: usize,
    pub admission: BudgetAdmissionBinding,
    pub invocation_quotas: Vec<BudgetInvocationQuota>,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
}

impl SqliteAdmissionOperationStore {
    pub fn load_admission_budget_custody(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionBudgetCustodySnapshot>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let snapshot = crate::budget_store::SqliteBudgetStore::load_admission_budget_custody_tx(
            &transaction,
            &stored.operation,
        )
        .map_err(|error| invariant(error.to_string()))?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }
}
