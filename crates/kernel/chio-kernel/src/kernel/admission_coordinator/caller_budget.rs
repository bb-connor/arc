//! Fenced caller-share views for sibling-budget admission.

use super::*;
use crate::admission_operation::AdmissionCallerBudgetShare;

// A complete snapshot is required. Excess occupancy denies admission rather
// than silently dropping reservations from sibling-sum accounting.
const MAX_CALLER_SHARES_PER_PARENT: usize = 16_384;

impl ChioKernel {
    pub(crate) fn load_durable_caller_budget_shares(
        &self,
        parent_id: &str,
    ) -> Result<Vec<AdmissionCallerBudgetShare>, String> {
        let Some(runtime) = &self.durable_admission_runtime else {
            return Ok(Vec::new());
        };
        let parent_id = AdmissionIdentifier::try_new("parent_id", parent_id.to_owned())
            .map_err(|error| error.to_string())?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let shares = runtime
            .store
            .load_caller_budget_shares(
                &parent_id,
                MAX_CALLER_SHARES_PER_PARENT,
                &runtime.fence,
                now,
            )
            .map_err(|error| error.to_string())?;
        let mut operations = std::collections::HashSet::new();
        if shares.len() > MAX_CALLER_SHARES_PER_PARENT
            || shares.iter().any(|share| {
                share.parent_id() != &parent_id || !operations.insert(share.operation_id().clone())
            })
        {
            return Err(
                "caller sibling-share snapshot is oversized, duplicated or misbound".into(),
            );
        }
        Ok(shares)
    }
}
