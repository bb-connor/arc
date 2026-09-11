//! Read a complete delegated caller-share view from retained operations.

use super::*;
use chio_kernel::admission_operation::AdmissionCallerBudgetShare;

impl SqliteAdmissionOperationStore {
    pub(super) fn caller_budget_shares(
        &self,
        parent_id: &AdmissionIdentifier,
        limit: usize,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&transaction, now)?;
        let mut shares = Vec::new();
        {
            let mut statement = transaction
                .prepare(
                    "SELECT operation_id FROM admission_operations
                 WHERE terminal = 0 OR state = 'outcome_unknown_after_dispatch'
                 ORDER BY operation_id",
                )
                .map_err(sqlite_error)?;
            let mut rows = statement.query([]).map_err(sqlite_error)?;
            while let Some(row) = rows.next().map_err(sqlite_error)? {
                let id = AdmissionOperationId::from_persisted(
                    row.get::<_, String>(0).map_err(sqlite_error)?,
                )?;
                let stored = load_by_operation_id_tx(&transaction, &id)?.ok_or_else(|| {
                    invariant("caller share operation disappeared in its snapshot")
                })?;
                stored.verify_decision_time(now)?;
                if !AdmissionCallerBudgetShare::is_owned_by(&stored.operation) {
                    continue;
                }
                let retained =
                    retained_request::load_retained_request_tx(&transaction, &stored.operation)?
                        .ok_or_else(|| {
                            invariant("funded caller share lost its retained request")
                        })?;
                if let Some(share) = AdmissionCallerBudgetShare::from_retained_operation(
                    &stored.operation,
                    &retained,
                )? {
                    if share.parent_id() == parent_id {
                        if shares.len() == limit {
                            return Err(invariant(
                                "caller sibling-share snapshot exceeds its bound",
                            ));
                        }
                        shares.push(share);
                    }
                }
            }
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(shares)
    }
}
