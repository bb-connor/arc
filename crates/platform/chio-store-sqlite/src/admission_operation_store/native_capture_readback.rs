//! Independent, fenced readback of the committed native budget participant.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Read the original capture decision and current operation in one anchored
    /// snapshot. This never refreshes policy, reacquires custody or executes.
    pub fn load_native_dispatch_capture(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<chio_kernel::AdmissionBudgetCapture>, AdmissionOperationStoreError> {
        let capture = {
            let mut connection = self.connection()?;
            let transaction = self.begin_read(&mut connection)?;
            verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
            verify_trusted_time(&transaction, trusted_now_unix_ms)?;
            let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? else {
                return Ok(None);
            };
            stored.verify_decision_time(trusted_now_unix_ms)?;
            if stored.operation.native_dispatch_ledger_digest().is_none() {
                return Ok(None);
            }
            let original =
                retained_request::load_retained_request_tx(&transaction, &stored.operation)?
                    .ok_or_else(|| {
                        invariant("native capture readback lost its original request")
                    })?;
            if original.native_security_authority_binding().is_none() {
                return Err(invariant(
                    "native capture readback lost its original authority",
                ));
            }
            let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
                self.connection.clone(),
                self.serving_owner.clone(),
            );
            let decision = budget
                .load_native_capture_decision_tx(&transaction, &stored.operation, &original)
                .map_err(|error| invariant(error.to_string()))?;
            chio_kernel::AdmissionBudgetCapture {
                decision: chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(
                    decision,
                ),
                operation: stored.operation,
            }
        };
        #[cfg(feature = "admission-test-support")]
        {
            self.native_capture_readback_for_test(capture)
        }
        #[cfg(not(feature = "admission-test-support"))]
        {
            Ok(Some(capture))
        }
    }
}
