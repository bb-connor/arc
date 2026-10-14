//! Operation-bound durable payment journal loading and transitions.

use super::*;

impl ChioKernel {
    pub(crate) fn load_durable_payment_journal(
        &self,
        admission: &DurableToolAdmission,
    ) -> Result<crate::payment::PaymentJournalRecord, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let journal = runtime
            .store
            .load_payment_journal(admission.operation_id(), &runtime.fence)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable payment participant is absent for the admission operation".to_owned(),
                )
            })?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.operation_id != admission.operation_id() {
            return Err(KernelError::DurableAdmission(
                "durable payment participant changed operation identity".to_owned(),
            ));
        }
        Ok(journal)
    }

    pub(crate) fn advance_durable_payment_journal(
        &self,
        admission: &DurableToolAdmission,
        expected: &crate::payment::PaymentJournalRecord,
        transition: &crate::payment::PaymentJournalTransition,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::payment::PaymentJournalRecord, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        // The recovery claim commits only with the funded journal write it
        // authorizes; an exact replay persists neither.
        let claim =
            Self::recovery_claim_request(runtime, &admission.operation, trusted_now_unix_ms)?;
        let (journal, _) = runtime
            .store
            .claim_and_advance_payment_journal(
                crate::receipt_store::AdmissionPaymentJournalClaim {
                    claim,
                    operation: &admission.operation,
                    expected,
                    transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                },
                &mut crate::admission_operation::qualified_lease(claim, trusted_now_unix_ms),
            )
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        Ok(journal)
    }
}
