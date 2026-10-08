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
            .map_err(KernelError::admission)?
            .ok_or_else(|| {
                KernelError::admission_record(
                    "durable payment participant is absent for the admission operation",
                )
            })?;
        journal.validate().map_err(KernelError::admission)?;
        if journal.operation_id != admission.operation_id() {
            return Err(KernelError::admission_record(
                "durable payment participant changed operation identity",
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
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms)?;
        let recovery_lease =
            self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let journal = runtime
            .store
            .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                operation: &admission.operation,
                recovery_lease: &recovery_lease,
                expected,
                transition,
                release_evidence: None,
                active_fence: &runtime.fence,
                trusted_now_unix_ms,
            })
            .map_err(KernelError::admission)?;
        journal.validate().map_err(KernelError::admission)?;
        Ok(journal)
    }
}
