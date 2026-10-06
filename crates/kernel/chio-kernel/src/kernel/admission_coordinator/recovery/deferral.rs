//! Fenced item deferrals preserve the operation and never mark effects complete.

use super::*;
use crate::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralV1, AdmissionRecoveryDeferralWrite,
    AdmissionRecoveryStatusV1,
};

impl ChioKernel {
    pub(super) fn defer_admission_recovery(
        &self,
        operation: &AdmissionOperationV1,
        previous: Option<&AdmissionRecoveryStatusV1>,
        error: &KernelError,
        now: u64,
    ) -> Result<(), KernelError> {
        let kind = failure::classify(error).ok_or_else(|| {
            KernelError::DurableAdmission("unclassified recovery failure cannot be deferred".into())
        })?;
        let runtime = self.durable_runtime()?;
        let current = runtime
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                durable_store_error(
                    crate::admission_operation::AdmissionOperationStoreError::NotFound,
                )
            })?;
        if current.state().is_terminal() {
            if let Some(previous) = previous {
                self.clear_admission_recovery_deferral(&current, previous, now)?;
            }
            return Ok(());
        }
        let deferral = AdmissionRecoveryDeferralV1::after_failure(
            &current,
            previous.map(|previous| &previous.deferral),
            operation::phase(&current),
            kind,
            AdmissionDigest::try_new(
                "recovery_diagnostic_digest",
                sha256_hex(error.to_string().as_bytes()),
            )?,
            now,
        )
        .map_err(durable_store_error)?;
        let lease = self.claim_admission_recovery(&current, now)?;
        let stored_status = runtime
            .store
            .defer_recovery(AdmissionRecoveryDeferralWrite {
                operation: &current,
                lease: &lease,
                expected: previous,
                deferral: &deferral,
                fence: &runtime.fence,
                trusted_now_unix_ms: now,
            })
            .map_err(failure::port_error)?;
        warn!(operation_id = %current.binding().operation_id().as_str(),
            phase = ?stored_status.deferral.phase, failure_kind = ?stored_status.deferral.failure_kind,
            retry_not_before_unix_ms = stored_status.deferral.retry_not_before_unix_ms,
            reason = %redacted!(error), "retained admission recovery deferred");
        Ok(())
    }

    pub(super) fn clear_admission_recovery_deferral(
        &self,
        operation: &AdmissionOperationV1,
        previous: &AdmissionRecoveryStatusV1,
        now: u64,
    ) -> Result<(), KernelError> {
        if !previous.quarantined {
            return Ok(());
        }
        let runtime = self.durable_runtime()?;
        let lease = if operation.state().is_terminal() {
            None
        } else {
            Some(self.claim_admission_recovery(operation, now)?)
        };
        runtime
            .store
            .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
                operation,
                lease: lease.as_ref(),
                expected: previous,
                fence: &runtime.fence,
                trusted_now_unix_ms: now,
            })
            .map_err(failure::port_error)
    }
}
