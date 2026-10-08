//! The issuing port is the Kernel's actual qualified durable store.
use super::*;
use crate::process_return_custody::{
    FundedProcessNativeReturn, FundedProcessOriginalNonce, FundedProcessReturnEnrollment,
    NativeProcessReturnCustodyPort, ProcessNativeReturnCaptureDataV1,
    ProcessOriginalNonceCustodyDataV1, ProcessReturnFundingDataV1,
    ProcessReturnReconciliationDataV1, ProcessReturnSourceDataV1, ReconciledProcessNativeReturn,
};

struct OriginalStorePort<'a> {
    store: &'a dyn QualifiedAdmissionOperationStore,
}
impl NativeProcessReturnCustodyPort for OriginalStorePort<'_> {
    fn verify_original_process_return_enrollment(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ProcessReturnFundingDataV1, crate::admission_operation::AdmissionOperationStoreError>
    {
        self.store
            .verify_original_process_return_enrollment(source, fence, now)
    }
    fn verify_original_process_nonce_custody(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        ProcessOriginalNonceCustodyDataV1,
        crate::admission_operation::AdmissionOperationStoreError,
    > {
        self.store
            .verify_original_process_nonce_custody(source, fence, now)
    }
    fn verify_original_process_return_capture(
        &self,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        ProcessNativeReturnCaptureDataV1,
        crate::admission_operation::AdmissionOperationStoreError,
    > {
        self.store
            .verify_original_process_return_capture(source, fence, now)
    }
    fn verify_original_process_return_reconciliation(
        &self,
        source: &ProcessReturnSourceDataV1,
        receipt: &str,
        sequence: u64,
        event: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        ProcessReturnReconciliationDataV1,
        crate::admission_operation::AdmissionOperationStoreError,
    > {
        self.store.verify_original_process_return_reconciliation(
            source, receipt, sequence, event, fence, now,
        )
    }
}

impl ChioKernel {
    pub fn original_funded_process_return_enrollment(
        &self,
        source: &ProcessReturnSourceDataV1,
    ) -> Result<FundedProcessReturnEnrollment, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        FundedProcessReturnEnrollment::from_original_native_source(
            &OriginalStorePort {
                store: runtime.store.as_ref(),
            },
            source,
            &runtime.fence,
            now,
        )
        .map_err(unavailable)
    }
    pub fn original_funded_process_nonce_custody(
        &self,
        source: &ProcessReturnSourceDataV1,
    ) -> Result<FundedProcessOriginalNonce, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        FundedProcessOriginalNonce::from_original_native_source(
            &OriginalStorePort {
                store: runtime.store.as_ref(),
            },
            source,
            &runtime.fence,
            now,
        )
        .map_err(unavailable)
    }
    pub fn original_funded_process_native_return(
        &self,
        source: &ProcessReturnSourceDataV1,
    ) -> Result<FundedProcessNativeReturn, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        FundedProcessNativeReturn::from_original_native_source(
            &OriginalStorePort {
                store: runtime.store.as_ref(),
            },
            source,
            &runtime.fence,
            now,
        )
        .map_err(unavailable)
    }
    pub fn original_reconciled_process_native_return(
        &self,
        source: &ProcessReturnSourceDataV1,
        receipt: &str,
        sequence: u64,
        event: &str,
    ) -> Result<ReconciledProcessNativeReturn, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        ReconciledProcessNativeReturn::from_original_native_source(
            &OriginalStorePort {
                store: runtime.store.as_ref(),
            },
            source,
            receipt,
            sequence,
            event,
            &runtime.fence,
            now,
        )
        .map_err(unavailable)
    }
}

fn unavailable(_error: crate::admission_operation::AdmissionOperationStoreError) -> KernelError {
    KernelError::DurableAdmission("original funded Process custody unavailable".into())
}
