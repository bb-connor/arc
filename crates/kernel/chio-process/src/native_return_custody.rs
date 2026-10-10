//! Second-database participant contracts. Cost DATA is not a bank allowance.
use crate::{ProcessError, ProcessRuntime};
use chio_kernel::process_return_custody::{
    FundedProcessNativeReturn, FundedProcessOriginalNonce, FundedProcessReturnEnrollment,
    ProcessReturnSourceDataV1, ProcessReturnUnavailableReasonDataV1, ReconciledProcessNativeReturn,
};
use chio_kernel::{SecurityInvocationContext, ToolCallRequest};

pub use crate::store::native_return_custody::{
    ProcessFinishingTransactionPriceData, ProcessReturnRowEnvelopeData, ProcessReturnTableData,
    ProcessReturnTransactionData,
};

/// The actual Process factory owns this capsule. It exposes descriptive DATA
/// and no constructor, clone, deserializer, connection or mutation callback.
/// Native pricing still requires the borrowed actual Process source cut.
pub struct PreparedProcessReturnParticipant {
    pub(crate) original: crate::store::native_return_custody::PreparedProcessReturnSource,
}
impl PreparedProcessReturnParticipant {
    pub fn source(&self) -> &ProcessReturnSourceDataV1 {
        self.original.data()
    }
    pub fn canonical_source_bytes(&self) -> &[u8] {
        self.original.canonical_bytes()
    }
}
impl core::fmt::Debug for PreparedProcessReturnParticipant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparedProcessReturnParticipant([redacted])")
    }
}

pub struct ProcessReturnAccountCustody {
    original: crate::store::native_return_custody::RetainedProcessReturnAccount,
}
pub struct ProcessReturnReceiptCustody {
    original: crate::store::native_return_custody::RetainedProcessReturnReceipt,
}

impl ProcessRuntime {
    /// Effect-free source inspection. Amounts are DATA and cannot enroll a
    /// bank, authorize a capture or consume any future producer allowance.
    pub fn inspect_original_return_finishing_prices(
        &self,
        source: &PreparedProcessReturnParticipant,
    ) -> Result<Vec<ProcessFinishingTransactionPriceData>, ProcessError> {
        self.with_store(|store| store.inspect_original_return_finishing_prices(&source.original))
    }

    pub fn retain_original_return_unavailable(
        &self,
        account: &ProcessReturnAccountCustody,
        reason: ProcessReturnUnavailableReasonDataV1,
    ) -> Result<(), ProcessError> {
        self.with_store(|store| store.retain_original_return_unavailable(&account.original, reason))
    }

    pub fn retain_original_funded_nonce_custody(
        &self,
        account: &ProcessReturnAccountCustody,
        nonce: FundedProcessOriginalNonce,
    ) -> Result<(), ProcessError> {
        self.with_store(|store| store.retain_funded_original_nonce(&account.original, nonce))
    }

    /// The source is obtained before native authorization from the actual
    /// retained call. Invocation attribution JSON alone cannot attach it.
    pub fn prepare_original_native_return_participant(
        &self,
        process: &str,
        operation: &str,
        request: &ToolCallRequest,
        known_outcome_only: bool,
        context: Option<&SecurityInvocationContext>,
    ) -> Result<PreparedProcessReturnParticipant, ProcessError> {
        let binding = self.derive_call_binding(process, operation, request, known_outcome_only)?;
        let original = self.with_store(|store| {
            store.prepare_native_return_source(
                self,
                process,
                operation,
                request,
                &binding,
                known_outcome_only,
                context,
            )
        })?;
        Ok(PreparedProcessReturnParticipant { original })
    }

    /// Only the actual durable native Prepared account mints this input proof.
    /// A descriptive funding record cannot enter this producer.
    pub fn enroll_original_native_return_participant(
        &self,
        source: &PreparedProcessReturnParticipant,
        funding: FundedProcessReturnEnrollment,
    ) -> Result<ProcessReturnAccountCustody, ProcessError> {
        let original =
            self.with_store(|store| store.enroll_funded_native_return(&source.original, funding))?;
        Ok(ProcessReturnAccountCustody { original })
    }

    /// Reconcile owed capture custody before checking current Process liveness
    /// or returning a Kernel error. The actual original native proof owns this
    /// historical write. No new dispatch actor or output resend is requested.
    pub fn retain_original_native_return_custody(
        &self,
        account: &ProcessReturnAccountCustody,
        capture: FundedProcessNativeReturn,
    ) -> Result<ProcessReturnReceiptCustody, ProcessError> {
        let original =
            self.with_store(|store| store.record_funded_native_return(&account.original, capture))?;
        Ok(ProcessReturnReceiptCustody { original })
    }

    pub fn reconcile_original_native_return_custody(
        &self,
        account: &ProcessReturnAccountCustody,
        receipt: &ProcessReturnReceiptCustody,
        reconciliation: ReconciledProcessNativeReturn,
    ) -> Result<(), ProcessError> {
        self.with_store(|store| {
            store.reconcile_funded_native_return(
                &account.original,
                &receipt.original,
                reconciliation,
            )
        })
    }
}
