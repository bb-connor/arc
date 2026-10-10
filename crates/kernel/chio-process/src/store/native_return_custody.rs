//! Source-owned second-database return accounting. Activation remains closed.
use super::*;
use crate::binding::ProcessCallBinding;
use crate::ProcessRuntime;
use chio_kernel::process_return_custody::{
    FundedProcessNativeReturn, FundedProcessOriginalNonce, FundedProcessReturnEnrollment,
    ProcessNativeReturnCaptureDataV1, ProcessReturnSourceDataV1,
    ProcessReturnUnavailableReasonDataV1, ReconciledProcessNativeReturn,
    MAX_PROCESS_RETURN_SOURCE_BYTES,
};
use rusqlite::Transaction;

mod catalog;
mod pricing;
mod rows;
mod source;
#[cfg(test)]
mod tests;
pub use pricing::ProcessFinishingTransactionPriceData;
pub use rows::{
    ProcessReturnRowEnvelopeData, ProcessReturnTableData, ProcessReturnTransactionData,
};

const MAX_SOURCE_BYTES: usize = MAX_PROCESS_RETURN_SOURCE_BYTES;
const MAX_ACCOUNT_BYTES: usize = 32_768;
const MAX_RECEIPT_BYTES: usize = 8_192;
const MAX_EVENT_BYTES: usize = 512;
const MAX_ACTIVE_ACCOUNTS: u64 = 64;

/// This opaque producer capsule describes original source DATA. Its cut must
/// be revalidated inside the actual source transaction before native pricing.
/// It is not a bank allowance, permission to capture or retirement evidence.
pub(crate) struct PreparedProcessReturnSource {
    data: ProcessReturnSourceDataV1,
    bytes: Vec<u8>,
    profile: catalog::ProcessWriteProfileData,
    kernel_key: String,
    path: std::path::PathBuf,
    prepared_connection: usize,
    prepared_total_changes: u64,
    rows_digest: String,
}
impl PreparedProcessReturnSource {
    pub(crate) fn data(&self) -> &ProcessReturnSourceDataV1 {
        &self.data
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn profile(&self) -> &catalog::ProcessWriteProfileData {
        &self.profile
    }
}
impl core::fmt::Debug for PreparedProcessReturnSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PreparedProcessReturnSource([redacted])")
    }
}

impl Store {
    pub(crate) fn inspect_original_return_finishing_prices(
        &mut self,
        source: &PreparedProcessReturnSource,
    ) -> Result<Vec<ProcessFinishingTransactionPriceData>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prices = pricing::price_future_finishing_transactions(&tx, source)?;
        tx.rollback()?;
        Ok(prices)
    }

    pub(crate) fn retain_original_return_unavailable(
        &mut self,
        _original_account: &RetainedProcessReturnAccount,
        _reason: ProcessReturnUnavailableReasonDataV1,
    ) -> Result<(), ProcessError> {
        // Only the retained original account owns its single prepaid notice.
        // This neither retires the account nor drops any later output debt.
        Err(ProcessError::Configuration(
            "Process original unavailable return writer has not been installed",
        ))
    }

    pub(crate) fn retain_funded_original_nonce(
        &mut self,
        _original_account: &RetainedProcessReturnAccount,
        _nonce: FundedProcessOriginalNonce,
    ) -> Result<(), ProcessError> {
        Err(ProcessError::Configuration(
            "Process original funded nonce writer has not been installed",
        ))
    }

    pub(crate) fn enroll_funded_native_return(
        &mut self,
        _source: &PreparedProcessReturnSource,
        _funding: FundedProcessReturnEnrollment,
    ) -> Result<RetainedProcessReturnAccount, ProcessError> {
        Err(ProcessError::Configuration(
            "Process original funded enrollment writer has not been installed",
        ))
    }

    pub(crate) fn prepare_native_return_source(
        &mut self,
        runtime: &ProcessRuntime,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
        binding: &ProcessCallBinding,
        known_outcome_only: bool,
        security_context: Option<&chio_kernel::SecurityInvocationContext>,
    ) -> Result<PreparedProcessReturnSource, ProcessError> {
        source::verify_source_request(
            self,
            runtime,
            process_id,
            operation_key,
            request,
            binding,
            known_outcome_only,
            security_context,
        )?;
        // This is the genuine source-entry RED seam. Installation, physical
        // pricing, all writer preservation and native bank enrollment are
        // separately owned dependencies, not shortcuts from valid request DATA.
        Err(ProcessError::Configuration(
            "Process original return source has not been installed",
        ))
    }

    pub(crate) fn record_funded_native_return(
        &mut self,
        _original_account: &RetainedProcessReturnAccount,
        _capture: FundedProcessNativeReturn,
    ) -> Result<RetainedProcessReturnReceipt, ProcessError> {
        // Owning RED requires genuine native capture and bank enrollment before
        // this body can activate. A decoded ToolCallResponse is not accepted.
        Err(ProcessError::Configuration(
            "Process funded return writer has not been installed",
        ))
    }

    pub(crate) fn reconcile_funded_native_return(
        &mut self,
        _original_account: &RetainedProcessReturnAccount,
        _final_receipt: &RetainedProcessReturnReceipt,
        _reconciliation: ReconciledProcessNativeReturn,
    ) -> Result<(), ProcessError> {
        Err(ProcessError::Configuration(
            "Process return reconciliation writer has not been installed",
        ))
    }
}

/// Minted only by the owning Process enrollment transaction after its real
/// physical allowance and original native account are verified. No constructor
/// or wire decoding is exposed. The target scaffold cannot mint one yet.
pub(crate) struct RetainedProcessReturnAccount {
    source: ProcessReturnSourceDataV1,
    account_digest: String,
    original_event_sequence: u64,
    original_event_digest: String,
}

pub(crate) struct RetainedProcessReturnReceipt {
    account_digest: String,
    receipt: ProcessNativeReturnCaptureDataV1,
    final_event_sequence: u64,
    final_event_digest: String,
}

/// No absence-to-zero path. An uninstalled or incomplete bank refuses before
/// generic Process writers can promise that they preserve finishing liability.
pub(super) fn require_current_writer_preserves_process_return_debt(
    _tx: &Transaction<'_>,
) -> Result<(), ProcessError> {
    Err(ProcessError::Configuration(
        "Process full finishing debt preservation is unavailable",
    ))
}
