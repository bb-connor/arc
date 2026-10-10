//! Original second-database finishing custody. Wire records are DATA.
use crate::admission_operation::{AdmissionOperationStoreError, StoreMutationFence};
use serde::{Deserialize, Serialize};

mod bank;
pub use bank::*;

pub const PROCESS_RETURN_SOURCE_SCHEMA: &str = "chio.process-native-return-source.v1";
pub const PROCESS_RETURN_FUNDING_SCHEMA: &str = "chio.process-native-return-funding.v1";
pub const PROCESS_RETURN_CAPTURE_SCHEMA: &str = "chio.process-native-return-capture.v1";
pub const PROCESS_RETURN_RECONCILIATION_SCHEMA: &str =
    "chio.process-native-return-reconciliation.v1";
pub const PROCESS_ORIGINAL_NONCE_CUSTODY_SCHEMA: &str = "chio.process-original-nonce-custody.v1";
pub const PROCESS_RETURN_UNAVAILABLE_SCHEMA: &str = "chio.process-native-return-unavailable.v1";
pub const MAX_PROCESS_RETURN_SOURCE_BYTES: usize = 16_384;
pub const MAX_PROCESS_RETURN_FUNDING_BYTES: usize = 8_192;
pub const MAX_PROCESS_RETURN_RECEIPT_BYTES: usize = 8_192;
pub const MAX_PROCESS_NONCE_RECEIPT_BYTES: usize = 32_768;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

/// A sequence is meaningful only under its producing journal domain. Native
/// bank slot counters cannot be substituted for an authority-global receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum NativeReturnSequenceDomainDataV1 {
    #[default]
    #[serde(rename = "chio.authority-global-commit.v1")]
    AuthorityGlobalCommit,
}

/// The Process producer's complete selected call. Decoding this does not prove
/// its journal source, physical price, bank funding or native capture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnSourceDataV1 {
    pub schema: String,
    pub journal_namespace: String,
    pub journal_authority: String,
    pub kernel_key_digest: String,
    pub file_device: u64,
    pub file_inode: u64,
    pub catalog_digest: String,
    pub cut_digest: String,
    pub process_id: String,
    pub root_process_id: String,
    pub operation_key: String,
    pub request_id: String,
    pub attempt: u32,
    pub logical_request_digest: String,
    pub call_binding_digest: String,
    pub current_request_digest: String,
    pub capability_digest: String,
    pub known_outcome_only: bool,
    pub host_profile_digest: Option<String>,
    pub host_route_digest: Option<String>,
    pub launch_receipt_digest: Option<String>,
    pub security_context_digest: Option<String>,
    pub original_nonce_pending: bool,
    pub original_nonce_digest: Option<String>,
}

/// Original native before-effect enrollment, returned as descriptive DATA by
/// the bank's owning source verifier. No public value constructs its loan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnFundingDataV1 {
    pub schema: String,
    pub process_source_digest: String,
    pub process_account_digest: String,
    pub native_operation_id: String,
    pub native_request_binding_digest: String,
    pub native_account_digest: String,
    pub native_account_sequence: u64,
    pub native_account_sequence_domain: NativeReturnSequenceDomainDataV1,
    pub native_bank_epoch: u64,
    pub original_native_source_epoch_digest: String,
    pub original_store_uuid: String,
    pub original_store_lease_id: String,
    pub original_store_lease_epoch: u64,
    pub original_coordinator_lease_id: String,
    pub original_coordinator_lease_epoch: u64,
    pub original_profile_digest: String,
    pub original_actor_digest: String,
    pub original_context_digest: String,
    pub original_role_map_digest: String,
    pub physical_recipe_digest: String,
    pub process_future_transactions_digest: String,
    // Preserve the exact pre-publication v1 encoding when reading legacy DATA.
    // Such DATA can never satisfy the scoped bank's publication requirement.
    #[serde(
        default,
        skip_serializing_if = "ProcessNativeAccountPublicationDataV1::is_absent"
    )]
    pub original_native_publication: ProcessNativeAccountPublicationDataV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessOriginalReturnFateDataV1 {
    Captured {
        outcome_id: String,
        raw_output_digest: String,
        original_dispatch_commit_digest: String,
        original_outcome_receipt_digest: String,
    },
    /// Requires the native source's exact original no-future-return witness.
    /// An absent outcome, cancelled Process, exit or observed zero effect is
    /// never sufficient for this alternative.
    NoFutureReturn {
        original_no_future_return_digest: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessNativeReturnCaptureDataV1 {
    pub schema: String,
    pub process_source_digest: String,
    pub process_account_digest: String,
    pub native_funding: ProcessReturnFundingDataV1,
    pub native_capture_sequence: u64,
    pub native_capture_sequence_domain: NativeReturnSequenceDomainDataV1,
    pub native_capture_digest: String,
    pub fate: ProcessOriginalReturnFateDataV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnReconciliationDataV1 {
    pub schema: String,
    pub process_source_digest: String,
    pub process_account_digest: String,
    pub process_final_receipt_digest: String,
    pub process_final_event_sequence: u64,
    pub process_final_event_digest: String,
    pub native_account_digest: String,
    pub native_reconciliation_sequence: u64,
    pub native_reconciliation_sequence_domain: NativeReturnSequenceDomainDataV1,
    pub native_reconciliation_digest: String,
    pub native_bank_epoch: u64,
}

/// Fixed descriptions carry no backend message, caller payload or claim that
/// future native output has become impossible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessReturnUnavailableReasonDataV1 {
    NativeResultUnavailable,
    NativeResultUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReturnUnavailableDataV1 {
    pub schema: String,
    pub process_source_digest: String,
    pub process_account_digest: String,
    pub native_operation_id: String,
    pub reason: ProcessReturnUnavailableReasonDataV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOriginalNonceCustodyDataV1 {
    pub schema: String,
    pub process_source_digest: String,
    pub process_account_digest: String,
    pub native_funding: ProcessReturnFundingDataV1,
    pub original_nonce_source_digest: String,
    pub original_nonce_sequence: u64,
    pub original_nonce_sequence_domain: NativeReturnSequenceDomainDataV1,
    pub original_nonce: crate::execution_nonce::SignedExecutionNonce,
}

/// The actual durable authority must authenticate its committed original bank,
/// capture and matched Process reservation in a current fenced transaction.
/// All default paths refuse. Public DATA never supplies a success shortcut.
pub trait NativeProcessReturnCustodyPort: Send + Sync {
    fn verify_original_process_return_inventory(
        &self,
        _inventory: &ProcessReturnInventoryDataV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<ProcessReturnBankReadbackDataV1, AdmissionOperationStoreError> {
        Err(unavailable())
    }

    fn verify_original_process_nonce_custody(
        &self,
        _source: &ProcessReturnSourceDataV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<ProcessOriginalNonceCustodyDataV1, AdmissionOperationStoreError> {
        Err(unavailable())
    }

    /// Prepared is an actual durable native account retaining all Process
    /// purposes. It supplies no capture or rail permission before Confirmed.
    fn verify_original_process_return_enrollment(
        &self,
        _source: &ProcessReturnSourceDataV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<ProcessReturnFundingDataV1, AdmissionOperationStoreError> {
        Err(unavailable())
    }

    fn verify_original_process_return_capture(
        &self,
        _source: &ProcessReturnSourceDataV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<ProcessNativeReturnCaptureDataV1, AdmissionOperationStoreError> {
        Err(unavailable())
    }

    fn verify_original_process_return_reconciliation(
        &self,
        _source: &ProcessReturnSourceDataV1,
        _final_receipt_digest: &str,
        _final_sequence: u64,
        _final_event_digest: &str,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<ProcessReturnReconciliationDataV1, AdmissionOperationStoreError> {
        Err(unavailable())
    }
}

/// Original nonce custody is a separate funded purpose before tool capture.
/// It cannot be minted from a signed nonce, final return or an observed replay.
pub struct FundedProcessOriginalNonce {
    source_bytes: Vec<u8>,
    receipt: ProcessOriginalNonceCustodyDataV1,
}
impl FundedProcessOriginalNonce {
    pub(crate) fn from_original_native_source(
        port: &dyn NativeProcessReturnCustodyPort,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_bytes = encode_source(source)?;
        let receipt = port.verify_original_process_nonce_custody(source, fence, now)?;
        if receipt.schema != PROCESS_ORIGINAL_NONCE_CUSTODY_SCHEMA
            || receipt.process_source_digest != digest(&source_bytes)
            || receipt.process_account_digest != receipt.native_funding.process_account_digest
            || !source.original_nonce_pending
            || !positive_sequence(receipt.original_nonce_sequence)
            || receipt.original_nonce_sequence < receipt.native_funding.native_account_sequence
            || receipt.original_nonce.nonce.bound_to.request_id != source.request_id
        {
            return Err(unavailable());
        }
        require_digest(&receipt.original_nonce_source_digest)?;
        validate_funding(source, &source_bytes, &receipt.native_funding)?;
        bounded_bytes(&receipt.original_nonce, 16_384)?;
        bounded_bytes(&receipt, MAX_PROCESS_NONCE_RECEIPT_BYTES)?;
        Ok(Self {
            source_bytes,
            receipt,
        })
    }
    pub fn consume_for(
        self,
        actual_source: &ProcessReturnSourceDataV1,
    ) -> Result<ProcessOriginalNonceCustodyDataV1, AdmissionOperationStoreError> {
        if self.source_bytes != encode_source(actual_source)? {
            return Err(unavailable());
        }
        Ok(self.receipt)
    }
}
impl core::fmt::Debug for FundedProcessOriginalNonce {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FundedProcessOriginalNonce([redacted])")
    }
}

/// Affine enrollment custody from the durable original native Prepared bank.
/// Its source issuer must also retain the entire side-database allowance.
///
/// ```compile_fail
/// use chio_kernel::process_return_custody::FundedProcessReturnEnrollment;
/// let _: Result<FundedProcessReturnEnrollment, _> = serde_json::from_str("{}");
/// ```
pub struct FundedProcessReturnEnrollment {
    source_bytes: Vec<u8>,
    funding: ProcessReturnFundingDataV1,
}
impl FundedProcessReturnEnrollment {
    pub(crate) fn from_original_native_source(
        port: &dyn NativeProcessReturnCustodyPort,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_bytes = encode_source(source)?;
        let funding = port.verify_original_process_return_enrollment(source, fence, now)?;
        validate_funding(source, &source_bytes, &funding)?;
        Ok(Self {
            source_bytes,
            funding,
        })
    }
    pub fn consume_for(
        self,
        actual_source: &ProcessReturnSourceDataV1,
    ) -> Result<ProcessReturnFundingDataV1, AdmissionOperationStoreError> {
        if self.source_bytes != encode_source(actual_source)? {
            return Err(unavailable());
        }
        Ok(self.funding)
    }
}
impl core::fmt::Debug for FundedProcessReturnEnrollment {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FundedProcessReturnEnrollment([redacted])")
    }
}

/// Affine historical capture custody. Only the Kernel owning native verifier
/// issues this, and Process consumes it against its retained original source.
/// It grants no dispatch, output resend or unverified account retirement.
///
/// ```compile_fail
/// use chio_kernel::process_return_custody::FundedProcessNativeReturn;
/// let _: Result<FundedProcessNativeReturn, _> = serde_json::from_str("{}");
/// ```
///
/// ```compile_fail
/// use chio_kernel::process_return_custody::FundedProcessNativeReturn;
/// fn duplicate(value: &FundedProcessNativeReturn) {
///     let _: FundedProcessNativeReturn = Clone::clone(value);
/// }
/// ```
pub struct FundedProcessNativeReturn {
    source_bytes: Vec<u8>,
    receipt: ProcessNativeReturnCaptureDataV1,
}

impl FundedProcessNativeReturn {
    pub(crate) fn from_original_native_source(
        port: &dyn NativeProcessReturnCustodyPort,
        source: &ProcessReturnSourceDataV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_bytes = encode_source(source)?;
        let receipt = port.verify_original_process_return_capture(source, fence, now)?;
        validate_capture(source, &source_bytes, &receipt)?;
        Ok(Self {
            source_bytes,
            receipt,
        })
    }

    pub fn consume_for(
        self,
        actual_source: &ProcessReturnSourceDataV1,
    ) -> Result<ProcessNativeReturnCaptureDataV1, AdmissionOperationStoreError> {
        if self.source_bytes != encode_source(actual_source)? {
            return Err(unavailable());
        }
        Ok(self.receipt)
    }
}

impl core::fmt::Debug for FundedProcessNativeReturn {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FundedProcessNativeReturn([redacted])")
    }
}

/// A separate affine proof after native readback has authenticated the exact
/// Process final event. A capture proof alone cannot close the live count.
///
/// ```compile_fail
/// use chio_kernel::process_return_custody::ReconciledProcessNativeReturn;
/// let _: Result<ReconciledProcessNativeReturn, _> = serde_json::from_str("{}");
/// ```
pub struct ReconciledProcessNativeReturn {
    source_bytes: Vec<u8>,
    receipt: ProcessReturnReconciliationDataV1,
}
impl ReconciledProcessNativeReturn {
    pub(crate) fn from_original_native_source(
        port: &dyn NativeProcessReturnCustodyPort,
        source: &ProcessReturnSourceDataV1,
        final_receipt_digest: &str,
        final_sequence: u64,
        final_event_digest: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_bytes = encode_source(source)?;
        let receipt = port.verify_original_process_return_reconciliation(
            source,
            final_receipt_digest,
            final_sequence,
            final_event_digest,
            fence,
            now,
        )?;
        if receipt.schema != PROCESS_RETURN_RECONCILIATION_SCHEMA
            || receipt.process_source_digest != digest(&source_bytes)
            || receipt.process_final_receipt_digest != final_receipt_digest
            || receipt.process_final_event_sequence != final_sequence
            || receipt.process_final_event_digest != final_event_digest
            || !positive_sequence(receipt.native_reconciliation_sequence)
            || !positive_sequence(receipt.native_bank_epoch)
            || !positive_sequence(receipt.process_final_event_sequence)
        {
            return Err(unavailable());
        }
        for value in [
            &receipt.process_account_digest,
            &receipt.process_final_receipt_digest,
            &receipt.process_final_event_digest,
            &receipt.native_account_digest,
            &receipt.native_reconciliation_digest,
        ] {
            require_digest(value)?;
        }
        bounded_bytes(&receipt, MAX_PROCESS_RETURN_RECEIPT_BYTES)?;
        Ok(Self {
            source_bytes,
            receipt,
        })
    }
    pub fn consume_for(
        self,
        actual_source: &ProcessReturnSourceDataV1,
        final_receipt_digest: &str,
        final_sequence: u64,
        final_event_digest: &str,
    ) -> Result<ProcessReturnReconciliationDataV1, AdmissionOperationStoreError> {
        if self.source_bytes != encode_source(actual_source)?
            || self.receipt.process_final_receipt_digest != final_receipt_digest
            || self.receipt.process_final_event_sequence != final_sequence
            || self.receipt.process_final_event_digest != final_event_digest
        {
            return Err(unavailable());
        }
        Ok(self.receipt)
    }
}
impl core::fmt::Debug for ReconciledProcessNativeReturn {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReconciledProcessNativeReturn([redacted])")
    }
}

/// Validate and encode a Process description as DATA only. This does not
/// authenticate the journal, allocate funding or construct a capture proof.
pub fn canonical_process_return_source_data(
    source: &ProcessReturnSourceDataV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    encode_source(source)
}

fn encode_source(
    source: &ProcessReturnSourceDataV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    if source.schema != PROCESS_RETURN_SOURCE_SCHEMA
        || !(1..=3).contains(&source.attempt)
        || !uuid_text(&source.journal_namespace)
        || !uuid_text(&source.journal_authority)
        || source.file_inode == 0
        || source.process_id.is_empty()
        || source.root_process_id.is_empty()
        || source.operation_key.is_empty()
        || [
            &source.process_id,
            &source.root_process_id,
            &source.operation_key,
        ]
        .iter()
        .any(|value| {
            value.len() > 256
                || value.trim() != value.as_str()
                || value.chars().any(char::is_control)
        })
        || !process_request_id(source)
        || source.original_nonce_pending && source.original_nonce_digest.is_some()
    {
        return Err(unavailable());
    }
    for value in [
        &source.kernel_key_digest,
        &source.catalog_digest,
        &source.cut_digest,
        &source.logical_request_digest,
        &source.call_binding_digest,
        &source.current_request_digest,
        &source.capability_digest,
    ] {
        require_digest(value)?;
    }
    for value in [
        source.host_profile_digest.as_deref(),
        source.host_route_digest.as_deref(),
        source.launch_receipt_digest.as_deref(),
        source.security_context_digest.as_deref(),
        source.original_nonce_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        require_digest(value)?;
    }
    bounded_bytes(source, MAX_PROCESS_RETURN_SOURCE_BYTES)
}

fn validate_capture(
    source: &ProcessReturnSourceDataV1,
    source_bytes: &[u8],
    receipt: &ProcessNativeReturnCaptureDataV1,
) -> Result<(), AdmissionOperationStoreError> {
    let source_digest = digest(source_bytes);
    if receipt.schema != PROCESS_RETURN_CAPTURE_SCHEMA
        || receipt.process_source_digest != source_digest
        || receipt.process_account_digest != receipt.native_funding.process_account_digest
        || !positive_sequence(receipt.native_capture_sequence)
        || receipt.native_capture_sequence < receipt.native_funding.native_account_sequence
    {
        return Err(unavailable());
    }
    require_digest(&receipt.process_account_digest)?;
    require_digest(&receipt.native_capture_digest)?;
    validate_funding(source, source_bytes, &receipt.native_funding)?;
    match &receipt.fate {
        ProcessOriginalReturnFateDataV1::Captured {
            outcome_id,
            raw_output_digest,
            original_dispatch_commit_digest,
            original_outcome_receipt_digest,
        } => {
            for value in [
                outcome_id,
                raw_output_digest,
                original_dispatch_commit_digest,
                original_outcome_receipt_digest,
            ] {
                require_digest(value)?;
            }
        }
        ProcessOriginalReturnFateDataV1::NoFutureReturn {
            original_no_future_return_digest,
        } => {
            require_digest(original_no_future_return_digest)?;
        }
    }
    bounded_bytes(receipt, MAX_PROCESS_RETURN_RECEIPT_BYTES)?;
    Ok(())
}

fn validate_funding(
    source: &ProcessReturnSourceDataV1,
    source_bytes: &[u8],
    funding: &ProcessReturnFundingDataV1,
) -> Result<(), AdmissionOperationStoreError> {
    if funding.schema != PROCESS_RETURN_FUNDING_SCHEMA
        || funding.process_source_digest != digest(source_bytes)
        || !positive_sequence(funding.native_account_sequence)
        || !positive_sequence(funding.native_bank_epoch)
        || !positive_sequence(funding.original_store_lease_epoch)
        || !positive_sequence(funding.original_coordinator_lease_epoch)
        || funding.original_store_uuid != source.journal_authority
        || !uuid_text(&funding.original_store_lease_id)
        || funding.original_coordinator_lease_id.is_empty()
        || funding.original_coordinator_lease_id.len() > 256
        || funding
            .original_coordinator_lease_id
            .chars()
            .any(char::is_control)
    {
        return Err(unavailable());
    }
    for value in [
        &funding.process_account_digest,
        &funding.native_operation_id,
        &funding.native_request_binding_digest,
        &funding.native_account_digest,
        &funding.original_native_source_epoch_digest,
        &funding.original_profile_digest,
        &funding.original_actor_digest,
        &funding.original_context_digest,
        &funding.original_role_map_digest,
        &funding.physical_recipe_digest,
        &funding.process_future_transactions_digest,
    ] {
        require_digest(value)?;
    }
    if funding.process_account_digest != process_return_account_intent_digest(source, funding)? {
        return Err(unavailable());
    }
    if !funding.original_native_publication.is_absent() {
        funding.original_native_publication.validate()?;
        if funding.original_native_publication.global_commit_sequence
            != funding.native_account_sequence
        {
            return Err(unavailable());
        }
    }
    bounded_bytes(funding, MAX_PROCESS_RETURN_FUNDING_BYTES)?;
    Ok(())
}

/// DATA identity for the prospective immutable Process account. The actual
/// native account seal and publication sequence are deliberately excluded to
/// avoid a cyclic pair of receipt hashes. Computing it grants no enrollment.
pub fn process_return_account_intent_digest(
    source: &ProcessReturnSourceDataV1,
    funding: &ProcessReturnFundingDataV1,
) -> Result<String, AdmissionOperationStoreError> {
    let source_digest = digest(&encode_source(source)?);
    #[derive(Serialize)]
    struct Intent<'a> {
        schema: &'static str,
        process_source_digest: &'a str,
        native_operation_id: &'a str,
        native_request_binding_digest: &'a str,
        native_bank_epoch: u64,
        original_native_source_epoch_digest: &'a str,
        original_store_uuid: &'a str,
        original_store_lease_id: &'a str,
        original_store_lease_epoch: u64,
        original_coordinator_lease_id: &'a str,
        original_coordinator_lease_epoch: u64,
        original_profile_digest: &'a str,
        original_actor_digest: &'a str,
        original_context_digest: &'a str,
        original_role_map_digest: &'a str,
        physical_recipe_digest: &'a str,
        process_future_transactions_digest: &'a str,
    }
    let bytes = bounded_bytes(
        &Intent {
            schema: "chio.process-native-return-account-intent.v1",
            process_source_digest: &source_digest,
            native_operation_id: &funding.native_operation_id,
            native_request_binding_digest: &funding.native_request_binding_digest,
            native_bank_epoch: funding.native_bank_epoch,
            original_native_source_epoch_digest: &funding.original_native_source_epoch_digest,
            original_store_uuid: &funding.original_store_uuid,
            original_store_lease_id: &funding.original_store_lease_id,
            original_store_lease_epoch: funding.original_store_lease_epoch,
            original_coordinator_lease_id: &funding.original_coordinator_lease_id,
            original_coordinator_lease_epoch: funding.original_coordinator_lease_epoch,
            original_profile_digest: &funding.original_profile_digest,
            original_actor_digest: &funding.original_actor_digest,
            original_context_digest: &funding.original_context_digest,
            original_role_map_digest: &funding.original_role_map_digest,
            physical_recipe_digest: &funding.physical_recipe_digest,
            process_future_transactions_digest: &funding.process_future_transactions_digest,
        },
        MAX_PROCESS_RETURN_FUNDING_BYTES,
    )?;
    Ok(digest(&bytes))
}

fn bounded_bytes(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let bytes = chio_core_types::canonical_json_bytes(value).map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(unavailable());
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    chio_core_types::crypto::sha256_hex(bytes)
}
fn require_digest(value: &str) -> Result<(), AdmissionOperationStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(unavailable());
    }
    Ok(())
}
fn uuid_text(value: &str) -> bool {
    value.len() == 36
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}
fn process_request_id(source: &ProcessReturnSourceDataV1) -> bool {
    let bytes = if source.attempt == 1 {
        chio_core_types::canonical_json_bytes(&(
            &source.journal_namespace,
            &source.process_id,
            &source.operation_key,
        ))
    } else {
        chio_core_types::canonical_json_bytes(&(
            &source.journal_namespace,
            &source.process_id,
            &source.operation_key,
            source.attempt,
        ))
    };
    bytes.is_ok_and(|value| source.request_id == format!("process:{}", digest(&value)))
}
fn positive_sequence(value: u64) -> bool {
    (1..=MAX_SEQUENCE).contains(&value)
}
fn unavailable() -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Unavailable(
        "original funded Process return custody unavailable".into(),
    )
}

/// Structural DATA validation only. The actual Native owner authenticates
/// publication history independently before any loan is issued.
pub fn validate_process_return_funding_data(
    source: &ProcessReturnSourceDataV1,
    funding: &ProcessReturnFundingDataV1,
) -> Result<(), AdmissionOperationStoreError> {
    validate_funding(source, &encode_source(source)?, funding)
}
