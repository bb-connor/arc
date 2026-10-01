//! Input budgets and original-byte validation for commerce evidence.

use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

use crate::{CommerceOrderError, CommerceOrderVerificationBundle};

const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DOCUMENTS: usize = 4096;

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CommerceOrderError> {
    UntrustedJsonText::from_wire(bytes, MAX_DOCUMENT_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|error| CommerceOrderError::Input(error.into()))
}

/// Only for projections of an already validated original document.
pub(crate) fn project<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, CommerceOrderError> {
    serde_json::from_value(value)
        .map_err(|error| CommerceOrderError::Input(UntrustedJsonError::Decode(error).into()))
}

pub(crate) fn validate_budget(
    bundle: &CommerceOrderVerificationBundle,
) -> Result<(), CommerceOrderError> {
    let documents = [
        bundle.event_log_bytes.as_slice(),
        bundle.payment_lifecycle_bytes.as_slice(),
        bundle.mandate_ledger_bytes.as_slice(),
        bundle.provider_passport_bytes.as_slice(),
        bundle.reputation_snapshot_bytes.as_slice(),
        bundle.federation_trust_bundle_bytes.as_slice(),
        bundle.settlement_packet_bytes.as_slice(),
    ]
    .into_iter()
    .chain(bundle.risk_comptroller_report_bytes.as_deref())
    .chain(
        bundle
            .event_authority_receipts
            .iter()
            .map(|artifact| artifact.receipt_bytes.as_slice()),
    )
    .chain(
        bundle
            .mandate_protocol_payloads
            .iter()
            .map(|artifact| artifact.payload_bytes.as_slice()),
    );
    let mut remaining = MAX_BUNDLE_BYTES;
    for (index, document) in documents.enumerate() {
        if index >= MAX_DOCUMENTS || document.len() > MAX_DOCUMENT_BYTES {
            return Err(CommerceOrderError::EvidenceLimit);
        }
        remaining = remaining
            .checked_sub(document.len())
            .ok_or(CommerceOrderError::EvidenceLimit)?;
    }
    Ok(())
}
