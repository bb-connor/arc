//! Data-only original request commitments, never capture or release authority.
use super::{
    AdmissionDigest, AdmissionOperationStoreError, AdmissionOperationV1,
    NativeSecurityDispatchLedgerRecordV1,
};
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonError};
use chio_core::crypto::sha256_hex;
use chio_security_types::ports::RecordId;

pub const NATIVE_DISPATCH_LEDGER_LEGACY_SCHEMA: &str = "chio.native-dispatch-preparation-ledger.v1";
pub const NATIVE_DISPATCH_LEDGER_SCHEMA: &str = "chio.native-dispatch-preparation-ledger.v2";
const MAX_LIVE_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_LEDGER_BYTES: usize = 1024 * 1024;

/// Bounded structural data. A store must independently bind these values to
/// its original operation, live input, capture and anchored immutable history.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeSecurityDispatchRequestBindingV1 {
    dispatch_commitment_id: RecordId,
    live_request_digest: AdmissionDigest,
}

impl NativeSecurityDispatchRequestBindingV1 {
    /// Calculate both values from the same complete live bytes. This pure
    /// function does not assert that any effect, custody or release occurred.
    pub fn from_live_request(
        request: &crate::ToolCallRequest,
        context: &crate::SecurityInvocationContext,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let canonical = canonical_json_bytes(request).map_err(invalid)?;
        if canonical.is_empty() || canonical.len() > MAX_LIVE_REQUEST_BYTES {
            return Err(invalid("original native live request exceeds its bound"));
        }
        Ok(Self {
            dispatch_commitment_id: crate::kernel::derive_security_dispatch_commitment_id(
                &canonical, context,
            )
            .map_err(invalid)?,
            live_request_digest: AdmissionDigest::try_new(
                "original_live_request_digest",
                sha256_hex(&canonical),
            )?,
        })
    }

    /// Inspect exact bounded data after the caller has independently read the
    /// original fenced ledger. A legacy record supplies no missing provenance.
    pub fn from_ledger(
        record: &NativeSecurityDispatchLedgerRecordV1,
        context: &crate::SecurityInvocationContext,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let bytes = &record.canonical_record;
        if bytes.is_empty() || bytes.len() > MAX_LEDGER_BYTES {
            return Err(invalid("original native ledger exceeds its bound"));
        }
        let value: serde_json::Value =
            chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_LEDGER_BYTES)
                .and_then(|input| input.decode_signed())?;
        let operation = AdmissionOperationV1::from_persisted(
            serde_json::from_value(value["operation"].clone())
                .map_err(UntrustedJsonError::Decode)?,
        )?;
        if canonical_json_bytes(&value).map_err(UntrustedJsonError::Canonicalization)? != *bytes
            || sha256_hex(bytes) != record.record_digest.as_str()
            || operation.binding().operation_id() != &record.operation_id
            || value.get("context")
                != Some(
                    &serde_json::to_value(context)
                        .map_err(|error| UntrustedJsonError::Canonicalization(error.into()))?,
                )
        {
            return Err(invalid("original native ledger changed its data binding"));
        }
        match value.get("schema").and_then(serde_json::Value::as_str) {
            Some(NATIVE_DISPATCH_LEDGER_LEGACY_SCHEMA)
                if value.get("original_dispatch_commitment_id").is_none() =>
            {
                Ok(None)
            }
            Some(NATIVE_DISPATCH_LEDGER_SCHEMA) => {
                let dispatch_commitment_id: RecordId =
                    serde_json::from_value(value["original_dispatch_commitment_id"].clone())
                        .map_err(UntrustedJsonError::Decode)?;
                if !valid_dispatch_commitment_id(&dispatch_commitment_id) {
                    return Err(invalid("original native dispatch commitment is invalid"));
                }
                Ok(Some(Self {
                    dispatch_commitment_id,
                    live_request_digest: serde_json::from_value(
                        value["live_request_digest"].clone(),
                    )
                    .map_err(UntrustedJsonError::Decode)?,
                }))
            }
            _ => Err(invalid("original native ledger schema is invalid")),
        }
    }

    pub fn dispatch_commitment_id(&self) -> &RecordId {
        &self.dispatch_commitment_id
    }

    pub fn live_request_digest(&self) -> &AdmissionDigest {
        &self.live_request_digest
    }
}

pub(crate) fn valid_dispatch_commitment_id(id: &RecordId) -> bool {
    id.as_str()
        .strip_prefix("dispatch-commitment:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn invalid(detail: impl ToString) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.to_string())
}
