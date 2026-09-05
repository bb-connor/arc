//! Checked nonce material for an operation-owned reservation, not a dispatch permit.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use super::{
    AdmissionIdentifier, AdmissionOperationStoreError, AdmissionOperationV1,
    RetainedToolAdmissionRequestV1,
};
use crate::execution_nonce::{validate_execution_nonce, NonceBinding, SignedExecutionNonce};

const MAX_NONCE_BYTES: usize = 16 * 1024;

/// Signature-checked, exactly bound nonce material. The trusted store must still
/// pin the issuer to its coordinator, verify original-request provenance, check
/// its current fence and clock, and reserve atomically with the operation.
/// Neither construction nor decoding establishes reservation or replay authority.
#[derive(Clone)]
pub struct AdmissionExecutionNonceReservationV1 {
    wire: ReservationWire,
    canonical: Vec<u8>,
    nonce_id: AdmissionIdentifier,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationWire {
    schema: String,
    operation_id: super::AdmissionOperationId,
    issuer: PublicKey,
    signed_nonce: SignedExecutionNonce,
}

impl std::fmt::Debug for AdmissionExecutionNonceReservationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionExecutionNonceReservationV1")
            .finish_non_exhaustive()
    }
}

impl AdmissionExecutionNonceReservationV1 {
    /// `trusted_issuer` is an operator-owned trust input, never an HTTP field.
    pub fn verify(
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        signed_nonce: &SignedExecutionNonce,
        trusted_issuer: &PublicKey,
        now_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let nonce = &signed_nonce.nonce;
        let binding = &nonce.bound_to;
        let source_bytes = [
            nonce.schema.as_str(),
            nonce.nonce_id.as_str(),
            binding.subject_id.as_str(),
            binding.request_id.as_str(),
            binding.capability_id.as_str(),
            binding.tool_server.as_str(),
            binding.tool_name.as_str(),
            binding.parameter_hash.as_str(),
            nonce.reserved_hold_id.as_deref().unwrap_or(""),
            nonce.reserving_request_id.as_deref().unwrap_or(""),
        ]
        .iter()
        .try_fold(0_usize, |length, value| length.checked_add(value.len()));
        if source_bytes.is_none_or(|length| length > MAX_NONCE_BYTES) {
            return Err(invalid(
                "execution nonce reservation exceeds its artifact bound",
            ));
        }
        let wire = ReservationWire {
            schema: "chio.admission-execution-nonce-reservation.v1".into(),
            operation_id: operation.binding().operation_id().clone(),
            issuer: trusted_issuer.clone(),
            signed_nonce: signed_nonce.clone(),
        };
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        Self::from_canonical_bytes(&canonical, operation, original, trusted_issuer, now_unix_ms)
    }

    /// Recheck persisted material with a caller-supplied trusted issuer and time.
    /// Historical validation uses the independently authenticated reservation
    /// time; it must not turn an expired artifact into new execution authority.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        trusted_issuer: &PublicKey,
        now_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_NONCE_BYTES {
            return Err(invalid(
                "execution nonce reservation exceeds its artifact bound",
            ));
        }
        let wire: ReservationWire = serde_json::from_slice(bytes).map_err(invalid)?;
        if wire.schema != "chio.admission-execution-nonce-reservation.v1"
            || wire.operation_id != *operation.binding().operation_id()
            || wire.issuer != *trusted_issuer
            || !operation
                .binding()
                .participant_requirements()
                .execution_nonce
            || now_unix_ms > super::I_JSON_MAX_SAFE_INTEGER
        {
            return Err(invalid("execution nonce reservation binding is invalid"));
        }
        original.validate_binding(operation.binding())?;
        let nonce = &wire.signed_nonce.nonce;
        let nonce_id = AdmissionIdentifier::try_new("execution_nonce_id", nonce.nonce_id.clone())?;
        let now = i64::try_from(now_unix_ms / 1_000).map_err(invalid)?;
        if nonce.issued_at < 0 || nonce.issued_at > now || nonce.expires_at <= nonce.issued_at {
            return Err(invalid("execution nonce issuance interval is invalid"));
        }
        if nonce.reserved_hold_id.as_deref().is_some_and(|hold| {
            operation.budget_hold_id().map(AdmissionIdentifier::as_str) != Some(hold)
                || nonce.reserving_request_id.as_deref()
                    != Some(operation.binding().request_id().as_str())
        }) || nonce.reserved_hold_id.is_none() && nonce.reserving_request_id.is_some()
        {
            return Err(invalid(
                "execution nonce reserved hold does not match its operation",
            ));
        }
        let request = original.request_for_revalidation();
        let binding = NonceBinding {
            subject_id: request.capability.subject.to_hex(),
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: operation
                .binding()
                .action_parameter_hash()
                .as_str()
                .to_owned(),
        };
        validate_execution_nonce(&wire.signed_nonce, trusted_issuer, &binding, now)
            .map_err(invalid)?;
        let canonical = canonical_json_bytes(&wire).map_err(invalid)?;
        if canonical != bytes {
            return Err(invalid(
                "execution nonce reservation is not exact typed canonical JSON",
            ));
        }
        Ok(Self {
            wire,
            canonical,
            nonce_id,
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub fn nonce_id(&self) -> &AdmissionIdentifier {
        &self.nonce_id
    }

    #[must_use]
    pub fn issuer(&self) -> &PublicKey {
        &self.wire.issuer
    }
}

fn invalid(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.to_string())
}
