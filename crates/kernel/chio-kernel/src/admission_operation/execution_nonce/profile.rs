//! Context-bound nonce signatures. The operation ID is authenticated context,
//! reconstructed from the trusted admission, never selected by the presented nonce.

use super::*;
use crate::execution_nonce::{
    validate_execution_nonce_binding_and_expiry, ExecutionNonce, ExecutionNonceConfig,
};
use chio_core::crypto::Keypair;

/// Nonce profile reserved for the operation-owned admission authority.
pub const OPERATION_EXECUTION_NONCE_SCHEMA: &str = "chio.execution_nonce.v2";

#[derive(Serialize)]
struct SigningContext<'a> {
    schema: &'static str,
    operation_id: &'a crate::admission_operation::AdmissionOperationId,
    nonce: &'a ExecutionNonce,
}

fn signing_bytes(
    operation: &AdmissionOperationV1,
    nonce: &ExecutionNonce,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(&SigningContext {
        schema: "chio.admission-execution-nonce-signature.v1",
        operation_id: operation.binding().operation_id(),
        nonce,
    })
    .map_err(invalid)
}

impl AdmissionExecutionNonceReservationV1 {
    /// Create signature-checked material for one immutable operation.
    /// The caller must still revalidate authorization and persist unique issuance
    /// before delivering it. This method neither reserves nor commits a nonce.
    pub fn mint_for_operation(
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        issuer: &Keypair,
        config: &ExecutionNonceConfig,
        now_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        original.validate_binding(operation.binding())?;
        if !operation
            .binding()
            .participant_requirements()
            .execution_nonce
            || now_unix_ms > crate::admission_operation::I_JSON_MAX_SAFE_INTEGER
        {
            return Err(invalid(
                "operation nonce issuance binding or time is invalid",
            ));
        }
        let now = i64::try_from(now_unix_ms / 1_000).map_err(invalid)?;
        let ttl = i64::try_from(config.nonce_ttl_secs).map_err(invalid)?;
        let maximum_expiry =
            i64::try_from(crate::admission_operation::I_JSON_MAX_SAFE_INTEGER / 1_000)
                .map_err(invalid)?;
        let expires = now
            .checked_add(ttl)
            .filter(|expires| *expires > now && *expires <= maximum_expiry)
            .ok_or_else(|| invalid("operation nonce issuance interval is invalid"))?;
        let nonce = ExecutionNonce {
            schema: OPERATION_EXECUTION_NONCE_SCHEMA.into(),
            nonce_id: uuid::Uuid::now_v7().as_hyphenated().to_string(),
            issued_at: now,
            expires_at: expires,
            bound_to: expected_binding(operation, original),
            reserved_hold_id: None,
            reserving_request_id: None,
        };
        let bytes = signing_bytes(operation, &nonce)?;
        if bytes.len() > MAX_NONCE_BYTES {
            return Err(invalid("operation nonce exceeds its signing bound"));
        }
        let signed = SignedExecutionNonce {
            nonce,
            signature: issuer.sign(&bytes),
        };
        Self::verify(
            operation,
            original,
            &signed,
            &issuer.public_key(),
            now_unix_ms,
        )
    }
}

pub(super) fn verify(
    presented: &SignedExecutionNonce,
    operation: &AdmissionOperationV1,
    issuer: &PublicKey,
    binding: &NonceBinding,
    now: i64,
) -> Result<(), AdmissionOperationStoreError> {
    if presented.nonce.expires_at
        > i64::try_from(crate::admission_operation::I_JSON_MAX_SAFE_INTEGER / 1_000)
            .map_err(invalid)?
    {
        return Err(invalid("operation nonce issuance interval is invalid"));
    }
    validate_execution_nonce_binding_and_expiry(presented, binding, now).map_err(invalid)?;
    if !issuer.verify(
        &signing_bytes(operation, &presented.nonce)?,
        &presented.signature,
    ) {
        return Err(invalid(
            "operation-bound execution nonce signature is invalid",
        ));
    }
    Ok(())
}
