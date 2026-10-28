//! Context-bound nonce signatures. The operation ID is authenticated context,
//! reconstructed from the trusted admission, never selected by the presented nonce.

use super::*;
use crate::execution_nonce::{
    validate_execution_nonce_binding_and_expiry, ExecutionNonce, ExecutionNonceConfig,
};
use chio_core::canonical::CanonicalBytes;
use chio_core::crypto::{verify_wrapped_bytes, SigningBackend};

/// Nonce profile reserved for the operation-owned admission authority.
pub const OPERATION_EXECUTION_NONCE_SCHEMA: &str = "chio.operation_execution_nonce.v1";

#[derive(Serialize)]
struct SigningContext<'a> {
    operation_id: &'a crate::admission_operation::AdmissionOperationId,
    nonce: &'a ExecutionNonce,
}

/// Canonical signing body; the wrapper binds it to
/// `chio.operation_execution_nonce.v1`.
fn signing_body(
    operation_id: &crate::admission_operation::AdmissionOperationId,
    nonce: &ExecutionNonce,
) -> Result<CanonicalBytes, AdmissionOperationStoreError> {
    let body = CanonicalBytes::from_serializable(&SigningContext {
        operation_id,
        nonce,
    })
    .map_err(invalid)?;
    if body.len() > MAX_NONCE_BYTES {
        return Err(invalid("operation nonce exceeds its signing bound"));
    }
    Ok(body)
}

impl AdmissionExecutionNonceReservationV1 {
    /// Create signature-checked material for one immutable operation.
    /// The caller must still revalidate authorization and persist unique issuance
    /// before delivering it. This method neither reserves nor commits a nonce.
    pub fn mint_for_operation(
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        issuer: &dyn SigningBackend,
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
        let body = signing_body(operation.binding().operation_id(), &nonce)?;
        let outcome = issuer
            .sign_wrapped(OPERATION_EXECUTION_NONCE_SCHEMA, &body)
            .map_err(invalid)?;
        let signed = SignedExecutionNonce {
            nonce,
            signature: outcome.signature,
        };
        Self::verify(
            operation,
            original,
            &signed,
            &outcome.public_key,
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
    verify_operation_execution_nonce_at(
        presented,
        operation.binding().operation_id(),
        issuer,
        binding,
        now,
    )
}

/// Verify the operation-bound signature, exact request binding and validity at
/// a caller-authenticated historical time. This does not consume a nonce, prove
/// reservation or custody, or authorize any new dispatch. The operation ID,
/// issuer, binding and time must come from independently authenticated evidence.
pub fn verify_operation_execution_nonce_at(
    presented: &SignedExecutionNonce,
    operation_id: &crate::admission_operation::AdmissionOperationId,
    issuer: &PublicKey,
    binding: &NonceBinding,
    now: i64,
) -> Result<(), AdmissionOperationStoreError> {
    AdmissionIdentifier::try_new("execution_nonce_id", presented.nonce.nonce_id.clone())?;
    if presented.nonce.schema != OPERATION_EXECUTION_NONCE_SCHEMA
        || presented.nonce.issued_at < 0
        || presented.nonce.issued_at > now
        || presented.nonce.expires_at <= presented.nonce.issued_at
        || presented.nonce.expires_at
            > i64::try_from(crate::admission_operation::I_JSON_MAX_SAFE_INTEGER / 1_000)
                .map_err(invalid)?
    {
        return Err(invalid("operation nonce issuance interval is invalid"));
    }
    validate_execution_nonce_binding_and_expiry(presented, binding, now).map_err(invalid)?;
    let body = signing_body(operation_id, &presented.nonce)?;
    if verify_wrapped_bytes(
        issuer,
        OPERATION_EXECUTION_NONCE_SCHEMA,
        &body,
        &presented.signature,
    )
    .is_err()
    {
        return Err(invalid(
            "operation-bound execution nonce signature is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

    #[test]
    fn historical_nonce_requires_original_operation_request_key_and_time(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = Keypair::generate();
        let operation =
            crate::admission_operation::AdmissionOperationId::from_persisted("a".repeat(64))?;
        let binding = NonceBinding {
            subject_id: key.public_key().to_hex(),
            request_id: "original-request".into(),
            capability_id: "original-capability".into(),
            tool_server: "original-server".into(),
            tool_name: "append".into(),
            parameter_hash: "b".repeat(64),
        };
        let nonce = ExecutionNonce {
            schema: OPERATION_EXECUTION_NONCE_SCHEMA.into(),
            nonce_id: "original-nonce".into(),
            issued_at: 100,
            expires_at: 130,
            bound_to: binding.clone(),
            reserved_hold_id: None,
            reserving_request_id: None,
        };
        let signature = key.sign_wrapped(
            OPERATION_EXECUTION_NONCE_SCHEMA,
            &signing_body(&operation, &nonce)?,
        )?;
        let signed = SignedExecutionNonce { nonce, signature };
        verify_operation_execution_nonce_at(&signed, &operation, &key.public_key(), &binding, 100)?;
        verify_operation_execution_nonce_at(&signed, &operation, &key.public_key(), &binding, 129)?;
        for schema in [
            "chio.execution_nonce.v2",
            "chio.execution_nonce.v3",
            "chio.operation_execution_nonce.v2",
            "chio.operation_execution_nonce.v3",
        ] {
            let mut retired = signed.clone();
            retired.nonce.schema = schema.into();
            let body = signing_body(&operation, &retired.nonce)?;
            retired.signature = key.sign_wrapped(OPERATION_EXECUTION_NONCE_SCHEMA, &body)?;
            assert_eq!(
                verify_operation_execution_nonce_at(
                    &retired,
                    &operation,
                    &key.public_key(),
                    &binding,
                    100
                ),
                Err(AdmissionOperationStoreError::Invariant(
                    "operation nonce issuance interval is invalid".into()
                )),
                "{schema}"
            );
        }
        for now in [99, 130, 131] {
            assert!(verify_operation_execution_nonce_at(
                &signed,
                &operation,
                &key.public_key(),
                &binding,
                now
            )
            .is_err());
        }
        let other =
            crate::admission_operation::AdmissionOperationId::from_persisted("c".repeat(64))?;
        assert!(verify_operation_execution_nonce_at(
            &signed,
            &other,
            &key.public_key(),
            &binding,
            100
        )
        .is_err());
        assert!(verify_operation_execution_nonce_at(
            &signed,
            &operation,
            &Keypair::generate().public_key(),
            &binding,
            100
        )
        .is_err());
        let body = signing_body(&operation, &signed.nonce)?;
        for (label, signature) in crate::wrapper_refusals::refused_signatures_over(&key, &body) {
            let mut refused = signed.clone();
            refused.signature = signature;
            assert_eq!(
                verify_operation_execution_nonce_at(
                    &refused,
                    &operation,
                    &key.public_key(),
                    &binding,
                    100
                ),
                Err(AdmissionOperationStoreError::Invariant(
                    "operation-bound execution nonce signature is invalid".into()
                )),
                "{label}"
            );
        }
        let mut substituted = binding;
        substituted.request_id = "another-request".into();
        assert!(verify_operation_execution_nonce_at(
            &signed,
            &operation,
            &key.public_key(),
            &substituted,
            100
        )
        .is_err());
        Ok(())
    }
}
