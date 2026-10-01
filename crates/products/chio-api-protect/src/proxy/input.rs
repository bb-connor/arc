//! Original-byte JSON boundaries and redacted HTTP diagnostics.
use super::*;
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;

pub(crate) const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;
pub(crate) const MAX_RECEIPT_BYTES: usize = 1024 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_signed()
}

/// Requests carry unsigned arguments alongside signed credentials. Preserve each
/// original credential lexeme instead of validating a rounded Value projection.
pub(crate) fn decode_arguments<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    let input = UntrustedJsonText::from_wire(bytes, bound)?;
    let fields: std::collections::BTreeMap<String, &serde_json::value::RawValue> =
        serde_json::from_slice(bytes).map_err(UntrustedJsonError::Decode)?;
    for (name, value) in fields {
        match name.as_str() {
            "arguments" | "parameters" => {}
            "governed_intent" => validate_governed_fields(value, bound)?,
            _ => validate_signed_value(value, bound)?,
        }
    }
    // This validates original duplicate keys, including nested argument keys,
    // before the request DTO is projected and before any authority is exercised.
    input.decode_document()
}

fn validate_signed_value(
    value: &serde_json::value::RawValue,
    bound: usize,
) -> Result<(), UntrustedJsonError> {
    UntrustedJsonText::from_wire(value.get().as_bytes(), bound)?
        .decode_signed::<serde_json::Value>()?;
    Ok(())
}

/// An intent has caller-created context and normalized runtime evidence, plus
/// fields that can contain signed plans or outcomes. Validate credential slices
/// before the request's final duplicate-aware document projection.
fn validate_governed_fields(
    value: &serde_json::value::RawValue,
    bound: usize,
) -> Result<(), UntrustedJsonError> {
    use chio_core_types::capability::governance::{
        GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY,
        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY,
    };
    type Fields<'a> = std::collections::BTreeMap<String, &'a serde_json::value::RawValue>;
    let fields: Option<Fields<'_>> =
        serde_json::from_str(value.get()).map_err(UntrustedJsonError::Decode)?;
    let Some(fields) = fields else {
        return Ok(());
    };
    for (name, field) in fields {
        match name.as_str() {
            "runtime_attestation" => {} // Unsigned RuntimeAttestationEvidence DTO.
            "context" => {
                // Arbitrary non-object context cannot carry the reserved keys.
                if field.get().trim_start().starts_with('{') {
                    let context: Fields<'_> =
                        serde_json::from_str(field.get()).map_err(UntrustedJsonError::Decode)?;
                    for key in [
                        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY,
                        GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY,
                    ] {
                        if let Some(proof) = context.get(key) {
                            validate_signed_value(proof, bound)?;
                        }
                    }
                }
            }
            _ => validate_signed_value(field, bound)?,
        }
    }
    Ok(())
}

pub(crate) fn with_source<E: std::error::Error + Send + Sync + 'static>(
    mut response: Response,
    error: E,
) -> Response {
    response.extensions_mut().insert(Arc::new(error));
    response
}

pub(crate) fn rejected(error: UntrustedJsonError) -> Response {
    with_source(sidecar_bad_request(error.code()).into_response(), error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn unsigned_arguments_do_not_relax_original_signed_credential_numbers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value: serde_json::Value =
            decode_arguments(br#"{"arguments":{"n":0.50,"id":9007199254740993}}"#, 1024)?;
        assert_eq!(value["arguments"]["n"].as_f64(), Some(0.5));
        assert_eq!(value["arguments"]["id"].as_u64(), Some(9007199254740993));
        for bytes in [
            br#"{"arguments":{"n":1,"n":2}}"#.as_slice(),
            br#"{"arguments":{},"arguments":{"n":1}}"#,
            br#"{"parameters":{"n":0.50},"capability":{"signed_number":0.50}}"#,
            br#"{"arguments":{},"execution_nonce":{"signed_number":0.123456789012345678901}}"#,
        ] {
            assert!(decode_arguments::<serde_json::Value>(bytes, 1024).is_err());
        }
        assert!(decode::<serde_json::Value>(br#"{"n":0.50}"#, MAX_HEADER_BYTES).is_err());
        assert!(decode_arguments::<serde_json::Value>(b"{}", 1).is_err());
        Ok(())
    }

    #[test]
    fn governed_unsigned_fields_keep_original_reserved_credential_slices(
    ) -> Result<(), Box<dyn Error>> {
        let value: serde_json::Value = decode_arguments(
            br#"{"governed_intent":{"context":{"measurement":1e-05},"runtime_attestation":{"claims":{"confidence":0.50}}}}"#, 1024,
        )?;
        assert_eq!(
            value["governed_intent"]["runtime_attestation"]["claims"]["confidence"],
            serde_json::json!(0.5)
        );
        for bytes in [
            br#"{"governed_intent":{"context":{"callChainUpstreamProof":{"signed_number":0.50}}}}"#
                .as_slice(),
            br#"{"governed_intent":{"context":{"callChainContinuation":{"signed_number":1e-05}}}}"#,
            br#"{"governed_intent":{"body":{"canonical_plan_body":{"signed_number":0.50}}}}"#,
        ] {
            assert!(matches!(
                decode_arguments::<serde_json::Value>(bytes, 1024),
                Err(UntrustedJsonError::SignedInput(_))
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn original_input_rejection_retains_source_without_reflecting_secrets() {
        let error = decode::<serde_json::Value>(
            br#"{"scope":{"private-marker":1,"private-marker":2}}"#,
            MAX_BODY_BYTES,
        )
        .unwrap_err();
        assert!(error.source().is_some());
        let response = rejected(error);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response
            .extensions()
            .get::<Arc<UntrustedJsonError>>()
            .unwrap()
            .source()
            .is_some());
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("signed-json-invalid-input"));
        assert!(!text.contains("private-marker"));
    }

    #[test]
    fn header_limits_and_native_integer_domain_are_enforced_before_projection() {
        let error =
            decode::<serde_json::Value>(&vec![b' '; MAX_HEADER_BYTES + 1], MAX_HEADER_BYTES)
                .unwrap_err();
        assert!(matches!(error, UntrustedJsonError::TooLarge { .. }));
        let value: serde_json::Value = decode(br#"{"n":18446744073709551615}"#, 100).unwrap();
        assert_eq!(value["n"].as_u64(), Some(u64::MAX));
    }
}
