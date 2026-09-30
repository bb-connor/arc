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
