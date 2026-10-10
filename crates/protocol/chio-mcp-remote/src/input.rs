//! Original-byte parsing for peer documents and locally persisted signed state.
use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// Encode trusted typed rows within the unchanged native reader's byte ceiling.
pub(crate) fn encode_session<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    struct BoundedOutput(Vec<u8>);
    impl std::io::Write for BoundedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_SESSION_JSON_BYTES.saturating_sub(self.0.len()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MCP durable JSON exceeds its native reader byte limit",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut output, value)?;
    String::from_utf8(output.0).map_err(|error| {
        serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.utf8_error(),
        ))
    })
}

pub(crate) const MAX_CONTROL_JSON_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SESSION_JSON_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_AUTH_JSON_BYTES: usize = 64 * 1024;

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_signed()
}

/// Peer requests carry ordinary JSON numbers, while persisted/auth records use decode.
pub(crate) fn document<T: DeserializeOwned>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, UntrustedJsonError> {
    UntrustedJsonText::from_wire(bytes, bound)?.decode_document()
}

/// Keep the typed parser cause available to local middleware without rendering payload text.
pub(crate) fn with_source<E>(mut response: Response, error: E) -> Response
where
    E: std::error::Error + Send + Sync + 'static,
{
    response.extensions_mut().insert(Arc::new(error));
    response
}

pub(crate) struct BoundedJson<T>(pub T);
impl<S, T> FromRequest<S> for BoundedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Response;
    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let is_json = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
        }
        let bytes = axum::body::to_bytes(request.into_body(), MAX_CONTROL_JSON_BYTES)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())?;
        document(&bytes, MAX_CONTROL_JSON_BYTES)
            .map(Self)
            .map_err(|error| {
                with_source(
                    (StatusCode::BAD_REQUEST, error.code()).into_response(),
                    error,
                )
            })
    }
}

#[derive(thiserror::Error)]
pub(crate) enum SenderConstraintError {
    #[error("{}", .0.code())]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    Replay(#[from] chio_kernel::KernelError),
    #[error("{0}")]
    Json(#[from] UntrustedJsonError),
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Encoding(#[from] base64::DecodeError),
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Header(#[from] axum::http::header::ToStrError),
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    UnsupportedSchema,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    MissingBinding,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    MtlsBinding,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    AttestationBinding,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    MissingProof,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    SenderKeyMismatch,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    TargetMismatch,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    EmptyNonce,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    InvalidSignature,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    NonceReused,
    #[error("urn:chio:error:transport:dpop-verification-failed")]
    Canonical(#[from] chio_core::error::Error),
}
impl std::fmt::Debug for SenderConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::error::Error;

    #[test]
    fn native_envelopes_preserve_u64_and_reject_original_duplicate_keys() {
        let value: Value = decode(br#"{"id":18446744073709551615}"#, 100).unwrap();
        assert_eq!(value["id"].as_u64(), Some(u64::MAX));
        for bytes in [
            br#"{"params":{"secret_marker":1,"secret_marker":2}}"#.as_slice(),
            b"{",
            br#"{"number":0.123456789012345678901}"#,
        ] {
            let error = decode::<Value>(bytes, 100).unwrap_err();
            assert!(error.source().is_some());
            assert!(!format!("{error:?} {error}").contains("secret_marker"));
        }
        assert!(matches!(
            decode::<Value>(b"{}", 1),
            Err(UntrustedJsonError::TooLarge { bytes: 2, bound: 1 })
        ));
    }

    #[tokio::test]
    async fn administrative_extractor_rejects_duplicates_and_retains_local_source() {
        let request = Request::builder()
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"arguments":{"token":"private","token":"replacement"}}"#,
            ))
            .unwrap();
        let response = match BoundedJson::<Value>::from_request(request, &()).await {
            Ok(_) => panic!("duplicate key accepted"),
            Err(response) => response,
        };
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
        assert!(!std::str::from_utf8(&body).unwrap().contains("private"));
    }
}
