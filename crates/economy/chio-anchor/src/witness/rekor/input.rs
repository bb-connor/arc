//! Original response and nested body budgets, before projection or retention.
use super::{AnchorWitnessError, RekorPublishResponse, BASE64_STANDARD};
use base64::Engine;
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};

pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(super) fn decode_body(encoded: &str) -> Result<Vec<u8>, AnchorWitnessError> {
    let encoded_bound = MAX_BODY_BYTES.div_ceil(3) * 4;
    if encoded.len() > encoded_bound {
        return Err(UntrustedJsonError::TooLarge {
            bytes: encoded.len(),
            bound: encoded_bound,
        }
        .into());
    }
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(AnchorWitnessError::Base64)?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(UntrustedJsonError::TooLarge {
            bytes: bytes.len(),
            bound: MAX_BODY_BYTES,
        }
        .into());
    }
    Ok(bytes)
}

pub(super) async fn response(
    mut response: reqwest::Response,
) -> Result<RekorPublishResponse, AnchorWitnessError> {
    let status = response.status();
    if !status.is_success() {
        return Err(AnchorWitnessError::Http {
            status: status.as_u16(),
            body: "Rekor request rejected".to_owned(),
        });
    }
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_RESPONSE_BYTES as u64)
    {
        return Err(UntrustedJsonError::TooLarge {
            bytes: MAX_RESPONSE_BYTES + 1,
            bound: MAX_RESPONSE_BYTES,
        }
        .into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(AnchorWitnessError::transport)?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
            return Err(UntrustedJsonError::TooLarge {
                bytes: MAX_RESPONSE_BYTES + 1,
                bound: MAX_RESPONSE_BYTES,
            }
            .into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let parsed: RekorPublishResponse =
        UntrustedJsonText::from_wire(&bytes, MAX_RESPONSE_BYTES)?.decode_signed()?;
    if parsed.entries.len() != 1 {
        return Err(AnchorWitnessError::Decode(
            "Rekor must return exactly one entry".to_owned(),
        ));
    }
    Ok(parsed)
}
