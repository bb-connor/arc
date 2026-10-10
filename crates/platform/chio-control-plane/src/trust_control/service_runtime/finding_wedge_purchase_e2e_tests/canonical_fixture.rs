use super::*;

pub(super) fn digest_of<T: serde::Serialize>(value: &T) -> Result<String, AnyError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

pub(super) fn canonical_string<T: serde::Serialize>(value: &T) -> Result<String, AnyError> {
    Ok(String::from_utf8(canonical_json_bytes(value)?)?)
}
/// The exact two-field envelope the reveal server returns.
pub(super) fn reveal_envelope(media_type: &str, payload: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "media_type": media_type,
        "payload_b64": STANDARD.encode(payload),
    })
}
