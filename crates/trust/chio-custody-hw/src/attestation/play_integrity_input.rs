//! Reject ambiguous JWS/JWKS input before the JWT library projects its fields.
use super::errors::AttestationError;
use base64ct::{Base64UrlUnpadded, Encoding};
use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};

pub(super) const MAX_TOKEN_BYTES: usize = 64 * 1024;
pub(super) const MAX_JWKS_BYTES: usize = 256 * 1024;

pub(super) fn validate_token(token: &str) -> Result<(), AttestationError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(UntrustedJsonError::TooLarge {
            bytes: token.len(),
            bound: MAX_TOKEN_BYTES,
        }
        .into());
    }
    let mut parts = token.split('.');
    for _ in 0..2 {
        let encoded = parts.next().ok_or_else(invalid_segments)?;
        let decoded = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| invalid_segments())?;
        let _: serde_json::Value =
            UntrustedJsonText::from_wire(&decoded, MAX_TOKEN_BYTES)?.decode_external()?;
    }
    if parts.next().is_none_or(str::is_empty) || parts.next().is_some() {
        return Err(invalid_segments());
    }
    Ok(())
}

fn invalid_segments() -> AttestationError {
    AttestationError::PlayIntegrityInvalidToken("invalid compact JWS encoding".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_original_header_and_claims_are_checked_before_projection() {
        for (header, claims) in [
            (r#"{"kid":"secret-sentinel","kid":"other"}"#, "{}"),
            ("{}", r#"{"nonce":"first","nonce":"second"}"#),
            ("{}", r#"{"custom":9007199254740993}"#),
        ] {
            let token = format!(
                "{}.{}.signature",
                Base64UrlUnpadded::encode_string(header.as_bytes()),
                Base64UrlUnpadded::encode_string(claims.as_bytes())
            );
            let result = validate_token(&token);
            assert!(matches!(result, Err(AttestationError::Input(_))));
            assert!(!format!("{result:?}").contains("secret-sentinel"));
        }
    }
    #[test]
    fn token_limit_precedes_base64_allocation() {
        let raw = "A".repeat(MAX_TOKEN_BYTES + 1);
        assert!(matches!(
            validate_token(&raw),
            Err(AttestationError::Input(_))
        ));
    }
}
