//! Storage ports for a verifier's single-use ledgers. A backend applies a
//! transition only while the row still holds the expected status and reports
//! whether that guard held, so two racing spenders cannot both win.

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerFieldError {
    #[error("{0} must be 1 to 512 characters without NUL")]
    Identifier(&'static str),
    #[error("{0} must be a lowercase hex SHA-256 digest")]
    Digest(&'static str),
}

fn identifier(value: &str, field: &'static str) -> Result<(), LedgerFieldError> {
    let chars = value.chars().count();
    if chars == 0 || chars > 512 || value.contains('\0') {
        return Err(LedgerFieldError::Identifier(field));
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), LedgerFieldError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LedgerFieldError::Digest(field));
    }
    Ok(())
}

macro_rules! ledger_text {
    ($name:ident, $check:ident, $field:literal) => {
        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, super::LedgerFieldError> {
                let value = value.into();
                super::$check(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

pub mod oid4vp_requests;
pub mod presentation_challenges;

/// Why a ledger backend could not complete an operation. Backend causes stay in
/// the backend; a port caller sees only this closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerFault {
    #[error("verifier ledger already holds this identifier")]
    Duplicate,
    #[error("verifier ledger cannot store this value")]
    Unrepresentable,
    #[error("verifier ledger is unavailable")]
    Unavailable,
    #[error("verifier ledger holds a row or schema that fails its integrity checks")]
    IntegrityFailure,
}

/// One backend serving both single-use ledgers of a verifier, shared by every
/// request of the process that opened it.
pub trait VerifierLedger:
    presentation_challenges::PresentationChallengeLedger<Error = LedgerFault>
    + oid4vp_requests::Oid4vpRequestLedger<Error = LedgerFault>
    + Send
    + Sync
{
}

#[cfg(test)]
mod tests {
    use super::oid4vp_requests::Oid4vpRequestHash;
    use super::presentation_challenges::PresentationChallengeId;
    use super::LedgerFieldError;

    #[test]
    fn identifiers_are_bounded_and_nul_free() {
        let longest = "\u{1f600}".repeat(512);
        assert!(PresentationChallengeId::parse(longest.as_str()).is_ok());
        for refused in [String::new(), "x".repeat(513), "a\0b".to_owned()] {
            assert_eq!(
                PresentationChallengeId::parse(refused),
                Err(LedgerFieldError::Identifier("challenge_id"))
            );
        }
    }

    #[test]
    fn digests_are_lowercase_sha256_hex() {
        assert!(Oid4vpRequestHash::parse("0".repeat(64)).is_ok());
        for refused in [
            "0".repeat(63),
            "0".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert_eq!(
                Oid4vpRequestHash::parse(refused),
                Err(LedgerFieldError::Digest("request_hash"))
            );
        }
    }
}
