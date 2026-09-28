//! Original JSON text is retained until the owning numeric and wire contract is checked.

use alloc::vec::Vec;
use core::{fmt, str::Utf8Error};
use serde::{de::DeserializeOwned, Serialize};

use crate::error::Error;

/// Untrusted text. No raw accessor, serde implementation, or implicit string conversion.
/// Native signed records and I-JSON have deliberately different numeric domains.
pub struct UntrustedJsonText<'a> {
    text: &'a str,
}

impl fmt::Debug for UntrustedJsonText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UntrustedJsonText")
            .field("bytes", &self.text.len())
            .finish()
    }
}

impl<'a> UntrustedJsonText<'a> {
    /// Mark already bounded file/database text as untrusted without copying it.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self { text }
    }

    pub fn from_wire(bytes: &'a [u8], bound: usize) -> Result<Self, UntrustedJsonError> {
        if bytes.len() > bound {
            return Err(UntrustedJsonError::TooLarge {
                bytes: bytes.len(),
                bound,
            });
        }
        core::str::from_utf8(bytes)
            .map(Self::new)
            .map_err(UntrustedJsonError::NotUtf8)
    }

    /// Strict I-JSON canonicalization. Full-width native integers use `decode_signed`.
    pub fn canonicalize(&self) -> Result<Vec<u8>, UntrustedJsonError> {
        super::canonical_json_bytes_from_str(self.text)
            .map_err(UntrustedJsonError::Canonicalization)
    }

    /// Lossless native signed JSON, before the owner's signature and authorization checks.
    pub fn decode_signed<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        let value = super::signed_json::parse_signed_json(self.text)
            .map_err(UntrustedJsonError::SignedInput)?;
        serde_json::from_value(value).map_err(UntrustedJsonError::Decode)
    }

    /// Canonical wire/storage contract, including exact original-byte equality.
    pub fn decode_canonical<T: DeserializeOwned + Serialize>(
        &self,
    ) -> Result<T, UntrustedJsonError> {
        let value: T = serde_json::from_str(self.text).map_err(UntrustedJsonError::Decode)?;
        let canonical = zeroize::Zeroizing::new(
            super::canonical_json_bytes(&value).map_err(UntrustedJsonError::Canonicalization)?,
        );
        if canonical.as_slice() != self.text.as_bytes() {
            return Err(UntrustedJsonError::NonCanonical);
        }
        Ok(value)
    }
}

/// Stable rules for input rejection. Display never includes untrusted text.
pub enum UntrustedJsonError {
    TooLarge { bytes: usize, bound: usize },
    NotUtf8(Utf8Error),
    SignedInput(Error),
    Decode(serde_json::Error),
    Canonicalization(Error),
    NonCanonical,
}

impl fmt::Debug for UntrustedJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Parser sources can contain rejected values. Logs get only the rule;
        // a trusted diagnostic consumer can explicitly inspect Error::source.
        f.debug_struct("UntrustedJsonError")
            .field("code", &self.code())
            .finish()
    }
}

impl UntrustedJsonError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "urn:chio:error:attest:signed-json-too-large",
            Self::NotUtf8(_) => "urn:chio:error:attest:signed-json-not-utf8",
            Self::SignedInput(_) => "urn:chio:error:attest:signed-json-invalid-input",
            Self::Decode(_) => "urn:chio:error:attest:signed-json-invalid-shape",
            Self::Canonicalization(_) => "urn:chio:error:attest:signed-json-canonicalization",
            Self::NonCanonical => "urn:chio:error:attest:signed-json-noncanonical",
        }
    }
}

impl fmt::Display for UntrustedJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for UntrustedJsonError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotUtf8(error) => Some(error),
            Self::SignedInput(error) | Self::Canonicalization(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::TooLarge { .. } | Self::NonCanonical => None,
        }
    }
}
