//! Original JSON text is retained until the owning numeric and wire contract is checked.

use alloc::sync::Arc;
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
        bounded_text(bytes, bound).map(Self::new)
    }

    /// Strict I-JSON canonicalization. Full-width native integers use `decode_signed`.
    pub fn canonicalize(&self) -> Result<Vec<u8>, UntrustedJsonError> {
        super::canonical_json_bytes_from_str(self.text)
            .map_err(UntrustedJsonError::Canonicalization)
    }

    /// External I-JSON: validate original keys and numeric values before typed projection.
    pub fn decode_external<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        let canonical = self.canonicalize()?;
        serde_json::from_slice(&canonical).map_err(UntrustedJsonError::Decode)
    }

    /// Unsigned JSON documents: reject original duplicate keys, then apply the
    /// target's ordinary Serde numeric conversions. This accepts float spellings
    /// such as `0.10` and is suitable for approximate embedding vectors.
    /// Signed or authoritative records must use their signed/external/canonical
    /// contract instead; this does not enforce lossless numeric spelling.
    /// New readers name the contract by type with [`DocumentJson`].
    pub fn decode_document<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        let value = super::signed_json::parse_document(self.text)
            .map_err(UntrustedJsonError::SignedInput)?;
        serde_json::from_value(value).map_err(UntrustedJsonError::Decode)
    }

    /// Lossless native signed JSON, before the owner's signature and authorization checks.
    /// New readers name the contract by type with [`SignedRecordJson`].
    pub fn decode_signed<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        let value = super::signed_json::parse_signed_json(self.text)
            .map_err(UntrustedJsonError::SignedInput)?;
        serde_json::from_value(value).map_err(UntrustedJsonError::Decode)
    }

    /// Canonical wire/storage contract, including exact original-byte equality.
    pub fn decode_canonical<T: DeserializeOwned + Serialize>(
        &self,
    ) -> Result<T, UntrustedJsonError> {
        self.decode_canonical_with(super::canonical_json_bytes_zeroizing)
    }

    /// Decode private custody without granting the value a general `Serialize`
    /// implementation. The owner supplies its explicit canonical custody export;
    /// original-byte equality still rejects duplicate fields and alternate encodings.
    pub fn decode_canonical_with<T: DeserializeOwned>(
        &self,
        export: impl FnOnce(&T) -> super::Result<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Result<T, UntrustedJsonError> {
        let value: T = serde_json::from_str(self.text).map_err(UntrustedJsonError::Decode)?;
        let canonical = export(&value).map_err(UntrustedJsonError::Canonicalization)?;
        if canonical.as_slice() != self.text.as_bytes() {
            return Err(UntrustedJsonError::NonCanonical);
        }
        Ok(value)
    }
}

fn bounded_text(bytes: &[u8], bound: usize) -> Result<&str, UntrustedJsonError> {
    if bytes.len() > bound {
        return Err(UntrustedJsonError::TooLarge {
            bytes: bytes.len(),
            bound,
        });
    }
    core::str::from_utf8(bytes).map_err(UntrustedJsonError::NotUtf8)
}

/// Unsigned JSON documents: peer envelopes, tool arguments and payloads that
/// carry no signature. The input type fixes the numeric contract, so a decoder
/// cannot apply signed-record rules to producer output by choosing a method.
/// Duplicate keys are refused. Numbers follow the target's ordinary Serde
/// conversions, so producer spellings such as `0.50`, `1e-05` and `1e+16`
/// decode. Never use this for a record whose signature or digest is checked.
#[derive(Debug)]
pub struct DocumentJson<'a>(UntrustedJsonText<'a>);

impl<'a> DocumentJson<'a> {
    /// Mark already bounded text as an unsigned document without copying it.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(UntrustedJsonText { text })
    }

    /// Bound and UTF-8 check original wire bytes.
    pub fn from_wire(bytes: &'a [u8], bound: usize) -> Result<Self, UntrustedJsonError> {
        bounded_text(bytes, bound).map(Self::new)
    }

    /// Decode with duplicate-key rejection and ordinary numeric conversions.
    #[allow(
        clippy::disallowed_methods,
        reason = "The document contract type is the sanctioned caller of the document reader."
    )]
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        self.0.decode_document()
    }
}

/// Signed records and native records Chio wrote itself. The input type fixes
/// the numeric contract. Duplicate keys are refused, and every number token
/// must be a spelling a typed or canonical writer emits: full-width integers
/// stay exact and no fractional digit is discarded before the owner rebuilds
/// the signing body. Peer documents such as `0.50` or `1e-05` are refused, so
/// unsigned input belongs in [`DocumentJson`]. No signature is verified here.
#[derive(Debug)]
pub struct SignedRecordJson<'a>(UntrustedJsonText<'a>);

impl<'a> SignedRecordJson<'a> {
    /// Mark already bounded text as a signed or native record without copying it.
    #[must_use]
    pub const fn new(text: &'a str) -> Self {
        Self(UntrustedJsonText { text })
    }

    /// Bound and UTF-8 check original wire bytes.
    pub fn from_wire(bytes: &'a [u8], bound: usize) -> Result<Self, UntrustedJsonError> {
        bounded_text(bytes, bound).map(Self::new)
    }

    /// Decode losslessly, before the owner's signature and authorization checks.
    #[allow(
        clippy::disallowed_methods,
        reason = "The signed-record contract type is the sanctioned caller of the signed reader."
    )]
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, UntrustedJsonError> {
        self.0.decode_signed()
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

/// A shared parser failure for cloneable operation and recovery errors.
/// Equality identifies the same failure, rather than comparing sensitive input
/// embedded in a parser's diagnostic. Display and Debug expose only its rule.
#[derive(Clone, Debug)]
pub struct SharedUntrustedJsonError(Arc<UntrustedJsonError>);

impl From<UntrustedJsonError> for SharedUntrustedJsonError {
    fn from(error: UntrustedJsonError) -> Self {
        Self(Arc::new(error))
    }
}

impl SharedUntrustedJsonError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.0.code()
    }
}

impl PartialEq for SharedUntrustedJsonError {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for SharedUntrustedJsonError {}

impl fmt::Display for SharedUntrustedJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl core::error::Error for SharedUntrustedJsonError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod external_tests {
    use super::*;
    #[test]
    fn external_numeric_contract_does_not_narrow_native_signed_input(
    ) -> Result<(), UntrustedJsonError> {
        let text = r#"{"counter":18446744073709551615}"#;
        let input = UntrustedJsonText::from_wire(text.as_bytes(), 1024)?;
        let native: serde_json::Value = input.decode_signed()?;
        assert_eq!(native["counter"].as_u64(), Some(u64::MAX));
        assert!(matches!(
            input.decode_external::<serde_json::Value>(),
            Err(UntrustedJsonError::Canonicalization(_))
        ));
        let input = UntrustedJsonText::new(r#"{"extension":{"x":1,"x":2}}"#);
        assert!(matches!(
            input.decode_external::<serde_json::Value>(),
            Err(UntrustedJsonError::Canonicalization(_))
        ));
        Ok(())
    }
}

#[cfg(test)]
mod document_tests {
    use super::*;

    #[test]
    fn unsigned_floats_do_not_relax_signed_numeric_or_duplicate_contracts(
    ) -> Result<(), UntrustedJsonError> {
        let text = UntrustedJsonText::from_wire(b"[0.10,1.00,1e-2]", 128)?;
        assert_eq!(
            text.decode_document::<Vec<f32>>()?,
            alloc::vec![0.1, 1.0, 0.01]
        );
        assert!(matches!(
            text.decode_signed::<Vec<f32>>(),
            Err(UntrustedJsonError::SignedInput(_))
        ));
        assert!(matches!(
            text.decode_external::<Vec<f32>>(),
            Err(UntrustedJsonError::Canonicalization(_))
        ));
        let ambiguous =
            UntrustedJsonText::from_wire(br#"{"ignored":{"secret":1,"secret":2}}"#, 128)?;
        match ambiguous.decode_document::<serde_json::Value>() {
            Err(UntrustedJsonError::SignedInput(error)) => {
                assert!(core::error::Error::source(&error).is_some());
            }
            other => panic!("expected original duplicate rejection, got {other:?}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_type_tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn producer_spellings_decode_as_documents_and_refuse_as_signed_records(
    ) -> Result<(), UntrustedJsonError> {
        for (token, expected) in [
            ("0.50", 0.5),
            ("1e-05", 0.00001),
            ("1e+016", 1e16),
            ("1E2", 100.0),
            ("18446744073709551616", 18_446_744_073_709_551_616.0),
        ] {
            let text = alloc::format!(r#"{{"n":{token}}}"#);
            let document: Value = DocumentJson::from_wire(text.as_bytes(), 64)?.decode()?;
            assert_eq!(document["n"].as_f64(), Some(expected));
            assert!(matches!(
                SignedRecordJson::from_wire(text.as_bytes(), 64)?.decode::<Value>(),
                Err(UntrustedJsonError::SignedInput(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn writer_spellings_decode_identically_under_both_contracts() -> Result<(), UntrustedJsonError>
    {
        for text in [
            r#"{"n":0.5}"#,
            r#"{"n":100}"#,
            r#"{"n":18446744073709551615}"#,
            r#"{"n":-9223372036854775808}"#,
        ] {
            let document: Value = DocumentJson::new(text).decode()?;
            let signed: Value = SignedRecordJson::new(text).decode()?;
            assert_eq!(document, signed);
        }
        let wide: Value = SignedRecordJson::new(r#"{"n":18446744073709551615}"#).decode()?;
        assert_eq!(wide["n"].as_u64(), Some(u64::MAX));
        Ok(())
    }

    #[test]
    fn both_contracts_refuse_duplicates_oversize_and_invalid_utf8() {
        let duplicate = br#"{"n":1,"n":2}"#;
        assert!(matches!(
            DocumentJson::from_wire(duplicate, 64).and_then(|input| input.decode::<Value>()),
            Err(UntrustedJsonError::SignedInput(_))
        ));
        assert!(matches!(
            SignedRecordJson::from_wire(duplicate, 64).and_then(|input| input.decode::<Value>()),
            Err(UntrustedJsonError::SignedInput(_))
        ));
        assert!(matches!(
            DocumentJson::from_wire(duplicate, 4),
            Err(UntrustedJsonError::TooLarge {
                bytes: 13,
                bound: 4
            })
        ));
        assert!(matches!(
            SignedRecordJson::from_wire(duplicate, 4),
            Err(UntrustedJsonError::TooLarge {
                bytes: 13,
                bound: 4
            })
        ));
        assert!(matches!(
            DocumentJson::from_wire(&[0xff], 4),
            Err(UntrustedJsonError::NotUtf8(_))
        ));
        assert!(matches!(
            SignedRecordJson::from_wire(&[0xff], 4),
            Err(UntrustedJsonError::NotUtf8(_))
        ));
    }
}
