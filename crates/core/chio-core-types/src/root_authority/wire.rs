//! Bounded string, digest and key encodings shared by the root-authority artifacts.

use alloc::string::{String, ToString};
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::capability::attenuation::scope_hash;
use crate::capability::scope::ChioScope;
use crate::crypto::{PublicKey, Signature};
use crate::hashing::{Hash, Sha256State};

use super::RootAuthorityShapeError;

/// Declares `$name`, a validated wrapper around its `$fields` struct.
///
/// `$name::new` and the `Deserialize` impl are the only ways to build one,
/// and both run `$fields::validate`. Fields are read through `Deref`; a
/// changed value is rebuilt from [`into_fields`](#method.into_fields) and
/// validated again. `Serialize` is transparent, so the wire form is the
/// fields' own.
macro_rules! validated_type {
    ($(#[$meta:meta])* $name:ident($fields:ident)) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        pub struct $name($fields);

        impl $name {
            /// Validate `fields` and wrap them.
            pub fn new(fields: $fields) -> core::result::Result<Self, RootAuthorityShapeError> {
                fields.validate()?;
                Ok(Self(fields))
            }

            /// The validated fields, for building a changed value through `new`.
            #[must_use]
            pub fn into_fields(self) -> $fields {
                self.0
            }
        }

        impl core::ops::Deref for $name {
            type Target = $fields;

            fn deref(&self) -> &$fields {
                &self.0
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                let fields = <$fields as serde::Deserialize>::deserialize(deserializer)?;
                Self::new(fields).map_err(serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use validated_type;

/// `^[^\u0000\s]` characters: NUL and the ECMAScript `\s` class.
fn is_nul_or_space(character: char) -> bool {
    character == '\0' || character.is_whitespace() || character == '\u{feff}'
}

fn check_length(
    field: &'static str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), RootAuthorityShapeError> {
    let actual = value.chars().count();
    if actual < min || actual > max {
        return Err(RootAuthorityShapeError::Length {
            field,
            min,
            max,
            actual,
        });
    }
    Ok(())
}

pub(crate) fn check_nul_free(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), RootAuthorityShapeError> {
    check_length(field, value, 1, max)?;
    if value.contains('\0') {
        return Err(RootAuthorityShapeError::Nul { field });
    }
    Ok(())
}

pub(crate) fn check_items(
    field: &'static str,
    actual: usize,
    min: usize,
    max: usize,
) -> Result<(), RootAuthorityShapeError> {
    if actual < min || actual > max {
        return Err(RootAuthorityShapeError::Items {
            field,
            min,
            max,
            actual,
        });
    }
    Ok(())
}

pub(crate) fn check_unique<T: PartialEq>(
    field: &'static str,
    items: &[T],
) -> Result<(), RootAuthorityShapeError> {
    for (index, item) in items.iter().enumerate() {
        if items.iter().skip(index + 1).any(|other| other == item) {
            return Err(RootAuthorityShapeError::Duplicate { field });
        }
    }
    Ok(())
}

macro_rules! bounded_text {
    ($(#[$meta:meta])* $name:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validate `value` against this encoding.
            pub fn new(value: impl Into<String>) -> Result<Self, RootAuthorityShapeError> {
                let value = value.into();
                let check: fn(&str) -> Result<(), RootAuthorityShapeError> = $check;
                check(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_text!(
    /// A NUL-free identifier of 1 to 128 characters.
    Identifier,
    |value| check_nul_free("identifier", value, 128)
);

bounded_text!(
    /// A NUL-free string of 1 to 1024 characters.
    Text,
    |value| check_nul_free("text", value, 1024)
);

bounded_text!(
    /// A URI or URN of 1 to 2048 characters without NUL or whitespace.
    Uri,
    |value| {
        check_length("uri", value, 1, 2048)?;
        if value.chars().any(is_nul_or_space) {
            return Err(RootAuthorityShapeError::Pattern {
                field: "uri",
                expected: "a URI without NUL or whitespace",
            });
        }
        Ok(())
    }
);

bounded_text!(
    /// An `https://` URL of at most 2048 characters without NUL or whitespace.
    HttpsUrl,
    |value| {
        check_length("https_url", value, 1, 2048)?;
        let rest = value.strip_prefix("https://").unwrap_or_default();
        if rest.is_empty() || rest.chars().any(is_nul_or_space) {
            return Err(RootAuthorityShapeError::Pattern {
                field: "https_url",
                expected: "an https:// URL without NUL or whitespace",
            });
        }
        Ok(())
    }
);

bounded_text!(
    /// A disclosure-store salt reference: dotted lowercase segments, at most 64 characters.
    SaltRef,
    |value| {
        check_length("salt_ref", value, 1, 64)?;
        let mut segments = value.split('.');
        let head_ok = segments.next().is_some_and(|head| {
            head.chars().next().is_some_and(|first| first.is_ascii_lowercase())
                && head.chars().all(is_salt_ref_char)
        });
        let tail_ok = segments.all(|segment| !segment.is_empty() && segment.chars().all(is_salt_ref_char));
        if !head_ok || !tail_ok {
            return Err(RootAuthorityShapeError::Pattern {
                field: "salt_ref",
                expected: "^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*$",
            });
        }
        Ok(())
    }
);

fn is_salt_ref_char(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
}

/// A SHA-256 digest encoded as `sha256:` and 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    const PREFIX: &'static str = "sha256:";

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn from_hash(hash: Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// `SHA-256(domain || body)`.
    #[must_use]
    pub fn of_domain(domain: &[u8], body: &[u8]) -> Self {
        let mut state = Sha256State::new();
        state.update(domain);
        state.update(body);
        Self::from_hash(state.finalize())
    }

    /// SHA-256 of the canonical scope, as [`scope_hash`] computes it.
    pub fn of_scope(scope: &ChioScope) -> crate::Result<Self> {
        let hex_digest = scope_hash(scope)?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(hex_digest, &mut bytes)
            .map_err(|error| crate::Error::InvalidHex(error.to_string()))?;
        Ok(Self(bytes))
    }

    /// Parse the `sha256:<64 lowercase hex>` encoding.
    pub fn parse(value: &str) -> Result<Self, RootAuthorityShapeError> {
        let invalid = RootAuthorityShapeError::Pattern {
            field: "digest",
            expected: "sha256:<64 lowercase hex>",
        };
        let hex_part = value.strip_prefix(Self::PREFIX).ok_or(invalid.clone())?;
        if hex_part.len() != 64
            || !hex_part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid);
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(hex_part, &mut bytes).map_err(|_| invalid)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex without the `sha256:` prefix.
    #[must_use]
    pub fn to_bare_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::PREFIX)?;
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A base64url text value (`^[A-Za-z0-9_-]+$`) of at most `MAX` characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Base64UrlText<const MAX: usize>(String);

impl<const MAX: usize> Base64UrlText<MAX> {
    pub fn new(value: impl Into<String>) -> Result<Self, RootAuthorityShapeError> {
        let value = value.into();
        check_length("base64url", &value, 1, MAX)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(RootAuthorityShapeError::Pattern {
                field: "base64url",
                expected: "^[A-Za-z0-9_-]+$",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> Serialize for Base64UrlText<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Base64UrlText<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A padded standard base64 value (`^[A-Za-z0-9+/]+={0,2}$`) of at most `MAX` characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Base64Text<const MAX: usize>(String);

impl<const MAX: usize> Base64Text<MAX> {
    pub fn new(value: impl Into<String>) -> Result<Self, RootAuthorityShapeError> {
        let value = value.into();
        check_length("base64", &value, 1, MAX)?;
        let body = value.trim_end_matches('=');
        let padding = value.len() - body.len();
        if body.is_empty()
            || padding > 2
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        {
            return Err(RootAuthorityShapeError::Pattern {
                field: "base64",
                expected: "^[A-Za-z0-9+/]+={0,2}$",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MAX: usize> Serialize for Base64Text<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for Base64Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Decode a public key only in its canonical self-describing encoding.
pub(crate) fn canonical_public_key<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PublicKey, D::Error> {
    let text = String::deserialize(deserializer)?;
    let key = PublicKey::from_hex(&text).map_err(serde::de::Error::custom)?;
    if key.to_hex() != text {
        return Err(serde::de::Error::custom(
            RootAuthorityShapeError::NonCanonicalEncoding {
                field: "public_key",
            },
        ));
    }
    Ok(key)
}

/// Decode a list of public keys, each in its canonical encoding.
pub(crate) fn canonical_public_keys<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<alloc::vec::Vec<PublicKey>, D::Error> {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Canonical(#[serde(deserialize_with = "canonical_public_key")] PublicKey);
    let keys = alloc::vec::Vec::<Canonical>::deserialize(deserializer)?;
    Ok(keys.into_iter().map(|Canonical(key)| key).collect())
}

/// Decode a signature only in its canonical self-describing encoding.
pub(crate) fn canonical_signature<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Signature, D::Error> {
    let text = String::deserialize(deserializer)?;
    let signature = Signature::from_hex(&text).map_err(serde::de::Error::custom)?;
    if signature.to_hex() != text {
        return Err(serde::de::Error::custom(
            RootAuthorityShapeError::NonCanonicalEncoding { field: "signature" },
        ));
    }
    Ok(signature)
}

/// A `schema` member pinned to one value.
pub(crate) fn check_schema(
    actual: &str,
    expected: &'static str,
) -> Result<(), RootAuthorityShapeError> {
    if actual != expected {
        return Err(RootAuthorityShapeError::Const {
            field: "schema",
            expected,
        });
    }
    Ok(())
}
