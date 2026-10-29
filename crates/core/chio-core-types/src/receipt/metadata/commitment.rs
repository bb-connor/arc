//! Salted commitments over single receipt-metadata field values.
//!
//! A committed field is `{alg, value, salt_ref}` with `salt_ref` `metadata.<block>.<field>`
//! and value `SHA-256(chio.receipt.metadata.v1\0 || utf8(salt_ref) || 0x00 || salt ||
//! canonical JSON of the field value)`. The salt and the canonical value form the field's
//! opening; openings never enter a signed body.

use alloc::collections::btree_map::{self, BTreeMap};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::canonical::canonical_json_bytes;
use crate::receipt::commitment::{commit, CommitmentAlg, CommitmentDomain, Salt};
use crate::rng::{Rng, RngError};
use crate::root_authority::{SaltRef, Sha256Digest};

/// Every metadata `salt_ref` starts with this segment.
pub const METADATA_SALT_REF_PREFIX: &str = "metadata.";

/// Accepts exactly the `salt_ref`s the `receipt_metadata_values.salt_ref` column accepts:
/// `metadata.` followed by a segment that starts with a lowercase letter, every segment
/// `[a-z0-9_]+`, at most 64 bytes.
pub fn check_metadata_salt_ref(salt_ref: &SaltRef) -> Result<(), MetadataCommitmentError> {
    let accepted = salt_ref
        .as_str()
        .strip_prefix(METADATA_SALT_REF_PREFIX)
        .and_then(|rest| rest.bytes().next())
        .is_some_and(|first| first.is_ascii_lowercase());
    if accepted {
        Ok(())
    } else {
        Err(MetadataCommitmentError::SaltRef {
            salt_ref: salt_ref.as_str().to_string(),
        })
    }
}

/// The `salt_ref` `metadata.<block>.<field>` of one committed field.
pub fn metadata_salt_ref(block: &str, field: &str) -> Result<SaltRef, MetadataCommitmentError> {
    let text = format!("{METADATA_SALT_REF_PREFIX}{block}.{field}");
    let salt_ref = SaltRef::new(text.clone())
        .map_err(|_| MetadataCommitmentError::SaltRef { salt_ref: text })?;
    check_metadata_salt_ref(&salt_ref)?;
    Ok(salt_ref)
}

/// Canonical JSON (RFC 8785) of one committed metadata field's value. Zeroized on drop;
/// `Debug` never prints it; equality is constant-time.
#[derive(Clone)]
pub struct MetadataValue(Zeroizing<Vec<u8>>);

impl MetadataValue {
    /// Canonicalizes `value`. A value that has no canonical JSON form is refused.
    pub fn from_json<T: Serialize>(value: &T) -> Result<Self, MetadataCommitmentError> {
        canonical_json_bytes(value)
            .map(|bytes| Self(Zeroizing::new(bytes)))
            .map_err(|error| MetadataCommitmentError::Value(error.to_string()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for MetadataValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for MetadataValue {}

impl fmt::Debug for MetadataValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataValue(..)")
    }
}

/// The salt and canonical value of one metadata commitment. `Debug` prints neither.
#[derive(Clone, PartialEq, Eq)]
pub struct MetadataOpening {
    pub salt: Salt,
    pub value: MetadataValue,
}

impl fmt::Debug for MetadataOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetadataOpening(..)")
    }
}

/// A committed metadata field. Its `salt_ref` is always a metadata `salt_ref`; decoding
/// refuses any other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MetadataCommitmentWire")]
pub struct MetadataCommitment {
    alg: CommitmentAlg,
    value: Sha256Digest,
    salt_ref: SaltRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCommitmentWire {
    alg: CommitmentAlg,
    value: Sha256Digest,
    salt_ref: SaltRef,
}

impl TryFrom<MetadataCommitmentWire> for MetadataCommitment {
    type Error = MetadataCommitmentError;

    fn try_from(wire: MetadataCommitmentWire) -> Result<Self, Self::Error> {
        check_metadata_salt_ref(&wire.salt_ref)?;
        Ok(Self {
            alg: wire.alg,
            value: wire.value,
            salt_ref: wire.salt_ref,
        })
    }
}

impl MetadataCommitment {
    /// Commits `opening` under `salt_ref`.
    pub fn compute(
        salt_ref: SaltRef,
        opening: &MetadataOpening,
    ) -> Result<Self, MetadataCommitmentError> {
        check_metadata_salt_ref(&salt_ref)?;
        let value = commit(
            CommitmentDomain::Metadata(&salt_ref),
            &opening.salt,
            opening.value.as_bytes(),
        );
        Ok(Self {
            alg: CommitmentAlg::Sha256Salted,
            value,
            salt_ref,
        })
    }

    /// Recomputes the commitment from `opening` and compares in constant time.
    #[must_use]
    pub fn opens_to(&self, opening: &MetadataOpening) -> bool {
        let recomputed = commit(
            CommitmentDomain::Metadata(&self.salt_ref),
            &opening.salt,
            opening.value.as_bytes(),
        );
        recomputed.as_bytes().ct_eq(self.value.as_bytes()).into()
    }

    #[must_use]
    pub const fn alg(&self) -> CommitmentAlg {
        self.alg
    }

    #[must_use]
    pub const fn value(&self) -> &Sha256Digest {
        &self.value
    }

    #[must_use]
    pub const fn salt_ref(&self) -> &SaltRef {
        &self.salt_ref
    }
}

/// The openings of the metadata commitments one writer or projection built, keyed by
/// `salt_ref`. Every `salt_ref` and every salt occurs once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataOpenings(BTreeMap<SaltRef, MetadataOpening>);

impl MetadataOpenings {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Commits `value` under `salt_ref` with a salt drawn from `rng`, records the opening
    /// and returns the commitment. A failed draw refuses; no fallback salt is used.
    pub fn commit<T: Serialize>(
        &mut self,
        salt_ref: SaltRef,
        value: &T,
        rng: &dyn Rng,
    ) -> Result<MetadataCommitment, MetadataCommitmentError> {
        let value = MetadataValue::from_json(value)?;
        self.commit_value(salt_ref, value, rng)
    }

    /// As [`Self::commit`], for a value already in canonical form.
    pub fn commit_value(
        &mut self,
        salt_ref: SaltRef,
        value: MetadataValue,
        rng: &dyn Rng,
    ) -> Result<MetadataCommitment, MetadataCommitmentError> {
        let salt = Salt::draw(rng).map_err(MetadataCommitmentError::Entropy)?;
        let opening = MetadataOpening { salt, value };
        let commitment = MetadataCommitment::compute(salt_ref.clone(), &opening)?;
        self.insert(salt_ref, opening)?;
        Ok(commitment)
    }

    /// Records an opening. Refuses a non-metadata `salt_ref`, a `salt_ref` already present
    /// and a salt equal to one already present.
    pub fn insert(
        &mut self,
        salt_ref: SaltRef,
        opening: MetadataOpening,
    ) -> Result<(), MetadataCommitmentError> {
        check_metadata_salt_ref(&salt_ref)?;
        if self.0.values().any(|held| held.salt == opening.salt) {
            return Err(MetadataCommitmentError::DuplicateSalt { salt_ref });
        }
        match self.0.entry(salt_ref) {
            btree_map::Entry::Occupied(entry) => Err(MetadataCommitmentError::DuplicateSaltRef {
                salt_ref: entry.key().clone(),
            }),
            btree_map::Entry::Vacant(entry) => {
                entry.insert(opening);
                Ok(())
            }
        }
    }

    /// The opening of `commitment`, refused when it is missing or does not recompute.
    pub fn open(
        &self,
        commitment: &MetadataCommitment,
    ) -> Result<&MetadataOpening, MetadataCommitmentError> {
        let opening = self.0.get(commitment.salt_ref()).ok_or_else(|| {
            MetadataCommitmentError::OpeningUnavailable {
                salt_ref: commitment.salt_ref().clone(),
            }
        })?;
        if commitment.opens_to(opening) {
            Ok(opening)
        } else {
            Err(MetadataCommitmentError::MetadataCommitmentMismatch {
                salt_ref: commitment.salt_ref().clone(),
            })
        }
    }

    #[must_use]
    pub fn get(&self, salt_ref: &SaltRef) -> Option<&MetadataOpening> {
        self.0.get(salt_ref)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SaltRef, &MetadataOpening)> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why a metadata commitment or opening is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataCommitmentError {
    /// Not a metadata `salt_ref`.
    SaltRef {
        salt_ref: String,
    },
    DuplicateSaltRef {
        salt_ref: SaltRef,
    },
    DuplicateSalt {
        salt_ref: SaltRef,
    },
    Entropy(RngError),
    /// The field value has no canonical JSON form.
    Value(String),
    OpeningUnavailable {
        salt_ref: SaltRef,
    },
    MetadataCommitmentMismatch {
        salt_ref: SaltRef,
    },
    /// A projection check was given an opening the projection never commits.
    UnusedOpening {
        salt_ref: SaltRef,
    },
}

impl fmt::Display for MetadataCommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SaltRef { salt_ref } => {
                write!(formatter, "`{salt_ref}` is not a metadata salt_ref")
            }
            Self::DuplicateSaltRef { salt_ref } => {
                write!(
                    formatter,
                    "metadata salt_ref `{salt_ref}` is already opened"
                )
            }
            Self::DuplicateSalt { salt_ref } => write!(
                formatter,
                "metadata salt_ref `{salt_ref}` reuses the salt of another opening"
            ),
            Self::Entropy(error) => write!(formatter, "metadata salt draw failed: {error}"),
            Self::Value(message) => {
                write!(formatter, "metadata value is not canonical JSON: {message}")
            }
            Self::OpeningUnavailable { salt_ref } => {
                write!(formatter, "no opening for metadata salt_ref `{salt_ref}`")
            }
            Self::MetadataCommitmentMismatch { salt_ref } => write!(
                formatter,
                "opening of metadata salt_ref `{salt_ref}` does not match its commitment"
            ),
            Self::UnusedOpening { salt_ref } => write!(
                formatter,
                "opening of metadata salt_ref `{salt_ref}` has no commitment in the projection"
            ),
        }
    }
}

impl core::error::Error for MetadataCommitmentError {}
