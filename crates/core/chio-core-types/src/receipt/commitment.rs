//! Salted commitments carried by receipts and delegation contexts.
//!
//! A commitment is `SHA-256(domain || salt || preimage)`. The salt is fixed-length, so the
//! concatenation is unambiguous. Salts never enter a signed body; they travel in openings
//! keyed by the commitment's `salt_ref`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::canonical::canonical_json_bytes;
use crate::hashing::Sha256State;
use crate::rng::{Rng, RngError};
use crate::root_authority::{SaltRef, Sha256Digest};

pub const SALT_LEN: usize = 32;
pub const PARAMETERS_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.parameters.v1\0";
pub const CONTENT_COMMITMENT_DOMAIN: &[u8] = b"chio.receipt.content.v1\0";
pub const CHAIN_DIGEST_DOMAIN: &[u8] = b"chio.receipt.chain-digest.v1\0";
pub const DELEGATION_SUBJECT_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.subject.v1\0";
pub const DELEGATION_TENANT_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.tenant.v1\0";
pub const DELEGATION_CLAIM_COMMITMENT_DOMAIN: &[u8] = b"chio.delegation-context.claim.v1\0";
pub const PARAMS_SALT_REF: &str = "params";
pub const CONTENT_SALT_REF: &str = "content";

/// 32 secret bytes drawn per field from the producer's `Rng`. Zeroized on drop; `Debug`
/// never prints the bytes; equality is constant-time.
#[derive(Clone)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Draws a fresh salt. A failed draw is an error; no fallback bytes are used.
    pub fn draw(rng: &dyn Rng) -> Result<Self, RngError> {
        let mut bytes = Zeroizing::new([0_u8; SALT_LEN]);
        rng.fill_bytes(bytes.as_mut_slice())?;
        Ok(Self(*bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl PartialEq for Salt {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Salt {}

impl fmt::Debug for Salt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Salt(..)")
    }
}

impl Zeroize for Salt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Salt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Salt {}

/// Closed commitment algorithm set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitmentAlg {
    #[serde(rename = "sha256-salted")]
    Sha256Salted,
}

/// A receipt field commitment: `{alg, value, salt_ref}`. The domain is selected by the
/// commitment's position in the receipt, never by the commitment or its opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptCommitment {
    pub alg: CommitmentAlg,
    pub value: Sha256Digest,
    pub salt_ref: SaltRef,
}

impl ReceiptCommitment {
    #[must_use]
    pub fn compute(
        domain: CommitmentDomain<'_>,
        salt_ref: SaltRef,
        salt: &Salt,
        preimage: &[u8],
    ) -> Self {
        Self {
            alg: CommitmentAlg::Sha256Salted,
            value: commit(domain, salt, preimage),
            salt_ref,
        }
    }

    /// Recomputes the commitment under `domain` and compares in constant time.
    #[must_use]
    pub fn opens_to(&self, domain: CommitmentDomain<'_>, salt: &Salt, preimage: &[u8]) -> bool {
        let recomputed = commit(domain, salt, preimage);
        recomputed.as_bytes().ct_eq(self.value.as_bytes()).into()
    }
}

/// A delegation-context claim name: one or more of `[a-z0-9_]`, so it never contains the
/// NUL that terminates it inside a claim commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimName<'a>(&'a str);

impl<'a> ClaimName<'a> {
    pub fn new(name: &'a str) -> Result<Self, CommitmentError> {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if valid {
            Ok(Self(name))
        } else {
            Err(CommitmentError::ClaimName)
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// The closed set of commitment domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentDomain<'a> {
    Parameters,
    Content,
    DelegationSubject,
    DelegationTenant,
    /// `chio.delegation-context.claim.v1\0 || utf8(name) || 0x00` precedes the salt.
    DelegationClaim(ClaimName<'a>),
}

impl CommitmentDomain<'_> {
    fn absorb_prefix(&self, state: &mut Sha256State) {
        match self {
            Self::Parameters => state.update(PARAMETERS_COMMITMENT_DOMAIN),
            Self::Content => state.update(CONTENT_COMMITMENT_DOMAIN),
            Self::DelegationSubject => state.update(DELEGATION_SUBJECT_COMMITMENT_DOMAIN),
            Self::DelegationTenant => state.update(DELEGATION_TENANT_COMMITMENT_DOMAIN),
            Self::DelegationClaim(name) => {
                state.update(DELEGATION_CLAIM_COMMITMENT_DOMAIN);
                state.update(name.as_str().as_bytes());
                state.update(&[0]);
            }
        }
    }
}

/// `SHA-256(domain || salt || preimage)`.
#[must_use]
pub fn commit(domain: CommitmentDomain<'_>, salt: &Salt, preimage: &[u8]) -> Sha256Digest {
    let mut state = Sha256State::new();
    domain.absorb_prefix(&mut state);
    state.update(salt.as_bytes());
    state.update(preimage);
    Sha256Digest::from_hash(state.finalize())
}

/// The content preimage of a tool output. A value output is its RFC 8785 canonical JSON;
/// an empty output is the zero-length byte string; a stream is the concatenated lowercase
/// hex SHA-256 of each canonical chunk, and a stream with no chunks is an empty output.
#[derive(Debug, Clone, Copy)]
pub enum ContentPreimage<'a> {
    Value(&'a serde_json::Value),
    Empty,
    Stream(&'a [[u8; 32]]),
}

impl ContentPreimage<'_> {
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        match self {
            Self::Value(value) => canonical_json_bytes(value),
            Self::Empty => Ok(Vec::new()),
            Self::Stream(chunks) => {
                let mut text = String::with_capacity(chunks.len().saturating_mul(64));
                for chunk in chunks.iter() {
                    text.push_str(&hex::encode(chunk));
                }
                Ok(text.into_bytes())
            }
        }
    }
}

/// Why a commitment input is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentError {
    ClaimName,
}

impl fmt::Display for CommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimName => formatter.write_str("claim name is not one or more of [a-z0-9_]"),
        }
    }
}

impl core::error::Error for CommitmentError {}
