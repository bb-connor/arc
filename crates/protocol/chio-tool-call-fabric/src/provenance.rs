//! Stand-alone signed provenance helper.
//!
//! The Chio receipt is signed end-to-end, but the provenance stamp itself is
//! not separately attestable from the receipt alone. This small helper lets
//! downstream auditors verify the upstream identity (provider, request id,
//! principal) without pulling the surrounding receipt.
//!
//! The construction is intentionally narrow: a [`SignedProvenance`] envelope
//! carries the canonical-JSON bytes of the [`ProvenanceStamp`], the producing
//! [`PublicKey`], and the [`Signature`] over those bytes. Verification is the
//! inverse and never panics.
//!
//! All cryptography is delegated to `chio_core::crypto`, which already powers
//! capability tokens, receipts, and DPoP proofs. The fabric crate does not
//! introduce new key handling or new algorithms.

use chio_core::canonical::CanonicalBytes;
use chio_core::crypto::{verify_wrapped_bytes, PublicKey, Signature, SigningBackend};
use chio_core::error::Error as CoreError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProvenanceStamp;

/// Signing-wrapper schema id of a signed provenance stamp.
pub const PROVENANCE_STAMP_SCHEMA: &str = "chio.provenance-stamp.v1";

/// Envelope wrapping a [`ProvenanceStamp`] together with a detached signature
/// over its canonical-JSON bytes.
///
/// The envelope is itself canonical-JSON serializable, so it can be embedded
/// in an audit log line, attached to a receipt, or transmitted as a standalone
/// attestation. Equality is byte-equality on every field including the signed
/// bytes, matching the protocol's general "receipts compare by exact bytes"
/// posture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedProvenance {
    /// Original stamp. Mirrors the unsigned shape so consumers that only
    /// trust their own canonicalization can re-derive the signed bytes.
    pub stamp: ProvenanceStamp,
    /// RFC 8785 canonical-JSON bytes of `stamp`. Stored explicitly so the
    /// signer's exact byte sequence is reproducible without re-running
    /// canonicalization on the verifier side.
    pub signed_bytes: Vec<u8>,
    /// Public half of the producing [`SigningBackend`]; its encoding alone
    /// selects the signature algorithm.
    pub public_key: PublicKey,
    /// Detached signature over the signing wrapper of [`Self::signed_bytes`]
    /// under `chio.provenance-stamp.v1`.
    pub signature: Signature,
}

/// Error returned by [`sign_provenance`] and [`verify_signed_provenance`].
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// Underlying canonicalization or signing failure surfaced by
    /// `chio_core::crypto`.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Signature did not verify against the supplied public key and bytes.
    #[error("signature did not verify against the provided public key")]
    SignatureMismatch,
    /// The envelope's `signed_bytes` differ from the canonical-JSON
    /// re-serialization of `stamp`. Surfaces canonicalization drift before a
    /// signature check, since the bytes that were signed must equal the bytes
    /// the verifier independently produces.
    #[error("envelope signed_bytes diverged from canonical re-serialization of stamp")]
    CanonicalDrift,
}

impl From<CoreError> for ProvenanceError {
    fn from(value: CoreError) -> Self {
        ProvenanceError::Crypto(value.to_string())
    }
}

/// Sign a [`ProvenanceStamp`] with the given backend and return a
/// [`SignedProvenance`] envelope.
///
/// The stamp is serialized to RFC 8785 canonical JSON; the resulting bytes
/// are signed through the signing wrapper; both the bytes and the
/// signature are placed in the returned envelope alongside the producing
/// public key.
///
/// This is a thin convenience layer over `chio_core::crypto`; the fabric does
/// not add new cryptographic primitives.
pub fn sign_provenance(
    stamp: &ProvenanceStamp,
    backend: &dyn SigningBackend,
) -> Result<SignedProvenance, ProvenanceError> {
    let canonical = CanonicalBytes::from_serializable(stamp)?;
    let outcome = backend.sign_wrapped(PROVENANCE_STAMP_SCHEMA, &canonical)?;
    Ok(SignedProvenance {
        stamp: stamp.clone(),
        signed_bytes: canonical.into_vec(),
        public_key: outcome.public_key,
        signature: outcome.signature,
    })
}

/// Verify a [`SignedProvenance`] envelope.
///
/// Two checks run, in order:
///
/// 1. The envelope's `signed_bytes` re-canonicalize from `stamp` byte-for-byte
///    (so a verifier never trusts unsigned framing decisions).
/// 2. The signature verifies against `public_key` over the wrapper of
///    `signed_bytes`.
///
/// On success returns the public key that signed the stamp so callers can
/// route trust decisions through their identity layer.
pub fn verify_signed_provenance(
    envelope: &SignedProvenance,
) -> Result<&PublicKey, ProvenanceError> {
    let recanon = CanonicalBytes::from_serializable(&envelope.stamp)?;
    if recanon.as_bytes() != envelope.signed_bytes.as_slice() {
        return Err(ProvenanceError::CanonicalDrift);
    }
    if verify_wrapped_bytes(
        &envelope.public_key,
        PROVENANCE_STAMP_SCHEMA,
        &recanon,
        &envelope.signature,
    )
    .is_err()
    {
        return Err(ProvenanceError::SignatureMismatch);
    }
    Ok(&envelope.public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Principal, ProviderId};
    use chio_core::crypto::Ed25519Backend;
    use std::time::{Duration, SystemTime};

    fn sample_stamp() -> ProvenanceStamp {
        ProvenanceStamp {
            provider: ProviderId::Bedrock,
            request_id: "tooluse_42".to_string(),
            api_version: "bedrock-2023-09-30".to_string(),
            principal: Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: None,
            },
            received_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let envelope = sign_provenance(&stamp, &backend).unwrap();
        assert_eq!(envelope.stamp, stamp);
        assert!(!serde_json::to_string(&envelope)
            .unwrap()
            .contains("\"algorithm\""));
        let pk = verify_signed_provenance(&envelope).unwrap();
        assert_eq!(pk, &backend.public_key().unwrap());
    }

    #[test]
    fn tampered_stamp_fails_canonical_drift() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend).unwrap();
        envelope.stamp.request_id = "tooluse_43".to_string();
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::CanonicalDrift);
    }

    #[test]
    fn tampered_signed_bytes_fail_canonical_drift() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend).unwrap();
        envelope.signed_bytes.push(b' ');
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::CanonicalDrift);
    }

    #[test]
    fn wrong_public_key_fails_signature_mismatch() {
        let backend_a = Ed25519Backend::generate();
        let backend_b = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend_a).unwrap();
        envelope.public_key = backend_b.public_key().unwrap();
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::SignatureMismatch);
    }

    #[test]
    fn signed_provenance_round_trips_through_canonical_json() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let envelope = sign_provenance(&stamp, &backend).unwrap();
        let json = serde_json::to_vec(&envelope).unwrap();
        let back: SignedProvenance = serde_json::from_slice(&json).unwrap();
        assert_eq!(envelope, back);
        verify_signed_provenance(&back).unwrap();
    }
}
