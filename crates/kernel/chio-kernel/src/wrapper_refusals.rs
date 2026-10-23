//! Signatures every wrapper boundary refuses, made by the key that boundary
//! trusts: one over the raw canonical body and one over the wrapper under a
//! registered id the boundary does not verify.

use chio_core::canonical::{CanonicalBytes, CanonicalJsonWitness};
use chio_core::crypto::{ExemptFormat, Keypair, Signature};
use serde::Serialize;

/// Registered id that no kernel boundary verifies under.
const FOREIGN_SCHEMA_ID: &str = chio_core_types::CHIO_DECLASSIFICATION_GRANT_SCHEMA;

/// Both refused signatures over the canonical JSON of `body`, labelled for
/// assertion messages.
pub(crate) fn refused_signatures<T: Serialize>(
    key: &Keypair,
    body: &T,
) -> [(&'static str, Signature); 2] {
    refused_signatures_over(key, &CanonicalBytes::from_serializable(body).unwrap())
}

/// [`refused_signatures`] over canonical bytes the boundary already holds.
pub(crate) fn refused_signatures_over(
    key: &Keypair,
    canonical: &CanonicalBytes<CanonicalJsonWitness>,
) -> [(&'static str, Signature); 2] {
    [
        (
            "raw canonical body",
            key.sign_exempt(ExemptFormat::JwsSigningInput, canonical.as_bytes()),
        ),
        (
            "foreign schema id",
            key.sign_wrapped(FOREIGN_SCHEMA_ID, canonical).unwrap(),
        ),
    ]
}

/// A well-formed signature by `key` that covers none of the artifacts under
/// test.
pub(crate) fn unrelated_signature(key: &Keypair) -> Signature {
    key.sign_wrapped(
        FOREIGN_SCHEMA_ID,
        &CanonicalBytes::from_serializable(&"unrelated").unwrap(),
    )
    .unwrap()
}
