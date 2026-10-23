//! Signing-wrapper calls shared by every key-log artifact.

use chio_core_types::crypto::{sign_wrapped, verify_wrapped, verify_wrapped_bytes};
use chio_core_types::{CanonicalBytes, PublicKey, Signature, SigningBackend, SigningOutcome};
use serde::Serialize;

use crate::{KeyringError, Result};

/// Signs the wrapper over the canonical `value` under `schema_id` and refuses
/// an outcome whose signature algorithm differs from its public key.
pub(crate) fn sign_wrapped_value<T: Serialize>(
    backend: &dyn SigningBackend,
    schema_id: &str,
    value: &T,
) -> Result<SigningOutcome> {
    let (outcome, _) = sign_wrapped(backend, schema_id, value)?;
    if outcome.signature.algorithm() != outcome.public_key.algorithm() {
        return Err(KeyringError::AlgorithmMismatch);
    }
    Ok(outcome)
}

/// Verifies the wrapper signature against `key`. An algorithm mismatch is
/// `AlgorithmMismatch`; a rejected signature is `InvalidSignature`.
pub(crate) fn verify_wrapped_value<T: Serialize>(
    key: &PublicKey,
    schema_id: &str,
    value: &T,
    signature: &Signature,
) -> Result<()> {
    map_verification(verify_wrapped(key, schema_id, value, signature))
}

fn map_verification(result: chio_core_types::Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(chio_core_types::Error::SignatureAlgorithmMismatch { .. }) => {
            Err(KeyringError::AlgorithmMismatch)
        }
        Err(chio_core_types::Error::SignatureRejected) => Err(KeyringError::InvalidSignature),
        Err(error) => Err(error.into()),
    }
}

/// [`verify_wrapped_value`] over canonical bytes the caller already holds.
pub(crate) fn verify_wrapped_canonical(
    key: &PublicKey,
    schema_id: &str,
    canonical: &CanonicalBytes,
    signature: &Signature,
) -> Result<()> {
    map_verification(verify_wrapped_bytes(key, schema_id, canonical, signature))
}

/// Signs the wrapper over canonical bytes the caller already holds.
pub(crate) fn sign_wrapped_canonical(
    backend: &dyn SigningBackend,
    schema_id: &str,
    canonical: &CanonicalBytes,
) -> Result<SigningOutcome> {
    let outcome = backend.sign_wrapped(schema_id, canonical)?;
    if outcome.signature.algorithm() != outcome.public_key.algorithm() {
        return Err(KeyringError::AlgorithmMismatch);
    }
    Ok(outcome)
}
