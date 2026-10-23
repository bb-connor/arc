use alloc::format;

use crate::canonical::{CanonicalBytes, CanonicalJsonWitness};
use crate::crypto::{
    Keypair, PublicKey, SigningBackend, SigningMessage, SigningOutcome, SigningWrapper,
};
use crate::error::{Error, Result};

pub(crate) fn ensure_keypair_matches_embedded_key(
    embedded_key: &PublicKey,
    keypair: &Keypair,
    artifact: &str,
    field: &str,
) -> Result<()> {
    ensure_public_key_matches(embedded_key, &keypair.public_key(), artifact, field)
}

pub(crate) fn ensure_backend_matches_embedded_key(
    embedded_key: &PublicKey,
    backend: &dyn SigningBackend,
    artifact: &str,
    field: &str,
) -> Result<()> {
    let actual_key = backend.public_key()?;
    ensure_public_key_matches(embedded_key, &actual_key, artifact, field)
}

/// Retain the artifact's selected identity across a rotating backend call.
/// Validate overridden callbacks too before returning a signed artifact.
pub(crate) fn sign_wrapped_for_embedded_key(
    embedded_key: &PublicKey,
    backend: &dyn SigningBackend,
    schema_id: &str,
    canonical: &CanonicalBytes<CanonicalJsonWitness>,
) -> Result<SigningOutcome> {
    let wrapper = SigningWrapper::new(schema_id, canonical)?;
    let message = wrapper.as_bytes();
    let outcome =
        backend.sign_bytes_for_identity(embedded_key, SigningMessage::wrapper(&wrapper))?;
    let algorithm = embedded_key.algorithm();
    if outcome.public_key != *embedded_key
        || outcome.algorithm != algorithm
        || outcome.signature.algorithm() != algorithm
        || !embedded_key.verify(message, &outcome.signature)
    {
        return Err(Error::InvalidSignature(
            "signing backend returned an artifact from a different identity".into(),
        ));
    }
    Ok(outcome)
}

fn ensure_public_key_matches(
    embedded_key: &PublicKey,
    actual_key: &PublicKey,
    artifact: &str,
    field: &str,
) -> Result<()> {
    if embedded_key == actual_key {
        return Ok(());
    }

    Err(Error::InvalidPublicKey(format!(
        "{artifact} {field} does not match signing key"
    )))
}

#[cfg(test)]
#[path = "signer_binding_tests.rs"]
mod tests;
