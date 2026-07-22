//! # chio-manifest
//!
//! Tool server manifest format for the Chio protocol. A manifest declares what
//! tools a server provides, what arguments they accept, and what permissions
//! they require. Manifests are signed by the tool server's Ed25519 key and
//! verified by the Runtime Kernel before the server is admitted.
//!
//! The manifest serves two purposes:
//!
//! 1. **Discovery**: the kernel learns what tools are available and their schemas.
//! 2. **Trust**: the kernel verifies the manifest signature against the server's
//!    registered public key, preventing a compromised server from advertising
//!    tools it should not expose.

#![forbid(unsafe_code)]

mod admission;
mod input_schema;
mod validation;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_01.inc"
));

/// Verify a signed manifest against a known public key.
pub fn verify_manifest(
    signed: &SignedManifest,
    public_key: &PublicKey,
) -> Result<(), ManifestError> {
    validate_manifest(&signed.manifest)?;
    ensure_embedded_public_key_matches(&signed.manifest, &signed.signer_key)?;
    if signed.signer_key != *public_key {
        return Err(ManifestError::VerificationFailed);
    }
    let valid = public_key.verify_canonical(&signed.manifest, &signed.signature)?;
    if valid {
        Ok(())
    } else {
        Err(ManifestError::VerificationFailed)
    }
}
