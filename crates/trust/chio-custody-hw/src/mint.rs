//! Issuer-side capability signing.
//!
//! The signature covers the signing wrapper over the canonical JSON of the
//! unsigned [`PasskeyCapability`] (the envelope with `signature = ""`) under
//! `chio.passkey-capability.v1`. Verifiers rebuild the same body by clearing
//! `signature` to `""` before re-canonicalising.
//!
//! # Crypto floor
//!
//! The mint path is generic over `SigningBackend`, so the same call site works
//! with [`chio_core_types::crypto::Ed25519Backend`], the FIPS-gated P-256 /
//! P-384 backends and [`chio_core_types::pq::HybridBackend`] (gated on the
//! `pq` feature). The unsigned canonical envelope is identical across modes;
//! only the bytes the `signature` slot ultimately holds differ.
//!
//! # Trust contract
//!
//! - Empty signatures NEVER verify. The signing function refuses to return
//!   `Ok(_)` with an empty signature; the kernel verifier refuses to accept
//!   any capability whose `signature` is empty.

use chio_core_types::canonical::CanonicalBytes;
use chio_core_types::crypto::{verify_wrapped_bytes, PublicKey, Signature, SigningBackend};

use crate::capability::PasskeyCapability;
use crate::error::CustodyError;

/// Signing-wrapper schema id of a passkey capability.
pub const PASSKEY_CAPABILITY_SCHEMA: &str = "chio.passkey-capability.v1";

/// Sign `capability` in place using `backend`, replacing its `signature`
/// field with the hex-encoded signature over the signing wrapper of the
/// envelope (with `signature = ""`).
///
/// Fail-closed: any encoding or signing failure returns
/// [`CustodyError::Encoding`]. The function refuses to return `Ok(_)` if the
/// backend produces an empty signature.
pub fn sign_capability(
    capability: &mut PasskeyCapability,
    backend: &dyn SigningBackend,
) -> Result<(), CustodyError> {
    // Canonical bytes are computed over the unsigned envelope. Clearing the
    // signature slot ensures resigning a previously-signed capability does
    // not embed the old signature in the message.
    capability.signature = String::new();
    let canonical = signing_body(capability)?;

    let signature = backend
        .sign_wrapped(PASSKEY_CAPABILITY_SCHEMA, &canonical)
        .map_err(|err| CustodyError::Encoding(format!("issuer signing failed: {err}")))?
        .signature;

    let hex = signature.to_hex();
    if hex.is_empty() {
        return Err(CustodyError::Encoding(
            "issuer signing backend returned empty signature".into(),
        ));
    }
    capability.signature = hex;
    Ok(())
}

/// Canonical body the wrapper covers for `capability`: the envelope with
/// `signature` cleared.
pub fn signing_body(capability: &PasskeyCapability) -> Result<CanonicalBytes, CustodyError> {
    let mut shadow = capability.clone();
    shadow.signature = String::new();
    CanonicalBytes::from_serializable(&shadow)
        .map_err(|err| CustodyError::Encoding(format!("canonical-json encode: {err}")))
}

/// Verify `capability.signature` against `issuer` under
/// `chio.passkey-capability.v1`. An empty signature never verifies.
pub fn verify_capability_signature(
    capability: &PasskeyCapability,
    issuer: &PublicKey,
) -> Result<(), CustodyError> {
    if capability.signature.is_empty() {
        return Err(CustodyError::AssertionRejected("empty signature".into()));
    }
    let signature = Signature::from_hex(&capability.signature)
        .map_err(|err| CustodyError::AssertionRejected(format!("signature hex decode failed: {err}")))?;
    verify_wrapped_bytes(issuer, PASSKEY_CAPABILITY_SCHEMA, &signing_body(capability)?, &signature)
        .map_err(|err| CustodyError::AssertionRejected(format!("signature rejected: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::ScopeSet;
    use chio_core_types::crypto::{Ed25519Backend, Keypair};
    use chrono::{TimeZone, Utc};

    fn fixed_iat() -> chrono::DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 29, 0, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_iat fixture must construct"),
        }
    }

    fn fixture_cap() -> PasskeyCapability {
        PasskeyCapability::new_stub_unsigned(
            "urn:chio:audience:kernel",
            "AAAA",
            ScopeSet::new(["tool:read", "tool:write"]),
            "nonce-1",
            fixed_iat(),
        )
    }

    #[test]
    fn sign_capability_populates_signature_with_ed25519_backend() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[7u8; 32]));
        let mut cap = fixture_cap();
        assert_eq!(cap.signature, "");
        if let Err(e) = sign_capability(&mut cap, &backend) {
            panic!("sign must succeed: {e}");
        }
        assert!(
            !cap.signature.is_empty(),
            "signed capability must carry a signature"
        );
    }

    #[test]
    fn signing_body_clears_signature_slot_for_byte_stability() {
        let backend = Ed25519Backend::new(Keypair::from_seed(&[7u8; 32]));
        let mut cap = fixture_cap();
        let pre = match signing_body(&cap) {
            Ok(b) => b,
            Err(e) => panic!("pre signing_body must encode: {e}"),
        };
        if let Err(e) = sign_capability(&mut cap, &backend) {
            panic!("sign must succeed: {e}");
        }
        let post = match signing_body(&cap) {
            Ok(b) => b,
            Err(e) => panic!("post signing_body must encode: {e}"),
        };
        assert_eq!(
            pre, post,
            "signing message must be invariant to whether `signature` is populated"
        );
    }

    #[test]
    fn resigning_overwrites_prior_signature() {
        let backend_a = Ed25519Backend::new(Keypair::from_seed(&[1u8; 32]));
        let backend_b = Ed25519Backend::new(Keypair::from_seed(&[2u8; 32]));
        let mut cap = fixture_cap();
        if let Err(e) = sign_capability(&mut cap, &backend_a) {
            panic!("first sign must succeed: {e}");
        }
        let first = cap.signature.clone();
        if let Err(e) = sign_capability(&mut cap, &backend_b) {
            panic!("second sign must succeed: {e}");
        }
        assert_ne!(first, cap.signature, "resign must overwrite, not append");
    }
}
