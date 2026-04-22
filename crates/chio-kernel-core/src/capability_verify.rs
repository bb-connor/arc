//! Pure capability verification.
//!
//! Given a `CapabilityToken`, a trusted-issuer key set, and a clock, this
//! module answers: "is the signature valid, is the issuer trusted, and is
//! the capability inside its validity window right now?". It does NOT
//! check:
//!
//! - Revocation (stateful, lives in `chio-kernel::revocation_runtime`).
//! - Delegation-chain lineage against the receipt store (IO-dependent).
//! - Scope match against a request (use [`crate::scope::resolve_capability_grants`]).
//! - DPoP subject binding (lives in `chio-kernel::dpop`).
//!
//! All four are orchestrated by `chio-kernel::ChioKernel::evaluate_tool_call_sync`,
//! which calls into this module for the pure pieces and its own async/std
//! plumbing for the rest.
//!
//! Verified-core boundary note:
//! `formal/proof-manifest.toml` includes this module in the bounded verified
//! core because it performs only issuer-trust, signature, and time-window
//! checks over an in-memory capability token. Revocation stores, delegation
//! lineage joins, and transport-bound subject proof remain excluded surfaces.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chio_core_types::capability::{CapabilityToken, ChioScope};
use chio_core_types::crypto::PublicKey;

use crate::clock::Clock;
use crate::normalized::{NormalizationError, NormalizedVerifiedCapability};

/// The subset of a verified capability that portable callers actually need.
///
/// This deliberately excludes mutable kernel state (budget counters,
/// revocation membership) and avoids returning a reference into the token
/// so adapters that drop the token after verification can still act on
/// the captured scope.
#[derive(Debug, Clone)]
pub struct VerifiedCapability {
    /// The capability ID.
    pub id: String,
    /// The subject hex-encoded public key.
    pub subject_hex: String,
    /// The issuer hex-encoded public key.
    pub issuer_hex: String,
    /// The authorized scope.
    pub scope: ChioScope,
    /// `issued_at` timestamp (Unix seconds).
    pub issued_at: u64,
    /// `expires_at` timestamp (Unix seconds).
    pub expires_at: u64,
    /// The clock value used for time-bound enforcement.
    pub evaluated_at: u64,
}

impl VerifiedCapability {
    /// Project this verification result into the proof-facing normalized AST.
    pub fn normalized(&self) -> Result<NormalizedVerifiedCapability, NormalizationError> {
        NormalizedVerifiedCapability::try_from(self)
    }
}

/// Errors raised by [`verify_capability`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// Issuer public key is not in the trusted set.
    UntrustedIssuer,
    /// Canonical-JSON signature did not verify against the issuer key.
    InvalidSignature,
    /// Token is not yet valid (clock is before `issued_at`).
    NotYetValid,
    /// Token has expired.
    Expired,
    /// An internal invariant was violated (e.g. canonical-JSON failure).
    Internal(String),
}

/// Verify the signature, issuer trust, and time-bounds of a capability token.
///
/// Returns a [`VerifiedCapability`] when all three checks succeed. Delegation
/// chain validation, revocation lookup, and subject-binding checks are the
/// caller's responsibility (see module docs).
pub fn verify_capability(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
) -> Result<VerifiedCapability, CapabilityError> {
    // Issuer trust check. The legacy kernel also trusts its own public key
    // and the set returned by the capability authority; callers must
    // provide the full trust set they care about.
    if !trusted_issuers.contains(&token.issuer) {
        return Err(CapabilityError::UntrustedIssuer);
    }

    // Signature check.
    match token.verify_signature() {
        Ok(true) => {}
        Ok(false) => return Err(CapabilityError::InvalidSignature),
        Err(error) => {
            return Err(CapabilityError::Internal(error.to_string()));
        }
    }

    // Time-bound check.
    let now = clock.now_unix_secs();
    if now < token.issued_at {
        return Err(CapabilityError::NotYetValid);
    }
    if now >= token.expires_at {
        return Err(CapabilityError::Expired);
    }

    Ok(VerifiedCapability {
        id: token.id.clone(),
        subject_hex: token.subject.to_hex(),
        issuer_hex: token.issuer.to_hex(),
        scope: token.scope.clone(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        evaluated_at: now,
    })
}

/// Convenience wrapper around [`verify_capability`] that returns the
/// trusted-issuer list as a `Vec` so adapters can build it lazily.
pub fn verify_capability_with_trusted<I>(
    token: &CapabilityToken,
    trusted_issuers: I,
    clock: &dyn Clock,
) -> Result<VerifiedCapability, CapabilityError>
where
    I: IntoIterator<Item = PublicKey>,
{
    let trusted: Vec<PublicKey> = trusted_issuers.into_iter().collect();
    verify_capability(token, &trusted, clock)
}
