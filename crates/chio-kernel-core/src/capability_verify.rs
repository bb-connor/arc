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

use chio_core_types::capability::{
    CapabilityCryptoFloor, CapabilityFloorVerifyError, CapabilityToken, ChioScope,
};
use chio_core_types::crypto::PublicKey;

use crate::budget_split::{BudgetRegistry, BudgetSplitError, NoopBudgetRegistry};
use crate::clock::Clock;
use crate::formal_core::{classify_time_window, TimeWindowStatus};
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
    /// Signature material violates the configured crypto floor.
    CryptoFloorRejected(String),
    /// Token is not yet valid (clock is before `issued_at`).
    NotYetValid,
    /// Token has expired.
    Expired,
    /// Sibling-sum budget enforcement rejected this delegation.
    BudgetSplitRejected(BudgetSplitError),
    /// An internal invariant was violated (e.g. canonical-JSON failure).
    Internal(String),
}

impl From<BudgetSplitError> for CapabilityError {
    fn from(err: BudgetSplitError) -> Self {
        CapabilityError::BudgetSplitRejected(err)
    }
}

/// Verify the signature, issuer trust, and time-bounds of a capability token.
///
/// Returns a [`VerifiedCapability`] when all three checks succeed. Delegation
/// chain validation, revocation lookup, and subject-binding checks are the
/// caller's responsibility (see module docs).
///
/// This wrapper uses a [`NoopBudgetRegistry`] internally; callers that need
/// sibling-sum budget enforcement must use [`verify_capability_with_floor`]
/// directly with their own [`BudgetRegistry`] instance.
pub fn verify_capability(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
) -> Result<VerifiedCapability, CapabilityError> {
    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(
        token,
        trusted_issuers,
        clock,
        CapabilityCryptoFloor::AllowClassical,
        &mut budgets,
    )
}

/// Verify a capability token while enforcing the configured crypto floor and
/// sibling-sum budget split.
///
/// This is the floor-aware entry point for kernels that load
/// `policy.crypto_floor`. The default [`verify_capability`] wrapper preserves
/// legacy callers by using [`CapabilityCryptoFloor::AllowClassical`] and a
/// [`NoopBudgetRegistry`].
///
/// Sibling-sum enforcement: when the token carries a non-empty
/// `delegation_chain`, the verifier asks `budgets` to admit the new child
/// under the immediate parent (the last entry in the chain). The proposed
/// share is `token.budget_share_bps.unwrap_or(MAX_BUDGET_SHARE_BPS)`: a
/// missing field is interpreted as a request for the full parent share, so
/// the registry can still detect oversubscription. Per-token validation has
/// already enforced the `<= 10_000` cap by the time the token reaches this
/// function.
pub fn verify_capability_with_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    // Issuer trust check. The legacy kernel also trusts its own public key
    // and the set returned by the capability authority; callers must
    // provide the full trust set they care about.
    if !trusted_issuers.contains(&token.issuer) {
        return Err(CapabilityError::UntrustedIssuer);
    }

    // Signature check.
    match token.verify_signature_with_floor(crypto_floor) {
        Ok(true) => {}
        Ok(false) => return Err(CapabilityError::InvalidSignature),
        Err(error @ CapabilityFloorVerifyError::RejectedByCryptoFloor { .. }) => {
            return Err(CapabilityError::CryptoFloorRejected(error.to_string()));
        }
        Err(error @ CapabilityFloorVerifyError::AlgorithmMismatch { .. }) => {
            return Err(CapabilityError::CryptoFloorRejected(error.to_string()));
        }
        Err(CapabilityFloorVerifyError::Crypto(error)) => {
            return Err(CapabilityError::Internal(error.to_string()));
        }
    }

    // Time-bound check.
    let now = clock.now_unix_secs();
    match classify_time_window(now, token.issued_at, token.expires_at) {
        TimeWindowStatus::Valid => {}
        TimeWindowStatus::NotYetValid => return Err(CapabilityError::NotYetValid),
        TimeWindowStatus::Expired => return Err(CapabilityError::Expired),
    }

    // Sibling-sum budget split. Only fires for tokens that carry a
    // delegation chain; root-issued tokens have nothing to split.
    if let Some(parent_link) = token.delegation_chain.last() {
        let proposed_share = token
            .budget_share_bps
            .unwrap_or(crate::budget_split::MAX_BUDGET_SHARE_BPS);
        budgets.try_admit_child(
            parent_link.capability_id.as_str(),
            token.id.clone(),
            proposed_share,
        )?;
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

/// Convenience wrapper around [`verify_capability_with_floor`] for callers that
/// build the trusted issuer set lazily. Uses a [`NoopBudgetRegistry`]; new
/// callers that care about sibling-sum enforcement should call
/// [`verify_capability_with_floor`] with their own registry.
pub fn verify_capability_with_trusted_and_floor<I>(
    token: &CapabilityToken,
    trusted_issuers: I,
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
) -> Result<VerifiedCapability, CapabilityError>
where
    I: IntoIterator<Item = PublicKey>,
{
    let trusted: Vec<PublicKey> = trusted_issuers.into_iter().collect();
    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(token, &trusted, clock, crypto_floor, &mut budgets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::capability::{CapabilityTokenBody, ChioScope};
    use chio_core_types::crypto::Keypair;

    #[test]
    fn pq_required_rejects_classical_capability() {
        let issuer = Keypair::generate();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-classical".to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign classical capability");
        let clock = crate::FixedClock::new(150);

        let mut budgets = NoopBudgetRegistry;
        let err = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::PqRequired,
            &mut budgets,
        )
        .expect_err("classical capability must fail under pq_required");

        assert!(matches!(err, CapabilityError::CryptoFloorRejected(_)));
    }

    #[test]
    fn allow_classical_accepts_classical_capability() {
        let issuer = Keypair::generate();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-classical".to_string(),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("sign classical capability");
        let clock = crate::FixedClock::new(150);

        let mut budgets = NoopBudgetRegistry;
        let verified = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &mut budgets,
        )
        .expect("classical capability is accepted under allow_classical");

        assert_eq!(verified.id, "cap-classical");
    }
}
