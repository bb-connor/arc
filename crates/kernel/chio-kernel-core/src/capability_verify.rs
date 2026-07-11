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
    attenuation::{
        validate_capability_delegation_chain, validate_delegation_chain_with_trust_root, ScopeHash,
    },
    crypto_floor::{CapabilityCryptoFloor, CapabilityFloorVerifyError},
    features::CapabilityNegotiation,
    scope::ChioScope,
    token::CapabilityToken,
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
    /// Attenuated capability token violated the chain-binding rule.
    /// `attenuation_proof.parent_scope_hash` did not match either the
    /// issuer's trust-root scope hash (direct issue) or the last
    /// delegation link's `scope_hash` (delegated chain).
    AttenuationViolation(String),
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
/// `policy.crypto_floor`. The default [`verify_capability`] wrapper uses
/// [`CapabilityCryptoFloor::AllowClassical`] and a [`NoopBudgetRegistry`].
///
/// Sibling-sum enforcement: when the token carries a non-empty
/// `delegation_chain`, the verifier asks `budgets` to admit the new child
/// under the immediate parent (the last entry in the chain). The proposed
/// share is `token.budget_share_bps.unwrap_or(MAX_BUDGET_SHARE_BPS)`: a
/// missing field is interpreted as a request for the full parent share.
/// The parent itself must already be registered in `budgets` from
/// verifier-owned lineage or a parent snapshot. Unknown parents fail closed.
/// Per-token validation has already enforced the `<= 10_000` cap by the time
/// the token reaches this function.
pub fn verify_capability_with_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified = verify_capability_base(token, trusted_issuers, clock, crypto_floor)?;
    admit_delegated_budget(token, budgets)?;
    Ok(verified)
}

fn verify_capability_base(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
) -> Result<VerifiedCapability, CapabilityError> {
    // Issuer trust check. The full kernel also trusts its own public key
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

    // Aggregate limits are signed and structurally valid, but no production
    // quota authority enforces them yet. Deny after signature authentication
    // and before any admission-side mutation so callers cannot mistake the
    // wire field for an active security guarantee.
    if token.aggregate_invocation_budget.is_some() {
        return Err(CapabilityError::AttenuationViolation(
            "aggregate invocation budget enforcement is disabled".to_string(),
        ));
    }

    // Time-bound check.
    let now = clock.now_unix_secs();
    match classify_time_window(now, token.issued_at, token.expires_at) {
        TimeWindowStatus::Valid => {}
        TimeWindowStatus::NotYetValid => return Err(CapabilityError::NotYetValid),
        TimeWindowStatus::Expired => return Err(CapabilityError::Expired),
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

pub(crate) fn admit_delegated_budget(
    token: &CapabilityToken,
    budgets: &mut dyn BudgetRegistry,
) -> Result<(), CapabilityError> {
    // Sibling-sum budget split. Only fires for tokens that carry a
    // delegation chain; root-issued tokens have nothing to split.
    //
    // The parent must already be registered from verifier-owned lineage
    // or a parent snapshot. Unknown parents fail closed; the verifier must
    // not fabricate a missing parent share at MAX_BUDGET_SHARE_BPS.
    //
    // This runs on the shared VERIFY surface (portable/preflight verdicts and
    // adapter one-shot evaluations produced by the pure `evaluate_*` entry
    // points). None of those callers hold a `PostAdmissionDropGuard` or reach
    // `release_admitted_capability_budget`, so this MUST NOT take a holder
    // lease: a lease acquired here would never be released and would pin the
    // child edge upward forever. `verify_child_admission` runs the same
    // fail-closed oversubscription checks and still commits a fresh child's
    // share for sibling-sum accounting, but records no releasable holder. The
    // authoritative lease is taken separately by the hosted dispatch path
    // (`ChioKernel::admit_capability_budget`), which owns the matching release.
    if let Some(parent_link) = token.delegation_chain.last() {
        let proposed_share = token
            .budget_share_bps
            .unwrap_or(crate::budget_split::MAX_BUDGET_SHARE_BPS);
        budgets.verify_child_admission(
            parent_link.capability_id.as_str(),
            token.id.clone(),
            proposed_share,
        )?;
    }

    Ok(())
}

/// Verify a capability token while enforcing the configured crypto floor.
/// The peer profile is still accepted so federation callers can keep one
/// call surface, but Chio-owned capability schemas are single-version until
/// first release.
pub fn verify_capability_with_negotiated_floor(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    _peer: &CapabilityNegotiation,
) -> Result<VerifiedCapability, CapabilityError> {
    let mut budgets = NoopBudgetRegistry;
    verify_capability_with_floor(token, trusted_issuers, clock, crypto_floor, &mut budgets)
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

/// Resolver returning the trust-root scope hash bound to a given issuer
/// public key. Kernels supply this so the verifier can bind
/// `attenuation_proof.parent_scope_hash` to the issuing CA's authority
/// hash on direct-issue attenuated tokens.
pub trait TrustRootResolver {
    /// Resolve the trust-root scope hash for `issuer`, returning `None`
    /// when the issuer has no registered authority hash. The verifier
    /// treats `None` as a fail-closed deny for attenuated tokens that require
    /// chain binding.
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash>;
}

impl<F> TrustRootResolver for F
where
    F: Fn(&PublicKey) -> Option<ScopeHash>,
{
    fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash> {
        (self)(issuer)
    }
}

/// Chain-binding entry point. Verify a capability token while also
/// enforcing the chain-binding rule required for delegation soundness.
///
/// In addition to the checks in [`verify_capability_with_floor`], this
/// entry point checks tokens that carry an `attenuation_proof`
/// whose `parent_scope_hash` matches either:
///
/// - `trust_root_scope_hash` (when the delegation chain is empty: a
///   direct issue from the trust-root authority binds the witness to the
///   verifier-known authority hash); or
/// - `delegation_chain.last().scope_hash` (when delegation has occurred:
///   the witness binds to the predecessor's signed scope_hash).
///
/// Non-attenuated tokens are accepted unchanged.
pub fn verify_capability_with_floor_and_trust_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    trust_root_scope_hash: &ScopeHash,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified = verify_capability_base(token, trusted_issuers, clock, crypto_floor)?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_trust_root(token, trust_root_scope_hash)?;

    Ok(verified)
}

/// Resolver-driven variant of [`verify_capability_with_floor_and_trust_root`].
///
/// Kernels that maintain a per-issuer trust-root registry pass a
/// [`TrustRootResolver`] so the verifier can pick the correct authority
/// hash without leaking the registry shape into the verifier surface.
pub fn verify_capability_with_floor_and_resolver(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    trust_root: &dyn TrustRootResolver,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified = verify_capability_base(token, trusted_issuers, clock, crypto_floor)?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_resolver(token, trust_root)?;

    Ok(verified)
}

/// Full verifier entry point for current capability semantics.
pub fn verify_capability_full(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
    clock: &dyn Clock,
    crypto_floor: CapabilityCryptoFloor,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
    budgets: &mut dyn BudgetRegistry,
) -> Result<VerifiedCapability, CapabilityError> {
    let verified = verify_capability_base(token, trusted_issuers, clock, crypto_floor)?;
    verify_delegation_chain_shape(token)?;
    verify_chain_binding_with_negotiation(token, peer, trust_root)?;
    admit_delegated_budget(token, budgets)?;
    Ok(verified)
}

fn verify_delegation_chain_shape(token: &CapabilityToken) -> Result<(), CapabilityError> {
    validate_capability_delegation_chain(token, None).map_err(|err| match err {
        chio_core_types::Error::DelegationChainBroken { reason } => {
            CapabilityError::AttenuationViolation(reason)
        }
        other => CapabilityError::AttenuationViolation(other.to_string()),
    })
}

fn verify_chain_binding_with_trust_root(
    token: &CapabilityToken,
    trust_root_scope_hash: &ScopeHash,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        token
            .validate_chain_binding(trust_root_scope_hash)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }
    Ok(())
}

fn verify_chain_binding_with_resolver(
    token: &CapabilityToken,
    trust_root: &dyn TrustRootResolver,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        let issuer_root = trust_root
            .trust_root_scope_hash(&token.issuer)
            .ok_or_else(|| {
                CapabilityError::AttenuationViolation(
                    "chain-binding: no trust-root scope hash registered for issuer".to_string(),
                )
            })?;
        validate_delegation_chain_with_trust_root(&token.delegation_chain, None, &issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
        token
            .validate_chain_binding(&issuer_root)
            .map_err(|err| CapabilityError::AttenuationViolation(err.to_string()))?;
    }
    Ok(())
}

fn verify_chain_binding_with_negotiation(
    token: &CapabilityToken,
    peer: &CapabilityNegotiation,
    trust_root: &dyn TrustRootResolver,
) -> Result<(), CapabilityError> {
    if token.requires_chain_binding() {
        let chain_binding_enabled = peer
            .features
            .get(chio_core_types::capability::features::DELEGATION_CHAIN_BINDING)
            .copied()
            .unwrap_or(true);
        if !chain_binding_enabled {
            return Err(CapabilityError::AttenuationViolation(
                "chain-binding: peer disabled delegation_chain_binding; attenuated tokens are rejected".to_string(),
            ));
        }
        verify_chain_binding_with_resolver(token, trust_root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryBudgetRegistry;
    use alloc::format;
    use alloc::vec;
    use chio_core_types::capability::{
        aggregate_budget::{AggregateInvocationBudget, AggregateInvocationScope},
        attenuation::{
            compute_attenuation_witness, scope_hash, AttenuationProof, DelegationLink,
            DelegationLinkBody,
        },
        features,
        scope::ChioScope,
        token::{CapabilityTokenAttenuationBody, CapabilityTokenBody},
    };
    use chio_core_types::crypto::Keypair;
    use core::cell::Cell;

    struct CountingTrustRootResolver {
        issuer: PublicKey,
        root: ScopeHash,
        calls: Cell<u32>,
    }

    impl CountingTrustRootResolver {
        fn new(issuer: PublicKey, root: ScopeHash) -> Self {
            Self {
                issuer,
                root,
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.get()
        }
    }

    impl TrustRootResolver for CountingTrustRootResolver {
        fn trust_root_scope_hash(&self, issuer: &PublicKey) -> Option<ScopeHash> {
            self.calls.set(self.calls.get() + 1);
            if issuer == &self.issuer {
                Some(self.root.clone())
            } else {
                None
            }
        }
    }

    fn aggregate_budget_token(issuer: &Keypair, max_invocations: u32) -> CapabilityToken {
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("cap-aggregate-{max_invocations}"),
                issuer: issuer.public_key(),
                subject: Keypair::generate().public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: Some(AggregateInvocationBudget {
                    scope: AggregateInvocationScope::Capability,
                    max_invocations,
                    root_binding: None,
                }),
            },
            issuer,
        )
        .expect("sign structurally valid aggregate capability")
    }

    fn assert_aggregate_enforcement_disabled(error: CapabilityError) {
        assert_eq!(
            error,
            CapabilityError::AttenuationViolation(
                "aggregate invocation budget enforcement is disabled".to_string()
            )
        );
    }

    #[test]
    fn aggregate_invocation_enforcement_disabled_rejects_portable_and_full_verification() {
        let issuer = Keypair::generate();
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let trust_roots = |_issuer: &PublicKey| None;

        for max_invocations in [0, 7] {
            let token = aggregate_budget_token(&issuer, max_invocations);
            assert!(token
                .verify_signature()
                .expect("core-types signature verification remains valid"));

            let portable_error = verify_capability(&token, &[issuer.public_key()], &clock)
                .expect_err("portable verification must deny unenforced aggregate budgets");
            assert_aggregate_enforcement_disabled(portable_error);

            let mut budgets = NoopBudgetRegistry;
            let full_error = verify_capability_full(
                &token,
                &[issuer.public_key()],
                &clock,
                CapabilityCryptoFloor::AllowClassical,
                &peer,
                &trust_roots,
                &mut budgets,
            )
            .expect_err("full verification must deny unenforced aggregate budgets");
            assert_aggregate_enforcement_disabled(full_error);
        }

        let mut tampered = aggregate_budget_token(&issuer, 0);
        tampered.id.push_str("-tampered");
        let portable_error = verify_capability(&tampered, &[issuer.public_key()], &clock)
            .expect_err("signature authentication must precede aggregate rollout denial");
        assert_eq!(portable_error, CapabilityError::InvalidSignature);

        let mut budgets = NoopBudgetRegistry;
        let full_error = verify_capability_full(
            &tampered,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("full verification must authenticate before aggregate rollout denial");
        assert_eq!(full_error, CapabilityError::InvalidSignature);
    }

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
                aggregate_invocation_budget: None,
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
                aggregate_invocation_budget: None,
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

    fn make_attenuated_token(id: &str, issuer: &Keypair, subject: &Keypair) -> CapabilityToken {
        let scope = ChioScope::default();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&scope).expect("parent scope hash"),
            child_scope_hash: scope_hash(&scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(&scope, &scope)
                .expect("attenuation witness"),
        };
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: id.to_string(),
                    issuer: issuer.public_key(),
                    subject: subject.public_key(),
                    scope,
                    issued_at: 100,
                    expires_at: 200,
                    delegation_chain: Vec::new(),
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            issuer,
        )
        .expect("sign attenuated token")
    }

    fn counting_resolver_for(issuer: &Keypair) -> CountingTrustRootResolver {
        CountingTrustRootResolver::new(
            issuer.public_key(),
            scope_hash(&ChioScope::default()).expect("trust root hash"),
        )
    }

    #[test]
    fn full_verifier_rejects_attenuated_token_when_chain_binding_feature_is_disabled() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token =
            make_attenuated_token("cap-attenuated-disabled-chain-binding", &issuer, &subject);
        let clock = crate::FixedClock::new(150);
        let mut peer = CapabilityNegotiation::t1_default();
        peer.features
            .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("attenuated token must fail when chain binding is disabled");

        assert!(matches!(err, CapabilityError::AttenuationViolation(_)));
    }

    #[test]
    fn full_verifier_rejects_untrusted_attenuated_token_before_resolver_lookup() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_attenuated_token("cap-untrusted-before-resolver", &issuer, &subject);
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let resolver = counting_resolver_for(&issuer);
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &resolver,
            &mut budgets,
        )
        .expect_err("untrusted attenuated token must fail before chain binding");

        assert_eq!(err, CapabilityError::UntrustedIssuer);
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn full_verifier_rejects_tampered_attenuated_token_before_resolver_lookup() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut token = make_attenuated_token("cap-tampered-before-resolver", &issuer, &subject);
        token.id.push_str("-tampered");
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let resolver = counting_resolver_for(&issuer);
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &resolver,
            &mut budgets,
        )
        .expect_err("tampered attenuated token must fail before chain binding");

        assert_eq!(err, CapabilityError::InvalidSignature);
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn full_verifier_rejects_expired_attenuated_token_before_resolver_lookup() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_attenuated_token("cap-expired-before-resolver", &issuer, &subject);
        let clock = crate::FixedClock::new(201);
        let peer = CapabilityNegotiation::t1_default();
        let resolver = counting_resolver_for(&issuer);
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &resolver,
            &mut budgets,
        )
        .expect_err("expired attenuated token must fail before chain binding");

        assert_eq!(err, CapabilityError::Expired);
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn delegation_family_leaf_issuer_continuity_rejects_trusted_unrelated_signer_across_chain_aware_entrypoints(
    ) {
        let final_delegator = Keypair::generate();
        let leaf_subject = Keypair::generate();
        let unrelated_signer = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: final_delegator.public_key(),
                delegatee: leaf_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: Some(scope_hash(&ChioScope::default()).expect("scope hash")),
            },
            &final_delegator,
        )
        .expect("sign parent link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "trusted-unrelated-leaf-signer".to_string(),
                issuer: unrelated_signer.public_key(),
                subject: leaf_subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![parent_link],
                aggregate_invocation_budget: None,
            },
            &unrelated_signer,
        )
        .expect("sign unrelated leaf");
        let clock = crate::FixedClock::new(150);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let resolver =
            CountingTrustRootResolver::new(unrelated_signer.public_key(), trust_root_hash.clone());
        let expected = CapabilityError::AttenuationViolation(
            "delegation chain final delegator does not match capability issuer".to_string(),
        );

        assert_eq!(
            verify_capability_with_floor_and_trust_root(
                &token,
                &[unrelated_signer.public_key()],
                &clock,
                CapabilityCryptoFloor::AllowClassical,
                &trust_root_hash,
            )
            .expect_err("trusted unrelated leaf signer must fail"),
            expected
        );
        assert_eq!(
            verify_capability_with_floor_and_resolver(
                &token,
                &[unrelated_signer.public_key()],
                &clock,
                CapabilityCryptoFloor::AllowClassical,
                &resolver,
            )
            .expect_err("resolver entrypoint must reject unrelated signer"),
            expected
        );

        let peer = CapabilityNegotiation::t1_default();
        let mut budgets = NoopBudgetRegistry;
        assert_eq!(
            verify_capability_full(
                &token,
                &[unrelated_signer.public_key()],
                &clock,
                CapabilityCryptoFloor::AllowClassical,
                &peer,
                &resolver,
                &mut budgets,
            )
            .expect_err("full verifier must reject unrelated signer"),
            expected
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn delegation_family_leaf_issuer_continuity_accepts_final_not_root_delegator() {
        let root_delegator = Keypair::generate();
        let final_delegator = Keypair::generate();
        let leaf_subject = Keypair::generate();
        let root_hash = scope_hash(&ChioScope::default()).expect("root hash");
        let first_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "root-capability".to_string(),
                delegator: root_delegator.public_key(),
                delegatee: final_delegator.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: Some(root_hash.clone()),
            },
            &root_delegator,
        )
        .expect("sign first link");
        let final_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "intermediate-capability".to_string(),
                delegator: final_delegator.public_key(),
                delegatee: leaf_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 101,
                scope_hash: Some(root_hash.clone()),
            },
            &final_delegator,
        )
        .expect("sign final link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "final-delegator-leaf".to_string(),
                issuer: final_delegator.public_key(),
                subject: leaf_subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 101,
                expires_at: 200,
                delegation_chain: vec![first_link, final_link],
                aggregate_invocation_budget: None,
            },
            &final_delegator,
        )
        .expect("sign final leaf");
        let clock = crate::FixedClock::new(150);

        let verified = verify_capability_with_floor_and_trust_root(
            &token,
            &[final_delegator.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &root_hash,
        )
        .expect("leaf issuer must match the final, not first, delegator");
        assert_eq!(verified.id, token.id);
    }

    #[test]
    fn delegation_family_leaf_issuer_continuity_precedes_budget_admission() {
        let final_delegator = Keypair::generate();
        let leaf_subject = Keypair::generate();
        let unrelated_signer = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "unregistered-parent".to_string(),
                delegator: final_delegator.public_key(),
                delegatee: leaf_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &final_delegator,
        )
        .expect("sign parent link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "continuity-before-budget".to_string(),
                issuer: unrelated_signer.public_key(),
                subject: leaf_subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: vec![parent_link],
                aggregate_invocation_budget: None,
            },
            &unrelated_signer,
        )
        .expect("sign unrelated leaf");
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let resolver = counting_resolver_for(&unrelated_signer);
        let mut budgets = InMemoryBudgetRegistry::new();

        let error = verify_capability_full(
            &token,
            &[unrelated_signer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &resolver,
            &mut budgets,
        )
        .expect_err("continuity must fail before unknown-parent budget admission");

        assert_eq!(
            error,
            CapabilityError::AttenuationViolation(
                "delegation chain final delegator does not match capability issuer".to_string()
            )
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn full_verifier_accepts_plain_pass_through_delegation_when_chain_binding_feature_is_disabled()
    {
        // A pass-through delegation that introduces no new attenuation does
        // not require chain binding, so the negotiated
        // `DELEGATION_CHAIN_BINDING=false` profile must NOT reject it. The
        // leaf token is signed by its issuer and each `DelegationLink`
        // carries its own signature; there is nothing about the leaf scope
        // for the chain-binding rule to bind against.
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "delegated-current-v1-token".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .expect("sign delegated token");
        let clock = crate::FixedClock::new(150);
        let mut peer = CapabilityNegotiation::t1_default();
        peer.features
            .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        // The parent must already be registered in the budget registry for
        // sibling-sum admission; pass-through delegations admit at the full
        // parent share.
        let mut budgets = InMemoryBudgetRegistry::new();
        BudgetRegistry::register_parent(
            &mut budgets,
            "parent-capability".to_string(),
            crate::budget_split::MAX_BUDGET_SHARE_BPS,
        )
        .expect("register parent");

        let verified = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect("pass-through delegation must verify when no new attenuation is introduced");

        assert_eq!(verified.id, "delegated-current-v1-token");
    }

    #[test]
    fn full_verifier_rejects_delegation_chain_with_wrong_final_delegatee() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: issuer.public_key(),
                delegatee: issuer.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "delegated-wrong-final-delegatee".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .expect("sign delegated token");
        let clock = crate::FixedClock::new(150);
        let mut peer = CapabilityNegotiation::t1_default();
        peer.features
            .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = InMemoryBudgetRegistry::new();

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("mismatched final delegatee must fail");

        match err {
            CapabilityError::AttenuationViolation(message) => {
                assert!(message.contains("final delegatee does not match capability subject"));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    #[test]
    fn full_verifier_rejects_tampered_delegation_link_payload() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        parent_link.capability_id = "tampered-parent".to_string();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "delegated-tampered-link".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .expect("sign delegated token");
        let clock = crate::FixedClock::new(150);
        let mut peer = CapabilityNegotiation::t1_default();
        peer.features
            .insert(features::DELEGATION_CHAIN_BINDING.to_string(), false);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = InMemoryBudgetRegistry::new();

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("tampered delegation link must fail");

        match err {
            CapabilityError::AttenuationViolation(message) => {
                assert!(message.contains("signature invalid"));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    #[test]
    fn resolver_entrypoints_reject_tampered_plain_delegation_link() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let mut parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        parent_link.capability_id = "tampered-parent-capability".to_string();
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "plain-delegated-token-with-tampered-link".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::from([parent_link]),
                aggregate_invocation_budget: None,
            },
            &issuer,
        )
        .expect("sign outer token");
        let clock = crate::FixedClock::new(150);
        let trust_root_hash = scope_hash(&ChioScope::default()).expect("trust root hash");
        let resolver = counting_resolver_for(&issuer);

        let resolver_err = verify_capability_with_floor_and_resolver(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &resolver,
        )
        .expect_err("resolver verifier must validate plain delegation-chain links");
        let trust_root_err = verify_capability_with_floor_and_trust_root(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &trust_root_hash,
        )
        .expect_err("trust-root verifier must validate plain delegation-chain links");

        for err in [resolver_err, trust_root_err] {
            match err {
                CapabilityError::AttenuationViolation(message) => {
                    assert!(message.contains("signature invalid"));
                }
                other => panic!("expected attenuation violation, got {other:?}"),
            }
        }
    }

    #[test]
    fn full_verifier_rejects_delegated_attenuation_unbound_from_trust_root() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let authorized_scope = ChioScope::default();
        let inflated_scope = ChioScope {
            grants: vec![chio_core_types::capability::scope::ToolGrant {
                server_id: "*".to_string(),
                tool_name: "*".to_string(),
                operations: vec![chio_core_types::capability::scope::Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let inflated_hash = scope_hash(&inflated_scope).expect("inflated scope hash");
        let trust_root_hash = scope_hash(&authorized_scope).expect("trust root hash");
        assert_ne!(inflated_hash, trust_root_hash);

        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "parent-capability".to_string(),
                delegator: issuer.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: Some(inflated_hash.clone()),
            },
            &issuer,
        )
        .expect("sign delegation link");
        let proof = AttenuationProof {
            parent_scope_hash: inflated_hash,
            child_scope_hash: scope_hash(&authorized_scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(
                &inflated_scope,
                &authorized_scope,
            )
            .expect("attenuation witness"),
        };
        let token = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "delegated-unbound-root".to_string(),
                    issuer: issuer.public_key(),
                    subject: subject.public_key(),
                    scope: authorized_scope,
                    issued_at: 100,
                    expires_at: 200,
                    delegation_chain: vec![parent_link],
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            &issuer,
        )
        .expect("sign attenuated token");
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let issuer_public = issuer.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("first delegation link must bind to issuer trust root");

        match err {
            CapabilityError::AttenuationViolation(message) => {
                assert!(message.contains("scope_hash does not match trust root"));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    #[test]
    fn full_verifier_rejects_multi_hop_attenuation_without_child_scope_witnesses() {
        let issuer = Keypair::generate();
        let intermediate = Keypair::generate();
        let subject = Keypair::generate();
        let authorized_scope = ChioScope::default();
        let trust_root_hash = scope_hash(&authorized_scope).expect("trust root hash");
        let intermediate_scope = ChioScope {
            grants: vec![chio_core_types::capability::scope::ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "tool-a".to_string(),
                operations: vec![chio_core_types::capability::scope::Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let intermediate_hash = scope_hash(&intermediate_scope).expect("intermediate scope hash");

        let first_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "root-parent".to_string(),
                delegator: issuer.public_key(),
                delegatee: intermediate.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: Some(trust_root_hash.clone()),
            },
            &issuer,
        )
        .expect("sign first delegation link");
        let second_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "intermediate-parent".to_string(),
                delegator: intermediate.public_key(),
                delegatee: subject.public_key(),
                attenuations: Vec::new(),
                timestamp: 101,
                scope_hash: Some(intermediate_hash.clone()),
            },
            &intermediate,
        )
        .expect("sign second delegation link");
        let proof = AttenuationProof {
            parent_scope_hash: intermediate_hash,
            child_scope_hash: scope_hash(&authorized_scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(
                &intermediate_scope,
                &authorized_scope,
            )
            .expect("attenuation witness"),
        };
        let token = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "delegated-multi-hop-without-witnesses".to_string(),
                    issuer: intermediate.public_key(),
                    subject: subject.public_key(),
                    scope: authorized_scope,
                    issued_at: 100,
                    expires_at: 200,
                    delegation_chain: vec![first_link, second_link],
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            &intermediate,
        )
        .expect("sign attenuated token");
        let clock = crate::FixedClock::new(150);
        let peer = CapabilityNegotiation::t1_default();
        let issuer_public = intermediate.public_key();
        let resolver_issuer = issuer_public.clone();
        let trust_roots = move |candidate: &PublicKey| {
            if candidate == &resolver_issuer {
                Some(trust_root_hash.clone())
            } else {
                None
            }
        };
        let mut budgets = NoopBudgetRegistry;

        let err = verify_capability_full(
            &token,
            &[issuer_public],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &peer,
            &trust_roots,
            &mut budgets,
        )
        .expect_err("multi-hop attenuated chains need per-hop child-scope witnesses");

        match err {
            CapabilityError::AttenuationViolation(message) => {
                assert!(message.contains("multi-hop attenuated delegation chains"));
            }
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    #[test]
    fn delegated_budget_unknown_parent_fails_closed() {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let parent_link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: "missing-parent".to_string(),
                delegator: issuer.public_key(),
                delegatee: issuer.public_key(),
                attenuations: Vec::new(),
                timestamp: 100,
                scope_hash: None,
            },
            &issuer,
        )
        .expect("sign delegation link");
        let scope = ChioScope::default();
        let proof = AttenuationProof {
            parent_scope_hash: scope_hash(&scope).expect("parent scope hash"),
            child_scope_hash: scope_hash(&scope).expect("child scope hash"),
            normalized_subset_proof: compute_attenuation_witness(&scope, &scope)
                .expect("attenuation witness"),
        };
        let token = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: "cap-child".to_string(),
                    issuer: issuer.public_key(),
                    subject: subject.public_key(),
                    scope,
                    issued_at: 100,
                    expires_at: 200,
                    delegation_chain: Vec::from([parent_link]),
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: proof,
                budget_share_bps: None,
            },
            &issuer,
        )
        .expect("sign child token");
        let clock = crate::FixedClock::new(150);
        let mut budgets = crate::InMemoryBudgetRegistry::new();

        let err = verify_capability_with_floor(
            &token,
            &[issuer.public_key()],
            &clock,
            CapabilityCryptoFloor::AllowClassical,
            &mut budgets,
        )
        .expect_err("unknown budget parent must fail closed");

        assert!(matches!(
            err,
            CapabilityError::BudgetSplitRejected(BudgetSplitError::UnknownParent { .. })
        ));
    }
}
