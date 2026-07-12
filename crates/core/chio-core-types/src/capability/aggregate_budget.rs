//! Aggregate invocation budget wire types, issuance, and authority verification.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    canonical_json_bytes, is_default_optional_algorithm, sha256_hex, Keypair, PublicKey, Signature,
    SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::signer_binding::ensure_keypair_matches_embedded_key;

use super::attenuation::{scope_hash, validate_capability_delegation_chain, ScopeHash};
use super::scope::ChioScope;
use super::token::{CapabilityToken, CapabilityTokenBody};

/// Schema carried by aggregate delegation-family root binding bodies.
pub const CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA: &str = "chio.aggregate-budget-root.v1";

/// Domain for hashing a pre-binding aggregate-budget root commitment.
pub const CHIO_AGGREGATE_BUDGET_ROOT_COMMITMENT_DOMAIN: &str =
    "chio.aggregate-budget-root-commitment.v1\0";

/// Domain for signing an aggregate-budget root binding body.
pub const CHIO_AGGREGATE_BUDGET_ROOT_SIGNATURE_DOMAIN: &str = "chio.aggregate-budget-root.v1\0";

/// Domain for deriving an aggregate delegation-family quota owner.
pub const CHIO_AGGREGATE_BUDGET_FAMILY_KEY_DOMAIN: &str = "chio.aggregate-budget-family-key.v1\0";

/// Domain for hashing a complete aggregate-budget root binding envelope.
pub const CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN: &str =
    "chio.aggregate-budget-root-binding.v1\0";

/// Maximum UTF-8 byte length accepted for a durable aggregate family-root ID.
pub const MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES: usize = 512;

/// Scope over which an aggregate invocation maximum is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateInvocationScope {
    /// The maximum belongs only to this capability token.
    Capability,
    /// The maximum is shared by a root capability and its descendants.
    DelegationFamily,
}

/// Optional invocation maximum carried by a capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateInvocationBudget {
    pub scope: AggregateInvocationScope,
    pub max_invocations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_binding: Option<AggregateBudgetRootBinding>,
}

impl AggregateInvocationBudget {
    /// Validate the budget's non-cryptographic relationship to a token scope.
    ///
    /// A zero maximum is valid. Root-binding signature and field verification
    /// is outside this structural validator.
    pub fn validate_for_scope(&self, token_scope: &ChioScope) -> Result<()> {
        match self.scope {
            AggregateInvocationScope::Capability => {
                if self.root_binding.is_some() {
                    return Err(Error::AttenuationViolation {
                        reason: "capability-scoped aggregate budget must not carry a root binding"
                            .to_string(),
                    });
                }
                if token_scope.authorizes_delegation() {
                    return Err(Error::AttenuationViolation {
                        reason: "capability-scoped aggregate budget cannot authorize delegation"
                            .to_string(),
                    });
                }
            }
            AggregateInvocationScope::DelegationFamily => {
                if self.root_binding.is_none() {
                    return Err(Error::AttenuationViolation {
                        reason: "delegation-family aggregate budget requires a root binding"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Pre-binding commitment for a direct aggregate delegation-family root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootCommitment {
    pub root_capability_id: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub root_scope_hash: ScopeHash,
    pub root_issued_at: u64,
    pub root_expires_at: u64,
    pub aggregate_scope: AggregateInvocationScope,
    pub max_invocations: u32,
}

/// Signed aggregate delegation-family root facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBindingBody {
    pub schema: String,
    pub root_capability_id: String,
    pub root_capability_hash: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub max_invocations: u32,
    pub root_expires_at: u64,
    pub root_scope_hash: ScopeHash,
}

/// Signature envelope carrying aggregate delegation-family root facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBinding {
    pub body: AggregateBudgetRootBindingBody,
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

/// Signed projection proving preservation of aggregate family authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateFamilyPreservationEvidence {
    pub root_binding_digest: String,
    pub max_invocations: u32,
}

impl AggregateBudgetRootCommitment {
    /// Canonical RFC 8785 bytes of the schema-free root commitment.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json_bytes(self)
    }

    /// Domain-separated hash of the schema-free root commitment.
    pub fn commitment_hash(&self) -> Result<String> {
        domain_separated_hash(CHIO_AGGREGATE_BUDGET_ROOT_COMMITMENT_DOMAIN, self)
    }
}

impl AggregateBudgetRootBindingBody {
    /// Exact bytes signed by the aggregate family-root authority.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_separated_bytes(CHIO_AGGREGATE_BUDGET_ROOT_SIGNATURE_DOMAIN, self)
    }

    /// Derive an unverified family-owner candidate from this raw body.
    ///
    /// Production authority code must consume
    /// [`VerifiedAggregateFamilyRoot::family_owner`] instead. This helper is
    /// crate-visible only for verification and conformance tests.
    pub(crate) fn unverified_family_owner(&self) -> Result<String> {
        domain_separated_hash(CHIO_AGGREGATE_BUDGET_FAMILY_KEY_DOMAIN, self)
    }
}

impl AggregateBudgetRootBinding {
    /// Hash the complete binding envelope for preservation evidence.
    pub fn preservation_digest(&self) -> Result<String> {
        domain_separated_hash(CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN, self)
    }
}

impl AggregateFamilyPreservationEvidence {
    /// Validate this projection against authenticated family authority.
    pub fn validate_against_verified_root(&self, root: &VerifiedAggregateFamilyRoot) -> Result<()> {
        validate_preservation_values(self, root.root_binding_digest(), root.max_invocations())
    }

    pub(crate) fn validate_against_budget(&self, budget: &AggregateInvocationBudget) -> Result<()> {
        let binding = budget
            .root_binding
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "delegation-family aggregate budget is missing its root binding"
                    .to_string(),
            })?;
        let digest = binding.preservation_digest()?;
        validate_preservation_values(self, &digest, budget.max_invocations)
    }
}

fn validate_preservation_values(
    evidence: &AggregateFamilyPreservationEvidence,
    root_binding_digest: &str,
    max_invocations: u32,
) -> Result<()> {
    if evidence.root_binding_digest != root_binding_digest {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family preservation digest does not match the root binding"
                .to_string(),
        });
    }
    if evidence.max_invocations != max_invocations {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family preservation maximum does not match the immutable maximum"
                .to_string(),
        });
    }
    Ok(())
}

/// Authenticated projection of a direct aggregate delegation-family root.
///
/// The non-exhaustive shape prevents external callers from constructing a
/// value that bypasses [`verify_direct_aggregate_family_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedAggregateFamilyRoot {
    root_issued_at: u64,
    root_binding_digest: String,
    family_owner: String,
    root_binding: Box<AggregateBudgetRootBinding>,
}

impl VerifiedAggregateFamilyRoot {
    /// Authenticated root capability identifier.
    #[must_use]
    pub fn root_capability_id(&self) -> &str {
        &self.root_binding.body.root_capability_id
    }

    /// Authenticated root issuing authority.
    #[must_use]
    pub fn root_issuer(&self) -> &PublicKey {
        &self.root_binding.body.root_issuer
    }

    /// Authenticated root subject.
    #[must_use]
    pub fn root_subject(&self) -> &PublicKey {
        &self.root_binding.body.root_subject
    }

    /// Authenticated canonical scope hash.
    #[must_use]
    pub fn root_scope_hash(&self) -> &str {
        &self.root_binding.body.root_scope_hash
    }

    /// Authenticated root issuance timestamp.
    #[must_use]
    pub fn root_issued_at(&self) -> u64 {
        self.root_issued_at
    }

    /// Authenticated root expiry timestamp.
    #[must_use]
    pub fn root_expires_at(&self) -> u64 {
        self.root_binding.body.root_expires_at
    }

    /// Immutable authenticated family invocation maximum.
    #[must_use]
    pub fn max_invocations(&self) -> u32 {
        self.root_binding.body.max_invocations
    }

    /// Digest of the complete authenticated binding envelope.
    #[must_use]
    pub fn root_binding_digest(&self) -> &str {
        &self.root_binding_digest
    }

    /// Authenticated family quota owner.
    #[must_use]
    pub fn family_owner(&self) -> &str {
        &self.family_owner
    }

    /// Complete authenticated root binding envelope.
    #[must_use]
    pub fn root_binding(&self) -> &AggregateBudgetRootBinding {
        self.root_binding.as_ref()
    }

    /// Signed attenuation projection for this authenticated family root.
    #[must_use]
    pub fn preservation_evidence(&self) -> AggregateFamilyPreservationEvidence {
        AggregateFamilyPreservationEvidence {
            root_binding_digest: self.root_binding_digest.clone(),
            max_invocations: self.max_invocations(),
        }
    }
}

/// Authenticated legacy root facts returned by a trusted resolver.
///
/// Construction alone does not confer authority. A value becomes authoritative
/// only when returned by the caller-selected [`AggregateFamilyRootResolver`].
/// Private fields prevent mutation after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LegacyUnboundAggregateRoot {
    root_capability_id: String,
    root_subject: PublicKey,
    root_scope_hash: ScopeHash,
    root_expires_at: u64,
}

impl LegacyUnboundAggregateRoot {
    /// Build an immutable legacy root record for a trusted resolver.
    #[must_use]
    pub fn new(
        root_capability_id: String,
        root_subject: PublicKey,
        root_scope_hash: ScopeHash,
        root_expires_at: u64,
    ) -> Self {
        Self {
            root_capability_id,
            root_subject,
            root_scope_hash,
            root_expires_at,
        }
    }

    /// Authenticated legacy root capability identifier.
    #[must_use]
    pub fn root_capability_id(&self) -> &str {
        &self.root_capability_id
    }

    /// Authenticated legacy root subject.
    #[must_use]
    pub fn root_subject(&self) -> &PublicKey {
        &self.root_subject
    }

    /// Authenticated legacy root scope hash.
    #[must_use]
    pub fn root_scope_hash(&self) -> &str {
        &self.root_scope_hash
    }

    /// Authenticated legacy root expiry.
    #[must_use]
    pub fn root_expires_at(&self) -> u64 {
        self.root_expires_at
    }
}

/// Authenticated aggregate-root state returned by a trusted resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AggregateFamilyRootResolution {
    /// The authenticated root predates aggregate family binding.
    LegacyUnbound(LegacyUnboundAggregateRoot),
    /// The authenticated root established immutable family authority.
    FamilyBound(VerifiedAggregateFamilyRoot),
}

/// Typed failures from aggregate family-root resolution.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AggregateFamilyRootResolutionError {
    /// No authenticated root record exists for the requested capability ID.
    #[cfg_attr(feature = "std", error("aggregate family root record is missing"))]
    Missing,
    /// The trusted authority could not perform the lookup.
    #[cfg_attr(
        feature = "std",
        error("aggregate family root resolver unavailable: {0}")
    )]
    Unavailable(String),
    /// The trusted authority found an invalid or inconsistent record.
    #[cfg_attr(feature = "std", error("aggregate family root record is corrupt: {0}"))]
    Corrupt(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AggregateFamilyRootResolutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => write!(f, "aggregate family root record is missing"),
            Self::Unavailable(reason) => {
                write!(f, "aggregate family root resolver unavailable: {reason}")
            }
            Self::Corrupt(reason) => {
                write!(f, "aggregate family root record is corrupt: {reason}")
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for AggregateFamilyRootResolutionError {}

/// Trusted aggregate family-root authority lookup.
///
/// Implementations authenticate both legacy and family-bound records. Missing,
/// unavailable, and corrupt state must be returned as typed errors and never
/// converted into [`AggregateFamilyRootResolution::LegacyUnbound`].
pub trait AggregateFamilyRootResolver {
    /// Resolve the authenticated root record keyed by the first delegation
    /// link's capability identifier.
    fn resolve_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> core::result::Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError>;
}

impl<F> AggregateFamilyRootResolver for F
where
    F: Fn(
        &str,
    ) -> core::result::Result<
        AggregateFamilyRootResolution,
        AggregateFamilyRootResolutionError,
    >,
{
    fn resolve_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> core::result::Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError>
    {
        (self)(root_capability_id)
    }
}

/// Immutable authority for a capability-scoped aggregate maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedCapabilityAggregateAuthority {
    owner: String,
    max_invocations: u32,
}

impl VerifiedCapabilityAggregateAuthority {
    /// Capability identifier that owns this aggregate maximum.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Immutable authenticated maximum.
    #[must_use]
    pub fn max_invocations(&self) -> u32 {
        self.max_invocations
    }
}

/// Authenticated aggregate invocation authority for either supported scope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifiedAggregateInvocationAuthority {
    /// The maximum belongs only to the verified leaf capability.
    Capability(VerifiedCapabilityAggregateAuthority),
    /// The maximum belongs to the authenticated delegation family.
    DelegationFamily(VerifiedAggregateFamilyRoot),
}

impl VerifiedAggregateInvocationAuthority {
    /// Authenticated aggregate scope.
    #[must_use]
    pub fn scope(&self) -> AggregateInvocationScope {
        match self {
            Self::Capability(_) => AggregateInvocationScope::Capability,
            Self::DelegationFamily(_) => AggregateInvocationScope::DelegationFamily,
        }
    }

    /// Immutable quota owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        match self {
            Self::Capability(authority) => authority.owner(),
            Self::DelegationFamily(root) => root.family_owner(),
        }
    }

    /// Immutable authenticated maximum.
    #[must_use]
    pub fn max_invocations(&self) -> u32 {
        match self {
            Self::Capability(authority) => authority.max_invocations(),
            Self::DelegationFamily(root) => root.max_invocations(),
        }
    }

    /// Complete-envelope root-binding digest for family authority.
    #[must_use]
    pub fn root_binding_digest(&self) -> Option<&str> {
        match self {
            Self::Capability(_) => None,
            Self::DelegationFamily(root) => Some(root.root_binding_digest()),
        }
    }

    /// Borrow the verified family root when this is family authority.
    #[must_use]
    pub fn family_root(&self) -> Option<&VerifiedAggregateFamilyRoot> {
        match self {
            Self::Capability(_) => None,
            Self::DelegationFamily(root) => Some(root),
        }
    }

    /// Signed attenuation projection when this authority belongs to a family.
    #[must_use]
    pub fn preservation_evidence(&self) -> Option<AggregateFamilyPreservationEvidence> {
        match self {
            Self::Capability(_) => None,
            Self::DelegationFamily(root) => Some(root.preservation_evidence()),
        }
    }
}

/// Fail-closed errors from aggregate authority verification.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
#[non_exhaustive]
pub enum AggregateInvocationAuthorityError {
    /// Leaf, chain, or aggregate authority authentication failed.
    #[cfg_attr(feature = "std", error("aggregate authority verification failed: {0}"))]
    Verification(#[cfg_attr(feature = "std", source)] Error),
    /// Trusted root resolution failed.
    #[cfg_attr(feature = "std", error("aggregate family root resolution failed: {0}"))]
    RootResolution(#[cfg_attr(feature = "std", source)] AggregateFamilyRootResolutionError),
}

impl From<Error> for AggregateInvocationAuthorityError {
    fn from(error: Error) -> Self {
        Self::Verification(error)
    }
}

impl From<AggregateFamilyRootResolutionError> for AggregateInvocationAuthorityError {
    fn from(error: AggregateFamilyRootResolutionError) -> Self {
        Self::RootResolution(error)
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AggregateInvocationAuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verification(error) => {
                write!(f, "aggregate authority verification failed: {error}")
            }
            Self::RootResolution(error) => {
                write!(f, "aggregate family root resolution failed: {error}")
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for AggregateInvocationAuthorityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Verification(error) => Some(error),
            Self::RootResolution(error) => Some(error),
        }
    }
}

/// Issue a direct aggregate delegation-family root with an Ed25519 keypair.
///
/// Callers provide only an ordinary, empty-chain capability body and the
/// immutable family maximum. Root commitment, binding, owner, and signatures
/// are derived internally.
pub fn issue_aggregate_family_root(
    mut body: CapabilityTokenBody,
    max_invocations: u32,
    keypair: &Keypair,
) -> Result<CapabilityToken> {
    validate_direct_root_issuance_body(&body)?;
    ensure_keypair_matches_embedded_key(&body.issuer, keypair, "aggregate family root", "issuer")?;

    let commitment = commitment_from_body(&body, max_invocations)?;
    let binding_body = binding_body_from_commitment(&commitment)?;
    let signature = keypair.sign(&binding_body.signing_bytes()?);
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::DelegationFamily,
        max_invocations,
        root_binding: Some(AggregateBudgetRootBinding {
            body: binding_body,
            algorithm: None,
            signature,
        }),
    });
    CapabilityToken::sign(body, keypair)
}

/// Issue a direct aggregate delegation-family root with a signing backend.
pub fn issue_aggregate_family_root_with_backend(
    mut body: CapabilityTokenBody,
    max_invocations: u32,
    backend: &dyn SigningBackend,
) -> Result<CapabilityToken> {
    validate_direct_root_issuance_body(&body)?;
    let expected_issuer = backend.public_key();
    let expected_algorithm = backend.algorithm();
    if body.issuer != expected_issuer {
        return Err(Error::InvalidPublicKey(
            "aggregate family root issuer does not match signing key".to_string(),
        ));
    }
    if expected_issuer.algorithm() != expected_algorithm {
        return Err(Error::InvalidSignature(
            "aggregate family root backend algorithm does not match public key".to_string(),
        ));
    }

    let commitment = commitment_from_body(&body, max_invocations)?;
    let binding_body = binding_body_from_commitment(&commitment)?;
    let binding_signing_bytes = binding_body.signing_bytes()?;
    let signature = backend.sign_bytes(&binding_signing_bytes)?;
    if signature.algorithm() != expected_algorithm {
        return Err(Error::InvalidSignature(
            "aggregate family root backend algorithm does not match returned signature".to_string(),
        ));
    }
    if !expected_issuer.verify(&binding_signing_bytes, &signature) {
        return Err(Error::InvalidSignature(
            "aggregate family root binding signature invalid".to_string(),
        ));
    }
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::DelegationFamily,
        max_invocations,
        root_binding: Some(AggregateBudgetRootBinding {
            body: binding_body,
            algorithm: (!expected_algorithm.is_default()).then_some(expected_algorithm),
            signature,
        }),
    });
    let token = CapabilityToken::sign_with_backend(body, backend)?;
    verify_direct_aggregate_family_root(&token, core::slice::from_ref(&expected_issuer))?;
    Ok(token)
}

/// Authenticate and project a direct aggregate delegation-family root.
pub fn verify_direct_aggregate_family_root(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
) -> Result<VerifiedAggregateFamilyRoot> {
    ensure_algorithm_consistency(
        token.algorithm,
        &token.issuer,
        &token.signature,
        "aggregate family root capability algorithm does not match issuer and signature",
    )?;
    if !token.verify_signature()? {
        return Err(Error::InvalidSignature(
            "aggregate family root capability signature invalid".to_string(),
        ));
    }
    if !trusted_issuers.contains(&token.issuer) {
        return Err(Error::InvalidPublicKey(
            "aggregate family root issuer is not trusted".to_string(),
        ));
    }
    if !token.delegation_chain.is_empty() {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root verification requires an empty delegation chain"
                .to_string(),
        });
    }

    let budget =
        token
            .aggregate_invocation_budget
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "aggregate family root requires aggregate_invocation_budget".to_string(),
            })?;
    if budget.scope != AggregateInvocationScope::DelegationFamily {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root requires delegation_family scope".to_string(),
        });
    }
    let binding = budget
        .root_binding
        .as_ref()
        .ok_or_else(|| Error::AttenuationViolation {
            reason: "aggregate family root requires a root binding".to_string(),
        })?;
    if binding.body.schema != CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA {
        return Err(Error::InvalidSignature(
            "aggregate family root binding schema mismatch".to_string(),
        ));
    }
    if binding.body.root_issuer != token.issuer {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding root_issuer does not match token issuer"
                .to_string(),
        });
    }
    ensure_algorithm_consistency(
        binding.algorithm,
        &binding.body.root_issuer,
        &binding.signature,
        "aggregate family root binding algorithm does not match root issuer and signature",
    )?;
    if !binding
        .body
        .root_issuer
        .verify(&binding.body.signing_bytes()?, &binding.signature)
    {
        return Err(Error::InvalidSignature(
            "aggregate family root binding signature invalid".to_string(),
        ));
    }

    if binding.body.root_capability_id != token.id {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding root_capability_id does not match token id"
                .to_string(),
        });
    }
    if binding.body.root_subject != token.subject {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding root_subject does not match token subject"
                .to_string(),
        });
    }
    if binding.body.root_expires_at != token.expires_at {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding root_expires_at does not match token expiry"
                .to_string(),
        });
    }
    let root_scope_hash = scope_hash(&token.scope)?;
    if binding.body.root_scope_hash != root_scope_hash {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding root_scope_hash does not match token scope"
                .to_string(),
        });
    }
    if binding.body.max_invocations != budget.max_invocations {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root binding max_invocations does not match aggregate budget"
                .to_string(),
        });
    }

    let commitment = AggregateBudgetRootCommitment {
        root_capability_id: token.id.clone(),
        root_issuer: token.issuer.clone(),
        root_subject: token.subject.clone(),
        root_scope_hash: root_scope_hash.clone(),
        root_issued_at: token.issued_at,
        root_expires_at: token.expires_at,
        aggregate_scope: budget.scope,
        max_invocations: budget.max_invocations,
    };
    if binding.body.root_capability_hash != commitment.commitment_hash()? {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root commitment hash mismatch".to_string(),
        });
    }

    let root_binding_digest = binding.preservation_digest()?;
    let family_owner = binding.body.unverified_family_owner()?;
    Ok(VerifiedAggregateFamilyRoot {
        root_issued_at: token.issued_at,
        root_binding_digest,
        family_owner,
        root_binding: Box::new(binding.clone()),
    })
}

/// Authenticate a complete direct token as a durable aggregate-root record.
///
/// This is stricter than family-binding verification alone. Both explicit
/// legacy roots and family-bound roots must be direct, delegable, unattenuated
/// authority artifacts with a valid lifetime and trusted outer signature.
pub fn verify_direct_aggregate_root_record(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
) -> Result<AggregateFamilyRootResolution> {
    if token.id.is_empty() || token.id.len() > MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES {
        return Err(Error::AttenuationViolation {
            reason: "aggregate root capability id must contain 1 to 512 bytes".to_string(),
        });
    }
    ensure_algorithm_consistency(
        token.algorithm,
        &token.issuer,
        &token.signature,
        "aggregate root capability algorithm does not match issuer and signature",
    )?;
    if !token.verify_signature()? {
        return Err(Error::InvalidSignature(
            "aggregate root capability signature invalid".to_string(),
        ));
    }
    if !trusted_issuers.contains(&token.issuer) {
        return Err(Error::InvalidPublicKey(
            "aggregate root issuer is not trusted".to_string(),
        ));
    }
    if !token.delegation_chain.is_empty() {
        return Err(Error::AttenuationViolation {
            reason: "aggregate root record requires an empty delegation chain".to_string(),
        });
    }
    if !token.scope.authorizes_delegation() {
        return Err(Error::AttenuationViolation {
            reason: "aggregate root record requires a scope that authorizes delegation".to_string(),
        });
    }
    if !token.caveats.is_empty()
        || token
            .scope_attenuations
            .as_ref()
            .is_some_and(|attenuations| !attenuations.is_empty())
        || token.attenuation_proof.is_some()
        || token.budget_share_bps.is_some()
    {
        return Err(Error::AttenuationViolation {
            reason: "aggregate root record cannot be attenuated or caveated".to_string(),
        });
    }
    if token.issued_at >= token.expires_at {
        return Err(Error::AttenuationViolation {
            reason: "aggregate root expiry must be later than issuance".to_string(),
        });
    }

    match token.aggregate_invocation_budget.as_ref() {
        None => Ok(AggregateFamilyRootResolution::LegacyUnbound(
            LegacyUnboundAggregateRoot::new(
                token.id.clone(),
                token.subject.clone(),
                scope_hash(&token.scope)?,
                token.expires_at,
            ),
        )),
        Some(budget) if budget.scope == AggregateInvocationScope::DelegationFamily => {
            Ok(AggregateFamilyRootResolution::FamilyBound(
                verify_direct_aggregate_family_root(token, trusted_issuers)?,
            ))
        }
        Some(_) => Err(Error::AttenuationViolation {
            reason: "capability-scoped aggregate budget is not an aggregate family root"
                .to_string(),
        }),
    }
}

/// Authenticate aggregate authority for a direct capability or descendant.
///
/// Direct family roots use [`verify_direct_aggregate_family_root`]. Every
/// descendant first authenticates the leaf and complete delegation chain, then
/// resolves the first link's root capability ID through the trusted resolver.
/// The resolver is never called for direct tokens or unauthenticated chains.
/// Direct tokens require an independently trusted root issuer; descendant-leaf
/// trust never authorizes empty-chain issuance.
pub fn verify_aggregate_invocation_authority(
    token: &CapabilityToken,
    trusted_direct_root_issuers: &[PublicKey],
    trusted_descendant_leaf_issuers: &[PublicKey],
    resolver: &dyn AggregateFamilyRootResolver,
) -> core::result::Result<
    Option<VerifiedAggregateInvocationAuthority>,
    AggregateInvocationAuthorityError,
> {
    ensure_algorithm_consistency(
        token.algorithm,
        &token.issuer,
        &token.signature,
        "aggregate authority capability algorithm does not match issuer and signature",
    )?;
    if !token.verify_signature()? {
        return Err(Error::InvalidSignature(
            "aggregate authority capability signature invalid".to_string(),
        )
        .into());
    }

    if token.delegation_chain.is_empty() {
        if !trusted_direct_root_issuers.contains(&token.issuer) {
            return Err(Error::InvalidPublicKey(
                "aggregate direct capability issuer is not trusted as a root authority".to_string(),
            )
            .into());
        }
        return verify_direct_aggregate_authority(token, trusted_direct_root_issuers);
    }

    if !trusted_descendant_leaf_issuers.contains(&token.issuer) {
        return Err(Error::InvalidPublicKey(
            "aggregate descendant capability issuer is not trusted as a leaf authority".to_string(),
        )
        .into());
    }
    validate_capability_delegation_chain(token, None)?;

    let first_link =
        token
            .delegation_chain
            .first()
            .ok_or_else(|| Error::DelegationChainBroken {
                reason: "delegation chain unexpectedly empty after non-empty check".to_string(),
            })?;
    let lookup_root_id = first_link.capability_id.as_str();
    let resolved = resolver.resolve_aggregate_family_root(lookup_root_id)?;

    match resolved {
        AggregateFamilyRootResolution::LegacyUnbound(root) => {
            ensure_resolved_record_matches_lookup(root.root_capability_id(), lookup_root_id)?;
            reject_spurious_family_preservation(token)?;
            let authority = match token.aggregate_invocation_budget.as_ref() {
                None => None,
                Some(budget) if budget.scope == AggregateInvocationScope::Capability => {
                    Some(capability_aggregate_authority(token, budget))
                }
                Some(_) => {
                    return Err(Error::AttenuationViolation {
                        reason:
                            "legacy-unbound root cannot create a delegation-family aggregate budget"
                                .to_string(),
                    }
                    .into());
                }
            };
            verify_resolved_root_lineage(
                token,
                first_link,
                root.root_subject(),
                root.root_scope_hash(),
                root.root_expires_at(),
            )?;
            Ok(authority)
        }
        AggregateFamilyRootResolution::FamilyBound(root) => {
            ensure_resolved_record_matches_lookup(root.root_capability_id(), lookup_root_id)?;
            let budget = token.aggregate_invocation_budget.as_ref().ok_or_else(|| {
                Error::AttenuationViolation {
                    reason: "family-bound descendant must preserve aggregate_invocation_budget"
                        .to_string(),
                }
            })?;
            if budget.scope != AggregateInvocationScope::DelegationFamily {
                return Err(Error::AttenuationViolation {
                    reason: "family-bound descendant cannot downgrade aggregate scope".to_string(),
                }
                .into());
            }
            if budget.max_invocations != root.max_invocations() {
                return Err(Error::AttenuationViolation {
                    reason: "family-bound descendant changed the immutable aggregate maximum"
                        .to_string(),
                }
                .into());
            }
            let binding =
                budget
                    .root_binding
                    .as_ref()
                    .ok_or_else(|| Error::AttenuationViolation {
                        reason: "family-bound descendant must preserve the root binding"
                            .to_string(),
                    })?;
            if binding.preservation_digest()? != root.root_binding_digest() {
                return Err(Error::AttenuationViolation {
                    reason: "family-bound descendant changed the root binding envelope".to_string(),
                }
                .into());
            }
            validate_family_preservation(token, &root)?;
            verify_resolved_root_lineage(
                token,
                first_link,
                root.root_subject(),
                root.root_scope_hash(),
                root.root_expires_at(),
            )?;
            Ok(Some(
                VerifiedAggregateInvocationAuthority::DelegationFamily(root),
            ))
        }
    }
}

fn verify_direct_aggregate_authority(
    token: &CapabilityToken,
    trusted_issuers: &[PublicKey],
) -> core::result::Result<
    Option<VerifiedAggregateInvocationAuthority>,
    AggregateInvocationAuthorityError,
> {
    let Some(budget) = token.aggregate_invocation_budget.as_ref() else {
        reject_spurious_family_preservation(token)?;
        return Ok(None);
    };
    match budget.scope {
        AggregateInvocationScope::Capability => {
            reject_spurious_family_preservation(token)?;
            Ok(Some(capability_aggregate_authority(token, budget)))
        }
        AggregateInvocationScope::DelegationFamily => {
            let root = verify_direct_aggregate_family_root(token, trusted_issuers)?;
            validate_family_preservation(token, &root)?;
            Ok(Some(
                VerifiedAggregateInvocationAuthority::DelegationFamily(root),
            ))
        }
    }
}

fn validate_family_preservation(
    token: &CapabilityToken,
    root: &VerifiedAggregateFamilyRoot,
) -> Result<()> {
    if let Some(proof) = token.attenuation_proof.as_ref() {
        let evidence = proof
            .aggregate_family_preservation
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "attenuated delegation-family capability must preserve aggregate family evidence"
                    .to_string(),
            })?;
        evidence.validate_against_verified_root(root)?;
    }
    for link in &token.delegation_chain {
        if let Some(evidence) = link.aggregate_family_preservation.as_ref() {
            evidence.validate_against_verified_root(root)?;
        }
    }
    Ok(())
}

fn reject_spurious_family_preservation(token: &CapabilityToken) -> Result<()> {
    let proof_has_evidence = token
        .attenuation_proof
        .as_ref()
        .and_then(|proof| proof.aggregate_family_preservation.as_ref())
        .is_some();
    let link_has_evidence = token
        .delegation_chain
        .iter()
        .any(|link| link.aggregate_family_preservation.is_some());
    if proof_has_evidence || link_has_evidence {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family preservation evidence requires a delegation-family budget"
                .to_string(),
        });
    }
    Ok(())
}

fn capability_aggregate_authority(
    token: &CapabilityToken,
    budget: &AggregateInvocationBudget,
) -> VerifiedAggregateInvocationAuthority {
    VerifiedAggregateInvocationAuthority::Capability(VerifiedCapabilityAggregateAuthority {
        owner: token.id.clone(),
        max_invocations: budget.max_invocations,
    })
}

fn ensure_resolved_record_matches_lookup(
    resolved_root_id: &str,
    lookup_root_id: &str,
) -> core::result::Result<(), AggregateInvocationAuthorityError> {
    if resolved_root_id == lookup_root_id {
        return Ok(());
    }
    Err(AggregateFamilyRootResolutionError::Corrupt(
        "resolved root capability ID does not match lookup key".to_string(),
    )
    .into())
}

fn verify_resolved_root_lineage(
    token: &CapabilityToken,
    first_link: &super::attenuation::DelegationLink,
    root_subject: &PublicKey,
    root_scope_hash: &str,
    root_expires_at: u64,
) -> core::result::Result<(), AggregateInvocationAuthorityError> {
    if &first_link.delegator != root_subject {
        return Err(Error::AttenuationViolation {
            reason: "delegation chain first delegator does not match resolved root subject"
                .to_string(),
        }
        .into());
    }
    if first_link.scope_hash.as_deref() != Some(root_scope_hash) {
        return Err(Error::AttenuationViolation {
            reason: "delegation chain first scope hash does not match resolved root scope hash"
                .to_string(),
        }
        .into());
    }
    if token.expires_at > root_expires_at {
        return Err(Error::AttenuationViolation {
            reason: "descendant capability outlives resolved aggregate root".to_string(),
        }
        .into());
    }
    Ok(())
}

fn domain_separated_bytes<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn domain_separated_hash<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    Ok(sha256_hex(&domain_separated_bytes(domain, value)?))
}

fn validate_direct_root_issuance_body(body: &CapabilityTokenBody) -> Result<()> {
    if body.aggregate_invocation_budget.is_some() {
        return Err(Error::AttenuationViolation {
            reason:
                "aggregate family root issuance requires aggregate_invocation_budget to be absent"
                    .to_string(),
        });
    }
    if !body.delegation_chain.is_empty() {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family root issuance requires an empty delegation chain".to_string(),
        });
    }
    Ok(())
}

fn commitment_from_body(
    body: &CapabilityTokenBody,
    max_invocations: u32,
) -> Result<AggregateBudgetRootCommitment> {
    Ok(AggregateBudgetRootCommitment {
        root_capability_id: body.id.clone(),
        root_issuer: body.issuer.clone(),
        root_subject: body.subject.clone(),
        root_scope_hash: scope_hash(&body.scope)?,
        root_issued_at: body.issued_at,
        root_expires_at: body.expires_at,
        aggregate_scope: AggregateInvocationScope::DelegationFamily,
        max_invocations,
    })
}

fn binding_body_from_commitment(
    commitment: &AggregateBudgetRootCommitment,
) -> Result<AggregateBudgetRootBindingBody> {
    Ok(AggregateBudgetRootBindingBody {
        schema: CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA.to_string(),
        root_capability_id: commitment.root_capability_id.clone(),
        root_capability_hash: commitment.commitment_hash()?,
        root_issuer: commitment.root_issuer.clone(),
        root_subject: commitment.root_subject.clone(),
        max_invocations: commitment.max_invocations,
        root_expires_at: commitment.root_expires_at,
        root_scope_hash: commitment.root_scope_hash.clone(),
    })
}

fn ensure_algorithm_consistency(
    declared: Option<SigningAlgorithm>,
    public_key: &PublicKey,
    signature: &Signature,
    reason: &str,
) -> Result<()> {
    let effective = declared.unwrap_or(SigningAlgorithm::Ed25519);
    if effective != public_key.algorithm() || effective != signature.algorithm() {
        return Err(Error::InvalidSignature(reason.to_string()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::capability::attenuation::{scope_hash, DelegationLink, DelegationLinkBody};
    use crate::capability::scope::{Operation, ToolGrant};
    use crate::capability::token::{CapabilityToken, CapabilityTokenBody};
    use crate::crypto::{
        canonical_json_bytes, sha256_hex, Ed25519Backend, Keypair, SigningAlgorithm, SigningBackend,
    };

    const FIXED_ISSUER_SEED: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const FIXED_SUBJECT_SEED: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const FIXED_COMMITMENT_JSON: &str = concat!(
        "{\"aggregate_scope\":\"delegation_family\",\"max_invocations\":3,",
        "\"root_capability_id\":\"cap-family-root\",\"root_expires_at\":2000,",
        "\"root_issued_at\":1000,\"root_issuer\":",
        "\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",",
        "\"root_scope_hash\":",
        "\"2222222222222222222222222222222222222222222222222222222222222222\",",
        "\"root_subject\":",
        "\"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\"}"
    );
    const FIXED_COMMITMENT_HASH: &str =
        "17ee61436f0e78da037cdd55094c94eaa30c16f7cdb5ec88ea46bf5892155393";

    fn fixed_issuer() -> Keypair {
        Keypair::from_seed_hex(FIXED_ISSUER_SEED).expect("fixed issuer")
    }

    fn fixed_subject() -> Keypair {
        Keypair::from_seed_hex(FIXED_SUBJECT_SEED).expect("fixed subject")
    }

    fn ordinary_root_body(
        issuer: &PublicKey,
        subject: &PublicKey,
        id: &str,
    ) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        }
    }

    fn delegable_root_body(
        issuer: &PublicKey,
        subject: &PublicKey,
        id: &str,
    ) -> CapabilityTokenBody {
        let mut body = ordinary_root_body(issuer, subject, id);
        body.scope.grants.push(ToolGrant {
            server_id: "aggregate-root-server".to_string(),
            tool_name: "aggregate-root-tool".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
        body
    }

    fn valid_root(max_invocations: u32) -> (Keypair, CapabilityToken) {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let token = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer.public_key(),
                &subject.public_key(),
                "cap-family-root",
            ),
            max_invocations,
            &issuer,
        )
        .expect("issue aggregate family root");
        (issuer, token)
    }

    fn assert_attenuation_reason(error: Error, expected: &str) {
        match error {
            Error::AttenuationViolation { reason } => assert_eq!(reason, expected),
            other => panic!("expected attenuation violation, got {other:?}"),
        }
    }

    fn assert_invalid_signature(error: Error, expected: &str) {
        match error {
            Error::InvalidSignature(reason) => assert_eq!(reason, expected),
            other => panic!("expected invalid signature, got {other:?}"),
        }
    }

    fn root_binding_mut(body: &mut CapabilityTokenBody) -> &mut AggregateBudgetRootBinding {
        body.aggregate_invocation_budget
            .as_mut()
            .and_then(|budget| budget.root_binding.as_mut())
            .expect("root binding")
    }

    fn root_binding(token: &CapabilityToken) -> &AggregateBudgetRootBinding {
        token
            .aggregate_invocation_budget
            .as_ref()
            .and_then(|budget| budget.root_binding.as_ref())
            .expect("root binding")
    }

    fn resign_binding(binding: &mut AggregateBudgetRootBinding, signer: &Keypair) {
        binding.signature = signer.sign(&binding.body.signing_bytes().expect("binding bytes"));
    }

    fn resign_outer(body: CapabilityTokenBody, signer: &Keypair) -> CapabilityToken {
        CapabilityToken::sign(body, signer).expect("resign outer capability")
    }

    fn domain_hash<T: Serialize>(domain: &str, value: &T) -> String {
        let canonical = canonical_json_bytes(value).expect("canonical value");
        let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
        preimage.extend_from_slice(domain.as_bytes());
        preimage.extend_from_slice(&canonical);
        sha256_hex(&preimage)
    }

    struct InconsistentBackend {
        keypair: Keypair,
    }

    impl SigningBackend for InconsistentBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::P256
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            Ok(self.keypair.sign(message))
        }
    }

    struct SignatureMismatchBackend {
        keypair: Keypair,
    }

    impl SigningBackend for SignatureMismatchBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::Ed25519
        }

        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_bytes(&self, _message: &[u8]) -> Result<Signature> {
            Ok(Signature::from_p256_der(&[1_u8, 2, 3]))
        }
    }

    struct TwoStageSignatureBackend {
        expected_keypair: Keypair,
        other_keypair: Keypair,
        expected_signature_first: bool,
        sign_calls: AtomicUsize,
    }

    impl SigningBackend for TwoStageSignatureBackend {
        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::Ed25519
        }

        fn public_key(&self) -> PublicKey {
            self.expected_keypair.public_key()
        }

        fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
            let first_call = self.sign_calls.fetch_add(1, Ordering::SeqCst) == 0;
            if first_call == self.expected_signature_first {
                Ok(self.expected_keypair.sign(message))
            } else {
                Ok(self.other_keypair.sign(message))
            }
        }
    }

    #[test]
    fn aggregate_invocation_root_commitment_matches_fixed_canonical_vector() {
        let commitment = AggregateBudgetRootCommitment {
            root_capability_id: "cap-family-root".to_string(),
            root_issuer: fixed_issuer().public_key(),
            root_subject: fixed_subject().public_key(),
            root_scope_hash: "22".repeat(32),
            root_issued_at: 1_000,
            root_expires_at: 2_000,
            aggregate_scope: AggregateInvocationScope::DelegationFamily,
            max_invocations: 3,
        };

        assert_eq!(
            commitment.canonical_bytes().expect("canonical commitment"),
            FIXED_COMMITMENT_JSON.as_bytes()
        );
        assert_eq!(
            commitment.commitment_hash().expect("commitment hash"),
            FIXED_COMMITMENT_HASH
        );
    }

    #[test]
    fn aggregate_invocation_root_binding_signing_bytes_use_exact_domain_prefix() {
        let body = AggregateBudgetRootBindingBody {
            schema: CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA.to_string(),
            root_capability_id: "cap-family-root".to_string(),
            root_capability_hash: "11".repeat(32),
            root_issuer: fixed_issuer().public_key(),
            root_subject: fixed_subject().public_key(),
            max_invocations: 3,
            root_expires_at: 2_000,
            root_scope_hash: "22".repeat(32),
        };
        let expected_json = concat!(
            "{\"max_invocations\":3,\"root_capability_hash\":",
            "\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"root_capability_id\":\"cap-family-root\",\"root_expires_at\":2000,",
            "\"root_issuer\":",
            "\"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\",",
            "\"root_scope_hash\":",
            "\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"root_subject\":",
            "\"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c\",",
            "\"schema\":\"chio.aggregate-budget-root.v1\"}"
        );
        let mut expected = CHIO_AGGREGATE_BUDGET_ROOT_SIGNATURE_DOMAIN
            .as_bytes()
            .to_vec();
        expected.extend_from_slice(expected_json.as_bytes());

        assert_eq!(
            body.signing_bytes().expect("binding signing bytes"),
            expected
        );
    }

    #[test]
    fn aggregate_invocation_root_keypair_issuance_accepts_zero_and_verifies() {
        let (issuer, token) = valid_root(0);
        assert!(token
            .verify_signature()
            .expect("final capability signature"));

        let verified =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).expect("root");
        assert_eq!(verified.root_capability_id(), token.id);
        assert_eq!(verified.root_issuer(), &token.issuer);
        assert_eq!(verified.root_subject(), &token.subject);
        assert_eq!(
            verified.root_scope_hash(),
            scope_hash(&token.scope).unwrap()
        );
        assert_eq!(verified.root_issued_at(), token.issued_at);
        assert_eq!(verified.root_expires_at(), token.expires_at);
        assert_eq!(verified.max_invocations(), 0);
        assert_eq!(verified.root_binding(), root_binding(&token));
        assert_eq!(
            verified.root_binding_digest(),
            verified.root_binding().preservation_digest().unwrap()
        );
        assert_eq!(
            verified.family_owner(),
            verified
                .root_binding()
                .body
                .unverified_family_owner()
                .unwrap()
        );
    }

    #[test]
    fn direct_aggregate_root_record_verifier_authenticates_family_and_legacy_shapes() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let family = issue_aggregate_family_root(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), "family-root"),
            0,
            &issuer,
        )
        .expect("family root");
        let legacy = CapabilityToken::sign(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), "legacy-root"),
            &issuer,
        )
        .expect("legacy root");

        assert!(matches!(
            verify_direct_aggregate_root_record(&family, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::FamilyBound(root))
                if root.root_capability_id() == "family-root" && root.max_invocations() == 0
        ));
        assert!(matches!(
            verify_direct_aggregate_root_record(&legacy, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
                if root.root_capability_id() == "legacy-root"
        ));

        let nondelegable = CapabilityToken::sign(
            ordinary_root_body(&issuer.public_key(), &subject.public_key(), "not-a-root"),
            &issuer,
        )
        .expect("signed direct token");
        assert!(
            verify_direct_aggregate_root_record(&nondelegable, &[issuer.public_key()]).is_err()
        );
    }

    #[test]
    fn direct_aggregate_root_record_verifier_enforces_id_byte_bound_before_issuer_trust() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let accepted_id = "a".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES);
        let accepted = CapabilityToken::sign(
            delegable_root_body(&issuer.public_key(), &subject.public_key(), &accepted_id),
            &issuer,
        )
        .expect("512-byte root id");
        assert!(matches!(
            verify_direct_aggregate_root_record(&accepted, &[issuer.public_key()]),
            Ok(AggregateFamilyRootResolution::LegacyUnbound(root))
                if root.root_capability_id() == accepted_id
        ));

        for rejected_id in [
            String::new(),
            "b".repeat(MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES + 1),
        ] {
            let rejected = CapabilityToken::sign(
                delegable_root_body(&issuer.public_key(), &subject.public_key(), &rejected_id),
                &issuer,
            )
            .expect("structurally signed root");
            let error = verify_direct_aggregate_root_record(&rejected, &[])
                .expect_err("invalid root id must fail before issuer trust");
            assert_attenuation_reason(
                error,
                "aggregate root capability id must contain 1 to 512 bytes",
            );
        }
    }

    #[test]
    fn aggregate_invocation_root_backend_issuance_accepts_safe_body() {
        let keypair = fixed_issuer();
        let backend = Ed25519Backend::new(keypair);
        let subject = fixed_subject();
        let token = issue_aggregate_family_root_with_backend(
            ordinary_root_body(
                &backend.public_key(),
                &subject.public_key(),
                "cap-family-backend",
            ),
            3,
            &backend,
        )
        .expect("backend issue");
        let binding = token
            .aggregate_invocation_budget
            .as_ref()
            .and_then(|budget| budget.root_binding.as_ref())
            .expect("root binding");
        assert_eq!(binding.algorithm, None);
        assert!(serde_json::to_value(binding)
            .unwrap()
            .get("algorithm")
            .is_none());
        verify_direct_aggregate_family_root(&token, &[backend.public_key()])
            .expect("verify backend root");
    }

    #[cfg(feature = "fips")]
    #[test]
    fn aggregate_invocation_root_nondefault_backend_records_algorithm_and_verifies() {
        let backend = crate::crypto::P256Backend::generate().expect("P-256 backend");
        let subject = fixed_subject();
        let token = issue_aggregate_family_root_with_backend(
            ordinary_root_body(
                &backend.public_key(),
                &subject.public_key(),
                "cap-family-p256",
            ),
            5,
            &backend,
        )
        .expect("P-256 issue");
        assert_eq!(root_binding(&token).algorithm, Some(SigningAlgorithm::P256));
        verify_direct_aggregate_family_root(&token, &[backend.public_key()])
            .expect("verify P-256 root");
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_keypair_and_backend_signer_mismatch() {
        let issuer = fixed_issuer();
        let other = Keypair::from_seed(&[9_u8; 32]);
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-keypair-mismatch",
        );
        match issue_aggregate_family_root(body, 3, &other).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(
                    reason,
                    "aggregate family root issuer does not match signing key"
                )
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }

        let backend = Ed25519Backend::new(other);
        let body = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-backend-mismatch",
        );
        match issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(
                    reason,
                    "aggregate family root issuer does not match signing key"
                )
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_inconsistent_backend_algorithm() {
        let backend = InconsistentBackend {
            keypair: fixed_issuer(),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-inconsistent-backend",
        );
        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "aggregate family root backend algorithm does not match public key",
        );
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_backend_signature_algorithm_mismatch() {
        let backend = SignatureMismatchBackend {
            keypair: fixed_issuer(),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-signature-mismatch-backend",
        );
        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "aggregate family root backend algorithm does not match returned signature",
        );
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_stateful_second_signature_key_drift() {
        let backend = TwoStageSignatureBackend {
            expected_keypair: fixed_issuer(),
            other_keypair: Keypair::from_seed(&[7_u8; 32]),
            expected_signature_first: true,
            sign_calls: AtomicUsize::new(0),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-second-signature-key-drift",
        );

        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(
            error,
            "capability token backend signature failed verification",
        );
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_same_algorithm_wrong_key_binding_signature() {
        let backend = TwoStageSignatureBackend {
            expected_keypair: fixed_issuer(),
            other_keypair: Keypair::from_seed(&[8_u8; 32]),
            expected_signature_first: false,
            sign_calls: AtomicUsize::new(0),
        };
        let subject = fixed_subject();
        let body = ordinary_root_body(
            &backend.public_key(),
            &subject.public_key(),
            "cap-wrong-key-binding-signature",
        );

        let error = issue_aggregate_family_root_with_backend(body, 3, &backend).unwrap_err();
        assert_invalid_signature(error, "aggregate family root binding signature invalid");
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn aggregate_invocation_root_issuance_rejects_prepopulated_or_delegated_body() {
        let issuer = fixed_issuer();
        let subject = fixed_subject();
        let mut prepopulated = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-prepopulated",
        );
        prepopulated.aggregate_invocation_budget = Some(AggregateInvocationBudget {
            scope: AggregateInvocationScope::Capability,
            max_invocations: 1,
            root_binding: None,
        });
        let error = issue_aggregate_family_root(prepopulated, 3, &issuer).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root issuance requires aggregate_invocation_budget to be absent",
        );

        let mut delegated = ordinary_root_body(
            &issuer.public_key(),
            &subject.public_key(),
            "cap-delegated-root",
        );
        delegated.delegation_chain.push(
            DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: "parent".to_string(),
                    delegator: issuer.public_key(),
                    delegatee: subject.public_key(),
                    attenuations: vec![],
                    timestamp: 900,
                    scope_hash: None,
                    aggregate_family_preservation: None,
                },
                &issuer,
            )
            .unwrap(),
        );
        let error = issue_aggregate_family_root(delegated, 3, &issuer).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root issuance requires an empty delegation chain",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_untrusted_issuer() {
        let (_issuer, token) = valid_root(3);
        match verify_direct_aggregate_family_root(&token, &[]).unwrap_err() {
            Error::InvalidPublicKey(reason) => {
                assert_eq!(reason, "aggregate family root issuer is not trusted")
            }
            error => panic!("expected invalid public key, got {error:?}"),
        }
    }

    #[test]
    fn aggregate_invocation_root_verifier_requires_delegation_family_scope() {
        let (issuer, mut token) = valid_root(3);
        token
            .aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .scope = AggregateInvocationScope::Capability;

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "capability-scoped aggregate budget must not carry a root binding",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_nonempty_chain() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.delegation_chain.push(
            DelegationLink::sign(
                DelegationLinkBody {
                    capability_id: "grafted-parent".to_string(),
                    delegator: issuer.public_key(),
                    delegatee: body.subject.clone(),
                    attenuations: vec![],
                    timestamp: 900,
                    scope_hash: None,
                    aggregate_family_preservation: None,
                },
                &issuer,
            )
            .unwrap(),
        );
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root verification requires an empty delegation chain",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_wrong_binding_schema() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.schema = "chio.aggregate-budget-root.v2".to_string();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root binding schema mismatch");
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_binding_algorithm_mismatch() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        root_binding_mut(&mut body).algorithm = Some(SigningAlgorithm::P256);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(
            error,
            "aggregate family root binding algorithm does not match root issuer and signature",
        );
    }

    #[test]
    fn aggregate_invocation_root_verifier_rejects_wrong_binding_signature() {
        let (issuer, token) = valid_root(3);
        let attacker = Keypair::from_seed(&[17_u8; 32]);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.signature = attacker.sign(&binding.body.signing_bytes().unwrap());
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root binding signature invalid");
    }

    #[test]
    fn aggregate_invocation_root_owner_hashes_body_and_digest_hashes_complete_envelope() {
        let (_issuer, token) = valid_root(3);
        let binding = root_binding(&token).clone();
        assert_eq!(
            binding.body.unverified_family_owner().unwrap(),
            domain_hash(CHIO_AGGREGATE_BUDGET_FAMILY_KEY_DOMAIN, &binding.body)
        );
        assert_eq!(
            binding.preservation_digest().unwrap(),
            domain_hash(CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN, &binding)
        );

        let mut changed_envelope = binding.clone();
        changed_envelope.signature = Keypair::from_seed(&[23_u8; 32]).sign(b"different");
        assert_eq!(
            binding.body.unverified_family_owner().unwrap(),
            changed_envelope.body.unverified_family_owner().unwrap()
        );
        assert_ne!(
            binding.preservation_digest().unwrap(),
            changed_envelope.preservation_digest().unwrap()
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_capability_id_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_capability_id = "cap-forged-id".to_string();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_capability_id does not match token id",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_commitment_hash_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_capability_hash = "00".repeat(32);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(error, "aggregate family root commitment hash mismatch");
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_issuer_mutation() {
        let (issuer, token) = valid_root(3);
        let other = Keypair::from_seed(&[31_u8; 32]);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_issuer = other.public_key();
        resign_binding(binding, &other);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_subject_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_subject = Keypair::from_seed(&[37_u8; 32]).public_key();
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_subject does not match token subject",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_issued_at_mutation_via_commitment_hash() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.issued_at = body.issued_at.saturating_add(1);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(error, "aggregate family root commitment hash mismatch");
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_expiry_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_expires_at = binding.body.root_expires_at.saturating_add(1);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_expires_at does not match token expiry",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_root_scope_hash_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        let binding = root_binding_mut(&mut body);
        binding.body.root_scope_hash = "ff".repeat(32);
        resign_binding(binding, &issuer);
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_scope_hash does not match token scope",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_maximum_mutation() {
        let (issuer, token) = valid_root(3);
        let mut body = token.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .max_invocations = 2;
        let token = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding max_invocations does not match aggregate budget",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_final_capability_signature_mutation() {
        let (issuer, mut token) = valid_root(3);
        token.id.push_str("-tampered");

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key()]).unwrap_err();
        assert_invalid_signature(error, "aggregate family root capability signature invalid");
    }

    #[test]
    fn aggregate_invocation_root_rejects_token_issuer_mutation() {
        let (issuer, token) = valid_root(3);
        let other = Keypair::from_seed(&[41_u8; 32]);
        let mut body = token.body();
        body.issuer = other.public_key();
        let token = resign_outer(body, &other);

        let error =
            verify_direct_aggregate_family_root(&token, &[issuer.public_key(), other.public_key()])
                .unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_binding_graft() {
        let issuer = fixed_issuer();
        let subject_a = fixed_subject();
        let subject_b = Keypair::from_seed(&[43_u8; 32]);
        let root_a = issue_aggregate_family_root(
            ordinary_root_body(&issuer.public_key(), &subject_a.public_key(), "cap-root-a"),
            3,
            &issuer,
        )
        .unwrap();
        let root_b = issue_aggregate_family_root(
            ordinary_root_body(&issuer.public_key(), &subject_b.public_key(), "cap-root-b"),
            3,
            &issuer,
        )
        .unwrap();
        let mut body = root_b.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .root_binding = Some(root_binding(&root_a).clone());
        let grafted = resign_outer(body, &issuer);

        let error =
            verify_direct_aggregate_family_root(&grafted, &[issuer.public_key()]).unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_capability_id does not match token id",
        );
    }

    #[test]
    fn aggregate_invocation_root_rejects_binding_from_mismatched_authority() {
        let issuer_a = fixed_issuer();
        let issuer_b = Keypair::from_seed(&[47_u8; 32]);
        let subject = fixed_subject();
        let root_a = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer_a.public_key(),
                &subject.public_key(),
                "cap-authority-a",
            ),
            3,
            &issuer_a,
        )
        .unwrap();
        let root_b = issue_aggregate_family_root(
            ordinary_root_body(
                &issuer_b.public_key(),
                &subject.public_key(),
                "cap-authority-b",
            ),
            3,
            &issuer_b,
        )
        .unwrap();
        let mut body = root_a.body();
        body.aggregate_invocation_budget
            .as_mut()
            .expect("aggregate budget")
            .root_binding = Some(root_binding(&root_b).clone());
        let grafted = resign_outer(body, &issuer_a);

        let error = verify_direct_aggregate_family_root(
            &grafted,
            &[issuer_a.public_key(), issuer_b.public_key()],
        )
        .unwrap_err();
        assert_attenuation_reason(
            error,
            "aggregate family root binding root_issuer does not match token issuer",
        );
    }
}
