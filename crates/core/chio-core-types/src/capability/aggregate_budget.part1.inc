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

    /// Validate the complete aggregate root binding carried by this budget.
    pub fn validate_root_binding(&self) -> Result<()> {
        match self.scope {
            AggregateInvocationScope::Capability => {
                if self.root_binding.is_some() {
                    return Err(Error::AttenuationViolation {
                        reason: "capability-scoped aggregate budget must not carry a root binding"
                            .to_string(),
                    });
                }
            }
            AggregateInvocationScope::DelegationFamily => {
                let binding =
                    self.root_binding
                        .as_ref()
                        .ok_or_else(|| Error::AttenuationViolation {
                            reason: "delegation-family aggregate budget requires a root binding"
                                .to_string(),
                        })?;
                binding.validate()?;
                if binding.body.max_invocations != self.max_invocations {
                    return Err(Error::AttenuationViolation {
                        reason: "aggregate family root maximum does not match aggregate budget"
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

/// Compact signed-link projection retained for compatibility with the
/// original aggregate budget enforcement path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetDelegationMarker {
    pub root_binding_digest: String,
    pub max_invocations: u32,
}

impl AggregateBudgetDelegationMarker {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_sha256_hex(
            &self.root_binding_digest,
            "aggregate budget root binding digest",
        )
    }
}

/// Signed projection proving preservation of aggregate family authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateFamilyPreservationEvidence {
    pub root_capability_id: String,
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
    /// Parse an exact canonical envelope and authenticate its root signature.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let binding: Self = serde_json::from_slice(bytes)?;
        if canonical_json_bytes(&binding)? != bytes {
            return Err(Error::CanonicalJson(
                "aggregate root binding bytes are not canonical".to_string(),
            ));
        }
        binding.validate()?;
        Ok(binding)
    }

    /// Validate the binding schema, digest fields, algorithm, and signature.
    pub fn validate(&self) -> Result<()> {
        if self.body.schema != CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA {
            return Err(Error::InvalidSignature(
                "aggregate family root binding schema mismatch".to_string(),
            ));
        }
        if self.body.root_capability_id.is_empty()
            || self.body.root_capability_id.len() > MAX_AGGREGATE_FAMILY_ROOT_ID_BYTES
        {
            return Err(Error::AttenuationViolation {
                reason: "aggregate root capability id must contain 1 to 512 bytes".to_string(),
            });
        }
        validate_sha256_hex(
            &self.body.root_capability_hash,
            "aggregate root capability hash",
        )?;
        validate_sha256_hex(&self.body.root_scope_hash, "aggregate root scope hash")?;
        ensure_algorithm_consistency(
            self.algorithm,
            &self.body.root_issuer,
            &self.signature,
            "aggregate family root binding algorithm does not match root issuer and signature",
        )?;
        if !self
            .body
            .root_issuer
            .verify(&self.body.signing_bytes()?, &self.signature)
        {
            return Err(Error::InvalidSignature(
                "aggregate family root binding signature invalid".to_string(),
            ));
        }
        Ok(())
    }

    /// Hash the complete binding envelope for preservation evidence.
    pub fn preservation_digest(&self) -> Result<String> {
        domain_separated_hash(CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN, self)
    }

    pub(crate) fn delegation_marker(&self) -> Result<AggregateBudgetDelegationMarker> {
        Ok(AggregateBudgetDelegationMarker {
            root_binding_digest: self.preservation_digest()?,
            max_invocations: self.body.max_invocations,
        })
    }
}

impl AggregateFamilyPreservationEvidence {
    /// Validate this projection against authenticated family authority.
    pub fn validate_against_verified_root(&self, root: &VerifiedAggregateFamilyRoot) -> Result<()> {
        validate_preservation_values(
            self,
            root.root_capability_id(),
            root.root_binding_digest(),
            root.max_invocations(),
        )
    }

    pub fn validate_against_budget(&self, budget: &AggregateInvocationBudget) -> Result<()> {
        budget.validate_root_binding()?;
        let binding = budget
            .root_binding
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "delegation-family aggregate budget is missing its root binding"
                    .to_string(),
            })?;
        let digest = binding.preservation_digest()?;
        validate_preservation_values(
            self,
            &binding.body.root_capability_id,
            &digest,
            budget.max_invocations,
        )
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!("{field} must be 64 lowercase hexadecimal characters"),
        });
    }
    Ok(())
}

fn validate_preservation_values(
    evidence: &AggregateFamilyPreservationEvidence,
    root_capability_id: &str,
    root_binding_digest: &str,
    max_invocations: u32,
) -> Result<()> {
    if evidence.root_capability_id != root_capability_id {
        return Err(Error::AttenuationViolation {
            reason: "aggregate family preservation root capability ID does not match the authenticated root"
                .to_string(),
        });
    }
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
            root_capability_id: self.root_capability_id().to_string(),
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
    let expected_issuer = body.issuer.clone();
    let expected_algorithm = expected_issuer.algorithm();

    let commitment = commitment_from_body(&body, max_invocations)?;
    let binding_body = binding_body_from_commitment(&commitment)?;
    let binding_signing_bytes = binding_body.signing_bytes()?;
    let outcome = backend.sign_bytes_for_identity(&expected_issuer, &binding_signing_bytes)?;
    let signature = outcome.signature;
    if outcome.algorithm != expected_algorithm || signature.algorithm() != expected_algorithm {
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
    let expected_marker = AggregateBudgetDelegationMarker {
        root_binding_digest: root.root_binding_digest().to_string(),
        max_invocations: root.max_invocations(),
    };
    if let Some(proof) = token.attenuation_proof.as_ref() {
        let evidence = proof
            .aggregate_family_preservation
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "attenuated delegation-family capability must preserve aggregate family evidence"
                    .to_string(),
            })?;
        evidence.validate_against_verified_root(root)?;
        if proof.normalized_subset_proof.aggregate_budget.as_ref() != Some(&expected_marker) {
            return Err(Error::AttenuationViolation {
                reason: "aggregate family attenuation witness changed or omitted the authenticated root binding marker"
                    .to_string(),
            });
        }
    }
    for link in &token.delegation_chain {
        let evidence = link
            .aggregate_family_preservation
            .as_ref()
            .ok_or_else(|| Error::AttenuationViolation {
                reason: "delegation-family capability link is missing aggregate family preservation evidence"
                    .to_string(),
            })?;
        evidence.validate_against_verified_root(root)?;
        if link.aggregate_budget.as_ref() != Some(&expected_marker) {
            return Err(Error::AttenuationViolation {
                reason: "aggregate family delegation link changed or omitted the authenticated root binding marker"
                    .to_string(),
            });
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
    if body.scope.has_cumulative_approval() {
        return Err(Error::AttenuationViolation {
            reason:
                "aggregate and cumulative approval family roots cannot be combined".to_string(),
        });
    }
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
