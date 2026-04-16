//! Capability tokens: Ed25519-signed, scoped, time-bounded authorizations.
//!
//! A ARC capability token is the sole authority to invoke a tool. There is no
//! ambient authority. The Kernel validates the token on every request and denies
//! access if any check fails.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use crate::error::{Error, Result};
use crate::runtime_attestation::{
    derive_runtime_attestation_trust_material, AttestationVerifierFamily,
    RuntimeAttestationTrustMaterial,
};
use crate::session::SessionAnchorReference;

/// A ARC capability token. Ed25519-signed, scoped, time-bounded.
///
/// The `signature` field covers the canonical JSON of all other fields.
/// Verification re-serializes the token (excluding the signature), computes
/// the canonical form, and checks the Ed25519 signature against `issuer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token ID (UUIDv7 recommended, used for revocation).
    pub id: String,
    /// Capability Authority (or delegating agent) that issued this token.
    pub issuer: PublicKey,
    /// Agent this capability is bound to (DPoP sender constraint).
    pub subject: PublicKey,
    /// What this token authorizes.
    pub scope: ArcScope,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// Ordered list of delegation links from the root CA to this token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
    /// Ed25519 signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a capability token, containing every field except the signature.
/// Used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenBody {
    pub id: String,
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub scope: ArcScope,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationLink>,
}

impl CapabilityToken {
    /// Extract the body (everything except the signature) for re-verification.
    #[must_use]
    pub fn body(&self) -> CapabilityTokenBody {
        CapabilityTokenBody {
            id: self.id.clone(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            scope: self.scope.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            delegation_chain: self.delegation_chain.clone(),
        }
    }

    /// Sign a capability token body with the given keypair.
    pub fn sign(body: CapabilityTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            issuer: body.issuer,
            subject: body.subject,
            scope: body.scope,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            delegation_chain: body.delegation_chain,
            signature,
        })
    }

    /// Verify the token's signature against its issuer key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.issuer.verify_canonical(&body, &self.signature)
    }

    /// Check whether this token is expired at the given unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check whether this token is valid at the given unix timestamp
    /// (issued_at <= now < expires_at).
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Validate time bounds, returning an error on failure.
    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

/// What a capability token authorizes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArcScope {
    /// Individual tool grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<ToolGrant>,

    /// Individual resource grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_grants: Vec<ResourceGrant>,

    /// Individual prompt grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_grants: Vec<PromptGrant>,
}

impl ArcScope {
    /// Returns true if `self` is a subset of `other` -- that is, every grant
    /// in `self` is covered by some grant in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &ArcScope) -> bool {
        self.grants.iter().all(|child_grant| {
            other
                .grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.resource_grants.iter().all(|child_grant| {
            other
                .resource_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        }) && self.prompt_grants.iter().all(|child_grant| {
            other
                .prompt_grants
                .iter()
                .any(|parent| child_grant.is_subset_of(parent))
        })
    }
}

/// A monetary amount with currency denomination.
///
/// Uses minor-unit integers to avoid floating-point precision issues.
/// For USD, 1 dollar = 100 units (cents). For JPY, 1 yen = 1 unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. cents for USD).
    pub units: u64,
    /// ISO 4217 currency code. Examples: "USD", "EUR", "JPY".
    pub currency: String,
}

/// Explicit operator-visible runtime assurance tier derived from attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAssuranceTier {
    #[default]
    None,
    Basic,
    Attested,
    Verified,
}

/// Explicit governed autonomy tier requested for one economically sensitive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedAutonomyTier {
    #[default]
    Direct,
    Delegated,
    Autonomous,
}

impl GovernedAutonomyTier {
    #[must_use]
    pub fn requires_delegation_bond(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn requires_call_chain(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn minimum_runtime_assurance(self) -> RuntimeAssuranceTier {
        match self {
            Self::Direct => RuntimeAssuranceTier::None,
            Self::Delegated => RuntimeAssuranceTier::Attested,
            Self::Autonomous => RuntimeAssuranceTier::Verified,
        }
    }
}

/// Normalized workload-identity scheme accepted by ARC runtime attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIdentityScheme {
    Spiffe,
}

/// Upstream credential family that bound the workload identity to attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCredentialKind {
    #[default]
    Uri,
    X509Svid,
    JwtSvid,
}

/// Normalized workload identity derived from runtime attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadIdentity {
    /// Identity scheme ARC recognized from the upstream evidence.
    pub scheme: WorkloadIdentityScheme,
    /// Credential family that authenticated the workload.
    pub credential_kind: WorkloadCredentialKind,
    /// Canonical workload identifier URI.
    pub uri: String,
    /// Stable trust domain resolved from the identifier.
    pub trust_domain: String,
    /// Canonical workload path within the trust domain.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadIdentityError {
    #[error("runtime_identity must not be empty when provided")]
    EmptyRuntimeIdentity,

    #[error("workload identity URI must not be empty")]
    EmptyUri,

    #[error("unsupported workload identity scheme '{0}'")]
    UnsupportedScheme(String),

    #[error("workload identity URI is malformed: {0}")]
    MalformedUri(String),

    #[error("SPIFFE workload identity must include a trust domain")]
    MissingTrustDomain,

    #[error("SPIFFE workload identity must not include userinfo or a port")]
    InvalidAuthority,

    #[error("SPIFFE workload identity must not include query or fragment")]
    InvalidSuffix,

    #[error("SPIFFE workload identity path '{0}' is invalid")]
    InvalidPath(String),

    #[error(
        "explicit workload identity conflicts with runtime_identity for {field}: expected '{expected}', got '{actual}'"
    )]
    Conflict {
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error(
        "runtime_identity '{0}' is opaque and cannot be reconciled with explicit workload_identity"
    )]
    OpaqueRuntimeIdentityConflict(String),
}

impl WorkloadIdentity {
    pub fn parse_spiffe_uri(uri: &str) -> std::result::Result<Self, WorkloadIdentityError> {
        Self::parse_spiffe_uri_with_kind(uri, WorkloadCredentialKind::Uri)
    }

    pub fn parse_spiffe_uri_with_kind(
        uri: &str,
        credential_kind: WorkloadCredentialKind,
    ) -> std::result::Result<Self, WorkloadIdentityError> {
        let trimmed = uri.trim();
        if trimmed.is_empty() {
            return Err(WorkloadIdentityError::EmptyUri);
        }

        let parsed = Url::parse(trimmed)
            .map_err(|_| WorkloadIdentityError::MalformedUri(trimmed.to_string()))?;
        if parsed.scheme() != "spiffe" {
            return Err(WorkloadIdentityError::UnsupportedScheme(
                parsed.scheme().to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() || parsed.port().is_some() {
            return Err(WorkloadIdentityError::InvalidAuthority);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(WorkloadIdentityError::InvalidSuffix);
        }

        let Some(trust_domain) = parsed.host_str() else {
            return Err(WorkloadIdentityError::MissingTrustDomain);
        };
        let path = parsed.path();
        if path.is_empty() || !path.starts_with('/') || path.contains("//") {
            return Err(WorkloadIdentityError::InvalidPath(path.to_string()));
        }

        Ok(Self {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind,
            uri: trimmed.to_string(),
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    pub fn validate(&self) -> std::result::Result<(), WorkloadIdentityError> {
        let parsed = match self.scheme {
            WorkloadIdentityScheme::Spiffe => {
                Self::parse_spiffe_uri_with_kind(&self.uri, self.credential_kind)?
            }
        };

        if self.trust_domain != parsed.trust_domain {
            return Err(WorkloadIdentityError::Conflict {
                field: "trust_domain",
                expected: parsed.trust_domain,
                actual: self.trust_domain.clone(),
            });
        }
        if self.path != parsed.path {
            return Err(WorkloadIdentityError::Conflict {
                field: "path",
                expected: parsed.path,
                actual: self.path.clone(),
            });
        }

        Ok(())
    }
}

/// Normalized runtime attestation evidence carried with governed requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAttestationEvidence {
    /// Schema or format identifier of the upstream attestation statement.
    pub schema: String,
    /// Attestation verifier or relying party that accepted the evidence.
    pub verifier: String,
    /// Normalized assurance tier resolved from the evidence.
    pub tier: RuntimeAssuranceTier,
    /// Unix timestamp (seconds) when this attestation was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this attestation expires.
    pub expires_at: u64,
    /// Stable SHA-256 digest of the attestation evidence payload.
    pub evidence_sha256: String,
    /// Optional runtime identity or workload identifier associated with the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_identity: Option<String>,
    /// Optional normalized workload identity when the upstream verifier exposed one explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    /// Optional structured claims preserved for adapters or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

impl RuntimeAttestationEvidence {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn normalized_workload_identity(
        &self,
    ) -> std::result::Result<Option<WorkloadIdentity>, WorkloadIdentityError> {
        let explicit = self
            .workload_identity
            .as_ref()
            .map(|identity| {
                identity.validate()?;
                Ok(identity.clone())
            })
            .transpose()?;
        let parsed_runtime_identity = match self.runtime_identity.as_deref() {
            Some(value) if value.trim().is_empty() => {
                return Err(WorkloadIdentityError::EmptyRuntimeIdentity);
            }
            Some(value) if value.trim_start().starts_with("spiffe://") => {
                Some(WorkloadIdentity::parse_spiffe_uri(value)?)
            }
            Some(_) => None,
            None => None,
        };

        match (explicit, parsed_runtime_identity) {
            (Some(explicit), Some(parsed)) => {
                if explicit.scheme != parsed.scheme {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "scheme",
                        expected: format!("{:?}", parsed.scheme).to_lowercase(),
                        actual: format!("{:?}", explicit.scheme).to_lowercase(),
                    });
                }
                if explicit.trust_domain != parsed.trust_domain {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "trust_domain",
                        expected: parsed.trust_domain,
                        actual: explicit.trust_domain,
                    });
                }
                if explicit.path != parsed.path {
                    return Err(WorkloadIdentityError::Conflict {
                        field: "path",
                        expected: parsed.path,
                        actual: explicit.path,
                    });
                }
                Ok(Some(explicit))
            }
            (Some(explicit), None) => {
                if let Some(runtime_identity) = self.runtime_identity.as_ref() {
                    return Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(
                        runtime_identity.clone(),
                    ));
                }
                Ok(Some(explicit))
            }
            (None, Some(parsed)) => Ok(Some(parsed)),
            (None, None) => Ok(None),
        }
    }

    pub fn validate_workload_identity_binding(
        &self,
    ) -> std::result::Result<(), WorkloadIdentityError> {
        self.normalized_workload_identity().map(|_| ())
    }

    pub fn resolve_effective_runtime_assurance(
        &self,
        policy: Option<&AttestationTrustPolicy>,
        now: u64,
    ) -> std::result::Result<ResolvedRuntimeAssurance, AttestationTrustError> {
        self.validate_workload_identity_binding()
            .map_err(|error| AttestationTrustError::InvalidWorkloadIdentity(error.to_string()))?;
        if !self.is_valid_at(now) {
            return Err(AttestationTrustError::StaleEvidence {
                now,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }

        let raw_tier = self.tier;
        let Some(policy) = policy else {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        };
        if policy.rules.is_empty() {
            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: raw_tier,
                matched_rule: None,
            });
        }
        let trust_material = derive_runtime_attestation_trust_material(self).map_err(|_| {
            AttestationTrustError::UnsupportedEvidence {
                schema: self.schema.clone(),
            }
        })?;

        for rule in &policy.rules {
            if !rule.matches(self, &trust_material) {
                continue;
            }
            if let Some(max_age_seconds) = rule.max_evidence_age_seconds {
                let age = now.saturating_sub(self.issued_at);
                if age > max_age_seconds {
                    return Err(AttestationTrustError::EvidenceTooOld {
                        rule: rule.name.clone(),
                        max_age_seconds,
                        actual_age_seconds: age,
                    });
                }
            }
            if !rule.allowed_attestation_types.is_empty() {
                let actual = trust_material
                    .normalized_assertions
                    .get("attestationType")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| AttestationTrustError::MissingAttestationType {
                        rule: rule.name.clone(),
                    })?;
                if !rule
                    .allowed_attestation_types
                    .iter()
                    .any(|allowed| allowed == actual)
                {
                    return Err(AttestationTrustError::DisallowedAttestationType {
                        rule: rule.name.clone(),
                        actual: actual.to_string(),
                    });
                }
            }
            for (assertion, expected) in &rule.required_assertions {
                let actual = trust_material
                    .normalized_assertions
                    .get(assertion)
                    .ok_or_else(|| AttestationTrustError::MissingAssertion {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                    })?;
                let actual = normalized_assertion_string(actual).ok_or_else(|| {
                    AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual: actual.to_string(),
                    }
                })?;
                if actual != *expected {
                    return Err(AttestationTrustError::AssertionMismatch {
                        rule: rule.name.clone(),
                        assertion: assertion.clone(),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }

            return Ok(ResolvedRuntimeAssurance {
                raw_tier,
                effective_tier: rule.effective_tier,
                matched_rule: Some(rule.name.clone()),
            });
        }

        Err(AttestationTrustError::UntrustedEvidence {
            verifier: self.verifier.clone(),
            schema: self.schema.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustPolicy {
    #[serde(default)]
    pub rules: Vec<AttestationTrustRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationTrustRule {
    pub name: String,
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_assertions: BTreeMap<String, String>,
}

impl AttestationTrustRule {
    fn matches(
        &self,
        attestation: &RuntimeAttestationEvidence,
        trust_material: &RuntimeAttestationTrustMaterial,
    ) -> bool {
        self.schema == attestation.schema
            && canonicalize_attestation_verifier(&self.verifier)
                == canonicalize_attestation_verifier(&attestation.verifier)
            && self
                .verifier_family
                .is_none_or(|family| family == trust_material.verifier_family)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRuntimeAssurance {
    pub raw_tier: RuntimeAssuranceTier,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationTrustError {
    #[error("runtime attestation workload identity is invalid: {0}")]
    InvalidWorkloadIdentity(String),

    #[error(
        "runtime attestation evidence is stale at {now} (issued_at={issued_at}, expires_at={expires_at})"
    )]
    StaleEvidence {
        now: u64,
        issued_at: u64,
        expires_at: u64,
    },

    #[error(
        "attestation trust rule `{rule}` rejected evidence older than {max_age_seconds}s (actual age {actual_age_seconds}s)"
    )]
    EvidenceTooOld {
        rule: String,
        max_age_seconds: u64,
        actual_age_seconds: u64,
    },

    #[error("attestation trust rule `{rule}` requires an attestationType claim")]
    MissingAttestationType { rule: String },

    #[error("attestation trust rule `{rule}` rejected attestation type `{actual}`")]
    DisallowedAttestationType { rule: String, actual: String },

    #[error(
        "runtime attestation schema `{schema}` is not supported by the appraisal-aware trust boundary"
    )]
    UnsupportedEvidence { schema: String },

    #[error("attestation trust rule `{rule}` requires normalized assertion `{assertion}`")]
    MissingAssertion { rule: String, assertion: String },

    #[error(
        "attestation trust rule `{rule}` rejected normalized assertion `{assertion}`: expected `{expected}`, got `{actual}`"
    )]
    AssertionMismatch {
        rule: String,
        assertion: String,
        expected: String,
        actual: String,
    },

    #[error(
        "runtime attestation evidence from verifier `{verifier}` with schema `{schema}` did not match any trusted verifier rule"
    )]
    UntrustedEvidence { verifier: String, schema: String },
}

fn normalized_assertion_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(if *value {
            "true".to_string()
        } else {
            "false".to_string()
        }),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

pub fn canonicalize_attestation_verifier(value: &str) -> String {
    let trimmed = value.trim();
    match Url::parse(trimmed) {
        Ok(url) => url.to_string().trim_end_matches('/').to_string(),
        Err(_) => trimmed.trim_end_matches('/').to_string(),
    }
}

/// Policy-visible settlement posture for quoted metered billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeteredSettlementMode {
    /// The action should not execute unless the quoted amount is prepaid.
    MustPrepay,
    /// The action may execute against a hold and settle later via capture/release.
    HoldCapture,
    /// The action may execute first and settle later with truthful pending state.
    AllowThenSettle,
}

/// Stable quote describing pre-execution metered billing expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingQuote {
    /// Stable quote identifier from the billing or metering authority.
    pub quote_id: String,
    /// Billing or metering provider that issued the quote.
    pub provider: String,
    /// Billing unit used to interpret `quoted_units` (for example `1k_tokens`).
    pub billing_unit: String,
    /// Quoted number of billable units for the pre-execution estimate.
    pub quoted_units: u64,
    /// Quoted monetary amount for the estimate.
    pub quoted_cost: MonetaryAmount,
    /// Unix timestamp (seconds) when the quote was issued.
    pub issued_at: u64,
    /// Optional Unix timestamp (seconds) when the quote expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MeteredBillingQuote {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// Generic metered-billing context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingContext {
    /// Settlement posture expected for this metered tool action.
    pub settlement_mode: MeteredSettlementMode,
    /// Pre-execution quote bound to the governed request.
    pub quote: MeteredBillingQuote,
    /// Optional explicit upper bound on billable units for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
}

/// Delegated call-chain context bound into a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainContext {
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
}

/// Reserved key inside `GovernedTransactionIntent.context` for legacy upstream call-chain proofs.
pub const GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: &str = "callChainUpstreamProof";

/// Signable upstream proof for delegated governed call-chain provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProofBody {
    /// Public key that authenticated the upstream delegated handoff.
    pub signer: PublicKey,
    /// Capability subject key this handoff was issued to.
    pub subject: PublicKey,
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
    /// Unix timestamp (seconds) when this proof was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this proof expires.
    pub expires_at: u64,
}

/// Signed upstream proof ARC can validate and promote to verified provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProof {
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    pub origin_subject: String,
    pub delegator_subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

impl GovernedUpstreamCallChainProof {
    #[must_use]
    pub fn body(&self) -> GovernedUpstreamCallChainProofBody {
        GovernedUpstreamCallChainProofBody {
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            origin_subject: self.origin_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: GovernedUpstreamCallChainProofBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            origin_subject: body.origin_subject,
            delegator_subject: body.delegator_subject,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }
}

/// Reserved key inside `GovernedTransactionIntent.context` for continuation tokens.
pub const GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: &str = "callChainContinuation";
/// Versioned schema identifier for continuation tokens.
pub const ARC_CALL_CHAIN_CONTINUATION_SCHEMA: &str = "arc.call_chain_continuation.v1";

/// Audience binding for a continuation token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationAudience {
    pub server_id: String,
    pub tool_name: String,
}

/// Stronger cross-kernel continuation artifact for governed provenance transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationTokenBody {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Signed continuation token used to move governed provenance across kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationToken {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_upstream_proof: Option<GovernedUpstreamCallChainProof>,
    pub signature: Signature,
}

impl CallChainContinuationToken {
    #[must_use]
    pub fn body(&self) -> CallChainContinuationTokenBody {
        CallChainContinuationTokenBody {
            schema: self.schema.clone(),
            token_id: self.token_id.clone(),
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            parent_receipt_hash: self.parent_receipt_hash.clone(),
            parent_session_anchor: self.parent_session_anchor.clone(),
            current_subject: self.current_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            origin_subject: self.origin_subject.clone(),
            parent_capability_id: self.parent_capability_id.clone(),
            delegation_link_hash: self.delegation_link_hash.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            audience: self.audience.clone(),
            nonce: self.nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: CallChainContinuationTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            schema: body.schema,
            token_id: body.token_id,
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            parent_receipt_hash: body.parent_receipt_hash,
            parent_session_anchor: body.parent_session_anchor,
            current_subject: body.current_subject,
            delegator_subject: body.delegator_subject,
            origin_subject: body.origin_subject,
            parent_capability_id: body.parent_capability_id,
            delegation_link_hash: body.delegation_link_hash,
            governed_intent_hash: body.governed_intent_hash,
            audience: body.audience,
            nonce: body.nonce,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            legacy_upstream_proof: None,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        if let Some(legacy_upstream_proof) = &self.legacy_upstream_proof {
            return Ok(legacy_upstream_proof.verify_signature()?
                && legacy_upstream_proof.chain_id == self.chain_id
                && legacy_upstream_proof.parent_request_id == self.parent_request_id
                && legacy_upstream_proof.parent_receipt_id == self.parent_receipt_id
                && legacy_upstream_proof.origin_subject == self.origin_subject
                && legacy_upstream_proof.delegator_subject == self.delegator_subject
                && legacy_upstream_proof.signer == self.signer
                && legacy_upstream_proof.subject == self.subject
                && legacy_upstream_proof.issued_at == self.issued_at
                && legacy_upstream_proof.expires_at == self.expires_at);
        }
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }

    #[must_use]
    pub fn matches_session_anchor(&self, session_anchor: &SessionAnchorReference) -> bool {
        self.parent_session_anchor.as_ref() == Some(session_anchor)
    }

    #[must_use]
    pub fn matches_target(&self, server_id: &str, tool_name: &str) -> bool {
        self.audience.as_ref().is_some_and(|audience| {
            audience.server_id == server_id && audience.tool_name == tool_name
        })
    }

    #[must_use]
    pub fn matches_intent_hash(&self, intent_hash: &str) -> bool {
        self.governed_intent_hash.as_deref() == Some(intent_hash)
    }

    #[must_use]
    pub fn matches_subject(&self, subject: &PublicKey) -> bool {
        &self.subject == subject
    }

    pub fn from_legacy_upstream_proof(proof: &GovernedUpstreamCallChainProof) -> Result<Self> {
        let proof_body = proof.body();
        let canonical = canonical_json_bytes(&proof_body)?;
        Ok(Self {
            schema: ARC_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: format!("legacy:{}", sha256_hex(&canonical)),
            signer: proof.signer.clone(),
            subject: proof.subject.clone(),
            chain_id: proof.chain_id.clone(),
            parent_request_id: proof.parent_request_id.clone(),
            parent_receipt_id: proof.parent_receipt_id.clone(),
            parent_receipt_hash: None,
            parent_session_anchor: None,
            current_subject: proof.subject.to_hex(),
            delegator_subject: proof.delegator_subject.clone(),
            origin_subject: proof.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: None,
            audience: None,
            nonce: None,
            issued_at: proof.issued_at,
            expires_at: proof.expires_at,
            legacy_upstream_proof: Some(proof.clone()),
            signature: proof.signature.clone(),
        })
    }
}

/// Evidence class describing how ARC learned or validated provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProvenanceEvidenceClass {
    /// Caller-asserted provenance bound into the request, but not independently checked yet.
    #[default]
    Asserted,
    /// Provenance observed by ARC or a trusted subsystem, but not fully verified end-to-end.
    Observed,
    /// Provenance verified against authoritative evidence such as receipt linkage or signatures.
    Verified,
}

/// Generic evidence class used across ARC provenance artifacts.
pub type ProvenanceEvidenceClass = GovernedProvenanceEvidenceClass;

/// Authoritative local evidence ARC used to corroborate governed call-chain metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedCallChainEvidenceSource {
    /// The call-chain parent request matched an authenticated parent request in the live session.
    SessionParentRequestLineage,
    /// The optional parent receipt identifier matched a receipt ARC already recorded locally.
    LocalParentReceiptLinkage,
    /// The asserted delegator subject matched the validated capability delegation source.
    CapabilityDelegatorSubject,
    /// The asserted origin subject matched the root delegator visible in capability lineage.
    CapabilityOriginSubject,
    /// ARC validated a signed upstream handoff against the capability's delegator key.
    UpstreamDelegatorProof,
}

/// Typed provenance envelope for delegated governed call-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainProvenance {
    /// Evidence class describing how strongly ARC should treat this provenance.
    #[serde(default)]
    pub evidence_class: GovernedProvenanceEvidenceClass,
    /// Specific authoritative local evidence ARC used when it upgraded the caller assertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<GovernedCallChainEvidenceSource>,
    /// Optional signed upstream proof ARC validated before upgrading to verified provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_proof: Option<GovernedUpstreamCallChainProof>,
    /// Optional preserved caller assertion when ARC upgraded or rewrote the effective context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_context: Option<GovernedCallChainContext>,
    /// Optional continuation token identifier that backed a verified upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    /// Optional session-anchor identifier that scoped the verified lineage edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    /// Optional receipt-lineage statement identifier that authenticated the receipt edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_lineage_statement_id: Option<String>,
    /// The delegated call-chain details carried with the governed request or receipt.
    #[serde(flatten)]
    pub context: GovernedCallChainContext,
}

impl GovernedCallChainProvenance {
    #[must_use]
    pub fn new(
        context: GovernedCallChainContext,
        evidence_class: GovernedProvenanceEvidenceClass,
    ) -> Self {
        Self {
            evidence_class,
            evidence_sources: Vec::new(),
            upstream_proof: None,
            asserted_context: None,
            continuation_token_id: None,
            session_anchor_id: None,
            receipt_lineage_statement_id: None,
            context,
        }
    }

    #[must_use]
    pub fn with_evidence_sources(
        mut self,
        evidence_sources: impl IntoIterator<Item = GovernedCallChainEvidenceSource>,
    ) -> Self {
        self.evidence_sources = evidence_sources.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_upstream_proof(mut self, upstream_proof: GovernedUpstreamCallChainProof) -> Self {
        self.upstream_proof = Some(upstream_proof);
        self
    }

    #[must_use]
    pub fn with_asserted_context(mut self, asserted_context: GovernedCallChainContext) -> Self {
        self.asserted_context = Some(asserted_context);
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }

    #[must_use]
    pub fn with_session_anchor_id(mut self, session_anchor_id: impl Into<String>) -> Self {
        self.session_anchor_id = Some(session_anchor_id.into());
        self
    }

    #[must_use]
    pub fn with_receipt_lineage_statement_id(
        mut self,
        receipt_lineage_statement_id: impl Into<String>,
    ) -> Self {
        self.receipt_lineage_statement_id = Some(receipt_lineage_statement_id.into());
        self
    }

    #[must_use]
    pub fn asserted(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Asserted)
    }

    #[must_use]
    pub fn observed(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Observed)
    }

    #[must_use]
    pub fn verified(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Verified)
    }

    #[must_use]
    pub fn is_asserted(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        )
    }

    #[must_use]
    pub fn is_observed(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Observed
        )
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Verified
        )
    }

    #[must_use]
    pub fn as_context(&self) -> &GovernedCallChainContext {
        &self.context
    }

    #[must_use]
    pub fn asserted_context(&self) -> Option<&GovernedCallChainContext> {
        self.asserted_context
            .as_ref()
            .or_else(|| self.is_asserted().then_some(&self.context))
    }

    #[must_use]
    pub fn verified_context(&self) -> Option<&GovernedCallChainContext> {
        self.is_verified().then_some(&self.context)
    }

    #[must_use]
    pub fn into_inner(self) -> GovernedCallChainContext {
        self.context
    }
}

impl From<GovernedCallChainContext> for GovernedCallChainProvenance {
    fn from(context: GovernedCallChainContext) -> Self {
        Self::asserted(context)
    }
}

impl std::ops::Deref for GovernedCallChainProvenance {
    type Target = GovernedCallChainContext;

    fn deref(&self) -> &Self::Target {
        self.as_context()
    }
}

/// Explicit autonomy and delegation-bond context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAutonomyContext {
    /// Requested autonomy tier for this one governed action.
    pub tier: GovernedAutonomyTier,
    /// Optional signed delegation-bond artifact that backs higher-risk execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_bond_id: Option<String>,
}

/// Canonical intent attached to a governed transaction request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernedTransactionIntent {
    /// Unique intent identifier (UUIDv7 recommended).
    pub id: String,
    /// Target tool server for this governed action.
    pub server_id: String,
    /// Target tool name for this governed action.
    pub tool_name: String,
    /// Human or policy-readable purpose for the governed action.
    pub purpose: String,
    /// Optional maximum amount explicitly approved for this intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    /// Optional commerce approval context for seller-scoped payment rails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedCommerceContext>,
    /// Optional metered-billing quote and settlement context for non-rail tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<MeteredBillingContext>,
    /// Optional runtime attestation evidence bound to this governed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<RuntimeAttestationEvidence>,
    /// Optional delegated call-chain context for upstream transaction provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainContext>,
    /// Optional explicit autonomy tier and delegation-bond attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy: Option<GovernedAutonomyContext>,
    /// Optional structured context for downstream policy or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl GovernedTransactionIntent {
    /// Compute a stable canonical hash for approval-token binding and receipts.
    pub fn binding_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    /// Extract the reserved upstream call-chain proof from the optional context object.
    pub fn upstream_call_chain_proof(&self) -> Result<Option<GovernedUpstreamCallChainProof>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };
        let Some(value) = object.get(GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract an explicitly attached continuation token without legacy fallback.
    pub fn explicit_continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };

        let Some(value) = object.get(GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract the stronger continuation token, falling back to the legacy upstream proof key.
    pub fn continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        if let Some(token) = self.explicit_continuation_token()? {
            return Ok(Some(token));
        }

        self.upstream_call_chain_proof()?
            .as_ref()
            .map(CallChainContinuationToken::from_legacy_upstream_proof)
            .transpose()
    }
}

/// Seller-scoped commerce approval context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedCommerceContext {
    /// Seller or payee identifier that the approval is bound to.
    pub seller: String,
    /// Shared payment token or equivalent external commerce approval reference.
    pub shared_payment_token_id: String,
}

/// Decision encoded by a governed approval token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedApprovalDecision {
    Approved,
    Denied,
}

/// Signable body of a governed approval token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalTokenBody {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
}

/// Signed approval artifact bound to one governed intent and one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
    pub signature: Signature,
}

impl GovernedApprovalToken {
    #[must_use]
    pub fn body(&self) -> GovernedApprovalTokenBody {
        GovernedApprovalTokenBody {
            id: self.id.clone(),
            approver: self.approver.clone(),
            subject: self.subject.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            request_id: self.request_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            decision: self.decision,
        }
    }

    pub fn sign(body: GovernedApprovalTokenBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.approver.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

/// Authorization for a single tool on a single server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolGrant {
    /// Which tool server (by server_id from the manifest).
    pub server_id: String,
    /// Which tool on that server.
    pub tool_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
    /// Parameter constraints that narrow the tool's input space.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    /// Maximum number of invocations allowed under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    /// Maximum monetary cost per single invocation under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    /// Maximum aggregate monetary cost across all invocations under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    /// If Some(true), the kernel requires a valid DPoP proof for every invocation.
    /// None and Some(false) both mean DPoP is not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_required: Option<bool>,
}

impl ToolGrant {
    /// Returns true if `self` is a subset of `parent`.
    ///
    /// A child grant is a subset when:
    /// - It targets the same server and tool, unless the parent uses `*`.
    /// - Its operations are a subset of the parent's.
    /// - Its max_invocations is no greater than the parent's (if set).
    /// - Its constraints are at least as restrictive (superset of constraints).
    #[must_use]
    pub fn is_subset_of(&self, parent: &ToolGrant) -> bool {
        // Must target the same server + tool (or parent grants all via "*")
        if parent.server_id != "*" && self.server_id != parent.server_id {
            return false;
        }
        if parent.tool_name != "*" && self.tool_name != parent.tool_name {
            return false;
        }

        // Child operations must be a subset of parent operations
        let ops_ok = self
            .operations
            .iter()
            .all(|op| parent.operations.contains(op));
        if !ops_ok {
            return false;
        }

        // If parent has an invocation cap, child must too and it must be <= parent
        if let Some(parent_max) = parent.max_invocations {
            match self.max_invocations {
                Some(child_max) if child_max <= parent_max => {}
                None => return false, // child is uncapped but parent is capped
                Some(_) => return false, // child exceeds parent
            }
        }

        // Child must have at least as many constraints (more restrictive).
        // Each parent constraint must appear in the child's constraint list.
        let constraints_ok = parent
            .constraints
            .iter()
            .all(|pc| self.constraints.contains(pc));
        if !constraints_ok {
            return false;
        }

        // If parent has a per-invocation cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_cost_per_invocation {
            match &self.max_cost_per_invocation {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent has a total cost cap, child must too and it must be <=
        if let Some(ref parent_cost) = parent.max_total_cost {
            match &self.max_total_cost {
                Some(child_cost)
                    if child_cost.currency == parent_cost.currency
                        && child_cost.units <= parent_cost.units => {}
                _ => return false,
            }
        }

        // If parent requires DPoP, child must also require DPoP.
        // If parent does not require DPoP (None or Some(false)), child may do anything.
        if parent.dpop_required == Some(true) && self.dpop_required != Some(true) {
            return false;
        }

        true
    }
}

/// Authorization for reading or subscribing to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGrant {
    /// URI pattern identifying which resources are in scope.
    pub uri_pattern: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl ResourceGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &ResourceGrant) -> bool {
        pattern_covers(&parent.uri_pattern, &self.uri_pattern)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

/// Authorization for retrieving a prompt by name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGrant {
    /// Prompt name pattern.
    pub prompt_name: String,
    /// Allowed operations.
    pub operations: Vec<Operation>,
}

impl PromptGrant {
    #[must_use]
    pub fn is_subset_of(&self, parent: &PromptGrant) -> bool {
        pattern_covers(&parent.prompt_name, &self.prompt_name)
            && self
                .operations
                .iter()
                .all(|operation| parent.operations.contains(operation))
    }
}

fn pattern_covers(parent: &str, child: &str) -> bool {
    if parent == "*" {
        return true;
    }

    if let Some(prefix) = parent.strip_suffix('*') {
        return child.starts_with(prefix);
    }

    parent == child
}

/// An operation that can be performed under a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Invoke the tool (execute it).
    Invoke,
    /// Read the result of a previous invocation.
    ReadResult,
    /// Read a resource.
    Read,
    /// Subscribe to resource updates.
    Subscribe,
    /// Retrieve a prompt.
    Get,
    /// Delegate this grant to another agent.
    Delegate,
}

/// Operation class for data-layer tool calls (SQL, document DB, etc.).
///
/// Used by `Constraint::OperationClass` to restrict a grant to read-only,
/// read-write, or administrative operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOperationClass {
    /// SELECT and other read-only statements only.
    ReadOnly,
    /// Read and write (INSERT, UPDATE, DELETE) but no schema changes.
    ReadWrite,
    /// Schema-altering or privilege-altering operations.
    Admin,
}

/// Content review tier for outbound communication constraints.
///
/// Used by `Constraint::ContentReviewTier` to indicate the level of
/// content review that downstream guards should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentReviewTier {
    /// No content review required.
    None,
    /// Basic heuristic review (e.g. keyword filters).
    Basic,
    /// Strict review (e.g. model-based review or human approval).
    Strict,
}

/// Safety tier for model-routing constraints.
///
/// Used by `Constraint::ModelConstraint` to express a minimum safety
/// floor for the model executing a tool-bearing agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSafetyTier {
    /// Low assurance: unfiltered or permissive models.
    Low,
    /// Standard assurance: baseline safety filters.
    Standard,
    /// High assurance: stricter safety filters and evaluations.
    High,
    /// Restricted: only models meeting restricted-use criteria.
    Restricted,
}

/// A constraint on tool parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Constraint {
    /// File path parameter must start with this prefix.
    PathPrefix(String),
    /// Network domain must match exactly.
    DomainExact(String),
    /// Network domain must match a glob pattern.
    DomainGlob(String),
    /// Parameter must match a regular expression.
    RegexMatch(String),
    /// String parameter must not exceed this length.
    MaxLength(usize),
    /// Requests must carry a governed transaction intent.
    GovernedIntentRequired,
    /// Requests at or above this threshold require a valid approval token.
    RequireApprovalAbove { threshold_units: u64 },
    /// Requests must carry commerce approval context for this exact seller.
    SellerExact(String),
    /// Governed requests must carry valid runtime attestation at or above this tier.
    MinimumRuntimeAssurance(RuntimeAssuranceTier),
    /// Governed requests at or above this autonomy tier must carry autonomy context and pass bond gating.
    MinimumAutonomyTier(GovernedAutonomyTier),
    /// Extensibility: arbitrary key-value constraint.
    Custom(String, String),

    // ---- Phase 2.2 additions -----------------------------------------
    //
    // The variants below were added per docs/protocols/ADR-TYPE-EVOLUTION.md
    // section 3 to carry data-layer, communication, financial,
    // model-routing, and memory-governance policy. They participate in
    // the existing tagged serde envelope
    // (`#[serde(tag = "type", content = "value", rename_all = "snake_case")]`).

    /// Data layer: database tables the grant may reference.
    ///
    /// Evaluated against parsed SQL by `arc-data-guards`; the kernel
    /// records the constraint and leaves enforcement to that guard.
    TableAllowlist(Vec<String>),
    /// Data layer: forbidden columns, formatted as `"table.column"`.
    ///
    /// Evaluated by `arc-data-guards`; kernel treats it as an advisory
    /// constraint and does not reject at the request-matching stage.
    ColumnDenylist(Vec<String>),
    /// Data layer: maximum number of rows a query may return.
    ///
    /// Enforced post-invocation by downstream result-shaping guards.
    MaxRowsReturned(u64),
    /// Data layer: operation class the grant authorises.
    OperationClass(SqlOperationClass),
    /// Communication: allowed recipient channels or IDs.
    AudienceAllowlist(Vec<String>),
    /// Communication: content review tier demanded of downstream guards.
    ContentReviewTier(ContentReviewTier),
    /// Financial: maximum transaction amount in USD.
    ///
    /// The value is a decimal string (e.g. `"100.00"`) because
    /// `rust_decimal` is not in the workspace.
    MaxTransactionAmountUsd(String),
    /// Financial: whether the grant requires dual approval before execution.
    RequireDualApproval(bool),
    /// Model routing: constrain the models this grant may execute under.
    ModelConstraint {
        /// Explicit allowlist of model identifiers. Empty means no allowlist.
        allowed_model_ids: Vec<String>,
        /// Minimum acceptable model safety tier, if any.
        min_safety_tier: Option<ModelSafetyTier>,
    },
    /// Memory governance: memory stores the grant may write to.
    MemoryStoreAllowlist(Vec<String>),
    /// Memory governance: regex patterns that block writes.
    ///
    /// Patterns are compiled lazily during kernel evaluation so invalid
    /// regexes do not break construction or round-trip serialization.
    MemoryWriteDenyPatterns(Vec<String>),
}

/// A link in the delegation chain, recording that `delegator` granted a
/// narrowed capability to `delegatee`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Capability ID of the ancestor token delegated at this step.
    pub capability_id: String,
    /// Public key of the agent that delegated.
    pub delegator: PublicKey,
    /// Public key of the agent that received the delegation.
    pub delegatee: PublicKey,
    /// How the scope was narrowed in this delegation step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    /// Unix timestamp of the delegation.
    pub timestamp: u64,
    /// Ed25519 signature by the delegator over the canonical form of the
    /// other fields in this link.
    pub signature: Signature,
}

/// The body of a delegation link, used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLinkBody {
    pub capability_id: String,
    pub delegator: PublicKey,
    pub delegatee: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    pub timestamp: u64,
}

impl DelegationLink {
    /// Sign a delegation link body.
    pub fn sign(body: DelegationLinkBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            capability_id: body.capability_id,
            delegator: body.delegator,
            delegatee: body.delegatee,
            attenuations: body.attenuations,
            timestamp: body.timestamp,
            signature,
        })
    }

    /// Extract the signable body.
    #[must_use]
    pub fn body(&self) -> DelegationLinkBody {
        DelegationLinkBody {
            capability_id: self.capability_id.clone(),
            delegator: self.delegator.clone(),
            delegatee: self.delegatee.clone(),
            attenuations: self.attenuations.clone(),
            timestamp: self.timestamp,
        }
    }

    /// Verify this link's signature against the delegator's key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.delegator.verify_canonical(&body, &self.signature)
    }
}

/// Describes how a scope was narrowed during delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attenuation {
    /// A tool was removed from the scope.
    RemoveTool {
        server_id: String,
        tool_name: String,
    },
    /// An operation was removed from a tool grant.
    RemoveOperation {
        server_id: String,
        tool_name: String,
        operation: Operation,
    },
    /// A constraint was added to a tool grant.
    AddConstraint {
        server_id: String,
        tool_name: String,
        constraint: Constraint,
    },
    /// The invocation budget was reduced.
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    /// The expiration was shortened.
    ShortenExpiry { new_expires_at: u64 },
    /// The per-invocation cost cap was tightened during delegation.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },
    /// The total cost budget was reduced during delegation.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}

/// Validate an entire delegation chain.
///
/// Checks that:
/// 1. Each link's signature is valid.
/// 2. Adjacent links are connected (link[i].delegatee == link[i+1].delegator).
/// 3. Timestamps are non-decreasing.
/// 4. The chain length does not exceed `max_depth` (if provided).
pub fn validate_delegation_chain(chain: &[DelegationLink], max_depth: Option<u32>) -> Result<()> {
    if let Some(max) = max_depth {
        let len = u32::try_from(chain.len()).unwrap_or(u32::MAX);
        if len > max {
            return Err(Error::DelegationDepthExceeded { depth: len, max });
        }
    }

    for (i, link) in chain.iter().enumerate() {
        let sig_valid = link.verify_signature()?;
        if !sig_valid {
            return Err(Error::DelegationChainBroken {
                reason: format!("signature invalid at link index {i}"),
            });
        }

        if i > 0 {
            let prev = &chain[i - 1];
            if prev.delegatee != link.delegator {
                return Err(Error::DelegationChainBroken {
                    reason: format!("link {i} delegator does not match link {} delegatee", i - 1),
                });
            }
            if link.timestamp < prev.timestamp {
                return Err(Error::DelegationChainBroken {
                    reason: format!(
                        "link {i} timestamp ({}) precedes link {} timestamp ({})",
                        link.timestamp,
                        i - 1,
                        prev.timestamp
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Validate that a child scope is a valid attenuation of a parent scope.
///
/// Returns Ok(()) if child is a subset of parent. Returns an error otherwise.
pub fn validate_attenuation(parent: &ArcScope, child: &ArcScope) -> Result<()> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(Error::AttenuationViolation {
            reason: "child scope is not a subset of parent scope".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_grant(server: &str, tool: &str, ops: Vec<Operation>) -> ToolGrant {
        ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: ops,
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }
    }

    fn make_scope(grants: Vec<ToolGrant>) -> ArcScope {
        ArcScope {
            grants,
            ..ArcScope::default()
        }
    }

    #[test]
    fn capability_token_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-001".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "file_read",
                vec![Operation::Invoke],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&token).unwrap();
        let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token.id, restored.id);
        assert_eq!(token.issuer, restored.issuer);
        assert_eq!(token.subject, restored.subject);
        assert_eq!(token.issued_at, restored.issued_at);
        assert_eq!(token.expires_at, restored.expires_at);
        assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn capability_token_signature_verification() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-002".to_string(),
            issuer: kp.public_key(),
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![make_grant(
                "srv-a",
                "shell_exec",
                vec![Operation::Invoke, Operation::ReadResult],
            )]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        assert!(token.verify_signature().unwrap());
    }

    #[test]
    fn wrong_key_signature_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-003".to_string(),
            issuer: other_kp.public_key(), // issuer != signer
            subject: Keypair::generate().public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();
        // Signature was made by kp but issuer is other_kp, so it should fail.
        assert!(!token.verify_signature().unwrap());
    }

    #[test]
    fn time_validation() {
        let kp = Keypair::generate();
        let body = CapabilityTokenBody {
            id: "cap-time".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: make_scope(vec![]),
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
        };
        let token = CapabilityToken::sign(body, &kp).unwrap();

        assert!(token.is_valid_at(1000));
        assert!(token.is_valid_at(1500));
        assert!(token.is_valid_at(1999));
        assert!(!token.is_valid_at(999)); // before issued_at
        assert!(!token.is_valid_at(2000)); // at expires_at (exclusive)
        assert!(!token.is_valid_at(3000)); // after expires_at

        assert!(token.is_expired_at(2000));
        assert!(token.is_expired_at(3000));
        assert!(!token.is_expired_at(1999));

        assert!(token.validate_time(1500).is_ok());
        assert!(token.validate_time(999).is_err());
        assert!(token.validate_time(2000).is_err());
    }

    #[test]
    fn scope_subset_same() {
        let scope = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(scope.is_subset_of(&scope));
    }

    #[test]
    fn scope_subset_fewer_grants() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_subset_fewer_operations() {
        let parent = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::ReadResult],
        )]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&child));
    }

    #[test]
    fn scope_not_subset_different_server() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("b", "t1", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_not_subset_different_tool() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t2", vec![Operation::Invoke])]);
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn scope_subset_wildcard_tool() {
        let parent = make_scope(vec![make_grant("a", "*", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_invocation_budget() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_ok = ToolGrant {
            max_invocations: Some(5),
            ..parent.clone()
        };
        let child_exceed = ToolGrant {
            max_invocations: Some(20),
            ..parent.clone()
        };
        let child_none = ToolGrant {
            max_invocations: None,
            ..parent.clone()
        };

        assert!(child_ok.is_subset_of(&parent));
        assert!(!child_exceed.is_subset_of(&parent));
        assert!(!child_none.is_subset_of(&parent)); // uncapped child of capped parent
    }

    #[test]
    fn grant_subset_with_constraints() {
        let parent = ToolGrant {
            server_id: "a".to_string(),
            tool_name: "t1".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/app".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        // Child has parent's constraint + an extra one (more restrictive)
        let child = ToolGrant {
            constraints: vec![
                Constraint::PathPrefix("/app".to_string()),
                Constraint::MaxLength(1024),
            ],
            ..parent.clone()
        };
        // Child missing parent's constraint (less restrictive)
        let bad_child = ToolGrant {
            constraints: vec![Constraint::MaxLength(1024)],
            ..parent.clone()
        };

        assert!(child.is_subset_of(&parent));
        assert!(!bad_child.is_subset_of(&parent));
    }

    #[test]
    fn grant_subset_with_wildcard_server() {
        let parent = ToolGrant {
            server_id: "*".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child = ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };

        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn validate_attenuation_ok() {
        let parent = make_scope(vec![
            make_grant("a", "t1", vec![Operation::Invoke, Operation::ReadResult]),
            make_grant("a", "t2", vec![Operation::Invoke]),
        ]);
        let child = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        assert!(validate_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn validate_attenuation_escalation_fails() {
        let parent = make_scope(vec![make_grant("a", "t1", vec![Operation::Invoke])]);
        let child = make_scope(vec![make_grant(
            "a",
            "t1",
            vec![Operation::Invoke, Operation::Delegate],
        )]);
        assert!(validate_attenuation(&parent, &child).is_err());
    }

    fn make_signed_link(
        capability_id: &str,
        delegator_kp: &Keypair,
        delegatee: &PublicKey,
        timestamp: u64,
    ) -> DelegationLink {
        let body = DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp,
        };
        DelegationLink::sign(body, delegator_kp).unwrap()
    }

    #[test]
    fn delegation_chain_valid() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        assert!(validate_delegation_chain(&[link1, link2], None).is_ok());
    }

    #[test]
    fn delegation_chain_broken_connectivity() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();
        let kp_d = Keypair::generate();

        // link1: A -> B, link2: C -> D (not connected)
        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-c", &kp_c, &kp_d.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn delegation_chain_non_monotonic_timestamps() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 200);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 100); // earlier!

        let err = validate_delegation_chain(&[link1, link2], None).unwrap_err();
        assert!(err.to_string().contains("precedes"));
    }

    #[test]
    fn delegation_chain_exceeds_depth() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        let link2 = make_signed_link("cap-b", &kp_b, &kp_c.public_key(), 200);

        let err = validate_delegation_chain(&[link1, link2], Some(1)).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn delegation_chain_invalid_signature() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let kp_c = Keypair::generate();

        let mut link1 = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 100);
        // Tamper: change the delegatee after signing
        link1.delegatee = kp_c.public_key();

        let err = validate_delegation_chain(&[link1], None).unwrap_err();
        assert!(err.to_string().contains("signature invalid"));
    }

    #[test]
    fn delegation_link_serde_roundtrip() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let link = make_signed_link("cap-a", &kp_a, &kp_b.public_key(), 12345);

        let json = serde_json::to_string_pretty(&link).unwrap();
        let restored: DelegationLink = serde_json::from_str(&json).unwrap();

        assert_eq!(link.capability_id, restored.capability_id);
        assert_eq!(link.delegator, restored.delegator);
        assert_eq!(link.delegatee, restored.delegatee);
        assert_eq!(link.timestamp, restored.timestamp);
        assert_eq!(link.signature.to_hex(), restored.signature.to_hex());
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let constraints = vec![
            Constraint::PathPrefix("/app/src".to_string()),
            Constraint::DomainExact("api.example.com".to_string()),
            Constraint::DomainGlob("*.example.com".to_string()),
            Constraint::RegexMatch(r"^[a-z]+$".to_string()),
            Constraint::MaxLength(1024),
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: 500,
            },
            Constraint::SellerExact("merchant.example".to_string()),
            Constraint::MinimumRuntimeAssurance(RuntimeAssuranceTier::Attested),
            Constraint::MinimumAutonomyTier(GovernedAutonomyTier::Delegated),
            Constraint::Custom("category".to_string(), "read-only".to_string()),
        ];

        let json = serde_json::to_string_pretty(&constraints).unwrap();
        let restored: Vec<Constraint> = serde_json::from_str(&json).unwrap();
        assert_eq!(constraints, restored);
    }

    #[test]
    fn governed_transaction_intent_binding_hash_changes_with_payload() {
        let base = GovernedTransactionIntent {
            id: "intent-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            commerce: Some(GovernedCommerceContext {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: "spt_123".to_string(),
            }),
            metered_billing: Some(MeteredBillingContext {
                settlement_mode: MeteredSettlementMode::AllowThenSettle,
                quote: MeteredBillingQuote {
                    quote_id: "quote-1".to_string(),
                    provider: "meter.arc".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 12,
                    quoted_cost: MonetaryAmount {
                        units: 300,
                        currency: "USD".to_string(),
                    },
                    issued_at: 950,
                    expires_at: Some(1300),
                },
                max_billed_units: Some(20),
            }),
            runtime_attestation: Some(RuntimeAttestationEvidence {
                schema: "arc.runtime-attestation.v1".to_string(),
                verifier: "verifier.arc".to_string(),
                tier: RuntimeAssuranceTier::Attested,
                issued_at: 900,
                expires_at: 1200,
                evidence_sha256: "attestation-digest".to_string(),
                runtime_identity: Some("spiffe://arc/runtime/123".to_string()),
                workload_identity: None,
                claims: None,
            }),
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-1".to_string(),
                parent_request_id: "req-parent-1".to_string(),
                parent_receipt_id: Some("rc-parent-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: Some(GovernedAutonomyContext {
                tier: GovernedAutonomyTier::Delegated,
                delegation_bond_id: Some("bond-1".to_string()),
            }),
            context: None,
        };
        let mut changed = base.clone();
        changed
            .call_chain
            .as_mut()
            .expect("call chain present")
            .parent_request_id = "req-parent-2".to_string();

        assert_ne!(
            base.binding_hash().unwrap(),
            changed.binding_hash().unwrap()
        );
    }

    #[test]
    fn metered_billing_quote_validity_window_respects_optional_expiry() {
        let quote = MeteredBillingQuote {
            quote_id: "quote-1".to_string(),
            provider: "meter.arc".to_string(),
            billing_unit: "1k_tokens".to_string(),
            quoted_units: 8,
            quoted_cost: MonetaryAmount {
                units: 125,
                currency: "USD".to_string(),
            },
            issued_at: 100,
            expires_at: Some(200),
        };

        assert!(!quote.is_valid_at(99));
        assert!(quote.is_valid_at(100));
        assert!(quote.is_valid_at(199));
        assert!(!quote.is_valid_at(200));
    }

    #[test]
    fn governed_approval_token_signature_roundtrip() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let body = GovernedApprovalTokenBody {
            id: "approval-1".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: "intent-hash".to_string(),
            request_id: "req-1".to_string(),
            issued_at: 1000,
            expires_at: 2000,
            decision: GovernedApprovalDecision::Approved,
        };

        let token = GovernedApprovalToken::sign(body, &approver).unwrap();

        assert!(token.verify_signature().unwrap());
        assert!(token.is_valid_at(1500));
        assert!(!token.is_valid_at(2000));
        assert_eq!(token.subject, subject.public_key());
    }

    #[test]
    fn governed_upstream_call_chain_proof_roundtrip_and_context_extraction() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: "chain-proof-1".to_string(),
                parent_request_id: "req-parent-proof-1".to_string(),
                parent_receipt_id: Some("rc-parent-proof-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-proof-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-proof-1".to_string(),
                parent_request_id: "req-parent-proof-1".to_string(),
                parent_receipt_id: Some("rc-parent-proof-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: proof.clone(),
                "note": "preserve-other-context"
            })),
        };

        assert!(proof.verify_signature().unwrap());
        assert!(proof.is_valid_at(1500));
        assert!(!proof.is_valid_at(2000));
        assert!(proof.matches_context(intent.call_chain.as_ref().unwrap()));
        assert_eq!(intent.upstream_call_chain_proof().unwrap(), Some(proof));
    }

    #[test]
    fn call_chain_continuation_token_roundtrip_and_matching_helpers() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let session_anchor = SessionAnchorReference::new("anchor-1", "anchor-hash-1");
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-cont-1".to_string(),
            parent_request_id: "req-parent-cont-1".to_string(),
            parent_receipt_id: Some("rc-parent-cont-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        };
        let token = CallChainContinuationToken::sign(
            CallChainContinuationTokenBody {
                schema: ARC_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
                token_id: "continuation-1".to_string(),
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: call_chain.chain_id.clone(),
                parent_request_id: call_chain.parent_request_id.clone(),
                parent_receipt_id: call_chain.parent_receipt_id.clone(),
                parent_receipt_hash: Some("receipt-hash-1".to_string()),
                parent_session_anchor: Some(session_anchor.clone()),
                current_subject: subject.public_key().to_hex(),
                delegator_subject: call_chain.delegator_subject.clone(),
                origin_subject: call_chain.origin_subject.clone(),
                parent_capability_id: Some("cap-parent-1".to_string()),
                delegation_link_hash: Some("delegation-link-hash-1".to_string()),
                governed_intent_hash: Some("intent-hash-1".to_string()),
                audience: Some(CallChainContinuationAudience {
                    server_id: "srv-pay".to_string(),
                    tool_name: "charge".to_string(),
                }),
                nonce: Some("nonce-1".to_string()),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-cont-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(call_chain.clone()),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: token.clone()
            })),
        };

        assert!(token.verify_signature().unwrap());
        assert!(token.matches_context(&call_chain));
        assert!(token.matches_session_anchor(&session_anchor));
        assert!(token.matches_target("srv-pay", "charge"));
        assert!(token.matches_intent_hash("intent-hash-1"));
        assert!(token.matches_subject(&subject.public_key()));
        assert_eq!(
            intent.explicit_continuation_token().unwrap(),
            Some(token.clone())
        );
        assert_eq!(intent.continuation_token().unwrap(), Some(token));
    }

    #[test]
    fn continuation_token_falls_back_to_legacy_upstream_proof() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: "chain-legacy-1".to_string(),
                parent_request_id: "req-parent-legacy-1".to_string(),
                parent_receipt_id: Some("rc-parent-legacy-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
                issued_at: 1000,
                expires_at: 2000,
            },
            &signer,
        )
        .unwrap();
        let intent = GovernedTransactionIntent {
            id: "intent-legacy-1".to_string(),
            server_id: "srv-pay".to_string(),
            tool_name: "charge".to_string(),
            purpose: "pay supplier".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: Some(GovernedCallChainContext {
                chain_id: "chain-legacy-1".to_string(),
                parent_request_id: "req-parent-legacy-1".to_string(),
                parent_receipt_id: Some("rc-parent-legacy-1".to_string()),
                origin_subject: "origin-subject".to_string(),
                delegator_subject: "delegator-subject".to_string(),
            }),
            autonomy: None,
            context: Some(serde_json::json!({
                GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: proof
            })),
        };

        let token = intent.continuation_token().unwrap().unwrap();

        assert!(token.verify_signature().unwrap());
        assert!(token.token_id.starts_with("legacy:"));
        assert_eq!(intent.explicit_continuation_token().unwrap(), None);
        assert_eq!(token.parent_request_id, "req-parent-legacy-1");
        assert_eq!(
            token.parent_receipt_id.as_deref(),
            Some("rc-parent-legacy-1")
        );
    }

    #[test]
    fn governed_call_chain_provenance_separates_asserted_and_verified_views() {
        let asserted_context = GovernedCallChainContext {
            chain_id: "chain-prov-1".to_string(),
            parent_request_id: "req-parent-prov-1".to_string(),
            parent_receipt_id: Some("rc-parent-prov-1".to_string()),
            origin_subject: "origin-asserted".to_string(),
            delegator_subject: "delegator-asserted".to_string(),
        };
        let verified_context = GovernedCallChainContext {
            chain_id: "chain-prov-1".to_string(),
            parent_request_id: "req-parent-prov-1".to_string(),
            parent_receipt_id: Some("rc-parent-prov-1".to_string()),
            origin_subject: "origin-verified".to_string(),
            delegator_subject: "delegator-verified".to_string(),
        };
        let provenance = GovernedCallChainProvenance::verified(verified_context.clone())
            .with_asserted_context(asserted_context.clone())
            .with_continuation_token_id("continuation-1")
            .with_session_anchor_id("anchor-1")
            .with_receipt_lineage_statement_id("statement-1");

        let encoded = serde_json::to_value(&provenance).unwrap();

        assert!(provenance.is_verified());
        assert_eq!(provenance.asserted_context(), Some(&asserted_context));
        assert_eq!(provenance.verified_context(), Some(&verified_context));
        assert_eq!(encoded["continuationTokenId"], "continuation-1");
        assert_eq!(encoded["sessionAnchorId"], "anchor-1");
        assert_eq!(encoded["receiptLineageStatementId"], "statement-1");
        assert_eq!(
            encoded["assertedContext"]["originSubject"],
            "origin-asserted"
        );
        assert_eq!(encoded["originSubject"], "origin-verified");
    }

    #[test]
    fn runtime_attestation_evidence_validity_window_is_half_open() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Verified,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };

        assert!(!attestation.is_valid_at(99));
        assert!(attestation.is_valid_at(100));
        assert!(attestation.is_valid_at(199));
        assert!(!attestation.is_valid_at(200));
    }

    #[test]
    fn workload_identity_parses_spiffe_uri() {
        let workload = WorkloadIdentity::parse_spiffe_uri("spiffe://prod.arc/payments/worker")
            .expect("parse SPIFFE workload identity");

        assert_eq!(workload.scheme, WorkloadIdentityScheme::Spiffe);
        assert_eq!(workload.credential_kind, WorkloadCredentialKind::Uri);
        assert_eq!(workload.trust_domain, "prod.arc");
        assert_eq!(workload.path, "/payments/worker");
    }

    #[test]
    fn workload_identity_rejects_invalid_spiffe_variants() {
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri(" "),
            Err(WorkloadIdentityError::EmptyUri)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://prod.arc/payments/worker?version=1"),
            Err(WorkloadIdentityError::InvalidSuffix)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("https://prod.arc/payments/worker"),
            Err(WorkloadIdentityError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://user@prod.arc/payments/worker"),
            Err(WorkloadIdentityError::InvalidAuthority)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe:///payments/worker"),
            Err(WorkloadIdentityError::MissingTrustDomain)
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("spiffe://prod.arc/payments//worker"),
            Err(WorkloadIdentityError::InvalidPath(_))
        ));
        assert!(matches!(
            WorkloadIdentity::parse_spiffe_uri("%%%"),
            Err(WorkloadIdentityError::MalformedUri(_))
        ));
    }

    #[test]
    fn runtime_attestation_normalizes_spiffe_runtime_identity() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("spiffe://prod.arc/payments/worker".to_string()),
            workload_identity: None,
            claims: None,
        };

        let workload = attestation
            .normalized_workload_identity()
            .expect("normalize workload identity")
            .expect("workload identity present");
        assert_eq!(workload.trust_domain, "prod.arc");
        assert_eq!(workload.path, "/payments/worker");
    }

    #[test]
    fn runtime_attestation_rejects_conflicting_explicit_workload_identity() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("spiffe://prod.arc/payments/worker".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::X509Svid,
                uri: "spiffe://dev.arc/payments/worker".to_string(),
                trust_domain: "dev.arc".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };

        let error = attestation
            .validate_workload_identity_binding()
            .expect_err("conflicting workload identities should fail");
        assert!(error.to_string().contains("trust_domain"));
    }

    #[test]
    fn workload_identity_validation_and_runtime_identity_conflicts_cover_remaining_paths() {
        let identity = WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::Uri,
            uri: "spiffe://prod.arc/payments/worker".to_string(),
            trust_domain: "prod.arc".to_string(),
            path: "/payments/other".to_string(),
        };
        assert!(matches!(
            identity.validate(),
            Err(WorkloadIdentityError::Conflict { field: "path", .. })
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("   ".to_string()),
            workload_identity: None,
            claims: None,
        };
        assert!(matches!(
            attestation.normalized_workload_identity(),
            Err(WorkloadIdentityError::EmptyRuntimeIdentity)
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: Some("//compute.googleapis.com/projects/demo".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://prod.arc/payments/worker".to_string(),
                trust_domain: "prod.arc".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };
        assert!(matches!(
            attestation.normalized_workload_identity(),
            Err(WorkloadIdentityError::OpaqueRuntimeIdentityConflict(_))
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://prod.arc/payments/worker".to_string(),
                trust_domain: "prod.arc".to_string(),
                path: "/payments/worker".to_string(),
            }),
            claims: None,
        };
        let normalized = attestation
            .normalized_workload_identity()
            .expect("explicit workload identity should normalize")
            .expect("workload identity should exist");
        assert_eq!(normalized.trust_domain, "prod.arc");
    }

    #[test]
    fn runtime_attestation_trust_policy_rebinds_effective_tier() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let resolved = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect("resolve effective tier");
        assert_eq!(resolved.raw_tier, RuntimeAssuranceTier::Attested);
        assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
        assert_eq!(resolved.matched_rule.as_deref(), Some("azure-contoso"));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_stale_verified_evidence() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 400,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(30),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("stale evidence should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::EvidenceTooOld { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_disallowed_attestation_type() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sev_snp"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("unexpected attestation type should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::DisallowedAttestationType { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_untrusted_verifier() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.untrusted.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::new(),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("untrusted verifier should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::UntrustedEvidence { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_matches_google_family_and_required_assertions() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([
                    ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                    ("secureBoot".to_string(), "enabled".to_string()),
                ]),
            }],
        };

        let resolved = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect("google attestation should satisfy appraisal-aware trust policy");
        assert_eq!(resolved.effective_tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            resolved.matched_rule.as_deref(),
            Some("google-confidential")
        );
    }

    #[test]
    fn runtime_attestation_trust_policy_rejects_missing_required_assertion() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: Some(60),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([(
                    "secureBoot".to_string(),
                    "enabled".to_string(),
                )]),
            }],
        };

        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("missing secureBoot assertion should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::MissingAssertion { .. }
        ));
    }

    #[test]
    fn runtime_attestation_trust_policy_covers_remaining_fail_closed_paths() {
        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("missing attestationType should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::MissingAttestationType { .. }
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest-google".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_INTEL_TDX",
                    "secureBoot": "enabled"
                }
            })),
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "arc.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::GoogleAttestation),
                max_evidence_age_seconds: None,
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: BTreeMap::from([(
                    "hardwareModel".to_string(),
                    "GCP_AMD_SEV".to_string(),
                )]),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("mismatched required assertion should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::AssertionMismatch { .. }
        ));

        let attestation = RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.unsupported.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: None,
        };
        let policy = AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "unsupported".to_string(),
                schema: "arc.runtime-attestation.unsupported.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: None,
                max_evidence_age_seconds: None,
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::new(),
            }],
        };
        let error = attestation
            .resolve_effective_runtime_assurance(Some(&policy), 150)
            .expect_err("unsupported evidence schema should fail closed");
        assert!(matches!(
            error,
            AttestationTrustError::UnsupportedEvidence { .. }
        ));
    }

    #[test]
    fn operation_serde_roundtrip() {
        let ops = vec![
            Operation::Invoke,
            Operation::ReadResult,
            Operation::Delegate,
        ];
        let json = serde_json::to_string(&ops).unwrap();
        let restored: Vec<Operation> = serde_json::from_str(&json).unwrap();
        assert_eq!(ops, restored);
    }

    #[test]
    fn attenuation_serde_roundtrip() {
        let attenuations = vec![
            Attenuation::RemoveTool {
                server_id: "srv".to_string(),
                tool_name: "danger".to_string(),
            },
            Attenuation::RemoveOperation {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                operation: Operation::Delegate,
            },
            Attenuation::AddConstraint {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                constraint: Constraint::PathPrefix("/safe".to_string()),
            },
            Attenuation::ReduceBudget {
                server_id: "srv".to_string(),
                tool_name: "tool".to_string(),
                max_invocations: 5,
            },
            Attenuation::ShortenExpiry {
                new_expires_at: 9999,
            },
        ];

        let json = serde_json::to_string_pretty(&attenuations).unwrap();
        let restored: Vec<Attenuation> = serde_json::from_str(&json).unwrap();
        assert_eq!(attenuations, restored);
    }
}
