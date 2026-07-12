use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{
    is_default_optional_algorithm, sha256_hex, sign_canonical_with_backend, Keypair, PublicKey,
    Signature, SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::schema_binding::ensure_schema_matches;
use crate::session::SessionAnchorReference;
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
};

use super::runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence};
use super::scope::MonetaryAmount;
use super::threshold_approval::MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES;

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

/// Reserved key inside `GovernedTransactionIntent.context` for compatibility upstream call-chain proofs.
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

/// Signed upstream proof Chio can validate and promote to verified provenance.
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
        ensure_keypair_matches_embedded_key(&body.signer, keypair, "call-chain proof", "signer")?;
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

    /// Verify the signature AND enforce the validity window in one pass.
    ///
    /// Sanctioned entry point when freshness matters: fails closed on expiry /
    /// not-yet-valid proofs, which the bare
    /// [`GovernedUpstreamCallChainProof::verify_signature`] does not check. A
    /// clock is threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: the signature is checked FIRST. A proof with an
    /// invalid signature is rejected before the time window is consulted.
    /// Returns `Ok(true)` only when the signature verifies and `now` is within
    /// `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
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
pub const CHIO_CALL_CHAIN_CONTINUATION_SCHEMA: &str = "chio.call_chain_continuation.v1";

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
        ensure_schema_matches(
            &body.schema,
            CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
            "call-chain continuation token",
        )?;
        ensure_keypair_matches_embedded_key(&body.signer, keypair, "continuation token", "signer")?;
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
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        ensure_schema_matches(
            &self.schema,
            CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
            "call-chain continuation token",
        )?;
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    /// Verify the signature AND enforce the validity window in one pass.
    ///
    /// Sanctioned entry point when freshness matters: fails closed on expiry /
    /// not-yet-valid tokens, which the bare
    /// [`CallChainContinuationToken::verify_signature`] does not check. A clock
    /// is threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: schema + signature are checked FIRST. A token with
    /// an invalid signature (or schema) is rejected before the time window is
    /// consulted. Returns `Ok(true)` only when the signature verifies and `now`
    /// is within `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
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
}

/// Evidence class describing how Chio learned or validated provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProvenanceEvidenceClass {
    /// Caller-asserted provenance bound into the request, but not independently checked yet.
    #[default]
    Asserted,
    /// Provenance observed by Chio or a trusted subsystem, but not fully verified end-to-end.
    Observed,
    /// Provenance verified against authoritative evidence such as receipt linkage or signatures.
    Verified,
}

/// Generic evidence class used across Chio provenance artifacts.
pub type ProvenanceEvidenceClass = GovernedProvenanceEvidenceClass;

/// Authoritative local evidence Chio used to corroborate governed call-chain metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedCallChainEvidenceSource {
    /// The call-chain parent request matched an authenticated parent request in the live session.
    SessionParentRequestLineage,
    /// The optional parent receipt identifier matched a receipt Chio already recorded locally.
    LocalParentReceiptLinkage,
    /// The asserted delegator subject matched the validated capability delegation source.
    CapabilityDelegatorSubject,
    /// The asserted origin subject matched the root delegator visible in capability lineage.
    CapabilityOriginSubject,
    /// Chio validated a signed upstream handoff against the capability's delegator key.
    UpstreamDelegatorProof,
}

/// Typed provenance envelope for delegated governed call-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainProvenance {
    /// Evidence class describing how strongly Chio should treat this provenance.
    #[serde(default)]
    pub evidence_class: GovernedProvenanceEvidenceClass,
    /// Specific authoritative local evidence Chio used when it upgraded the caller assertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<GovernedCallChainEvidenceSource>,
    /// Optional signed upstream proof Chio validated before upgrading to verified provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_proof: Option<GovernedUpstreamCallChainProof>,
    /// Optional preserved caller assertion when Chio upgraded or rewrote the effective context.
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

impl core::ops::Deref for GovernedCallChainProvenance {
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

/// Schema for the protocol-owned active-response plan body.
pub const CHIO_RESPONSE_PLAN_SCHEMA: &str = "chio.response-plan.v1";
/// Domain separator for the canonical active-response plan body hash.
pub const CHIO_RESPONSE_PLAN_HASH_DOMAIN: &str = "chio:response-plan:v1\0";
/// Explicit schema for governed intent variants introduced after the legacy tool-call shape.
pub const CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2: &str = "chio.governed-transaction-intent.v2";
/// Internal tool server whose capability grants authorize response effects.
pub const CHIO_ACTIVE_RESPONSE_SERVER_ID: &str = "chio.control-plane.active-response";

const MAX_RESPONSE_PLAN_IDENTIFIER_BYTES: usize = 256;
const MAX_RESPONSE_PLAN_BODY_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_PLAN_BINDING_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_PLAN_JSON_DEPTH: usize = 32;
const MAX_RESPONSE_PLAN_JSON_NODES: usize = 4_096;
const MAX_RESPONSE_PLAN_EFFECTS: usize = 5;

/// Closed logical response effects authorized by ordinary Chio tool grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedResponseEffect {
    ThrottleSession,
    RestrictEgress,
    SuspendSession,
    SuspendCapabilitySet,
    FreezeIssuance,
}

impl GovernedResponseEffect {
    /// Logical tool name that must be present on the verified operator capability.
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::ThrottleSession => "throttle_session",
            Self::RestrictEgress => "restrict_egress",
            Self::SuspendSession => "suspend_session",
            Self::SuspendCapabilitySet => "suspend_capability_set",
            Self::FreezeIssuance => "freeze_issuance",
        }
    }
}

/// Protocol-owned, validated projection of an active-defense response plan.
///
/// Construction and deserialization both validate every structural invariant. The canonical
/// plan body remains opaque to core so active-defense can evolve without a reverse dependency,
/// but it must be a bounded object rather than a caller-supplied plan hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedResponsePlanIntentBody {
    plan_schema: String,
    plan_id: String,
    operator_capability_id: String,
    operator_capability_hash: String,
    operator_capability_expires_at: u64,
    executor_subject: PublicKey,
    canonical_plan_body: serde_json::Value,
    plan_body_hash: String,
    target_binding: serde_json::Value,
    ordered_effects: Vec<GovernedResponseEffect>,
    expires_at: u64,
    rollback_binding: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GovernedResponsePlanIntentBodyWire {
    plan_schema: String,
    plan_id: String,
    operator_capability_id: String,
    operator_capability_hash: String,
    operator_capability_expires_at: u64,
    executor_subject: PublicKey,
    canonical_plan_body: serde_json::Value,
    plan_body_hash: String,
    target_binding: serde_json::Value,
    ordered_effects: Vec<GovernedResponseEffect>,
    expires_at: u64,
    rollback_binding: serde_json::Value,
}

impl<'de> Deserialize<'de> for GovernedResponsePlanIntentBody {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let wire = GovernedResponsePlanIntentBodyWire::deserialize(deserializer)?;
        let body = Self {
            plan_schema: wire.plan_schema,
            plan_id: wire.plan_id,
            operator_capability_id: wire.operator_capability_id,
            operator_capability_hash: wire.operator_capability_hash,
            operator_capability_expires_at: wire.operator_capability_expires_at,
            executor_subject: wire.executor_subject,
            canonical_plan_body: wire.canonical_plan_body,
            plan_body_hash: wire.plan_body_hash,
            target_binding: wire.target_binding,
            ordered_effects: wire.ordered_effects,
            expires_at: wire.expires_at,
            rollback_binding: wire.rollback_binding,
        };
        body.validate().map_err(D::Error::custom)?;
        Ok(body)
    }
}

impl GovernedResponsePlanIntentBody {
    /// Construct and validate a complete governed response-plan projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_schema: impl Into<String>,
        plan_id: impl Into<String>,
        operator_capability_id: impl Into<String>,
        operator_capability_hash: impl Into<String>,
        operator_capability_expires_at: u64,
        executor_subject: PublicKey,
        canonical_plan_body: serde_json::Value,
        plan_body_hash: impl Into<String>,
        target_binding: serde_json::Value,
        ordered_effects: Vec<GovernedResponseEffect>,
        expires_at: u64,
        rollback_binding: serde_json::Value,
    ) -> Result<Self> {
        let body = Self {
            plan_schema: plan_schema.into(),
            plan_id: plan_id.into(),
            operator_capability_id: operator_capability_id.into(),
            operator_capability_hash: operator_capability_hash.into(),
            operator_capability_expires_at,
            executor_subject,
            canonical_plan_body,
            plan_body_hash: plan_body_hash.into(),
            target_binding,
            ordered_effects,
            expires_at,
            rollback_binding,
        };
        body.validate()?;
        Ok(body)
    }

    /// Compute the required domain-separated hash of the canonical plan body.
    pub fn compute_plan_body_hash(canonical_plan_body: &serde_json::Value) -> Result<String> {
        validate_plan_body_shape(canonical_plan_body)?;
        let canonical = canonical_json_bytes(canonical_plan_body)?;
        let mut preimage =
            Vec::with_capacity(CHIO_RESPONSE_PLAN_HASH_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(CHIO_RESPONSE_PLAN_HASH_DOMAIN.as_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
    }

    /// Revalidate invariants after crossing a trust boundary.
    pub fn validate(&self) -> Result<()> {
        if self.plan_schema != CHIO_RESPONSE_PLAN_SCHEMA {
            return Err(invalid_response_plan("unsupported plan schema"));
        }
        validate_response_plan_identifier(&self.plan_id, "plan id")?;
        validate_response_plan_identifier(&self.operator_capability_id, "operator capability id")?;
        validate_response_plan_digest(&self.operator_capability_hash, "operator capability hash")?;
        if self.operator_capability_expires_at == 0 {
            return Err(invalid_response_plan(
                "operator capability expiry must be nonzero",
            ));
        }
        if self.expires_at == 0 || self.expires_at > self.operator_capability_expires_at {
            return Err(invalid_response_plan(
                "plan expiry must be nonzero and no later than operator capability expiry",
            ));
        }
        validate_bounded_json(
            &self.canonical_plan_body,
            MAX_RESPONSE_PLAN_BODY_BYTES,
            "canonical plan body",
        )?;
        let expected_hash = Self::compute_plan_body_hash(&self.canonical_plan_body)?;
        validate_response_plan_digest(&self.plan_body_hash, "plan body hash")?;
        if self.plan_body_hash != expected_hash {
            return Err(invalid_response_plan(
                "canonical plan body does not match plan body hash",
            ));
        }
        validate_binding_object(&self.target_binding, "target binding")?;
        validate_bounded_json(
            &self.target_binding,
            MAX_RESPONSE_PLAN_BINDING_BYTES,
            "target binding",
        )?;
        validate_binding_object(&self.rollback_binding, "rollback binding")?;
        validate_bounded_json(
            &self.rollback_binding,
            MAX_RESPONSE_PLAN_BINDING_BYTES,
            "rollback binding",
        )?;
        if self.ordered_effects.is_empty() || self.ordered_effects.len() > MAX_RESPONSE_PLAN_EFFECTS
        {
            return Err(invalid_response_plan(
                "ordered effects must be nonempty and within the closed effect ceiling",
            ));
        }
        for (index, effect) in self.ordered_effects.iter().enumerate() {
            if self.ordered_effects[..index].contains(effect) {
                return Err(invalid_response_plan("ordered effects contain a duplicate"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn plan_schema(&self) -> &str {
        &self.plan_schema
    }

    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    #[must_use]
    pub fn operator_capability_id(&self) -> &str {
        &self.operator_capability_id
    }

    #[must_use]
    pub fn operator_capability_hash(&self) -> &str {
        &self.operator_capability_hash
    }

    #[must_use]
    pub const fn operator_capability_expires_at(&self) -> u64 {
        self.operator_capability_expires_at
    }

    #[must_use]
    pub fn executor_subject(&self) -> &PublicKey {
        &self.executor_subject
    }

    #[must_use]
    pub fn canonical_plan_body(&self) -> &serde_json::Value {
        &self.canonical_plan_body
    }

    #[must_use]
    pub fn plan_body_hash(&self) -> &str {
        &self.plan_body_hash
    }

    #[must_use]
    pub fn target_binding(&self) -> &serde_json::Value {
        &self.target_binding
    }

    #[must_use]
    pub fn ordered_effects(&self) -> &[GovernedResponseEffect] {
        &self.ordered_effects
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn rollback_binding(&self) -> &serde_json::Value {
        &self.rollback_binding
    }
}

fn invalid_response_plan(reason: &str) -> Error {
    Error::CanonicalJson(alloc::format!("invalid governed response plan: {reason}"))
}

fn validate_response_plan_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_RESPONSE_PLAN_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid_response_plan(&alloc::format!(
            "{label} is empty, contains control characters, or exceeds the byte ceiling"
        )));
    }
    Ok(())
}

fn validate_response_plan_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_response_plan(&alloc::format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn validate_plan_body_shape(value: &serde_json::Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Err(invalid_response_plan(
            "canonical plan body must be a JSON object, not a raw hash",
        ));
    };
    if object.is_empty() || object.contains_key("planHash") || object.contains_key("plan_hash") {
        return Err(invalid_response_plan(
            "canonical plan body is empty or substitutes a standalone plan hash",
        ));
    }
    Ok(())
}

fn validate_binding_object(value: &serde_json::Value, label: &str) -> Result<()> {
    if value.as_object().is_none_or(serde_json::Map::is_empty) {
        return Err(invalid_response_plan(&alloc::format!(
            "{label} must be a nonempty JSON object"
        )));
    }
    Ok(())
}

fn validate_bounded_json(value: &serde_json::Value, max_bytes: usize, label: &str) -> Result<()> {
    let mut nodes = 0usize;
    validate_json_depth_and_nodes(value, 0, &mut nodes, label)?;
    let canonical = canonical_json_bytes(value)?;
    if canonical.len() > max_bytes {
        return Err(invalid_response_plan(&alloc::format!(
            "{label} exceeds the canonical byte ceiling"
        )));
    }
    Ok(())
}

fn validate_json_depth_and_nodes(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
    label: &str,
) -> Result<()> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| invalid_response_plan("JSON node accounting overflowed"))?;
    if depth > MAX_RESPONSE_PLAN_JSON_DEPTH || *nodes > MAX_RESPONSE_PLAN_JSON_NODES {
        return Err(invalid_response_plan(&alloc::format!(
            "{label} exceeds the JSON depth or node ceiling"
        )));
    }
    match value {
        serde_json::Value::Array(values) => {
            for item in values {
                validate_json_depth_and_nodes(item, depth + 1, nodes, label)?;
            }
        }
        serde_json::Value::Object(values) => {
            for item in values.values() {
                validate_json_depth_and_nodes(item, depth + 1, nodes, label)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

/// Closed, explicitly discriminated governed transaction intent body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum GovernedTransactionIntentBody {
    ToolInvocation(Box<GovernedToolInvocationIntentBody>),
    ActiveResponsePlan(Box<GovernedResponsePlanIntentBody>),
}

/// Canonical, versioned intent attached to a governed transaction request.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedTransactionIntent {
    schema: String,
    #[serde(flatten)]
    pub body: GovernedTransactionIntentBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GovernedTransactionIntentWire {
    schema: String,
    #[serde(flatten)]
    body: GovernedTransactionIntentBody,
}

impl<'de> Deserialize<'de> for GovernedTransactionIntent {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let wire = GovernedTransactionIntentWire::deserialize(deserializer)?;
        if wire.schema != CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2 {
            return Err(D::Error::custom("unsupported governed intent schema"));
        }
        let intent = Self {
            schema: wire.schema,
            body: wire.body,
        };
        if let GovernedTransactionIntentBody::ActiveResponsePlan(plan) = &intent.body {
            plan.validate().map_err(D::Error::custom)?;
        }
        Ok(intent)
    }
}

impl GovernedTransactionIntent {
    /// Wrap the complete existing tool-invocation fields in the explicit v2 variant.
    #[must_use]
    pub fn tool_invocation(body: GovernedToolInvocationIntentBody) -> Self {
        Self {
            schema: CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2.into(),
            body: GovernedTransactionIntentBody::ToolInvocation(Box::new(body)),
        }
    }

    /// Wrap a validated protocol-owned active-response plan in the explicit v2 variant.
    #[must_use]
    pub fn active_response_plan(body: GovernedResponsePlanIntentBody) -> Self {
        Self {
            schema: CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2.into(),
            body: GovernedTransactionIntentBody::ActiveResponsePlan(Box::new(body)),
        }
    }

    /// Versioned governed intent schema.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Compute the canonical binding used by governed approval tokens and receipts.
    pub fn binding_hash(&self) -> Result<String> {
        if self.schema != CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2 {
            return Err(invalid_response_plan("unsupported governed intent schema"));
        }
        if let GovernedTransactionIntentBody::ActiveResponsePlan(body) = &self.body {
            body.validate()?;
        }
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    #[must_use]
    pub fn as_tool_invocation(&self) -> Option<&GovernedToolInvocationIntentBody> {
        match &self.body {
            GovernedTransactionIntentBody::ToolInvocation(intent) => Some(intent.as_ref()),
            GovernedTransactionIntentBody::ActiveResponsePlan(_) => None,
        }
    }

    #[must_use]
    pub fn as_tool_invocation_mut(&mut self) -> Option<&mut GovernedToolInvocationIntentBody> {
        match &mut self.body {
            GovernedTransactionIntentBody::ToolInvocation(intent) => Some(intent.as_mut()),
            GovernedTransactionIntentBody::ActiveResponsePlan(_) => None,
        }
    }

    #[must_use]
    pub fn as_active_response_plan(&self) -> Option<&GovernedResponsePlanIntentBody> {
        match &self.body {
            GovernedTransactionIntentBody::ActiveResponsePlan(plan) => Some(plan.as_ref()),
            GovernedTransactionIntentBody::ToolInvocation(_) => None,
        }
    }

    /// Extract the reserved upstream call-chain proof from a tool-invocation body.
    pub fn upstream_call_chain_proof(&self) -> Result<Option<GovernedUpstreamCallChainProof>> {
        self.as_tool_invocation().map_or(
            Ok(None),
            GovernedToolInvocationIntentBody::upstream_call_chain_proof,
        )
    }

    /// Extract an explicitly attached continuation token from a tool-invocation body.
    pub fn explicit_continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        self.as_tool_invocation().map_or(
            Ok(None),
            GovernedToolInvocationIntentBody::explicit_continuation_token,
        )
    }

    /// Extract the explicit continuation token, if present.
    pub fn continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        self.explicit_continuation_token()
    }
}

/// Existing governed tool-invocation fields preserved as one closed v2 intent variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedToolInvocationIntentBody {
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

impl GovernedToolInvocationIntentBody {
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

    /// Extract an explicitly attached continuation token.
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

/// Domain for hashing a complete signed governed approval token.
pub const CHIO_GOVERNED_APPROVAL_TOKEN_DIGEST_DOMAIN: &str = "chio.governed-approval-token.v1\0";

/// Signable body of a governed approval token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalTokenBody {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    /// Signed threshold proposal this token answers. Legacy one-of-one tokens omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_proposal_hash: Option<String>,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
}

/// Signed approval artifact bound to one governed intent and one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    /// Signed threshold proposal this token answers. Legacy one-of-one tokens omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_proposal_hash: Option<String>,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
    /// Signing algorithm. Absent means Ed25519 (the default).
    ///
    /// Informational: verification dispatches off the algorithm encoded in
    /// [`GovernedApprovalToken::signature`] and [`GovernedApprovalToken::approver`].
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
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
            threshold_proposal_hash: self.threshold_proposal_hash.clone(),
            request_id: self.request_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            decision: self.decision,
        }
    }

    /// Sign a governed approval token body with the given Ed25519 keypair.
    pub fn sign(body: GovernedApprovalTokenBody, keypair: &Keypair) -> Result<Self> {
        validate_governed_approval_token_id(&body.id)?;
        validate_threshold_proposal_hash(body.threshold_proposal_hash.as_deref())?;
        ensure_keypair_matches_embedded_key(
            &body.approver,
            keypair,
            "governed approval token",
            "approver",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            threshold_proposal_hash: body.threshold_proposal_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: None,
            signature,
        })
    }

    /// Sign a governed approval token body with an arbitrary [`SigningBackend`].
    ///
    /// `body.approver` must equal `backend.public_key()`.
    pub fn sign_with_backend(
        body: GovernedApprovalTokenBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        validate_governed_approval_token_id(&body.id)?;
        validate_threshold_proposal_hash(body.threshold_proposal_hash.as_deref())?;
        ensure_backend_matches_embedded_key(
            &body.approver,
            backend,
            "governed approval token",
            "approver",
        )?;
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            threshold_proposal_hash: body.threshold_proposal_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        validate_governed_approval_token_id(&self.id)?;
        validate_threshold_proposal_hash(self.threshold_proposal_hash.as_deref())?;
        let body = self.body();
        self.approver.verify_canonical(&body, &self.signature)
    }

    /// Hash the complete canonical token, including its signature.
    pub fn token_digest(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        let mut preimage =
            Vec::with_capacity(CHIO_GOVERNED_APPROVAL_TOKEN_DIGEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(CHIO_GOVERNED_APPROVAL_TOKEN_DIGEST_DOMAIN.as_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
    }

    /// Verify the signature AND enforce the approval-token validity window in
    /// one pass.
    ///
    /// Sanctioned entry point when freshness matters (settlement lanes that
    /// must assert approval expiry, per the dependent C2/C3 work): fails closed
    /// on expiry / not-yet-valid approvals, which the bare
    /// [`GovernedApprovalToken::verify_signature`] does not check. A clock is
    /// threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: the signature is checked FIRST. An approval with an
    /// invalid signature is rejected before the time window is consulted.
    /// Returns `Ok(true)` only when the signature verifies and `now` is within
    /// `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
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

fn validate_threshold_proposal_hash(hash: Option<&str>) -> Result<()> {
    let Some(hash) = hash else {
        return Ok(());
    };
    if hash.len() != 64 {
        return Err(Error::InvalidHashLength {
            expected: 64,
            actual: hash.len(),
        });
    }
    if !hash
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidHex(
            "threshold proposal hash must be lowercase SHA-256 hex".to_string(),
        ));
    }
    Ok(())
}

fn validate_governed_approval_token_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_THRESHOLD_APPROVAL_IDENTIFIER_BYTES
        || id.trim() != id
        || id.chars().any(char::is_control)
    {
        return Err(Error::AttenuationViolation {
            reason: "governed approval token ID is empty, unbounded, or not normalized".to_string(),
        });
    }
    Ok(())
}
