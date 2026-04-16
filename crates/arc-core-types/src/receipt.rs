//! ARC receipts: signed proof that a tool call was evaluated.
//!
//! Every tool invocation -- whether allowed or denied -- produces a receipt.
//! Receipts are the immutable audit trail of the ARC protocol.

use serde::{Deserialize, Serialize};

use crate::capability::{
    GovernedAutonomyTier, GovernedCallChainContext, GovernedCallChainProvenance,
    MeteredBillingQuote, MeteredSettlementMode, MonetaryAmount, ProvenanceEvidenceClass,
    RuntimeAssuranceTier, WorkloadIdentity,
};
use crate::crypto::{
    canonical_json_bytes, is_default_optional_algorithm, sha256_hex, sign_canonical_with_backend,
    Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::oracle::OracleConversionEvidence;
use crate::runtime_attestation::AttestationVerifierFamily;
use crate::session::{
    OperationKind, OperationTerminalState, RequestId, SessionAnchorReference, SessionId,
};

/// Trust level of a receipt's authorization, recording HOW the Kernel
/// participated in the evaluation. Captured per-receipt so downstream
/// consumers (audit, regulatory, dashboards) can reason about the strength
/// of mediation that produced each authorization.
///
/// See `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` and roadmap Phase 1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Tool invocation was synchronously mediated by the kernel (the
    /// strongest form: kernel observed the call inline and authorized it).
    /// This is the default and the safest baseline.
    Mediated,
    /// Authorization happened inline in the agent process (e.g. a
    /// long-running orchestrator embedded the kernel via FFI). The kernel
    /// observed the call but did not synchronously mediate it through a
    /// separate trust boundary.
    Verified,
    /// Authorization was advisory only -- the kernel evaluated but the
    /// caller may have proceeded regardless. Used for shadow-mode
    /// integrations and observability-only deployments.
    Advisory,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Mediated
    }
}

impl TrustLevel {
    /// Return the canonical snake_case string for this trust level.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mediated => "mediated",
            Self::Verified => "verified",
            Self::Advisory => "advisory",
        }
    }
}

fn is_default_trust_level(level: &TrustLevel) -> bool {
    matches!(level, TrustLevel::Mediated)
}

/// A ARC receipt. Signed proof that a tool call was evaluated by the Kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcReceipt {
    /// Unique receipt ID (UUIDv7 recommended).
    pub id: String,
    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,
    /// ID of the capability token that was exercised (or presented).
    pub capability_id: String,
    /// Tool server that handled the invocation.
    pub tool_server: String,
    /// Tool that was invoked (or attempted).
    pub tool_name: String,
    /// The action that was evaluated.
    pub action: ToolCallAction,
    /// The Kernel's decision.
    pub decision: Decision,
    /// SHA-256 hash of the evaluated content for this receipt.
    pub content_hash: String,
    /// SHA-256 hash of the policy that was applied.
    pub policy_hash: String,
    /// Per-guard evidence collected during evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    /// Optional receipt metadata for stream/accounting details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Strength of kernel mediation that produced this receipt. Defaults
    /// to `Mediated`. Older receipts that omit this field deserialize
    /// to `Mediated` for backward compatibility.
    #[serde(default, skip_serializing_if = "is_default_trust_level")]
    pub trust_level: TrustLevel,
    /// The Kernel's public key (for verification without out-of-band lookup).
    pub kernel_key: PublicKey,
    /// Signing algorithm used for [`ArcReceipt::signature`]. Absent means
    /// Ed25519 for backward compatibility with receipts issued prior to the
    /// introduction of [`SigningAlgorithm`]. Informational only: verification
    /// dispatches off the self-describing encoding of the signature itself.
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    /// Signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a receipt (everything except the signature), used for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    pub decision: Decision,
    pub content_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "is_default_trust_level")]
    pub trust_level: TrustLevel,
    pub kernel_key: PublicKey,
}

/// Signed audit record for a nested child request handled under a parent tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildRequestReceipt {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
    /// Signing algorithm. Absent means Ed25519 for backward compatibility.
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

/// The body of a child-request receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildRequestReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

impl ArcReceipt {
    /// Sign a receipt body with the Kernel's Ed25519 keypair.
    pub fn sign(body: ArcReceiptBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            trust_level: body.trust_level,
            kernel_key: body.kernel_key,
            algorithm: None,
            signature,
        })
    }

    /// Sign a receipt body with an arbitrary [`SigningBackend`].
    ///
    /// The `body.kernel_key` must equal `backend.public_key()`.
    pub fn sign_with_backend(body: ArcReceiptBody, backend: &dyn SigningBackend) -> Result<Self> {
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            trust_level: body.trust_level,
            kernel_key: body.kernel_key,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> ArcReceiptBody {
        ArcReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            capability_id: self.capability_id.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            action: self.action.clone(),
            decision: self.decision.clone(),
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: self.evidence.clone(),
            metadata: self.metadata.clone(),
            trust_level: self.trust_level,
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the receipt signature against the embedded kernel key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Whether this receipt records an allow decision.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Whether this receipt records a deny decision.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, Decision::Deny { .. })
    }

    /// Whether this receipt records a cancelled terminal outcome.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.decision, Decision::Cancelled { .. })
    }

    /// Whether this receipt records an incomplete terminal outcome.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        matches!(self.decision, Decision::Incomplete { .. })
    }

    fn typed_metadata<T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.get(key))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
    }

    /// Extract typed financial receipt metadata when present.
    #[must_use]
    pub fn financial_metadata(&self) -> Option<FinancialReceiptMetadata> {
        self.typed_metadata("financial")
    }

    /// Extract typed budget-authority lineage for monetary receipts when present.
    #[must_use]
    pub fn financial_budget_authority_metadata(
        &self,
    ) -> Option<FinancialBudgetAuthorityReceiptMetadata> {
        self.typed_metadata("budget_authority")
    }
}

impl ChildRequestReceipt {
    pub fn sign(body: ChildRequestReceiptBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            session_id: body.session_id,
            parent_request_id: body.parent_request_id,
            request_id: body.request_id,
            operation_kind: body.operation_kind,
            terminal_state: body.terminal_state,
            outcome_hash: body.outcome_hash,
            policy_hash: body.policy_hash,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            algorithm: None,
            signature,
        })
    }

    /// Sign a child-request receipt body with an arbitrary [`SigningBackend`].
    pub fn sign_with_backend(
        body: ChildRequestReceiptBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            session_id: body.session_id,
            parent_request_id: body.parent_request_id,
            request_id: body.request_id,
            operation_kind: body.operation_kind,
            terminal_state: body.terminal_state,
            outcome_hash: body.outcome_hash,
            policy_hash: body.policy_hash,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> ChildRequestReceiptBody {
        ChildRequestReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            session_id: self.session_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            request_id: self.request_id.clone(),
            operation_kind: self.operation_kind,
            terminal_state: self.terminal_state.clone(),
            outcome_hash: self.outcome_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }
}

/// Versioned schema identifier for signed receipt-lineage statements.
pub const ARC_RECEIPT_LINEAGE_STATEMENT_SCHEMA: &str = "arc.receipt_lineage_statement.v1";

fn default_receipt_lineage_evidence_class() -> ProvenanceEvidenceClass {
    ProvenanceEvidenceClass::Verified
}

/// Relation type carried by a receipt-lineage statement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLineageRelationKind {
    LocalChild,
    Continued,
}

/// Signable receipt-lineage statement body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatementBody {
    pub schema: String,
    pub id: String,
    pub parent_receipt_id: String,
    pub child_receipt_id: String,
    pub parent_request_id: RequestId,
    pub child_request_id: RequestId,
    pub parent_session_anchor: SessionAnchorReference,
    pub child_session_anchor: SessionAnchorReference,
    pub relation_kind: ReceiptLineageRelationKind,
    #[serde(default = "default_receipt_lineage_evidence_class")]
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
}

impl ReceiptLineageStatementBody {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        parent_receipt_id: impl Into<String>,
        child_receipt_id: impl Into<String>,
        parent_request_id: RequestId,
        child_request_id: RequestId,
        parent_session_anchor: SessionAnchorReference,
        child_session_anchor: SessionAnchorReference,
        relation_kind: ReceiptLineageRelationKind,
        issued_at: u64,
        kernel_key: PublicKey,
    ) -> Self {
        Self {
            schema: ARC_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            id: id.into(),
            parent_receipt_id: parent_receipt_id.into(),
            child_receipt_id: child_receipt_id.into(),
            parent_request_id,
            child_request_id,
            parent_session_anchor,
            child_session_anchor,
            relation_kind,
            evidence_class: default_receipt_lineage_evidence_class(),
            continuation_token_id: None,
            issued_at,
            kernel_key,
        }
    }

    #[must_use]
    pub fn with_evidence_class(mut self, evidence_class: ProvenanceEvidenceClass) -> Self {
        self.evidence_class = evidence_class;
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }
}

/// Signed linkage statement connecting parent and child receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatement {
    pub schema: String,
    pub id: String,
    pub parent_receipt_id: String,
    pub child_receipt_id: String,
    pub parent_request_id: RequestId,
    pub child_request_id: RequestId,
    pub parent_session_anchor: SessionAnchorReference,
    pub child_session_anchor: SessionAnchorReference,
    pub relation_kind: ReceiptLineageRelationKind,
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

impl ReceiptLineageStatement {
    pub fn sign(body: ReceiptLineageStatementBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            schema: body.schema,
            id: body.id,
            parent_receipt_id: body.parent_receipt_id,
            child_receipt_id: body.child_receipt_id,
            parent_request_id: body.parent_request_id,
            child_request_id: body.child_request_id,
            parent_session_anchor: body.parent_session_anchor,
            child_session_anchor: body.child_session_anchor,
            relation_kind: body.relation_kind,
            evidence_class: body.evidence_class,
            continuation_token_id: body.continuation_token_id,
            issued_at: body.issued_at,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> ReceiptLineageStatementBody {
        ReceiptLineageStatementBody {
            schema: self.schema.clone(),
            id: self.id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            child_receipt_id: self.child_receipt_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            child_request_id: self.child_request_id.clone(),
            parent_session_anchor: self.parent_session_anchor.clone(),
            child_session_anchor: self.child_session_anchor.clone(),
            relation_kind: self.relation_kind,
            evidence_class: self.evidence_class,
            continuation_token_id: self.continuation_token_id.clone(),
            issued_at: self.issued_at,
            kernel_key: self.kernel_key.clone(),
        }
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.evidence_class == ProvenanceEvidenceClass::Verified
    }
}

/// Signed envelope for stable export/report artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignedExportEnvelope<T> {
    /// Unsigned export payload.
    pub body: T,
    /// Public key that signed the export.
    pub signer_key: PublicKey,
    /// Signature over the canonical JSON of `body`.
    pub signature: Signature,
}

impl<T> SignedExportEnvelope<T>
where
    T: Serialize + Clone,
{
    /// Sign an export payload with the provided keypair.
    pub fn sign(body: T, keypair: &Keypair) -> Result<Self> {
        let (signature, _) = keypair.sign_canonical(&body)?;
        Ok(Self {
            body,
            signer_key: keypair.public_key(),
            signature,
        })
    }

    /// Verify the envelope signature against the embedded signer key.
    pub fn verify_signature(&self) -> Result<bool> {
        self.signer_key
            .verify_canonical(&self.body, &self.signature)
    }
}

/// Declared verifier material required to treat a checkpoint publication as
/// trust-anchored rather than local-preview only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointPublicationTrustAnchorBinding {
    /// Typed publication surface identity declared for this publication path.
    pub publication_identity: CheckpointPublicationIdentity,
    /// Typed trust-anchor identity declared for this publication path.
    pub trust_anchor_identity: CheckpointTrustAnchorIdentity,
    /// Stable identifier for the trust anchor that vouches for the publication path.
    pub trust_anchor_ref: String,
    /// Stable identifier for the signer certificate or chain entry used by the publisher.
    pub signer_cert_ref: String,
    /// Versioned publication profile that defines the verifier policy for this path.
    pub publication_profile_version: String,
}

impl CheckpointPublicationTrustAnchorBinding {
    pub fn validate(&self) -> Result<()> {
        fn require_non_empty(value: &str, field: &str) -> Result<()> {
            if value.trim().is_empty() {
                return Err(Error::CanonicalJson(format!(
                    "{field} must not be empty for trust-anchored checkpoint publication"
                )));
            }
            Ok(())
        }

        if !self.publication_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "publication_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        if !self.trust_anchor_identity.has_identity() {
            return Err(Error::CanonicalJson(
                "trust_anchor_identity.identity must not be empty for trust-anchored checkpoint publication"
                    .to_string(),
            ));
        }
        require_non_empty(&self.trust_anchor_ref, "trust_anchor_ref")?;
        require_non_empty(&self.signer_cert_ref, "signer_cert_ref")?;
        require_non_empty(
            &self.publication_profile_version,
            "publication_profile_version",
        )?;
        Ok(())
    }
}

/// The Kernel's verdict on a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    /// The tool call was allowed and executed.
    Allow,
    /// The tool call was denied.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
        /// The guard or validation step that triggered the denial.
        guard: String,
    },
    /// The tool call was interrupted by explicit cancellation.
    Cancelled {
        /// Human-readable reason for the cancellation.
        reason: String,
    },
    /// The tool call did not reach a complete terminal result.
    Incomplete {
        /// Human-readable reason for the incomplete terminal state.
        reason: String,
    },
}

/// Describes the tool call that was evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallAction {
    /// The parameters that were passed to the tool (or attempted).
    pub parameters: serde_json::Value,
    /// SHA-256 hash of the canonical JSON of `parameters`.
    pub parameter_hash: String,
}

impl ToolCallAction {
    /// Construct from raw parameters, computing the hash automatically.
    pub fn from_parameters(parameters: serde_json::Value) -> Result<Self> {
        let canonical = canonical_json_bytes(&parameters)?;
        let hash = sha256_hex(&canonical);
        Ok(Self {
            parameters,
            parameter_hash: hash,
        })
    }

    /// Verify that `parameter_hash` matches the canonical hash of `parameters`.
    pub fn verify_hash(&self) -> Result<bool> {
        let canonical = canonical_json_bytes(&self.parameters)?;
        let expected = sha256_hex(&canonical);
        Ok(self.parameter_hash == expected)
    }
}

/// Evidence from a single guard's evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvidence {
    /// Name of the guard (e.g. "ForbiddenPathGuard").
    pub guard_name: String,
    /// Whether the guard passed (true) or denied (false).
    pub verdict: bool,
    /// Optional details about the guard's decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Financial metadata attached to receipts for monetary grant invocations.
///
/// For allow receipts under a monetary grant, this struct is serialized under
/// the "financial" key in `ArcReceiptBody::metadata`.
///
/// For denial receipts caused by budget exhaustion, `attempted_cost` is
/// populated with the cost that would have been charged.
///
/// # Field Invariants
///
/// Callers constructing this struct must uphold the following invariants:
///
/// - `cost_charged <= budget_total`: the amount charged for a single invocation
///   must not exceed the total budget allocation.
/// - `budget_remaining == budget_total - cost_charged` (approximately): the
///   remaining budget field should reflect the post-charge balance. Due to HA
///   split-brain scenarios, `budget_remaining` may be a best-effort snapshot
///   rather than a strict invariant at read time, but callers must ensure it is
///   computed correctly at write time.
/// - For denial receipts, `cost_charged` should be 0 and `attempted_cost`
///   should hold the cost that was rejected.
///
/// These invariants are not enforced by the type system and must be upheld by
/// the kernel when constructing financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    /// Index of the matching grant in the capability token's scope.
    pub grant_index: u32,
    /// Cost charged for this invocation in currency minor units (e.g. cents for USD).
    pub cost_charged: u64,
    /// ISO 4217 currency code (e.g. "USD").
    pub currency: String,
    /// Remaining budget after this charge, in currency minor units.
    pub budget_remaining: u64,
    /// Total budget for this grant, in currency minor units.
    pub budget_total: u64,
    /// Depth of the delegation chain at the time of invocation.
    pub delegation_depth: u32,
    /// Identifier of the root budget holder in the delegation chain.
    pub root_budget_holder: String,
    /// Optional payment reference for external settlement systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    /// Settlement status for this charge.
    pub settlement_status: SettlementStatus,
    /// Optional itemized cost breakdown for audit purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
    /// Oracle price evidence used for cross-currency conversion, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_evidence: Option<OracleConversionEvidence>,
    /// Cost that was attempted but denied (populated only on denial receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
}

/// Authority identity bound to a budget hold lineage record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetHoldAuthorityMetadata {
    pub authority_id: String,
    pub lease_id: String,
    pub lease_epoch: u64,
}

/// Authorize event lineage preserved on a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetAuthorizeReceiptMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_commit_index: Option<u64>,
    pub exposure_units: u64,
    pub committed_cost_units_after: u64,
}

/// Terminal hold mutation lineage preserved on a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetTerminalReceiptMetadata {
    pub disposition: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_commit_index: Option<u64>,
    pub exposure_units: u64,
    pub realized_spend_units: u64,
    pub committed_cost_units_after: u64,
}

/// Explicit budget hold lineage and guarantee data attached to a financial receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinancialBudgetAuthorityReceiptMetadata {
    pub guarantee_level: String,
    pub authority_profile: String,
    pub metering_profile: String,
    pub hold_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<FinancialBudgetHoldAuthorityMetadata>,
    pub authorize: FinancialBudgetAuthorizeReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<FinancialBudgetTerminalReceiptMetadata>,
}

/// Canonical settlement states for receipt-side financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    /// No external settlement applies to this receipt (for example, a pre-execution denial).
    NotApplicable,
    /// Settlement has been initiated but is not yet final.
    Pending,
    /// The recorded charge is final for the current execution path.
    Settled,
    /// Execution completed, but settlement failed or became invalid.
    Failed,
}

/// Approval evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernedApprovalReceiptMetadata {
    /// Approval token identifier.
    pub token_id: String,
    /// Hex-encoded approver public key.
    pub approver_key: String,
    /// Whether the token represented a positive approval.
    pub approved: bool,
}

/// Runtime assurance evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAssuranceReceiptMetadata {
    /// Schema or format identifier of the attestation evidence ARC accepted.
    pub schema: String,
    /// Optional verifier family recognized by ARC's canonical appraisal boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    /// Normalized assurance tier accepted for the request.
    pub tier: RuntimeAssuranceTier,
    /// Verifier or relying party that accepted the upstream evidence.
    pub verifier: String,
    /// Stable digest of the attestation payload.
    pub evidence_sha256: String,
    /// Optional normalized workload identity resolved from the attestation evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

/// Commerce approval evidence attached to a governed-transaction receipt block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernedCommerceReceiptMetadata {
    /// Seller or payee identifier the approval was scoped to.
    pub seller: String,
    /// Shared payment token or equivalent external commerce approval reference.
    pub shared_payment_token_id: String,
}

/// Optional post-execution usage evidence attached to metered-billing receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredUsageEvidenceReceiptMetadata {
    /// Evidence adapter or source kind that produced the usage record.
    pub evidence_kind: String,
    /// Stable identifier of the usage record in the external billing system.
    pub evidence_id: String,
    /// Observed billable units reported after execution.
    pub observed_units: u64,
    /// Stable digest of the external usage payload when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
}

/// Metered-billing quote and evidence context preserved on governed receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReceiptMetadata {
    /// Settlement posture attached to the governed request.
    pub settlement_mode: MeteredSettlementMode,
    /// Pre-execution metered quote bound into the governed intent.
    pub quote: MeteredBillingQuote,
    /// Optional explicit upper bound on billable units for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
    /// Optional post-execution usage evidence preserved separately from receipt truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_evidence: Option<MeteredUsageEvidenceReceiptMetadata>,
}

/// Explicit autonomy and delegation-bond context preserved on governed receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAutonomyReceiptMetadata {
    /// Requested autonomy tier for this governed action.
    pub tier: GovernedAutonomyTier,
    /// Optional signed delegation-bond artifact bound to the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_bond_id: Option<String>,
}

/// Governed transaction metadata attached to receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernedTransactionReceiptMetadata {
    /// Governed transaction intent identifier.
    pub intent_id: String,
    /// Canonical intent hash used for approval-token binding.
    pub intent_hash: String,
    /// Human or policy-readable purpose.
    pub purpose: String,
    /// Target tool server from the intent.
    pub server_id: String,
    /// Target tool name from the intent.
    pub tool_name: String,
    /// Optional explicit spend bound carried on the intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    /// Optional seller-scoped commerce approval evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedCommerceReceiptMetadata>,
    /// Optional metered-billing quote and usage evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<MeteredBillingReceiptMetadata>,
    /// Optional approval evidence that accompanied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<GovernedApprovalReceiptMetadata>,
    /// Optional runtime assurance evidence that accompanied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<RuntimeAssuranceReceiptMetadata>,
    /// Optional delegated call-chain provenance bound through the governed intent hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainProvenance>,
    /// Optional autonomy tier and delegation-bond attachment bound through the governed intent hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy: Option<GovernedAutonomyReceiptMetadata>,
}

impl GovernedTransactionReceiptMetadata {
    #[must_use]
    pub fn asserted_call_chain(&self) -> Option<&GovernedCallChainContext> {
        self.call_chain
            .as_ref()
            .and_then(GovernedCallChainProvenance::asserted_context)
    }

    #[must_use]
    pub fn verified_call_chain(&self) -> Option<&GovernedCallChainContext> {
        self.call_chain
            .as_ref()
            .and_then(GovernedCallChainProvenance::verified_context)
    }
}

/// Declared publication surface family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointPublicationIdentityKind {
    LocalLog,
    TransparencyService,
    ImmutableRecord,
    ChainAnchor,
}

/// Optional typed publication identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPublicationIdentity {
    pub kind: CheckpointPublicationIdentityKind,
    pub identity: String,
}

impl CheckpointPublicationIdentity {
    #[must_use]
    pub fn new(kind: CheckpointPublicationIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}

/// Declared trust-anchor family for a checkpoint publication record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointTrustAnchorIdentityKind {
    OperatorRoot,
    Did,
    X509Root,
    TransparencyRoot,
    ChainRoot,
}

/// Optional typed trust-anchor identity carried alongside a checkpoint record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointTrustAnchorIdentity {
    pub kind: CheckpointTrustAnchorIdentityKind,
    pub identity: String,
}

impl CheckpointTrustAnchorIdentity {
    #[must_use]
    pub fn new(kind: CheckpointTrustAnchorIdentityKind, identity: impl Into<String>) -> Self {
        Self {
            kind,
            identity: identity.into(),
        }
    }

    #[must_use]
    pub fn has_identity(&self) -> bool {
        !self.identity.trim().is_empty()
    }
}

/// Universal receipt-side attribution for capability context.
///
/// This metadata gives downstream analytics a deterministic local join path
/// from a receipt to the capability subject and, when available, the matched
/// grant within the capability scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAttributionMetadata {
    /// Hex-encoded subject public key of the capability holder.
    pub subject_key: String,
    /// Hex-encoded issuer public key of the capability issuer.
    pub issuer_key: String,
    /// Delegation depth of the capability used for this receipt.
    pub delegation_depth: u32,
    /// Index of the matched grant when the request resolved to a specific grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_index: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn make_action() -> ToolCallAction {
        ToolCallAction::from_parameters(serde_json::json!({
            "path": "/app/src/main.rs"
        }))
        .unwrap()
    }

    fn make_receipt_body(kp: &Keypair) -> ArcReceiptBody {
        ArcReceiptBody {
            id: "rcpt-001".to_string(),
            timestamp: 1710000000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action: make_action(),
            decision: Decision::Allow,
            content_hash: sha256_hex(br#"{"ok":true}"#),
            policy_hash: "abc123def456".to_string(),
            evidence: vec![
                GuardEvidence {
                    guard_name: "ForbiddenPathGuard".to_string(),
                    verdict: true,
                    details: None,
                },
                GuardEvidence {
                    guard_name: "SecretLeakGuard".to_string(),
                    verdict: true,
                    details: Some("no secrets detected".to_string()),
                },
            ],
            metadata: Some(serde_json::json!({
                "sandbox": {
                    "enforced": true
                }
            })),
            trust_level: TrustLevel::default(),
            kernel_key: kp.public_key(),
        }
    }

    fn make_child_receipt_body(kp: &Keypair) -> ChildRequestReceiptBody {
        ChildRequestReceiptBody {
            id: "child-rcpt-001".to_string(),
            timestamp: 1710000001,
            session_id: SessionId::new("sess-001"),
            parent_request_id: RequestId::new("parent-001"),
            request_id: RequestId::new("child-001"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
            policy_hash: "abc123def456".to_string(),
            metadata: Some(serde_json::json!({
                "outcome": "result"
            })),
            kernel_key: kp.public_key(),
        }
    }

    #[test]
    fn receipt_sign_and_verify() {
        let kp = Keypair::generate();
        let body = make_receipt_body(&kp);
        let receipt = ArcReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn signed_export_envelope_roundtrip() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct ExampleExport {
            schema: String,
            exported_at: u64,
        }

        let kp = Keypair::generate();
        let export = ExampleExport {
            schema: "arc.example-export.v1".to_string(),
            exported_at: 1_710_000_000,
        };
        let envelope = SignedExportEnvelope::sign(export.clone(), &kp).unwrap();
        assert_eq!(envelope.body, export);
        assert!(envelope.verify_signature().unwrap());
    }

    #[test]
    fn receipt_deny_decision() {
        let kp = Keypair::generate();
        let body = ArcReceiptBody {
            decision: Decision::Deny {
                reason: "path /etc/passwd is forbidden".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = ArcReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_denied());
        assert!(!receipt.is_allowed());
    }

    #[test]
    fn receipt_cancelled_decision() {
        let kp = Keypair::generate();
        let body = ArcReceiptBody {
            decision: Decision::Cancelled {
                reason: "cancelled by user".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = ArcReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_cancelled());
        assert!(!receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn receipt_incomplete_decision() {
        let kp = Keypair::generate();
        let body = ArcReceiptBody {
            decision: Decision::Incomplete {
                reason: "stream terminated before final frame".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = ArcReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_incomplete());
        assert!(!receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = make_receipt_body(&kp);
        let receipt = ArcReceipt::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let restored: ArcReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.id, restored.id);
        assert_eq!(receipt.capability_id, restored.capability_id);
        assert_eq!(receipt.tool_name, restored.tool_name);
        assert_eq!(receipt.content_hash, restored.content_hash);
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn receipt_wrong_key_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        // Body claims kernel_key is other_kp but we sign with kp
        let body = ArcReceiptBody {
            kernel_key: other_kp.public_key(),
            ..make_receipt_body(&kp)
        };
        let receipt = ArcReceipt::sign(body, &kp).unwrap();
        // Verify against embedded kernel_key (other_kp) should fail
        assert!(!receipt.verify_signature().unwrap());
    }

    #[test]
    fn tool_call_action_hash_verification() {
        let action = make_action();
        assert!(action.verify_hash().unwrap());
    }

    #[test]
    fn tool_call_action_tampered_hash() {
        let mut action = make_action();
        action.parameter_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!action.verify_hash().unwrap());
    }

    #[test]
    fn decision_serde_roundtrip() {
        let allow = Decision::Allow;
        let json = serde_json::to_string(&allow).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(allow, restored);

        let deny = Decision::Deny {
            reason: "forbidden".to_string(),
            guard: "TestGuard".to_string(),
        };
        let json = serde_json::to_string(&deny).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(deny, restored);

        let cancelled = Decision::Cancelled {
            reason: "cancelled by client".to_string(),
        };
        let json = serde_json::to_string(&cancelled).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(cancelled, restored);

        let incomplete = Decision::Incomplete {
            reason: "stream ended early".to_string(),
        };
        let json = serde_json::to_string(&incomplete).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(incomplete, restored);
    }

    #[test]
    fn guard_evidence_serde_roundtrip() {
        let evidence = vec![
            GuardEvidence {
                guard_name: "Guard1".to_string(),
                verdict: true,
                details: None,
            },
            GuardEvidence {
                guard_name: "Guard2".to_string(),
                verdict: false,
                details: Some("blocked".to_string()),
            },
        ];

        let json = serde_json::to_string_pretty(&evidence).unwrap();
        let restored: Vec<GuardEvidence> = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence.len(), restored.len());
        assert_eq!(evidence[0].guard_name, restored[0].guard_name);
        assert_eq!(evidence[1].details, restored[1].details);
    }

    #[test]
    fn child_receipt_sign_and_verify() {
        let kp = Keypair::generate();
        let body = make_child_receipt_body(&kp);
        let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(receipt.request_id, RequestId::new("child-001"));
    }

    #[test]
    fn financial_receipt_metadata_serde_roundtrip() {
        let meta = FinancialReceiptMetadata {
            grant_index: 2,
            cost_charged: 150,
            currency: "USD".to_string(),
            budget_remaining: 850,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: Some("ref-abc123".to_string()),
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: Some(serde_json::json!({"compute": 100, "io": 50})),
            oracle_evidence: None,
            attempted_cost: None,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let restored: FinancialReceiptMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(meta.grant_index, restored.grant_index);
        assert_eq!(meta.cost_charged, restored.cost_charged);
        assert_eq!(meta.currency, restored.currency);
        assert_eq!(meta.budget_remaining, restored.budget_remaining);
        assert_eq!(meta.budget_total, restored.budget_total);
        assert_eq!(meta.delegation_depth, restored.delegation_depth);
        assert_eq!(meta.root_budget_holder, restored.root_budget_holder);
        assert_eq!(meta.settlement_status, restored.settlement_status);
        assert_eq!(meta.payment_reference, restored.payment_reference);
        assert!(restored.attempted_cost.is_none());
    }

    #[test]
    fn financial_receipt_metadata_under_financial_key() {
        let meta = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 200,
            currency: "USD".to_string(),
            budget_remaining: 800,
            budget_total: 1000,
            delegation_depth: 0,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };

        let wrapped = serde_json::json!({"financial": meta});
        let extracted: FinancialReceiptMetadata =
            serde_json::from_value(wrapped["financial"].clone()).unwrap();
        assert_eq!(extracted.cost_charged, 200);
        assert_eq!(extracted.settlement_status, SettlementStatus::Settled);
    }

    #[test]
    fn financial_receipt_metadata_attempted_cost_optional() {
        // With attempted_cost Some: field present in JSON
        let meta_with = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 0,
            currency: "USD".to_string(),
            budget_remaining: 0,
            budget_total: 1000,
            delegation_depth: 0,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::NotApplicable,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(500),
        };
        let json_with = serde_json::to_string(&meta_with).unwrap();
        assert!(json_with.contains("attempted_cost"));

        // Without attempted_cost: field absent from JSON
        let meta_without = FinancialReceiptMetadata {
            attempted_cost: None,
            ..meta_with
        };
        let json_without = serde_json::to_string(&meta_without).unwrap();
        assert!(!json_without.contains("attempted_cost"));
    }

    #[test]
    fn financial_budget_authority_metadata_serde_roundtrip() {
        let metadata = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "authoritative_hold_event".to_string(),
            metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
            hold_id: "budget-hold:req-1:cap-1:0".to_string(),
            budget_term: Some("http://leader-a:7".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-a".to_string(),
                lease_id: "http://leader-a#term-7".to_string(),
                lease_epoch: 7,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("budget-hold:req-1:cap-1:0:authorize".to_string()),
                budget_commit_index: Some(41),
                exposure_units: 120,
                committed_cost_units_after: 120,
            },
            terminal: Some(FinancialBudgetTerminalReceiptMetadata {
                disposition: "reconciled".to_string(),
                event_id: Some("budget-hold:req-1:cap-1:0:reconcile".to_string()),
                budget_commit_index: Some(42),
                exposure_units: 120,
                realized_spend_units: 75,
                committed_cost_units_after: 75,
            }),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let restored: FinancialBudgetAuthorityReceiptMetadata =
            serde_json::from_str(&json).unwrap();

        assert_eq!(restored, metadata);
    }

    #[test]
    fn checkpoint_publication_trust_anchor_binding_serde_and_validation() {
        let binding = CheckpointPublicationTrustAnchorBinding {
            publication_identity: CheckpointPublicationIdentity::new(
                CheckpointPublicationIdentityKind::TransparencyService,
                "transparency.example/checkpoints/7",
            ),
            trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
                CheckpointTrustAnchorIdentityKind::Did,
                "did:arc:operator-root",
            ),
            trust_anchor_ref: "arc_checkpoint_witness_chain".to_string(),
            signer_cert_ref: "did:web:arc.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        };

        let json = serde_json::to_string(&binding).unwrap();
        let restored: CheckpointPublicationTrustAnchorBinding =
            serde_json::from_str(&json).unwrap();

        restored.validate().unwrap();
        assert_eq!(restored, binding);
    }

    #[test]
    fn checkpoint_publication_trust_anchor_binding_rejects_blank_fields() {
        let error = CheckpointPublicationTrustAnchorBinding {
            publication_identity: CheckpointPublicationIdentity::new(
                CheckpointPublicationIdentityKind::TransparencyService,
                "",
            ),
            trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
                CheckpointTrustAnchorIdentityKind::Did,
                "did:arc:operator-root",
            ),
            trust_anchor_ref: " ".to_string(),
            signer_cert_ref: "did:web:arc.example#checkpoint-signer".to_string(),
            publication_profile_version: "phase4-preview.v1".to_string(),
        }
        .validate()
        .expect_err("blank trust anchor must be rejected");
        assert!(error.to_string().contains("publication_identity.identity"));
    }

    #[test]
    fn arc_receipt_extracts_typed_financial_and_budget_authority_metadata() {
        let kp = Keypair::generate();
        let financial = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 75,
            currency: "USD".to_string(),
            budget_remaining: 925,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "authoritative_hold_event".to_string(),
            metering_profile: "max_cost_preauthorize_then_reconcile_actual".to_string(),
            hold_id: "budget-hold:req-1:cap-1:0".to_string(),
            budget_term: Some("http://leader-a:7".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-a".to_string(),
                lease_id: "http://leader-a#term-7".to_string(),
                lease_epoch: 7,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("budget-hold:req-1:cap-1:0:authorize".to_string()),
                budget_commit_index: Some(41),
                exposure_units: 120,
                committed_cost_units_after: 120,
            },
            terminal: Some(FinancialBudgetTerminalReceiptMetadata {
                disposition: "reconciled".to_string(),
                event_id: Some("budget-hold:req-1:cap-1:0:reconcile".to_string()),
                budget_commit_index: Some(42),
                exposure_units: 120,
                realized_spend_units: 75,
                committed_cost_units_after: 75,
            }),
        };
        let receipt = ArcReceipt::sign(
            ArcReceiptBody {
                metadata: Some(serde_json::json!({
                    "financial": financial.clone(),
                    "budget_authority": budget_authority.clone(),
                })),
                ..make_receipt_body(&kp)
            },
            &kp,
        )
        .unwrap();

        let extracted_financial = receipt
            .financial_metadata()
            .expect("extract financial metadata");
        assert_eq!(extracted_financial.grant_index, financial.grant_index);
        assert_eq!(extracted_financial.cost_charged, financial.cost_charged);
        assert_eq!(extracted_financial.currency, financial.currency);
        assert_eq!(
            extracted_financial.budget_remaining,
            financial.budget_remaining
        );
        assert_eq!(extracted_financial.budget_total, financial.budget_total);
        assert_eq!(
            extracted_financial.root_budget_holder,
            financial.root_budget_holder
        );
        assert_eq!(
            receipt.financial_budget_authority_metadata(),
            Some(budget_authority)
        );
    }

    #[test]
    fn settlement_status_serde_roundtrip() {
        let status = SettlementStatus::Failed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"failed\"");
        let restored: SettlementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, SettlementStatus::Failed);
    }

    #[test]
    fn governed_transaction_receipt_metadata_serde_roundtrip() {
        let proof_signer = Keypair::generate();
        let proof_subject = Keypair::generate();
        let metadata = GovernedTransactionReceiptMetadata {
            intent_id: "intent-1".to_string(),
            intent_hash: "intent-hash".to_string(),
            purpose: "pay supplier".to_string(),
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            max_amount: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            commerce: Some(GovernedCommerceReceiptMetadata {
                seller: "merchant.example".to_string(),
                shared_payment_token_id: "spt_123".to_string(),
            }),
            metered_billing: Some(MeteredBillingReceiptMetadata {
                settlement_mode: MeteredSettlementMode::AllowThenSettle,
                quote: MeteredBillingQuote {
                    quote_id: "quote-1".to_string(),
                    provider: "meter.arc".to_string(),
                    billing_unit: "1k_tokens".to_string(),
                    quoted_units: 10,
                    quoted_cost: MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    },
                    issued_at: 1000,
                    expires_at: Some(1600),
                },
                max_billed_units: Some(12),
                usage_evidence: Some(MeteredUsageEvidenceReceiptMetadata {
                    evidence_kind: "billing_export".to_string(),
                    evidence_id: "usage-1".to_string(),
                    observed_units: 9,
                    evidence_sha256: Some("usage-digest".to_string()),
                }),
            }),
            approval: Some(GovernedApprovalReceiptMetadata {
                token_id: "approval-1".to_string(),
                approver_key: "approver-key".to_string(),
                approved: true,
            }),
            runtime_assurance: Some(RuntimeAssuranceReceiptMetadata {
                schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                tier: RuntimeAssuranceTier::Attested,
                verifier: "verifier.arc".to_string(),
                evidence_sha256: "attestation-digest".to_string(),
                workload_identity: None,
            }),
            call_chain: Some(
                GovernedCallChainProvenance::observed(
                    crate::capability::GovernedCallChainContext {
                        chain_id: "chain-1".to_string(),
                        parent_request_id: "req-parent-1".to_string(),
                        parent_receipt_id: Some("rc-parent-1".to_string()),
                        origin_subject: "origin-subject".to_string(),
                        delegator_subject: "delegator-subject".to_string(),
                    },
                )
                .with_upstream_proof(
                    crate::capability::GovernedUpstreamCallChainProof::sign(
                        crate::capability::GovernedUpstreamCallChainProofBody {
                            signer: proof_signer.public_key(),
                            subject: proof_subject.public_key(),
                            chain_id: "chain-1".to_string(),
                            parent_request_id: "req-parent-1".to_string(),
                            parent_receipt_id: Some("rc-parent-1".to_string()),
                            origin_subject: "origin-subject".to_string(),
                            delegator_subject: "delegator-subject".to_string(),
                            issued_at: 1000,
                            expires_at: 1600,
                        },
                        &proof_signer,
                    )
                    .unwrap(),
                )
                .with_evidence_sources([
                    crate::capability::GovernedCallChainEvidenceSource::SessionParentRequestLineage,
                    crate::capability::GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
                    crate::capability::GovernedCallChainEvidenceSource::UpstreamDelegatorProof,
                ]),
            ),
            autonomy: Some(GovernedAutonomyReceiptMetadata {
                tier: GovernedAutonomyTier::Delegated,
                delegation_bond_id: Some("bond-1".to_string()),
            }),
        };

        let json = serde_json::to_string(&serde_json::json!({
            "governed_transaction": metadata.clone()
        }))
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let restored: GovernedTransactionReceiptMetadata =
            serde_json::from_value(value["governed_transaction"].clone()).unwrap();
        assert_eq!(restored, metadata);
    }

    #[test]
    fn receipt_lineage_statement_sign_and_verify() {
        let kp = Keypair::generate();
        let body = ReceiptLineageStatementBody::new(
            "statement-1",
            "receipt-parent-1",
            "receipt-child-1",
            RequestId::new("req-parent-1"),
            RequestId::new("req-child-1"),
            SessionAnchorReference::new("anchor-parent-1", "anchor-parent-hash-1"),
            SessionAnchorReference::new("anchor-child-1", "anchor-child-hash-1"),
            ReceiptLineageRelationKind::Continued,
            1_710_000_000,
            kp.public_key(),
        )
        .with_continuation_token_id("continuation-1");
        let statement = ReceiptLineageStatement::sign(body, &kp).unwrap();
        let encoded = serde_json::to_string(&statement).unwrap();
        let decoded: ReceiptLineageStatement = serde_json::from_str(&encoded).unwrap();

        assert!(decoded.verify_signature().unwrap());
        assert!(decoded.is_verified());
        assert_eq!(decoded.parent_receipt_id, "receipt-parent-1");
        assert_eq!(decoded.child_receipt_id, "receipt-child-1");
        assert_eq!(
            decoded.continuation_token_id.as_deref(),
            Some("continuation-1")
        );
    }

    #[test]
    fn governed_transaction_receipt_metadata_helpers_split_asserted_and_verified_call_chain() {
        let asserted_context = crate::capability::GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-asserted".to_string(),
            delegator_subject: "delegator-asserted".to_string(),
        };
        let verified_context = crate::capability::GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rc-parent-1".to_string()),
            origin_subject: "origin-verified".to_string(),
            delegator_subject: "delegator-verified".to_string(),
        };
        let metadata = GovernedTransactionReceiptMetadata {
            intent_id: "intent-1".to_string(),
            intent_hash: "intent-hash".to_string(),
            purpose: "pay supplier".to_string(),
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            approval: None,
            runtime_assurance: None,
            call_chain: Some(
                crate::capability::GovernedCallChainProvenance::verified(verified_context.clone())
                    .with_asserted_context(asserted_context.clone()),
            ),
            autonomy: None,
        };

        assert_eq!(metadata.asserted_call_chain(), Some(&asserted_context));
        assert_eq!(metadata.verified_call_chain(), Some(&verified_context));
    }

    #[test]
    fn receipt_attribution_metadata_serde_roundtrip() {
        let metadata = ReceiptAttributionMetadata {
            subject_key: "subject-key".to_string(),
            issuer_key: "issuer-key".to_string(),
            delegation_depth: 2,
            grant_index: Some(1),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let restored: ReceiptAttributionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, metadata);
    }

    #[test]
    fn checkpoint_publication_and_trust_anchor_identities_roundtrip() {
        let publication_identity = CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::TransparencyService,
            "transparency.example/checkpoints/7",
        );
        let trust_anchor_identity = CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::Did,
            "did:arc:operator-root",
        );

        assert!(publication_identity.has_identity());
        assert!(trust_anchor_identity.has_identity());

        let encoded = serde_json::to_string(&serde_json::json!({
            "publication_identity": publication_identity.clone(),
            "trust_anchor_identity": trust_anchor_identity.clone(),
        }))
        .unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let restored_publication: CheckpointPublicationIdentity =
            serde_json::from_value(decoded["publication_identity"].clone()).unwrap();
        let restored_trust_anchor: CheckpointTrustAnchorIdentity =
            serde_json::from_value(decoded["trust_anchor_identity"].clone()).unwrap();

        assert_eq!(restored_publication, publication_identity);
        assert_eq!(restored_trust_anchor, trust_anchor_identity);
    }

    #[test]
    fn child_receipt_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = make_child_receipt_body(&kp);
        let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let restored: ChildRequestReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.id, restored.id);
        assert_eq!(receipt.parent_request_id, restored.parent_request_id);
        assert_eq!(receipt.outcome_hash, restored.outcome_hash);
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn ed25519_receipt_is_byte_identical_without_algorithm_field() {
        // Back-compat: a standard Ed25519 receipt must still serialize
        // without any `algorithm` envelope field. Persisted receipts from
        // earlier ARC releases decode cleanly (the `algorithm` field is
        // `#[serde(default)]`) and verify through the unchanged path.
        let kp = Keypair::generate();
        let receipt = ArcReceipt::sign(make_receipt_body(&kp), &kp).unwrap();
        let value = serde_json::to_value(&receipt).unwrap();
        assert!(
            value.get("algorithm").is_none(),
            "Ed25519 receipts must omit the `algorithm` envelope field"
        );
        // Simulate an old on-disk receipt by stripping any algorithm field we
        // might later add and ensure it still verifies.
        let wire = serde_json::to_string(&receipt).unwrap();
        let restored: ArcReceipt = serde_json::from_str(&wire).unwrap();
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn legacy_ed25519_receipt_without_algorithm_field_still_verifies() {
        // Generate an Ed25519 receipt, then assert that parsing its JSON (which
        // has no `algorithm` key) produces a receipt whose `algorithm` is
        // `None` and whose signature still verifies.
        let kp = Keypair::generate();
        let receipt = ArcReceipt::sign(make_receipt_body(&kp), &kp).unwrap();
        let wire = serde_json::to_string(&receipt).unwrap();
        assert!(!wire.contains("\"algorithm\""));
        let restored: ArcReceipt = serde_json::from_str(&wire).unwrap();
        assert!(restored.algorithm.is_none());
        assert!(restored.verify_signature().unwrap());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn receipt_signs_and_verifies_under_p256_backend() {
        use crate::crypto::{P256Backend, SigningAlgorithm, SigningBackend};
        let backend = P256Backend::generate().expect("p256 backend");
        let mut body = make_receipt_body(&Keypair::generate());
        body.kernel_key = backend.public_key();
        let receipt = ArcReceipt::sign_with_backend(body, &backend).unwrap();
        assert_eq!(receipt.algorithm, Some(SigningAlgorithm::P256));
        assert!(receipt.verify_signature().unwrap());
        // And through the wire.
        let wire = serde_json::to_string(&receipt).unwrap();
        assert!(wire.contains("\"p256:"));
        let restored: ArcReceipt = serde_json::from_str(&wire).unwrap();
        assert!(restored.verify_signature().unwrap());
    }
}
