//! Portable evidence export model: the bundle, its records, the signed
//! package manifest and the read boundary an export was taken under.
//!
//! Every type here is pure data plus checks that need no store, clock or
//! network, so offline verifiers decode and check bundles without the hosted
//! kernel.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::canonical::{UntrustedJsonError, UntrustedJsonText};
use crate::capability::{scope::ChioScope, token::CapabilityToken};
use crate::crypto::{PublicKey, Signature};
use crate::receipt::body::ChioReceipt;
use crate::receipt::checkpoint::{
    CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};
use crate::receipt::lineage::{ChildRequestReceipt, SignedExportEnvelope};

pub const EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA: &str = "chio.evidence_transparency_claims.v1";
pub const EVIDENCE_EXPORT_MANIFEST_SCHEMA: &str = "chio.evidence_export_manifest.v1";
pub const EVIDENCE_EXPORT_COMMITMENT_SCHEMA: &str = "chio.evidence_export_commitment.v1";
pub const EVIDENCE_DISCLOSURE_NOTICE_SCHEMA: &str = "chio.evidence_export_disclosure_notice.v1";
pub const FEDERATION_POLICY_SCHEMA: &str = "chio.federation-policy.v1";
pub const FEDERATED_EVIDENCE_SHARE_SCHEMA: &str = "chio.federated-evidence-share.v1";

/// Bound on one capability snapshot's serialized scope.
const MAX_SNAPSHOT_SCOPE_BYTES: usize = 64 * 1024 * 1024;

/// Explicit receipt read boundary for query, export, and report surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ReceiptReadBoundary {
    /// Caller has explicit administrative access to all receipt rows.
    AdminAll,
    /// Caller is scoped to a single authenticated tenant.
    TenantScoped { tenant: String },
}

impl ReceiptReadBoundary {
    #[must_use]
    pub fn tenant_scoped(tenant: impl Into<String>) -> Self {
        Self::TenantScoped {
            tenant: tenant.into(),
        }
    }
}

/// An export query whose read boundary is missing or inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReadBoundaryError(pub String);

impl fmt::Display for EvidenceReadBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "receipt read boundary error: {}", self.0)
    }
}

impl core::error::Error for EvidenceReadBoundaryError {}

/// Full-export query used for offline evidence packaging.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// Multi-tenant receipt isolation: restrict the export to a single tenant
    /// so exported evidence bundles carry the tenant tag end-to-end. MUST be
    /// derived from the operator's authenticated tenant claim; callers MUST
    /// NOT let the agent choose this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Explicit read boundary for receipt export. Local exports must not infer
    /// admin scope from an omitted tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_boundary: Option<ReceiptReadBoundary>,
}

impl EvidenceExportQuery {
    #[must_use]
    pub fn admin_all() -> Self {
        Self {
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn tenant_scoped(tenant: impl Into<String>) -> Self {
        let tenant = tenant.into();
        Self {
            tenant: Some(tenant.clone()),
            read_boundary: Some(ReceiptReadBoundary::TenantScoped { tenant }),
            ..Self::default()
        }
    }

    pub fn validate_read_boundary(&self) -> Result<(), EvidenceReadBoundaryError> {
        match &self.read_boundary {
            Some(ReceiptReadBoundary::AdminAll) => {
                if self
                    .tenant
                    .as_deref()
                    .is_some_and(|tenant| tenant.trim().is_empty())
                {
                    return Err(EvidenceReadBoundaryError(
                        "admin-all evidence export tenant filter requires a non-empty tenant"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
                let tenant = tenant.trim();
                if tenant.is_empty() {
                    return Err(EvidenceReadBoundaryError(
                        "tenant-scoped evidence export requires a non-empty tenant".to_string(),
                    ));
                }
                if self
                    .tenant
                    .as_deref()
                    .is_some_and(|query_tenant| query_tenant != tenant)
                {
                    return Err(EvidenceReadBoundaryError(
                        "tenant-scoped evidence export tenant does not match query tenant"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            None => Err(EvidenceReadBoundaryError(
                "evidence export requires an explicit receipt read boundary".to_string(),
            )),
        }
    }

    #[must_use]
    pub fn normalized_for_read_boundary(&self) -> Self {
        let mut normalized = self.clone();
        if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &self.read_boundary {
            normalized.tenant = Some(tenant.clone());
        }
        normalized
    }

    /// The tenant receipts must carry: the scoped boundary's tenant, else the
    /// query's own tenant filter.
    #[must_use]
    pub fn effective_tenant_filter(&self) -> Option<String> {
        match &self.read_boundary {
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => Some(tenant.clone()),
            _ => self.tenant.clone(),
        }
    }

    fn has_subject_or_capability_scope(&self) -> bool {
        self.capability_id.is_some() || self.agent_subject.is_some()
    }

    fn has_time_window(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    #[must_use]
    pub fn child_receipt_scope(&self) -> EvidenceChildReceiptScope {
        if self
            .effective_tenant_filter()
            .as_deref()
            .is_some_and(|tenant| !tenant.trim().is_empty())
        {
            return EvidenceChildReceiptScope::OmittedNoJoinPath;
        }
        if matches!(
            self.read_boundary,
            Some(ReceiptReadBoundary::TenantScoped { .. })
        ) {
            return EvidenceChildReceiptScope::OmittedNoJoinPath;
        }
        if self.has_subject_or_capability_scope() {
            if self.has_time_window() {
                EvidenceChildReceiptScope::TimeWindowContextOnly
            } else {
                EvidenceChildReceiptScope::OmittedNoJoinPath
            }
        } else {
            EvidenceChildReceiptScope::FullQueryWindow
        }
    }
}

/// Coverage mode for child receipts in an export bundle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChildReceiptScope {
    /// All child receipts matching the query window are included.
    FullQueryWindow,
    /// Child receipts are included only as time-window context because there is
    /// no capability/agent join path for them yet.
    TimeWindowContextOnly,
    /// Child receipts are omitted because the export was capability/agent scoped
    /// without a capability/agent join path or time-window fallback.
    OmittedNoJoinPath,
}

/// Lineage reference slots that outward report and export surfaces populate
/// when provenance artifacts are first-class records.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceLineageReferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_lineage_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_lineage_statement_id: Option<String>,
}

impl EvidenceLineageReferences {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.session_anchor_id.is_none()
            && self.request_lineage_id.is_none()
            && self.receipt_lineage_statement_id.is_none()
    }
}

/// Tool receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceToolReceiptRecord {
    pub seq: u64,
    pub receipt: ChioReceipt,
}

/// Child receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceChildReceiptRecord {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

/// Receipt that was exported but does not currently have checkpoint coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceUncheckpointedReceipt {
    pub seq: u64,
    pub receipt_id: String,
}

/// Live-database retention state captured at export time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRetentionMetadata {
    #[serde(default)]
    pub live_db_size_bytes: Option<u64>,
    #[serde(default)]
    pub oldest_live_receipt_timestamp: Option<u64>,
}

/// Audit-only claims that can be made from a local evidence export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceAuditClaims {
    pub checkpoint_logs: Vec<String>,
    pub signed_checkpoints: u64,
    pub checkpoint_publications: u64,
    pub checkpoint_witnesses: u64,
    pub checkpoint_consistency_proofs: u64,
    pub inclusion_proofs: u64,
    pub capability_lineage_records: u64,
}

/// Transparency materials that remain preview-only without a trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceTransparencyPreviewClaim {
    pub log_id: String,
    pub claim: String,
    pub reason: String,
    pub checkpoint_count: u64,
    pub witness_count: u64,
    pub consistency_proof_count: u64,
    pub log_tree_size: u64,
}

/// Explicit publication state for bundled checkpoint claims.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePublicationState {
    #[default]
    TransparencyPreview,
    TrustAnchored,
}

impl EvidencePublicationState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransparencyPreview => "transparency_preview",
            Self::TrustAnchored => "trust_anchored",
        }
    }
}

/// Stable outward separation between audit claims and transparency-preview claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceTransparencyClaims {
    pub schema: String,
    #[serde(default)]
    pub publication_state: EvidencePublicationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor: Option<String>,
    pub audit: EvidenceAuditClaims,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transparency_preview: Vec<EvidenceTransparencyPreviewClaim>,
}

impl EvidenceTransparencyClaims {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA {
            return Err(format!(
                "unsupported transparency claims schema: expected {}, got {}",
                EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA, self.schema
            ));
        }
        let trust_anchor = self
            .trust_anchor
            .as_deref()
            .map(str::trim)
            .filter(|anchor| !anchor.is_empty());
        match self.publication_state {
            EvidencePublicationState::TransparencyPreview => {
                if trust_anchor.is_some() {
                    return Err(
                        "transparency_preview claims must not declare a trust_anchor".to_string(),
                    );
                }
            }
            EvidencePublicationState::TrustAnchored => {
                if trust_anchor.is_none() {
                    return Err(
                        "trust_anchored claims require a non-empty trust_anchor".to_string()
                    );
                }
                if !self.transparency_preview.is_empty() {
                    return Err(
                        "trust_anchored claims must not retain transparency_preview entries"
                            .to_string(),
                    );
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_trust_anchored(&self) -> bool {
        self.publication_state == EvidencePublicationState::TrustAnchored
    }
}

/// Complete evidence bundle assembled from a receipt store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportBundle {
    pub query: EvidenceExportQuery,
    pub tool_receipts: Vec<EvidenceToolReceiptRecord>,
    pub child_receipts: Vec<EvidenceChildReceiptRecord>,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub checkpoints: Vec<KernelCheckpoint>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
    pub inclusion_proofs: Vec<ReceiptInclusionProof>,
    pub uncheckpointed_receipts: Vec<EvidenceUncheckpointedReceipt>,
    pub retention: EvidenceRetentionMetadata,
}

/// Evidence source of a capability snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySnapshotProvenance {
    /// Projection derived from and bound to an exact signed capability token.
    SignedToken,
    /// Unsigned local anchor derived from a verified federated delegation policy.
    SyntheticAnchor,
}

impl CapabilitySnapshotProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignedToken => "signed_token",
            Self::SyntheticAnchor => "synthetic_anchor",
        }
    }
}

impl core::str::FromStr for CapabilitySnapshotProvenance {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "signed_token" => Ok(Self::SignedToken),
            "synthetic_anchor" => Ok(Self::SyntheticAnchor),
            _ => Err(format!(
                "unsupported capability snapshot provenance {value:?}"
            )),
        }
    }
}

/// A point-in-time snapshot of a capability token persisted at issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// The unique token ID (matches CapabilityToken.id).
    pub capability_id: String,
    /// Hex-encoded subject public key (agent bound to this capability).
    pub subject_key: String,
    /// Hex-encoded issuer public key (Capability Authority or delegating agent).
    pub issuer_key: String,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// JSON-serialized ChioScope (grants, resource_grants, prompt_grants).
    pub grants_json: String,
    /// Depth in the delegation chain. Root capabilities have depth 0.
    pub delegation_depth: u64,
    /// Parent capability_id if this was delegated from another token.
    pub parent_capability_id: Option<String>,
    /// Unsigned cross-federation parent edge, separate from signed token lineage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_parent_capability_id: Option<String>,
    /// Evidence source for this projection.
    pub provenance: CapabilitySnapshotProvenance,
    /// Exact signed capability token, when the snapshot originated from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_capability: Option<CapabilityToken>,
}

/// Why a capability snapshot fails validation.
#[derive(Debug)]
pub enum CapabilitySnapshotError {
    /// The snapshot contradicts itself or its signed token.
    Conflict(String),
    /// The persisted scope is not admissible JSON.
    UntrustedInput(UntrustedJsonError),
    /// A scope failed to re-serialize for comparison.
    Json(serde_json::Error),
}

impl fmt::Display for CapabilitySnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(reason) => write!(formatter, "conflict: {reason}"),
            Self::UntrustedInput(error) => fmt::Display::fmt(error, formatter),
            Self::Json(error) => write!(formatter, "serialization error: {error}"),
        }
    }
}

impl core::error::Error for CapabilitySnapshotError {}

impl From<UntrustedJsonError> for CapabilitySnapshotError {
    fn from(error: UntrustedJsonError) -> Self {
        Self::UntrustedInput(error)
    }
}

impl From<serde_json::Error> for CapabilitySnapshotError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl CapabilitySnapshot {
    /// Validate a snapshot read from a store or crossing a replication or
    /// evidence trust boundary.
    pub fn validate(&self) -> Result<(), CapabilitySnapshotError> {
        if self
            .federated_parent_capability_id
            .as_deref()
            .is_some_and(|parent| parent == self.capability_id)
        {
            return Err(self.conflict("uses itself as its federated parent"));
        }

        match self.provenance {
            CapabilitySnapshotProvenance::SignedToken => self.validate_signed_token(),
            CapabilitySnapshotProvenance::SyntheticAnchor => self.validate_synthetic_anchor(),
        }
    }

    fn validate_signed_token(&self) -> Result<(), CapabilitySnapshotError> {
        let Some(token) = self.signed_capability.as_ref() else {
            return Err(self.conflict("claims signed-token provenance without a signed token"));
        };
        token.validate_schema().map_err(|error| {
            self.conflict(&format!(
                "contains a signed token with an invalid schema: {error}"
            ))
        })?;
        if !token.verify_integrity_embedded_key().map_err(|error| {
            self.conflict(&format!(
                "contains a signed token that could not be verified: {error}"
            ))
        })? {
            return Err(self.conflict("contains a signed token with an invalid signature"));
        }

        let persisted_scope: ChioScope =
            UntrustedJsonText::from_wire(self.grants_json.as_bytes(), MAX_SNAPSHOT_SCOPE_BYTES)
                .and_then(|input| input.decode_signed())?;
        let scope_matches =
            serde_json::to_value(&persisted_scope)? == serde_json::to_value(&token.scope)?;
        let fields_match = self.capability_id == token.id
            && self.subject_key == token.subject.to_hex()
            && self.issuer_key == token.issuer.to_hex()
            && self.issued_at == token.issued_at
            && self.expires_at == token.expires_at
            && scope_matches;
        if !fields_match {
            return Err(self.conflict("does not match its signed token projection"));
        }

        let expected_parent = token
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        if self.parent_capability_id.as_deref() != expected_parent
            || u64::try_from(token.delegation_chain.len()) != Ok(self.delegation_depth)
        {
            return Err(self.conflict("does not match its signed delegation lineage"));
        }
        Ok(())
    }

    fn validate_synthetic_anchor(&self) -> Result<(), CapabilitySnapshotError> {
        if self.signed_capability.is_some() {
            return Err(self.conflict("marks a signed token as a synthetic anchor"));
        }
        let digest = self.capability_id.strip_prefix("fed-del-");
        if !digest.is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(self.conflict("is not a structurally valid fed-del anchor"));
        }
        if self.parent_capability_id.is_some() || self.delegation_depth != 0 {
            return Err(self.conflict("places unsigned federation data in signed lineage fields"));
        }
        if self.issued_at >= self.expires_at {
            return Err(self.conflict("has an empty or reversed validity window"));
        }
        PublicKey::from_hex(&self.subject_key)
            .map_err(|error| self.conflict(&format!("has an invalid subject key: {error}")))?;
        PublicKey::from_hex(&self.issuer_key)
            .map_err(|error| self.conflict(&format!("has an invalid issuer key: {error}")))?;
        let _: ChioScope =
            UntrustedJsonText::from_wire(self.grants_json.as_bytes(), MAX_SNAPSHOT_SCOPE_BYTES)
                .and_then(|input| input.decode_signed())?;
        Ok(())
    }

    fn conflict(&self, reason: &str) -> CapabilitySnapshotError {
        CapabilitySnapshotError::Conflict(format!(
            "capability lineage {} {reason}",
            self.capability_id
        ))
    }
}

/// Per-file record counts a package manifest commits to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceExportCounts {
    pub tool_receipts: u64,
    pub child_receipts: u64,
    pub checkpoints: u64,
    pub capability_lineage: u64,
    pub inclusion_proofs: u64,
    pub uncheckpointed_receipts: u64,
}

/// Checkpoint coverage of the exported tool receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProofCoverage {
    pub checkpointed_receipts: u64,
    pub uncheckpointed_receipts: u64,
}

/// Receipt kind and boundary-class tallies derived from the tool receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReceiptSemanticSummary {
    pub mediated_decisions: u64,
    pub trace_observations: u64,
    pub advisory_evaluations: u64,
    pub prevent: u64,
    pub detect_only: u64,
    pub advisory_only: u64,
    pub cannot_see: u64,
    pub authorized: u64,
}

/// One package file the manifest commits to by path, digest and length.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceExportFileHash {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Identity of a policy attached to a package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyAttachmentMetadata {
    pub format: String,
    pub source_hash: String,
    pub runtime_hash: String,
    pub source_path: String,
    pub source_bytes: u64,
}

/// Summary of the signed federation policy attached to a package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPolicyAttachmentMetadata {
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub require_proofs: bool,
}

/// Signed body of a bilateral federation policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederationPolicyBody {
    pub schema: String,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub query: EvidenceExportQuery,
    pub require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// A federation policy and its signature over the canonical body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederationPolicyDocument {
    pub body: FederationPolicyBody,
    pub signature: Signature,
}

impl FederationPolicyDocument {
    #[must_use]
    pub fn attachment_metadata(&self) -> FederationPolicyAttachmentMetadata {
        FederationPolicyAttachmentMetadata {
            issuer: self.body.issuer.clone(),
            partner: self.body.partner.clone(),
            signer_public_key: self.body.signer_public_key.clone(),
            created_at: self.body.created_at,
            expires_at: self.body.expires_at,
            require_proofs: self.body.require_proofs,
        }
    }
}

/// Documented metadata disclosure attached to tenant-scoped exports.
///
/// Tenant-scoped evidence exports inherit kernel-signed checkpoint bodies and
/// their inclusion proofs. Those signed artifacts cover the full per-batch
/// Merkle tree, which is shared across tenants by design. This notice lists
/// which cross-tenant fields the exported checkpoint set inherently reveals,
/// so receiving parties can audit the disclosure boundary without parsing
/// every signed body manually. Admin-all exports do not carry the notice
/// because the operator already requested a cross-tenant view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDisclosureNotice {
    /// Stable identifier for the notice format so downstream parsers can
    /// branch deterministically when the disclosure list changes.
    pub schema: String,
    /// Concise summary describing why this disclosure is unavoidable in the
    /// current protocol version.
    pub summary: String,
    /// Names of fields on each exported `KernelCheckpointBody` (in
    /// `checkpoints.ndjson`) that describe the full per-batch Merkle tree and
    /// therefore reveal cross-tenant aggregate information.
    pub disclosed_checkpoint_body_fields: Vec<String>,
    /// Names of derived publication / witness fields (in
    /// `checkpoint-*.ndjson`) that mirror the signed body and are therefore
    /// equivalent disclosures.
    pub disclosed_publication_fields: Vec<String>,
    /// Specific metadata that is intentionally narrowed for tenant-scoped
    /// exports compared to admin-all exports.
    pub narrowed_metadata: Vec<String>,
    /// Stable reference to the docs section describing why the disclosure
    /// cannot be eliminated without protocol-level changes.
    pub protocol_reference: String,
}

impl EvidenceDisclosureNotice {
    /// The canonical notice every tenant-scoped export carries.
    #[must_use]
    pub fn tenant_scoped() -> Self {
        Self {
            schema: EVIDENCE_DISCLOSURE_NOTICE_SCHEMA.to_string(),
            summary: "Kernel-signed checkpoint bodies and their derived publication records cover the full per-batch Merkle tree shared across tenants. Tenant-scoped exports therefore reveal aggregate batch metadata for receipts they do not contain. This disclosure is unavoidable without protocol-level per-tenant subtree proofs.".to_string(),
            disclosed_checkpoint_body_fields: vec![
                "batch_start_seq".to_string(),
                "batch_end_seq".to_string(),
                "tree_size".to_string(),
                "merkle_root".to_string(),
                "checkpoint_seq".to_string(),
                "issued_at".to_string(),
                "previous_checkpoint_sha256".to_string(),
            ],
            disclosed_publication_fields: vec![
                "entry_start_seq".to_string(),
                "entry_end_seq".to_string(),
                "log_tree_size".to_string(),
            ],
            narrowed_metadata: vec![
                "retention.liveDbSizeBytes is omitted (admin-all only)".to_string(),
                "retention.oldestLiveReceiptTimestamp is restricted to the requesting tenant"
                    .to_string(),
            ],
            protocol_reference:
                "docs/release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md#tenant-scoped-disclosure"
                    .to_string(),
        }
    }

    /// The notice an export under `query` must carry, if any.
    #[must_use]
    pub fn for_query(query: &EvidenceExportQuery) -> Option<Self> {
        match &query.read_boundary {
            Some(ReceiptReadBoundary::TenantScoped { .. }) => Some(Self::tenant_scoped()),
            Some(ReceiptReadBoundary::AdminAll) | None => None,
        }
    }
}

/// Manifest of an exported evidence package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceExportManifest {
    pub schema: String,
    pub exported_at: u64,
    pub query: EvidenceExportQuery,
    pub counts: EvidenceExportCounts,
    pub proof_coverage: EvidenceProofCoverage,
    #[serde(default)]
    pub receipt_semantics: EvidenceReceiptSemanticSummary,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_boundary: Option<EvidenceTransparencyClaims>,
    pub files: Vec<EvidenceExportFileHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyAttachmentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyAttachmentMetadata>,
    /// Per-tenant disclosure notice attached when the export is tenant-scoped.
    /// Documents which signed-checkpoint fields inherently reveal aggregate
    /// cross-tenant metadata so the disclosure boundary stays auditable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_notice: Option<EvidenceDisclosureNotice>,
}

/// What the kernel key signs for a package: the manifest digest and the
/// digest of the decoded payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportCommitment {
    pub schema: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
}

/// The signed `export-envelope.json` of a package.
pub type EvidencePackageEnvelope = SignedExportEnvelope<ExportCommitment>;

/// The canonical payload `ExportCommitment::payload_sha256` commits to.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidencePackagePayload<'a> {
    pub bundle: &'a EvidenceExportBundle,
    pub transparency: Option<&'a CheckpointTransparencySummary>,
    pub federation_policy: Option<&'a FederationPolicyDocument>,
}

/// Every decoded part of an evidence package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceImportPackage {
    pub envelope: EvidencePackageEnvelope,
    pub manifest: EvidenceExportManifest,
    pub bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<CheckpointTransparencySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}
