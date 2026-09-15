use std::collections::BTreeMap;

use chio_core_types::{receipt::lineage::SignedExportEnvelope, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub verifier_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustedVerifierKey {
    pub verifier_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustedVerifierKeysDocument {
    pub schema: String,
    pub verifier_keys: Vec<RuntimeTrustedVerifierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeVerifierTrustBundleV4 {
    pub schema: String,
    pub verifier_id: String,
    pub key_id: String,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash_sha256: Option<String>,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
    pub revocation_checkpoint_sha256: String,
    pub revocation_authority_roots: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedRuntimeVerifierTrustBundle = SignedExportEnvelope<RuntimeVerifierTrustBundleV4>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePeerWeight {
    pub peer_kernel_id: String,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePeerWeights {
    pub schema: String,
    pub verifier_id: String,
    pub key_id: String,
    pub reputation_epoch: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub weights: Vec<RuntimePeerWeight>,
}

pub type SignedRuntimePeerWeights = SignedExportEnvelope<RuntimePeerWeights>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicyRule {
    pub rule_id: String,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub action_class_id: String,
    pub direction: String,
    pub threshold_total_strength: f64,
    pub effect: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicy {
    pub schema: String,
    pub policy_id: String,
    pub verifier_id: String,
    pub key_id: String,
    pub policy_version: u64,
    pub mode: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub allowed_reputation_epochs: Vec<u64>,
    pub max_query_report_age_ms: u64,
    pub min_distinct_origin_pairs: u64,
    pub runtime_trust_bundle_sha256: String,
    pub peer_weights_sha256: String,
    pub rules: Vec<RuntimePheromonePolicyRule>,
}

pub type SignedRuntimePheromonePolicy = SignedExportEnvelope<RuntimePheromonePolicy>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromonePolicyDecision {
    pub schema: String,
    pub enforced: bool,
    pub decision: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub query_report_sha256: String,
    pub peer_weights_sha256: String,
    pub reputation_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustFloorEntry {
    pub verifier_id: String,
    pub key_id: String,
    pub highest_version: u64,
    pub latest_bundle_sha256: String,
    pub latest_revocation_checkpoint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeTrustFloorState {
    pub schema: String,
    pub entries: Vec<RuntimeTrustFloorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRequestBinding {
    pub request_id: String,
    pub capability_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub tool_args_sha256: String,
    pub origin_kernel_id: Option<String>,
    pub host_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionBundle {
    pub schema: String,
    pub admission_id: String,
    pub binding: RuntimeRequestBinding,
    pub workflow_id: String,
    pub workflow_grant_id: String,
    pub step_index: u64,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub evidence_required: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderQuorum {
    pub n: u16,
    pub m: u16,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderManifest {
    pub schema: String,
    pub manifest_id: String,
    pub kernel_id: String,
    pub issuer: String,
    pub key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub destructive_floor: String,
    pub default_unknown_mode: String,
    pub action_classes: Vec<GovernanceLadderActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreatyScope {
    pub schema: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub participant_public_keys: Vec<PublicKey>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub allowed_action_classes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revocation_epoch_sha256: String,
    pub trust_bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersectionActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub evidence_required: Vec<String>,
    pub participant_modes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersection {
    pub schema: String,
    pub intersection_id: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub action_classes: Vec<LadderIntersectionActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossKernelContinuation {
    pub schema: String,
    pub continuation_id: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
    pub parent_receipt_sha256: String,
    pub parent_session_anchor_sha256: String,
    pub capability_id: String,
    pub action_class_id: String,
    pub audience_tool: String,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// Origin of one interval that bounds when a co-signed statement may be
/// presented to this receiver.
///
/// Every variant names a record the receiver resolves from its own store, never
/// a validity a counterparty wrote into the statement. The window is rebuilt
/// from the records resolved for the call being decided, so a record the
/// receiver stops resolving between calls drops out of the intersection and
/// closes the window for the counterparties that record bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresentationIntervalSource {
    /// Validity of the treaty scope, which binds every participant.
    TreatyScope,
    /// Validity of the capability lease record the admission bundle names.
    CapabilityLease,
    /// Validity of the governance receipt record the admission bundle names.
    GovernanceReceipt,
}

impl PresentationIntervalSource {
    /// Label used in rejection detail.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TreatyScope => "treaty scope",
            Self::CapabilityLease => "capability lease",
            Self::GovernanceReceipt => "governance receipt",
        }
    }
}

/// One half-open interval `[not_before_unix_ms, not_after_unix_ms)` the
/// receiver resolved for itself, together with the counterparties it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPresentationInterval {
    source: PresentationIntervalSource,
    counterparty_kernel_ids: Vec<String>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl ResolvedPresentationInterval {
    /// Rejects an interval that binds nobody and an interval that is already
    /// empty: a record the receiver cannot read a live interval out of must not
    /// enter the intersection at all.
    pub fn new(
        source: PresentationIntervalSource,
        counterparty_kernel_ids: Vec<String>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self, PresentationWindowError> {
        if counterparty_kernel_ids.is_empty() {
            return Err(PresentationWindowError::BindsNoCounterparty(source));
        }
        if not_before_unix_ms >= not_after_unix_ms {
            return Err(PresentationWindowError::EmptyInterval(source));
        }
        Ok(Self {
            source,
            counterparty_kernel_ids,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    fn binds(&self, kernel_id: &str) -> bool {
        self.counterparty_kernel_ids
            .iter()
            .any(|counterparty| counterparty == kernel_id)
    }
}

/// The window in which a co-signed statement may be presented to this receiver:
/// the intersection of the intervals the receiver resolved for the call being
/// decided.
///
/// The window is receiver-owned in both directions. A validity a counterparty
/// wrote into the statement may end earlier than the window but never later, so
/// widening it takes a change to a record the receiver holds rather than a
/// change to the statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationWindow {
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    intervals: Vec<ResolvedPresentationInterval>,
}

impl PresentationWindow {
    /// Intersects the resolved intervals, failing closed when none were
    /// resolved and when the intersection is empty.
    pub fn intersect(
        intervals: Vec<ResolvedPresentationInterval>,
    ) -> Result<Self, PresentationWindowError> {
        if intervals.is_empty() {
            return Err(PresentationWindowError::NothingResolved);
        }
        let mut not_before_unix_ms = 0;
        let mut not_after_unix_ms = u64::MAX;
        for interval in &intervals {
            not_before_unix_ms = not_before_unix_ms.max(interval.not_before_unix_ms);
            not_after_unix_ms = not_after_unix_ms.min(interval.not_after_unix_ms);
        }
        if not_before_unix_ms >= not_after_unix_ms {
            return Err(PresentationWindowError::Closed {
                not_before_unix_ms,
                not_after_unix_ms,
            });
        }
        Ok(Self {
            not_before_unix_ms,
            not_after_unix_ms,
            intervals,
        })
    }

    /// The window as it stands for one counterparty: the intersection of the
    /// intervals that bind it, and only if every required source resolved for
    /// it. Withdrawing one counterparty's record between calls removes its
    /// interval here and nowhere else, so a required record that stops
    /// resolving closes that counterparty's window and leaves every other
    /// counterparty's window where it was.
    pub fn for_counterparty(
        &self,
        kernel_id: &str,
        required: &[PresentationIntervalSource],
    ) -> Result<Self, PresentationWindowError> {
        let intervals: Vec<ResolvedPresentationInterval> = self
            .intervals
            .iter()
            .filter(|interval| interval.binds(kernel_id))
            .cloned()
            .collect();
        for source in required {
            if !intervals.iter().any(|interval| interval.source == *source) {
                return Err(PresentationWindowError::Unresolved {
                    source: *source,
                    counterparty_kernel_id: kernel_id.to_string(),
                });
            }
        }
        Self::intersect(intervals)
    }

    /// Whether a validity the statement carries stays inside this window. The
    /// receiver owns the upper bound, so an expiry at the window's own end is
    /// admitted and one millisecond past it is not.
    pub const fn admits_expiry(&self, expires_at_unix_ms: u64) -> bool {
        expires_at_unix_ms > self.not_before_unix_ms && expires_at_unix_ms <= self.not_after_unix_ms
    }

    /// First instant of the window.
    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    /// First instant past the window.
    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }
}

/// Why a presentation window could not be built, or could not be built for one
/// counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationWindowError {
    /// The receiver resolved no interval at all.
    NothingResolved,
    /// A resolved record carried an empty interval.
    EmptyInterval(PresentationIntervalSource),
    /// A resolved record named no counterparty.
    BindsNoCounterparty(PresentationIntervalSource),
    /// A record the receiver requires for one counterparty did not resolve on
    /// this call.
    Unresolved {
        source: PresentationIntervalSource,
        counterparty_kernel_id: String,
    },
    /// The resolved intervals do not overlap.
    Closed {
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    },
}

impl std::fmt::Display for PresentationWindowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingResolved => {
                write!(formatter, "the receiver resolved no interval for this call")
            }
            Self::EmptyInterval(source) => {
                write!(formatter, "the {} interval is empty", source.as_str())
            }
            Self::BindsNoCounterparty(source) => write!(
                formatter,
                "the {} interval binds no counterparty",
                source.as_str()
            ),
            Self::Unresolved {
                source,
                counterparty_kernel_id,
            } => write!(
                formatter,
                "the receiver resolved no {} interval for the counterparty {counterparty_kernel_id}",
                source.as_str()
            ),
            Self::Closed {
                not_before_unix_ms,
                not_after_unix_ms,
            } => write!(
                formatter,
                "the resolved intervals do not overlap (not before {not_before_unix_ms}, not after {not_after_unix_ms})"
            ),
        }
    }
}

impl std::error::Error for PresentationWindowError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageStatement {
    pub schema: String,
    pub statement_id: String,
    pub parent_receipt_sha256: String,
    pub child_receipt_sha256: String,
    pub continuation_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub evidence_class: String,
    pub source_kernel_id: String,
    pub target_kernel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryAdmissionReport {
    pub schema: String,
    pub treaty_id: String,
    pub action_class_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub mode: String,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub required_evidence: Vec<String>,
    pub present_evidence: Vec<String>,
    #[serde(default)]
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ladder_intersection_sha256: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryEvidenceRef {
    pub evidence_class: String,
    pub artifact_sha256: String,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BilateralInvocation {
    pub schema: String,
    pub invocation_id: String,
    pub treaty_id: String,
    pub ladder_intersection_sha256: String,
    pub continuation_sha256: String,
    pub lineage_statement_sha256: String,
    pub action_class_id: String,
    pub consistency_model: String,
    pub capability_id: String,
    pub request_sha256: String,
    pub outcome_sha256: String,
    pub local_receipt_sha256: String,
    pub remote_receipt_sha256: String,
    pub signer_kernel_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationPacket {
    pub schema: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub capability_id: String,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    pub cross_boundary_admission_report_sha256: String,
    pub continuation_sha256: String,
    pub receipt_lineage_statement_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_receipt_sha256: String,
    pub proof_package_sha256: String,
    pub verifier_report_sha256: String,
    pub budget_refs: Vec<String>,
    pub settlement_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationVerificationReport {
    pub schema: String,
    pub packet_id: String,
    pub verification_state: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLineageBundle {
    pub schema: String,
    pub bundle_id: String,
    pub root_receipt_sha256: String,
    pub leaf_receipt_sha256: String,
    pub statements: Vec<ReceiptLineageStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewArtifactRef {
    pub role: String,
    pub relative_path: String,
    pub artifact_sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyerAttestationReviewSource {
    pub role: String,
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

pub struct BuyerAttestationReviewTrustContext<'a> {
    pub verifier_trust_bundle: &'a serde_json::Value,
    pub verification_context: &'a serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub generated_at_unix_ms: u64,
    pub artifacts: Vec<BuyerAttestationReviewArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewCheck {
    pub code: String,
    pub passed: bool,
    pub severity: String,
    pub artifact_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_sha256: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationReviewReport {
    pub schema: String,
    pub package_id: String,
    pub packet_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<BuyerAttestationReviewCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreatyRuntimeArtifactRecord {
    pub evidence_kind: String,
    pub evidence_id: String,
    pub artifact_sha256: String,
    pub raw_json: serde_json::Value,
}

pub struct CrossBoundaryAdmissionInput<'a> {
    pub treaty_scope: &'a TreatyScope,
    pub ladder_intersection: &'a LadderIntersection,
    pub expected_ladder_intersection_sha256: Option<String>,
    pub action_class_id: &'a str,
    pub present_evidence: Vec<String>,
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionCheck {
    pub code: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAdmissionReport {
    pub schema: String,
    pub admission_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub checks: Vec<RuntimeAdmissionCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pheromone_advisory: Option<RuntimePheromoneAdvisory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pheromone_policy_decision: Option<RuntimePheromonePolicyDecision>,
    pub receipt_metadata: serde_json::Value,
}

pub type SignedRuntimeAdmissionReport = SignedExportEnvelope<RuntimeAdmissionReport>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePheromoneAdvisory {
    pub source_report_sha256: String,
    pub accepted: bool,
    pub subject_class: String,
    pub subject_class_namespace: String,
    pub total_strength: f64,
    #[serde(default)]
    pub distinct_origin_pairs: u64,
    pub reputation_epoch: u64,
    pub evaluated_at_unix_ms: u64,
    pub observe_only: bool,
}

pub type SignedRuntimePheromoneQueryReport = SignedExportEnvelope<serde_json::Value>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeWorkflowRunReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub admission_report_sha256: String,
    pub evidence_paths: Vec<String>,
    pub step_evidence: Vec<RuntimeStepEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_regeneration_report_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeStepEvidence {
    pub schema: String,
    pub step_index: u64,
    pub admission_id: String,
    pub admission_report_sha256: String,
    pub tool_receipt_id: String,
    pub tool_receipt_sha256: String,
    pub output_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_step_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_sha256: Option<String>,
    pub consistency_anchor: String,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofSourceRecord {
    pub step_index: u64,
    pub admission_report_sha256: String,
    pub tool_receipt_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_step_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifestEntry {
    pub role: String,
    pub path: String,
    pub sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceManifest {
    pub schema: String,
    pub run_id: String,
    pub generated_at_unix_ms: u64,
    pub workflow_run_report_sha256: String,
    pub proof_regeneration_report_sha256: String,
    pub entries: Vec<RuntimeEvidenceManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofRegenerationInput {
    pub schema: String,
    pub run_id: String,
    pub evidence_manifest_sha256: String,
    pub workflow_run_report_sha256: String,
    pub admission_report_sha256: String,
    pub trust_bundle_sha256: String,
    pub verification_context_sha256: String,
    pub source_records: Vec<RuntimeProofSourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofRegenerationReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_package_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_receipt_sha256: Option<String>,
    pub source_records: Vec<RuntimeProofSourceRecord>,
    pub checks: Vec<String>,
}

pub use chio_runtime_proof_parity::{RuntimeProofParityMismatch, RuntimeProofParityReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub verifier_id: String,
    pub mode: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_concurrent_runs: u64,
    pub fail_closed_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRunContract {
    pub schema: String,
    pub run_id: String,
    pub profile_sha256: String,
    pub workflow_id: String,
    pub expected_step_count: u64,
    pub admission_ids: Vec<String>,
    pub store_id: String,
    pub evidence_sink_id: String,
    pub proof_regeneration_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationPlannedStep {
    pub step_index: u64,
    pub admission_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationPlan {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub run_contract_sha256: String,
    pub planned_steps: Vec<RuntimeOrchestrationPlannedStep>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationStepState {
    pub step_index: u64,
    pub admission_id: String,
    pub state: String,
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationRunReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub status: String,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub run_contract_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_run_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_regeneration_report_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_report_sha256: Option<String>,
    pub step_states: Vec<RuntimeOrchestrationStepState>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationResumePlan {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step_index: Option<u64>,
    pub reusable_step_indices: Vec<u64>,
    pub blocked: bool,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOrchestrationStatusReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub profile_sha256: String,
    pub store_backend: String,
    pub store_path_sha256: String,
    pub run_counts: BTreeMap<String, u64>,
    pub consumed_lease_count: u64,
    pub trust_floor_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_failure_code: Option<String>,
    pub evidence_sink_healthy: bool,
    pub ready: bool,
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofDrift {
    pub field: String,
    pub baseline_value_sha256: String,
    pub candidate_value_sha256: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofArtifactDrift {
    pub role: String,
    pub path: String,
    pub baseline_sha256: String,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProofDriftReport {
    pub schema: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub baseline_manifest_sha256: String,
    pub candidate_manifest_sha256: String,
    pub baseline_proof_regeneration_report_sha256: String,
    pub candidate_proof_regeneration_report_sha256: String,
    pub comparison_profile: String,
    pub normalized_fields: Vec<String>,
    pub semantic_drifts: Vec<RuntimeProofDrift>,
    pub artifact_drifts: Vec<RuntimeProofArtifactDrift>,
    pub verifier_drifts: Vec<RuntimeProofDrift>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSupervisorProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub max_concurrent_runs: u64,
    pub run_lease_ttl_ms: u64,
    pub stale_run_after_ms: u64,
    pub evidence_required_roles: Vec<String>,
    pub fail_closed_on: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRunLease {
    pub schema: String,
    pub run_id: String,
    pub lease_id: String,
    pub owner_id: String,
    pub acquired_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub heartbeat_at_unix_ms: u64,
    pub fencing_token: u64,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeSchedulerTickReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub tick_id: String,
    pub owner_id: String,
    pub generated_at_unix_ms: u64,
    pub max_runs: u64,
    pub claimed_run_ids: Vec<String>,
    pub expired_run_ids: Vec<String>,
    pub blocked_run_ids: Vec<String>,
    pub skipped_run_count: u64,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeEvidenceSinkHealthReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub evidence_root_sha256: String,
    pub required_roles: Vec<String>,
    pub missing_roles: Vec<String>,
    pub missing_artifacts: Vec<String>,
    pub artifact_hash_mismatches: Vec<String>,
    pub artifact_byte_count_mismatches: Vec<String>,
    pub unexpected_paths: Vec<String>,
    pub temp_write_ok: bool,
    pub atomic_rename_ok: bool,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRecoveryDrillReport {
    pub schema: String,
    pub run_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub resumable: bool,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_step_index: Option<u64>,
    pub reusable_step_indices: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_required_reason: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionProfile {
    pub schema: String,
    pub profile_id: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub min_retain_ms: u64,
    pub destructive_hold_ms: u64,
    pub legal_hold: bool,
    pub dry_run_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionAction {
    pub run_id: String,
    pub action: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifactRetentionPlan {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub retention_profile_sha256: String,
    pub retain_count: u64,
    pub blocked_count: u64,
    pub quarantine_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_operator_review_count: u64,
    pub candidate_actions: Vec<RuntimeArtifactRetentionAction>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeightsBindingMode {
    NotRequired,
    Required,
    RequiredWithPin,
    Unavailable,
}

impl WeightsBindingMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Required => "required",
            Self::RequiredWithPin => "required_with_pin",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderBinding {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    pub local_kernel_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub discovery_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_card_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_card_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_weights_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights_binding_mode: Option<WeightsBindingMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderBindingsDocument {
    pub schema: String,
    pub bindings: Vec<RuntimeProviderBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderLoadedWeightsEvidence {
    pub binding_id: String,
    pub loaded_weights_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderHealthCheck {
    pub provider_id: String,
    pub binding_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub weights_binding_mode: WeightsBindingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_card_id: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeProviderHealthReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub provider_bindings_sha256: String,
    pub checked_provider_count: u64,
    pub healthy_provider_count: u64,
    pub degraded_provider_ids: Vec<String>,
    #[serde(default)]
    pub provider_checks: Vec<RuntimeProviderHealthCheck>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeOpsStatusReport {
    pub schema: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub generated_at_unix_ms: u64,
    pub supervisor_profile_sha256: String,
    pub run_counts: BTreeMap<String, u64>,
    pub active_lease_count: u64,
    pub stale_lease_count: u64,
    pub consumed_lease_count: u64,
    pub evidence_sink_healthy: bool,
    pub provider_healthy: bool,
    pub ready: bool,
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_failure_code: Option<String>,
    pub checks: Vec<String>,
}

#[cfg(test)]
mod presentation_window_tests {
    use super::{
        PresentationIntervalSource, PresentationWindow, PresentationWindowError,
        ResolvedPresentationInterval,
    };

    const AGREEMENT: PresentationIntervalSource = PresentationIntervalSource::TreatyScope;
    const LEASE: PresentationIntervalSource = PresentationIntervalSource::CapabilityLease;
    const GOVERNANCE: PresentationIntervalSource = PresentationIntervalSource::GovernanceReceipt;

    type TestResult = Result<(), PresentationWindowError>;

    fn interval(
        source: PresentationIntervalSource,
        counterparties: &[&str],
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<ResolvedPresentationInterval, PresentationWindowError> {
        ResolvedPresentationInterval::new(
            source,
            counterparties
                .iter()
                .map(|counterparty| (*counterparty).to_string())
                .collect(),
            not_before_unix_ms,
            not_after_unix_ms,
        )
    }

    #[test]
    fn the_window_is_the_intersection_of_the_resolved_intervals() -> TestResult {
        let window = PresentationWindow::intersect(vec![
            interval(AGREEMENT, &["kernel.a", "kernel.b"], 100, 900)?,
            interval(LEASE, &["kernel.a"], 200, 800)?,
            interval(GOVERNANCE, &["kernel.b"], 150, 700)?,
        ])?;

        assert_eq!(window.not_before_unix_ms(), 200);
        assert_eq!(window.not_after_unix_ms(), 700);
        Ok(())
    }

    #[test]
    fn a_receiver_that_resolved_nothing_has_no_window() {
        assert_eq!(
            PresentationWindow::intersect(Vec::new()),
            Err(PresentationWindowError::NothingResolved)
        );
    }

    #[test]
    fn intervals_that_do_not_overlap_close_the_window() -> TestResult {
        let outcome = PresentationWindow::intersect(vec![
            interval(AGREEMENT, &["kernel.a"], 100, 400)?,
            interval(LEASE, &["kernel.a"], 500, 900)?,
        ]);

        assert_eq!(
            outcome,
            Err(PresentationWindowError::Closed {
                not_before_unix_ms: 500,
                not_after_unix_ms: 400,
            })
        );
        Ok(())
    }

    #[test]
    fn a_record_the_receiver_cannot_read_an_interval_out_of_is_refused() {
        assert_eq!(
            interval(LEASE, &["kernel.a"], 900, 900),
            Err(PresentationWindowError::EmptyInterval(LEASE))
        );
        assert_eq!(
            interval(LEASE, &[], 100, 900),
            Err(PresentationWindowError::BindsNoCounterparty(LEASE))
        );
    }

    #[test]
    fn each_counterparty_gets_the_intervals_resolved_for_it() -> TestResult {
        let window = PresentationWindow::intersect(vec![
            interval(AGREEMENT, &["kernel.a", "kernel.b"], 100, 900)?,
            interval(LEASE, &["kernel.a"], 100, 500)?,
        ])?;

        assert_eq!(
            window
                .for_counterparty("kernel.a", &[AGREEMENT])?
                .not_after_unix_ms(),
            500
        );
        assert_eq!(
            window
                .for_counterparty("kernel.b", &[AGREEMENT])?
                .not_after_unix_ms(),
            900
        );
        Ok(())
    }

    #[test]
    fn withdrawing_one_counterparty_record_closes_that_counterparty_alone() -> TestResult {
        let required = &[AGREEMENT, LEASE];
        let agreement = interval(AGREEMENT, &["kernel.a", "kernel.b"], 100, 900)?;

        let first_call = PresentationWindow::intersect(vec![
            agreement.clone(),
            interval(LEASE, &["kernel.a"], 100, 900)?,
            interval(LEASE, &["kernel.b"], 100, 900)?,
        ])?;
        assert!(first_call
            .for_counterparty("kernel.a", required)?
            .admits_expiry(900));

        let second_call = PresentationWindow::intersect(vec![
            agreement,
            interval(LEASE, &["kernel.b"], 100, 900)?,
        ])?;
        assert_eq!(
            second_call.for_counterparty("kernel.a", required),
            Err(PresentationWindowError::Unresolved {
                source: LEASE,
                counterparty_kernel_id: "kernel.a".to_string(),
            })
        );
        assert!(second_call
            .for_counterparty("kernel.b", required)?
            .admits_expiry(900));
        Ok(())
    }

    #[test]
    fn the_window_owns_the_upper_bound_of_any_validity_presented_to_it() -> TestResult {
        let window =
            PresentationWindow::intersect(vec![interval(AGREEMENT, &["kernel.a"], 100, 900)?])?;

        assert!(!window.admits_expiry(100));
        assert!(window.admits_expiry(101));
        assert!(window.admits_expiry(900));
        assert!(!window.admits_expiry(901));
        assert!(!window.admits_expiry(u64::MAX));
        Ok(())
    }
}
