//! Closed ordinary sink payload. Signatures and sensitive source data stay in
//! the original receipt, retrieved separately through authorized evidence reads.

use chio_core::crypto::{sha256_hex, PublicKey};
use chio_core::receipt::{
    body::ChioReceipt,
    decision::Decision,
    kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    },
};
use serde::Serialize;

use crate::alerting::{severity_for_guard, AlertSeverity};
use crate::event::SourceVerification;

/// An unsigned, bounded reference to an original receipt for ordinary sinks.
/// Fields are private and the type cannot be constructed from external JSON.
/// Verification flags describe the original, never a signature on this view.
///
/// ```compile_fail
/// use chio_siem::SiemSinkProjection;
/// let _: SiemSinkProjection = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct SiemSinkProjection {
    schema: &'static str,
    projection: &'static str,
    signature_scope: &'static str,
    pub(crate) receipt_id: Option<SinkDigest>,
    pub(crate) receipt_id_sha256: SinkDigest,
    pub(crate) timestamp: u64,
    pub(crate) parameter_hash: Option<SinkDigest>,
    pub(crate) policy_hash: Option<SinkDigest>,
    pub(crate) content_hash: Option<SinkDigest>,
    pub(crate) capability_id_sha256: SinkDigest,
    pub(crate) tool_server_sha256: SinkDigest,
    pub(crate) tool_name_sha256: SinkDigest,
    pub(crate) tenant_id_sha256: Option<SinkDigest>,
    pub(crate) guard_sha256: Option<SinkDigest>,
    kernel_key_sha256: SinkDigest,
    pub(crate) receipt_kind: ReceiptKind,
    pub(crate) boundary_class: BoundaryClass,
    observation_outcome: Option<ObservationOutcome>,
    tool_origin: ToolOrigin,
    pub(crate) trust_level: TrustLevel,
    pub(crate) source_redaction_mode: RedactionMode,
    pub(crate) decision: SinkDecision,
    decision_id: u8,
    result: SinkResult,
    pub(crate) severity_id: u8,
    severity: &'static str,
    pub(crate) authoritative: bool,
    signature_valid: bool,
    receipt_id_valid: bool,
    parameter_hash_valid: bool,
    signer_trusted: bool,
    pub(crate) authorized: bool,
    financial: Option<NumericFinancial>,
    payload_included: bool,
    original_retrieval_required: bool,
    projection_signed: bool,
    #[serde(skip)]
    pub(crate) alert_severity: AlertSeverity,
}

/// Only constructors in this module can introduce a digest into a sink view.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub(crate) struct SinkDigest(String);

impl SinkDigest {
    fn commitment(value: &str) -> Option<Self> {
        (value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self(value.to_string()))
    }

    fn reference(value: &str) -> Self {
        Self(sha256_hex(value.as_bytes()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SinkDecision {
    Authorized,
    Denied,
    Cancelled,
    Incomplete,
    Unverified,
    TraceObservation,
    AdvisoryEvaluation,
    Invalid,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum SinkResult {
    Authorized,
    Denied,
    Cancelled,
    Incomplete,
    Unverified,
    Observed,
    Advisory,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
struct NumericFinancial {
    grant_index: u32,
    cost_charged: u64,
    budget_remaining: Option<u64>,
    budget_total: Option<u64>,
    delegation_depth: u32,
    attempted_cost: Option<u64>,
}

impl NumericFinancial {
    fn from_receipt(receipt: &ChioReceipt) -> Option<Self> {
        let data = receipt.metadata.as_ref()?.get("financial")?.as_object()?;
        Some(Self {
            grant_index: data.get("grant_index")?.as_u64()?.try_into().ok()?,
            cost_charged: data.get("cost_charged")?.as_u64()?,
            budget_remaining: optional_amount(Some(data.get("budget_remaining")?))?,
            budget_total: optional_amount(Some(data.get("budget_total")?))?,
            delegation_depth: data.get("delegation_depth")?.as_u64()?.try_into().ok()?,
            attempted_cost: optional_amount(data.get("attempted_cost"))?,
        })
    }
}

fn optional_amount(value: Option<&serde_json::Value>) -> Option<Option<u64>> {
    match value {
        None | Some(serde_json::Value::Null) => Some(None),
        Some(value) => value.as_u64().map(Some),
    }
}

impl SiemSinkProjection {
    pub(crate) fn from_receipt(receipt: &ChioReceipt, trusted_pin: Option<&PublicKey>) -> Self {
        let verified = SourceVerification::new(receipt, trusted_pin);
        let decision = match receipt.receipt_kind {
            ReceiptKind::TraceObservation => SinkDecision::TraceObservation,
            ReceiptKind::AdvisoryEvaluation => SinkDecision::AdvisoryEvaluation,
            ReceiptKind::MediatedDecision => match &receipt.decision {
                Some(Decision::Allow) if verified.authorized => SinkDecision::Authorized,
                Some(Decision::Allow) => SinkDecision::Unverified,
                Some(Decision::Deny { .. }) => SinkDecision::Denied,
                Some(Decision::Cancelled { .. }) => SinkDecision::Cancelled,
                Some(Decision::Incomplete { .. }) => SinkDecision::Incomplete,
                None => SinkDecision::Invalid,
            },
        };
        let (decision_id, result) = match decision {
            SinkDecision::Authorized => (1, SinkResult::Authorized),
            SinkDecision::Denied => (2, SinkResult::Denied),
            SinkDecision::Cancelled => (3, SinkResult::Cancelled),
            SinkDecision::Incomplete => (4, SinkResult::Incomplete),
            SinkDecision::TraceObservation => (5, SinkResult::Observed),
            SinkDecision::AdvisoryEvaluation => (6, SinkResult::Advisory),
            SinkDecision::Unverified => (7, SinkResult::Unverified),
            SinkDecision::Invalid => (0, SinkResult::Invalid),
        };
        let alert_severity = match &receipt.decision {
            Some(Decision::Allow)
                if verified.authorized && receipt.evidence.iter().all(|e| e.verdict) =>
            {
                AlertSeverity::Info
            }
            Some(Decision::Deny { guard, .. }) => severity_for_guard(guard, &receipt.evidence),
            _ => AlertSeverity::Low,
        };
        let severity_id = match alert_severity {
            AlertSeverity::Info => 1,
            AlertSeverity::Low => 2,
            AlertSeverity::Medium => 3,
            AlertSeverity::High => 4,
            AlertSeverity::Critical => 5,
        };
        Self {
            schema: "chio.siem.sink-projection.v1",
            projection: "receipt_reference",
            signature_scope: "original_receipt",
            receipt_id: verified
                .receipt_id_valid
                .then(|| SinkDigest::commitment(&receipt.id))
                .flatten(),
            receipt_id_sha256: SinkDigest::reference(&receipt.id),
            timestamp: receipt.timestamp,
            parameter_hash: verified
                .parameter_hash_valid
                .then(|| SinkDigest::commitment(&receipt.action.parameter_hash))
                .flatten(),
            policy_hash: SinkDigest::commitment(&receipt.policy_hash),
            content_hash: SinkDigest::commitment(&receipt.content_hash),
            capability_id_sha256: SinkDigest::reference(&receipt.capability_id),
            tool_server_sha256: SinkDigest::reference(&receipt.tool_server),
            tool_name_sha256: SinkDigest::reference(&receipt.tool_name),
            tenant_id_sha256: receipt.tenant_id.as_deref().map(SinkDigest::reference),
            guard_sha256: match &receipt.decision {
                Some(Decision::Deny { guard, .. }) => Some(SinkDigest::reference(guard)),
                _ => None,
            },
            kernel_key_sha256: SinkDigest::reference(&receipt.kernel_key.to_hex()),
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            trust_level: receipt.trust_level,
            source_redaction_mode: receipt.redaction_mode,
            decision,
            decision_id,
            result,
            severity_id,
            severity: alert_severity.as_tag(),
            authoritative: verified.authoritative,
            signature_valid: verified.signature_valid,
            receipt_id_valid: verified.receipt_id_valid,
            parameter_hash_valid: verified.parameter_hash_valid,
            signer_trusted: verified.signer_trusted,
            authorized: verified.authorized,
            financial: NumericFinancial::from_receipt(receipt),
            payload_included: false,
            original_retrieval_required: true,
            projection_signed: false,
            alert_severity,
        }
    }

    /// Canonical original receipt ID, or a hashed diagnostic ID if invalid.
    #[must_use]
    pub fn event_reference(&self) -> &str {
        self.receipt_id
            .as_ref()
            .unwrap_or(&self.receipt_id_sha256)
            .as_str()
    }

    /// A fixed semantic result label; it contains no source denial text.
    #[must_use]
    pub fn result_label(&self) -> &'static str {
        match self.result {
            SinkResult::Authorized => "Authorized",
            SinkResult::Denied => "Denied",
            SinkResult::Cancelled => "Cancelled",
            SinkResult::Incomplete => "Incomplete",
            SinkResult::Unverified => "Unverified",
            SinkResult::Observed => "Observed",
            SinkResult::Advisory => "Advisory",
            SinkResult::Invalid => "Invalid",
        }
    }

    /// Fixed decision classification. Only a pinned, verified prevent allow
    /// produces `allow`; observations keep their semantic class.
    #[must_use]
    pub fn decision_label(&self) -> &'static str {
        match self.decision {
            SinkDecision::Authorized => "allow",
            SinkDecision::Denied => "deny",
            SinkDecision::Cancelled => "cancelled",
            SinkDecision::Incomplete => "incomplete",
            _ => self.receipt_kind.as_str(),
        }
    }
}
