//! Frozen authoritative-spend contract (`chio.mediated_spend.v1`).
//!
//! Direction A freezes this shape so B and C can pin against it. Any advisory
//! or label-only receipt fails `is_authoritative_spend_receipt`, making
//! advisory-only consumption a machine-visible conformance failure.

use crate::crypto::PublicKey;
use crate::receipt::body::ChioReceipt;
use crate::receipt::kinds::{BoundaryClass, ReceiptKind, TrustLevel};

/// Receipt-profile identifier for a fully authoritative mediated-spend receipt.
pub const MEDIATED_SPEND_PROFILE: &str = "chio.mediated_spend.v1";

/// Projected budget-hold lineage carried by an authoritative spend receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorityReceiptRef {
    pub hold_id: String,
    pub authorize_event_id: Option<String>,
    pub reconcile_event_id: Option<String>,
    pub capability_id: String,
    pub grant_index: u32,
    pub exposed_units: u64,
    pub realized_units: u64,
    pub execution_nonce_id: Option<String>,
    pub guarantee_level: String,
}

impl BudgetAuthorityReceiptRef {
    /// Project the frozen linkage from a receipt's typed budget-authority
    /// metadata. Returns `None` when the receipt carries no budget-authority
    /// block (a label-only receipt).
    #[must_use]
    pub fn from_receipt(receipt: &ChioReceipt) -> Option<Self> {
        let authority = receipt.financial_budget_authority_metadata()?;
        let grant_index = receipt
            .financial_metadata()
            .map_or(0, |financial| financial.grant_index);
        // `reconcile_event_id` is `Some` only when the terminal mutation was a
        // reconcile (not a reverse/release), so `is_none()` means "not
        // reconciled".
        let (reconcile_event_id, realized_units) = match authority.terminal.as_ref() {
            Some(terminal) if terminal.disposition == "reconciled" => {
                (terminal.event_id.clone(), terminal.realized_spend_units)
            }
            _ => (None, 0),
        };
        let execution_nonce_id = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("budget_authority"))
            .and_then(|block| block.get("execution_nonce_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Some(Self {
            hold_id: authority.hold_id.clone(),
            authorize_event_id: authority.authorize.event_id.clone(),
            reconcile_event_id,
            capability_id: receipt.capability_id.clone(),
            grant_index,
            exposed_units: authority.authorize.exposure_units,
            realized_units,
            execution_nonce_id,
            guarantee_level: authority.guarantee_level.clone(),
        })
    }
}

/// Read-only view of a kernel-signed execution nonce, implemented by
/// `chio_kernel::execution_nonce::SignedExecutionNonce`. Keeps this contract in
/// the lowest crate without depending on the kernel.
pub trait PresentedNonceView {
    fn nonce_id(&self) -> &str;
    fn bound_capability_id(&self) -> &str;
    fn bound_tool_server(&self) -> &str;
    fn bound_tool_name(&self) -> &str;
    fn bound_parameter_hash(&self) -> &str;
    fn verify_signed_by(&self, key: &PublicKey) -> bool;
}

/// Distinct rejection reasons; each of the (a)-(f) conjunction fragments maps to
/// at least one variant so a conformance matrix can flip them independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAuthoritativeReason {
    SignerNotAdmitted,
    NotMediatedDecision,
    NotPreventBoundary,
    ObservationOutcomePresent,
    NotMediatedTrustLevel,
    NotAllowDecision,
    MissingBudgetAuthority,
    HoldNotReconciled,
    ExposureNotCommitted,
    NonceLinkMissing,
    NonceLinkMismatch,
    NonceBindingMismatch { field: &'static str },
    NonceSignatureInvalid,
}

/// Structurally checkable conjunction over the kernel signature. Fail-closed:
/// any missing or invalid element is an `Err`.
pub fn is_authoritative_spend_receipt(
    receipt: &ChioReceipt,
    admitted_kernel_keys: &[PublicKey],
    presented_nonce: &dyn PresentedNonceView,
) -> Result<(), NotAuthoritativeReason> {
    // (e) signer must be an admitted kernel key.
    if !admitted_kernel_keys.contains(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::SignerNotAdmitted);
    }
    // (a) mediated-decision semantics (mirrors sidecar.rs:796-799 verify side).
    if receipt.receipt_kind != ReceiptKind::MediatedDecision {
        return Err(NotAuthoritativeReason::NotMediatedDecision);
    }
    if receipt.boundary_class != BoundaryClass::Prevent {
        return Err(NotAuthoritativeReason::NotPreventBoundary);
    }
    if receipt.observation_outcome.is_some() {
        return Err(NotAuthoritativeReason::ObservationOutcomePresent);
    }
    if receipt.trust_level != TrustLevel::Mediated {
        return Err(NotAuthoritativeReason::NotMediatedTrustLevel);
    }
    if !receipt.is_allowed() {
        return Err(NotAuthoritativeReason::NotAllowDecision);
    }
    // (b) an atomically committed, reconciled hold that actually moved exposure.
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    if budget.hold_id.is_empty() {
        return Err(NotAuthoritativeReason::MissingBudgetAuthority);
    }
    if budget.reconcile_event_id.is_none() {
        return Err(NotAuthoritativeReason::HoldNotReconciled);
    }
    if budget.exposed_units == 0 {
        return Err(NotAuthoritativeReason::ExposureNotCommitted);
    }
    // (d) hold <-> nonce cross-binding: the receipt must name the nonce.
    let linked_nonce_id = budget
        .execution_nonce_id
        .as_deref()
        .ok_or(NotAuthoritativeReason::NonceLinkMissing)?;
    if linked_nonce_id != presented_nonce.nonce_id() {
        return Err(NotAuthoritativeReason::NonceLinkMismatch);
    }
    // (c) the nonce binding must match the exact call the receipt authorized.
    if presented_nonce.bound_capability_id() != receipt.capability_id {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "capability_id" });
    }
    if presented_nonce.bound_tool_server() != receipt.tool_server {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "tool_server" });
    }
    if presented_nonce.bound_tool_name() != receipt.tool_name {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "tool_name" });
    }
    if presented_nonce.bound_parameter_hash() != receipt.action.parameter_hash {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "parameter_hash" });
    }
    // (e) the nonce must be signed by the same admitted kernel key.
    if !presented_nonce.verify_signed_by(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::NonceSignatureInvalid);
    }
    Ok(())
}

/// R4 guarantee-level truthfulness: refuse a receipt claiming a guarantee level
/// stronger than the operator's configured floor. Levels are ordered
/// advisory_posthoc < single_node_atomic < partition_escrowed < ha_linearizable.
#[must_use]
pub fn guarantee_level_rank(level: &str) -> u8 {
    match level {
        "ha_linearizable" => 3,
        "partition_escrowed" => 2,
        "single_node_atomic" => 1,
        _ => 0,
    }
}

/// Returns `Ok(())` only when the receipt's guarantee level is at least the
/// operator floor. Fail-closed on a missing budget-authority block.
pub fn receipt_meets_guarantee_floor(
    receipt: &ChioReceipt,
    minimum_level: &str,
) -> Result<(), NotAuthoritativeReason> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    if guarantee_level_rank(&budget.guarantee_level) < guarantee_level_rank(minimum_level) {
        return Err(NotAuthoritativeReason::NotMediatedTrustLevel);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, dead_code, unused_imports)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, PublicKey};
    use crate::receipt::body::{ChioReceipt, ChioReceiptBody};
    use crate::receipt::decision::{Decision, ToolCallAction};
    use crate::receipt::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel};

    /// Minimal test double for a kernel-signed execution nonce.
    struct FakeNonce {
        nonce_id: String,
        capability_id: String,
        tool_server: String,
        tool_name: String,
        parameter_hash: String,
        signer: Option<PublicKey>,
    }

    impl PresentedNonceView for FakeNonce {
        fn nonce_id(&self) -> &str { &self.nonce_id }
        fn bound_capability_id(&self) -> &str { &self.capability_id }
        fn bound_tool_server(&self) -> &str { &self.tool_server }
        fn bound_tool_name(&self) -> &str { &self.tool_name }
        fn bound_parameter_hash(&self) -> &str { &self.parameter_hash }
        fn verify_signed_by(&self, key: &PublicKey) -> bool {
            self.signer.as_ref() == Some(key)
        }
    }

    fn param_hash() -> String {
        let canonical = crate::canonical_json_bytes(&serde_json::json!({"x": 1})).unwrap();
        crate::sha256_hex(&canonical)
    }

    fn authoritative_receipt(kp: &Keypair) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({"x": 1})).unwrap();
        let parameter_hash = action.parameter_hash.clone();
        let content_hash = crate::sha256_hex(b"content");
        let metadata = serde_json::json!({
            "financial": { "grant_index": 0, "cost_charged": 50, "currency": "USD",
                "budget_remaining": 50, "budget_total": 100, "delegation_depth": 0,
                "root_budget_holder": "root", "settlement_status": "settled" },
            "budget_authority": {
                "guarantee_level": "single_node_atomic",
                "authority_profile": "authoritative_hold_event",
                "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
                "hold_id": "budget-hold:req-1:cap-1:0",
                "execution_nonce_id": "nonce-1",
                "mediated_spend": { "profile": MEDIATED_SPEND_PROFILE },
                "authorize": { "event_id": "budget-hold:req-1:cap-1:0:authorize",
                    "exposure_units": 100, "committed_cost_units_after": 100 },
                "terminal": { "disposition": "reconciled",
                    "event_id": "budget-hold:req-1:cap-1:0:reconcile",
                    "exposure_units": 100, "realized_spend_units": 50,
                    "committed_cost_units_after": 50 }
            }
        });
        let body = ChioReceiptBody {
            id: "rcpt-1".to_string(), timestamp: 1, capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(), tool_name: "tool".to_string(), action,
            decision: Some(Decision::Allow), receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent, observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted, redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(), content_hash, policy_hash: crate::sha256_hex(b"policy"),
            evidence: Vec::new(), metadata: Some(metadata), trust_level: TrustLevel::Mediated,
            tenant_id: None, kernel_key: kp.public_key(), bbs_projection_version: None,
        };
        let _ = parameter_hash;
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn good_nonce(kp: &Keypair, receipt: &ChioReceipt) -> FakeNonce {
        FakeNonce {
            nonce_id: "nonce-1".to_string(),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
            signer: Some(kp.public_key()),
        }
    }

    #[test]
    fn authoritative_receipt_with_bound_nonce_passes() {
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn r1_forged_mediated_label_without_budget_authority_is_rejected() {
        // R1: a trusted signer stamps advisory content as Mediated with zero budget movement.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        // Strip the budget_authority metadata but keep the Mediated label.
        receipt.metadata = Some(serde_json::json!({}));
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::MissingBudgetAuthority)
        );
    }
}
