//! Settlement observer slot wired into the kernel evaluator.
//!
//! Plugs `chio-settle::SettlementHook` into the kernel's post-dispatch
//! observer surface. A hook produces a typed outcome. Durable retry and
//! dead-letter routing is provided by the paired kernel observer runtime.
//!
//! The kernel field [`ChioKernel::settlement_observer`] holds an
//! optional handle; deployments that do not wire a settlement runtime
//! see byte-identical receipts (an integration test enforces this
//! invariant explicitly).

use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_core::receipt::{
    body::ChioReceipt,
    economics::{ChannelReceiptMetadataV1, SettlementStatus},
};
use chio_settle::{
    ObservedSettlement, SettlementFailureClass, SettlementFailureCode, SettlementFailureReason,
    SettlementHook, SettlementHookError, SettlementIdempotencyKey, SettlementObservation,
    SettlementOutcome, SettlementSkipReason,
};

/// Schema string emitted on the wire for settlement-observer status frames.
/// Public so external observers can pin against the same identifier the
/// kernel records.
pub const SETTLEMENT_OBSERVER_STATUS_SCHEMA: &str = "chio.settle.observer-status.v1";

/// Status the kernel records for each settlement observer invocation.
///
/// Settlement runs post-dispatch: regardless of which variant lands,
/// the receipt has already been signed and persisted. The variants
/// document only what the observer slot did with the hook's return,
/// not whether the receipt committed (it always committed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementObserverStatus {
    /// No settlement hook is registered on this kernel; the observation
    /// was not produced.
    NotRegistered,
    /// The receipt requires no settlement work.
    Skipped { reason: SettlementSkipReason },
    /// The hook accepted the observation and returned an outcome
    /// classification. The downstream lifecycle is then driven by the
    /// retry policy and dead-letter machinery.
    Observed { outcome: SettlementOutcome },
    /// Observation construction or the hook returned a typed failure.
    HookFailed {
        class: SettlementFailureClass,
        reason: SettlementFailureReason,
    },
}

impl SettlementObserverStatus {
    #[must_use]
    pub const fn skipped(reason: SettlementSkipReason) -> Self {
        Self::Skipped { reason }
    }

    #[must_use]
    pub fn hook_failed(err: &SettlementHookError) -> Self {
        let (class, reason) = err.classification();
        Self::HookFailed { class, reason }
    }
}

/// Result of validating and interpreting a finalized receipt for settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementObservationBuild {
    /// A valid positive-charge receipt produced an observation.
    Observation(Box<SettlementObservation>),
    /// The receipt legitimately requires no settlement work.
    Skipped(SettlementSkipReason),
    /// The receipt failed integrity or economic-metadata validation.
    Permanent(SettlementFailureReason),
}

fn permanent(code: SettlementFailureCode, detail: impl AsRef<[u8]>) -> SettlementObservationBuild {
    SettlementObservationBuild::Permanent(SettlementFailureReason::from_detail(code, detail))
}

fn malformed(detail: &'static str) -> SettlementFailureReason {
    SettlementFailureReason::from_detail(SettlementFailureCode::MalformedFinancialMetadata, detail)
}

fn optional_text(
    value: Option<&serde_json::Value>,
    detail: &'static str,
) -> Result<Option<String>, SettlementFailureReason> {
    match value {
        None => Ok(None),
        Some(serde_json::Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        Some(_) => Err(malformed(detail)),
    }
}

fn budget_hold_id(metadata: &serde_json::Value) -> Result<Option<String>, SettlementFailureReason> {
    match metadata.get("budget_authority") {
        None => Ok(None),
        Some(serde_json::Value::Object(budget)) => match budget.get("hold_id") {
            Some(serde_json::Value::String(hold_id)) if !hold_id.is_empty() => {
                Ok(Some(hold_id.clone()))
            }
            _ => Err(malformed("budget authority hold id is malformed")),
        },
        Some(_) => Err(malformed("budget authority metadata is not an object")),
    }
}

fn retained_payment_settlement(
    metadata: &serde_json::Value,
) -> Option<Result<ObservedSettlement, SettlementFailureReason>> {
    let financial = match metadata.get("financial")? {
        serde_json::Value::Object(financial) => financial,
        _ => return Some(Err(malformed("financial metadata is not an object"))),
    };
    match financial.get("payment_authorization_ambiguous") {
        None | Some(serde_json::Value::Bool(false)) => None,
        Some(serde_json::Value::Bool(true)) => Some(retained_payment_fields(metadata, financial)),
        Some(_) => Some(Err(malformed(
            "payment authorization ambiguity marker is not a boolean",
        ))),
    }
}

fn retained_payment_fields(
    metadata: &serde_json::Value,
    financial: &serde_json::Map<String, serde_json::Value>,
) -> Result<ObservedSettlement, SettlementFailureReason> {
    let operation_id = optional_text(
        financial.get("payment_attempt_reference"),
        "payment attempt reference is malformed",
    )?
    .ok_or_else(|| malformed("retained payment requires a payment attempt reference"))?;
    let hold_id = budget_hold_id(metadata)?
        .ok_or_else(|| malformed("retained payment requires a budget hold id"))?;
    let exposure_units = metadata
        .pointer("/budget_authority/authorize/exposure_units")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed("retained payment requires held exposure units"))?;
    Ok(ObservedSettlement::RetainedPayment {
        operation_id,
        hold_id,
        exposure_units,
    })
}

fn observation_for(receipt: &ChioReceipt, settlement: ObservedSettlement) -> SettlementObservation {
    let observation = SettlementObservation::new(
        receipt.id.clone(),
        receipt.timestamp,
        receipt.tool_server.clone(),
        receipt.tool_name.clone(),
        receipt.capability_id.clone(),
        settlement,
        receipt.content_hash.clone(),
        receipt.policy_hash.clone(),
    );
    match receipt.tenant_id.clone() {
        Some(tenant_id) => observation.with_tenant(tenant_id),
        None => observation,
    }
}

#[must_use]
pub fn build_observation(
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
) -> SettlementObservationBuild {
    match receipt.verify_signature() {
        Ok(true) => {}
        Ok(false) => {
            return permanent(
                SettlementFailureCode::InvalidReceiptSignature,
                "receipt signature did not verify",
            );
        }
        Err(error) => {
            return permanent(
                SettlementFailureCode::InvalidReceiptSignature,
                error.to_string(),
            );
        }
    }
    match receipt.action.verify_hash() {
        Ok(true) => {}
        Ok(false) => {
            return permanent(
                SettlementFailureCode::InvalidActionHash,
                "receipt action hash did not verify",
            );
        }
        Err(error) => {
            return permanent(SettlementFailureCode::InvalidActionHash, error.to_string());
        }
    }
    if trusted_kernel_keys.is_empty()
        || !trusted_kernel_keys
            .iter()
            .any(|trusted| trusted == &receipt.kernel_key)
    {
        return permanent(
            SettlementFailureCode::UntrustedReceiptSigner,
            "receipt signer is not trusted",
        );
    }
    let metadata = receipt.metadata.as_ref();
    let channelized = if let Some(channel_value) = metadata.and_then(|value| value.get("channel")) {
        match serde_json::from_value::<ChannelReceiptMetadataV1>(channel_value.clone()) {
            Ok(channel) if channel.is_valid() => true,
            Ok(_) | Err(_) => {
                return permanent(
                    SettlementFailureCode::InvalidObservation,
                    "channel metadata is malformed",
                );
            }
        }
    } else {
        false
    };
    if channelized {
        if !receipt.is_allowed() && !receipt.is_denied() {
            return permanent(
                SettlementFailureCode::InvalidObservation,
                "receipt does not contain an authorized terminal decision",
            );
        }
        if receipt.financial_metadata().is_none() {
            return permanent(
                SettlementFailureCode::MalformedFinancialMetadata,
                "channel financial metadata is malformed",
            );
        }
        return permanent(
            SettlementFailureCode::InvalidObservation,
            "channel settlement handler is not configured",
        );
    }
    if receipt.is_denied() {
        return match metadata.and_then(retained_payment_settlement) {
            None => SettlementObservationBuild::Skipped(SettlementSkipReason::Denied),
            Some(Err(reason)) => SettlementObservationBuild::Permanent(reason),
            Some(Ok(settlement)) => SettlementObservationBuild::Observation(Box::new(
                observation_for(receipt, settlement),
            )),
        };
    }
    if !receipt.is_allowed() {
        return permanent(
            SettlementFailureCode::InvalidObservation,
            "receipt does not contain an authorized terminal decision",
        );
    }

    let Some(metadata) = metadata else {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::NoEconomicIntent);
    };
    let Some(financial_value) = metadata.get("financial") else {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::NoEconomicIntent);
    };
    let Some(financial) = financial_value.as_object() else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "financial metadata is not an object",
        );
    };
    let Some(charged_value) = financial.get("cost_charged") else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "financial metadata is missing cost_charged",
        );
    };
    let Some(units) = charged_value.as_u64() else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "cost_charged is not an unsigned integer",
        );
    };
    if units == 0 {
        return SettlementObservationBuild::Skipped(SettlementSkipReason::ZeroCharge);
    }
    let Some(currency) = financial
        .get("currency")
        .and_then(serde_json::Value::as_str)
    else {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "positive cost_charged requires a currency",
        );
    };
    // ISO 4217 alphabetic codes are the money path's invariant, enforced identically
    // on the charge path, payment journal, cumulative approval, receipt query, and
    // channel and EVM settlement. A code that does not conform is malformed metadata
    // rather than a new denomination, so classifying it permanent is correct. A
    // backfill that enrolls receipts written before this rule must revisit this
    // classification first, since those receipts were accepted without a format check.
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return permanent(
            SettlementFailureCode::MalformedFinancialMetadata,
            "positive cost_charged requires a three-letter uppercase currency",
        );
    }

    let status = match financial
        .get("settlement_status")
        .cloned()
        .map(serde_json::from_value::<SettlementStatus>)
    {
        Some(Ok(status)) => status,
        Some(Err(_)) | None => {
            return permanent(
                SettlementFailureCode::MalformedFinancialMetadata,
                "positive cost_charged requires a settlement status",
            );
        }
    };
    let payment_reference = match optional_text(
        financial.get("payment_reference"),
        "payment reference is malformed",
    ) {
        Ok(payment_reference) => payment_reference,
        Err(reason) => return SettlementObservationBuild::Permanent(reason),
    };
    let hold_id = match budget_hold_id(metadata) {
        Ok(hold_id) => hold_id,
        Err(reason) => return SettlementObservationBuild::Permanent(reason),
    };

    SettlementObservationBuild::Observation(Box::new(observation_for(
        receipt,
        ObservedSettlement::Charge {
            amount: chio_core::capability::scope::MonetaryAmount {
                currency: currency.to_string(),
                units,
            },
            status,
            payment_reference,
            hold_id,
        },
    )))
}

/// Run the registered settlement hook against a freshly signed receipt.
///
/// Settlement is observer-only relative to receipt bytes: the receipt
/// has already been signed and persisted before this function runs,
/// and the returned status NEVER feeds back into the dispatch path.
/// The function is plumbed through the kernel struct in
/// [`super::ChioKernel::run_settlement_observer`] so callers only
/// need the kernel handle.
#[must_use]
pub fn run_observer(
    hook: Option<&Arc<dyn SettlementHook>>,
    receipt: &ChioReceipt,
    trusted_kernel_keys: &[PublicKey],
    idempotency_key: &SettlementIdempotencyKey,
) -> SettlementObserverStatus {
    let Some(hook) = hook else {
        return SettlementObserverStatus::NotRegistered;
    };

    let observation = match build_observation(receipt, trusted_kernel_keys) {
        SettlementObservationBuild::Observation(observation) => observation,
        SettlementObservationBuild::Skipped(reason) => {
            return SettlementObserverStatus::skipped(reason);
        }
        SettlementObservationBuild::Permanent(reason) => {
            return SettlementObserverStatus::HookFailed {
                class: SettlementFailureClass::Permanent,
                reason,
            };
        }
    };

    if idempotency_key.receipt_id != observation.receipt_id || idempotency_key.row_version == 0 {
        return SettlementObserverStatus::hook_failed(&SettlementHookError::InvalidObservation(
            "settlement idempotency key does not match the claimed receipt".to_string(),
        ));
    }

    match hook.observe(&observation, idempotency_key) {
        Ok(outcome) => SettlementObserverStatus::Observed { outcome },
        Err(error) => SettlementObserverStatus::hook_failed(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core::capability::scope::MonetaryAmount;
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        economics::CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA, kinds::TrustLevel,
        metadata::GuardEvidence,
    };

    fn sign_with(body_metadata: serde_json::Value, decision: Decision) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("test tool-call action constructs");
        sign_with_action(body_metadata, decision, action)
    }

    fn sign_with_action(
        body_metadata: serde_json::Value,
        decision: Decision,
        action: ToolCallAction,
    ) -> ChioReceipt {
        let kp = Keypair::generate();
        let body = ChioReceiptBody {
            id: "rcpt-test".to_string(),
            timestamp: 100,
            capability_id: "cap-1".to_string(),
            tool_server: "srv-1".to_string(),
            tool_name: "tool-1".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "ch-1".to_string(),
            policy_hash: "ph-1".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "G".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: Some(body_metadata),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, &kp).expect("test receipt signs")
    }

    fn channel_metadata() -> serde_json::Value {
        serde_json::json!({
            "schema": CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA,
            "channelId": "a".repeat(64),
            "openDigest": "b".repeat(64),
            "reservationId": "c".repeat(64),
            "reservationDigest": "d".repeat(64),
            "sequence": 1,
            "settlementMode": "channelized",
        })
    }

    fn idempotency_key(receipt: &ChioReceipt) -> SettlementIdempotencyKey {
        SettlementIdempotencyKey {
            receipt_id: receipt.id.clone(),
            row_version: 1,
        }
    }

    struct AcceptingHook;
    impl SettlementHook for AcceptingHook {
        fn observe(
            &self,
            observation: &SettlementObservation,
            idempotency_key: &SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            assert_eq!(idempotency_key.receipt_id, observation.receipt_id);
            assert_eq!(idempotency_key.row_version, 1);
            Ok(SettlementOutcome::accepted(format!(
                "ts-{}",
                observation.receipt_id
            )))
        }
    }

    struct FailingHook;
    impl SettlementHook for FailingHook {
        fn observe(
            &self,
            _observation: &SettlementObservation,
            _idempotency_key: &SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            Err(SettlementHookError::Transient("rpc lag".to_string()))
        }
    }

    #[test]
    fn build_observation_skips_explicit_deny() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 100, "currency": "USD"}
            }),
            Decision::Deny {
                reason: "denied".to_string(),
                guard: "G".to_string(),
            },
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Skipped(SettlementSkipReason::Denied)
        ));
    }

    #[test]
    fn build_observation_rejects_nonterminal_decisions() {
        let cases = [
            Decision::Cancelled {
                reason: "cancelled".to_string(),
            },
            Decision::Incomplete {
                reason: "incomplete".to_string(),
            },
        ];

        for decision in cases {
            let receipt = sign_with(
                serde_json::json!({
                    "financial": {"cost_charged": 100, "currency": "USD"}
                }),
                decision,
            );
            assert!(matches!(
                build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
                SettlementObservationBuild::Permanent(ref reason)
                    if reason.code() == SettlementFailureCode::InvalidObservation
            ));
        }
    }

    #[test]
    fn build_observation_skips_zero_priced_receipts() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Skipped(SettlementSkipReason::ZeroCharge)
        ));
    }

    #[test]
    fn build_observation_skips_when_metadata_missing_financial_section() {
        let receipt = sign_with(serde_json::json!({}), Decision::Allow);
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Skipped(SettlementSkipReason::NoEconomicIntent)
        ));
    }

    #[test]
    fn build_observation_rejects_channelized_receipts_with_malformed_financial_metadata() {
        let receipt = sign_with(
            serde_json::json!({
                "channel": channel_metadata(),
                "financial": "invalid"
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::MalformedFinancialMetadata
        ));
    }

    #[test]
    fn build_observation_rejects_channelized_receipts_without_financial_metadata() {
        let receipt = sign_with(
            serde_json::json!({"channel": channel_metadata()}),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::MalformedFinancialMetadata
        ));
    }

    #[test]
    fn build_observation_rejects_denied_channelized_receipts_without_a_channel_handler() {
        let receipt = sign_with(
            serde_json::json!({
                "channel": channel_metadata(),
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 0,
                    "currency": "USD",
                    "budget_remaining": 1000,
                    "budget_total": 1000,
                    "delegation_depth": 0,
                    "root_budget_holder": "payer",
                    "settlement_status": "not_applicable"
                }
            }),
            Decision::Deny {
                reason: "denied".to_owned(),
                guard: "G".to_owned(),
            },
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidObservation
        ));
    }

    #[test]
    fn build_observation_rejects_channelized_receipts_without_a_channel_handler() {
        let receipt = sign_with(
            serde_json::json!({
                "channel": channel_metadata(),
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 250,
                    "currency": "USD",
                    "budget_remaining": 750,
                    "budget_total": 1000,
                    "delegation_depth": 0,
                    "root_budget_holder": "payer",
                    "settlement_status": "pending"
                }
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidObservation
        ));
    }

    #[test]
    fn build_observation_rejects_malformed_channel_metadata() {
        let receipt = sign_with(
            serde_json::json!({
                "channel": {"schema": CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA},
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidObservation
        ));
    }

    #[test]
    fn build_observation_validates_integrity_and_trust_before_channel_skip() {
        let mut invalid_signature = sign_with(
            serde_json::json!({"channel": channel_metadata()}),
            Decision::Allow,
        );
        invalid_signature.tool_name = "tampered".to_string();
        assert!(matches!(
            build_observation(
                &invalid_signature,
                std::slice::from_ref(&invalid_signature.kernel_key)
            ),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidReceiptSignature
        ));

        let untrusted = sign_with(
            serde_json::json!({"channel": channel_metadata()}),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&untrusted, &[]),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::UntrustedReceiptSigner
        ));
    }

    #[test]
    fn build_observation_rejects_invalid_signature() {
        let mut receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        receipt.tool_name = "tampered".to_string();
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidReceiptSignature
        ));
    }

    #[test]
    fn build_observation_rejects_mismatched_action_hash() {
        let mut action = ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/a"}))
            .expect("test tool-call action constructs");
        action.parameters = serde_json::json!({"path": "/tmp/b"});
        let receipt = sign_with_action(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
            action,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::InvalidActionHash
        ));
    }

    #[test]
    fn build_observation_constructs_priced_frame() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        let SettlementObservationBuild::Observation(observation) =
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
        else {
            panic!("priced receipt did not yield an observation");
        };
        assert_eq!(observation.receipt_id, receipt.id);
        assert_eq!(observation.finalized_at, 100);
        assert_eq!(
            observation.settlement,
            ObservedSettlement::Charge {
                amount: MonetaryAmount {
                    currency: "USD".to_string(),
                    units: 250,
                },
                status: SettlementStatus::Settled,
                payment_reference: None,
                hold_id: None,
            }
        );
        assert_eq!(observation.content_hash, "ch-1");
    }

    #[test]
    fn build_observation_carries_the_recorded_settlement_truth() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "cost_charged": 250,
                    "currency": "USD",
                    "settlement_status": "settled",
                    "payment_reference": "pay-1"
                },
                "budget_authority": {"hold_id": "hold-1"}
            }),
            Decision::Allow,
        );
        let SettlementObservationBuild::Observation(observation) =
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
        else {
            panic!("settled receipt did not yield an observation");
        };
        assert_eq!(
            observation.settlement,
            ObservedSettlement::Charge {
                amount: MonetaryAmount {
                    currency: "USD".to_string(),
                    units: 250,
                },
                status: SettlementStatus::Settled,
                payment_reference: Some("pay-1".to_string()),
                hold_id: Some("hold-1".to_string()),
            }
        );
    }

    fn retained_payment_metadata() -> serde_json::Value {
        serde_json::json!({
            "financial": {
                "payment_authorization_ambiguous": true,
                "payment_authorization_error_code": "timeout",
                "payment_attempt_reference": "op-1"
            },
            "budget_authority": {
                "hold_id": "hold-1",
                "authorize": {"exposure_units": 100, "committed_cost_units_after": 100}
            }
        })
    }

    fn denied() -> Decision {
        Decision::Deny {
            reason: "payment authorization outcome is ambiguous".to_string(),
            guard: "kernel".to_string(),
        }
    }

    #[test]
    fn build_observation_observes_a_retained_payment_denial() {
        let receipt = sign_with(retained_payment_metadata(), denied());
        let SettlementObservationBuild::Observation(observation) =
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
        else {
            panic!("retained payment denial did not yield an observation");
        };
        assert_eq!(
            observation.settlement,
            ObservedSettlement::RetainedPayment {
                operation_id: "op-1".to_string(),
                hold_id: "hold-1".to_string(),
                exposure_units: 100,
            }
        );
    }

    #[test]
    fn build_observation_skips_a_denial_with_an_absent_or_false_ambiguity_marker() {
        let cases = [
            serde_json::json!({}),
            serde_json::json!({"financial": {"cost_charged": 0, "currency": "USD"}}),
            serde_json::json!({"financial": {"payment_authorization_ambiguous": false}}),
        ];
        for metadata in cases {
            let receipt = sign_with(metadata.clone(), denied());
            assert_eq!(
                build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
                SettlementObservationBuild::Skipped(SettlementSkipReason::Denied),
                "{metadata}"
            );
        }
    }

    #[test]
    fn build_observation_rejects_a_denial_with_malformed_ambiguity_evidence() {
        let cases = [
            (
                serde_json::json!({"financial": "invalid"}),
                "financial metadata is not an object",
            ),
            (
                serde_json::json!({"financial": {"payment_authorization_ambiguous": "true"}}),
                "payment authorization ambiguity marker is not a boolean",
            ),
            (
                serde_json::json!({"financial": {"payment_authorization_ambiguous": null}}),
                "payment authorization ambiguity marker is not a boolean",
            ),
            (
                serde_json::json!({"financial": {"payment_authorization_ambiguous": 1}}),
                "payment authorization ambiguity marker is not a boolean",
            ),
        ];
        for (metadata, detail) in cases {
            let receipt = sign_with(metadata.clone(), denied());
            assert_eq!(
                build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
                SettlementObservationBuild::Permanent(SettlementFailureReason::from_detail(
                    SettlementFailureCode::MalformedFinancialMetadata,
                    detail,
                )),
                "{metadata}"
            );
        }
    }

    #[test]
    fn build_observation_rejects_a_retained_payment_without_its_bindings() {
        let removals = [
            ("/financial", "payment_attempt_reference"),
            ("/budget_authority", "hold_id"),
            ("/budget_authority/authorize", "exposure_units"),
        ];
        for (parent, key) in removals {
            let mut metadata = retained_payment_metadata();
            if let Some(object) = metadata
                .pointer_mut(parent)
                .and_then(serde_json::Value::as_object_mut)
            {
                object.remove(key);
            }
            let receipt = sign_with(metadata, denied());
            assert!(
                matches!(
                    build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
                    SettlementObservationBuild::Permanent(ref reason)
                        if reason.code() == SettlementFailureCode::MalformedFinancialMetadata
                ),
                "missing {parent}/{key} must be malformed"
            );
        }
    }

    #[test]
    fn build_observation_rejects_untrusted_signer() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, &[]),
            SettlementObservationBuild::Permanent(ref reason)
                if reason.code() == SettlementFailureCode::UntrustedReceiptSigner
        ));
    }

    #[test]
    fn run_observer_returns_not_registered_without_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        let status = run_observer(
            None,
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(status, SettlementObserverStatus::NotRegistered));
    }

    #[test]
    fn run_observer_records_hook_outcome() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(AcceptingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        match status {
            SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::Accepted { transcript_id, .. },
            } => assert_eq!(transcript_id, format!("ts-{}", receipt.id)),
            other => panic!("expected accepted outcome, got {other:?}"),
        }
    }

    #[test]
    fn run_observer_skips_zero_price_without_invoking_hook() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 0, "currency": "USD"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(
            status,
            SettlementObserverStatus::Skipped {
                reason: SettlementSkipReason::ZeroCharge,
            }
        ));
    }

    #[test]
    fn build_observation_reads_canonical_financial_metadata() {
        // The kernel canonical financial-metadata shape is
        // `FinancialReceiptMetadata` (`cost_charged`, `currency`,
        // `attempted_cost`). Receipts emitted by the kernel's normal
        // finalize path use this shape, so the settlement observer
        // MUST recognize it.
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "grant_index": 0,
                    "cost_charged": 250,
                    "currency": "USD",
                    "budget_remaining": 750,
                    "budget_total": 1000,
                    "delegation_depth": 1,
                    "root_budget_holder": "tenant-a",
                    "settlement_status": "pending"
                }
            }),
            Decision::Allow,
        );
        let SettlementObservationBuild::Observation(observation) =
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key))
        else {
            panic!("canonical financial metadata did not yield an observation");
        };
        assert!(matches!(
            observation.settlement,
            ObservedSettlement::Charge {
                ref amount,
                status: SettlementStatus::Pending,
                ..
            } if amount.units == 250 && amount.currency == "USD"
        ));
    }

    #[test]
    fn build_observation_skips_zero_cost_charged() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {
                    "cost_charged": 0,
                    "currency": "USD"
                }
            }),
            Decision::Allow,
        );
        assert!(matches!(
            build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
            SettlementObservationBuild::Skipped(SettlementSkipReason::ZeroCharge)
        ));
    }

    #[test]
    fn run_observer_records_hook_failures_without_panicking() {
        let receipt = sign_with(
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"}
            }),
            Decision::Allow,
        );
        let hook: Arc<dyn SettlementHook> = Arc::new(FailingHook);
        let status = run_observer(
            Some(&hook),
            &receipt,
            std::slice::from_ref(&receipt.kernel_key),
            &idempotency_key(&receipt),
        );
        assert!(matches!(
            status,
            SettlementObserverStatus::HookFailed {
                class: SettlementFailureClass::Retryable,
                reason,
            } if reason.code() == SettlementFailureCode::Backend
        ));
    }

    #[test]
    fn build_observation_rejects_malformed_positive_financial_metadata() {
        let cases = [
            serde_json::json!({"financial": {"currency": "USD"}}),
            serde_json::json!({"financial": {"cost_charged": "250", "currency": "USD"}}),
            serde_json::json!({"financial": {"cost_charged": 250}}),
            serde_json::json!({"financial": {"cost_charged": 250, "currency": "usd"}}),
            serde_json::json!({"financial": {"cost_charged": 250, "currency": "US D"}}),
            serde_json::json!({"financial": {"cost_charged": 250, "currency": "USD"}}),
            serde_json::json!({"financial": {
                "cost_charged": 250, "currency": "USD", "settlement_status": "unknown"
            }}),
            serde_json::json!({"financial": {
                "cost_charged": 250, "currency": "USD", "settlement_status": "settled",
                "payment_reference": 7
            }}),
            serde_json::json!({
                "financial": {"cost_charged": 250, "currency": "USD", "settlement_status": "settled"},
                "budget_authority": {"hold_id": ""}
            }),
            serde_json::json!({"financial": "invalid"}),
        ];

        for metadata in cases {
            let receipt = sign_with(metadata, Decision::Allow);
            assert!(matches!(
                build_observation(&receipt, std::slice::from_ref(&receipt.kernel_key)),
                SettlementObservationBuild::Permanent(ref reason)
                    if reason.code() == SettlementFailureCode::MalformedFinancialMetadata
            ));
        }
    }
}
