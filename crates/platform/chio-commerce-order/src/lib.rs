mod error;
mod escrow;
mod ids;
mod mandate;
mod payment;
mod provider;
mod replay;
mod settlement;
mod types;
mod validation;

pub use error::CommerceOrderError;
pub use escrow::{
    accept, release, CommerceEscrowAcceptRequest, CommerceEscrowAcceptance, CommerceEscrowLedger,
    CommerceEscrowLeg, CommerceEscrowLegKind, CommerceEscrowRelease, CommerceEscrowStatus,
    CommerceReservationReceipt, CommerceSettlementDispatch, EscrowBroadcastIntent, OrderState,
    SignedCommerceReservationReceipt, VerifiedCommerceReservation,
    COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID,
};
pub use ids::{
    COMMERCE_ESCROW_LEDGER_SCHEMA_ID, COMMERCE_EVENT_LOG_SCHEMA_ID,
    COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID, COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
    COMMERCE_ORDER_CONTEXT_SCHEMA_ID, COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
    COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID, COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
    COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID, COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID,
    COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID,
};
pub use types::{
    CommerceCoverageRequirement, CommerceEventAuthorityReceiptArtifact,
    CommerceMandateProtocolPayload, CommerceOrderContext, CommerceOrderPassportReport,
    CommerceOrderVerificationBundle, CommerceSettlementPacket, CommerceTrustMarketRequirement,
    CommerceVerifiedTrustMarketContext,
};

use mandate::{validate_mandate_ledger, CommerceMandateLedger};
use payment::validate_payment_lifecycle;
use provider::validate_provider_trust_evidence;
use replay::{replay_event_log, CommerceEventLog};
use serde_json::json;
use settlement::validate_settlement_packet;
use types::{
    CommerceFederationTrustBundle, CommerceOrderDisclosurePolicy,
    CommerceOrderPassportArtifactDigests, CommercePaymentLifecycle, CommerceProviderPassport,
    CommerceReputationSnapshot,
};

const CLAIM_ORDER_REPLAY_CONSISTENT: &str = "claim.commerce.order_replay_consistent";
const CLAIM_PAYMENT_LIFECYCLE_BOUND: &str = "claim.commerce.payment_lifecycle_bound";
const CLAIM_MANDATE_ALLOWANCE_BOUND: &str = "claim.commerce.mandate_allowance_bound";
const CLAIM_ADMISSION_GATES_BOUND: &str = "claim.commerce.admission_gates_bound";
const CLAIM_SETTLEMENT_LIFECYCLE_BOUND: &str = "claim.commerce.settlement_lifecycle_bound";
const CLAIM_ORDER_PASSPORT_SUMMARY_BOUND: &str = "claim.commerce.order_passport_summary_bound";
const CLAIM_COVERAGE_DECISION_BOUND: &str = "claim.commerce.coverage_decision_bound";
const CLAIM_TRUST_MARKET_CONTEXT_BOUND: &str = "claim.commerce.trust_market_context_bound";
const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";
const RISK_COMPTROLLER_REPORT_SCHEMA_ID: &str = "chio.risk.comptroller-report.v1";

pub fn verify_commerce_order(
    bundle: &CommerceOrderVerificationBundle,
) -> Result<CommerceOrderPassportReport, CommerceOrderError> {
    bundle.order_context.validate_shape()?;
    verify_quote_digest(&bundle.order_context)?;
    verify_digest(
        "event log",
        &bundle.order_context.event_log_sha256,
        &bundle.event_log_bytes,
    )?;
    verify_digest(
        "payment lifecycle",
        &bundle.order_context.payment_lifecycle_sha256,
        &bundle.payment_lifecycle_bytes,
    )?;
    verify_digest(
        "mandate allowance ledger",
        &bundle.order_context.mandate_ledger_sha256,
        &bundle.mandate_ledger_bytes,
    )?;
    verify_digest(
        "provider passport",
        &bundle.order_context.provider_passport_sha256,
        &bundle.provider_passport_bytes,
    )?;
    verify_digest(
        "reputation snapshot",
        &bundle.order_context.reputation_snapshot_sha256,
        &bundle.reputation_snapshot_bytes,
    )?;
    verify_digest(
        "federation trust bundle",
        &bundle.order_context.federation_trust_bundle_sha256,
        &bundle.federation_trust_bundle_bytes,
    )?;
    verify_digest(
        "settlement packet",
        &bundle.order_context.settlement_packet_sha256,
        &bundle.settlement_packet_bytes,
    )?;
    verify_escrow_digest(&bundle.order_context, bundle.escrow_ledger_bytes.as_deref())?;
    let coverage_decision_bound = verify_coverage_requirement(
        &bundle.order_context,
        bundle.risk_comptroller_report_bytes.as_deref(),
        &bundle.trusted_risk_comptroller_signer_keys,
    )?;
    let trust_market_context_bound = verify_trust_market_requirement(
        &bundle.order_context,
        bundle.verified_trust_market_context.as_ref(),
    )?;

    let event_log: CommerceEventLog = parse_json("event log", &bundle.event_log_bytes)?;
    let payment: CommercePaymentLifecycle =
        parse_json("payment lifecycle", &bundle.payment_lifecycle_bytes)?;
    let mandate: CommerceMandateLedger =
        parse_json("mandate allowance ledger", &bundle.mandate_ledger_bytes)?;
    let provider_passport: CommerceProviderPassport =
        parse_json("provider passport", &bundle.provider_passport_bytes)?;
    let reputation_snapshot: CommerceReputationSnapshot =
        parse_json("reputation snapshot", &bundle.reputation_snapshot_bytes)?;
    let federation_trust_bundle: CommerceFederationTrustBundle = parse_json(
        "federation trust bundle",
        &bundle.federation_trust_bundle_bytes,
    )?;
    let settlement: CommerceSettlementPacket =
        parse_json("settlement packet", &bundle.settlement_packet_bytes)?;

    let replay = replay_event_log(
        &event_log,
        &bundle.order_context,
        &payment,
        &mandate,
        &bundle.event_authority_receipts,
        &bundle.trusted_event_authority_receipt_kernel_keys,
    )?;
    validate_provider_trust_evidence(
        &bundle.order_context,
        &provider_passport,
        &reputation_snapshot,
        &federation_trust_bundle,
        &bundle.trusted_provider_trust_signer_keys,
    )?;
    validate_mandate_ledger(
        &bundle.order_context,
        &payment,
        &mandate,
        &bundle.mandate_protocol_payloads,
    )?;
    validate_payment_lifecycle(
        &bundle.order_context,
        &payment,
        &bundle.trusted_payment_signer_keys,
    )?;
    validate_settlement_packet(&bundle.order_context, &payment, &settlement)?;
    let mut verified_claims = vec![
        CLAIM_ORDER_REPLAY_CONSISTENT.to_string(),
        CLAIM_PAYMENT_LIFECYCLE_BOUND.to_string(),
        CLAIM_MANDATE_ALLOWANCE_BOUND.to_string(),
        CLAIM_ADMISSION_GATES_BOUND.to_string(),
        CLAIM_SETTLEMENT_LIFECYCLE_BOUND.to_string(),
        CLAIM_ORDER_PASSPORT_SUMMARY_BOUND.to_string(),
    ];
    if coverage_decision_bound {
        verified_claims.push(CLAIM_COVERAGE_DECISION_BOUND.to_string());
    }
    if trust_market_context_bound {
        verified_claims.push(CLAIM_TRUST_MARKET_CONTEXT_BOUND.to_string());
    }

    Ok(CommerceOrderPassportReport {
        schema: COMMERCE_ORDER_PASSPORT_SCHEMA_ID.to_string(),
        id: format!("commerce-order-passport-{}", bundle.order_context.order_id),
        issued_at: bundle.order_context.issued_at.clone(),
        verdict: "verified".to_string(),
        order_id: bundle.order_context.order_id.clone(),
        current_state: replay.current_state,
        artifact_digests: commerce_order_passport_artifact_digests(&bundle.order_context)?,
        selective_disclosure_policy: commerce_order_disclosure_policy(),
        verified_claims,
    })
}

fn commerce_order_passport_artifact_digests(
    context: &CommerceOrderContext,
) -> Result<CommerceOrderPassportArtifactDigests, CommerceOrderError> {
    Ok(CommerceOrderPassportArtifactDigests {
        order_context_sha256: canonical_order_context_sha256(context)?,
        event_log_sha256: context.event_log_sha256.clone(),
        payment_lifecycle_sha256: context.payment_lifecycle_sha256.clone(),
        mandate_ledger_sha256: context.mandate_ledger_sha256.clone(),
        provider_passport_sha256: context.provider_passport_sha256.clone(),
        reputation_snapshot_sha256: context.reputation_snapshot_sha256.clone(),
        federation_trust_bundle_sha256: context.federation_trust_bundle_sha256.clone(),
        settlement_packet_sha256: context.settlement_packet_sha256.clone(),
        risk_comptroller_report_sha256: context
            .coverage_requirement
            .as_ref()
            .filter(|requirement| requirement.required)
            .map(|requirement| requirement.risk_comptroller_report_sha256.clone()),
    })
}

fn verify_trust_market_requirement(
    context: &CommerceOrderContext,
    verified_context: Option<&CommerceVerifiedTrustMarketContext>,
) -> Result<bool, CommerceOrderError> {
    let Some(requirement) = &context.trust_market_requirement else {
        return Ok(false);
    };
    if !requirement.required {
        return Ok(false);
    }
    let Some(verified_context) = verified_context else {
        return Err(CommerceOrderError::ReplayFailed(
            "trust-market verifier context missing".to_string(),
        ));
    };
    for (field, expected, actual) in [
        (
            "provider discovery snapshot",
            &requirement.provider_discovery_snapshot_ref,
            &verified_context.provider_discovery_snapshot_ref,
        ),
        (
            "provider selection report",
            &requirement.provider_selection_report_ref,
            &verified_context.provider_selection_report_ref,
        ),
        (
            "trust scorecard",
            &requirement.trust_scorecard_ref,
            &verified_context.trust_scorecard_ref,
        ),
        (
            "reputation import",
            &requirement.reputation_import_ref,
            &verified_context.reputation_import_ref,
        ),
        (
            "SLA commitment",
            &requirement.sla_commitment_ref,
            &verified_context.sla_commitment_ref,
        ),
        (
            "collateral position",
            &requirement.collateral_position_ref,
            &verified_context.collateral_position_ref,
        ),
        (
            "guarantee decision",
            &requirement.guarantee_decision_ref,
            &verified_context.guarantee_decision_ref,
        ),
        (
            "adjudication jurisdiction",
            &requirement.adjudication_jurisdiction_ref,
            &verified_context.adjudication_jurisdiction_ref,
        ),
    ] {
        if expected != actual {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "trust-market {field} ref mismatch"
            )));
        }
    }
    if verified_context.selected_provider_subject.is_empty() {
        return Err(CommerceOrderError::ReplayFailed(
            "trust-market selected provider missing".to_string(),
        ));
    }
    if let Some(coverage_requirement) = context
        .coverage_requirement
        .as_ref()
        .filter(|coverage_requirement| coverage_requirement.required)
    {
        if verified_context.risk_comptroller_report_ref
            != coverage_requirement.risk_comptroller_report_ref
        {
            return Err(CommerceOrderError::CoverageFailed(
                "trust-market risk report ref mismatch".to_string(),
            ));
        }
    }
    Ok(true)
}

fn commerce_order_disclosure_policy() -> CommerceOrderDisclosurePolicy {
    CommerceOrderDisclosurePolicy {
        policy_id: "chio.commerce.order-passport.public-summary.v1".to_string(),
        disclosed_fields: vec![
            "artifact_digests".to_string(),
            "current_state".to_string(),
            "order_id".to_string(),
            "verified_claims".to_string(),
        ],
        redacted_fields: vec![
            "acp_delegated_payment_token_hash".to_string(),
            "agent_subject".to_string(),
            "buyer_subject".to_string(),
            "payment_intent_id".to_string(),
            "x402_payment_requirements_hash".to_string(),
        ],
    }
}

#[derive(Debug, serde::Deserialize)]
struct CommerceCoverageDecisionReport {
    schema: String,
    id: String,
    order_id: String,
    verdict: String,
    risk_state: String,
    coverage: CommerceCoverageDecision,
    verified_claims: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CommerceCoverageDecision {
    coverage_id: String,
    order_id: String,
    currency: String,
    status: String,
}

fn verify_coverage_requirement(
    context: &CommerceOrderContext,
    risk_report_bytes: Option<&[u8]>,
    trusted_risk_comptroller_signer_keys: &[chio_core_types::PublicKey],
) -> Result<bool, CommerceOrderError> {
    let Some(requirement) = &context.coverage_requirement else {
        return Ok(false);
    };
    if !requirement.required {
        return Ok(false);
    }
    let Some(report_bytes) = risk_report_bytes else {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report missing".to_string(),
        ));
    };
    verify_digest(
        "risk comptroller report",
        &requirement.risk_comptroller_report_sha256,
        report_bytes,
    )?;
    let report_value: serde_json::Value = parse_json("risk comptroller report", report_bytes)?;
    chio_risk_comptroller::validate_risk_report_signature(
        &report_value,
        trusted_risk_comptroller_signer_keys,
    )
    .map_err(|error| CommerceOrderError::CoverageFailed(error.to_string()))?;
    let report: CommerceCoverageDecisionReport =
        serde_json::from_value(report_value).map_err(|error| {
            CommerceOrderError::InvalidArtifact {
                field: "risk comptroller report",
                message: error.to_string(),
            }
        })?;
    validate_coverage_decision_report(context, requirement, &report)?;
    Ok(true)
}

fn validate_coverage_decision_report(
    context: &CommerceOrderContext,
    requirement: &CommerceCoverageRequirement,
    report: &CommerceCoverageDecisionReport,
) -> Result<(), CommerceOrderError> {
    if report.schema != RISK_COMPTROLLER_REPORT_SCHEMA_ID {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report schema mismatch".to_string(),
        ));
    }
    if report.id != requirement.risk_comptroller_report_ref {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report ref mismatch".to_string(),
        ));
    }
    if report.order_id != context.order_id || report.coverage.order_id != context.order_id {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report order mismatch".to_string(),
        ));
    }
    if report.verdict != "verified" || report.risk_state != "reconciled" {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report was not verified".to_string(),
        ));
    }
    if !report
        .verified_claims
        .iter()
        .any(|claim| claim == CLAIM_RISK_COMPTROLLER_REPORT_BOUND)
    {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage report risk claim missing".to_string(),
        ));
    }
    if report.coverage.coverage_id != requirement.coverage_id {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage id mismatch".to_string(),
        ));
    }
    if report.coverage.status != "bound" {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage is not bound".to_string(),
        ));
    }
    if report.coverage.currency != context.quote_currency {
        return Err(CommerceOrderError::CoverageFailed(
            "coverage currency mismatch".to_string(),
        ));
    }
    Ok(())
}

fn verify_digest(field: &str, expected: &str, bytes: &[u8]) -> Result<(), CommerceOrderError> {
    let actual = sha256_hex(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(CommerceOrderError::DigestMismatch {
            field: field.to_string(),
            expected: expected.to_string(),
            actual,
        })
    }
}

fn verify_quote_digest(context: &CommerceOrderContext) -> Result<(), CommerceOrderError> {
    let actual = canonical_quote_sha256(context)?;
    if actual == context.quote_sha256 {
        Ok(())
    } else {
        Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "quote digest mismatch: expected {}, got {}",
                context.quote_sha256, actual
            ),
        })
    }
}

fn canonical_quote_sha256(context: &CommerceOrderContext) -> Result<String, CommerceOrderError> {
    let binding = json!({
        "amount_minor": context.quote_amount_minor,
        "currency": context.quote_currency,
        "merchant_subject": context.merchant_subject,
        "order_id": context.order_id,
        "quote_id": context.quote_id,
    });
    let canonical = chio_core_types::canonical_json_bytes(&binding).map_err(|error| {
        CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!("quote binding canonicalization failed: {error}"),
        }
    })?;
    Ok(sha256_hex(&canonical))
}

fn canonical_order_context_sha256(
    context: &CommerceOrderContext,
) -> Result<String, CommerceOrderError> {
    let canonical = chio_core_types::canonical_json_bytes(context).map_err(|error| {
        CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!("order context canonicalization failed: {error}"),
        }
    })?;
    Ok(sha256_hex(&canonical))
}

fn parse_json<T: for<'de> serde::Deserialize<'de>>(
    field: &'static str,
    bytes: &[u8],
) -> Result<T, CommerceOrderError> {
    serde_json::from_slice(bytes).map_err(|error| CommerceOrderError::InvalidArtifact {
        field,
        message: error.to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

/// Require proof for the order context's `escrow_digest`. When the context pins
/// an `escrow_digest`, the bundle MUST carry the escrow-ledger bytes that produced
/// it; the ledger is parsed, its CANONICAL digest (the same `digest()` the
/// accept/release code path pins) is recomputed and compared to the pinned value,
/// its conservation/isolation invariants are re-checked, and it is bound to this
/// order. Fail-closed: an `escrow_digest` with no backing ledger, a pinned digest
/// that does not equal the ledger's CANONICAL digest (so a non-canonical wire
/// encoding whose raw-byte hash is self-consistent is rejected), a ledger that
/// violates conservation/Seam A, or a ledger bound to a different order is all
/// rejected, so an arbitrary 64-hex value (or a non-canonical ledger encoding)
/// can never appear in a verified order passport. When no `escrow_digest` is
/// present there is nothing to prove.
fn verify_escrow_digest(
    context: &CommerceOrderContext,
    escrow_ledger_bytes: Option<&[u8]>,
) -> Result<(), CommerceOrderError> {
    let Some(expected) = context.escrow_digest.as_deref() else {
        return Ok(());
    };
    let Some(bytes) = escrow_ledger_bytes else {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: "escrow_digest is present but the verification bundle carries no escrow \
                      ledger bytes to prove it"
                .to_string(),
        });
    };
    // Parse the ledger first, then compare the pinned digest to the CANONICAL
    // digest the escrow code path produces. Hashing the raw wire bytes would
    // trust a non-canonical encoding (a self-consistent raw-byte hash over
    // whitespace-padded or reordered JSON), which the accept/release path would
    // never emit.
    let ledger: CommerceEscrowLedger = parse_json("escrow ledger", bytes)?;
    let canonical_digest = ledger.digest()?;
    if expected != canonical_digest {
        return Err(CommerceOrderError::DigestMismatch {
            field: "escrow ledger".to_string(),
            expected: expected.to_string(),
            actual: canonical_digest,
        });
    }
    // Re-check the ledger invariants a verified order passport must not vouch for
    // implicitly: value is conserved across all accounts and no leg names a
    // freetier:global pool row (Seam A). A malformed ledger whose canonical digest
    // happens to be the pinned value cannot ride into a verified passport.
    ledger.assert_conservation()?;
    if ledger.order_id != context.order_id {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger order mismatch: ledger {} vs context {}",
                ledger.order_id, context.order_id
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod escrow_digest_verification_tests {
    use super::*;
    use chio_test_support::prelude::*;

    const HEX64: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn order_context(order_id: &str) -> CommerceOrderContext {
        let value = json!({
            "schema": ids::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
            "id": "ctx-1",
            "issued_at": "2026-06-25T00:00:00Z",
            "order_id": order_id,
            "buyer_subject": "buyer:alice",
            "agent_subject": "agent:alice",
            "merchant_subject": "merchant:coffee",
            "intent_ref": "intent-1",
            "provider_admission_ref": "admission-1",
            "provider_passport_ref": "passport-1",
            "reputation_snapshot_ref": "reputation-1",
            "federation_trust_bundle_ref": "federation-1",
            "quote_id": "quote-1",
            "quote_amount_minor": 4200u64,
            "quote_currency": "USD",
            "quote_sha256": HEX64,
            "settlement_packet_ref": "settlement-packet-1",
            "reconciliation_ref": "reconciliation-1",
            "event_log_sha256": HEX64,
            "event_log_path": "event-log.json",
            "payment_lifecycle_sha256": HEX64,
            "payment_lifecycle_path": "payment-lifecycle.json",
            "mandate_ledger_sha256": HEX64,
            "mandate_ledger_path": "mandate-ledger.json",
            "provider_passport_sha256": HEX64,
            "provider_passport_path": "provider-passport.json",
            "reputation_snapshot_sha256": HEX64,
            "reputation_snapshot_path": "reputation-snapshot.json",
            "federation_trust_bundle_sha256": HEX64,
            "federation_trust_bundle_path": "federation-trust-bundle.json",
            "settlement_packet_sha256": HEX64,
            "settlement_packet_path": "settlement-packet.json",
            "current_state": "settlement_reconciled",
        });
        serde_json::from_value(value).test_expect("order context deserializes")
    }

    fn ledger(order_id: &str) -> CommerceEscrowLedger {
        CommerceEscrowLedger {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id: order_id.to_string(),
            currency: "USD".to_string(),
            depositor_account: "buyer:alice".to_string(),
            beneficiary_account: "merchant:coffee".to_string(),
            custody_account: "chio:commerce:escrow:custody".to_string(),
            amount_minor: 4200,
            legs: vec![CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Lock,
                from_account: "buyer:alice".to_string(),
                to_account: "chio:commerce:escrow:custody".to_string(),
                amount_minor: 4200,
            }],
            status: CommerceEscrowStatus::Locked,
        }
    }

    fn canonical_ledger_bytes(ledger: &CommerceEscrowLedger) -> Vec<u8> {
        chio_core_types::canonical_json_bytes(ledger).test_expect("canonical ledger bytes")
    }

    #[test]
    fn absent_escrow_digest_needs_no_proof() {
        let context = order_context("order-commerce-001");
        assert!(context.escrow_digest.is_none());
        verify_escrow_digest(&context, None).test_expect("no escrow digest is a no-op");
    }

    #[test]
    fn present_escrow_digest_with_matching_ledger_verifies() {
        let order_id = "order-commerce-001";
        let ledger = ledger(order_id);
        let bytes = canonical_ledger_bytes(&ledger);
        let mut context = order_context(order_id);
        context.escrow_digest = Some(sha256_hex(&bytes));
        verify_escrow_digest(&context, Some(&bytes)).test_expect("matching ledger proves digest");
    }

    #[test]
    fn present_escrow_digest_without_bytes_is_denied() {
        let mut context = order_context("order-commerce-001");
        context.escrow_digest = Some(HEX64.to_string());
        let error = verify_escrow_digest(&context, None)
            .test_expect_err("escrow digest with no ledger bytes is denied");
        assert!(matches!(
            error,
            CommerceOrderError::InvalidArtifact { message, .. }
                if message.contains("no escrow ledger bytes to prove it")
        ));
    }

    #[test]
    fn escrow_digest_that_does_not_recompute_is_denied() {
        let order_id = "order-commerce-001";
        let bytes = canonical_ledger_bytes(&ledger(order_id));
        let mut context = order_context(order_id);
        // A digest that does not match the supplied ledger bytes.
        context.escrow_digest = Some(HEX64.to_string());
        let error = verify_escrow_digest(&context, Some(&bytes))
            .test_expect_err("non-recomputing escrow digest is denied");
        assert!(matches!(error, CommerceOrderError::DigestMismatch { .. }));
    }

    #[test]
    fn escrow_ledger_bound_to_a_different_order_is_denied() {
        // The ledger proves a digest but is bound to a foreign order.
        let foreign_ledger = ledger("order-commerce-foreign");
        let bytes = canonical_ledger_bytes(&foreign_ledger);
        let mut context = order_context("order-commerce-001");
        context.escrow_digest = Some(sha256_hex(&bytes));
        let error = verify_escrow_digest(&context, Some(&bytes))
            .test_expect_err("escrow ledger bound to a different order is denied");
        assert!(matches!(
            error,
            CommerceOrderError::InvalidArtifact { message, .. }
                if message.contains("escrow ledger order mismatch")
        ));
    }

    /// Finding 3: a NON-CANONICAL ledger encoding whose raw-byte hash is pinned
    /// (a self-consistent raw-byte hash) is denied, because the pinned digest is
    /// now compared to the ledger's CANONICAL `digest()`, not to `sha256(raw wire
    /// bytes)`. The accept/release path only ever pins the canonical digest, so a
    /// non-canonical encoding cannot be trusted.
    #[test]
    fn non_canonical_ledger_with_self_consistent_raw_hash_is_denied() {
        let order_id = "order-commerce-001";
        let ledger = ledger(order_id);
        // Pretty (whitespace-padded) JSON is a valid but NON-canonical encoding:
        // its raw-byte hash differs from the canonical digest the escrow path pins.
        let non_canonical = serde_json::to_vec_pretty(&ledger).test_expect("pretty ledger bytes");
        let canonical = canonical_ledger_bytes(&ledger);
        assert_ne!(
            non_canonical, canonical,
            "pretty encoding must be non-canonical"
        );

        let mut context = order_context(order_id);
        // Self-consistent raw-byte hash over the non-canonical bytes: under the old
        // `sha256(raw bytes)` check this matched and was trusted.
        context.escrow_digest = Some(sha256_hex(&non_canonical));

        let error = verify_escrow_digest(&context, Some(&non_canonical))
            .test_expect_err("a non-canonical ledger encoding is denied");
        match error {
            CommerceOrderError::DigestMismatch {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "escrow ledger");
                // `expected` is the self-consistent raw-byte hash; `actual` is the
                // canonical digest the escrow path would have pinned. They differ.
                assert_eq!(expected, sha256_hex(&non_canonical));
                assert_eq!(actual, sha256_hex(&canonical));
                assert_ne!(expected, actual);
            }
            other => panic!("expected a DigestMismatch, got {other:?}"),
        }
    }
}
