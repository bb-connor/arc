//! Order passport replay for an order whose context pins a locked escrow
//! ledger: `accept` locks custody at settlement-packet assembly against the
//! buyer's signed acceptance and a reservation of the buyer's account, the
//! event log replays through settlement dispatch, and `verify_commerce_order`
//! proves the pinned ledger and reproduces the same verdict on every replay.

use chio_commerce_order::{
    accept, AcceptedEscrow, CommerceEscrowAcceptRequest, CommerceEscrowAcceptance,
    CommerceEscrowError, CommerceEscrowLedger, CommerceEscrowLeg, CommerceEscrowLegKind,
    CommerceEscrowStatus, CommerceOrderError, CommerceOrderVerificationBundle,
    CommerceReservationReceipt, CommerceSettlementDispatch, COMMERCE_ESCROW_ACCEPTANCE_SCHEMA_ID,
    COMMERCE_ESCROW_CUSTODY_ACCOUNT, COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID,
};
use chio_core_types::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_test_support::prelude::*;

#[path = "support/commerce_fixture.rs"]
mod commerce_fixture;
use commerce_fixture::*;

const ASSEMBLE_RECEIPT_REF: &str = "receipt-settlement-assemble-commerce-001";
const DISPATCH_RECEIPT_REF: &str = "receipt-settlement-dispatch-commerce-001";
const ACCEPTED_AT: u64 = 500;

fn merchant() -> Keypair {
    Keypair::from_seed(&[41u8; 32])
}

fn commerce_payment_signer() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn offer_token(issuer: &Keypair, subject: &PublicKey) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "offer-token-commerce-001".to_string(),
        issuer: issuer.public_key(),
        subject: subject.clone(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "demo-server".to_string(),
                tool_name: "search".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: Some(usd(4200)),
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at: 100,
        expires_at: 10_000,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).test_expect("offer token signs")
}

/// Replays the offline PSP order through settlement-packet assembly and
/// dispatch: keeps the events through `fulfillment_attested`, then appends the
/// assembly event and the dispatch event whose authority receipt the
/// settlement packet names.
fn replay_through_settlement_dispatch(bundle: &mut CommerceOrderVerificationBundle) {
    mutate_event_log(bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let fulfillment_index = events
            .iter()
            .position(|event| event["next_state"] == "fulfillment_attested")
            .test_expect("fulfillment attested event exists");
        let dispatch = events
            .iter()
            .find(|event| event["next_state"] == "settlement_dispatched")
            .test_expect("settlement dispatch event exists")
            .clone();
        events.truncate(fulfillment_index + 1);
        events.push(serde_json::json!({
            "actor": "agent:single-call-authority",
            "authority_receipt_ref": ASSEMBLE_RECEIPT_REF,
            "event_id": "event-commerce-001-settlement-assemble",
            "evidence_refs": ["settlement-packet-commerce-001"],
            "idempotency_key": "idem-event-commerce-001-settlement-assemble",
            "next_state": "settlement_packet_assembled",
            "occurred_at": "2026-06-10T00:05:30Z",
            "order_id": "order-commerce-001",
            "prior_state": "fulfillment_attested",
            "transition": "assemble_settlement_packet"
        }));
        let mut dispatch = dispatch;
        dispatch["prior_state"] = serde_json::json!("settlement_packet_assembled");
        events.push(dispatch);
    });
}

/// Locks custody for the order at `fulfillment_attested` and pins the result
/// into the bundle: the accepted context advanced to `settlement_dispatched`,
/// the signed settlement packet body, and the locked ledger bytes.
fn lock_escrow(bundle: &mut CommerceOrderVerificationBundle) -> AcceptedEscrow {
    let issuer = merchant();
    let buyer = Keypair::from_seed(&[42u8; 32]);
    let reservation_authority = Keypair::from_seed(&[43u8; 32]);
    let settlement_authority = Keypair::from_seed(&[44u8; 32]);
    let token = offer_token(&issuer, &buyer.public_key());
    let token_offer_sha256 = sha256_hex(
        &chio_core_types::canonical_json_bytes(&token).test_expect("offer canonicalizes"),
    );

    let mut order_context = bundle.order_context.clone();
    order_context.current_state = "fulfillment_attested".to_string();
    let acceptance = SignedExportEnvelope::sign(
        CommerceEscrowAcceptance {
            schema: COMMERCE_ESCROW_ACCEPTANCE_SCHEMA_ID.to_string(),
            order_id: order_context.order_id.clone(),
            quote_sha256: order_context.quote_sha256.clone(),
            buyer_subject: order_context.buyer_subject.clone(),
            token_offer_id: token.id.clone(),
            token_offer_sha256: token_offer_sha256.clone(),
            accepted_at: ACCEPTED_AT,
        },
        &buyer,
    )
    .test_expect("buyer signs the acceptance");
    let reservation = SignedExportEnvelope::sign(
        CommerceReservationReceipt {
            schema: COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID.to_string(),
            receipt_id: "reservation-commerce-001".to_string(),
            order_id: order_context.order_id.clone(),
            token_offer_id: token.id.clone(),
            token_offer_sha256,
            depositor_account: order_context.buyer_subject.clone(),
            reserved_amount: usd(4200),
        },
        &reservation_authority,
    )
    .test_expect("reservation receipt signs");
    let accepted = accept(CommerceEscrowAcceptRequest {
        order_context: &order_context,
        token_offer: &token,
        acceptance: &acceptance,
        reservation: &reservation,
        trusted_reservation_authorities: &[reservation_authority.public_key()],
        settlement: CommerceSettlementDispatch {
            issued_at: "2026-06-10T00:05:30Z".to_string(),
            psp: "stripe-shaped-offline".to_string(),
            payment_intent_id: "pi_commerce_001".to_string(),
            settlement_rail: "offline-psp-ledger".to_string(),
            settlement_account_ref: "settlement-account-commerce-001".to_string(),
            dispatch_receipt_ref: DISPATCH_RECEIPT_REF.to_string(),
            status: "dispatched".to_string(),
        },
        settlement_authority: &settlement_authority,
    })
    .test_expect("accept locks custody");

    let mut dispatched = accepted.updated_context().clone();
    dispatched.current_state = "settlement_dispatched".to_string();
    bundle.order_context = dispatched;
    bundle.settlement_packet_bytes =
        chio_core_types::canonical_json_bytes(&accepted.settlement_packet().body)
            .test_expect("settlement packet canonicalizes");
    bundle.escrow_ledger_bytes = Some(ledger_bytes(accepted.ledger()));
    accepted
}

fn ledger_bytes(ledger: &CommerceEscrowLedger) -> Vec<u8> {
    chio_core_types::canonical_json_bytes(ledger).test_expect("ledger canonicalizes")
}

fn json_value(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).test_expect("fixture artifact parses")
}

fn json_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).test_expect("fixture artifact serializes")
}

fn quote_sha256(context: &chio_commerce_order::CommerceOrderContext) -> String {
    let binding = serde_json::json!({
        "amount_minor": context.quote_amount_minor,
        "currency": context.quote_currency,
        "merchant_subject": context.merchant_subject,
        "order_id": context.order_id,
        "quote_id": context.quote_id,
    });
    sha256_hex(&chio_core_types::canonical_json_bytes(&binding).test_expect("quote canonicalizes"))
}

fn merchant_protocol_payload_bytes(
    merchant_subject: &str,
    protocol: &str,
    purpose: &str,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
        "protocol": protocol,
        "purpose": purpose,
        "order_id": "order-commerce-001",
        "amount_minor": 4200,
        "currency": "USD",
        "merchant_subject": merchant_subject,
    });
    chio_core_types::canonical_json_bytes(&payload).test_expect("payload canonicalizes")
}

/// The offline PSP order with its merchant replaced by the offer-issuing
/// merchant key, `did:chio:<key hex>`: the quote digest, protocol payloads,
/// mandate ledger, signed payment lifecycle and signed provider trust evidence
/// are rebuilt for that merchant and repinned in the order context.
fn merchant_keyed_bundle(merchant_key: &PublicKey) -> CommerceOrderVerificationBundle {
    let mut bundle = load_bundle("offline-psp-valid");
    let merchant_subject = format!("did:chio:{}", merchant_key.to_hex());
    let context = &mut bundle.order_context;
    context.merchant_subject = merchant_subject.clone();
    context.quote_sha256 = quote_sha256(context);
    let quote = context.quote_sha256.clone();

    for payload in &mut bundle.mandate_protocol_payloads {
        payload.payload_bytes =
            merchant_protocol_payload_bytes(&merchant_subject, &payload.protocol, &payload.purpose);
    }
    let payload_digest = |protocol: &str, purpose: &str| {
        let payload = bundle
            .mandate_protocol_payloads
            .iter()
            .find(|payload| payload.protocol == protocol && payload.purpose == purpose)
            .test_expect("mandate protocol payload exists");
        sha256_hex(&payload.payload_bytes)
    };
    let mut mandate = json_value(&bundle.mandate_ledger_bytes);
    mandate["merchant_subject"] = serde_json::json!(merchant_subject);
    mandate["quote_sha256"] = serde_json::json!(quote);
    for (field, protocol, purpose) in [
        ("ap2_checkout_mandate_hash", "ap2", "checkout_mandate"),
        ("ap2_payment_mandate_hash", "ap2", "payment_mandate"),
        (
            "acp_delegated_payment_token_hash",
            "acp-commerce",
            "delegated_payment_token",
        ),
        (
            "x402_payment_requirements_hash",
            "x402",
            "payment_requirements",
        ),
    ] {
        mandate[field] = serde_json::json!(payload_digest(protocol, purpose));
    }
    for projection in mandate["protocol_projections"]
        .as_array_mut()
        .test_expect("mandate protocol projections")
    {
        let protocol = projection["protocol"]
            .as_str()
            .test_expect("projection protocol");
        let purpose = projection["purpose"]
            .as_str()
            .test_expect("projection purpose");
        projection["digest"] = serde_json::json!(payload_digest(protocol, purpose));
    }
    bundle.mandate_ledger_bytes = json_bytes(&mandate);

    let mut payment = json_value(&bundle.payment_lifecycle_bytes);
    payment["merchant_subject"] = serde_json::json!(merchant_subject);
    payment["quote_sha256"] = serde_json::json!(quote);
    payment
        .as_object_mut()
        .test_expect("payment lifecycle object")
        .remove("signature");
    let signature = commerce_payment_signer()
        .sign_wrapped(
            chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
            &chio_core_types::CanonicalBytes::from_serializable(&payment)
                .test_expect("payment lifecycle canonicalizes"),
        )
        .test_expect("payment lifecycle signs");
    payment["signature"] = serde_json::json!(signature.to_hex());
    bundle.payment_lifecycle_bytes = json_bytes(&payment);

    let rebind_provider_trust = |bytes: &[u8]| {
        let mut value = json_value(bytes);
        value["provider_subject"] = serde_json::json!(merchant_subject);
        sign_provider_trust_value(&mut value);
        json_bytes(&value)
    };
    bundle.provider_passport_bytes = rebind_provider_trust(&bundle.provider_passport_bytes);
    bundle.reputation_snapshot_bytes = rebind_provider_trust(&bundle.reputation_snapshot_bytes);
    bundle.federation_trust_bundle_bytes =
        rebind_provider_trust(&bundle.federation_trust_bundle_bytes);

    let context = &mut bundle.order_context;
    context.mandate_ledger_sha256 = sha256_hex(&bundle.mandate_ledger_bytes);
    context.payment_lifecycle_sha256 = sha256_hex(&bundle.payment_lifecycle_bytes);
    context.provider_passport_sha256 = sha256_hex(&bundle.provider_passport_bytes);
    context.reputation_snapshot_sha256 = sha256_hex(&bundle.reputation_snapshot_bytes);
    context.federation_trust_bundle_sha256 = sha256_hex(&bundle.federation_trust_bundle_bytes);
    bundle
}

fn escrow_backed_bundle() -> (CommerceOrderVerificationBundle, AcceptedEscrow) {
    let mut bundle = merchant_keyed_bundle(&merchant().public_key());
    replay_through_settlement_dispatch(&mut bundle);
    let accepted = lock_escrow(&mut bundle);
    (bundle, accepted)
}

fn denial(bundle: &CommerceOrderVerificationBundle) -> CommerceOrderError {
    chio_commerce_order::verify_commerce_order(bundle).test_expect_err("replay is refused")
}

#[test]
fn order_passport_replay_verifies_the_pinned_locked_ledger() {
    let (bundle, accepted) = escrow_backed_bundle();
    assert_eq!(
        bundle.order_context.escrow_digest.as_deref(),
        Some(accepted.escrow_digest())
    );
    assert_eq!(accepted.ledger().status, CommerceEscrowStatus::Locked);

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("escrow-backed order replays");

    assert_eq!(report.verdict, "verified");
    assert_eq!(report.current_state, "settlement_dispatched");
    assert_eq!(
        report.artifact_digests.order_context_sha256,
        canonical_context_sha256(&bundle.order_context)
    );
}

#[test]
fn order_passport_replay_reproduces_the_verdict() {
    let (bundle_a, accepted_a) = escrow_backed_bundle();
    let (bundle_b, accepted_b) = escrow_backed_bundle();
    assert_eq!(accepted_a.escrow_digest(), accepted_b.escrow_digest());

    let first =
        chio_commerce_order::verify_commerce_order(&bundle_a).test_expect("first replay verifies");
    let again = chio_commerce_order::verify_commerce_order(&bundle_a)
        .test_expect("second replay of the same bundle verifies");
    let independent = chio_commerce_order::verify_commerce_order(&bundle_b)
        .test_expect("independently assembled bundle verifies");

    let bytes = |report: &chio_commerce_order::CommerceOrderPassportReport| {
        chio_core_types::canonical_json_bytes(report).test_expect("report canonicalizes")
    };
    assert_eq!(bytes(&first), bytes(&again));
    assert_eq!(bytes(&first), bytes(&independent));
}

#[test]
fn order_passport_replay_refuses_tampered_ledger_bytes() {
    let (mut bundle, accepted) = escrow_backed_bundle();
    let mut tampered = accepted.ledger().clone();
    tampered.amount_minor = 4100;
    tampered.legs[0].amount_minor = 4100;
    let tampered_digest = tampered.digest().test_expect("tampered ledger digest");
    bundle.escrow_ledger_bytes = Some(ledger_bytes(&tampered));

    assert_eq!(
        denial(&bundle),
        CommerceOrderError::DigestMismatch {
            field: "escrow ledger".to_string(),
            expected: accepted.escrow_digest().to_string(),
            actual: tampered_digest,
        }
    );
}

#[test]
fn order_passport_replay_refuses_a_dropped_escrow_digest() {
    let (mut bundle, _) = escrow_backed_bundle();
    bundle.order_context.escrow_digest = None;

    assert_eq!(
        denial(&bundle),
        CommerceOrderError::Escrow(CommerceEscrowError::LedgerUnpinned)
    );
}

#[test]
fn order_passport_replay_refuses_a_ledger_status_the_order_state_forbids() {
    let (mut bundle, accepted) = escrow_backed_bundle();
    let mut released = accepted.ledger().clone();
    released.status = CommerceEscrowStatus::Released;
    released.legs.push(CommerceEscrowLeg {
        kind: CommerceEscrowLegKind::Release,
        from_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
        to_account: released.beneficiary_account.clone(),
        amount_minor: released.amount_minor,
    });
    bundle.order_context.escrow_digest =
        Some(released.digest().test_expect("released ledger digest"));
    bundle.escrow_ledger_bytes = Some(ledger_bytes(&released));

    assert_eq!(
        denial(&bundle),
        CommerceOrderError::Escrow(CommerceEscrowError::LedgerStatusMismatch {
            state: "settlement_dispatched".to_string(),
            required: CommerceEscrowStatus::Locked,
        })
    );
}
