use super::*;

use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::capability::token::CapabilityTokenBody;
use chio_credit::{
    CapitalBookSourceKind, CapitalExecutionAuthorityStep, CapitalExecutionInstructionArtifact,
    CapitalExecutionIntendedState, CapitalExecutionObservation, CapitalExecutionRail,
    CapitalExecutionRailKind, CapitalExecutionRole, CapitalExecutionWindow,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use chio_test_support::prelude::*;

const HEX64: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_HEX64: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const ACCEPTED_AT: u64 = 500;
const RELEASED_AT: u64 = 800;

type Mutation<T> = (&'static str, fn(&mut T));

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn grant(cap: Option<MonetaryAmount>) -> ToolGrant {
    ToolGrant {
        server_id: "demo-server".to_string(),
        tool_name: "search".to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: Some(10),
        max_cost_per_invocation: None,
        max_total_cost: cap,
        dpop_required: None,
    }
}

fn sign_token(issuer: &Keypair, subject: &PublicKey, grants: Vec<ToolGrant>) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "offer-token-1".to_string(),
        issuer: issuer.public_key(),
        subject: subject.clone(),
        scope: ChioScope {
            grants,
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at: 100,
        expires_at: 10_000,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).test_expect("sign offer token")
}

fn order_context(current_state: &str) -> CommerceOrderContext {
    let value = serde_json::json!({
        "schema": crate::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
        "id": "ctx-1",
        "issued_at": "2026-06-25T00:00:00Z",
        "order_id": "order-commerce-001",
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
        "current_state": current_state,
    });
    let mut context: CommerceOrderContext =
        serde_json::from_value(value).test_expect("order context deserializes");
    pin_quote(&mut context);
    context
}

fn pin_quote(context: &mut CommerceOrderContext) {
    context.quote_sha256 = crate::canonical_quote_sha256(context).test_expect("quote digest");
}

fn dispatch() -> CommerceSettlementDispatch {
    CommerceSettlementDispatch {
        issued_at: "2026-06-25T00:00:00Z".to_string(),
        psp: "stripe".to_string(),
        payment_intent_id: "pi_123".to_string(),
        settlement_rail: "ach".to_string(),
        settlement_account_ref: "acct-1".to_string(),
        dispatch_receipt_ref: "dispatch-1".to_string(),
        status: "dispatched".to_string(),
    }
}

fn reservation_body(
    context: &CommerceOrderContext,
    token: &CapabilityToken,
    amount: MonetaryAmount,
) -> CommerceReservationReceipt {
    CommerceReservationReceipt {
        schema: COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID.to_string(),
        receipt_id: "reservation-1".to_string(),
        order_id: context.order_id.clone(),
        token_offer_id: token.id.clone(),
        token_offer_sha256: canonical_sha256(token).test_expect("offer digest"),
        reserved_amount: amount,
    }
}

fn sign<T: Serialize + Clone>(body: T, signer: &Keypair) -> SignedExportEnvelope<T> {
    SignedExportEnvelope::sign(body, signer).test_expect("sign envelope")
}

struct AcceptFixture {
    buyer: Keypair,
    issuer: Keypair,
    settlement_authority: Keypair,
    reservation_authority: Keypair,
    acceptor: PublicKey,
    token: CapabilityToken,
    context: CommerceOrderContext,
    reservation: SignedCommerceReservationReceipt,
    trusted_reservation: Vec<PublicKey>,
    settlement: CommerceSettlementDispatch,
    accepted_at: u64,
}

impl AcceptFixture {
    fn new() -> Self {
        let issuer = keypair(1);
        let buyer = keypair(2);
        let reservation_authority = keypair(9);
        let acceptor = buyer.public_key();
        let token = sign_token(&issuer, &acceptor, vec![grant(Some(usd(4200)))]);
        let context = order_context("fulfillment_attested");
        let reservation = sign(
            reservation_body(&context, &token, usd(4200)),
            &reservation_authority,
        );
        Self {
            trusted_reservation: vec![reservation_authority.public_key()],
            buyer,
            issuer,
            settlement_authority: keypair(7),
            reservation_authority,
            acceptor,
            token,
            context,
            reservation,
            settlement: dispatch(),
            accepted_at: ACCEPTED_AT,
        }
    }

    fn resign_reservation(&mut self, body: CommerceReservationReceipt) {
        self.reservation = sign(body, &self.reservation_authority);
    }

    fn reissue_token(&mut self, grants: Vec<ToolGrant>) {
        self.token = sign_token(&self.issuer, &self.acceptor, grants);
        self.resign_reservation(reservation_body(&self.context, &self.token, usd(4200)));
    }

    fn accept(&self) -> Result<CommerceEscrowAcceptance, CommerceOrderError> {
        accept(CommerceEscrowAcceptRequest {
            order_context: &self.context,
            token_offer: &self.token,
            acceptor: &self.acceptor,
            accepted_at: self.accepted_at,
            reservation: &self.reservation,
            trusted_reservation_authorities: &self.trusted_reservation,
            settlement: self.settlement.clone(),
            settlement_authority: &self.settlement_authority,
        })
    }

    fn denial(&self) -> CommerceOrderError {
        self.accept().test_expect_err("accept is denied")
    }
}

fn escrow(error: CommerceEscrowError) -> CommerceOrderError {
    CommerceOrderError::Escrow(error)
}

#[test]
fn accept_locks_quote_into_fixed_custody_and_pins_digests() {
    let fixture = AcceptFixture::new();
    let acceptance = fixture.accept().test_expect("accept succeeds");

    assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    assert_eq!(
        acceptance.ledger.legs,
        vec![CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Lock,
            from_account: "buyer:alice".to_string(),
            to_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor: 4200,
        }]
    );
    assert_eq!(acceptance.ledger.beneficiary_account, "merchant:coffee");
    assert_eq!(
        acceptance.escrow_digest,
        acceptance.ledger.digest().test_expect("ledger digest")
    );
    let context = &acceptance.updated_context;
    assert_eq!(context.current_state, "settlement_packet_assembled");
    assert_eq!(
        context.escrow_digest.as_deref(),
        Some(acceptance.escrow_digest.as_str())
    );
    assert_eq!(
        context.settlement_packet_sha256,
        canonical_sha256(&acceptance.settlement_packet.body).test_expect("packet digest")
    );
    assert_eq!(
        acceptance.settlement_packet.signer_key,
        fixture.settlement_authority.public_key()
    );
    assert!(acceptance
        .settlement_packet
        .verify_signature()
        .test_expect("packet signature verifies"));
    context
        .validate_shape()
        .test_expect("advanced context is well shaped");
    let ledger_bytes =
        chio_core_types::canonical_json_bytes(&acceptance.ledger).test_expect("ledger bytes");
    verify_escrow_ledger(context, Some(&ledger_bytes)).test_expect("verifier proves the digest");
}

#[test]
fn accept_denies_order_state_without_assembly_transition() {
    let mut fixture = AcceptFixture::new();
    fixture.context.current_state = "payment_verified".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::AcceptStateNotAllowed(
            "payment_verified".to_string()
        ))
    );
}

#[test]
fn accept_denies_unbound_quote_digest() {
    let mut fixture = AcceptFixture::new();
    let expected = fixture.context.quote_sha256.clone();
    fixture.context.quote_sha256 = HEX64.to_string();
    assert_eq!(
        fixture.denial(),
        CommerceOrderError::DigestMismatch {
            field: "order context quote".to_string(),
            expected: HEX64.to_string(),
            actual: expected,
        }
    );
}

#[test]
fn accept_denies_forged_offer_signature() {
    let mut fixture = AcceptFixture::new();
    fixture.token.id = "offer-token-forged".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::OfferSignatureInvalid)
    );
}

#[test]
fn accept_denies_offer_outside_validity_window() {
    let mut fixture = AcceptFixture::new();
    fixture.accepted_at = 20_000;
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::OfferOutsideValidityWindow)
    );
}

#[test]
fn accept_denies_self_issued_offer() {
    let mut fixture = AcceptFixture::new();
    fixture.token = sign_token(
        &fixture.buyer,
        &fixture.acceptor,
        vec![grant(Some(usd(4200)))],
    );
    fixture.resign_reservation(reservation_body(
        &fixture.context,
        &fixture.token,
        usd(4200),
    ));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::OfferSelfIssued)
    );
}

#[test]
fn accept_denies_acceptor_other_than_subject() {
    let mut fixture = AcceptFixture::new();
    fixture.acceptor = keypair(3).public_key();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::AcceptorNotSubject)
    );
}

#[test]
fn accept_denies_undefined_offer_liability() {
    let eur = MonetaryAmount {
        units: 1,
        currency: "EUR".to_string(),
    };
    let cases = [
        (vec![grant(None)], "uncapped grant"),
        (
            vec![grant(Some(usd(4199))), grant(Some(eur))],
            "mixed currencies",
        ),
        (Vec::new(), "no grants"),
        (vec![grant(Some(usd(0)))], "zero"),
        (
            vec![grant(Some(usd(u64::MAX))), grant(Some(usd(1)))],
            "overflow",
        ),
    ];
    for (grants, reason) in cases {
        let mut fixture = AcceptFixture::new();
        fixture.reissue_token(grants);
        assert_eq!(
            fixture.denial(),
            escrow(CommerceEscrowError::OfferLiabilityInvalid(reason)),
            "{reason}"
        );
    }
}

#[test]
fn accept_denies_liability_in_other_currency_than_quote() {
    let mut fixture = AcceptFixture::new();
    let eur = MonetaryAmount {
        units: 4200,
        currency: "EUR".to_string(),
    };
    fixture.reissue_token(vec![grant(Some(eur))]);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::LiabilityCurrencyMismatch)
    );
}

#[test]
fn accept_denies_liability_other_than_quote_amount() {
    let mut fixture = AcceptFixture::new();
    fixture.reissue_token(vec![grant(Some(usd(5000)))]);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::LiabilityQuoteMismatch)
    );
}

#[test]
fn accept_denies_reservation_without_pinned_authority() {
    let mut fixture = AcceptFixture::new();
    fixture.trusted_reservation.clear();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::NoTrustedReservationAuthority)
    );
}

#[test]
fn accept_denies_reservation_from_unpinned_signer() {
    let mut fixture = AcceptFixture::new();
    fixture.reservation = sign(fixture.reservation.body.clone(), &keypair(10));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationSignerUntrusted)
    );
}

#[test]
fn accept_denies_tampered_reservation() {
    let mut fixture = AcceptFixture::new();
    fixture.reservation.body.reserved_amount = usd(9_999);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationSignatureInvalid)
    );
}

#[test]
fn accept_denies_reservation_with_other_schema() {
    let mut fixture = AcceptFixture::new();
    let mut body = fixture.reservation.body.clone();
    body.schema = "chio.commerce.reservation-receipt.v0".to_string();
    fixture.resign_reservation(body);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationSchemaUnsupported(
            "chio.commerce.reservation-receipt.v0".to_string()
        ))
    );
}

#[test]
fn accept_denies_reservation_without_id() {
    let mut fixture = AcceptFixture::new();
    let mut body = fixture.reservation.body.clone();
    body.receipt_id = " ".to_string();
    fixture.resign_reservation(body);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationIdEmpty)
    );
}

#[test]
fn accept_denies_reservation_bound_to_other_order_or_offer() {
    let mutations: [Mutation<CommerceReservationReceipt>; 3] = [
        ("order_id", |body| body.order_id = "order-other".to_string()),
        ("token_offer_id", |body| {
            body.token_offer_id = "offer-token-other".to_string()
        }),
        ("token_offer_sha256", |body| {
            body.token_offer_sha256 = HEX64.to_string()
        }),
    ];
    for (field, mutate) in mutations {
        let mut fixture = AcceptFixture::new();
        let mut body = fixture.reservation.body.clone();
        mutate(&mut body);
        fixture.resign_reservation(body);
        assert_eq!(
            fixture.denial(),
            escrow(CommerceEscrowError::ReservationUnbound(field)),
            "{field}"
        );
    }
}

#[test]
fn accept_denies_reservation_in_other_currency() {
    let mut fixture = AcceptFixture::new();
    let eur = MonetaryAmount {
        units: 4200,
        currency: "EUR".to_string(),
    };
    fixture.resign_reservation(reservation_body(&fixture.context, &fixture.token, eur));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationCurrencyMismatch)
    );
}

#[test]
fn accept_denies_under_collateralized_reservation() {
    let mut fixture = AcceptFixture::new();
    fixture.resign_reservation(reservation_body(
        &fixture.context,
        &fixture.token,
        usd(4199),
    ));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReservationUnderCollateralized)
    );
}

#[test]
fn accept_denies_invalid_settlement_dispatch() {
    let mut fixture = AcceptFixture::new();
    fixture.settlement.psp = String::new();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::DispatchFieldEmpty("psp"))
    );

    let mut fixture = AcceptFixture::new();
    fixture.settlement.status = "settled".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::DispatchStatusNotDispatched(
            "settled".to_string()
        ))
    );

    let mut fixture = AcceptFixture::new();
    fixture.settlement.issued_at = "yesterday".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::DispatchIssuedAtInvalid)
    );
}

#[test]
fn accept_denies_buyer_paying_itself() {
    let mut fixture = AcceptFixture::new();
    fixture.context.merchant_subject = fixture.context.buyer_subject.clone();
    pin_quote(&mut fixture.context);
    fixture.resign_reservation(reservation_body(
        &fixture.context,
        &fixture.token,
        usd(4200),
    ));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::LedgerAccountsNotDistinct)
    );
}

fn locked_ledger() -> CommerceEscrowLedger {
    AcceptFixture::new()
        .accept()
        .test_expect("accept succeeds")
        .ledger
}

fn with_canonical_legs(mut ledger: CommerceEscrowLedger) -> CommerceEscrowLedger {
    ledger.legs = ledger.canonical_legs();
    ledger
}

#[test]
fn ledger_validate_denies_each_custody_invariant() {
    let mut ledger = locked_ledger();
    ledger.schema = "chio.commerce.escrow-ledger.v0".to_string();
    assert_eq!(
        ledger.validate(),
        Err(CommerceEscrowError::LedgerSchemaUnsupported(
            "chio.commerce.escrow-ledger.v0".to_string()
        ))
    );

    let mut ledger = locked_ledger();
    ledger.amount_minor = 0;
    assert_eq!(
        with_canonical_legs(ledger).validate(),
        Err(CommerceEscrowError::LedgerZeroAmount)
    );

    let mut ledger = locked_ledger();
    ledger.custody_account = "attacker:vault".to_string();
    assert_eq!(
        with_canonical_legs(ledger).validate(),
        Err(CommerceEscrowError::LedgerCustodyAccount(
            "attacker:vault".to_string()
        ))
    );

    let mut ledger = locked_ledger();
    ledger.depositor_account = COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string();
    assert_eq!(
        with_canonical_legs(ledger).validate(),
        Err(CommerceEscrowError::LedgerAccountsNotDistinct)
    );

    let mut ledger = locked_ledger();
    ledger.legs[0].to_account = "attacker:vault".to_string();
    assert_eq!(
        ledger.validate(),
        Err(CommerceEscrowError::LedgerLegsNotCanonical)
    );

    let mut ledger = locked_ledger();
    ledger.status = CommerceEscrowStatus::Released;
    assert_eq!(
        ledger.validate(),
        Err(CommerceEscrowError::LedgerLegsNotCanonical)
    );
}

#[test]
fn released_ledger_cannot_release_again() {
    let released = locked_ledger().released().test_expect("first release");
    assert_eq!(
        released.released(),
        Err(CommerceEscrowError::LedgerNotLocked)
    );
}

fn ledger_bytes(ledger: &CommerceEscrowLedger) -> Vec<u8> {
    chio_core_types::canonical_json_bytes(ledger).test_expect("ledger bytes")
}

fn pinned_context(ledger: &CommerceEscrowLedger, state: &str) -> CommerceOrderContext {
    let mut context = order_context(state);
    context.escrow_digest = Some(ledger.digest().test_expect("ledger digest"));
    context
}

#[test]
fn verifier_requires_ledger_exactly_when_digest_is_pinned() {
    let ledger = locked_ledger();
    let unpinned = order_context("settlement_packet_assembled");
    verify_escrow_ledger(&unpinned, None).test_expect("no digest needs no ledger");
    assert_eq!(
        verify_escrow_ledger(&unpinned, Some(&ledger_bytes(&ledger))),
        Err(escrow(CommerceEscrowError::LedgerUnpinned))
    );
    let pinned = pinned_context(&ledger, "settlement_packet_assembled");
    assert_eq!(
        verify_escrow_ledger(&pinned, None),
        Err(escrow(CommerceEscrowError::LedgerMissing))
    );
}

#[test]
fn verifier_denies_digest_that_does_not_recompute() {
    let ledger = locked_ledger();
    let mut context = order_context("settlement_packet_assembled");
    context.escrow_digest = Some(HEX64.to_string());
    assert_eq!(
        verify_escrow_ledger(&context, Some(&ledger_bytes(&ledger))),
        Err(CommerceOrderError::DigestMismatch {
            field: "escrow ledger".to_string(),
            expected: HEX64.to_string(),
            actual: ledger.digest().test_expect("ledger digest"),
        })
    );
}

#[test]
fn verifier_denies_ledger_outside_fixed_custody() {
    let mut ledger = locked_ledger();
    ledger.custody_account = "attacker:vault".to_string();
    let ledger = with_canonical_legs(ledger);
    let context = pinned_context(&ledger, "settlement_packet_assembled");
    assert_eq!(
        verify_escrow_ledger(&context, Some(&ledger_bytes(&ledger))),
        Err(escrow(CommerceEscrowError::LedgerCustodyAccount(
            "attacker:vault".to_string()
        )))
    );
}

#[test]
fn verifier_denies_ledger_bound_to_other_order_terms() {
    let mutations: [Mutation<CommerceEscrowLedger>; 5] = [
        ("order_id", |ledger| {
            ledger.order_id = "order-other".to_string()
        }),
        ("amount_minor", |ledger| ledger.amount_minor = 1),
        ("currency", |ledger| ledger.currency = "EUR".to_string()),
        ("depositor_account", |ledger| {
            ledger.depositor_account = "buyer:mallory".to_string()
        }),
        ("beneficiary_account", |ledger| {
            ledger.beneficiary_account = "merchant:mallory".to_string()
        }),
    ];
    for (field, mutate) in mutations {
        let mut ledger = locked_ledger();
        mutate(&mut ledger);
        let ledger = with_canonical_legs(ledger);
        let context = pinned_context(&ledger, "settlement_packet_assembled");
        assert_eq!(
            verify_escrow_ledger(&context, Some(&ledger_bytes(&ledger))),
            Err(escrow(CommerceEscrowError::LedgerOrderBinding(field))),
            "{field}"
        );
    }
}

#[test]
fn verifier_binds_ledger_status_to_order_state() {
    let ledger = locked_ledger();
    let context = pinned_context(&ledger, "settlement_reconciled");
    assert_eq!(
        verify_escrow_ledger(&context, Some(&ledger_bytes(&ledger))),
        Err(escrow(CommerceEscrowError::LedgerStatusMismatch {
            state: "settlement_reconciled".to_string(),
            required: CommerceEscrowStatus::Released,
        }))
    );

    let released = ledger.released().test_expect("release ledger");
    let context = pinned_context(&released, "settlement_dispatched");
    assert_eq!(
        verify_escrow_ledger(&context, Some(&ledger_bytes(&released))),
        Err(escrow(CommerceEscrowError::LedgerStatusMismatch {
            state: "settlement_dispatched".to_string(),
            required: CommerceEscrowStatus::Locked,
        }))
    );

    let context = pinned_context(&ledger, "fulfillment_attested");
    assert_eq!(
        verify_escrow_ledger(&context, Some(&ledger_bytes(&ledger))),
        Err(escrow(CommerceEscrowError::LedgerPinnedBeforeAccept(
            "fulfillment_attested".to_string()
        )))
    );

    let context = pinned_context(&released, "failed_closed");
    verify_escrow_ledger(&context, Some(&ledger_bytes(&released)))
        .test_expect("failed_closed accepts either status");
}

struct ReleaseFixture {
    settlement_authority: Keypair,
    execution_authority: Keypair,
    acceptance: CommerceEscrowAcceptance,
    advanced: CommerceOrderContext,
    execution: SignedCapitalExecutionInstruction,
    released_at: u64,
    trusted_settlement: Vec<PublicKey>,
    trusted_execution: Vec<PublicKey>,
}

fn execution_body() -> CapitalExecutionInstructionArtifact {
    let owner = keypair(12);
    let custodian = keypair(11);
    let authority_chain = vec![
        CapitalExecutionAuthorityStep::signed(
            CapitalExecutionRole::OperatorTreasury,
            &owner,
            100,
            10_000,
            None,
        )
        .test_expect("owner step"),
        CapitalExecutionAuthorityStep::signed(
            CapitalExecutionRole::Custodian,
            &custodian,
            100,
            10_000,
            None,
        )
        .test_expect("custodian step"),
    ];
    CapitalExecutionInstructionArtifact {
        schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        instruction_id: "instruction-1".to_string(),
        issued_at: 600,
        query: serde_json::from_value(serde_json::json!({ "agentSubject": "agent:alice" }))
            .test_expect("capital book query"),
        subject_key: "buyer:alice".to_string(),
        source_id: "escrow-order-commerce-001".to_string(),
        source_kind: CapitalBookSourceKind::ReserveBook,
        governed_receipt_id: None,
        completion_flow_row_id: None,
        action: CapitalExecutionInstructionAction::ReleaseReserve,
        owner_role: CapitalExecutionRole::OperatorTreasury,
        counterparty_role: CapitalExecutionRole::AgentCounterparty,
        counterparty_id: "merchant:coffee".to_string(),
        amount: Some(usd(4200)),
        authority_chain,
        execution_window: CapitalExecutionWindow {
            not_before: 600,
            not_after: 5_000,
        },
        rail: CapitalExecutionRail {
            kind: CapitalExecutionRailKind::Manual,
            rail_id: "rail-1".to_string(),
            custody_provider_id: custodian.public_key().to_hex(),
            source_account_ref: None,
            destination_account_ref: None,
            jurisdiction: None,
        },
        intended_state: CapitalExecutionIntendedState::PendingExecution,
        reconciled_state: CapitalExecutionReconciledState::Matched,
        related_instruction_id: None,
        observed_execution: Some(CapitalExecutionObservation {
            observed_at: 700,
            external_reference_id: "reconciliation-1".to_string(),
            amount: usd(4200),
        }),
        support_boundary: Default::default(),
        evidence_refs: Vec::new(),
        description: "release commerce escrow".to_string(),
    }
}

impl ReleaseFixture {
    fn new() -> Self {
        let accept = AcceptFixture::new();
        let acceptance = accept.accept().test_expect("accept succeeds");
        let mut advanced = acceptance.updated_context.clone();
        advanced.current_state = "settlement_observed".to_string();
        advanced.event_log_sha256 = OTHER_HEX64.to_string();
        let execution_authority = keypair(13);
        Self {
            execution: sign(execution_body(), &execution_authority),
            trusted_settlement: vec![accept.settlement_authority.public_key()],
            trusted_execution: vec![execution_authority.public_key()],
            settlement_authority: accept.settlement_authority,
            execution_authority,
            acceptance,
            advanced,
            released_at: RELEASED_AT,
        }
    }

    fn release(&self) -> Result<CommerceEscrowRelease, CommerceOrderError> {
        release(CommerceEscrowReleaseRequest {
            acceptance: &self.acceptance,
            advanced_context: &self.advanced,
            execution: &self.execution,
            released_at: self.released_at,
            trusted_settlement_authorities: &self.trusted_settlement,
            trusted_execution_authorities: &self.trusted_execution,
        })
    }

    fn denial(&self) -> CommerceOrderError {
        self.release().test_expect_err("release is denied")
    }

    fn reexecute(&mut self, mutate: impl FnOnce(&mut CapitalExecutionInstructionArtifact)) {
        let mut body = execution_body();
        mutate(&mut body);
        self.execution = sign(body, &self.execution_authority);
    }

    fn repin_ledger(&mut self, ledger: CommerceEscrowLedger) {
        let digest = ledger.digest().test_expect("ledger digest");
        self.acceptance.ledger = ledger;
        self.acceptance.escrow_digest = digest.clone();
        self.acceptance.updated_context.escrow_digest = Some(digest.clone());
        self.advanced.escrow_digest = Some(digest);
    }

    fn repin_packet(&mut self, packet: CommerceSettlementPacket) {
        let digest = canonical_sha256(&packet).test_expect("packet digest");
        self.acceptance.settlement_packet = sign(packet, &self.settlement_authority);
        self.acceptance.updated_context.settlement_packet_sha256 = digest.clone();
        self.advanced.settlement_packet_sha256 = digest;
    }
}

#[test]
fn release_drains_custody_to_merchant_against_authenticated_execution() {
    let fixture = ReleaseFixture::new();
    let released = fixture.release().test_expect("release succeeds");

    assert_eq!(released.ledger.status, CommerceEscrowStatus::Released);
    assert_eq!(
        released.ledger.legs[1],
        CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Release,
            from_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
            to_account: "merchant:coffee".to_string(),
            amount_minor: 4200,
        }
    );
    let context = &released.updated_context;
    assert_eq!(context.current_state, "settlement_reconciled");
    assert_eq!(context.event_log_sha256, OTHER_HEX64);
    assert_eq!(
        context.escrow_digest.as_deref(),
        Some(released.escrow_digest.as_str())
    );
    verify_escrow_ledger(context, Some(&ledger_bytes(&released.ledger)))
        .test_expect("verifier proves the released digest");
}

#[test]
fn release_denies_acceptance_digest_not_derived_from_ledger() {
    let mut fixture = ReleaseFixture::new();
    fixture.acceptance.escrow_digest = HEX64.to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::AcceptanceDigestMismatch)
    );
}

#[test]
fn release_denies_accepted_context_without_escrow_digest() {
    let mut fixture = ReleaseFixture::new();
    fixture.acceptance.updated_context.escrow_digest = None;
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::AcceptedContextUnbound)
    );
}

#[test]
fn release_denies_forged_custody_account() {
    let mut fixture = ReleaseFixture::new();
    let mut ledger = fixture.acceptance.ledger.clone();
    ledger.custody_account = "attacker:vault".to_string();
    fixture.repin_ledger(with_canonical_legs(ledger));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::LedgerCustodyAccount(
            "attacker:vault".to_string()
        ))
    );
}

#[test]
fn release_denies_ledger_paying_other_beneficiary() {
    let mut fixture = ReleaseFixture::new();
    let mut ledger = fixture.acceptance.ledger.clone();
    ledger.beneficiary_account = "merchant:mallory".to_string();
    fixture.repin_ledger(with_canonical_legs(ledger));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::LedgerOrderBinding(
            "beneficiary_account"
        ))
    );
}

#[test]
fn release_denies_settlement_packet_without_pinned_authority() {
    let mut fixture = ReleaseFixture::new();
    fixture.trusted_settlement.clear();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::NoTrustedSettlementAuthority)
    );
}

#[test]
fn release_denies_settlement_packet_from_unpinned_signer() {
    let mut fixture = ReleaseFixture::new();
    let packet = fixture.acceptance.settlement_packet.body.clone();
    fixture.acceptance.settlement_packet = sign(packet, &keypair(14));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::SettlementSignerUntrusted)
    );
}

#[test]
fn release_denies_tampered_settlement_packet() {
    let mut fixture = ReleaseFixture::new();
    fixture.acceptance.settlement_packet.body.reconciliation_ref = "reconciliation-2".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::SettlementSignatureInvalid)
    );
}

#[test]
fn release_denies_settlement_packet_not_pinned_by_accepted_context() {
    let mut fixture = ReleaseFixture::new();
    let mut packet = fixture.acceptance.settlement_packet.body.clone();
    packet.reconciliation_ref = "reconciliation-2".to_string();
    fixture.acceptance.settlement_packet = sign(packet, &fixture.settlement_authority);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::SettlementPacketUnbound(
            "settlement_packet_sha256"
        ))
    );

    let mut fixture = ReleaseFixture::new();
    let mut packet = fixture.acceptance.settlement_packet.body.clone();
    packet.order_id = "order-other".to_string();
    fixture.repin_packet(packet);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::SettlementPacketUnbound("order_id"))
    );
}

#[test]
fn release_denies_settlement_packet_for_other_economics() {
    let mutations: [Mutation<CommerceSettlementPacket>; 4] = [
        ("merchant_subject", |packet| {
            packet.merchant_subject = "merchant:mallory".to_string()
        }),
        ("amount_minor", |packet| packet.amount_minor = 1),
        ("currency", |packet| packet.currency = "EUR".to_string()),
        ("quote_sha256", |packet| {
            packet.quote_sha256 = OTHER_HEX64.to_string()
        }),
    ];
    for (field, mutate) in mutations {
        let mut fixture = ReleaseFixture::new();
        let mut packet = fixture.acceptance.settlement_packet.body.clone();
        mutate(&mut packet);
        fixture.repin_packet(packet);
        assert_eq!(
            fixture.denial(),
            escrow(CommerceEscrowError::SettlementPacketUnbound(field)),
            "{field}"
        );
    }
}

#[test]
fn release_denies_contexts_that_move_the_signed_packet_references() {
    let mutations: [Mutation<CommerceOrderContext>; 2] = [
        ("settlement_packet_ref", |context| {
            context.settlement_packet_ref = "settlement-packet-other".to_string()
        }),
        ("reconciliation_ref", |context| {
            context.reconciliation_ref = "reconciliation-other".to_string()
        }),
    ];
    for (field, mutate) in mutations {
        let mut fixture = ReleaseFixture::new();
        mutate(&mut fixture.acceptance.updated_context);
        mutate(&mut fixture.advanced);
        assert_eq!(
            fixture.denial(),
            escrow(CommerceEscrowError::SettlementPacketUnbound(field)),
            "{field}"
        );
    }
}

#[test]
fn release_denies_contexts_whose_quote_digest_does_not_recompute() {
    let mut fixture = ReleaseFixture::new();
    fixture.acceptance.updated_context.quote_id = "quote-other".to_string();
    fixture.advanced.quote_id = "quote-other".to_string();
    let expected = fixture.acceptance.updated_context.quote_sha256.clone();
    let actual = crate::canonical_quote_sha256(&fixture.acceptance.updated_context)
        .test_expect("quote digest");
    assert_eq!(
        fixture.denial(),
        CommerceOrderError::DigestMismatch {
            field: "order context quote".to_string(),
            expected,
            actual,
        }
    );
}

#[test]
fn release_denies_advanced_context_that_rewrites_immutable_fields() {
    let mutations: [Mutation<CommerceOrderContext>; 12] = [
        ("order_id", |context| {
            context.order_id = "order-other".to_string()
        }),
        ("buyer_subject", |context| {
            context.buyer_subject = "buyer:mallory".to_string()
        }),
        ("agent_subject", |context| {
            context.agent_subject = "agent:mallory".to_string()
        }),
        ("merchant_subject", |context| {
            context.merchant_subject = "merchant:mallory".to_string()
        }),
        ("quote_id", |context| {
            context.quote_id = "quote-2".to_string()
        }),
        ("quote_amount_minor", |context| {
            context.quote_amount_minor = 1
        }),
        ("quote_currency", |context| {
            context.quote_currency = "EUR".to_string()
        }),
        ("quote_sha256", |context| {
            context.quote_sha256 = OTHER_HEX64.to_string()
        }),
        ("settlement_packet_ref", |context| {
            context.settlement_packet_ref = "settlement-packet-2".to_string()
        }),
        ("settlement_packet_sha256", |context| {
            context.settlement_packet_sha256 = OTHER_HEX64.to_string()
        }),
        ("reconciliation_ref", |context| {
            context.reconciliation_ref = "reconciliation-2".to_string()
        }),
        ("escrow_digest", |context| {
            context.escrow_digest = Some(OTHER_HEX64.to_string())
        }),
    ];
    for (field, mutate) in mutations {
        let mut fixture = ReleaseFixture::new();
        mutate(&mut fixture.advanced);
        assert_eq!(
            fixture.denial(),
            escrow(CommerceEscrowError::ReleaseContextMismatch(field)),
            "{field}"
        );
    }
}

#[test]
fn release_denies_advanced_context_before_reconciliation() {
    let mut fixture = ReleaseFixture::new();
    fixture.advanced.current_state = "settlement_packet_assembled".to_string();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ReleaseStateNotAllowed(
            "settlement_packet_assembled".to_string()
        ))
    );
}

#[test]
fn release_denies_execution_without_pinned_authority() {
    let mut fixture = ReleaseFixture::new();
    fixture.trusted_execution.clear();
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::NoTrustedExecutionAuthority)
    );
}

#[test]
fn release_denies_execution_from_unpinned_signer() {
    let mut fixture = ReleaseFixture::new();
    fixture.execution = sign(execution_body(), &keypair(15));
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionSignerUntrusted)
    );
}

#[test]
fn release_denies_fabricated_matched_observation() {
    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| {
        body.reconciled_state = CapitalExecutionReconciledState::NotObserved;
        body.observed_execution = None;
    });
    let observation = CapitalExecutionObservation {
        observed_at: 700,
        external_reference_id: "reconciliation-1".to_string(),
        amount: usd(4200),
    };
    fixture.execution.body.reconciled_state = CapitalExecutionReconciledState::Matched;
    fixture.execution.body.observed_execution = Some(observation);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionSignatureInvalid)
    );
}

#[test]
fn release_denies_invalid_execution_instruction() {
    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| {
        if let Some(observed) = body.observed_execution.as_mut() {
            observed.observed_at = 9_000;
        }
    });
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionInvalid(
            "capital instruction observedExecution timestamp falls outside the execution window"
                .to_string()
        ))
    );
}

#[test]
fn release_denies_execution_other_than_reserve_release() {
    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| body.action = CapitalExecutionInstructionAction::LockReserve);
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionActionNotRelease)
    );
}

#[test]
fn release_denies_unobserved_execution() {
    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| {
        body.reconciled_state = CapitalExecutionReconciledState::NotObserved;
        body.observed_execution = None;
    });
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionNotMatched)
    );
}

#[test]
fn release_denies_execution_bound_to_other_payment() {
    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| {
        if let Some(observed) = body.observed_execution.as_mut() {
            observed.external_reference_id = "reconciliation-2".to_string();
        }
    });
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionUnbound(
            "external_reference_id"
        ))
    );

    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| {
        body.amount = Some(usd(4100));
        if let Some(observed) = body.observed_execution.as_mut() {
            observed.amount = usd(4100);
        }
    });
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionUnbound("amount"))
    );

    let mut fixture = ReleaseFixture::new();
    fixture.reexecute(|body| body.counterparty_id = "merchant:mallory".to_string());
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionUnbound("counterparty_id"))
    );
}

#[test]
fn release_denies_execution_after_release_time() {
    let mut fixture = ReleaseFixture::new();
    fixture.released_at = 550;
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionAfterRelease("issued_at"))
    );

    let mut fixture = ReleaseFixture::new();
    fixture.released_at = 650;
    assert_eq!(
        fixture.denial(),
        escrow(CommerceEscrowError::ExecutionAfterRelease("observed_at"))
    );
}
