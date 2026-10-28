//! Custodial escrow for commerce orders.
//!
//! [`accept`] locks the signed quote amount from the order buyer into the fixed
//! custody account, signs the settlement packet, and pins the escrow ledger
//! digest into the order context. [`release`] drains custody to the order
//! merchant only against a capital execution instruction that a pinned
//! execution authority signed and reconciled as matched for this order.
//!
//! Custody invariants, enforced by [`CommerceEscrowLedger::validate`] on every
//! ledger that `accept`, `release`, or the verifier touches:
//!
//! - the custody account is [`COMMERCE_ESCROW_CUSTODY_ACCOUNT`];
//! - depositor, beneficiary, and custody accounts are pairwise distinct;
//! - the legs are exactly the canonical lock leg (depositor to custody) and,
//!   once released, the canonical release leg (custody to beneficiary), each
//!   for the full ledger amount.
//!
//! Together these make value conservation an identity: a locked ledger holds
//! the full amount in custody and a released ledger credits it to the
//! beneficiary and leaves custody empty.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_credit::{
    CapitalExecutionInstructionAction, CapitalExecutionReconciledState,
    SignedCapitalExecutionInstruction,
};
use serde::{Deserialize, Serialize};

use crate::error::{CommerceEscrowError, CommerceOrderError};
use crate::ids::{
    COMMERCE_ESCROW_LEDGER_SCHEMA_ID, COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID,
    COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID,
};
use crate::types::{CommerceOrderContext, CommerceSettlementPacket};

/// The single account every escrow leg flows through.
pub const COMMERCE_ESCROW_CUSTODY_ACCOUNT: &str = "chio:commerce:escrow:custody";

const ASSEMBLE_SETTLEMENT_TRANSITION: &str = "assemble_settlement_packet";
const RECONCILE_SETTLEMENT_TRANSITION: &str = "reconcile_settlement";
const SETTLEMENT_PACKET_ASSEMBLED_STATE: &str = "settlement_packet_assembled";
const SETTLEMENT_RECONCILED_STATE: &str = "settlement_reconciled";
const DISPATCHED_SETTLEMENT_STATUS: &str = "dispatched";

/// Direction of one escrow ledger leg.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommerceEscrowLegKind {
    /// Debits the depositor and credits custody.
    Lock,
    /// Debits custody and credits the beneficiary.
    Release,
}

/// Lifecycle status of an escrow ledger.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommerceEscrowStatus {
    /// Custody holds the full amount; only the lock leg exists.
    Locked,
    /// Custody is drained to the beneficiary; both legs exist.
    Released,
}

/// One atomic transfer of `amount_minor` from `from_account` to `to_account`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceEscrowLeg {
    pub kind: CommerceEscrowLegKind,
    pub from_account: String,
    pub to_account: String,
    pub amount_minor: u64,
}

/// The custodial ledger backing one commerce order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceEscrowLedger {
    pub schema: String,
    pub order_id: String,
    pub currency: String,
    /// Equals the order `buyer_subject`.
    pub depositor_account: String,
    /// Equals the order `merchant_subject`.
    pub beneficiary_account: String,
    /// Equals [`COMMERCE_ESCROW_CUSTODY_ACCOUNT`].
    pub custody_account: String,
    /// Equals the order `quote_amount_minor`.
    pub amount_minor: u64,
    pub legs: Vec<CommerceEscrowLeg>,
    pub status: CommerceEscrowStatus,
}

impl CommerceEscrowLedger {
    fn lock(
        order_id: String,
        currency: String,
        depositor_account: String,
        beneficiary_account: String,
        amount_minor: u64,
    ) -> Result<Self, CommerceEscrowError> {
        let mut ledger = Self {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id,
            currency,
            depositor_account,
            beneficiary_account,
            custody_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor,
            legs: Vec::new(),
            status: CommerceEscrowStatus::Locked,
        };
        ledger.legs = ledger.canonical_legs();
        ledger.validate()?;
        Ok(ledger)
    }

    fn released(&self) -> Result<Self, CommerceEscrowError> {
        if self.status != CommerceEscrowStatus::Locked {
            return Err(CommerceEscrowError::LedgerNotLocked);
        }
        let mut ledger = self.clone();
        ledger.status = CommerceEscrowStatus::Released;
        ledger.legs = ledger.canonical_legs();
        ledger.validate()?;
        Ok(ledger)
    }

    fn canonical_legs(&self) -> Vec<CommerceEscrowLeg> {
        let lock = CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Lock,
            from_account: self.depositor_account.clone(),
            to_account: self.custody_account.clone(),
            amount_minor: self.amount_minor,
        };
        match self.status {
            CommerceEscrowStatus::Locked => vec![lock],
            CommerceEscrowStatus::Released => vec![
                lock,
                CommerceEscrowLeg {
                    kind: CommerceEscrowLegKind::Release,
                    from_account: self.custody_account.clone(),
                    to_account: self.beneficiary_account.clone(),
                    amount_minor: self.amount_minor,
                },
            ],
        }
    }

    /// Checks the custody invariants listed in the module documentation.
    pub fn validate(&self) -> Result<(), CommerceEscrowError> {
        if self.schema != COMMERCE_ESCROW_LEDGER_SCHEMA_ID {
            return Err(CommerceEscrowError::LedgerSchemaUnsupported(
                self.schema.clone(),
            ));
        }
        if self.amount_minor == 0 {
            return Err(CommerceEscrowError::LedgerZeroAmount);
        }
        if self.custody_account != COMMERCE_ESCROW_CUSTODY_ACCOUNT {
            return Err(CommerceEscrowError::LedgerCustodyAccount(
                self.custody_account.clone(),
            ));
        }
        if self.depositor_account == self.beneficiary_account
            || self.depositor_account == self.custody_account
            || self.beneficiary_account == self.custody_account
        {
            return Err(CommerceEscrowError::LedgerAccountsNotDistinct);
        }
        if self.legs != self.canonical_legs() {
            return Err(CommerceEscrowError::LedgerLegsNotCanonical);
        }
        Ok(())
    }

    /// sha256 hex over the canonical JSON of the ledger. This is the value
    /// pinned in `CommerceOrderContext::escrow_digest`.
    pub fn digest(&self) -> Result<String, CommerceEscrowError> {
        canonical_sha256(self)
    }

    fn bind_to_order(&self, context: &CommerceOrderContext) -> Result<(), CommerceEscrowError> {
        let bindings = [
            ("order_id", self.order_id == context.order_id),
            (
                "amount_minor",
                self.amount_minor == context.quote_amount_minor,
            ),
            ("currency", self.currency == context.quote_currency),
            (
                "depositor_account",
                self.depositor_account == context.buyer_subject,
            ),
            (
                "beneficiary_account",
                self.beneficiary_account == context.merchant_subject,
            ),
        ];
        match bindings.iter().find(|(_, bound)| !bound) {
            Some((field, _)) => Err(CommerceEscrowError::LedgerOrderBinding(field)),
            None => Ok(()),
        }
    }
}

/// Off-context settlement dispatch fields used to build the settlement packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceSettlementDispatch {
    /// RFC3339 UTC timestamp.
    pub issued_at: String,
    pub psp: String,
    pub payment_intent_id: String,
    pub settlement_rail: String,
    pub settlement_account_ref: String,
    pub dispatch_receipt_ref: String,
    /// Must be `dispatched`: accept locks custody but settles nothing.
    pub status: String,
}

impl CommerceSettlementDispatch {
    fn validate(&self) -> Result<(), CommerceEscrowError> {
        for (field, value) in [
            ("issued_at", &self.issued_at),
            ("psp", &self.psp),
            ("payment_intent_id", &self.payment_intent_id),
            ("settlement_rail", &self.settlement_rail),
            ("settlement_account_ref", &self.settlement_account_ref),
            ("dispatch_receipt_ref", &self.dispatch_receipt_ref),
            ("status", &self.status),
        ] {
            if value.trim().is_empty() {
                return Err(CommerceEscrowError::DispatchFieldEmpty(field));
            }
        }
        if self.status != DISPATCHED_SETTLEMENT_STATUS {
            return Err(CommerceEscrowError::DispatchStatusNotDispatched(
                self.status.clone(),
            ));
        }
        crate::validation::parse_rfc3339_utc(&self.issued_at, "settlement dispatch issued_at")
            .map_err(|_| CommerceEscrowError::DispatchIssuedAtInvalid)?;
        Ok(())
    }
}

/// Funds-reservation witness a settlement reservation authority signs for one
/// order and one exact offer token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceReservationReceipt {
    pub schema: String,
    pub receipt_id: String,
    /// Equals the order `order_id`.
    pub order_id: String,
    /// Equals the offer token `id`.
    pub token_offer_id: String,
    /// sha256 hex over the canonical JSON of the offer token.
    pub token_offer_sha256: String,
    pub reserved_amount: MonetaryAmount,
}

pub type SignedCommerceReservationReceipt = SignedExportEnvelope<CommerceReservationReceipt>;

/// Inputs to [`accept`].
pub struct CommerceEscrowAcceptRequest<'a> {
    /// Its `current_state` must allow the settlement-packet-assembly transition.
    pub order_context: &'a CommerceOrderContext,
    /// Its grants' `max_total_cost` sum is the custodial liability.
    pub token_offer: &'a CapabilityToken,
    /// Must equal the offer token subject.
    pub acceptor: &'a PublicKey,
    /// Unix seconds; the offer token must be valid at this time.
    pub accepted_at: u64,
    pub reservation: &'a SignedCommerceReservationReceipt,
    /// Pinned from verified launch configuration, never from the reservation.
    pub trusted_reservation_authorities: &'a [PublicKey],
    pub settlement: CommerceSettlementDispatch,
    pub settlement_authority: &'a Keypair,
}

/// Output of [`accept`], the only way to obtain one. [`release`] relies on
/// its contents being exactly what `accept` produced, so callers can read but
/// never rewrite or assemble an accepted escrow.
///
/// ```compile_fail
/// fn clear_requirements(accepted: &mut chio_commerce_order::AcceptedEscrow) {
///     accepted.updated_context.coverage_requirement = None;
///     accepted.updated_context.trust_market_requirement = None;
/// }
/// ```
///
/// ```compile_fail
/// use chio_commerce_order::{
///     AcceptedEscrow, CommerceEscrowLedger, CommerceOrderContext, CommerceSettlementPacket,
/// };
/// use chio_core_types::receipt::lineage::SignedExportEnvelope;
/// fn forge(
///     ledger: CommerceEscrowLedger,
///     settlement_packet: SignedExportEnvelope<CommerceSettlementPacket>,
///     updated_context: CommerceOrderContext,
/// ) -> AcceptedEscrow {
///     AcceptedEscrow {
///         ledger,
///         settlement_packet,
///         escrow_digest: String::new(),
///         updated_context,
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AcceptedEscrow {
    /// Locked ledger.
    pub ledger: CommerceEscrowLedger,
    /// `updated_context.settlement_packet_sha256` is the sha256 of the
    /// canonical JSON of this packet body.
    pub settlement_packet: SignedExportEnvelope<CommerceSettlementPacket>,
    /// Digest of `ledger`, also pinned in `updated_context.escrow_digest`.
    pub escrow_digest: String,
    /// The order context advanced to `settlement_packet_assembled`.
    pub updated_context: CommerceOrderContext,
}

/// Inputs to [`release`].
pub struct CommerceEscrowReleaseRequest<'a> {
    /// Consumed: one acceptance backs one release.
    pub acceptance: AcceptedEscrow,
    /// The same order advanced to a settlement-reconciliation predecessor
    /// state. Its order, party, quote, settlement, and escrow fields must equal
    /// the accepted context.
    pub advanced_context: &'a CommerceOrderContext,
    pub execution: &'a SignedCapitalExecutionInstruction,
    /// Unix seconds; the execution must be issued and observed no later.
    pub released_at: u64,
    /// Pinned from verified launch configuration, never from the acceptance.
    pub trusted_settlement_authorities: &'a [PublicKey],
    /// Pinned from verified launch configuration, never from the execution.
    pub trusted_execution_authorities: &'a [PublicKey],
}

/// Output of [`release`].
#[derive(Debug, Clone)]
pub struct CommerceEscrowRelease {
    /// Released ledger.
    pub ledger: CommerceEscrowLedger,
    /// Digest of `ledger`, also pinned in `updated_context.escrow_digest`.
    pub escrow_digest: String,
    /// The advanced context moved to `settlement_reconciled`.
    pub updated_context: CommerceOrderContext,
}

/// Locks custody for an authenticated offer against a signed reservation.
///
/// Denies unless the quote digest recomputes, the order state allows
/// settlement-packet assembly, the offer token is authentic, valid at
/// `accepted_at`, issued by a counterparty other than its subject, and accepted
/// by its subject, the reservation is signed by a pinned authority for this
/// order and offer, and the offer liability equals the signed quote and is
/// fully reserved in the quote currency.
pub fn accept(
    request: CommerceEscrowAcceptRequest<'_>,
) -> Result<AcceptedEscrow, CommerceOrderError> {
    let context = request.order_context;
    context.validate_shape()?;
    crate::verify_quote_digest(context)?;
    if !crate::replay::is_allowed_transition(
        &context.current_state,
        SETTLEMENT_PACKET_ASSEMBLED_STATE,
        ASSEMBLE_SETTLEMENT_TRANSITION,
    ) {
        return Err(
            CommerceEscrowError::AcceptStateNotAllowed(context.current_state.clone()).into(),
        );
    }
    authenticate_offer(request.token_offer, request.acceptor, request.accepted_at)?;
    let liability = token_offer_liability(request.token_offer)?;
    let reserved = verify_reservation(
        request.reservation,
        request.trusted_reservation_authorities,
        context,
        request.token_offer,
    )?;
    if liability.currency != context.quote_currency {
        return Err(CommerceEscrowError::LiabilityCurrencyMismatch.into());
    }
    if liability.units != context.quote_amount_minor {
        return Err(CommerceEscrowError::LiabilityQuoteMismatch.into());
    }
    if reserved.currency != liability.currency {
        return Err(CommerceEscrowError::ReservationCurrencyMismatch.into());
    }
    if reserved.units < liability.units {
        return Err(CommerceEscrowError::ReservationUnderCollateralized.into());
    }

    let ledger = CommerceEscrowLedger::lock(
        context.order_id.clone(),
        liability.currency,
        context.buyer_subject.clone(),
        context.merchant_subject.clone(),
        liability.units,
    )?;
    request.settlement.validate()?;
    let packet = build_settlement_packet(context, &request.settlement);
    let settlement_packet_sha256 = canonical_sha256(&packet)?;
    let settlement_packet = SignedExportEnvelope::sign(packet, request.settlement_authority)
        .map_err(|error| CommerceEscrowError::SettlementSigningFailed(error.to_string()))?;
    let escrow_digest = ledger.digest()?;

    let mut updated_context = context.clone();
    updated_context.escrow_digest = Some(escrow_digest.clone());
    updated_context.settlement_packet_sha256 = settlement_packet_sha256;
    updated_context.current_state = SETTLEMENT_PACKET_ASSEMBLED_STATE.to_string();

    Ok(AcceptedEscrow {
        ledger,
        settlement_packet,
        escrow_digest,
        updated_context,
    })
}

/// Drains custody to the order merchant.
///
/// Every binding of the public `acceptance` is re-derived: the accepted quote
/// digest recomputes; the ledger passes [`CommerceEscrowLedger::validate`],
/// recomputes to the pinned escrow digest, and is bound to the accepted order;
/// the settlement packet is signed by a pinned settlement authority, is the
/// packet the accepted context pins, and carries the accepted packet and
/// reconciliation references and the locked merchant, amount, currency, and
/// quote digest. The advanced context must carry every accepted context field
/// except the ones settlement progress advances and be in a state that allows
/// settlement reconciliation. The execution instruction must be signed by a
/// pinned execution authority, validate, be a matched `release_reserve` of the
/// depositor's reserve paying the order merchant the locked amount against the
/// packet's reconciliation reference, and be issued and observed no later than
/// `released_at`.
pub fn release(
    request: CommerceEscrowReleaseRequest<'_>,
) -> Result<CommerceEscrowRelease, CommerceOrderError> {
    let acceptance = &request.acceptance;
    let accepted = &acceptance.updated_context;
    acceptance.ledger.validate()?;
    if acceptance.ledger.digest()? != acceptance.escrow_digest {
        return Err(CommerceEscrowError::AcceptanceDigestMismatch.into());
    }
    accepted.validate_shape()?;
    crate::verify_quote_digest(accepted)?;
    if accepted.escrow_digest.as_deref() != Some(acceptance.escrow_digest.as_str()) {
        return Err(CommerceEscrowError::AcceptedContextUnbound.into());
    }
    acceptance.ledger.bind_to_order(accepted)?;

    let packet = &acceptance.settlement_packet;
    require_pinned_signature(
        packet,
        request.trusted_settlement_authorities,
        CommerceEscrowError::NoTrustedSettlementAuthority,
        CommerceEscrowError::SettlementSignerUntrusted,
        CommerceEscrowError::SettlementSignatureInvalid,
    )?;
    if canonical_sha256(&packet.body)? != accepted.settlement_packet_sha256 {
        return Err(
            CommerceEscrowError::SettlementPacketUnbound("settlement_packet_sha256").into(),
        );
    }
    bind_settlement_packet(&packet.body, accepted, &acceptance.ledger)?;

    let advanced = request.advanced_context;
    advanced.validate_shape()?;
    bind_release_context(accepted, advanced)?;
    if !crate::replay::is_allowed_transition(
        &advanced.current_state,
        SETTLEMENT_RECONCILED_STATE,
        RECONCILE_SETTLEMENT_TRANSITION,
    ) {
        return Err(
            CommerceEscrowError::ReleaseStateNotAllowed(advanced.current_state.clone()).into(),
        );
    }

    verify_execution(
        request.execution,
        request.trusted_execution_authorities,
        &acceptance.ledger,
        &packet.body.reconciliation_ref,
        request.released_at,
    )?;

    let ledger = acceptance.ledger.released()?;
    let escrow_digest = ledger.digest()?;
    let mut updated_context = advanced.clone();
    updated_context.escrow_digest = Some(escrow_digest.clone());
    updated_context.current_state = SETTLEMENT_RECONCILED_STATE.to_string();

    Ok(CommerceEscrowRelease {
        ledger,
        escrow_digest,
        updated_context,
    })
}

/// Proves `context.escrow_digest` against the bundled escrow ledger bytes.
///
/// A pinned digest requires ledger bytes and unpinned ledger bytes are
/// rejected. The ledger must pass [`CommerceEscrowLedger::validate`], recompute
/// to the pinned digest, bind to the order, and carry the status the order
/// state requires.
pub(crate) fn verify_escrow_ledger(
    context: &CommerceOrderContext,
    ledger_bytes: Option<&[u8]>,
) -> Result<(), CommerceOrderError> {
    let (expected, bytes) = match (context.escrow_digest.as_deref(), ledger_bytes) {
        (None, None) => return Ok(()),
        (None, Some(_)) => return Err(CommerceEscrowError::LedgerUnpinned.into()),
        (Some(_), None) => return Err(CommerceEscrowError::LedgerMissing.into()),
        (Some(expected), Some(bytes)) => (expected, bytes),
    };
    let ledger: CommerceEscrowLedger = crate::input::decode(bytes)?;
    ledger.validate()?;
    let actual = ledger.digest()?;
    if actual != expected {
        return Err(CommerceOrderError::DigestMismatch {
            field: "escrow ledger".to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    ledger.bind_to_order(context)?;
    let required = required_escrow_status(&context.current_state)?;
    if let Some(required) = required {
        if ledger.status != required {
            return Err(CommerceEscrowError::LedgerStatusMismatch {
                state: context.current_state.clone(),
                required,
            }
            .into());
        }
    }
    Ok(())
}

/// The ledger status an order state requires once an escrow digest is pinned.
/// `failed_closed` is reachable before and after release, so it constrains
/// nothing; states before settlement-packet assembly cannot carry a digest.
fn required_escrow_status(
    state: &str,
) -> Result<Option<CommerceEscrowStatus>, CommerceEscrowError> {
    match state {
        "settlement_packet_assembled" | "settlement_dispatched" | "settlement_observed" => {
            Ok(Some(CommerceEscrowStatus::Locked))
        }
        "settlement_reconciled" | "completed" | "disputed" | "refunded" => {
            Ok(Some(CommerceEscrowStatus::Released))
        }
        "failed_closed" => Ok(None),
        other => Err(CommerceEscrowError::LedgerPinnedBeforeAccept(
            other.to_string(),
        )),
    }
}

fn authenticate_offer(
    token: &CapabilityToken,
    acceptor: &PublicKey,
    accepted_at: u64,
) -> Result<(), CommerceEscrowError> {
    if !matches!(token.verify_signature(), Ok(true)) {
        return Err(CommerceEscrowError::OfferSignatureInvalid);
    }
    token
        .validate_time(accepted_at)
        .map_err(|_| CommerceEscrowError::OfferOutsideValidityWindow)?;
    if token.issuer == token.subject {
        return Err(CommerceEscrowError::OfferSelfIssued);
    }
    if *acceptor != token.subject {
        return Err(CommerceEscrowError::AcceptorNotSubject);
    }
    Ok(())
}

/// Sum of every grant's `max_total_cost`. Every grant must carry a cap in one
/// shared currency and the sum must be nonzero and fit in `u64`.
fn token_offer_liability(token: &CapabilityToken) -> Result<MonetaryAmount, CommerceEscrowError> {
    let mut liability: Option<MonetaryAmount> = None;
    for grant in &token.scope.grants {
        let cap = grant
            .max_total_cost
            .as_ref()
            .ok_or(CommerceEscrowError::OfferLiabilityInvalid("uncapped grant"))?;
        liability = Some(match liability {
            None => cap.clone(),
            Some(total) if total.currency != cap.currency => {
                return Err(CommerceEscrowError::OfferLiabilityInvalid(
                    "mixed currencies",
                ));
            }
            Some(total) => MonetaryAmount {
                units: total
                    .units
                    .checked_add(cap.units)
                    .ok_or(CommerceEscrowError::OfferLiabilityInvalid("overflow"))?,
                currency: total.currency,
            },
        });
    }
    let liability = liability.ok_or(CommerceEscrowError::OfferLiabilityInvalid("no grants"))?;
    if liability.units == 0 {
        return Err(CommerceEscrowError::OfferLiabilityInvalid("zero"));
    }
    Ok(liability)
}

fn verify_reservation(
    receipt: &SignedCommerceReservationReceipt,
    trusted_authorities: &[PublicKey],
    context: &CommerceOrderContext,
    token: &CapabilityToken,
) -> Result<MonetaryAmount, CommerceEscrowError> {
    require_pinned_signature(
        receipt,
        trusted_authorities,
        CommerceEscrowError::NoTrustedReservationAuthority,
        CommerceEscrowError::ReservationSignerUntrusted,
        CommerceEscrowError::ReservationSignatureInvalid,
    )?;
    let body = &receipt.body;
    if body.schema != COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID {
        return Err(CommerceEscrowError::ReservationSchemaUnsupported(
            body.schema.clone(),
        ));
    }
    if body.receipt_id.trim().is_empty() {
        return Err(CommerceEscrowError::ReservationIdEmpty);
    }
    if body.order_id != context.order_id {
        return Err(CommerceEscrowError::ReservationUnbound("order_id"));
    }
    if body.token_offer_id != token.id {
        return Err(CommerceEscrowError::ReservationUnbound("token_offer_id"));
    }
    if body.token_offer_sha256 != canonical_sha256(token)? {
        return Err(CommerceEscrowError::ReservationUnbound(
            "token_offer_sha256",
        ));
    }
    Ok(body.reserved_amount.clone())
}

/// Fields the signed settlement packet must share with the accepted context
/// and the locked ledger.
fn bind_settlement_packet(
    packet: &CommerceSettlementPacket,
    accepted: &CommerceOrderContext,
    ledger: &CommerceEscrowLedger,
) -> Result<(), CommerceEscrowError> {
    let bindings = [
        ("order_id", packet.order_id == accepted.order_id),
        (
            "settlement_packet_ref",
            packet.id == accepted.settlement_packet_ref,
        ),
        (
            "reconciliation_ref",
            packet.reconciliation_ref == accepted.reconciliation_ref,
        ),
        (
            "merchant_subject",
            packet.merchant_subject == ledger.beneficiary_account,
        ),
        ("amount_minor", packet.amount_minor == ledger.amount_minor),
        ("currency", packet.currency == ledger.currency),
        ("quote_sha256", packet.quote_sha256 == accepted.quote_sha256),
    ];
    match bindings.iter().find(|(_, bound)| !bound) {
        Some((field, _)) => Err(CommerceEscrowError::SettlementPacketUnbound(field)),
        None => Ok(()),
    }
}

/// Order context fields that settlement progress advances between acceptance
/// and release. Every other field, including any field added later, must be
/// carried unchanged from the accepted context.
const RELEASE_ADVANCED_CONTEXT_FIELDS: [&str; 5] = [
    "id",
    "issued_at",
    "current_state",
    "event_log_sha256",
    "payment_lifecycle_sha256",
];

fn bind_release_context(
    accepted: &CommerceOrderContext,
    advanced: &CommerceOrderContext,
) -> Result<(), CommerceEscrowError> {
    let accepted = context_fields(accepted)?;
    let advanced = context_fields(advanced)?;
    let unbound = accepted
        .keys()
        .chain(advanced.keys())
        .filter(|field| !RELEASE_ADVANCED_CONTEXT_FIELDS.contains(&field.as_str()))
        .find(|field| accepted.get(*field) != advanced.get(*field));
    match unbound {
        Some(field) => Err(CommerceEscrowError::ReleaseContextMismatch(field.clone())),
        None => Ok(()),
    }
}

fn context_fields(
    context: &CommerceOrderContext,
) -> Result<serde_json::Map<String, serde_json::Value>, CommerceEscrowError> {
    match serde_json::to_value(context)
        .map_err(|error| CommerceEscrowError::Canonicalization(error.to_string()))?
    {
        serde_json::Value::Object(fields) => Ok(fields),
        _ => Err(CommerceEscrowError::Canonicalization(
            "order context is not a JSON object".to_string(),
        )),
    }
}

fn verify_execution(
    execution: &SignedCapitalExecutionInstruction,
    trusted_authorities: &[PublicKey],
    ledger: &CommerceEscrowLedger,
    reconciliation_ref: &str,
    released_at: u64,
) -> Result<(), CommerceEscrowError> {
    require_pinned_signature(
        execution,
        trusted_authorities,
        CommerceEscrowError::NoTrustedExecutionAuthority,
        CommerceEscrowError::ExecutionSignerUntrusted,
        CommerceEscrowError::ExecutionSignatureInvalid,
    )?;
    let body = &execution.body;
    body.validate()
        .map_err(CommerceEscrowError::ExecutionInvalid)?;
    if body.action != CapitalExecutionInstructionAction::ReleaseReserve {
        return Err(CommerceEscrowError::ExecutionActionNotRelease);
    }
    let observed = match (&body.observed_execution, body.reconciled_state) {
        (Some(observed), CapitalExecutionReconciledState::Matched) => observed,
        _ => return Err(CommerceEscrowError::ExecutionNotMatched),
    };
    if observed.external_reference_id != reconciliation_ref {
        return Err(CommerceEscrowError::ExecutionUnbound(
            "external_reference_id",
        ));
    }
    if observed.amount.units != ledger.amount_minor || observed.amount.currency != ledger.currency {
        return Err(CommerceEscrowError::ExecutionUnbound("amount"));
    }
    if body.counterparty_id != ledger.beneficiary_account {
        return Err(CommerceEscrowError::ExecutionUnbound("counterparty_id"));
    }
    if body.subject_key != ledger.depositor_account {
        return Err(CommerceEscrowError::ExecutionUnbound("subject_key"));
    }
    if body.issued_at > released_at {
        return Err(CommerceEscrowError::ExecutionAfterRelease("issued_at"));
    }
    if observed.observed_at > released_at {
        return Err(CommerceEscrowError::ExecutionAfterRelease("observed_at"));
    }
    Ok(())
}

/// Requires a nonempty pinned signer set, signer membership, and a valid
/// signature, in that order.
fn require_pinned_signature<T: Serialize + Clone>(
    envelope: &SignedExportEnvelope<T>,
    trusted: &[PublicKey],
    unpinned: CommerceEscrowError,
    untrusted: CommerceEscrowError,
    invalid: CommerceEscrowError,
) -> Result<(), CommerceEscrowError> {
    if trusted.is_empty() {
        return Err(unpinned);
    }
    if !trusted.contains(&envelope.signer_key) {
        return Err(untrusted);
    }
    if !matches!(envelope.verify_signature(), Ok(true)) {
        return Err(invalid);
    }
    Ok(())
}

fn build_settlement_packet(
    context: &CommerceOrderContext,
    dispatch: &CommerceSettlementDispatch,
) -> CommerceSettlementPacket {
    CommerceSettlementPacket {
        schema: COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID.to_string(),
        id: context.settlement_packet_ref.clone(),
        issued_at: dispatch.issued_at.clone(),
        order_id: context.order_id.clone(),
        merchant_subject: context.merchant_subject.clone(),
        psp: dispatch.psp.clone(),
        payment_intent_id: dispatch.payment_intent_id.clone(),
        amount_minor: context.quote_amount_minor,
        currency: context.quote_currency.clone(),
        quote_sha256: context.quote_sha256.clone(),
        settlement_rail: dispatch.settlement_rail.clone(),
        settlement_account_ref: dispatch.settlement_account_ref.clone(),
        dispatch_receipt_ref: dispatch.dispatch_receipt_ref.clone(),
        reconciliation_ref: context.reconciliation_ref.clone(),
        status: dispatch.status.clone(),
    }
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, CommerceEscrowError> {
    let canonical = chio_core_types::canonical_json_bytes(value)
        .map_err(|error| CommerceEscrowError::Canonicalization(error.to_string()))?;
    Ok(crate::sha256_hex(&canonical))
}

#[cfg(test)]
#[path = "escrow_tests.rs"]
mod tests;
