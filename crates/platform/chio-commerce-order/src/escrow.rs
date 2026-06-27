//! Custodial offer-safety escrow wired into the commerce-order spine.
//!
//! M1-15 binds the M0 single-ledger custodial escrow to the shipped
//! commerce-order state machine. [`accept`] performs the single-ledger atomic
//! two-leg swap (lock leg) against a verified offer/reservation pair, emits the
//! [`CommerceSettlementPacket`] as a signed body, and pins the resulting escrow
//! digest into the [`CommerceOrderContext`]. [`release`] commits the second leg
//! ONLY against a capital execution observation reconciled as
//! [`CapitalExecutionReconciledState::Matched`].
//!
//! Four fail-closed seams hold:
//!
//! - The offered capability token is authenticated BEFORE any custodial
//!   liability is derived from it: its signature must verify against its
//!   issuer key, it must be inside its validity window at the accept
//!   observation time, and it must be issued by a counterparty distinct from
//!   the acceptor/subject. `subject`/`issuer` are attacker-settable public
//!   fields, so the acceptor==subject guard is only meaningful once the token
//!   itself is proven authentic.
//! - The reservation MUST be a signed [`CommerceReservationReceipt`] witness:
//!   its signature verifies against the pinned settlement reservation authority,
//!   and it is bound to this order id and the exact offer token (token id plus
//!   canonical digest) BEFORE any collateral is trusted. A bare amount can be
//!   fabricated; a signed witness bound to the order/token cannot. The witnessed
//!   reservation must fully collateralize the offer liability, the locked amount
//!   must equal the signed quote, and the acceptor must be the offer subject, or
//!   [`accept`] denies.
//! - The custodial depositor/beneficiary accounts are bound to the order
//!   parties: they are derived from the order context's verified
//!   `buyer_subject` / `merchant_subject`, never caller-supplied, so custody can
//!   never be redirected to a third account while the settlement packet names
//!   the order merchant.
//! - Seam A: the freetier:global Sybil-ceiling pool ledger and the escrow
//!   ledger are hard-isolated. No escrow leg, in either direction, may name a
//!   `freetier:global:<window>` row (see [`is_freetier_global_pool_id`]).
//!
//! At M1 the on-chain value leg never moves: [`accept`] returns a PREPARE-ONLY
//! [`EscrowBroadcastIntent`]. The on-chain value move is M2 and reuses the
//! chio-settle prepare path (`prepare_web3_escrow_dispatch`).

use std::collections::BTreeMap;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::capability::token::{is_freetier_global_pool_id, CapabilityToken};
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_credit::{CapitalExecutionObservation, CapitalExecutionReconciledState};
use serde::{Deserialize, Serialize};

use super::error::CommerceOrderError;
use super::ids::{COMMERCE_ESCROW_LEDGER_SCHEMA_ID, COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID};
use super::types::{CommerceOrderContext, CommerceSettlementPacket};

/// Shipped state-machine transition the escrow accept binds to: assembling the
/// settlement packet.
const ASSEMBLE_SETTLEMENT_TRANSITION: &str = "assemble_settlement_packet";

/// Shipped state-machine transition the escrow release binds to: reconciling
/// the settlement.
const RECONCILE_SETTLEMENT_TRANSITION: &str = "reconcile_settlement";

/// The single custody account every escrow leg flows through. It is a fixed,
/// non-pool account id so the escrow ledger can never share a row with the
/// freetier:global pool (Seam A).
const ESCROW_CUSTODY_ACCOUNT: &str = "chio:commerce:escrow:custody";

/// Canonical commerce-order states, mirroring the strings the shipped event-log
/// replay drives (see `replay::is_allowed_transition`). The escrow path uses
/// this enum to bind its transitions to the shipped order spine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderState {
    None,
    IntentRecorded,
    ProviderAdmitted,
    QuoteBound,
    MandateBound,
    BudgetReserved,
    PaymentChallenged,
    PaymentVerified,
    FulfillmentRequested,
    FulfillmentAttested,
    SettlementPacketAssembled,
    SettlementDispatched,
    SettlementObserved,
    SettlementReconciled,
    Completed,
    Disputed,
    Refunded,
    FailedClosed,
}

impl OrderState {
    /// The canonical wire string for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OrderState::None => "none",
            OrderState::IntentRecorded => "intent_recorded",
            OrderState::ProviderAdmitted => "provider_admitted",
            OrderState::QuoteBound => "quote_bound",
            OrderState::MandateBound => "mandate_bound",
            OrderState::BudgetReserved => "budget_reserved",
            OrderState::PaymentChallenged => "payment_challenged",
            OrderState::PaymentVerified => "payment_verified",
            OrderState::FulfillmentRequested => "fulfillment_requested",
            OrderState::FulfillmentAttested => "fulfillment_attested",
            OrderState::SettlementPacketAssembled => "settlement_packet_assembled",
            OrderState::SettlementDispatched => "settlement_dispatched",
            OrderState::SettlementObserved => "settlement_observed",
            OrderState::SettlementReconciled => "settlement_reconciled",
            OrderState::Completed => "completed",
            OrderState::Disputed => "disputed",
            OrderState::Refunded => "refunded",
            OrderState::FailedClosed => "failed_closed",
        }
    }

    /// Parse a canonical state string, failing closed on any unknown value.
    pub fn parse(value: &str) -> Result<Self, CommerceOrderError> {
        let state = match value {
            "none" => OrderState::None,
            "intent_recorded" => OrderState::IntentRecorded,
            "provider_admitted" => OrderState::ProviderAdmitted,
            "quote_bound" => OrderState::QuoteBound,
            "mandate_bound" => OrderState::MandateBound,
            "budget_reserved" => OrderState::BudgetReserved,
            "payment_challenged" => OrderState::PaymentChallenged,
            "payment_verified" => OrderState::PaymentVerified,
            "fulfillment_requested" => OrderState::FulfillmentRequested,
            "fulfillment_attested" => OrderState::FulfillmentAttested,
            "settlement_packet_assembled" => OrderState::SettlementPacketAssembled,
            "settlement_dispatched" => OrderState::SettlementDispatched,
            "settlement_observed" => OrderState::SettlementObserved,
            "settlement_reconciled" => OrderState::SettlementReconciled,
            "completed" => OrderState::Completed,
            "disputed" => OrderState::Disputed,
            "refunded" => OrderState::Refunded,
            "failed_closed" => OrderState::FailedClosed,
            other => {
                return Err(CommerceOrderError::SettlementFailed(format!(
                    "unknown commerce order state: {other}"
                )))
            }
        };
        Ok(state)
    }
}

/// Direction of a single escrow ledger leg.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommerceEscrowLegKind {
    /// Debit the depositor (buyer), credit the custody account.
    Lock,
    /// Debit the custody account, credit the beneficiary (merchant).
    Release,
}

/// Lifecycle status of the single-ledger escrow.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommerceEscrowStatus {
    /// Funds are locked in custody; the release leg has not committed.
    Locked,
    /// Both legs have committed; custody is drained to the beneficiary.
    Released,
}

/// A single leg of the escrow swap: an atomic transfer of `amount_minor` from
/// `from_account` to `to_account`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceEscrowLeg {
    pub kind: CommerceEscrowLegKind,
    pub from_account: String,
    pub to_account: String,
    pub amount_minor: u64,
}

/// The single custodial ledger backing one commerce order. One ledger holds
/// both legs of the swap; conservation is preserved (no value is created or
/// destroyed across all accounts).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceEscrowLedger {
    pub schema: String,
    pub order_id: String,
    pub currency: String,
    pub depositor_account: String,
    pub beneficiary_account: String,
    pub custody_account: String,
    pub amount_minor: u64,
    pub legs: Vec<CommerceEscrowLeg>,
    pub status: CommerceEscrowStatus,
}

impl CommerceEscrowLedger {
    /// Build the locked ledger: the single lock leg debits the depositor and
    /// credits the custody account. Fails closed if any account is a
    /// freetier:global pool row (Seam A) or if conservation does not hold.
    fn lock(
        order_id: String,
        currency: String,
        depositor_account: String,
        beneficiary_account: String,
        amount_minor: u64,
    ) -> Result<Self, CommerceOrderError> {
        if amount_minor == 0 {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow lock amount must be greater than zero".to_string(),
            ));
        }
        for account in [
            depositor_account.as_str(),
            beneficiary_account.as_str(),
            ESCROW_CUSTODY_ACCOUNT,
        ] {
            ensure_pool_escrow_isolation(account)?;
        }
        let lock_leg = CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Lock,
            from_account: depositor_account.clone(),
            to_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor,
        };
        let ledger = Self {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id,
            currency,
            depositor_account,
            beneficiary_account,
            custody_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor,
            legs: vec![lock_leg],
            status: CommerceEscrowStatus::Locked,
        };
        ledger.assert_conservation()?;
        Ok(ledger)
    }

    /// Commit the second leg: debit custody, credit the beneficiary, draining
    /// custody to zero. Fails closed if the ledger is not locked or conservation
    /// would break.
    fn released(&self) -> Result<Self, CommerceOrderError> {
        if self.status != CommerceEscrowStatus::Locked {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow release denied: ledger is not in the locked state".to_string(),
            ));
        }
        let mut ledger = self.clone();
        ledger.legs.push(CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Release,
            from_account: self.custody_account.clone(),
            to_account: self.beneficiary_account.clone(),
            amount_minor: self.amount_minor,
        });
        ledger.status = CommerceEscrowStatus::Released;
        ledger.assert_conservation()?;
        Ok(ledger)
    }

    /// Conservation invariant for the single ledger: across all accounts the net
    /// flow is zero, custody is never overdrawn, and the lifecycle balances are
    /// consistent with the declared status. Every leg is re-checked against Seam
    /// A so neither direction can touch a freetier:global pool row.
    fn assert_conservation(&self) -> Result<(), CommerceOrderError> {
        let mut balances: BTreeMap<&str, i128> = BTreeMap::new();
        for leg in &self.legs {
            ensure_pool_escrow_isolation(&leg.from_account)?;
            ensure_pool_escrow_isolation(&leg.to_account)?;
            let amount = i128::from(leg.amount_minor);
            *balances.entry(leg.from_account.as_str()).or_default() -= amount;
            *balances.entry(leg.to_account.as_str()).or_default() += amount;
        }
        let net: i128 = balances.values().sum();
        if net != 0 {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow ledger violates conservation: net flow is non-zero".to_string(),
            ));
        }
        let custody = balances
            .get(self.custody_account.as_str())
            .copied()
            .unwrap_or(0);
        if custody < 0 {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow ledger overdraws custody".to_string(),
            ));
        }
        match self.status {
            CommerceEscrowStatus::Locked => {
                if custody != i128::from(self.amount_minor) {
                    return Err(CommerceOrderError::SettlementFailed(
                        "locked escrow custody does not hold the full offer amount".to_string(),
                    ));
                }
            }
            CommerceEscrowStatus::Released => {
                if custody != 0 {
                    return Err(CommerceOrderError::SettlementFailed(
                        "released escrow leaves a residual custody balance".to_string(),
                    ));
                }
                let beneficiary = balances
                    .get(self.beneficiary_account.as_str())
                    .copied()
                    .unwrap_or(0);
                if beneficiary != i128::from(self.amount_minor) {
                    return Err(CommerceOrderError::SettlementFailed(
                        "released escrow did not credit the full amount to the beneficiary"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// sha256 hex over the canonical JSON of the ledger.
    fn digest(&self) -> Result<String, CommerceOrderError> {
        let canonical = chio_core_types::canonical_json_bytes(self).map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "escrow ledger canonicalization failed: {error}"
            ))
        })?;
        Ok(sha256_hex(&canonical))
    }
}

/// Seam A: the custodial escrow ledger and the freetier:global Sybil-ceiling
/// pool ledger are hard-isolated. No escrow leg, in either direction, may name
/// a `freetier:global:<window>` row, so the escrow can never co-debit or
/// co-credit the aggregate pool.
fn ensure_pool_escrow_isolation(account_id: &str) -> Result<(), CommerceOrderError> {
    if is_freetier_global_pool_id(account_id) {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "escrow ledger isolation violation: account {account_id} is a freetier:global pool row"
        )));
    }
    Ok(())
}

/// The off-context settlement dispatch fields the escrow accept binds onto the
/// order context to build the settlement packet body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceSettlementDispatch {
    pub issued_at: String,
    pub psp: String,
    pub payment_intent_id: String,
    pub settlement_rail: String,
    pub settlement_account_ref: String,
    pub dispatch_receipt_ref: String,
    pub status: String,
}

impl CommerceSettlementDispatch {
    fn validate(&self) -> Result<(), CommerceOrderError> {
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
                return Err(CommerceOrderError::SettlementFailed(format!(
                    "escrow settlement dispatch {field} must not be empty"
                )));
            }
        }
        if !matches!(
            self.status.as_str(),
            "dispatched" | "reconciled" | "settled"
        ) {
            return Err(CommerceOrderError::SettlementFailed(format!(
                "unsupported escrow settlement status: {}",
                self.status
            )));
        }
        Ok(())
    }
}

/// PREPARE-ONLY broadcast intent. At M1 no value moves on-chain; the on-chain
/// value move is M2 and reuses the chio-settle prepare path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EscrowBroadcastIntent {
    pub prepare_only: bool,
    pub value_moved_on_chain: bool,
    pub escrow_id: String,
    pub amount_minor: u64,
    pub currency: String,
}

impl EscrowBroadcastIntent {
    fn prepare_only(ledger: &CommerceEscrowLedger) -> Result<Self, CommerceOrderError> {
        Ok(Self {
            prepare_only: true,
            value_moved_on_chain: false,
            escrow_id: ledger.digest()?,
            amount_minor: ledger.amount_minor,
            currency: ledger.currency.clone(),
        })
    }
}

/// Schema id of the signed commerce reservation receipt body.
pub const COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID: &str = "chio.commerce.reservation-receipt.v1";

/// The funds-reservation receipt body a settlement reservation authority signs
/// to witness that collateral was actually reserved for one commerce
/// order/offer. The body is bound to the order id AND the exact offer token (its
/// id and canonical digest), so a witness minted for one order/offer can never
/// be replayed to lock custody under another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommerceReservationReceipt {
    pub schema: String,
    /// Opaque, unique reservation receipt id (the settlement authority supplies it).
    pub receipt_id: String,
    /// The order this reservation collateralizes; MUST equal `order_context.order_id`.
    pub order_id: String,
    /// The offered capability token id this reservation collateralizes; MUST
    /// equal `token_offer.id`.
    pub token_offer_id: String,
    /// sha256 hex over the canonical offer token; binds the witness to the exact
    /// offer, not merely its id.
    pub token_offer_sha256: String,
    /// The funds the settlement authority witnesses as reserved for this offer.
    pub reserved_amount: MonetaryAmount,
}

/// A signed [`CommerceReservationReceipt`] (settlement reservation authority over
/// the canonical body).
pub type SignedCommerceReservationReceipt = SignedExportEnvelope<CommerceReservationReceipt>;

/// A verified funds-reservation witness bound to one commerce order/offer.
///
/// Construct it through [`VerifiedCommerceReservation::from_signed`], which proves
/// the receipt was signed by the pinned settlement reservation authority and is
/// bound to the order and the exact offer token before any custody is locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCommerceReservation {
    reserved_amount: MonetaryAmount,
}

impl VerifiedCommerceReservation {
    /// Verify a signed reservation receipt against the expected settlement
    /// reservation authority and bind it to the order and offer token.
    ///
    /// Fails closed when the receipt schema is unsupported, the receipt id is
    /// empty, the signer is not the expected reservation authority, the
    /// signature does not verify, the receipt is not bound to this order id, the
    /// receipt is not bound to this offer token id or canonical digest, or the
    /// witnessed amount is zero.
    pub fn from_signed(
        receipt: &SignedCommerceReservationReceipt,
        expected_reservation_authority: &PublicKey,
        order_context: &CommerceOrderContext,
        token_offer: &CapabilityToken,
    ) -> Result<Self, CommerceOrderError> {
        if receipt.body.schema != COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID {
            return Err(CommerceOrderError::SettlementFailed(format!(
                "escrow accept denied: unsupported reservation receipt schema: {}",
                receipt.body.schema
            )));
        }
        if receipt.body.receipt_id.trim().is_empty() {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt id must not be empty".to_string(),
            ));
        }
        // Settlement-authority binding: the witness MUST be signed by the pinned
        // reservation authority, and the signature MUST verify over the body.
        if receipt.signer_key != *expected_reservation_authority {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt is not signed by the expected \
                 settlement reservation authority"
                    .to_string(),
            ));
        }
        match receipt.verify_signature() {
            Ok(true) => {}
            _ => {
                return Err(CommerceOrderError::SettlementFailed(
                    "escrow accept denied: reservation receipt signature is invalid".to_string(),
                ))
            }
        }
        // Order binding: a witness minted for a different order cannot lock this one.
        if receipt.body.order_id != order_context.order_id {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt is not bound to this order".to_string(),
            ));
        }
        // Offer binding: pin both the offer token id and its canonical digest so
        // the witness cannot be replayed against a different (or tampered) offer.
        if receipt.body.token_offer_id != token_offer.id {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt is not bound to this offer token"
                    .to_string(),
            ));
        }
        let offer_digest = token_offer_digest(token_offer)?;
        if receipt.body.token_offer_sha256 != offer_digest {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt offer digest does not match the offer \
                 token"
                    .to_string(),
            ));
        }
        if receipt.body.reserved_amount.units == 0 {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation witnesses a zero amount".to_string(),
            ));
        }
        Ok(Self {
            reserved_amount: receipt.body.reserved_amount.clone(),
        })
    }

    /// The witnessed reserved amount, trusted only after binding verification.
    #[must_use]
    pub fn reserved_amount(&self) -> &MonetaryAmount {
        &self.reserved_amount
    }
}

/// sha256 hex over the canonical JSON of an offered capability token. Binds a
/// reservation witness to the exact offer (not merely its id).
fn token_offer_digest(token: &CapabilityToken) -> Result<String, CommerceOrderError> {
    let canonical = chio_core_types::canonical_json_bytes(token).map_err(|error| {
        CommerceOrderError::SettlementFailed(format!(
            "escrow accept denied: offer token canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Inputs to [`accept`]. Binds a verified offer/reservation pair to a shipped
/// commerce order.
pub struct CommerceEscrowAcceptRequest<'a> {
    /// The shipped order context. Its `current_state` is the spine prior state
    /// and must allow the settlement-packet-assembly transition.
    pub order_context: &'a CommerceOrderContext,
    /// The offered capability token. Its `subject` is the only permitted
    /// acceptor and its grants determine the collateral liability.
    pub token_offer: &'a CapabilityToken,
    /// The key accepting the offer.
    pub acceptor: &'a PublicKey,
    /// Observation time (unix seconds) the accept is evaluated at. The offer
    /// token's validity window is enforced against this clock; the accept fails
    /// closed when the token is not-yet-valid or expired at this time. Mirrors
    /// the open-market accept `accepted_at` parameter.
    pub accepted_at: u64,
    /// The signed reservation witness proving collateral was reserved for this
    /// order/offer. Verified and bound to the order and offer token before any
    /// custody is locked (see [`VerifiedCommerceReservation::from_signed`]).
    pub reservation: &'a SignedCommerceReservationReceipt,
    /// The pinned settlement reservation authority key the reservation witness
    /// MUST be signed by.
    pub reservation_authority: PublicKey,
    /// Off-context settlement dispatch fields for the settlement packet body.
    pub settlement: CommerceSettlementDispatch,
    /// Authority that signs the emitted settlement packet body.
    pub settlement_authority: &'a Keypair,
}

/// Result of [`accept`]: the locked single-ledger escrow, the signed settlement
/// packet, the pinned escrow digest, the prepare-only broadcast intent, and the
/// advanced order context.
#[derive(Debug, Clone)]
pub struct CommerceEscrowAcceptance {
    pub ledger: CommerceEscrowLedger,
    pub liability: MonetaryAmount,
    pub settlement_packet: SignedExportEnvelope<CommerceSettlementPacket>,
    pub escrow_digest: String,
    pub broadcast: EscrowBroadcastIntent,
    pub next_state: OrderState,
    pub updated_context: CommerceOrderContext,
}

/// Result of [`release`]: the released (drained) ledger and the advanced order
/// context.
#[derive(Debug, Clone)]
pub struct CommerceEscrowRelease {
    pub ledger: CommerceEscrowLedger,
    pub escrow_digest: String,
    pub external_reference_id: String,
    pub next_state: OrderState,
    pub updated_context: CommerceOrderContext,
}

/// Accept an offer against a custodial escrow and the shipped commerce-order
/// state machine.
///
/// Fails closed when:
///
/// - the offer token signature does not verify against its issuer key;
/// - the offer token is not-yet-valid or expired at `accepted_at`;
/// - the offer token issuer is not a counterparty distinct from the subject;
/// - the reservation witness is not signed by the expected settlement
///   reservation authority, or is not bound to this order id and offer token;
/// - the reservation under-collateralizes the offer liability;
/// - the locked offer liability does not equal the signed quote amount;
/// - the acceptor is not the offer subject;
/// - the order context's current state is not a settlement-assembly state;
/// - any escrow account is a freetier:global pool row (Seam A).
///
/// On success it performs the single-ledger atomic two-leg swap (lock leg),
/// emits the [`CommerceSettlementPacket`] signed body, derives a PREPARE-ONLY
/// broadcast intent (no value moves on-chain at M1), and returns the order
/// context advanced to `settlement_packet_assembled` with the escrow digest
/// pinned.
pub fn accept(
    request: CommerceEscrowAcceptRequest<'_>,
) -> Result<CommerceEscrowAcceptance, CommerceOrderError> {
    request.order_context.validate_shape()?;

    // Bind to the shipped order spine: the escrow accept IS the
    // settlement-packet-assembly transition, so the order's declared current
    // state must be one the shipped state machine allows to assemble.
    let prior_state = OrderState::parse(&request.order_context.current_state)?;
    if !super::replay::is_allowed_transition(
        prior_state.as_str(),
        OrderState::SettlementPacketAssembled.as_str(),
        ASSEMBLE_SETTLEMENT_TRANSITION,
    ) {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "escrow accept denied: {} is not a settlement-assembly state",
            prior_state.as_str()
        )));
    }

    // ESCROW-1: authenticate the offered capability token BEFORE deriving any
    // custodial liability from it. `subject` and `issuer` are attacker-settable
    // public fields, so the acceptor==subject guard below is hollow until the
    // token itself is proven authentic. This mirrors the open-market accept
    // (`chio_open_market::bidding::accept`): verify the offer signature, enforce
    // the validity window, then bind the issuer.

    // (1) The offer token signature MUST verify against its declared issuer
    // key. Fail closed on a forged/unsigned token (Ok(false)) or any
    // verification error (Err). The signature is checked FIRST so an expired
    // forgery is reported as a bad signature, never as merely "expired".
    match request.token_offer.verify_signature() {
        Ok(true) => {}
        _ => {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: offer token signature is invalid".to_string(),
            ))
        }
    }

    // (2) The offer token MUST be inside its validity window at the accept
    // observation time. Fail closed on a not-yet-valid or expired token.
    request
        .token_offer
        .validate_time(request.accepted_at)
        .map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "escrow accept denied: offer token is outside its validity window: {error}"
            ))
        })?;

    // (3) Issuer provenance. The open-market accept pins
    // `token_offer.issuer == ask.signer_key` against the signed ask. The
    // commerce `CommerceOrderContext` is a byte-stable signed-body wire type
    // that carries NO merchant/offer-issuer public key, so the offer issuer
    // cannot yet be cryptographically pinned to the order's merchant identity.
    // The available fail-closed binding is structural: the offer MUST be issued
    // by a counterparty distinct from the acceptor/subject. A self-issued,
    // self-accepted offer has no real counterparty and is a forge, so it is
    // denied here. RESIDUAL: binding `token_offer.issuer` to a merchant key
    // carried by the order context is the remaining step; it requires adding
    // that key to the `CommerceOrderContext` wire format and is deferred so this
    // change stays byte-stable.
    if request.token_offer.issuer == request.token_offer.subject {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: offer issuer is not a counterparty distinct from the subject"
                .to_string(),
        ));
    }

    let liability = token_offer_total_liability(request.token_offer)?;

    // Fail closed: only the offer subject may accept.
    if *request.acceptor != request.token_offer.subject {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: acceptor is not the offer subject".to_string(),
        ));
    }

    // ESCROW-2: the reservation is a SIGNED witness, never a bare amount. Verify
    // it against the pinned settlement reservation authority and bind it to this
    // order id and the exact offer token BEFORE any collateral is trusted. A
    // fabricated amount cannot satisfy this; only an authority-signed witness
    // minted for THIS order/offer can. Compose with the ESCROW-1 offer-token
    // authentication above.
    let reservation = VerifiedCommerceReservation::from_signed(
        request.reservation,
        &request.reservation_authority,
        request.order_context,
        request.token_offer,
    )?;
    let reserved_amount = reservation.reserved_amount();

    // Fail closed: the reservation must fully collateralize the offer liability
    // in the order's currency.
    if liability.currency != request.order_context.quote_currency {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: offer liability currency does not match the order quote"
                .to_string(),
        ));
    }
    if reserved_amount.currency != liability.currency {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: reservation currency does not match the offer liability"
                .to_string(),
        ));
    }
    // C1: the amount locked in custody is the offer collateral cap
    // (`liability.units`), but the settlement packet and the release leg are
    // settled against the signed quote (`quote_amount_minor`). When the cap
    // differs from the quote the custody hold and the settled amount disagree,
    // so fail closed: the locked amount MUST equal the signed quote.
    if liability.units != request.order_context.quote_amount_minor {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: offer liability does not equal the signed quote amount"
                .to_string(),
        ));
    }
    if reserved_amount.units < liability.units {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: reservation under-collateralizes the offer liability"
                .to_string(),
        ));
    }

    // ESCROW-3: bind the custodial accounts to the actual order parties. The
    // depositor (buyer) and beneficiary (merchant) accounts are NOT
    // caller-supplied; they are derived from the order context's verified
    // `buyer_subject` / `merchant_subject`. A caller can therefore never redirect
    // custody to a third account while the settlement packet still names the
    // order merchant. `validate_shape` above already proved both are non-empty.
    let depositor_account = request.order_context.buyer_subject.clone();
    let beneficiary_account = request.order_context.merchant_subject.clone();

    // Single-ledger custodial escrow: the lock leg debits the depositor (buyer)
    // and credits the custody account. Seam A is enforced inside `lock`.
    let ledger = CommerceEscrowLedger::lock(
        request.order_context.order_id.clone(),
        liability.currency.clone(),
        depositor_account,
        beneficiary_account,
        liability.units,
    )?;

    let packet = build_settlement_packet(request.order_context, &request.settlement)?;
    let settlement_packet = SignedExportEnvelope::sign(packet, request.settlement_authority)
        .map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "escrow accept failed to sign settlement packet: {error}"
            ))
        })?;

    let escrow_digest = ledger.digest()?;
    let broadcast = EscrowBroadcastIntent::prepare_only(&ledger)?;

    let mut updated_context = request.order_context.clone();
    updated_context.escrow_digest = Some(escrow_digest.clone());
    updated_context.current_state = OrderState::SettlementPacketAssembled.as_str().to_string();

    Ok(CommerceEscrowAcceptance {
        ledger,
        liability,
        settlement_packet,
        escrow_digest,
        broadcast,
        next_state: OrderState::SettlementPacketAssembled,
        updated_context,
    })
}

/// Release the locked escrow ONLY against a Matched capital execution
/// observation.
///
/// Fails closed when the reconciled state is not
/// [`CapitalExecutionReconciledState::Matched`], when `prior_state` is not a
/// settlement-reconciliation state on the shipped spine, or when the observed
/// execution does not cover exactly the locked amount and currency.
pub fn release(
    acceptance: &CommerceEscrowAcceptance,
    observation: &CapitalExecutionObservation,
    reconciled_state: CapitalExecutionReconciledState,
    prior_state: OrderState,
) -> Result<CommerceEscrowRelease, CommerceOrderError> {
    // Fail closed: a custodial release fires ONLY against a capital execution
    // observation reconciled as Matched. Any not-yet-matched state keeps the
    // funds locked.
    if reconciled_state != CapitalExecutionReconciledState::Matched {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: capital execution is not reconciled Matched".to_string(),
        ));
    }

    // Bind to the shipped spine: release IS the settlement reconciliation step.
    if !super::replay::is_allowed_transition(
        prior_state.as_str(),
        OrderState::SettlementReconciled.as_str(),
        RECONCILE_SETTLEMENT_TRANSITION,
    ) {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "escrow release denied: {} is not a settlement-reconciliation state",
            prior_state.as_str()
        )));
    }

    // The observed execution must cover exactly the locked amount and currency.
    if observation.amount.currency != acceptance.ledger.currency
        || observation.amount.units != acceptance.ledger.amount_minor
    {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: observed execution does not match the locked amount"
                .to_string(),
        ));
    }

    let ledger = acceptance.ledger.released()?;
    let escrow_digest = ledger.digest()?;

    let mut updated_context = acceptance.updated_context.clone();
    updated_context.escrow_digest = Some(escrow_digest.clone());
    updated_context.current_state = OrderState::SettlementReconciled.as_str().to_string();

    Ok(CommerceEscrowRelease {
        ledger,
        escrow_digest,
        external_reference_id: observation.external_reference_id.clone(),
        next_state: OrderState::SettlementReconciled,
        updated_context,
    })
}

/// The aggregate collateral liability of an offered capability token: the sum of
/// every grant's `max_total_cost`, in a single currency. Mirrors the open-market
/// reservation-collateral rule and binds to the shipped `CapabilityToken` scope
/// shape. Fails closed on a missing cap, a mixed currency, an empty offer, or a
/// zero total.
fn token_offer_total_liability(
    token: &CapabilityToken,
) -> Result<MonetaryAmount, CommerceOrderError> {
    let mut currency: Option<String> = None;
    let mut total: u64 = 0;
    for grant in &token.scope.grants {
        let max_total = grant.max_total_cost.as_ref().ok_or_else(|| {
            CommerceOrderError::SettlementFailed(
                "offer grant is missing max_total_cost; liability is unbounded".to_string(),
            )
        })?;
        match &currency {
            Some(existing) if existing != &max_total.currency => {
                return Err(CommerceOrderError::SettlementFailed(
                    "offer grants mix currencies; liability is undefined".to_string(),
                ));
            }
            None => currency = Some(max_total.currency.clone()),
            _ => {}
        }
        total = total.checked_add(max_total.units).ok_or_else(|| {
            CommerceOrderError::SettlementFailed("offer liability overflowed u64".to_string())
        })?;
    }
    let currency = currency.ok_or_else(|| {
        CommerceOrderError::SettlementFailed("offer carries no grants to collateralize".to_string())
    })?;
    if total == 0 {
        return Err(CommerceOrderError::SettlementFailed(
            "offer liability is zero".to_string(),
        ));
    }
    Ok(MonetaryAmount {
        units: total,
        currency,
    })
}

fn build_settlement_packet(
    context: &CommerceOrderContext,
    dispatch: &CommerceSettlementDispatch,
) -> Result<CommerceSettlementPacket, CommerceOrderError> {
    dispatch.validate()?;
    Ok(CommerceSettlementPacket {
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
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core_types::crypto::Keypair;
    use chio_test_support::prelude::*;

    const HEX64: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    fn token_offer(
        issuer: &Keypair,
        subject: &PublicKey,
        units: u64,
        currency: &str,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "offer-token-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.clone(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "demo-server".to_string(),
                    tool_name: "search".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: units / 10,
                        currency: currency.to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units,
                        currency: currency.to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 100,
            expires_at: 10_000,
            delegation_chain: Vec::new(),
        };
        CapabilityToken::sign(body, issuer).test_expect("sign offer token")
    }

    fn order_context(current_state: &str) -> CommerceOrderContext {
        let value = serde_json::json!({
            "schema": super::super::ids::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
            "id": "ctx-1",
            "issued_at": "2026-06-25T00:00:00Z",
            "order_id": "order-commerce-001",
            "buyer_subject": "buyer:alice",
            "agent_subject": "agent:alice",
            "merchant_subject": "merchant:stripe:coffee-shop",
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
        serde_json::from_value(value).test_expect("order context deserializes")
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

    fn reserved(units: u64, currency: &str) -> MonetaryAmount {
        MonetaryAmount {
            units,
            currency: currency.to_string(),
        }
    }

    /// The pinned settlement reservation authority the escrow tests sign their
    /// reservation witnesses with.
    fn reservation_authority() -> Keypair {
        keypair(9)
    }

    /// Build a signed reservation witness bound to `context` and `token` for
    /// `units`/`currency`, signed by `authority`.
    fn signed_reservation(
        context: &CommerceOrderContext,
        token: &CapabilityToken,
        units: u64,
        currency: &str,
        authority: &Keypair,
    ) -> SignedCommerceReservationReceipt {
        let body = CommerceReservationReceipt {
            schema: COMMERCE_RESERVATION_RECEIPT_SCHEMA_ID.to_string(),
            receipt_id: "reservation-receipt-1".to_string(),
            order_id: context.order_id.clone(),
            token_offer_id: token.id.clone(),
            token_offer_sha256: token_offer_digest(token).test_expect("offer digest"),
            reserved_amount: reserved(units, currency),
        };
        SignedExportEnvelope::sign(body, authority).test_expect("sign reservation receipt")
    }

    fn accept_request<'a>(
        context: &'a CommerceOrderContext,
        token: &'a CapabilityToken,
        acceptor: &'a PublicKey,
        reservation: &'a SignedCommerceReservationReceipt,
        reservation_authority: PublicKey,
        authority: &'a Keypair,
    ) -> CommerceEscrowAcceptRequest<'a> {
        CommerceEscrowAcceptRequest {
            order_context: context,
            token_offer: token,
            acceptor,
            accepted_at: 500,
            reservation,
            reservation_authority,
            settlement: dispatch(),
            settlement_authority: authority,
        }
    }

    #[test]
    fn accept_happy_path_locks_escrow_and_signs_settlement_packet() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("accept succeeds");

        assert_eq!(acceptance.liability.units, 4200);
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
        assert_eq!(acceptance.ledger.legs.len(), 1);
        assert_eq!(acceptance.ledger.legs[0].kind, CommerceEscrowLegKind::Lock);
        assert_eq!(acceptance.ledger.legs[0].from_account, "buyer:alice");
        assert_eq!(acceptance.ledger.legs[0].to_account, ESCROW_CUSTODY_ACCOUNT);
        // PREPARE-ONLY: no value moves on-chain at M1.
        assert!(acceptance.broadcast.prepare_only);
        assert!(!acceptance.broadcast.value_moved_on_chain);
        assert_eq!(acceptance.next_state, OrderState::SettlementPacketAssembled);
        // Escrow digest is pinned into the advanced context.
        assert_eq!(
            acceptance.updated_context.escrow_digest.as_deref(),
            Some(acceptance.escrow_digest.as_str())
        );
        assert_eq!(
            acceptance.updated_context.current_state,
            "settlement_packet_assembled"
        );
        // The emitted settlement packet is a verifiable signed body bound to the
        // order context.
        assert!(acceptance
            .settlement_packet
            .verify_signature()
            .test_expect("settlement packet signature verifies"));
        assert_eq!(acceptance.settlement_packet.body.id, "settlement-packet-1");
        assert_eq!(acceptance.settlement_packet.body.amount_minor, 4200);
        // The advanced context still passes the shipped shape validation.
        acceptance
            .updated_context
            .validate_shape()
            .test_expect("advanced context is well-shaped");
    }

    #[test]
    fn accept_fails_closed_when_reservation_under_collateralizes() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        // Reserve less than the 4200 liability.
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4199, "USD", &res_auth);

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("under-collateralized accept is denied");

        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("under-collateralizes")
        ));
    }

    #[test]
    fn accept_fails_closed_on_wrong_acceptor() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let offer_subject = subject.public_key();
        let wrong_acceptor = keypair(3).public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &offer_subject, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let error = accept(accept_request(
            &context,
            &token,
            &wrong_acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("wrong acceptor is denied");

        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("acceptor is not the offer subject")
        ));
    }

    #[test]
    fn release_fires_only_against_matched_observation() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("accept succeeds");

        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "exec-ref-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };

        // NotObserved keeps the funds locked.
        let denied = release(
            &acceptance,
            &observation,
            CapitalExecutionReconciledState::NotObserved,
            OrderState::SettlementObserved,
        )
        .test_expect_err("release denied without Matched");
        assert!(matches!(
            denied,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("not reconciled Matched")
        ));

        // Matched drains custody to the beneficiary and advances the order.
        let released = release(
            &acceptance,
            &observation,
            CapitalExecutionReconciledState::Matched,
            OrderState::SettlementObserved,
        )
        .test_expect("Matched release succeeds");

        assert_eq!(released.ledger.status, CommerceEscrowStatus::Released);
        assert_eq!(released.ledger.legs.len(), 2);
        assert_eq!(released.ledger.legs[1].kind, CommerceEscrowLegKind::Release);
        assert_eq!(
            released.ledger.legs[1].to_account,
            "merchant:stripe:coffee-shop"
        );
        assert_eq!(released.external_reference_id, "exec-ref-1");
        assert_eq!(released.next_state, OrderState::SettlementReconciled);
        assert_eq!(
            released.updated_context.current_state,
            "settlement_reconciled"
        );
    }

    #[test]
    fn escrow_and_freetier_pool_are_hard_isolated_both_directions() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let res_auth = reservation_authority();
        let pool_id = "freetier:global:2026-06";
        assert!(is_freetier_global_pool_id(pool_id));

        // Debit direction: the order's buyer_subject (the derived depositor) is a
        // freetier:global pool row.
        let mut debit_context = order_context("fulfillment_attested");
        debit_context.buyer_subject = pool_id.to_string();
        let reservation = signed_reservation(&debit_context, &token, 4200, "USD", &res_auth);
        let debit_error = accept(accept_request(
            &debit_context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("escrow may not debit a freetier:global pool row");
        assert!(matches!(
            debit_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("isolation violation") && message.contains(pool_id)
        ));

        // Credit direction: the order's merchant_subject (the derived
        // beneficiary) is a freetier:global pool row.
        let mut credit_context = order_context("fulfillment_attested");
        credit_context.merchant_subject = pool_id.to_string();
        let reservation = signed_reservation(&credit_context, &token, 4200, "USD", &res_auth);
        let credit_error = accept(accept_request(
            &credit_context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("escrow may not credit a freetier:global pool row");
        assert!(matches!(
            credit_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("isolation violation") && message.contains(pool_id)
        ));
    }

    // ESCROW-3: the locked ledger's depositor/beneficiary are bound to the order
    // parties (buyer_subject / merchant_subject), never caller-supplied, so
    // custody can never be redirected to a third account while the settlement
    // packet still names the order merchant.
    #[test]
    fn accept_binds_escrow_accounts_to_order_parties() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let mut context = order_context("fulfillment_attested");
        context.buyer_subject = "buyer:distinct-party".to_string();
        context.merchant_subject = "merchant:distinct-party".to_string();
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("accept succeeds");

        // The ledger custody flows are bound to the order parties.
        assert_eq!(acceptance.ledger.depositor_account, "buyer:distinct-party");
        assert_eq!(
            acceptance.ledger.beneficiary_account,
            "merchant:distinct-party"
        );
        assert_eq!(
            acceptance.ledger.legs[0].from_account,
            "buyer:distinct-party"
        );
        // The settlement packet names the SAME merchant as the ledger
        // beneficiary, so settlement routing and custody release cannot diverge.
        assert_eq!(
            acceptance.settlement_packet.body.merchant_subject,
            acceptance.ledger.beneficiary_account
        );
    }

    #[test]
    fn ledger_conservation_holds_across_both_legs() {
        let ledger = CommerceEscrowLedger::lock(
            "order-1".to_string(),
            "USD".to_string(),
            "buyer:alice".to_string(),
            "merchant:bob".to_string(),
            4200,
        )
        .test_expect("locked ledger conserves");
        // Locked: custody holds the full amount.
        ledger
            .assert_conservation()
            .test_expect("locked conservation holds");

        let released = ledger.released().test_expect("released ledger conserves");
        released
            .assert_conservation()
            .test_expect("released conservation holds");
    }

    /// Build an offer token with arbitrary grants, signed by `issuer`, in the
    /// `[100, 10_000)` validity window used by the other escrow tests.
    fn token_with_grants(
        issuer: &Keypair,
        subject: &PublicKey,
        grants: Vec<ToolGrant>,
    ) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "offer-token-custom".to_string(),
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
        };
        CapabilityToken::sign(body, issuer).test_expect("sign custom offer token")
    }

    /// A single tool grant carrying `units` (or no cap when `units` is `None`)
    /// in `currency`.
    fn grant(units: Option<u64>, currency: &str) -> ToolGrant {
        ToolGrant {
            server_id: "demo-server".to_string(),
            tool_name: "search".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: units.map(|units| MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            dpop_required: None,
        }
    }

    // ESCROW-1: a forged/unsigned offer token is denied before any custodial
    // liability is derived from it.
    #[test]
    fn accept_fails_closed_on_forged_offer_token() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        // Validly sign, then tamper a signed field so the signature no longer
        // matches the body. expires_at stays past accepted_at, so only the
        // signature check can fire.
        let mut token = token_offer(&issuer, &acceptor, 4200, "USD");
        token.expires_at += 1;
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("forged offer token is denied");

        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer token signature is invalid")
        ));
    }

    // ESCROW-1: an offer token issued by the acceptor to itself (issuer ==
    // subject) carries no real counterparty and is denied.
    #[test]
    fn accept_fails_closed_on_self_issued_offer_token() {
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        // issuer == subject == acceptor: a self-dealing forge.
        let token = token_offer(&subject, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("self-issued offer token is denied");

        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer issuer is not a counterparty distinct from the subject")
        ));
    }

    // ESCROW-1: an offer token outside its validity window is denied in both
    // directions (not-yet-valid and expired).
    #[test]
    fn accept_fails_closed_on_offer_token_outside_validity_window() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        // Not-yet-valid: accepted_at precedes the token issued_at (100).
        let mut not_yet = accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        );
        not_yet.accepted_at = 50;
        let not_yet_error = accept(not_yet).test_expect_err("not-yet-valid offer token is denied");
        assert!(matches!(
            not_yet_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer token is outside its validity window")
        ));

        // Expired: accepted_at reaches the token expires_at (10_000).
        let mut expired = accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        );
        expired.accepted_at = 10_000;
        let expired_error = accept(expired).test_expect_err("expired offer token is denied");
        assert!(matches!(
            expired_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer token is outside its validity window")
        ));
    }

    // C1: the locked offer collateral cap must equal the signed quote amount.
    #[test]
    fn accept_fails_closed_when_liability_cap_differs_from_quote() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        // Cap 5000 over a 4200 quote. The reservation covers the cap, currencies
        // all match, so only the cap-vs-quote binding can fire.
        let token = token_offer(&issuer, &acceptor, 5000, "USD");
        let context = order_context("fulfillment_attested");
        assert_eq!(context.quote_amount_minor, 4200);
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 5000, "USD", &res_auth);

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("cap that differs from the quote is denied");

        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer liability does not equal the signed quote amount")
        ));
    }

    // TC-4: accept currency mismatches are each denied with their own message.
    #[test]
    fn accept_fails_closed_on_currency_mismatches() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();

        // Liability currency (EUR) != order quote currency (USD).
        let eur_token = token_offer(&issuer, &acceptor, 4200, "EUR");
        let eur_reservation = signed_reservation(&context, &eur_token, 4200, "EUR", &res_auth);
        let liability_error = accept(accept_request(
            &context,
            &eur_token,
            &acceptor,
            &eur_reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("liability currency mismatch is denied");
        assert!(matches!(
            liability_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer liability currency does not match the order quote")
        ));

        // Reservation currency (EUR) != offer liability currency (USD).
        let usd_token = token_offer(&issuer, &acceptor, 4200, "USD");
        let mismatched_reservation =
            signed_reservation(&context, &usd_token, 4200, "EUR", &res_auth);
        let reservation_error = accept(accept_request(
            &context,
            &usd_token,
            &acceptor,
            &mismatched_reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("reservation currency mismatch is denied");
        assert!(matches!(
            reservation_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("reservation currency does not match the offer liability")
        ));
    }

    // TC-1: release against a Matched observation whose amount or currency does
    // not match the locked ledger is denied, and the ledger stays Locked.
    #[test]
    fn release_fails_closed_on_amount_or_currency_mismatch() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("accept locks the ledger");
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);

        let mismatches = [
            MonetaryAmount {
                units: 4201,
                currency: "USD".to_string(),
            },
            MonetaryAmount {
                units: 4199,
                currency: "USD".to_string(),
            },
            MonetaryAmount {
                units: 4200,
                currency: "EUR".to_string(),
            },
        ];
        for amount in mismatches {
            let observation = CapitalExecutionObservation {
                observed_at: 1_700_000_000,
                external_reference_id: "exec-ref-1".to_string(),
                amount,
            };
            let denied = release(
                &acceptance,
                &observation,
                CapitalExecutionReconciledState::Matched,
                OrderState::SettlementObserved,
            )
            .test_expect_err("mismatched observation is denied");
            assert!(matches!(
                denied,
                CommerceOrderError::SettlementFailed(message)
                    if message.contains("observed execution does not match the locked amount")
            ));
            // Custody is never drained: the locked ledger is untouched.
            assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
            assert_eq!(acceptance.ledger.legs.len(), 1);
        }
    }

    // TC-2: accept from a non-assembly state and release from a
    // non-reconciliation state are each denied on the shipped spine.
    #[test]
    fn accept_and_release_fail_closed_on_wrong_lifecycle_state() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let res_auth = reservation_authority();

        // accept from a state the spine does not allow to assemble.
        let non_assembly = order_context("intent_recorded");
        // The reservation binds to the shared order id, so it witnesses both the
        // non-assembly and the fulfillment-attested accepts below.
        let reservation = signed_reservation(&non_assembly, &token, 4200, "USD", &res_auth);
        let accept_error = accept(accept_request(
            &non_assembly,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("accept from a non-assembly state is denied");
        assert!(matches!(
            accept_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("is not a settlement-assembly state")
        ));

        // release from a non-reconciliation prior state.
        let context = order_context("fulfillment_attested");
        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("accept locks the ledger");
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "exec-ref-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };
        let release_error = release(
            &acceptance,
            &observation,
            CapitalExecutionReconciledState::Matched,
            OrderState::IntentRecorded,
        )
        .test_expect_err("release from a non-reconciliation state is denied");
        assert!(matches!(
            release_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("is not a settlement-reconciliation state")
        ));
        // Custody stays locked.
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    }

    // TC-3: token_offer_total_liability fail-closed branches.
    #[test]
    fn token_offer_total_liability_fail_closed_branches() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();

        // Unbounded grant (no cap) is denied.
        let unbounded = token_with_grants(&issuer, &acceptor, vec![grant(None, "USD")]);
        let unbounded_error = token_offer_total_liability(&unbounded)
            .test_expect_err("unbounded liability is denied");
        assert!(matches!(
            unbounded_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("missing max_total_cost")
        ));

        // Mixed currencies across grants is denied.
        let mixed = token_with_grants(
            &issuer,
            &acceptor,
            vec![grant(Some(1000), "USD"), grant(Some(2000), "EUR")],
        );
        let mixed_error = token_offer_total_liability(&mixed)
            .test_expect_err("mixed-currency liability is denied");
        assert!(matches!(
            mixed_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("mix currencies")
        ));

        // Two same-currency grants sum to the combined liability.
        let summed = token_with_grants(
            &issuer,
            &acceptor,
            vec![grant(Some(1000), "USD"), grant(Some(2000), "USD")],
        );
        let liability =
            token_offer_total_liability(&summed).test_expect("summed liability is computed");
        assert_eq!(liability.units, 3000);
        assert_eq!(liability.currency, "USD");

        // A zero-units grant yields a zero liability, which is denied.
        let zero = token_with_grants(&issuer, &acceptor, vec![grant(Some(0), "USD")]);
        let zero_error =
            token_offer_total_liability(&zero).test_expect_err("zero liability is denied");
        assert!(matches!(
            zero_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("offer liability is zero")
        ));
    }

    // TC-5: CommerceSettlementDispatch::validate fail-closed branches.
    #[test]
    fn settlement_dispatch_validate_fail_closed_branches() {
        // Blank required field (psp) is denied.
        let mut blank = dispatch();
        blank.psp = "  ".to_string();
        let blank_error = blank.validate().test_expect_err("blank psp is denied");
        assert!(matches!(
            blank_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("psp must not be empty")
        ));

        // Unsupported status is denied.
        let mut bad_status = dispatch();
        bad_status.status = "bogus".to_string();
        let status_error = bad_status
            .validate()
            .test_expect_err("unsupported status is denied");
        assert!(matches!(
            status_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("unsupported escrow settlement status")
        ));
    }

    // ESCROW-2: a tampered (unverifiable) reservation witness is denied; a bare
    // fabricated amount can never lock custody.
    #[test]
    fn accept_fails_closed_on_unsigned_reservation_witness() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        // Validly sign, then tamper the witnessed amount so the signature no
        // longer matches the body.
        let mut reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);
        reservation.body.reserved_amount.units = 1;

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("tampered reservation witness is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("reservation receipt signature is invalid")
        ));
    }

    // ESCROW-2: a reservation witnessed for a DIFFERENT order cannot lock this
    // order's custody, even when signed by the expected authority.
    #[test]
    fn accept_fails_closed_on_reservation_bound_to_wrong_order() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let mut reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);
        // Re-bind the witness to a foreign order and re-sign it: structurally
        // valid, correctly signed, but bound to the wrong order.
        reservation.body.order_id = "order-commerce-other".to_string();
        let reservation = SignedExportEnvelope::sign(reservation.body, &reservation_authority())
            .test_expect("re-sign reservation");

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("reservation bound to the wrong order is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("reservation receipt is not bound to this order")
        ));
    }

    // ESCROW-2: a reservation signed by an authority OTHER than the expected
    // settlement reservation authority is denied.
    #[test]
    fn accept_fails_closed_on_reservation_from_unexpected_authority() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        // Sign the witness with a rogue key, but tell accept to expect the
        // pinned reservation authority.
        let rogue = keypair(11);
        let reservation = signed_reservation(&context, &token, 4200, "USD", &rogue);

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            reservation_authority().public_key(),
            &authority,
        ))
        .test_expect_err("reservation from an unexpected authority is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("not signed by the expected")
        ));
    }
}
