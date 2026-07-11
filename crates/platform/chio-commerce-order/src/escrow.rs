//! Custodial offer-safety escrow wired into the commerce-order spine.
//!
//! This module binds the single-ledger custodial escrow to the shipped
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
//!   its signature verifies against a member of the pinned trusted settlement
//!   reservation-authority set (sourced from verified launch config, never from
//!   the receipt under verification), and it is bound to this order id and the
//!   exact offer token (token id plus
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
//! - Pool isolation: the freetier:global Sybil-ceiling pool ledger and the
//!   escrow ledger are hard-isolated. No escrow leg, in either direction, may name a
//!   `freetier:global:<window>` row (see [`is_freetier_global_pool_id`]).
//!
//! In the tokenless launch phase the on-chain value leg never moves: [`accept`]
//! returns a PREPARE-ONLY [`EscrowBroadcastIntent`]. The on-chain value move is
//! deferred to a later phase and reuses the chio-settle prepare path
//! (`prepare_web3_escrow_dispatch`).

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
/// freetier:global pool.
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
    /// freetier:global pool row or if conservation does not hold.
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
    pub(crate) fn assert_conservation(&self) -> Result<(), CommerceOrderError> {
        // Bind the leg set to the DECLARED parties and lifecycle status. Net
        // balance alone (zero net flow, custody not overdrawn) accepts ANY
        // net-balanced leg set, so a forged ledger funded by a DIFFERENT account
        // than the declared depositor, or paying a different beneficiary, could
        // net-balance and pass both `release` and `verify_escrow_digest`. Require
        // the legs to be EXACTLY the canonical lock (and, for Released, release)
        // legs over this ledger's depositor -> custody -> beneficiary accounts and
        // locked amount, the same legs `lock`/`released` emit. A leg with the wrong
        // kind, endpoints, or amount is denied here, before conservation is even
        // measured.
        let lock_leg = CommerceEscrowLeg {
            kind: CommerceEscrowLegKind::Lock,
            from_account: self.depositor_account.clone(),
            to_account: self.custody_account.clone(),
            amount_minor: self.amount_minor,
        };
        let expected_legs = match self.status {
            CommerceEscrowStatus::Locked => vec![lock_leg],
            CommerceEscrowStatus::Released => vec![
                lock_leg,
                CommerceEscrowLeg {
                    kind: CommerceEscrowLegKind::Release,
                    from_account: self.custody_account.clone(),
                    to_account: self.beneficiary_account.clone(),
                    amount_minor: self.amount_minor,
                },
            ],
        };
        if self.legs != expected_legs {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow ledger legs do not match the canonical lock/release shape for the \
                 declared depositor/custody/beneficiary accounts and amount"
                    .to_string(),
            ));
        }

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

    /// sha256 hex over the canonical JSON of the ledger. This is the CANONICAL
    /// digest the accept/release path pins into the order context, so callers
    /// proving a pinned `escrow_digest` MUST recompute against this (never against
    /// a raw-wire-byte hash, which would admit a non-canonical encoding).
    pub(crate) fn digest(&self) -> Result<String, CommerceOrderError> {
        let canonical = chio_core_types::canonical_json_bytes(self).map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "escrow ledger canonicalization failed: {error}"
            ))
        })?;
        Ok(sha256_hex(&canonical))
    }
}

/// Pool isolation: the custodial escrow ledger and the freetier:global
/// Sybil-ceiling pool ledger are hard-isolated. No escrow leg, in either direction, may name
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
        // Accept-time binding: the escrow accept only advances the order to
        // `settlement_packet_assembled` and locks custody prepare-only. The
        // emitted packet therefore MUST declare the dispatched/assembled status;
        // the final `reconciled`/`settled` statuses belong to the reconciliation
        // path (see `release`) and would otherwise let a merely-locked escrow sign
        // a packet claiming final settlement. Fail closed on any other status.
        if self.status.as_str() != "dispatched" {
            return Err(CommerceOrderError::SettlementFailed(format!(
                "escrow accept settlement status must be `dispatched`; final \
                 statuses are reserved for the reconciliation path: {}",
                self.status
            )));
        }
        // Parse `issued_at` as an RFC3339 UTC timestamp HERE, before `accept`
        // signs the packet and locks custody. The standard `validate_settlement_packet`
        // path (the verifier replay) parses `issued_at` the same way and would
        // otherwise reject the packet a merely-non-empty timestamp produced, so a
        // malformed timestamp could lock custody and pin a context digest for a
        // settlement artifact that can never verify. Fail closed on a malformed
        // timestamp so the accept and the later verifier agree.
        super::validation::parse_rfc3339_utc(&self.issued_at, "escrow settlement issued_at")
            .map_err(|_| {
                CommerceOrderError::SettlementFailed(format!(
                    "escrow accept settlement issued_at must be an RFC3339 UTC timestamp: {}",
                    self.issued_at
                ))
            })?;
        Ok(())
    }
}

/// PREPARE-ONLY broadcast intent. In the tokenless launch phase no value moves
/// on-chain; the on-chain value move is deferred to a later phase and reuses
/// the chio-settle prepare path.
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
    /// Verify a signed reservation receipt against the pinned set of trusted
    /// settlement reservation authorities and bind it to the order and offer
    /// token.
    ///
    /// `trusted_reservation_authorities` MUST be sourced from verified, externally
    /// pinned launch config (the RR2-TM-01 market-authority registry), NEVER
    /// derived from the receipt under verification. Deriving the expected signer
    /// from a request field the caller controls (e.g. echoing back the receipt's
    /// own `signer_key`) would let a holder self-sign a reservation receipt and
    /// name their own key as the authority, so the witness would prove nothing.
    ///
    /// Fails closed when the receipt schema is unsupported, the receipt id is
    /// empty, the trusted-authority set is empty, the signer is not a member of
    /// the trusted-authority set, the signature does not verify, the receipt is
    /// not bound to this order id, the receipt is not bound to this offer token id
    /// or canonical digest, or the witnessed amount is zero.
    pub fn from_signed(
        receipt: &SignedCommerceReservationReceipt,
        trusted_reservation_authorities: &[PublicKey],
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
        // Settlement-authority binding: the witness MUST be signed by a member of
        // the pinned trusted reservation-authority set, and the signature MUST
        // verify over the body. Fail closed on an empty pinned set: with no
        // trusted authority pinned there is no party whose witness can be
        // trusted, so a caller cannot bypass the binding by supplying nothing.
        if trusted_reservation_authorities.is_empty() {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: no trusted settlement reservation authority is pinned; \
                 pin the RR2-TM-01 registry authority set before locking custody"
                    .to_string(),
            ));
        }
        if !trusted_reservation_authorities.contains(&receipt.signer_key) {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow accept denied: reservation receipt is not signed by a pinned trusted \
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
    /// The pinned set of trusted settlement reservation-authority keys the
    /// reservation witness MUST be signed by. This MUST be sourced from verified,
    /// externally pinned launch config (the RR2-TM-01 market-authority registry),
    /// NEVER from the receipt under verification: a caller cannot satisfy the
    /// binding by signing a receipt with their own key and naming that same key
    /// here, because their key is not a member of the registry-pinned set. Fail
    /// closed on an empty set.
    pub trusted_reservation_authorities: Vec<PublicKey>,
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
/// - the reservation witness is not signed by a member of the pinned trusted
///   settlement reservation-authority set, or is not bound to this order id and
///   offer token;
/// - the reservation under-collateralizes the offer liability;
/// - the locked offer liability does not equal the signed quote amount;
/// - the acceptor is not the offer subject;
/// - the order context's current state is not a settlement-assembly state;
/// - any escrow account is a freetier:global pool row.
///
/// On success it performs the single-ledger atomic two-leg swap (lock leg),
/// emits the [`CommerceSettlementPacket`] signed body, derives a PREPARE-ONLY
/// broadcast intent (no value moves on-chain at launch), and returns the order
/// context advanced to `settlement_packet_assembled` with the escrow digest
/// pinned.
///
/// Authentication boundary: `order_context.buyer_subject` and
/// `merchant_subject` are structurally validated at this boundary, not
/// authenticated; the signed reservation witness binds order id, offer token,
/// and amount, not the party identities. Custody integrity still closes
/// because the escrow ledger binds the exact leg endpoints and its digest is
/// pinned into the signed passport, which `verify_commerce_order` recomputes.
/// Before any caller moves real value through this path, the order context
/// itself must be authenticated, or the buyer/merchant identities bound into
/// the reservation witness.
pub fn accept(
    request: CommerceEscrowAcceptRequest<'_>,
) -> Result<CommerceEscrowAcceptance, CommerceOrderError> {
    request.order_context.validate_shape()?;

    // Recompute and compare the canonical quote digest BEFORE building
    // the ledger or locking custody. `validate_shape` only proves `quote_sha256` is
    // a well-formed 64-hex string, NOT that it matches the canonical quote fields.
    // Without this gate an arbitrary same-shape `quote_sha256` passes accept, locks
    // custody, and signs a settlement packet, only for `verify_commerce_order` to
    // later recompute the quote digest and reject the bundle, leaving custody locked
    // for an unverifiable quote. Fail closed here so an unverifiable quote can never
    // lock custody.
    super::verify_quote_digest(request.order_context)?;

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

    // Authenticate the offered capability token BEFORE deriving any
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

    // The reservation is a SIGNED witness, never a bare amount. Verify
    // it against the pinned settlement reservation authority and bind it to this
    // order id and the exact offer token BEFORE any collateral is trusted. A
    // fabricated amount cannot satisfy this; only an authority-signed witness
    // minted for THIS order/offer can. Compose with the offer-token
    // authentication above.
    let reservation = VerifiedCommerceReservation::from_signed(
        request.reservation,
        &request.trusted_reservation_authorities,
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
    // The amount locked in custody is the offer collateral cap
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

    // Bind the custodial accounts to the actual order parties. The
    // depositor (buyer) and beneficiary (merchant) accounts are NOT
    // caller-supplied; they are derived from the order context's verified
    // `buyer_subject` / `merchant_subject`. A caller can therefore never redirect
    // custody to a third account while the settlement packet still names the
    // order merchant. `validate_shape` above already proved both are non-empty.
    let depositor_account = request.order_context.buyer_subject.clone();
    let beneficiary_account = request.order_context.merchant_subject.clone();

    // Single-ledger custodial escrow: the lock leg debits the depositor (buyer)
    // and credits the custody account. Pool isolation is enforced inside `lock`.
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

    // Bind the emitted settlement packet to the context digest. The packet body
    // is built from the dispatch fields, so its canonical digest need not equal
    // the inbound `settlement_packet_sha256` placeholder. Pin the advanced
    // context's `settlement_packet_sha256` to the digest of the packet that was
    // actually signed, so the accepted (context, packet) pair is internally
    // consistent and `verify_commerce_order`'s settlement-packet digest check
    // (which hashes the canonical packet body) passes. Fail closed if the packet
    // cannot be canonicalized.
    let settlement_packet_sha256 = sha256_hex(
        &chio_core_types::canonical_json_bytes(&settlement_packet.body).map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "escrow accept failed to canonicalize the settlement packet: {error}"
            ))
        })?,
    );

    let mut updated_context = request.order_context.clone();
    updated_context.escrow_digest = Some(escrow_digest.clone());
    updated_context.settlement_packet_sha256 = settlement_packet_sha256;
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
/// observation, bound to the SEALED acceptance and the ADVANCED order context.
///
/// `acceptance` is the sealed output of [`accept`]. Because its fields are
/// public, an external caller can fabricate one without going through [`accept`],
/// so release re-derives its bindings rather than trusting them: it recomputes
/// the escrow digest from the ledger, requires the accepted context to carry that
/// pinned digest, and re-verifies the emitted settlement-packet signature.
///
/// `advanced_context` is the SAME order advanced (by the out-of-band dispatch and
/// observe steps) to a settlement-reconciliation predecessor state. The release
/// spine state is derived from `advanced_context.current_state`, never from a
/// caller-supplied argument, and the context MUST name the same order and carry
/// the same pinned escrow digest as the acceptance, so a Matched observation can
/// never be replayed across orders or escrows.
///
/// Fails closed when the acceptance bindings do not re-derive, when the advanced
/// context is not bound to the locked order/escrow, when the reconciled state is
/// not [`CapitalExecutionReconciledState::Matched`], when the advanced context is
/// not a settlement-reconciliation predecessor on the shipped spine, or when the
/// observed execution does not cover exactly the locked amount and currency.
pub fn release(
    acceptance: &CommerceEscrowAcceptance,
    advanced_context: &CommerceOrderContext,
    observation: &CapitalExecutionObservation,
    reconciled_state: CapitalExecutionReconciledState,
) -> Result<CommerceEscrowRelease, CommerceOrderError> {
    // Re-validate the sealed acceptance (the acceptance fields are public, so a
    // forged locked acceptance must not be trusted as settlement authority). The
    // escrow digest MUST re-derive from the ledger, the accepted context MUST be
    // well-shaped and carry that pinned digest, and the emitted settlement packet
    // signature MUST still verify.
    let recomputed_escrow_digest = acceptance.ledger.digest()?;
    if recomputed_escrow_digest != acceptance.escrow_digest {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: acceptance escrow digest does not re-derive from its ledger"
                .to_string(),
        ));
    }
    acceptance.updated_context.validate_shape()?;
    if acceptance.updated_context.escrow_digest.as_deref()
        != Some(acceptance.escrow_digest.as_str())
    {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: accepted context is not bound to the locked escrow digest"
                .to_string(),
        ));
    }

    // Bind the locked LEDGER to the accepted ORDER CONTEXT, not merely its pinned
    // digest. The escrow-digest binding above proves only that the accepted context
    // pins THIS ledger's digest; it does NOT prove the ledger's order id, economics,
    // and parties are the order's. `CommerceEscrowAcceptance` is public, so a forged
    // acceptance could pair a same-value ledger LOCKED FOR A DIFFERENT order or
    // beneficiary with a context that names this order (setting the context's
    // `escrow_digest` to that foreign ledger) and drain the wrong custody. Apply the
    // SAME schema/order/economics/party binding the verifier enforces in
    // `verify_escrow_digest`, via the shared helper, so this class cannot reopen.
    bind_escrow_ledger_to_order_context(&acceptance.ledger, &acceptance.updated_context)?;

    match acceptance.settlement_packet.verify_signature() {
        Ok(true) => {}
        _ => {
            return Err(CommerceOrderError::SettlementFailed(
                "escrow release denied: accepted settlement packet signature is invalid"
                    .to_string(),
            ))
        }
    }

    // Bind the SIGNED settlement packet to the accepted context. A valid signature
    // only proves the packet was signed by SOME settlement authority, not that it
    // belongs to THIS order. `CommerceEscrowAcceptance` is public, so a forged
    // acceptance could pair order A's locked ledger/context with any validly-signed
    // packet for order B and then drain A's custody using B's reconciliation
    // reference (taken from the packet below). Re-check that the packet body's
    // canonical digest equals the digest `accept` pinned into the accepted context
    // AND that the packet names the same order, so the (context, packet) pair is the
    // one accept sealed. Fail closed on either mismatch.
    let accepted_packet_digest = sha256_hex(
        &chio_core_types::canonical_json_bytes(&acceptance.settlement_packet.body).map_err(
            |error| {
                CommerceOrderError::SettlementFailed(format!(
                    "escrow release failed to canonicalize the accepted settlement packet: {error}"
                ))
            },
        )?,
    );
    if accepted_packet_digest != acceptance.updated_context.settlement_packet_sha256 {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: accepted settlement packet digest does not match the accepted \
             context"
                .to_string(),
        ));
    }
    if acceptance.settlement_packet.body.order_id != acceptance.updated_context.order_id {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: accepted settlement packet order does not match the accepted \
             context"
                .to_string(),
        ));
    }

    // Bind the release to the SAME order and escrow the acceptance locked. The
    // advanced context is the order state the dispatch/observe steps produced; it
    // MUST name the same order and carry the same pinned (locked) escrow digest,
    // so an observation reconciled for a DIFFERENT order/escrow cannot drain this
    // custody.
    advanced_context.validate_shape()?;
    if advanced_context.order_id != acceptance.updated_context.order_id {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: release order does not match the locked escrow order"
                .to_string(),
        ));
    }
    if advanced_context.escrow_digest.as_deref() != Some(acceptance.escrow_digest.as_str()) {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: release context is not bound to the locked escrow digest"
                .to_string(),
        ));
    }

    // Fail closed: a custodial release fires ONLY against a capital execution
    // observation reconciled as Matched. Any not-yet-matched state keeps the
    // funds locked.
    if reconciled_state != CapitalExecutionReconciledState::Matched {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: capital execution is not reconciled Matched".to_string(),
        ));
    }

    // Derive the spine prior state from the ADVANCED order context, never a
    // caller-supplied argument. A release driven immediately after accept (the
    // context still at `settlement_packet_assembled`) is rejected here: that is
    // not a settlement-reconciliation transition, so the dispatched/observed
    // steps cannot be skipped while draining custody.
    let prior_state = OrderState::parse(&advanced_context.current_state)?;
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

    // Bind the observed execution to THIS order's reconciliation artifact,
    // not merely its amount/currency. Amount+currency alone cannot tell two
    // same-value payments apart, so a Matched execution belonging to a DIFFERENT
    // payment could otherwise drain this order's custody. The reconciliation ref
    // is taken from the SIGNED settlement packet (its signature was re-verified
    // above), so it is the authenticated reconciliation artifact for this order,
    // not a caller-mutable context field. Fail closed when the observed execution
    // reference does not match it.
    let expected_reconciliation_ref = acceptance
        .settlement_packet
        .body
        .reconciliation_ref
        .as_str();
    if observation.external_reference_id != expected_reconciliation_ref {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow release denied: observed execution reference does not match the order \
             reconciliation ref"
                .to_string(),
        ));
    }

    let ledger = acceptance.ledger.released()?;
    let escrow_digest = ledger.digest()?;

    // Advance the order from the verified ADVANCED context (not the frozen accept
    // context), so the released context reflects the dispatched/observed steps.
    let mut updated_context = advanced_context.clone();
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

/// Bind a custodial escrow ledger to the order context it must back. Shared by
/// the verifier (`verify_escrow_digest`, lib.rs) AND the live custody release
/// (`release`, above) so the binding can NEVER drift between the two paths.
///
/// A digest match plus conservation proves only that SOME conserved escrow ledger
/// exists; it does NOT prove the ledger covers THIS order's quote between THIS
/// order's buyer and merchant. Both `CommerceEscrowAcceptance` and the verifier
/// bundle are public, so a forged caller could otherwise pair a same-value ledger
/// LOCKED FOR A DIFFERENT order/beneficiary with a context that names this order
/// and either drain the wrong custody (release) or vouch for it in a verified
/// passport (verify). Fail closed unless the ledger carries the canonical
/// escrow-ledger schema and its order id, economics (amount and currency), and
/// parties (depositor == order buyer, beneficiary == order merchant) all match the
/// order context exactly. The schema check also rejects a field-matching ledger
/// whose `schema` is not `COMMERCE_ESCROW_LEDGER_SCHEMA_ID`, so a wrong-schema
/// ledger whose canonical digest happens to be pinned cannot ride into a verified
/// passport.
pub(crate) fn bind_escrow_ledger_to_order_context(
    ledger: &CommerceEscrowLedger,
    context: &CommerceOrderContext,
) -> Result<(), CommerceOrderError> {
    if ledger.schema != COMMERCE_ESCROW_LEDGER_SCHEMA_ID {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "escrow ledger",
            message: format!(
                "escrow ledger schema {} is not the canonical commerce escrow-ledger schema {}",
                ledger.schema, COMMERCE_ESCROW_LEDGER_SCHEMA_ID
            ),
        });
    }
    if ledger.order_id != context.order_id {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger order mismatch: ledger {} vs context {}",
                ledger.order_id, context.order_id
            ),
        });
    }
    if ledger.amount_minor != context.quote_amount_minor {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger amount {} does not match the order quote amount {}",
                ledger.amount_minor, context.quote_amount_minor
            ),
        });
    }
    if ledger.currency != context.quote_currency {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger currency {} does not match the order quote currency {}",
                ledger.currency, context.quote_currency
            ),
        });
    }
    if ledger.depositor_account != context.buyer_subject {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger depositor {} does not match the order buyer {}",
                ledger.depositor_account, context.buyer_subject
            ),
        });
    }
    if ledger.beneficiary_account != context.merchant_subject {
        return Err(CommerceOrderError::InvalidArtifact {
            field: "order context",
            message: format!(
                "escrow ledger beneficiary {} does not match the order merchant {}",
                ledger.beneficiary_account, context.merchant_subject
            ),
        });
    }
    Ok(())
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
        let mut context: CommerceOrderContext =
            serde_json::from_value(value).test_expect("order context deserializes");
        pin_quote_digest(&mut context);
        context
    }

    /// Pin the canonical quote digest into a test context. `accept`
    /// recomputes the canonical quote digest and denies a context whose pinned
    /// `quote_sha256` does not match the canonical quote fields, so every test
    /// context must carry the REAL digest (not the HEX64 placeholder), and any test
    /// that mutates a quote-binding field (order_id, merchant_subject, or the quote
    /// amount/currency/id) must re-pin it afterwards.
    fn pin_quote_digest(context: &mut CommerceOrderContext) {
        context.quote_sha256 =
            crate::canonical_quote_sha256(context).test_expect("canonical quote digest");
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

    /// Build the order context advanced (by the out-of-band dispatch/observe
    /// steps) to `state`, carrying the SAME order id and the SAME pinned escrow
    /// digest the accept locked. This is the legitimate input to `release`.
    fn advanced_context(
        acceptance: &CommerceEscrowAcceptance,
        state: &str,
    ) -> CommerceOrderContext {
        let mut context = acceptance.updated_context.clone();
        context.current_state = state.to_string();
        context
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
            trusted_reservation_authorities: vec![reservation_authority],
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
        // PREPARE-ONLY: no value moves on-chain at launch.
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

        // The observed execution reference MUST match the order's reconciliation
        // ref (the signed settlement packet carries `reconciliation-1`).
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "reconciliation-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };

        // The order has been advanced (by the dispatch/observe steps) to the
        // settlement-observed reconciliation predecessor, carrying the same order
        // id and the same pinned escrow digest the accept locked.
        let advanced = advanced_context(&acceptance, "settlement_observed");

        // NotObserved keeps the funds locked.
        let denied = release(
            &acceptance,
            &advanced,
            &observation,
            CapitalExecutionReconciledState::NotObserved,
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
            &advanced,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect("Matched release succeeds");

        assert_eq!(released.ledger.status, CommerceEscrowStatus::Released);
        assert_eq!(released.ledger.legs.len(), 2);
        assert_eq!(released.ledger.legs[1].kind, CommerceEscrowLegKind::Release);
        assert_eq!(
            released.ledger.legs[1].to_account,
            "merchant:stripe:coffee-shop"
        );
        assert_eq!(released.external_reference_id, "reconciliation-1");
        assert_eq!(released.next_state, OrderState::SettlementReconciled);
        assert_eq!(
            released.updated_context.current_state,
            "settlement_reconciled"
        );
    }

    // A Matched observation whose external reference does not
    // match the order's (signed) reconciliation ref is denied before custody is
    // drained, even when its amount and currency match the locked ledger exactly.
    // This stops a same-value execution from a DIFFERENT payment from draining
    // this order's custody.
    #[test]
    fn release_fails_closed_on_reconciliation_reference_mismatch() {
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
        // The signed settlement packet carries the order reconciliation ref.
        assert_eq!(
            acceptance.settlement_packet.body.reconciliation_ref,
            "reconciliation-1"
        );

        // A same-value Matched execution from a DIFFERENT payment: exact amount
        // and currency, but a foreign external reference.
        let foreign_payment = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "reconciliation-other-payment".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };
        let advanced = advanced_context(&acceptance, "settlement_observed");
        let denied = release(
            &acceptance,
            &advanced,
            &foreign_payment,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("a foreign-reference execution is denied");
        assert!(matches!(
            denied,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("reference does not match the order reconciliation ref")
        ));
        // Custody is never drained.
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
        assert_eq!(acceptance.ledger.legs.len(), 1);
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
        // merchant_subject is a quote-binding field; re-pin so the quote-digest gate
        // passes and the accept reaches the pool-isolation check (the actual SUT).
        pin_quote_digest(&mut credit_context);
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

    // The locked ledger's depositor/beneficiary are bound to the order
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
        // merchant_subject is a quote-binding field; re-pin the quote digest.
        pin_quote_digest(&mut context);
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

    // A forged/unsigned offer token is denied before any custodial
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

    // An offer token issued by the acceptor to itself (issuer ==
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

    // An offer token outside its validity window is denied in both
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

    // The locked offer collateral cap must equal the signed quote amount.
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
        let advanced = advanced_context(&acceptance, "settlement_observed");
        for amount in mismatches {
            let observation = CapitalExecutionObservation {
                observed_at: 1_700_000_000,
                external_reference_id: "exec-ref-1".to_string(),
                amount,
            };
            let denied = release(
                &acceptance,
                &advanced,
                &observation,
                CapitalExecutionReconciledState::Matched,
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
        // The advanced context is derived from a non-reconciliation predecessor
        // state, so the release spine check (derived from the context, not a
        // caller argument) denies.
        let advanced = advanced_context(&acceptance, "intent_recorded");
        let release_error = release(
            &acceptance,
            &advanced,
            &observation,
            CapitalExecutionReconciledState::Matched,
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
                if message.contains("settlement status must be `dispatched`")
        ));

        // The final reconciliation statuses are NOT accept-time dispatch statuses.
        for final_status in ["reconciled", "settled"] {
            let mut final_dispatch = dispatch();
            final_dispatch.status = final_status.to_string();
            let final_error = final_dispatch
                .validate()
                .test_expect_err("final settlement status is denied at accept time");
            assert!(matches!(
                final_error,
                CommerceOrderError::SettlementFailed(message)
                    if message.contains("settlement status must be `dispatched`")
            ));
        }

        // A non-RFC3339 issued_at is rejected here, before `accept`
        // signs the packet, so the accept and the later verifier agree.
        let mut bad_timestamp = dispatch();
        bad_timestamp.issued_at = "2026-06-25 00:00:00".to_string();
        let timestamp_error = bad_timestamp
            .validate()
            .test_expect_err("a non-RFC3339 issued_at is denied");
        assert!(matches!(
            timestamp_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("issued_at must be an RFC3339 UTC timestamp")
        ));
    }

    /// `accept` parses the settlement `issued_at` as RFC3339 BEFORE it
    /// signs the packet and locks custody, so a malformed timestamp (which the
    /// standard `validate_settlement_packet` verifier would later reject) can never
    /// lock custody or pin a context digest for an unverifiable settlement artifact.
    #[test]
    fn accept_fails_closed_on_malformed_settlement_issued_at() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let mut request = accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        );
        request.settlement.issued_at = "not-an-rfc3339-timestamp".to_string();
        let denied =
            accept(request).test_expect_err("a malformed issued_at is denied before locking");
        assert!(matches!(
            denied,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("issued_at must be an RFC3339 UTC timestamp")
        ));
    }

    /// A release whose acceptance pairs THIS order's locked
    /// ledger/context with a validly-signed settlement packet from a DIFFERENT
    /// order is denied. The accepted packet's canonical digest no longer matches
    /// the accepted context's pinned `settlement_packet_sha256`, so order B's
    /// reconciliation reference can never drain order A's custody, even though B's
    /// packet signature verifies and B's observation matches the locked amount.
    #[test]
    fn release_fails_closed_on_settlement_packet_from_a_different_order() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let res_auth = reservation_authority();

        // Order A: the order whose custody is locked.
        let context_a = order_context("fulfillment_attested");
        let reservation_a = signed_reservation(&context_a, &token, 4200, "USD", &res_auth);
        let acceptance_a = accept(accept_request(
            &context_a,
            &token,
            &acceptor,
            &reservation_a,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("order A accept locks the ledger");

        // Order B: a DIFFERENT order with its own validly-signed settlement packet.
        let mut context_b = order_context("fulfillment_attested");
        context_b.order_id = "order-commerce-002".to_string();
        // order_id is a quote-binding field; re-pin the quote digest for order B.
        pin_quote_digest(&mut context_b);
        let reservation_b = signed_reservation(&context_b, &token, 4200, "USD", &res_auth);
        let acceptance_b = accept(accept_request(
            &context_b,
            &token,
            &acceptor,
            &reservation_b,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect("order B accept locks its own ledger");
        // The two orders produce DIFFERENT signed packets.
        assert_ne!(
            acceptance_a.updated_context.settlement_packet_sha256,
            acceptance_b.updated_context.settlement_packet_sha256
        );

        // Forge an acceptance: A's sealed ledger/context paired with B's signed
        // packet (the acceptance fields are public, so this needs no authority).
        let mut forged = acceptance_a.clone();
        forged.settlement_packet = acceptance_b.settlement_packet.clone();

        // B's same-value payment observation (B's reconciliation ref).
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: acceptance_b
                .settlement_packet
                .body
                .reconciliation_ref
                .clone(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };
        let advanced = advanced_context(&acceptance_a, "settlement_observed");
        let denied = release(
            &forged,
            &advanced,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("a cross-order settlement packet cannot release this order");
        assert!(matches!(
            denied,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("settlement packet digest does not match the accepted context")
        ));
        // A's custody is never drained.
        assert_eq!(acceptance_a.ledger.status, CommerceEscrowStatus::Locked);
    }

    // A tampered (unverifiable) reservation witness is denied; a bare
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

    // A reservation witnessed for a DIFFERENT order cannot lock this
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

    // A reservation signed by a CALLER-CHOSEN key that is
    // not a member of the pinned trusted reservation-authority set is denied. The
    // expected signer is sourced from the pinned set, NEVER echoed from the
    // receipt, so a holder cannot self-sign a witness and name their own key as
    // the authority.
    #[test]
    fn accept_fails_closed_on_reservation_from_unexpected_authority() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        // Sign the witness with a caller-chosen rogue key, but pin the trusted
        // reservation authority set to the registry authority only.
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
        .test_expect_err("reservation from a non-pinned authority is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("not signed by a pinned trusted")
        ));

        // The footgun the finding closes: the caller cannot pin the rogue key as
        // the trusted authority by echoing the receipt's own signer, because in
        // production the trusted set is the registry-pinned set, not a
        // request-derived key. Here we verify that even a self-consistent
        // rogue-signed receipt is denied when the rogue key is absent from the
        // pinned set.
        let mut self_pinned = accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            // The PINNED set deliberately excludes the rogue signer.
            reservation_authority().public_key(),
            &authority,
        );
        // Sanity: the pinned set is the registry authority, not the rogue key.
        assert!(!self_pinned
            .trusted_reservation_authorities
            .contains(&rogue.public_key()));
        self_pinned.trusted_reservation_authorities = vec![reservation_authority().public_key()];
        let self_error = accept(self_pinned)
            .test_expect_err("rogue-signed receipt is denied off the pinned set");
        assert!(matches!(
            self_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("not signed by a pinned trusted")
        ));
    }

    // An empty pinned trusted reservation-authority set
    // fails closed; with no trusted authority pinned, no witness can lock custody.
    #[test]
    fn accept_fails_closed_on_empty_trusted_reservation_authorities() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        let mut request = accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        );
        request.trusted_reservation_authorities = Vec::new();
        let error = accept(request).test_expect_err("empty pinned trusted-authority set is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("no trusted settlement reservation authority is pinned")
        ));
    }

    /// The emitted settlement packet is bound to the advanced context's
    /// `settlement_packet_sha256`, which is pinned to the canonical digest of the
    /// signed packet body (not the inbound placeholder), so the accepted
    /// (context, packet) pair is internally consistent and verifiable.
    #[test]
    fn accept_binds_settlement_packet_to_context_digest() {
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

        let packet_digest = sha256_hex(
            &chio_core_types::canonical_json_bytes(&acceptance.settlement_packet.body)
                .test_expect("canonical settlement packet"),
        );
        // The advanced context pins the digest of the packet that was actually
        // signed, replacing the inbound placeholder.
        assert_eq!(
            acceptance.updated_context.settlement_packet_sha256,
            packet_digest
        );
        assert_ne!(acceptance.updated_context.settlement_packet_sha256, HEX64);
    }

    /// The accept-time settlement dispatch status is restricted to the
    /// dispatched/assembled state; a packet claiming a final `reconciled` or
    /// `settled` status while the escrow is merely locked is denied.
    #[test]
    fn accept_fails_closed_on_final_settlement_status() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);

        for final_status in ["reconciled", "settled"] {
            let mut request = accept_request(
                &context,
                &token,
                &acceptor,
                &reservation,
                res_auth.public_key(),
                &authority,
            );
            request.settlement.status = final_status.to_string();
            let error = accept(request).test_expect_err("final settlement status is denied");
            assert!(matches!(
                error,
                CommerceOrderError::SettlementFailed(message)
                    if message.contains("settlement status must be `dispatched`")
            ));
        }
    }

    /// Release derives the spine prior state from the ADVANCED order
    /// context, never a caller-supplied argument. A release driven immediately
    /// after accept (the context still at `settlement_packet_assembled`) is
    /// denied even with a Matched observation, so the dispatched/observed steps
    /// cannot be skipped while draining custody.
    #[test]
    fn release_fails_closed_when_context_not_advanced_past_assembly() {
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

        // The accept-frozen context is still at settlement_packet_assembled.
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "exec-ref-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };
        let denied = release(
            &acceptance,
            &acceptance.updated_context,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("release on an un-advanced context is denied");
        assert!(matches!(
            denied,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("is not a settlement-reconciliation state")
        ));
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    }

    /// A Matched observation cannot be replayed across orders or escrows.
    /// A release whose advanced context names a DIFFERENT order, or carries a
    /// DIFFERENT pinned escrow digest, is denied before custody is drained.
    #[test]
    fn release_fails_closed_on_cross_order_observation_reuse() {
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

        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "exec-ref-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };

        // A Matched observation routed through a DIFFERENT order's context.
        let mut wrong_order = advanced_context(&acceptance, "settlement_observed");
        wrong_order.order_id = "order-commerce-foreign".to_string();
        let denied_order = release(
            &acceptance,
            &wrong_order,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("cross-order release is denied");
        assert!(matches!(
            denied_order,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("release order does not match the locked escrow order")
        ));

        // A Matched observation routed through a context pinned to a DIFFERENT
        // escrow digest.
        let mut wrong_escrow = advanced_context(&acceptance, "settlement_observed");
        wrong_escrow.escrow_digest = Some(HEX64.to_string());
        let denied_escrow = release(
            &acceptance,
            &wrong_escrow,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("cross-escrow release is denied");
        assert!(matches!(
            denied_escrow,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("release context is not bound to the locked escrow digest")
        ));

        // Custody is never drained across either denial.
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    }

    /// A forged locked acceptance (its fields are public) cannot produce a
    /// released ledger. Release re-derives the escrow digest from the ledger and
    /// re-verifies the settlement-packet signature, denying a tampered digest or
    /// an unsigned/forged packet.
    #[test]
    fn release_fails_closed_on_forged_acceptance() {
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
        let advanced = advanced_context(&acceptance, "settlement_observed");
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "exec-ref-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };

        // Tamper the pinned escrow digest so it no longer re-derives from the
        // ledger.
        let mut forged_digest = acceptance.clone();
        forged_digest.escrow_digest = HEX64.to_string();
        let denied_digest = release(
            &forged_digest,
            &advanced,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("forged escrow digest is denied");
        assert!(matches!(
            denied_digest,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("does not re-derive from its ledger")
        ));

        // Tamper the emitted settlement packet body so its signature no longer
        // verifies.
        let mut forged_packet = acceptance.clone();
        forged_packet.settlement_packet.body.amount_minor += 1;
        let denied_packet = release(
            &forged_packet,
            &advanced,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("forged settlement packet is denied");
        assert!(matches!(
            denied_packet,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("settlement packet signature is invalid")
        ));

        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    }

    /// A forged acceptance whose LEDGER is locked for a
    /// DIFFERENT order or beneficiary (but the same value) than the accepted ORDER
    /// CONTEXT is denied. The escrow-digest binding alone proves only that the
    /// context pins THIS ledger's digest; without binding the ledger's order id and
    /// parties to the context, a public-field forge could pair a same-value ledger
    /// locked for order B (or one paying a foreign beneficiary) with a context
    /// naming order A and drain the wrong custody. The shared ledger<->context
    /// binding denies both.
    #[test]
    fn release_fails_closed_on_ledger_bound_to_a_different_order_or_beneficiary() {
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
        let advanced = advanced_context(&acceptance, "settlement_observed");
        // The observation matches the locked amount/currency and the order's
        // reconciliation ref, so it would drain custody if the ledger binding were
        // missing.
        let observation = CapitalExecutionObservation {
            observed_at: 1_700_000_000,
            external_reference_id: "reconciliation-1".to_string(),
            amount: MonetaryAmount {
                units: 4200,
                currency: "USD".to_string(),
            },
        };

        // (a) A same-value ledger locked for a DIFFERENT order. Re-pin the forged
        // acceptance's escrow digest and both contexts to that foreign ledger so
        // every digest-binding check the release performs still passes; only the
        // new ledger<->context order binding can fire.
        let foreign_order_ledger = CommerceEscrowLedger {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id: "order-commerce-foreign".to_string(),
            currency: "USD".to_string(),
            depositor_account: "buyer:alice".to_string(),
            beneficiary_account: acceptance.updated_context.merchant_subject.clone(),
            custody_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor: 4200,
            legs: vec![CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Lock,
                from_account: "buyer:alice".to_string(),
                to_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
                amount_minor: 4200,
            }],
            status: CommerceEscrowStatus::Locked,
        };
        let foreign_digest = foreign_order_ledger
            .digest()
            .test_expect("foreign ledger digest");
        let mut forged_order = acceptance.clone();
        forged_order.ledger = foreign_order_ledger;
        forged_order.escrow_digest = foreign_digest.clone();
        forged_order.updated_context.escrow_digest = Some(foreign_digest.clone());
        let mut advanced_order = advanced.clone();
        advanced_order.escrow_digest = Some(foreign_digest);
        let denied_order = release(
            &forged_order,
            &advanced_order,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("a ledger locked for a different order is denied");
        assert!(matches!(
            denied_order,
            CommerceOrderError::InvalidArtifact { message, .. }
                if message.contains("escrow ledger order mismatch")
        ));

        // (b) Same order id, but the ledger pays a FOREIGN beneficiary (not the
        // order merchant): the party binding fires.
        let foreign_beneficiary_ledger = CommerceEscrowLedger {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id: acceptance.updated_context.order_id.clone(),
            currency: "USD".to_string(),
            depositor_account: "buyer:alice".to_string(),
            beneficiary_account: "merchant:attacker".to_string(),
            custody_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor: 4200,
            legs: vec![CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Lock,
                from_account: "buyer:alice".to_string(),
                to_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
                amount_minor: 4200,
            }],
            status: CommerceEscrowStatus::Locked,
        };
        let foreign_beneficiary_digest = foreign_beneficiary_ledger
            .digest()
            .test_expect("foreign beneficiary ledger digest");
        let mut forged_beneficiary = acceptance.clone();
        forged_beneficiary.ledger = foreign_beneficiary_ledger;
        forged_beneficiary.escrow_digest = foreign_beneficiary_digest.clone();
        forged_beneficiary.updated_context.escrow_digest = Some(foreign_beneficiary_digest.clone());
        let mut advanced_beneficiary = advanced.clone();
        advanced_beneficiary.escrow_digest = Some(foreign_beneficiary_digest);
        let denied_beneficiary = release(
            &forged_beneficiary,
            &advanced_beneficiary,
            &observation,
            CapitalExecutionReconciledState::Matched,
        )
        .test_expect_err("a ledger paying a foreign beneficiary is denied");
        assert!(matches!(
            denied_beneficiary,
            CommerceOrderError::InvalidArtifact { message, .. }
                if message.contains("beneficiary")
                    && message.contains("does not match the order merchant")
        ));

        // Custody is never drained across either denial.
        assert_eq!(acceptance.ledger.status, CommerceEscrowStatus::Locked);
    }

    /// A net-balanced ledger whose lock leg is funded by a DIFFERENT
    /// account than the declared depositor is denied. Conservation alone (net flow
    /// zero, custody holds the full amount) would accept it; binding the leg KINDS,
    /// ENDPOINTS, and AMOUNTS to the declared depositor/custody/beneficiary catches
    /// the forgery before it can pass `release` or `verify_escrow_digest`.
    #[test]
    fn assert_conservation_denies_legs_with_wrong_endpoints() {
        // A Locked ledger whose lock leg is funded by `attacker:eve` (not the
        // declared `buyer:alice`). Net flow is zero and custody holds the full
        // amount, so the pre-existing conservation checks pass.
        let forged_lock = CommerceEscrowLedger {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id: "order-1".to_string(),
            currency: "USD".to_string(),
            depositor_account: "buyer:alice".to_string(),
            beneficiary_account: "merchant:bob".to_string(),
            custody_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor: 4200,
            legs: vec![CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Lock,
                from_account: "attacker:eve".to_string(),
                to_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
                amount_minor: 4200,
            }],
            status: CommerceEscrowStatus::Locked,
        };
        let error = forged_lock
            .assert_conservation()
            .test_expect_err("a lock leg funded by the wrong account is denied");
        assert!(matches!(
            error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("do not match the canonical lock/release shape")
        ));

        // A Released ledger whose release leg pays `merchant:attacker` while custody
        // is drained from a third account: still net-balanced, but the endpoints do
        // not match the declared depositor/custody/beneficiary.
        let forged_release = CommerceEscrowLedger {
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            order_id: "order-1".to_string(),
            currency: "USD".to_string(),
            depositor_account: "buyer:alice".to_string(),
            beneficiary_account: "merchant:bob".to_string(),
            custody_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
            amount_minor: 4200,
            legs: vec![
                CommerceEscrowLeg {
                    kind: CommerceEscrowLegKind::Lock,
                    from_account: "buyer:alice".to_string(),
                    to_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
                    amount_minor: 4200,
                },
                CommerceEscrowLeg {
                    kind: CommerceEscrowLegKind::Release,
                    from_account: ESCROW_CUSTODY_ACCOUNT.to_string(),
                    to_account: "merchant:attacker".to_string(),
                    amount_minor: 4200,
                },
            ],
            status: CommerceEscrowStatus::Released,
        };
        let release_error = forged_release
            .assert_conservation()
            .test_expect_err("a release leg paying the wrong beneficiary is denied");
        assert!(matches!(
            release_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("do not match the canonical lock/release shape")
        ));
    }

    /// `accept` recomputes the canonical quote digest and denies a
    /// context whose pinned `quote_sha256` does not match the canonical quote fields
    /// BEFORE it builds the ledger or locks custody, so an unverifiable quote (which
    /// `verify_commerce_order` would later reject) can never lock custody or sign a
    /// settlement packet.
    #[test]
    fn accept_fails_closed_on_quote_digest_mismatch() {
        let issuer = keypair(1);
        let subject = keypair(2);
        let acceptor = subject.public_key();
        let authority = keypair(7);
        let token = token_offer(&issuer, &acceptor, 4200, "USD");
        let mut context = order_context("fulfillment_attested");
        let res_auth = reservation_authority();
        let reservation = signed_reservation(&context, &token, 4200, "USD", &res_auth);
        // Overwrite the pinned canonical digest with an arbitrary 64-hex that does
        // NOT match the canonical quote fields (it is still a well-formed sha256, so
        // `validate_shape` passes and only the new quote-digest gate can fire).
        context.quote_sha256 = HEX64.to_string();

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            res_auth.public_key(),
            &authority,
        ))
        .test_expect_err("a non-matching quote_sha256 is denied before locking");
        assert!(matches!(
            error,
            CommerceOrderError::InvalidArtifact { message, .. }
                if message.contains("quote digest mismatch")
        ));
    }
}
