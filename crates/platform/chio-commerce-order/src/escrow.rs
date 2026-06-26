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
//! Two fail-closed seams hold:
//!
//! - The reservation must fully collateralize the offer liability and the
//!   acceptor must be the offer subject, or [`accept`] denies.
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
    /// The funds the reservation has locked for this offer.
    pub reserved_amount: &'a MonetaryAmount,
    /// The depositor (buyer) custodial account debited by the lock leg.
    pub depositor_account: String,
    /// The beneficiary (merchant) account credited by the release leg.
    pub beneficiary_account: String,
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
/// - the reservation under-collateralizes the offer liability;
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

    let liability = token_offer_total_liability(request.token_offer)?;

    // Fail closed: only the offer subject may accept.
    if *request.acceptor != request.token_offer.subject {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: acceptor is not the offer subject".to_string(),
        ));
    }

    // Fail closed: the reservation must fully collateralize the offer liability
    // in the order's currency.
    if liability.currency != request.order_context.quote_currency {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: offer liability currency does not match the order quote"
                .to_string(),
        ));
    }
    if request.reserved_amount.currency != liability.currency {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: reservation currency does not match the offer liability"
                .to_string(),
        ));
    }
    if request.reserved_amount.units < liability.units {
        return Err(CommerceOrderError::SettlementFailed(
            "escrow accept denied: reservation under-collateralizes the offer liability"
                .to_string(),
        ));
    }

    // Single-ledger custodial escrow: the lock leg debits the depositor (buyer)
    // and credits the custody account. Seam A is enforced inside `lock`.
    let ledger = CommerceEscrowLedger::lock(
        request.order_context.order_id.clone(),
        liability.currency.clone(),
        request.depositor_account.clone(),
        request.beneficiary_account.clone(),
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

    fn accept_request<'a>(
        context: &'a CommerceOrderContext,
        token: &'a CapabilityToken,
        acceptor: &'a PublicKey,
        reservation: &'a MonetaryAmount,
        authority: &'a Keypair,
        depositor: &str,
        beneficiary: &str,
    ) -> CommerceEscrowAcceptRequest<'a> {
        CommerceEscrowAcceptRequest {
            order_context: context,
            token_offer: token,
            acceptor,
            reserved_amount: reservation,
            depositor_account: depositor.to_string(),
            beneficiary_account: beneficiary.to_string(),
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
        let reservation = reserved(4200, "USD");

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            &authority,
            "buyer:alice",
            "merchant:stripe:coffee-shop",
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
        let reservation = reserved(4199, "USD");

        let error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            &authority,
            "buyer:alice",
            "merchant:stripe:coffee-shop",
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
        let reservation = reserved(4200, "USD");

        let error = accept(accept_request(
            &context,
            &token,
            &wrong_acceptor,
            &reservation,
            &authority,
            "buyer:alice",
            "merchant:stripe:coffee-shop",
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
        let reservation = reserved(4200, "USD");

        let acceptance = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            &authority,
            "buyer:alice",
            "merchant:stripe:coffee-shop",
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
        let context = order_context("fulfillment_attested");
        let reservation = reserved(4200, "USD");
        let pool_id = "freetier:global:2026-06";
        assert!(is_freetier_global_pool_id(pool_id));

        // Debit direction: depositor is a freetier:global pool row.
        let debit_error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            &authority,
            pool_id,
            "merchant:stripe:coffee-shop",
        ))
        .test_expect_err("escrow may not debit a freetier:global pool row");
        assert!(matches!(
            debit_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("isolation violation") && message.contains(pool_id)
        ));

        // Credit direction: beneficiary is a freetier:global pool row.
        let credit_error = accept(accept_request(
            &context,
            &token,
            &acceptor,
            &reservation,
            &authority,
            "buyer:alice",
            pool_id,
        ))
        .test_expect_err("escrow may not credit a freetier:global pool row");
        assert!(matches!(
            credit_error,
            CommerceOrderError::SettlementFailed(message)
                if message.contains("isolation violation") && message.contains(pool_id)
        ));
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
}
