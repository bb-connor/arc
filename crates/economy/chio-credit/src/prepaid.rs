//! Escrow-socketed closed-loop prepaid credit VIEW (M2-17).
//!
//! A user may prepay funds into the existing immutable [`ChioEscrow`] by
//! creating an escrow deposit (the depositor is the original funder). Those
//! prepaid funds become a CLOSED-LOOP prepaid credit balance: spendable only
//! within Chio (first-party-only, via the escrow's release-with-proof path to a
//! Chio first-party beneficiary), non-transferable to any third party, and
//! refundable to the ORIGINAL funder only after the deadline.
//!
//! This module realizes that prepaid balance as a READ-ONLY off-chain
//! projection over the escrow's already-signed on-chain truth, with:
//!
//! - ZERO new immutable contract (the existing `ChioEscrow` is the only
//!   instrument; no `ChioCreditVault`),
//! - ZERO restricted-ERC20 credit token,
//! - ZERO off-TCB ledger.
//!
//! It is the prepaid analogue of the off-chain netting collapse in
//! [`crate::netting`]: the benefit (a spendable, refundable closed-loop credit)
//! is computable off-chain from escrow truth that already exists.
//!
//! # SHIP is gated, not declared
//!
//! This is the VIEW + non-transferability logic only. The SHIP/READY
//! declaration (M2-23) is BLOCKED on a licensed issuer-of-record partner, a
//! MiCA e-money opinion (RG-MICA), and a closed-loop sign-off (RG-CLOSEDLOOP).
//! Every ship-gated support-boundary flag stays default-`false`: there is no
//! live, default-on, transferable, or open-loop path here.
//!
//! # The socket
//!
//! [`EscrowPrepaidSocket`] mirrors `chio_settle::EscrowSnapshot` field-for-field
//! (`funder_address` is the escrow `depositor_address`; `beneficiary_address`,
//! `deadline`, `deposited_minor_units`, `released_minor_units`, `refunded`, and
//! `remaining_minor_units` carry straight through). The projection reads it; it
//! never mutates the socket, mints an IOU, writes a ledger, or flips a flag.
//!
//! # Fail-closed invariants
//!
//! - The prepaid balance is non-transferable: [`ClosedLoopPrepaidView::evaluate_transfer`]
//!   has NO success branch. A transfer to any third party is denied closed; a
//!   transfer even to the original funder is denied closed (returning funds is
//!   only ever the post-deadline refund, never a balance transfer).
//! - The refund target is always the original funder. [`ClosedLoopPrepaidView::evaluate_refund`]
//!   denies any non-funder recipient closed, mirroring the contract's
//!   `refund()` (which pays `escrow.terms.depositor` only, after the deadline).
//! - The currency is pinned USD/USDC; any other settlement currency fails
//!   closed.
//! - Inconsistent escrow balances (released exceeding deposited, or a remaining
//!   that disagrees with `deposited - released`) fail closed rather than
//!   silently overstating spendable credit.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Schema tag for the off-chain closed-loop prepaid-credit projection.
pub const PREPAID_CREDIT_VIEW_SCHEMA: &str = "chio.credit.closed-loop-prepaid-view.v1";

/// Canonical settlement denomination for the closed-loop prepaid view. Prepaid
/// credit, like every Chio IOU, is pinned USD/USDC.
pub const PREPAID_CREDIT_CANONICAL_CURRENCY: &str = "USDC";

fn currency_is_pinned(currency: &str) -> bool {
    currency == "USD" || currency == PREPAID_CREDIT_CANONICAL_CURRENCY
}

/// Reason a closed-loop prepaid projection fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepaidCreditViewError {
    /// A required identity field (escrow id, funder, or beneficiary) was empty
    /// or whitespace-only. The closed loop refuses to project an anonymous
    /// socket.
    EmptyField { field: &'static str },
    /// The settlement currency is not the pinned USD/USDC. The closed loop
    /// refuses to project an unpinned denomination.
    UnsupportedCurrency { currency: String },
    /// The escrow balances are inconsistent: `released` exceeds `deposited`, or
    /// `remaining` does not equal `deposited - released`. The projection
    /// refuses to overstate spendable credit.
    InconsistentBalances {
        deposited_minor_units: u128,
        released_minor_units: u128,
        remaining_minor_units: u128,
    },
}

impl fmt::Display for PrepaidCreditViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField { field } => {
                write!(f, "closed-loop prepaid socket field `{field}` must be non-empty")
            }
            Self::UnsupportedCurrency { currency } => write!(
                f,
                "closed-loop prepaid credit is pinned USD/USDC and rejected currency `{currency}`"
            ),
            Self::InconsistentBalances {
                deposited_minor_units,
                released_minor_units,
                remaining_minor_units,
            } => write!(
                f,
                "closed-loop prepaid socket has inconsistent balances (deposited {deposited_minor_units}, released {released_minor_units}, remaining {remaining_minor_units})"
            ),
        }
    }
}

impl std::error::Error for PrepaidCreditViewError {}

/// Reason a prepaid-balance transfer is denied. The closed-loop prepaid balance
/// is non-transferable, so every transfer evaluation resolves to one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepaidTransferDenied {
    /// A transfer to a third party (any party other than the original funder)
    /// is forbidden: closed-loop prepaid credit is non-transferable.
    ThirdPartyTransferForbidden {
        escrow_id: String,
        requested_target: String,
    },
    /// Even a transfer back to the original funder is forbidden: the balance is
    /// categorically non-transferable. Funds return to the funder only through
    /// the post-deadline refund, never through a balance transfer.
    BalanceNonTransferable { escrow_id: String },
}

impl fmt::Display for PrepaidTransferDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThirdPartyTransferForbidden {
                escrow_id,
                requested_target,
            } => write!(
                f,
                "closed-loop prepaid balance for escrow `{escrow_id}` is non-transferable to third party `{requested_target}`"
            ),
            Self::BalanceNonTransferable { escrow_id } => write!(
                f,
                "closed-loop prepaid balance for escrow `{escrow_id}` is non-transferable; funds return to the funder only via the post-deadline refund"
            ),
        }
    }
}

impl std::error::Error for PrepaidTransferDenied {}

/// Reason a prepaid refund is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepaidRefundDenied {
    /// The requested recipient is not the original funder. The refund target is
    /// always the original funder; a third-party refund is forbidden.
    RefundTargetNotOriginalFunder {
        funder_address: String,
        requested_recipient: String,
    },
    /// The escrow has already been refunded. Mirrors the contract's
    /// `EscrowAlreadyRefunded`.
    AlreadyRefunded { escrow_id: String },
    /// The refund deadline has not yet passed. Mirrors the contract's
    /// `EscrowNotExpired` (`block.timestamp <= deadline`).
    NotYetAvailable { deadline: u64, now: u64 },
    /// Nothing remains to refund (the balance was fully consumed in the closed
    /// loop before the deadline).
    NothingToRefund { escrow_id: String },
}

impl fmt::Display for PrepaidRefundDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefundTargetNotOriginalFunder {
                funder_address,
                requested_recipient,
            } => write!(
                f,
                "closed-loop prepaid refund target must be the original funder `{funder_address}`, not `{requested_recipient}`"
            ),
            Self::AlreadyRefunded { escrow_id } => {
                write!(f, "closed-loop prepaid escrow `{escrow_id}` was already refunded")
            }
            Self::NotYetAvailable { deadline, now } => write!(
                f,
                "closed-loop prepaid refund is not available until after the deadline {deadline} (now {now})"
            ),
            Self::NothingToRefund { escrow_id } => {
                write!(f, "closed-loop prepaid escrow `{escrow_id}` has nothing to refund")
            }
        }
    }
}

impl std::error::Error for PrepaidRefundDenied {}

/// Lifecycle of a closed-loop prepaid balance, mirroring the escrow lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrepaidCreditLifecycle {
    /// Funded and untouched: deposited, nothing released, not refunded.
    Funded,
    /// Partially consumed in the closed loop: `0 < released < deposited`.
    PartiallyConsumed,
    /// Fully consumed in the closed loop: `released == deposited`.
    Consumed,
    /// Refunded to the original funder after the deadline.
    Refunded,
}

/// Support boundary for the closed-loop prepaid view.
///
/// The first block of markers records the intended closed-loop properties
/// (true): the view is a read-only projection, first-party-only, non-transferable,
/// refundable to the original funder only, and currency-pinned. The second block
/// is the DO-NOT-WEAKEN / ship-gated set, every flag default-`false`: no
/// third-party transferability, no open-loop spend, no live/default-on path, no
/// declared SHIP, and no new contract, restricted-ERC20 vault, or off-TCB ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrepaidCreditSupportBoundary {
    pub read_only_projection: bool,
    pub first_party_only: bool,
    pub non_transferable: bool,
    pub refund_to_original_funder_only: bool,
    pub currency_pinned_usd_usdc: bool,
    pub transferable_to_third_party: bool,
    pub open_loop_spend_supported: bool,
    pub default_on: bool,
    pub ship_ready: bool,
    pub new_contract_required: bool,
    pub restricted_erc20_vault_required: bool,
    pub off_tcb_ledger_required: bool,
}

impl Default for PrepaidCreditSupportBoundary {
    fn default() -> Self {
        Self {
            read_only_projection: true,
            first_party_only: true,
            non_transferable: true,
            refund_to_original_funder_only: true,
            currency_pinned_usd_usdc: true,
            transferable_to_third_party: false,
            open_loop_spend_supported: false,
            default_on: false,
            ship_ready: false,
            new_contract_required: false,
            restricted_erc20_vault_required: false,
            off_tcb_ledger_required: false,
        }
    }
}

/// Read-only socket onto an existing escrow deposit. Mirrors
/// `chio_settle::EscrowSnapshot` field-for-field; `funder_address` is the escrow
/// `depositor_address` (the original funder), the only refund target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EscrowPrepaidSocket {
    pub escrow_id: String,
    pub funder_address: String,
    pub beneficiary_address: String,
    pub currency: String,
    pub deadline: u64,
    pub deposited_minor_units: u128,
    pub released_minor_units: u128,
    pub refunded: bool,
    pub remaining_minor_units: u128,
}

/// A read-only off-chain projection of a closed-loop prepaid credit balance
/// socketed to an escrow deposit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClosedLoopPrepaidView {
    pub schema: String,
    pub escrow_id: String,
    /// The original funder (escrow depositor); the only refund target.
    pub funder_address: String,
    /// The Chio first-party beneficiary; the only closed-loop spend target.
    pub beneficiary_address: String,
    pub currency: String,
    pub deadline: u64,
    pub support_boundary: PrepaidCreditSupportBoundary,
    pub lifecycle: PrepaidCreditLifecycle,
    pub deposited_units: u128,
    /// Units already consumed in the closed loop (the escrow released amount).
    pub consumed_units: u128,
    /// Units still spendable within the closed loop (zero once refunded).
    pub prepaid_balance_units: u128,
    /// Units returned to the original funder by a refund (zero unless refunded).
    pub refunded_to_funder_units: u128,
    pub refunded: bool,
}

impl ClosedLoopPrepaidView {
    /// The only refund target: the original funder.
    #[must_use]
    pub fn refund_target(&self) -> &str {
        &self.funder_address
    }

    /// Evaluate a request to transfer this prepaid balance to `requested_target`.
    ///
    /// Closed-loop prepaid credit is non-transferable, so this has NO success
    /// branch and always fails closed. A third-party target is denied with
    /// [`PrepaidTransferDenied::ThirdPartyTransferForbidden`]; the original
    /// funder is denied with [`PrepaidTransferDenied::BalanceNonTransferable`]
    /// (funds return to the funder only through the post-deadline refund).
    ///
    /// # Errors
    ///
    /// Always returns a [`PrepaidTransferDenied`]: the balance is
    /// non-transferable by construction.
    pub fn evaluate_transfer(&self, requested_target: &str) -> Result<(), PrepaidTransferDenied> {
        if requested_target == self.funder_address {
            return Err(PrepaidTransferDenied::BalanceNonTransferable {
                escrow_id: self.escrow_id.clone(),
            });
        }
        Err(PrepaidTransferDenied::ThirdPartyTransferForbidden {
            escrow_id: self.escrow_id.clone(),
            requested_target: requested_target.to_string(),
        })
    }

    /// Evaluate a refund request at time `now` for `requested_recipient`.
    ///
    /// Mirrors the escrow contract's `refund()`: the recipient must be the
    /// original funder, the escrow must not already be refunded, the deadline
    /// must have passed (`now > deadline`), and there must be a non-zero
    /// remaining balance. The recipient check is first so a third-party refund
    /// is denied even after the deadline.
    ///
    /// # Errors
    ///
    /// Returns a [`PrepaidRefundDenied`] when the recipient is not the original
    /// funder, the escrow is already refunded, the deadline has not passed, or
    /// nothing remains to refund.
    pub fn evaluate_refund(
        &self,
        now: u64,
        requested_recipient: &str,
    ) -> Result<PrepaidRefundDisposition, PrepaidRefundDenied> {
        if requested_recipient != self.funder_address {
            return Err(PrepaidRefundDenied::RefundTargetNotOriginalFunder {
                funder_address: self.funder_address.clone(),
                requested_recipient: requested_recipient.to_string(),
            });
        }
        if self.refunded {
            return Err(PrepaidRefundDenied::AlreadyRefunded {
                escrow_id: self.escrow_id.clone(),
            });
        }
        if now <= self.deadline {
            return Err(PrepaidRefundDenied::NotYetAvailable {
                deadline: self.deadline,
                now,
            });
        }
        if self.prepaid_balance_units == 0 {
            return Err(PrepaidRefundDenied::NothingToRefund {
                escrow_id: self.escrow_id.clone(),
            });
        }
        Ok(PrepaidRefundDisposition {
            escrow_id: self.escrow_id.clone(),
            refund_target: self.funder_address.clone(),
            refundable_units: self.prepaid_balance_units,
            available_after: self.deadline,
        })
    }
}

/// The disposition of an available refund: the refundable units returning to the
/// original funder after the deadline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrepaidRefundDisposition {
    pub escrow_id: String,
    /// Always the original funder.
    pub refund_target: String,
    pub refundable_units: u128,
    /// The refund is available strictly after this deadline.
    pub available_after: u64,
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), PrepaidCreditViewError> {
    if value.trim().is_empty() {
        return Err(PrepaidCreditViewError::EmptyField { field });
    }
    Ok(())
}

/// Project a closed-loop prepaid credit view from an escrow deposit socket.
///
/// This is a pure, read-only projection. It validates the socket (non-empty
/// identities, USD/USDC-pinned currency, consistent balances), classifies the
/// lifecycle, and carries the ship-gated support-boundary flags straight off
/// their fail-closed defaults. It does not mutate the socket, mint an IOU, write
/// a ledger, or flip any flag.
///
/// # Errors
///
/// Returns a [`PrepaidCreditViewError`] when an identity field is empty, the
/// currency is not the pinned USD/USDC, or the escrow balances are inconsistent.
pub fn project_closed_loop_prepaid(
    socket: &EscrowPrepaidSocket,
) -> Result<ClosedLoopPrepaidView, PrepaidCreditViewError> {
    require_non_empty(&socket.escrow_id, "escrow_id")?;
    require_non_empty(&socket.funder_address, "funder_address")?;
    require_non_empty(&socket.beneficiary_address, "beneficiary_address")?;

    if !currency_is_pinned(&socket.currency) {
        return Err(PrepaidCreditViewError::UnsupportedCurrency {
            currency: socket.currency.clone(),
        });
    }

    let computed_remaining = socket
        .deposited_minor_units
        .checked_sub(socket.released_minor_units)
        .ok_or(PrepaidCreditViewError::InconsistentBalances {
            deposited_minor_units: socket.deposited_minor_units,
            released_minor_units: socket.released_minor_units,
            remaining_minor_units: socket.remaining_minor_units,
        })?;
    if computed_remaining != socket.remaining_minor_units {
        return Err(PrepaidCreditViewError::InconsistentBalances {
            deposited_minor_units: socket.deposited_minor_units,
            released_minor_units: socket.released_minor_units,
            remaining_minor_units: socket.remaining_minor_units,
        });
    }

    let lifecycle = if socket.refunded {
        PrepaidCreditLifecycle::Refunded
    } else if socket.released_minor_units == 0 {
        PrepaidCreditLifecycle::Funded
    } else if socket.released_minor_units < socket.deposited_minor_units {
        PrepaidCreditLifecycle::PartiallyConsumed
    } else {
        PrepaidCreditLifecycle::Consumed
    };

    // Once refunded, the remaining units have returned to the funder and are no
    // longer spendable in the closed loop.
    let prepaid_balance_units = if socket.refunded {
        0
    } else {
        socket.remaining_minor_units
    };
    let refunded_to_funder_units = if socket.refunded {
        socket.remaining_minor_units
    } else {
        0
    };

    Ok(ClosedLoopPrepaidView {
        schema: PREPAID_CREDIT_VIEW_SCHEMA.to_string(),
        escrow_id: socket.escrow_id.clone(),
        funder_address: socket.funder_address.clone(),
        beneficiary_address: socket.beneficiary_address.clone(),
        currency: socket.currency.clone(),
        deadline: socket.deadline,
        support_boundary: PrepaidCreditSupportBoundary::default(),
        lifecycle,
        deposited_units: socket.deposited_minor_units,
        consumed_units: socket.released_minor_units,
        prepaid_balance_units,
        refunded_to_funder_units,
        refunded: socket.refunded,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod do_not_weaken {
    //! DO-NOT-WEAKEN regression suite (M2-17).
    //!
    //! The closed-loop prepaid view is a projection, not an authority, and its
    //! SHIP declaration (M2-23) is gated. These locks freeze that posture at
    //! the default level: the closed-loop markers stay `true` and every
    //! ship-gated flag stays `false`. A future weakening (flipping a flag to
    //! `true`, declaring SHIP, requiring a new contract / restricted-ERC20
    //! vault / off-TCB ledger, or repointing the currency pin) is caught here.
    use super::*;

    #[test]
    fn prepaid_support_boundary_flags_stay_default_false() {
        let boundary = PrepaidCreditSupportBoundary::default();
        // Ship-gated / DO-NOT-WEAKEN flags all stay false.
        assert!(
            !boundary.transferable_to_third_party,
            "third-party transferability must stay unsupported"
        );
        assert!(
            !boundary.open_loop_spend_supported,
            "open-loop spend must stay unsupported (closed-loop only)"
        );
        assert!(
            !boundary.default_on,
            "the prepaid path must stay default-off (no live/default-on path)"
        );
        assert!(
            !boundary.ship_ready,
            "SHIP must not be declared: M2-23 is gated on a licensed partner + MiCA + closed-loop opinions"
        );
        assert!(
            !boundary.new_contract_required,
            "no new immutable contract is required"
        );
        assert!(
            !boundary.restricted_erc20_vault_required,
            "no restricted-ERC20 ChioCreditVault is required"
        );
        assert!(
            !boundary.off_tcb_ledger_required,
            "no off-TCB ledger is required"
        );
    }

    #[test]
    fn prepaid_support_boundary_closed_loop_markers_stay_true() {
        let boundary = PrepaidCreditSupportBoundary::default();
        assert!(
            boundary.read_only_projection,
            "the view must stay read-only"
        );
        assert!(
            boundary.first_party_only,
            "the prepaid balance must stay first-party-only (closed-loop)"
        );
        assert!(
            boundary.non_transferable,
            "the prepaid balance must stay non-transferable"
        );
        assert!(
            boundary.refund_to_original_funder_only,
            "refunds must stay targeted at the original funder only"
        );
        assert!(
            boundary.currency_pinned_usd_usdc,
            "the prepaid balance must stay pinned USD/USDC"
        );
    }

    #[test]
    fn prepaid_currency_pin_stays_usdc() {
        assert_eq!(
            PREPAID_CREDIT_CANONICAL_CURRENCY, "USDC",
            "the prepaid canonical currency must stay USDC (the USD/USDC pin)"
        );
        assert!(currency_is_pinned("USD"));
        assert!(currency_is_pinned("USDC"));
        assert!(!currency_is_pinned("EUR"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const FUNDER: &str = "0xFunder0000000000000000000000000000000001";
    const BENEFICIARY: &str = "0xChi0FirstParty00000000000000000000000002";
    const THIRD_PARTY: &str = "0xAttacker000000000000000000000000000000003";

    fn socket() -> EscrowPrepaidSocket {
        EscrowPrepaidSocket {
            escrow_id: "escrow-prepaid-001".to_string(),
            funder_address: FUNDER.to_string(),
            beneficiary_address: BENEFICIARY.to_string(),
            currency: "USDC".to_string(),
            deadline: 1_700_000_000,
            deposited_minor_units: 1_000,
            released_minor_units: 0,
            refunded: false,
            remaining_minor_units: 1_000,
        }
    }

    /// The prepaid VIEW is a read-only, first-party-only projection of the
    /// escrow socket.
    #[test]
    fn prepaid_view_is_read_only_and_first_party_only() {
        let socket = socket();
        let view = project_closed_loop_prepaid(&socket).unwrap();

        assert_eq!(view.schema, PREPAID_CREDIT_VIEW_SCHEMA);
        // First-party-only: the spend target is the Chio first-party beneficiary,
        // and the closed-loop markers are set.
        assert_eq!(view.beneficiary_address, BENEFICIARY);
        assert!(view.support_boundary.read_only_projection);
        assert!(view.support_boundary.first_party_only);
        assert!(!view.support_boundary.open_loop_spend_supported);
        // Read-only: the projection reflects the socket without inventing credit.
        assert_eq!(view.deposited_units, 1_000);
        assert_eq!(view.consumed_units, 0);
        assert_eq!(view.prepaid_balance_units, 1_000);
        assert_eq!(view.lifecycle, PrepaidCreditLifecycle::Funded);
    }

    /// The projection never mutates the socket it reads.
    #[test]
    fn prepaid_view_projection_does_not_mutate_socket() {
        let socket = socket();
        let snapshot = socket.clone();
        let _view = project_closed_loop_prepaid(&socket).unwrap();
        assert_eq!(socket, snapshot, "projection must not mutate the socket");
    }

    /// A transfer to a third party is denied fail-closed.
    #[test]
    fn transfer_to_third_party_is_denied_fail_closed() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let denied = view.evaluate_transfer(THIRD_PARTY).unwrap_err();
        assert_eq!(
            denied,
            PrepaidTransferDenied::ThirdPartyTransferForbidden {
                escrow_id: "escrow-prepaid-001".to_string(),
                requested_target: THIRD_PARTY.to_string(),
            }
        );
    }

    /// The balance is non-transferable even back to the original funder: the
    /// only return path is the post-deadline refund.
    #[test]
    fn transfer_even_to_funder_is_denied_balance_non_transferable() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let denied = view.evaluate_transfer(FUNDER).unwrap_err();
        assert_eq!(
            denied,
            PrepaidTransferDenied::BalanceNonTransferable {
                escrow_id: "escrow-prepaid-001".to_string(),
            }
        );
    }

    /// After the deadline the refund target is the original funder.
    #[test]
    fn refund_after_deadline_targets_original_funder() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let after_deadline = view.deadline + 1;
        let disposition = view.evaluate_refund(after_deadline, FUNDER).unwrap();
        assert_eq!(disposition.refund_target, FUNDER);
        assert_eq!(disposition.refundable_units, 1_000);
        assert_eq!(disposition.available_after, view.deadline);
        // The convenience accessor agrees: the refund target is always the funder.
        assert_eq!(view.refund_target(), FUNDER);
    }

    /// A refund to a third party is denied fail-closed, even after the deadline.
    #[test]
    fn refund_to_third_party_is_denied_fail_closed() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let after_deadline = view.deadline + 1;
        let denied = view
            .evaluate_refund(after_deadline, THIRD_PARTY)
            .unwrap_err();
        assert_eq!(
            denied,
            PrepaidRefundDenied::RefundTargetNotOriginalFunder {
                funder_address: FUNDER.to_string(),
                requested_recipient: THIRD_PARTY.to_string(),
            }
        );
    }

    /// Before the deadline the refund is not yet available (mirrors the
    /// contract's `EscrowNotExpired`).
    #[test]
    fn refund_before_deadline_is_denied_not_yet_available() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        // At the deadline (now == deadline) the contract still reverts.
        let denied = view.evaluate_refund(view.deadline, FUNDER).unwrap_err();
        assert_eq!(
            denied,
            PrepaidRefundDenied::NotYetAvailable {
                deadline: view.deadline,
                now: view.deadline,
            }
        );
    }

    /// An already-refunded escrow denies a further refund and shows the funds
    /// returned to the funder (never a third party).
    #[test]
    fn refunded_escrow_returns_units_to_funder_only() {
        let mut socket = socket();
        socket.refunded = true;
        let view = project_closed_loop_prepaid(&socket).unwrap();

        assert_eq!(view.lifecycle, PrepaidCreditLifecycle::Refunded);
        assert_eq!(
            view.prepaid_balance_units, 0,
            "refunded balance is no longer spendable"
        );
        assert_eq!(view.refunded_to_funder_units, 1_000);
        assert_eq!(view.refund_target(), FUNDER);

        let after_deadline = view.deadline + 1;
        let denied = view.evaluate_refund(after_deadline, FUNDER).unwrap_err();
        assert_eq!(
            denied,
            PrepaidRefundDenied::AlreadyRefunded {
                escrow_id: "escrow-prepaid-001".to_string(),
            }
        );
    }

    /// A fully consumed closed-loop balance has nothing to refund.
    #[test]
    fn fully_consumed_balance_has_nothing_to_refund() {
        let mut socket = socket();
        socket.released_minor_units = 1_000;
        socket.remaining_minor_units = 0;
        let view = project_closed_loop_prepaid(&socket).unwrap();

        assert_eq!(view.lifecycle, PrepaidCreditLifecycle::Consumed);
        assert_eq!(view.prepaid_balance_units, 0);

        let after_deadline = view.deadline + 1;
        let denied = view.evaluate_refund(after_deadline, FUNDER).unwrap_err();
        assert_eq!(
            denied,
            PrepaidRefundDenied::NothingToRefund {
                escrow_id: "escrow-prepaid-001".to_string(),
            }
        );
    }

    /// Partial consumption is projected as a partial closed-loop balance.
    #[test]
    fn partial_consumption_is_projected() {
        let mut socket = socket();
        socket.released_minor_units = 400;
        socket.remaining_minor_units = 600;
        let view = project_closed_loop_prepaid(&socket).unwrap();
        assert_eq!(view.lifecycle, PrepaidCreditLifecycle::PartiallyConsumed);
        assert_eq!(view.consumed_units, 400);
        assert_eq!(view.prepaid_balance_units, 600);
    }

    /// Every ship-gated support-boundary flag reads false on a live projection.
    #[test]
    fn prepaid_view_support_boundary_flags_stay_false() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let boundary = &view.support_boundary;
        assert!(!boundary.transferable_to_third_party);
        assert!(!boundary.open_loop_spend_supported);
        assert!(!boundary.default_on);
        assert!(!boundary.ship_ready);
        assert!(!boundary.new_contract_required);
        assert!(!boundary.restricted_erc20_vault_required);
        assert!(!boundary.off_tcb_ledger_required);
        // The view carries the default boundary verbatim.
        assert_eq!(*boundary, PrepaidCreditSupportBoundary::default());
    }

    /// USD socketed credit projects under the USD/USDC pin.
    #[test]
    fn usd_currency_is_pinned_and_projects() {
        let mut socket = socket();
        socket.currency = "USD".to_string();
        let view = project_closed_loop_prepaid(&socket).unwrap();
        assert_eq!(view.currency, "USD");
        assert!(view.support_boundary.currency_pinned_usd_usdc);
    }

    /// A non-pinned currency fails closed.
    #[test]
    fn unsupported_currency_fails_closed() {
        let mut socket = socket();
        socket.currency = "EUR".to_string();
        let error = project_closed_loop_prepaid(&socket).unwrap_err();
        assert_eq!(
            error,
            PrepaidCreditViewError::UnsupportedCurrency {
                currency: "EUR".to_string()
            }
        );
    }

    /// Inconsistent balances (remaining disagrees with deposited - released)
    /// fail closed rather than overstating spendable credit.
    #[test]
    fn inconsistent_remaining_fails_closed() {
        let mut socket = socket();
        socket.released_minor_units = 100;
        socket.remaining_minor_units = 1_000; // should be 900
        let error = project_closed_loop_prepaid(&socket).unwrap_err();
        assert_eq!(
            error,
            PrepaidCreditViewError::InconsistentBalances {
                deposited_minor_units: 1_000,
                released_minor_units: 100,
                remaining_minor_units: 1_000,
            }
        );
    }

    /// Released exceeding deposited fails closed.
    #[test]
    fn released_exceeding_deposited_fails_closed() {
        let mut socket = socket();
        socket.released_minor_units = 2_000;
        socket.remaining_minor_units = 0;
        let error = project_closed_loop_prepaid(&socket).unwrap_err();
        assert_eq!(
            error,
            PrepaidCreditViewError::InconsistentBalances {
                deposited_minor_units: 1_000,
                released_minor_units: 2_000,
                remaining_minor_units: 0,
            }
        );
    }

    /// An empty identity field fails closed.
    #[test]
    fn empty_funder_fails_closed() {
        let mut socket = socket();
        socket.funder_address = "  ".to_string();
        let error = project_closed_loop_prepaid(&socket).unwrap_err();
        assert_eq!(
            error,
            PrepaidCreditViewError::EmptyField {
                field: "funder_address"
            }
        );
    }

    /// The view round-trips through canonical JSON.
    #[test]
    fn prepaid_view_round_trips_through_json() {
        let view = project_closed_loop_prepaid(&socket()).unwrap();
        let encoded = serde_json::to_string(&view).unwrap();
        let decoded: ClosedLoopPrepaidView = serde_json::from_str(&encoded).unwrap();
        assert_eq!(view, decoded);
    }
}
