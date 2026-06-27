//! Off-chain single-denomination netting collapse for the exposure ledger.
//!
//! The token theses claimed that an on-chain credit instrument is required to
//! net per-currency credit exposure into a single denomination and free the
//! capital that per-currency segregation locks up. This module realizes that
//! exact benefit as a READ-ONLY off-chain projection over the already-signed
//! per-currency [`ExposureLedgerCurrencyPosition`] entries, with ZERO on-chain
//! instrument and ZERO new contract. It is the kill-evidence against any
//! on-chain credit token: the single-denomination netting and capital-allocation
//! benefit is computable off-chain from Chio truth that already exists.
//!
//! # Fail-closed invariants
//!
//! The collapse is a projection, not an authority. It does NOT flip any
//! support-boundary flag and does NOT change the prudential per-currency book:
//!
//! - [`ExposureLedgerSupportBoundary::cross_currency_netting_supported`] stays
//!   `false`.
//! - [`CreditScorecardSupportBoundary::capital_allocation_supported`] stays
//!   `false`.
//! - [`CapitalBookSupportBoundary::mixed_currency_netting_supported`] stays
//!   `false`.
//!
//! The netted view carries those three flags straight off the prudential
//! defaults, so any future weakening of a default is visible in the projection
//! (and caught by the regression locks). A missing or zero-denominator FX rate
//! fails closed with an error rather than silently understating exposure.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

use crate::{
    CapitalBookSupportBoundary, CreditScorecardSupportBoundary, ExposureLedgerCurrencyPosition,
    ExposureLedgerReport, ExposureLedgerSupportBoundary,
};

/// Canonical settlement denomination for the netted off-chain view. IOUs are
/// pinned USD/USDC; the collapse projects every position into this single
/// USDC-canonical denomination.
pub const CANONICAL_NETTING_CURRENCY: &str = "USDC";

/// Schema tag for the off-chain netted-view projection.
pub const EXPOSURE_LEDGER_NETTED_VIEW_SCHEMA: &str = "chio.credit.exposure-ledger-netted-view.v1";

/// Reason a single-denomination collapse fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureLedgerNettingError {
    /// No conversion rate into the canonical denomination was supplied for a
    /// non-canonical currency. The collapse refuses to guess a rate.
    MissingRate { currency: String },
    /// A supplied conversion rate had a zero denominator. The collapse refuses
    /// to divide by zero or understate exposure.
    ZeroDenominator { currency: String },
    /// A supplied conversion rate had a zero numerator. A zero numerator maps
    /// every positive exposure to zero canonical units, silently collapsing a
    /// non-canonical position to nothing. The collapse refuses it (fail-closed)
    /// rather than understate the netted view, exactly as it refuses a zero
    /// denominator.
    ZeroNumerator { currency: String },
    /// A conversion into the canonical denomination exceeded `u64::MAX`. The
    /// collapse refuses to cap or saturate the result, because a capped figure
    /// understates outstanding exposure and would publish a lower-than-true
    /// netted view (fail-closed: oversized books surface as an error).
    ConversionOverflow { currency: String },
    /// Summing a single position's unsettled channel (`pending + failed`)
    /// exceeded `u64::MAX`. The per-position capital requirement refuses to cap
    /// the unsettled exposure, because a capped figure understates the
    /// outstanding exposure the collapse and capital view publish.
    UnsettledExposureOverflow { currency: String },
    /// Summing a converted channel across positions into the aggregate canonical
    /// book exceeded `u64::MAX`. The collapse refuses to cap the aggregate,
    /// because a capped figure understates the netted exposure and capital-freed
    /// view (fail-closed: oversized books surface as an error).
    AggregateOverflow { channel: String },
    /// A pinned-parity currency (USD or the canonical USDC denomination) was
    /// supplied an explicit conversion rate that is not one-to-one. The collapse
    /// refuses the override rather than letting it break the USD/USDC pin and
    /// understate the canonical exposure.
    PinnedParityOverride { currency: String },
    /// The exposure ledger supplied more than one position row for the same
    /// currency. The segregated (per-currency) baseline sums each row's worst-case
    /// requirement, so two rows for one currency would inflate the segregated
    /// outstanding above the netted single-position outstanding and advertise a
    /// fictitious capital-freed benefit from positions that are NOT actually
    /// cross-currency. The collapse refuses duplicate-currency rows (fail-closed)
    /// rather than measure a netting benefit the single-denomination book cannot
    /// produce; callers must aggregate a currency's positions into one row first.
    DuplicateCurrency { currency: String },
}

impl fmt::Display for ExposureLedgerNettingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRate { currency } => write!(
                f,
                "exposure ledger netting is missing a canonical conversion rate for currency `{currency}`"
            ),
            Self::ZeroDenominator { currency } => write!(
                f,
                "exposure ledger netting rejected a zero-denominator conversion rate for currency `{currency}`"
            ),
            Self::ZeroNumerator { currency } => write!(
                f,
                "exposure ledger netting rejected a zero-numerator conversion rate for currency `{currency}`"
            ),
            Self::ConversionOverflow { currency } => write!(
                f,
                "exposure ledger netting conversion for currency `{currency}` overflowed u64; capping would understate exposure"
            ),
            Self::UnsettledExposureOverflow { currency } => write!(
                f,
                "exposure ledger netting unsettled exposure (pending + failed) for currency `{currency}` overflowed u64; capping would understate exposure"
            ),
            Self::AggregateOverflow { channel } => write!(
                f,
                "exposure ledger netting aggregate channel `{channel}` overflowed u64; capping would understate exposure"
            ),
            Self::PinnedParityOverride { currency } => write!(
                f,
                "exposure ledger netting rejected a non-parity override rate for pinned currency `{currency}`"
            ),
            Self::DuplicateCurrency { currency } => write!(
                f,
                "exposure ledger netting rejected duplicate position rows for currency `{currency}`; aggregate a currency's positions into one row before collapsing"
            ),
        }
    }
}

impl std::error::Error for ExposureLedgerNettingError {}

/// A rational conversion rate from a source currency into the canonical
/// denomination. Kept as an integer numerator/denominator so the projection is
/// exact and deterministic; conversions round UP so the netted view never
/// understates exposure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalConversionRate {
    pub currency: String,
    pub numerator: u64,
    pub denominator: u64,
}

impl CanonicalConversionRate {
    /// A one-to-one rate for a currency already at canonical parity.
    #[must_use]
    pub fn identity(currency: &str) -> Self {
        Self {
            currency: currency.to_string(),
            numerator: 1,
            denominator: 1,
        }
    }

    /// Whether this rate converts one-to-one (a parity rate): the numerator and
    /// denominator are equal and non-zero, so `convert` is the identity.
    #[must_use]
    pub fn is_parity(&self) -> bool {
        self.denominator != 0 && self.numerator == self.denominator
    }

    /// Convert `units` of the source currency into canonical units, rounding up.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureLedgerNettingError::ZeroDenominator`] when the rate
    /// denominator is zero, [`ExposureLedgerNettingError::ZeroNumerator`] when
    /// the rate numerator is zero (which would collapse a positive exposure to
    /// nothing), and [`ExposureLedgerNettingError::ConversionOverflow`] when the
    /// converted figure exceeds `u64::MAX` (the collapse fails closed rather than
    /// capping, since a capped figure understates exposure).
    pub fn convert(&self, units: u64) -> Result<u64, ExposureLedgerNettingError> {
        if self.denominator == 0 {
            return Err(ExposureLedgerNettingError::ZeroDenominator {
                currency: self.currency.clone(),
            });
        }
        if self.numerator == 0 {
            return Err(ExposureLedgerNettingError::ZeroNumerator {
                currency: self.currency.clone(),
            });
        }
        if units == 0 {
            return Ok(0);
        }
        // `u64` * `u64` always fits in `u128`, so the multiply never saturates;
        // the only overflow path is the final narrowing back to `u64`.
        let scaled = u128::from(units).saturating_mul(u128::from(self.numerator));
        let converted = scaled.div_ceil(u128::from(self.denominator));
        u64::try_from(converted).map_err(|_| ExposureLedgerNettingError::ConversionOverflow {
            currency: self.currency.clone(),
        })
    }

    /// Convert `units` of the source currency into canonical units, rounding DOWN.
    ///
    /// Used for recovery/offset channels: a recovery REDUCES the net loss, so
    /// rounding a gross recovery UP could shrink the net loss below the true
    /// figure after subtraction. Rounding the recovery down keeps the net-loss
    /// channel fail-closed (it never credits more recovery than the rate
    /// supports), so the netted view never understates exposure.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureLedgerNettingError::ZeroDenominator`] when the rate
    /// denominator is zero, [`ExposureLedgerNettingError::ZeroNumerator`] when
    /// the rate numerator is zero, and
    /// [`ExposureLedgerNettingError::ConversionOverflow`] when the converted
    /// figure exceeds `u64::MAX`.
    pub fn convert_floor(&self, units: u64) -> Result<u64, ExposureLedgerNettingError> {
        if self.denominator == 0 {
            return Err(ExposureLedgerNettingError::ZeroDenominator {
                currency: self.currency.clone(),
            });
        }
        if self.numerator == 0 {
            return Err(ExposureLedgerNettingError::ZeroNumerator {
                currency: self.currency.clone(),
            });
        }
        if units == 0 {
            return Ok(0);
        }
        let scaled = u128::from(units).saturating_mul(u128::from(self.numerator));
        let converted = scaled / u128::from(self.denominator);
        u64::try_from(converted).map_err(|_| ExposureLedgerNettingError::ConversionOverflow {
            currency: self.currency.clone(),
        })
    }
}

/// Conversion rates into the canonical denomination. USD and the canonical
/// currency itself convert one-to-one by default (the USD/USDC pin); any other
/// currency must be supplied explicitly or the collapse fails closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerNettingRates {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rates: Vec<CanonicalConversionRate>,
}

impl ExposureLedgerNettingRates {
    /// Build a rate table from explicit conversion rates.
    #[must_use]
    pub fn new(rates: Vec<CanonicalConversionRate>) -> Self {
        Self { rates }
    }

    /// Resolve the conversion rate for a source currency.
    ///
    /// The canonical currency and USD are pinned one-to-one (the USD/USDC pin):
    /// for those currencies an explicit override is honored ONLY when it is
    /// itself a parity rate, otherwise the collapse fails closed rather than let
    /// a `1/2` (or any non-parity) override halve canonical exposure. For any
    /// other currency an explicit rate wins; absent that, the collapse fails
    /// closed.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureLedgerNettingError::PinnedParityOverride`] when a pinned
    /// currency is given a non-parity override, and
    /// [`ExposureLedgerNettingError::MissingRate`] when no rate is known for a
    /// non-parity currency.
    pub fn rate_for(
        &self,
        currency: &str,
    ) -> Result<CanonicalConversionRate, ExposureLedgerNettingError> {
        let is_pinned_parity = currency == CANONICAL_NETTING_CURRENCY || currency == "USD";
        if let Some(rate) = self.rates.iter().find(|rate| rate.currency == currency) {
            // The USD/USDC pin takes precedence: a non-parity override for a
            // pinned currency is rejected before it can understate the netted
            // view, never accepted ahead of the pinned identity rate.
            if is_pinned_parity && !rate.is_parity() {
                return Err(ExposureLedgerNettingError::PinnedParityOverride {
                    currency: currency.to_string(),
                });
            }
            return Ok(rate.clone());
        }
        if is_pinned_parity {
            return Ok(CanonicalConversionRate::identity(currency));
        }
        Err(ExposureLedgerNettingError::MissingRate {
            currency: currency.to_string(),
        })
    }
}

/// The single-denomination netting benefit: the capital that per-currency
/// segregation locks up but a single canonical denomination frees, realized as
/// an off-chain projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SingleDenominationNettingBenefit {
    /// Outstanding capital requirement when each currency is held in its own
    /// segregated prudential book (the fail-closed status quo): the sum of each
    /// currency's outstanding requirement, converted to canonical units.
    pub segregated_outstanding_units: u64,
    /// Outstanding capital requirement under a single canonical denomination,
    /// where the exposure channels net at the aggregate level.
    pub netted_outstanding_units: u64,
    /// Capital freed by the single-denomination collapse:
    /// `segregated_outstanding_units - netted_outstanding_units`. Always
    /// non-negative; strictly positive only when a mixed-currency book lets the
    /// channels offset.
    pub capital_freed_units: u64,
}

/// Support boundary for the netted view. The three prudential netting flags are
/// carried straight off their defaults, proving the projection does not flip
/// them; the projection markers record that it is read-only and needs no
/// on-chain instrument or new contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerNettedSupportBoundary {
    pub read_only_projection: bool,
    pub prudential_book_unchanged: bool,
    pub cross_currency_netting_supported: bool,
    pub capital_allocation_supported: bool,
    pub mixed_currency_netting_supported: bool,
    pub on_chain_instrument_required: bool,
    pub new_contract_required: bool,
}

impl Default for ExposureLedgerNettedSupportBoundary {
    fn default() -> Self {
        // Carry the three prudential netting flags straight off their fail-closed
        // defaults. The collapse reads them; it never sets them.
        let exposure = ExposureLedgerSupportBoundary::default();
        let scorecard = CreditScorecardSupportBoundary::default();
        let capital = CapitalBookSupportBoundary::default();
        Self {
            read_only_projection: true,
            prudential_book_unchanged: true,
            cross_currency_netting_supported: exposure.cross_currency_netting_supported,
            capital_allocation_supported: scorecard.capital_allocation_supported,
            mixed_currency_netting_supported: capital.mixed_currency_netting_supported,
            on_chain_instrument_required: false,
            new_contract_required: false,
        }
    }
}

/// A read-only off-chain projection that collapses the per-currency exposure
/// positions into a single canonical-denomination netted position and reports
/// the single-denomination netting benefit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerNettedView {
    pub schema: String,
    pub canonical_currency: String,
    pub source_currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub support_boundary: ExposureLedgerNettedSupportBoundary,
    pub netted_position: ExposureLedgerCurrencyPosition,
    pub benefit: SingleDenominationNettingBenefit,
}

fn empty_canonical_position() -> ExposureLedgerCurrencyPosition {
    ExposureLedgerCurrencyPosition {
        currency: CANONICAL_NETTING_CURRENCY.to_string(),
        governed_max_exposure_units: 0,
        reserved_units: 0,
        settled_units: 0,
        pending_units: 0,
        failed_units: 0,
        provisional_loss_units: 0,
        recovered_units: 0,
        quoted_premium_units: 0,
        active_quoted_premium_units: 0,
    }
}

fn convert_position(
    position: &ExposureLedgerCurrencyPosition,
    rate: &CanonicalConversionRate,
) -> Result<ExposureLedgerCurrencyPosition, ExposureLedgerNettingError> {
    Ok(ExposureLedgerCurrencyPosition {
        currency: CANONICAL_NETTING_CURRENCY.to_string(),
        governed_max_exposure_units: rate.convert(position.governed_max_exposure_units)?,
        reserved_units: rate.convert(position.reserved_units)?,
        settled_units: rate.convert(position.settled_units)?,
        pending_units: rate.convert(position.pending_units)?,
        failed_units: rate.convert(position.failed_units)?,
        // The exposure channels round UP so the netted view never understates
        // them. The recovery channel offsets the provisional-loss channel
        // (`net loss = provisional_loss - recovered`), so it rounds DOWN: a
        // recovery rounded up could shrink the net loss below the true figure
        // after subtraction and understate `outstanding_exposure_units`.
        provisional_loss_units: rate.convert(position.provisional_loss_units)?,
        recovered_units: rate.convert_floor(position.recovered_units)?,
        quoted_premium_units: rate.convert(position.quoted_premium_units)?,
        active_quoted_premium_units: rate.convert(position.active_quoted_premium_units)?,
    })
}

/// Checked aggregate add: summing a converted channel into the canonical book
/// fails closed on `u64` overflow rather than capping, because a capped
/// aggregate understates the netted exposure and capital-freed view.
fn checked_aggregate_add(
    accumulator: u64,
    addend: u64,
    channel: &str,
) -> Result<u64, ExposureLedgerNettingError> {
    accumulator
        .checked_add(addend)
        .ok_or_else(|| ExposureLedgerNettingError::AggregateOverflow {
            channel: channel.to_string(),
        })
}

fn add_into_canonical(
    accumulator: &mut ExposureLedgerCurrencyPosition,
    converted: &ExposureLedgerCurrencyPosition,
) -> Result<(), ExposureLedgerNettingError> {
    accumulator.governed_max_exposure_units = checked_aggregate_add(
        accumulator.governed_max_exposure_units,
        converted.governed_max_exposure_units,
        "governedMaxExposureUnits",
    )?;
    accumulator.reserved_units = checked_aggregate_add(
        accumulator.reserved_units,
        converted.reserved_units,
        "reservedUnits",
    )?;
    accumulator.settled_units = checked_aggregate_add(
        accumulator.settled_units,
        converted.settled_units,
        "settledUnits",
    )?;
    accumulator.pending_units = checked_aggregate_add(
        accumulator.pending_units,
        converted.pending_units,
        "pendingUnits",
    )?;
    accumulator.failed_units = checked_aggregate_add(
        accumulator.failed_units,
        converted.failed_units,
        "failedUnits",
    )?;
    accumulator.provisional_loss_units = checked_aggregate_add(
        accumulator.provisional_loss_units,
        converted.provisional_loss_units,
        "provisionalLossUnits",
    )?;
    accumulator.recovered_units = checked_aggregate_add(
        accumulator.recovered_units,
        converted.recovered_units,
        "recoveredUnits",
    )?;
    accumulator.quoted_premium_units = checked_aggregate_add(
        accumulator.quoted_premium_units,
        converted.quoted_premium_units,
        "quotedPremiumUnits",
    )?;
    accumulator.active_quoted_premium_units = checked_aggregate_add(
        accumulator.active_quoted_premium_units,
        converted.active_quoted_premium_units,
        "activeQuotedPremiumUnits",
    )?;
    Ok(())
}

/// Collapse per-currency exposure positions into a single canonical-denomination
/// netted off-chain view.
///
/// Each position is converted into canonical units (rounding up so exposure is
/// never understated), summed component-wise into one netted position, and the
/// single-denomination netting benefit is computed as the difference between
/// segregated (per-currency) and netted (single-denomination) outstanding
/// capital requirements.
///
/// This is a pure, read-only projection. It does not mutate the input, mint any
/// IOU, write any ledger, or flip any support-boundary flag.
///
/// # Errors
///
/// Returns [`ExposureLedgerNettingError`] when any non-parity currency lacks a
/// conversion rate or a supplied rate has a zero denominator.
pub fn collapse_positions_to_canonical(
    positions: &[ExposureLedgerCurrencyPosition],
    rates: &ExposureLedgerNettingRates,
) -> Result<ExposureLedgerNettedView, ExposureLedgerNettingError> {
    let mut netted_position = empty_canonical_position();
    let mut segregated_outstanding_units = 0_u64;
    let mut source_currencies = Vec::with_capacity(positions.len());
    let mut distinct_currencies = BTreeSet::new();

    for position in positions {
        // Fail closed on a repeated currency. The segregated baseline sums the
        // worst-case requirement of EACH row, so two rows for one currency
        // (for example reserved=100 and pending=100 USD) would report a segregated
        // outstanding of 200 against a netted single-position outstanding of 100
        // and manufacture a phantom `capital_freed = 100` even though
        // `mixed_currency_book` is false and nothing cross-currency netted. The
        // single-denomination collapse measures a benefit only across DISTINCT
        // currencies; duplicate single-currency rows must be aggregated upstream.
        if !distinct_currencies.insert(position.currency.clone()) {
            return Err(ExposureLedgerNettingError::DuplicateCurrency {
                currency: position.currency.clone(),
            });
        }
        let rate = rates.rate_for(&position.currency)?;
        let converted = convert_position(position, &rate)?;
        segregated_outstanding_units = checked_aggregate_add(
            segregated_outstanding_units,
            converted.outstanding_exposure_units()?,
            "segregatedOutstandingUnits",
        )?;
        add_into_canonical(&mut netted_position, &converted)?;
        source_currencies.push(position.currency.clone());
    }

    let netted_outstanding_units = netted_position.outstanding_exposure_units()?;
    let capital_freed_units = segregated_outstanding_units.saturating_sub(netted_outstanding_units);

    Ok(ExposureLedgerNettedView {
        schema: EXPOSURE_LEDGER_NETTED_VIEW_SCHEMA.to_string(),
        canonical_currency: CANONICAL_NETTING_CURRENCY.to_string(),
        source_currencies,
        mixed_currency_book: distinct_currencies.len() > 1,
        support_boundary: ExposureLedgerNettedSupportBoundary::default(),
        netted_position,
        benefit: SingleDenominationNettingBenefit {
            segregated_outstanding_units,
            netted_outstanding_units,
            capital_freed_units,
        },
    })
}

impl ExposureLedgerReport {
    /// Collapse this report's per-currency positions into a single
    /// canonical-denomination netted off-chain view. See
    /// [`collapse_positions_to_canonical`].
    ///
    /// # Errors
    ///
    /// Returns [`ExposureLedgerNettingError`] when a non-parity currency lacks a
    /// conversion rate or a supplied rate has a zero denominator.
    pub fn collapse_to_canonical(
        &self,
        rates: &ExposureLedgerNettingRates,
    ) -> Result<ExposureLedgerNettedView, ExposureLedgerNettingError> {
        collapse_positions_to_canonical(&self.positions, rates)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod do_not_weaken {
    //! DO-NOT-WEAKEN regression suite (M2-5).
    //!
    //! The off-chain single-denomination collapse is a projection, not an
    //! authority: it must carry the three prudential netting flags straight
    //! off their fail-closed defaults, mark itself read-only, and require no
    //! on-chain instrument or new contract. These locks freeze that posture at
    //! the default level so a future weakening (flipping a flag to `true`,
    //! clearing a projection marker, or repointing the canonical currency) is
    //! caught without having to exercise the collapse.
    use super::*;

    /// The three prudential netting flags on the netted-view boundary stay
    /// `false` at the default level, matching the prudential defaults.
    #[test]
    fn netted_view_boundary_carries_prudential_flag_defaults_false() {
        let boundary = ExposureLedgerNettedSupportBoundary::default();
        assert!(
            !boundary.cross_currency_netting_supported,
            "cross-currency netting must stay unsupported on the netted view"
        );
        assert!(
            !boundary.capital_allocation_supported,
            "capital allocation must stay unsupported on the netted view"
        );
        assert!(
            !boundary.mixed_currency_netting_supported,
            "mixed-currency netting must stay unsupported on the netted view"
        );
        // The netted-view flags are carried straight off the prudential
        // defaults: weakening a prudential default surfaces here.
        assert_eq!(
            boundary.cross_currency_netting_supported,
            ExposureLedgerSupportBoundary::default().cross_currency_netting_supported
        );
        assert_eq!(
            boundary.capital_allocation_supported,
            CreditScorecardSupportBoundary::default().capital_allocation_supported
        );
        assert_eq!(
            boundary.mixed_currency_netting_supported,
            CapitalBookSupportBoundary::default().mixed_currency_netting_supported
        );
    }

    /// The projection markers: the collapse is a read-only projection that
    /// leaves the prudential book untouched and requires no on-chain
    /// instrument or new contract.
    #[test]
    fn netted_view_boundary_marks_read_only_and_no_instrument() {
        let boundary = ExposureLedgerNettedSupportBoundary::default();
        assert!(
            boundary.read_only_projection,
            "the netted view must stay a read-only projection"
        );
        assert!(
            boundary.prudential_book_unchanged,
            "the netted view must not change the prudential book"
        );
        assert!(
            !boundary.on_chain_instrument_required,
            "the netted view must not require an on-chain instrument"
        );
        assert!(
            !boundary.new_contract_required,
            "the netted view must not require a new contract"
        );
    }

    /// The canonical netting currency is pinned USD/USDC. Repointing it would
    /// silently change which parity the collapse assumes.
    #[test]
    fn canonical_netting_currency_is_pinned_usdc() {
        assert_eq!(
            CANONICAL_NETTING_CURRENCY, "USDC",
            "the canonical netting currency must stay USDC (the USD/USDC pin)"
        );
        // USD and the canonical currency convert one-to-one by default.
        let rates = ExposureLedgerNettingRates::default();
        assert_eq!(
            rates.rate_for("USD").unwrap().convert(1_234).unwrap(),
            1_234
        );
        assert_eq!(
            rates
                .rate_for(CANONICAL_NETTING_CURRENCY)
                .unwrap()
                .convert(1_234)
                .unwrap(),
            1_234
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{ExposureLedgerQuery, ExposureLedgerSummary, EXPOSURE_LEDGER_SCHEMA};

    fn position(currency: &str) -> ExposureLedgerCurrencyPosition {
        ExposureLedgerCurrencyPosition {
            currency: currency.to_string(),
            governed_max_exposure_units: 0,
            reserved_units: 0,
            settled_units: 0,
            pending_units: 0,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }
    }

    fn eur_at_1_1() -> ExposureLedgerNettingRates {
        ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 11,
            denominator: 10,
        }])
    }

    /// Mixed-currency book collapses to a single USDC-canonical denomination,
    /// summing every channel of every converted position.
    #[test]
    fn netting_collapses_mixed_currency_book_to_single_usdc_denomination() {
        let usd = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            pending_units: 80,
            settled_units: 40,
            ..position("USD")
        };
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 400,
            pending_units: 0,
            settled_units: 100,
            ..position("EUR")
        };

        let view = collapse_positions_to_canonical(&[usd, eur], &eur_at_1_1()).unwrap();

        assert_eq!(view.schema, EXPOSURE_LEDGER_NETTED_VIEW_SCHEMA);
        assert_eq!(view.canonical_currency, "USDC");
        assert_eq!(view.netted_position.currency, "USDC");
        assert_eq!(view.source_currencies, vec!["USD", "EUR"]);
        assert!(view.mixed_currency_book);
        // EUR 400 -> 440, EUR 100 -> 110 (rate 1.1, exact).
        assert_eq!(view.netted_position.reserved_units, 100 + 440);
        assert_eq!(view.netted_position.pending_units, 80);
        assert_eq!(view.netted_position.settled_units, 40 + 110);
    }

    /// The single-denomination collapse frees the capital that per-currency
    /// segregation locks up: segregated requirement (sum of per-currency maxes)
    /// exceeds the netted requirement (max of the summed channels).
    #[test]
    fn single_denomination_benefit_frees_capital_on_mixed_book() {
        let usd = ExposureLedgerCurrencyPosition {
            pending_units: 300,
            ..position("USD")
        };
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 400,
            ..position("EUR")
        };

        let view = collapse_positions_to_canonical(&[usd, eur], &eur_at_1_1()).unwrap();

        // Segregated: USD outstanding = max(0,300,0) = 300; EUR outstanding =
        // max(440,0,0) = 440; total = 740.
        assert_eq!(view.benefit.segregated_outstanding_units, 740);
        // Netted: reserved channel 440, unsettled channel 300; max = 440.
        assert_eq!(view.benefit.netted_outstanding_units, 440);
        // Capital freed by the off-chain single-denomination collapse.
        assert_eq!(view.benefit.capital_freed_units, 300);
        assert_eq!(
            view.benefit.capital_freed_units,
            view.benefit.segregated_outstanding_units - view.benefit.netted_outstanding_units
        );
    }

    /// PR959 codex P2: duplicate same-currency rows are rejected fail-closed and
    /// produce NO phantom capital-freed benefit. The segregated baseline sums each
    /// row's worst-case requirement, so two USD rows (reserved=100, pending=100)
    /// would report segregated=200 against netted=100 and advertise a fictitious
    /// `capital_freed=100` even though `mixed_currency_book` is false. The collapse
    /// refuses the duplicate; aggregating the two rows into one position first
    /// yields the honest single-currency view with no benefit.
    #[test]
    fn duplicate_same_currency_rows_are_rejected_and_yield_no_phantom_capital_freed() {
        let usd_reserved = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("USD")
        };
        let usd_pending = ExposureLedgerCurrencyPosition {
            pending_units: 100,
            ..position("USD")
        };

        // Two rows for the same currency fail closed rather than manufacture a
        // benefit a single-currency book cannot produce.
        let err = collapse_positions_to_canonical(
            &[usd_reserved, usd_pending],
            &ExposureLedgerNettingRates::default(),
        )
        .expect_err("duplicate USD rows must be rejected");
        assert_eq!(
            err,
            ExposureLedgerNettingError::DuplicateCurrency {
                currency: "USD".to_string()
            }
        );

        // Aggregating the duplicate channels into ONE USD row is the honest input:
        // outstanding = max(reserved 100, unsettled 100) = 100, so segregated and
        // netted agree and there is exactly zero capital freed.
        let usd_aggregated = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            pending_units: 100,
            ..position("USD")
        };
        let view = collapse_positions_to_canonical(
            &[usd_aggregated],
            &ExposureLedgerNettingRates::default(),
        )
        .expect("a single aggregated USD row collapses");
        assert!(!view.mixed_currency_book);
        assert_eq!(view.benefit.segregated_outstanding_units, 100);
        assert_eq!(view.benefit.netted_outstanding_units, 100);
        assert_eq!(
            view.benefit.capital_freed_units, 0,
            "a single-currency book frees no capital"
        );
    }

    /// KILL-EVIDENCE: all three prudential netting flags read false after the
    /// collapse, and the projection requires no on-chain instrument or contract.
    #[test]
    fn netted_view_support_boundary_flags_stay_false() {
        let usd = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("USD")
        };
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 200,
            ..position("EUR")
        };

        let view = collapse_positions_to_canonical(&[usd, eur], &eur_at_1_1()).unwrap();
        let boundary = &view.support_boundary;

        assert!(
            !boundary.cross_currency_netting_supported,
            "cross-currency netting must stay unsupported after the off-chain collapse"
        );
        assert!(
            !boundary.capital_allocation_supported,
            "capital allocation must stay unsupported after the off-chain collapse"
        );
        assert!(
            !boundary.mixed_currency_netting_supported,
            "mixed-currency netting must stay unsupported after the off-chain collapse"
        );
        assert!(!boundary.on_chain_instrument_required);
        assert!(!boundary.new_contract_required);
        assert!(boundary.read_only_projection);
        assert!(boundary.prudential_book_unchanged);

        // The netted-view flags are carried straight off the prudential defaults,
        // proving the collapse never flipped them.
        assert_eq!(
            boundary.cross_currency_netting_supported,
            ExposureLedgerSupportBoundary::default().cross_currency_netting_supported
        );
        assert_eq!(
            boundary.capital_allocation_supported,
            CreditScorecardSupportBoundary::default().capital_allocation_supported
        );
        assert_eq!(
            boundary.mixed_currency_netting_supported,
            CapitalBookSupportBoundary::default().mixed_currency_netting_supported
        );
    }

    /// The collapse is read-only: it never mutates the input positions.
    #[test]
    fn netting_is_read_only_and_does_not_mutate_positions() {
        let positions = vec![
            ExposureLedgerCurrencyPosition {
                reserved_units: 100,
                pending_units: 50,
                ..position("USD")
            },
            ExposureLedgerCurrencyPosition {
                reserved_units: 200,
                ..position("EUR")
            },
        ];
        let snapshot = positions.clone();

        let _view = collapse_positions_to_canonical(&positions, &eur_at_1_1()).unwrap();

        assert_eq!(
            positions, snapshot,
            "collapse must not mutate the input book"
        );
    }

    /// A single-currency book has nothing to net: the benefit is zero.
    #[test]
    fn single_currency_book_has_zero_netting_benefit() {
        let usd = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            pending_units: 300,
            ..position("USD")
        };

        let view = collapse_positions_to_canonical(&[usd], &ExposureLedgerNettingRates::default())
            .unwrap();

        assert!(!view.mixed_currency_book);
        assert_eq!(view.benefit.segregated_outstanding_units, 300);
        assert_eq!(view.benefit.netted_outstanding_units, 300);
        assert_eq!(view.benefit.capital_freed_units, 0);
    }

    /// USD and USDC convert one-to-one by default (the USD/USDC pin).
    #[test]
    fn usd_and_usdc_convert_at_parity_by_default() {
        let rates = ExposureLedgerNettingRates::default();
        assert_eq!(
            rates.rate_for("USD").unwrap().convert(1_234).unwrap(),
            1_234
        );
        assert_eq!(
            rates.rate_for("USDC").unwrap().convert(1_234).unwrap(),
            1_234
        );
    }

    /// A non-parity currency without a supplied rate fails closed.
    #[test]
    fn netting_missing_rate_fails_closed() {
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("EUR")
        };
        let error = collapse_positions_to_canonical(&[eur], &ExposureLedgerNettingRates::default())
            .unwrap_err();
        assert_eq!(
            error,
            ExposureLedgerNettingError::MissingRate {
                currency: "EUR".to_string()
            }
        );
    }

    /// A zero-denominator rate fails closed rather than dividing by zero.
    #[test]
    fn netting_zero_denominator_fails_closed() {
        let rates = ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 11,
            denominator: 0,
        }]);
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("EUR")
        };
        let error = collapse_positions_to_canonical(&[eur], &rates).unwrap_err();
        assert_eq!(
            error,
            ExposureLedgerNettingError::ZeroDenominator {
                currency: "EUR".to_string()
            }
        );
    }

    /// PR959 codex P2: a zero-numerator rate fails closed rather than collapsing
    /// a positive exposure to zero canonical units.
    #[test]
    fn netting_zero_numerator_fails_closed() {
        let rates = ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 0,
            denominator: 10,
        }]);
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("EUR")
        };
        let error = collapse_positions_to_canonical(&[eur], &rates).unwrap_err();
        assert_eq!(
            error,
            ExposureLedgerNettingError::ZeroNumerator {
                currency: "EUR".to_string()
            }
        );
        // The direct conversion path fails closed too (both round-up and floor).
        let rate = CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 0,
            denominator: 10,
        };
        assert_eq!(
            rate.convert(100).unwrap_err(),
            ExposureLedgerNettingError::ZeroNumerator {
                currency: "EUR".to_string()
            }
        );
        assert_eq!(
            rate.convert_floor(100).unwrap_err(),
            ExposureLedgerNettingError::ZeroNumerator {
                currency: "EUR".to_string()
            }
        );
    }

    /// Conversions round up so the projection never understates exposure.
    #[test]
    fn conversion_rounds_up_to_avoid_understating_exposure() {
        let rate = CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 11,
            denominator: 10,
        };
        // 401 * 11 / 10 = 441.1 -> 442.
        assert_eq!(rate.convert(401).unwrap(), 442);
        assert_eq!(rate.convert(0).unwrap(), 0);
    }

    /// The outstanding-exposure formula takes the worst channel.
    #[test]
    fn outstanding_exposure_units_takes_worst_channel() {
        let reserved_dominant = ExposureLedgerCurrencyPosition {
            reserved_units: 500,
            pending_units: 100,
            provisional_loss_units: 50,
            ..position("USD")
        };
        assert_eq!(reserved_dominant.outstanding_exposure_units().unwrap(), 500);

        let loss_dominant = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            provisional_loss_units: 900,
            recovered_units: 200,
            ..position("USD")
        };
        // net provisional loss = 900 - 200 = 700.
        assert_eq!(loss_dominant.outstanding_exposure_units().unwrap(), 700);
    }

    /// The report convenience method collapses its own positions.
    #[test]
    fn exposure_ledger_report_collapse_matches_free_function() {
        let positions = vec![
            ExposureLedgerCurrencyPosition {
                reserved_units: 100,
                pending_units: 300,
                ..position("USD")
            },
            ExposureLedgerCurrencyPosition {
                reserved_units: 400,
                ..position("EUR")
            },
        ];
        let report = ExposureLedgerReport {
            schema: EXPOSURE_LEDGER_SCHEMA.to_string(),
            generated_at: 1,
            filters: ExposureLedgerQuery {
                agent_subject: Some("subject-1".to_string()),
                ..ExposureLedgerQuery::default()
            },
            support_boundary: ExposureLedgerSupportBoundary::default(),
            summary: ExposureLedgerSummary {
                matching_receipts: 2,
                returned_receipts: 2,
                matching_decisions: 0,
                returned_decisions: 0,
                active_decisions: 0,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 1,
                failed_settlement_receipts: 0,
                currencies: vec!["EUR".to_string(), "USD".to_string()],
                mixed_currency_book: true,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            positions: positions.clone(),
            receipts: Vec::new(),
            decisions: Vec::new(),
        };

        let rates = eur_at_1_1();
        let via_method = report.collapse_to_canonical(&rates).unwrap();
        let via_function = collapse_positions_to_canonical(&positions, &rates).unwrap();
        assert_eq!(via_method, via_function);
        // Mixed book frees capital, and the prudential book is untouched.
        assert!(via_method.benefit.capital_freed_units > 0);
        assert!(!report.support_boundary.cross_currency_netting_supported);
    }

    /// The netted view round-trips through canonical JSON.
    #[test]
    fn netted_view_round_trips_through_json() {
        let usd = ExposureLedgerCurrencyPosition {
            reserved_units: 100,
            ..position("USD")
        };
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: 200,
            ..position("EUR")
        };
        let view = collapse_positions_to_canonical(&[usd, eur], &eur_at_1_1()).unwrap();
        let encoded = serde_json::to_string(&view).unwrap();
        let decoded: ExposureLedgerNettedView = serde_json::from_str(&encoded).unwrap();
        assert_eq!(view, decoded);
    }

    /// PR959 codex P1: a conversion that exceeds `u64::MAX` fails closed with a
    /// [`ExposureLedgerNettingError::ConversionOverflow`] rather than capping at
    /// `u64::MAX`, since a capped figure would understate outstanding exposure.
    #[test]
    fn oversized_conversion_fails_closed_instead_of_capping() {
        let rate = CanonicalConversionRate {
            currency: "EUR".to_string(),
            numerator: 2,
            denominator: 1,
        };
        // u64::MAX * 2 / 1 overflows u64; capping would publish a lower-than-true
        // exposure, so the convert fails closed.
        assert_eq!(
            rate.convert(u64::MAX).unwrap_err(),
            ExposureLedgerNettingError::ConversionOverflow {
                currency: "EUR".to_string()
            }
        );
        // The floor conversion is fail-closed on overflow too.
        assert_eq!(
            rate.convert_floor(u64::MAX).unwrap_err(),
            ExposureLedgerNettingError::ConversionOverflow {
                currency: "EUR".to_string()
            }
        );
        // The whole collapse propagates the overflow rather than understating.
        let eur = ExposureLedgerCurrencyPosition {
            reserved_units: u64::MAX,
            ..position("EUR")
        };
        let rates = ExposureLedgerNettingRates::new(vec![rate]);
        assert_eq!(
            collapse_positions_to_canonical(&[eur], &rates).unwrap_err(),
            ExposureLedgerNettingError::ConversionOverflow {
                currency: "EUR".to_string()
            }
        );
        // A conversion that lands exactly on u64::MAX still succeeds.
        let parity = CanonicalConversionRate::identity("USDC");
        assert_eq!(parity.convert(u64::MAX).unwrap(), u64::MAX);
    }

    /// PR959 codex P1: a single position whose unsettled channel
    /// (`pending + failed`) exceeds `u64::MAX` fails closed with an
    /// [`ExposureLedgerNettingError::UnsettledExposureOverflow`] rather than
    /// saturating, because a capped unsettled figure would understate the
    /// outstanding exposure the collapse and capital view publish.
    #[test]
    fn unsettled_exposure_overflow_fails_closed_instead_of_capping() {
        // pending = u64::MAX, failed = 1 -> pending + failed overflows u64.
        let oversized = ExposureLedgerCurrencyPosition {
            pending_units: u64::MAX,
            failed_units: 1,
            ..position("USD")
        };
        assert_eq!(
            oversized.outstanding_exposure_units().unwrap_err(),
            ExposureLedgerNettingError::UnsettledExposureOverflow {
                currency: "USD".to_string()
            }
        );
        // The whole collapse propagates the unsettled overflow rather than
        // publishing a capped, lower-than-true outstanding exposure. The
        // canonical-converted position carries the canonical currency.
        assert_eq!(
            collapse_positions_to_canonical(&[oversized], &ExposureLedgerNettingRates::default())
                .unwrap_err(),
            ExposureLedgerNettingError::UnsettledExposureOverflow {
                currency: CANONICAL_NETTING_CURRENCY.to_string()
            }
        );
        // A single position whose pending channel is exactly u64::MAX with no
        // failed backlog still succeeds (the add does not overflow).
        let at_max = ExposureLedgerCurrencyPosition {
            pending_units: u64::MAX,
            ..position("USD")
        };
        assert_eq!(at_max.outstanding_exposure_units().unwrap(), u64::MAX);
    }

    /// PR959 codex P1: summing individually valid positions past `u64::MAX` in
    /// the aggregate canonical book fails closed with an
    /// [`ExposureLedgerNettingError::AggregateOverflow`] rather than capping,
    /// because a capped aggregate would understate the netted exposure and
    /// capital-freed view.
    #[test]
    fn aggregate_channel_summation_fails_closed_instead_of_capping() {
        // Two DISTINCT pinned-parity currencies (USD and the canonical USDC), each
        // with reserved_units = u64::MAX, both convert one-to-one and push the
        // aggregate outstanding past u64::MAX; the collapse fails closed instead of
        // publishing a capped reserved_units = u64::MAX. Distinct currencies are
        // used because duplicate same-currency rows are now rejected before they can
        // aggregate (PR959 codex P2 finding 3).
        let reserved_max = |currency: &str| ExposureLedgerCurrencyPosition {
            reserved_units: u64::MAX,
            ..position(currency)
        };
        let error = collapse_positions_to_canonical(
            &[reserved_max("USD"), reserved_max("USDC")],
            &ExposureLedgerNettingRates::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, ExposureLedgerNettingError::AggregateOverflow { .. }),
            "aggregate past u64::MAX must fail closed, got {error:?}"
        );

        // Isolate the per-channel aggregate add: quoted_premium does not feed the
        // outstanding-exposure channels, so the segregated accumulator stays 0
        // and the failure surfaces from add_into_canonical's checked channel sum.
        let premium_max = |currency: &str| ExposureLedgerCurrencyPosition {
            quoted_premium_units: u64::MAX,
            ..position(currency)
        };
        assert_eq!(
            collapse_positions_to_canonical(
                &[premium_max("USD"), premium_max("USDC")],
                &ExposureLedgerNettingRates::default()
            )
            .unwrap_err(),
            ExposureLedgerNettingError::AggregateOverflow {
                channel: "quotedPremiumUnits".to_string()
            }
        );
    }

    /// PR959 codex P2: a pinned-parity currency (USD or USDC) supplied a
    /// non-parity explicit override is rejected before the override can halve
    /// canonical exposure; the USD/USDC pin is not negotiable.
    #[test]
    fn pinned_parity_rejects_non_identity_override() {
        for pinned in ["USDC", "USD"] {
            let rates = ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
                currency: pinned.to_string(),
                numerator: 1,
                denominator: 2,
            }]);
            assert_eq!(
                rates.rate_for(pinned).unwrap_err(),
                ExposureLedgerNettingError::PinnedParityOverride {
                    currency: pinned.to_string()
                }
            );
            // The collapse fails closed rather than netting at the bogus rate.
            let pos = ExposureLedgerCurrencyPosition {
                reserved_units: 1_000,
                ..position(pinned)
            };
            assert_eq!(
                collapse_positions_to_canonical(&[pos], &rates).unwrap_err(),
                ExposureLedgerNettingError::PinnedParityOverride {
                    currency: pinned.to_string()
                }
            );
        }
        // An explicit parity override for a pinned currency is still honored.
        let parity_override = ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
            currency: "USD".to_string(),
            numerator: 5,
            denominator: 5,
        }]);
        assert_eq!(
            parity_override
                .rate_for("USD")
                .unwrap()
                .convert(1_234)
                .unwrap(),
            1_234
        );
        // A non-pinned currency keeps accepting an explicit non-parity rate.
        assert_eq!(
            eur_at_1_1().rate_for("EUR").unwrap().convert(10).unwrap(),
            11
        );
    }

    /// PR959 codex P2: the recovery channel rounds DOWN so the net-loss channel
    /// is never understated after subtraction. With 2 EUR provisional loss and 1
    /// EUR recovered at 11/10 the net loss must be 2 USDC, not the 1 USDC that
    /// rounding the gross recovery up would produce.
    #[test]
    fn recovery_rounds_down_so_net_loss_is_not_understated() {
        let eur = ExposureLedgerCurrencyPosition {
            provisional_loss_units: 2,
            recovered_units: 1,
            ..position("EUR")
        };
        let view = collapse_positions_to_canonical(&[eur], &eur_at_1_1()).unwrap();
        // provisional loss rounds UP: ceil(2 * 1.1) = ceil(2.2) = 3.
        assert_eq!(view.netted_position.provisional_loss_units, 3);
        // recovery rounds DOWN: floor(1 * 1.1) = floor(1.1) = 1.
        assert_eq!(view.netted_position.recovered_units, 1);
        // net loss = 3 - 1 = 2 (NOT 3 - ceil(1.1) = 1).
        assert_eq!(
            view.netted_position.outstanding_exposure_units().unwrap(),
            2
        );
        assert_eq!(view.benefit.netted_outstanding_units, 2);
        assert_eq!(view.benefit.segregated_outstanding_units, 2);
    }
}
