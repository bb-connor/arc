//! Verifiability-graded pricing primitives.
//!
//! A [`VerifiabilityGrade`] scores how much of the evidence a quote *requires*
//! has actually been *verified*. The grade is:
//!
//! - DETERMINISTIC: it is a pure function of the (required, verified) evidence
//!   sets and a fixed per-requirement weight table. Equal inputs always produce
//!   an identical grade.
//! - MONOTONE: verifying more required evidence never lowers the grade, and any
//!   missing required evidence strictly lowers it. Concretely, if the verified
//!   evidence is a strict subset of a fuller verification, the grade is strictly
//!   lower. Full verification therefore strictly dominates every partial
//!   verification of the same requirement set.
//!
//! A [`GradedQuoteOption`] binds a graded price to a last-look window. It cannot
//! be exercised once `expires_at` has passed: exercise fails closed on expiry
//! (and, additionally, when the verifiability band sits below the option's
//! bound minimum). This keeps the surface additive and inside the existing
//! immutable-contract boundary - no signed body or wire schema is touched.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::capability::scope::MonetaryAmount;
use crate::LiabilityEvidenceRequirement;

/// Fixed, positive verifiability weight for a single evidence requirement.
///
/// Every variant carries a strictly positive weight. That is what makes the
/// grade strictly monotone: dropping any verified required item removes a
/// positive amount of score, so a strictly-less-verified input always grades
/// strictly lower. The table is a hard-coded constant, which is what makes the
/// grade deterministic.
#[must_use]
pub const fn evidence_weight(requirement: LiabilityEvidenceRequirement) -> u32 {
    match requirement {
        LiabilityEvidenceRequirement::BehavioralFeed => 1,
        LiabilityEvidenceRequirement::UnderwritingDecision => 3,
        LiabilityEvidenceRequirement::CreditProviderRiskPackage => 3,
        LiabilityEvidenceRequirement::RuntimeAttestationAppraisal => 2,
        LiabilityEvidenceRequirement::CertificationArtifact => 2,
        LiabilityEvidenceRequirement::CreditBond => 2,
        LiabilityEvidenceRequirement::AuthorizationReviewPack => 2,
    }
}

/// Coarse verifiability band derived from the underlying score.
///
/// The variants are declared (and ordered) from least to most verified so the
/// derived [`Ord`] matches the verification ordering: `Unverified < Partial <
/// Full`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum VerifiabilityBand {
    /// No required evidence has been verified (or nothing is required to grade
    /// against). Fail-closed callers treat this as the floor.
    #[default]
    Unverified,
    /// Some, but not all, required evidence has been verified.
    Partial,
    /// Every required evidence item has been verified.
    Full,
}

/// Deterministic, monotone verifiability grade for a price or quote.
///
/// The grade orders primarily by [`VerifiabilityBand`] and then by the raw
/// `verified_score`, so that within a fixed requirement set a strictly-less
/// verified quote always compares strictly lower. The ordering is consistent
/// with [`Eq`] because every field participates in both.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiabilityGrade {
    /// Coarse band, kept first so band ordering dominates raw score.
    pub band: VerifiabilityBand,
    /// Summed weight of the required evidence that was verified.
    pub verified_score: u32,
    /// Summed weight of all required evidence (the maximum attainable score).
    pub required_score: u32,
    /// Required evidence that was not verified, in deterministic sorted order.
    pub missing_evidence: Vec<LiabilityEvidenceRequirement>,
}

impl VerifiabilityGrade {
    /// Grade the verifiability of a quote from its required and verified
    /// evidence sets.
    ///
    /// Only evidence that is *required* contributes to the score; verified
    /// evidence outside the requirement set never lowers the grade and is
    /// ignored for scoring. The computation is a pure function of the two sets
    /// and the [`evidence_weight`] table, so equal inputs yield identical
    /// grades.
    #[must_use]
    pub fn grade(
        required: &BTreeSet<LiabilityEvidenceRequirement>,
        verified: &BTreeSet<LiabilityEvidenceRequirement>,
    ) -> Self {
        let required_score = sum_weights(required.iter().copied());
        let verified_score = sum_weights(required.intersection(verified).copied());
        let missing_evidence: Vec<LiabilityEvidenceRequirement> =
            required.difference(verified).copied().collect();
        let band = band_for(verified_score, required_score);
        Self {
            band,
            verified_score,
            required_score,
            missing_evidence,
        }
    }

    /// Grade from slices, de-duplicating and canonicalising into sets first.
    ///
    /// Input ordering and duplicates do not affect the result: both slices are
    /// folded into [`BTreeSet`]s before grading, so the grade stays
    /// deterministic regardless of how the caller assembled its evidence lists.
    #[must_use]
    pub fn from_slices(
        required: &[LiabilityEvidenceRequirement],
        verified: &[LiabilityEvidenceRequirement],
    ) -> Self {
        let required_set: BTreeSet<LiabilityEvidenceRequirement> =
            required.iter().copied().collect();
        let verified_set: BTreeSet<LiabilityEvidenceRequirement> =
            verified.iter().copied().collect();
        Self::grade(&required_set, &verified_set)
    }

    /// True when every required evidence item has been verified.
    #[must_use]
    pub fn is_fully_verified(&self) -> bool {
        matches!(self.band, VerifiabilityBand::Full)
    }

    /// Whether this grade is internally consistent with what [`Self::grade`]
    /// produces from some (required, verified) evidence pair.
    ///
    /// A grade that did not come from [`Self::grade`] (hand-built, deserialized,
    /// or otherwise externally constructed) can carry an arbitrary `band` and
    /// scores. This re-derives the invariants the grader guarantees and rejects
    /// any grade that violates them:
    ///
    /// - the verified score never exceeds the required score;
    /// - the `band` matches the band the scores imply (so `band = Full` with
    ///   `required_score = 0`, or any other band/score mismatch, is rejected);
    /// - the missing-evidence weights exactly account for the unverified portion
    ///   (`verified_score + sum(missing weights) == required_score`), which also
    ///   rejects duplicated or padded missing-evidence lists.
    ///
    /// It cannot prove the scores reflect genuinely verified evidence (that
    /// needs the original evidence sets), but it does close the inconsistent-shape
    /// bypass where a fabricated grade claims a band its scores do not support.
    #[must_use]
    pub fn is_internally_consistent(&self) -> bool {
        if self.verified_score > self.required_score {
            return false;
        }
        if self.band != band_for(self.verified_score, self.required_score) {
            return false;
        }
        let missing_weight = sum_weights(self.missing_evidence.iter().copied());
        self.verified_score.checked_add(missing_weight) == Some(self.required_score)
    }
}

/// Sum evidence weights with saturating arithmetic so the grade can never panic
/// or wrap on a pathological requirement set.
fn sum_weights(requirements: impl Iterator<Item = LiabilityEvidenceRequirement>) -> u32 {
    requirements.fold(0u32, |accumulator, requirement| {
        accumulator.saturating_add(evidence_weight(requirement))
    })
}

/// Derive the band from the verified and required scores.
///
/// `verified_score` can never exceed `required_score` because only required
/// evidence is scored, but the comparison uses `>=` defensively.
fn band_for(verified_score: u32, required_score: u32) -> VerifiabilityBand {
    if required_score == 0 || verified_score == 0 {
        VerifiabilityBand::Unverified
    } else if verified_score >= required_score {
        VerifiabilityBand::Full
    } else {
        VerifiabilityBand::Partial
    }
}

/// Compute the verifiability surcharge (in minor units) for a base price.
///
/// Fully verified quotes carry no surcharge. Each unit of missing verifiability
/// adds a proportional surcharge up to the full base price when nothing is
/// verified. The surcharge is a pure function of the base price and the grade,
/// and is monotone non-increasing in the grade: verifying more required
/// evidence never raises it. Integer division truncates, matching minor-unit
/// pricing semantics.
#[must_use]
pub fn verifiability_surcharge_minor(base_minor: u64, grade: &VerifiabilityGrade) -> u64 {
    if grade.required_score == 0 {
        return 0;
    }
    let missing = grade.required_score.saturating_sub(grade.verified_score);
    let numerator = u128::from(base_minor).saturating_mul(u128::from(missing));
    let surcharge = numerator / u128::from(grade.required_score);
    u64::try_from(surcharge).unwrap_or(u64::MAX)
}

/// Strict fail-closed currency check for quote-option prices.
///
/// Unlike the crate's case-normalising helper, this accepts only already
/// canonical three-letter uppercase ISO-style codes: a lowercase or padded code
/// is rejected rather than coerced.
fn is_canonical_currency(currency: &str) -> bool {
    currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// Errors raised when building or exercising a graded quote option.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuoteOptionError {
    /// A quote option must carry a non-empty quote identifier so an exercised
    /// option can be bound back to its quote.
    #[error("quote option requires a non-empty quote_id")]
    EmptyQuoteId,
    /// Quote-option prices use ISO-style uppercase three-letter currency codes.
    #[error("quote option currency `{currency}` must be a three-letter uppercase ISO 4217 code")]
    InvalidCurrency {
        /// The currency code that failed validation.
        currency: String,
    },
    /// The last-look window is empty or inverted; a quote option must be
    /// exercisable for a strictly positive interval.
    #[error("quote option expires_at {expires_at} must be after issued_at {issued_at}")]
    InvalidWindow {
        /// Issuance time supplied to the constructor.
        issued_at: u64,
        /// Expiry time supplied to the constructor.
        expires_at: u64,
    },
    /// The last-look window has not opened yet: the option is being exercised
    /// before its issuance time. Exercise fails closed before issuance so a
    /// caller cannot bind a quote before it exists or before its validity starts.
    #[error("quote option not yet issued: now {now} is before issued_at {issued_at}")]
    NotYetIssued {
        /// The exercise time presented by the caller.
        now: u64,
        /// The option's issuance time.
        issued_at: u64,
    },
    /// The last-look window has closed: the option is being exercised at or
    /// after its expiry. Exercise fails closed on expiry.
    #[error("quote option expired: now {now} is at or after expires_at {expires_at}")]
    Expired {
        /// The exercise time presented by the caller.
        now: u64,
        /// The option's expiry.
        expires_at: u64,
    },
    /// The graded verifiability band sits below the option's bound minimum.
    #[error(
        "quote option verifiability band {observed:?} is below the required minimum {minimum:?}"
    )]
    InsufficientVerifiability {
        /// The band actually graded for the quote.
        observed: VerifiabilityBand,
        /// The minimum band the option requires to be exercised.
        minimum: VerifiabilityBand,
    },
    /// The carried [`VerifiabilityGrade`] is not internally consistent with what
    /// [`VerifiabilityGrade::grade`] produces: its band does not match its
    /// scores, or its missing-evidence weights do not account for the gap
    /// between the verified and required scores. A grade that was hand-built or
    /// deserialized into an inconsistent shape (for example `band = Full` with
    /// `required_score = 0`) is rejected before it can bind a price.
    #[error("quote option grade is internally inconsistent and cannot bind a price")]
    InconsistentGrade,
    /// The exercised graded price (base price plus verifiability surcharge)
    /// exceeds `u64::MAX`. The option fails closed rather than saturating to
    /// `u64::MAX`, which would silently UNDERcharge a bound quote whose intended
    /// price is larger.
    #[error("quote option graded price overflows u64 and cannot bind a price")]
    PriceOverflow,
}

/// A graded price bound to a last-look window.
///
/// The option pins a base price, the verifiability grade earned by the
/// quote, the minimum band required to exercise, and the issuance/expiry of the
/// last-look window. It carries no signed body and adds no wire schema, so it is
/// purely additive to the market surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GradedQuoteOption {
    /// Identifier of the quote this option binds.
    pub quote_id: String,
    /// Base price before the verifiability surcharge is applied.
    pub base_price: MonetaryAmount,
    /// Verifiability grade earned by the quote evidence.
    pub grade: VerifiabilityGrade,
    /// Minimum verifiability band required to exercise the option.
    pub minimum_band: VerifiabilityBand,
    /// Issuance time of the last-look window.
    pub issued_at: u64,
    /// Expiry of the last-look window. The option cannot be exercised at or
    /// after this instant.
    pub expires_at: u64,
}

/// The bound result of exercising a [`GradedQuoteOption`] inside its window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExercisedQuote {
    /// Identifier of the quote that was exercised.
    pub quote_id: String,
    /// Final graded price (base price plus verifiability surcharge).
    pub price: MonetaryAmount,
    /// Verifiability grade that the price was bound against.
    pub grade: VerifiabilityGrade,
    /// Instant at which the option was exercised.
    pub exercised_at: u64,
}

impl GradedQuoteOption {
    /// Build and validate a graded quote option for fail-closed callers.
    ///
    /// # Errors
    ///
    /// Returns [`QuoteOptionError::EmptyQuoteId`] when the quote id is empty,
    /// [`QuoteOptionError::InvalidCurrency`] when the base price currency is not
    /// a three-letter uppercase ISO 4217 code, and
    /// [`QuoteOptionError::InvalidWindow`] when the last-look window does not end
    /// strictly after it begins.
    pub fn try_new(
        quote_id: impl Into<String>,
        base_price: MonetaryAmount,
        grade: VerifiabilityGrade,
        minimum_band: VerifiabilityBand,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, QuoteOptionError> {
        let quote_id = quote_id.into();
        if quote_id.trim().is_empty() {
            return Err(QuoteOptionError::EmptyQuoteId);
        }
        if !is_canonical_currency(&base_price.currency) {
            return Err(QuoteOptionError::InvalidCurrency {
                currency: base_price.currency.clone(),
            });
        }
        if expires_at <= issued_at {
            return Err(QuoteOptionError::InvalidWindow {
                issued_at,
                expires_at,
            });
        }
        Ok(Self {
            quote_id,
            base_price,
            grade,
            minimum_band,
            issued_at,
            expires_at,
        })
    }

    /// The graded price: base price plus the verifiability surcharge for the
    /// option's grade. Currency is carried through from the base price and the
    /// addition saturates rather than wrapping.
    ///
    /// This saturating form is for DISPLAY only. Binding a price goes through
    /// [`Self::checked_graded_price`], which fails closed on overflow instead of
    /// silently capping (and undercharging) at `u64::MAX`.
    #[must_use]
    pub fn graded_price(&self) -> MonetaryAmount {
        let surcharge = verifiability_surcharge_minor(self.base_price.units, &self.grade);
        MonetaryAmount {
            units: self.base_price.units.saturating_add(surcharge),
            currency: self.base_price.currency.clone(),
        }
    }

    /// The graded price computed fail-closed: base price plus the verifiability
    /// surcharge, rejecting an overflow rather than saturating.
    ///
    /// The surcharge and total are computed in `u128` (a `u64` base times a
    /// small `u32` weight gap can never overflow `u128`), then the total is
    /// narrowed back to `u64`. If the true total exceeds `u64::MAX` the option
    /// fails closed with [`QuoteOptionError::PriceOverflow`] rather than binding
    /// a capped, UNDER-charged price.
    ///
    /// This is the fail-closed price-binding path, so it FIRST re-runs every
    /// constructor invariant via [`Self::validate_for_exercise`]. [`Self`] derives
    /// `Deserialize` and exposes public fields, so a hand-built or decoded option
    /// can reach this public binding-price path WITHOUT ever passing through
    /// [`Self::try_new`] (or [`Self::exercise`], which validates first): it could
    /// carry a non-canonical (lowercase or padded) `base_price.currency`, an empty
    /// `quote_id`, an inverted last-look window, or a grade whose `verified_score`
    /// exceeds `required_score`. An inconsistent grade makes the missing-evidence
    /// term `required_score - verified_score` saturate to zero, silently dropping
    /// the surcharge and binding the BASE price (an undercharge); a non-canonical
    /// currency would bind a price `try_new`/`exercise` would reject. Re-validating
    /// the same fields the constructor checks fails closed so the binding price is
    /// never computed over a body the constructor would refuse.
    ///
    /// # Errors
    ///
    /// Returns [`QuoteOptionError::EmptyQuoteId`], [`QuoteOptionError::InvalidCurrency`],
    /// or [`QuoteOptionError::InvalidWindow`] when a constructor field invariant was
    /// bypassed, [`QuoteOptionError::InconsistentGrade`] when the option's grade is
    /// not internally consistent, and [`QuoteOptionError::PriceOverflow`] when the
    /// graded price exceeds `u64::MAX`.
    pub fn checked_graded_price(&self) -> Result<MonetaryAmount, QuoteOptionError> {
        self.validate_for_exercise()?;
        let surcharge: u128 = if self.grade.required_score == 0 {
            0
        } else {
            let missing = u128::from(
                self.grade
                    .required_score
                    .saturating_sub(self.grade.verified_score),
            );
            u128::from(self.base_price.units).saturating_mul(missing)
                / u128::from(self.grade.required_score)
        };
        let total = u128::from(self.base_price.units)
            .checked_add(surcharge)
            .ok_or(QuoteOptionError::PriceOverflow)?;
        let units = u64::try_from(total).map_err(|_| QuoteOptionError::PriceOverflow)?;
        Ok(MonetaryAmount {
            units,
            currency: self.base_price.currency.clone(),
        })
    }

    /// Re-run the constructor's fail-closed checks against this option's current
    /// fields, plus a grade-consistency check.
    ///
    /// [`Self`] derives `Deserialize` and exposes public fields, so an option
    /// can reach [`Self::exercise`] without ever passing through [`Self::try_new`]
    /// (for example decoded from JSON with a lowercase currency, an empty
    /// `quote_id`, an inverted window, or a hand-built inconsistent grade).
    /// Exercise calls this first so those bypassed invariants are enforced before
    /// any price binds.
    fn validate_for_exercise(&self) -> Result<(), QuoteOptionError> {
        if self.quote_id.trim().is_empty() {
            return Err(QuoteOptionError::EmptyQuoteId);
        }
        if !is_canonical_currency(&self.base_price.currency) {
            return Err(QuoteOptionError::InvalidCurrency {
                currency: self.base_price.currency.clone(),
            });
        }
        if self.expires_at <= self.issued_at {
            return Err(QuoteOptionError::InvalidWindow {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }
        if !self.grade.is_internally_consistent() {
            return Err(QuoteOptionError::InconsistentGrade);
        }
        Ok(())
    }

    /// Whether the last-look window has closed at `now`. The option is expired
    /// once `now` reaches `expires_at`: the boundary fails closed.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Exercise the option at `now`, binding the graded price.
    ///
    /// Fails closed when the option's own fields are invalid (bypassing
    /// [`Self::try_new`] via deserialization or direct construction), when the
    /// carried grade is internally inconsistent, when the option is exercised
    /// before its issuance time (`now` below `issued_at`), when the option has
    /// expired (`now` at or after `expires_at`), when the quote's verifiability
    /// band is below the option's bound minimum, and when the graded price would
    /// overflow `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`QuoteOptionError::EmptyQuoteId`], [`QuoteOptionError::InvalidCurrency`],
    /// or [`QuoteOptionError::InvalidWindow`] when a constructor invariant was
    /// bypassed, [`QuoteOptionError::InconsistentGrade`] when the grade is not
    /// internally consistent, [`QuoteOptionError::NotYetIssued`] before the
    /// last-look window opens, [`QuoteOptionError::Expired`] once it has closed,
    /// [`QuoteOptionError::InsufficientVerifiability`] when the graded band is
    /// below `minimum_band`, and [`QuoteOptionError::PriceOverflow`] when the
    /// graded price exceeds `u64::MAX`.
    pub fn exercise(&self, now: u64) -> Result<ExercisedQuote, QuoteOptionError> {
        self.validate_for_exercise()?;
        if now < self.issued_at {
            return Err(QuoteOptionError::NotYetIssued {
                now,
                issued_at: self.issued_at,
            });
        }
        if self.is_expired(now) {
            return Err(QuoteOptionError::Expired {
                now,
                expires_at: self.expires_at,
            });
        }
        if self.grade.band < self.minimum_band {
            return Err(QuoteOptionError::InsufficientVerifiability {
                observed: self.grade.band,
                minimum: self.minimum_band,
            });
        }
        let price = self.checked_graded_price()?;
        Ok(ExercisedQuote {
            quote_id: self.quote_id.clone(),
            price,
            grade: self.grade.clone(),
            exercised_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_EVIDENCE: [LiabilityEvidenceRequirement; 7] = [
        LiabilityEvidenceRequirement::BehavioralFeed,
        LiabilityEvidenceRequirement::UnderwritingDecision,
        LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
        LiabilityEvidenceRequirement::CertificationArtifact,
        LiabilityEvidenceRequirement::CreditBond,
        LiabilityEvidenceRequirement::AuthorizationReviewPack,
    ];

    fn usd(units: u64) -> MonetaryAmount {
        MonetaryAmount {
            units,
            currency: "USD".to_string(),
        }
    }

    #[test]
    fn grade_is_deterministic_for_identical_inputs() {
        let required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
        ];
        let verified = [
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
        ];
        let first = VerifiabilityGrade::from_slices(&required, &verified);
        let second = VerifiabilityGrade::from_slices(&required, &verified);
        assert_eq!(first, second);
        // Input ordering and duplicates must not change the grade.
        let shuffled_required = [
            LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            LiabilityEvidenceRequirement::UnderwritingDecision,
        ];
        let shuffled_verified = [
            LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let third = VerifiabilityGrade::from_slices(&shuffled_required, &shuffled_verified);
        assert_eq!(first, third);
    }

    #[test]
    fn full_verification_grades_above_every_partial() {
        let full = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        assert!(full.is_fully_verified());
        assert_eq!(full.band, VerifiabilityBand::Full);
        assert!(full.missing_evidence.is_empty());
        assert_eq!(full.verified_score, full.required_score);
        for drop_index in 0..ALL_EVIDENCE.len() {
            let verified: Vec<LiabilityEvidenceRequirement> = ALL_EVIDENCE
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != drop_index)
                .map(|(_, requirement)| *requirement)
                .collect();
            let partial = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &verified);
            // Partial verification grades strictly lower than full verification.
            assert!(
                partial < full,
                "partial {partial:?} should be < full {full:?}"
            );
            assert!(partial.verified_score < full.verified_score);
            assert!(!partial.is_fully_verified());
        }
    }

    #[test]
    fn strictly_less_verified_input_grades_strictly_lower() {
        let required: Vec<LiabilityEvidenceRequirement> = ALL_EVIDENCE.to_vec();
        let mut verified: Vec<LiabilityEvidenceRequirement> = ALL_EVIDENCE.to_vec();
        let mut previous = VerifiabilityGrade::from_slices(&required, &verified);
        // Remove one verified item at a time. Each strictly-smaller verified set
        // must grade strictly lower than the previous, fuller one.
        while let Some(removed) = verified.pop() {
            let current = VerifiabilityGrade::from_slices(&required, &verified);
            assert!(
                current < previous,
                "dropping {removed:?} should strictly lower the grade: {current:?} !< {previous:?}"
            );
            assert!(current.verified_score < previous.verified_score);
            assert!(current.missing_evidence.contains(&removed));
            previous = current;
        }
        assert_eq!(previous.band, VerifiabilityBand::Unverified);
        assert_eq!(previous.verified_score, 0);
    }

    #[test]
    fn extra_non_required_evidence_never_lowers_grade() {
        let required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let verified_required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let verified_with_extra = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
            // Not in the requirement set: must not change the grade.
            LiabilityEvidenceRequirement::BehavioralFeed,
        ];
        let baseline = VerifiabilityGrade::from_slices(&required, &verified_required);
        let with_extra = VerifiabilityGrade::from_slices(&required, &verified_with_extra);
        assert_eq!(baseline, with_extra);
        assert!(baseline.is_fully_verified());
    }

    #[test]
    fn empty_requirement_set_is_unverified_and_unsurcharged() {
        let grade = VerifiabilityGrade::from_slices(&[], &[]);
        assert_eq!(grade.band, VerifiabilityBand::Unverified);
        assert_eq!(grade.required_score, 0);
        assert_eq!(grade.verified_score, 0);
        assert_eq!(verifiability_surcharge_minor(10_000, &grade), 0);
    }

    #[test]
    fn surcharge_is_monotone_non_increasing_in_grade() {
        let required: Vec<LiabilityEvidenceRequirement> = ALL_EVIDENCE.to_vec();
        let mut verified: Vec<LiabilityEvidenceRequirement> = ALL_EVIDENCE.to_vec();
        let base_minor = 100_000u64;
        let full_grade = VerifiabilityGrade::from_slices(&required, &verified);
        assert_eq!(verifiability_surcharge_minor(base_minor, &full_grade), 0);
        let mut previous = verifiability_surcharge_minor(base_minor, &full_grade);
        while let Some(_removed) = verified.pop() {
            let grade = VerifiabilityGrade::from_slices(&required, &verified);
            let surcharge = verifiability_surcharge_minor(base_minor, &grade);
            assert!(
                surcharge >= previous,
                "less verification must not lower the surcharge: {surcharge} < {previous}"
            );
            previous = surcharge;
        }
        // Nothing verified: surcharge reaches the full base price.
        assert_eq!(previous, base_minor);
    }

    #[test]
    fn graded_price_adds_surcharge_for_partial_verification() {
        let required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let verified = [LiabilityEvidenceRequirement::UnderwritingDecision];
        let grade = VerifiabilityGrade::from_slices(&required, &verified);
        let option = match GradedQuoteOption::try_new(
            "quote-1",
            usd(1_000),
            grade,
            VerifiabilityBand::Partial,
            100,
            200,
        ) {
            Ok(option) => option,
            Err(error) => panic!("option should build: {error}"),
        };
        let priced = option.graded_price();
        // required_score = 3 + 3 = 6, verified_score = 3, missing = 3.
        // surcharge = 1000 * 3 / 6 = 500.
        assert_eq!(priced.units, 1_500);
        assert_eq!(priced.currency, "USD");
    }

    #[test]
    fn exercise_after_expiry_is_denied() {
        let grade = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        let option = match GradedQuoteOption::try_new(
            "quote-1",
            usd(1_000),
            grade,
            VerifiabilityBand::Unverified,
            100,
            200,
        ) {
            Ok(option) => option,
            Err(error) => panic!("option should build: {error}"),
        };
        // Inside the window: exercise succeeds.
        match option.exercise(150) {
            Ok(exercised) => {
                assert_eq!(exercised.quote_id, "quote-1");
                assert_eq!(exercised.exercised_at, 150);
                assert_eq!(exercised.price.units, 1_000);
            }
            Err(error) => panic!("in-window exercise should succeed: {error}"),
        }
        // At the expiry boundary: fail closed.
        assert!(option.is_expired(200));
        match option.exercise(200) {
            Err(QuoteOptionError::Expired { now, expires_at }) => {
                assert_eq!(now, 200);
                assert_eq!(expires_at, 200);
            }
            other => panic!("exercise at expiry must be denied, got {other:?}"),
        }
        // After expiry: fail closed.
        match option.exercise(500) {
            Err(QuoteOptionError::Expired { now, expires_at }) => {
                assert_eq!(now, 500);
                assert_eq!(expires_at, 200);
            }
            other => panic!("exercise after expiry must be denied, got {other:?}"),
        }
    }

    /// PR959 codex P2: exercising before the option's issuance time fails closed,
    /// so a caller cannot bind a quote before it exists or before its validity
    /// window opens. The lower bound is checked alongside the expiry upper bound.
    #[test]
    fn exercise_before_issuance_is_denied() {
        let grade = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        let option = match GradedQuoteOption::try_new(
            "quote-1",
            usd(1_000),
            grade,
            VerifiabilityBand::Unverified,
            100,
            200,
        ) {
            Ok(option) => option,
            Err(error) => panic!("option should build: {error}"),
        };
        // Before issuance: fail closed (the window has not opened yet).
        match option.exercise(50) {
            Err(QuoteOptionError::NotYetIssued { now, issued_at }) => {
                assert_eq!(now, 50);
                assert_eq!(issued_at, 100);
            }
            other => panic!("exercise before issuance must be denied, got {other:?}"),
        }
        // At the issuance boundary: the window is open, so exercise succeeds.
        match option.exercise(100) {
            Ok(exercised) => assert_eq!(exercised.exercised_at, 100),
            Err(error) => panic!("exercise at issuance should succeed: {error}"),
        }
    }

    #[test]
    fn exercise_below_minimum_band_is_denied() {
        let required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let verified = [LiabilityEvidenceRequirement::UnderwritingDecision];
        let grade = VerifiabilityGrade::from_slices(&required, &verified);
        assert_eq!(grade.band, VerifiabilityBand::Partial);
        let option = match GradedQuoteOption::try_new(
            "quote-1",
            usd(1_000),
            grade,
            VerifiabilityBand::Full,
            100,
            200,
        ) {
            Ok(option) => option,
            Err(error) => panic!("option should build: {error}"),
        };
        match option.exercise(150) {
            Err(QuoteOptionError::InsufficientVerifiability { observed, minimum }) => {
                assert_eq!(observed, VerifiabilityBand::Partial);
                assert_eq!(minimum, VerifiabilityBand::Full);
            }
            other => panic!("exercise below minimum band must be denied, got {other:?}"),
        }
    }

    #[test]
    fn try_new_rejects_invalid_inputs() {
        let grade = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        match GradedQuoteOption::try_new(
            "  ",
            usd(1_000),
            grade.clone(),
            VerifiabilityBand::Unverified,
            100,
            200,
        ) {
            Err(QuoteOptionError::EmptyQuoteId) => {}
            other => panic!("empty quote id must be rejected, got {other:?}"),
        }
        match GradedQuoteOption::try_new(
            "quote-1",
            MonetaryAmount {
                units: 1_000,
                currency: "usd".to_string(),
            },
            grade.clone(),
            VerifiabilityBand::Unverified,
            100,
            200,
        ) {
            Err(QuoteOptionError::InvalidCurrency { currency }) => assert_eq!(currency, "usd"),
            other => panic!("non-canonical currency must be rejected, got {other:?}"),
        }
        match GradedQuoteOption::try_new(
            "quote-1",
            usd(1_000),
            grade,
            VerifiabilityBand::Unverified,
            200,
            200,
        ) {
            Err(QuoteOptionError::InvalidWindow {
                issued_at,
                expires_at,
            }) => {
                assert_eq!(issued_at, 200);
                assert_eq!(expires_at, 200);
            }
            other => panic!("empty last-look window must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn evidence_weights_are_all_positive() {
        for requirement in ALL_EVIDENCE {
            assert!(
                evidence_weight(requirement) > 0,
                "every evidence weight must be positive for strict monotonicity"
            );
        }
    }

    /// PR959 codex P2: an option deserialized (or directly built) past
    /// `try_new`'s checks - here with an empty `quote_id` and a lowercase
    /// currency - is rejected at exercise rather than binding a price.
    #[test]
    fn exercise_revalidates_bypassed_constructor_invariants() {
        let grade = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        let bad_currency = GradedQuoteOption {
            quote_id: "quote-1".to_string(),
            base_price: MonetaryAmount {
                units: 1_000,
                currency: "usd".to_string(),
            },
            grade: grade.clone(),
            minimum_band: VerifiabilityBand::Unverified,
            issued_at: 100,
            expires_at: 200,
        };
        match bad_currency.exercise(150) {
            Err(QuoteOptionError::InvalidCurrency { currency }) => assert_eq!(currency, "usd"),
            other => panic!("non-canonical currency must be rejected at exercise, got {other:?}"),
        }
        let empty_id = GradedQuoteOption {
            quote_id: "  ".to_string(),
            base_price: usd(1_000),
            grade,
            minimum_band: VerifiabilityBand::Unverified,
            issued_at: 100,
            expires_at: 200,
        };
        match empty_id.exercise(150) {
            Err(QuoteOptionError::EmptyQuoteId) => {}
            other => panic!("empty quote id must be rejected at exercise, got {other:?}"),
        }
    }

    /// PR959 codex P2: a hand-built grade that claims `band = Full` with
    /// `required_score = 0` (no evidence required, none verified) is internally
    /// inconsistent and cannot bind a price - exercise fails closed instead of
    /// charging the unsurcharged base at a Full minimum.
    #[test]
    fn exercise_rejects_inconsistent_grade() {
        let fabricated = VerifiabilityGrade {
            band: VerifiabilityBand::Full,
            verified_score: 0,
            required_score: 0,
            missing_evidence: Vec::new(),
        };
        assert!(!fabricated.is_internally_consistent());
        let option = GradedQuoteOption {
            quote_id: "quote-1".to_string(),
            base_price: usd(1_000),
            grade: fabricated,
            minimum_band: VerifiabilityBand::Full,
            issued_at: 100,
            expires_at: 200,
        };
        match option.exercise(150) {
            Err(QuoteOptionError::InconsistentGrade) => {}
            other => panic!("an inconsistent grade must be rejected, got {other:?}"),
        }
        // A genuine grade from the grader stays exercisable.
        let real = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        assert!(real.is_internally_consistent());
    }

    /// PR959 codex P2: a graded price that would exceed `u64::MAX` fails closed
    /// rather than saturating to `u64::MAX` and UNDER-charging the bound quote.
    #[test]
    fn exercise_rejects_overflowing_graded_price() {
        // Partial verification leaves a positive surcharge on a u64::MAX base, so
        // base + surcharge overflows u64.
        let required = [
            LiabilityEvidenceRequirement::UnderwritingDecision,
            LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        ];
        let verified = [LiabilityEvidenceRequirement::UnderwritingDecision];
        let grade = VerifiabilityGrade::from_slices(&required, &verified);
        let option = match GradedQuoteOption::try_new(
            "quote-1",
            usd(u64::MAX),
            grade,
            VerifiabilityBand::Partial,
            100,
            200,
        ) {
            Ok(option) => option,
            Err(error) => panic!("option should build: {error}"),
        };
        match option.checked_graded_price() {
            Err(QuoteOptionError::PriceOverflow) => {}
            other => panic!("overflowing checked price must fail closed, got {other:?}"),
        }
        match option.exercise(150) {
            Err(QuoteOptionError::PriceOverflow) => {}
            other => panic!("overflowing graded price must fail closed at exercise, got {other:?}"),
        }
    }

    /// PR959 codex P2 (5th re-review): `checked_graded_price` is the public
    /// fail-closed binding-price path, so it must reject an internally inconsistent
    /// grade rather than silently undercharge. A hand-built/decoded grade with
    /// `verified_score > required_score` (here required=1, verified=2) makes the
    /// missing-evidence term saturate to zero, dropping the surcharge and binding
    /// the BASE price. A direct caller that does not route through `exercise`
    /// (which validates first) would undercharge; the binding path now fails closed
    /// on the inconsistency BEFORE computing the surcharge.
    #[test]
    fn checked_graded_price_rejects_inconsistent_grade() {
        let fabricated = VerifiabilityGrade {
            // band/score are mutually inconsistent; the decisive flaw is
            // verified_score (2) exceeding required_score (1), which would
            // saturate the missing-evidence term to zero and drop the surcharge.
            band: VerifiabilityBand::Full,
            verified_score: 2,
            required_score: 1,
            missing_evidence: Vec::new(),
        };
        assert!(!fabricated.is_internally_consistent());
        let option = GradedQuoteOption {
            quote_id: "quote-1".to_string(),
            base_price: usd(1_000),
            grade: fabricated,
            minimum_band: VerifiabilityBand::Unverified,
            issued_at: 100,
            expires_at: 200,
        };
        match option.checked_graded_price() {
            Err(QuoteOptionError::InconsistentGrade) => {}
            // Must NOT return Ok(base_price): that is the undercharge this guards.
            other => {
                panic!("an inconsistent grade must fail closed, not bind a price, got {other:?}")
            }
        }
    }

    /// PR959 codex P2 (6th re-review): `checked_graded_price` is the public
    /// fail-closed binding-price path, so it must re-run EVERY constructor field
    /// invariant - not just the grade-consistency check the 5th re-review added. A
    /// hand-built/decoded option can carry a non-canonical (lowercase) currency
    /// `try_new`/`exercise` would reject; the binding path must reject it too rather
    /// than bind a price in a non-canonical currency.
    #[test]
    fn checked_graded_price_rejects_non_canonical_currency() {
        let grade = VerifiabilityGrade::from_slices(&ALL_EVIDENCE, &ALL_EVIDENCE);
        assert!(grade.is_internally_consistent());
        let option = GradedQuoteOption {
            quote_id: "quote-1".to_string(),
            base_price: MonetaryAmount {
                units: 1_000,
                currency: "usd".to_string(),
            },
            grade,
            minimum_band: VerifiabilityBand::Unverified,
            issued_at: 100,
            expires_at: 200,
        };
        match option.checked_graded_price() {
            Err(QuoteOptionError::InvalidCurrency { currency }) => assert_eq!(currency, "usd"),
            other => panic!(
                "a non-canonical base_price currency must fail closed at checked_graded_price, got {other:?}"
            ),
        }
    }
}

/// Property tests for [`VerifiabilityGrade`] (M2-11).
///
/// `proptest` is not a dev-dependency of this crate, so rather than add a new
/// dependency these tests enumerate the *entire* powerset of the evidence
/// requirements. With seven requirements that is `1 << 7 == 128` distinct
/// subsets, so every `(required, verified)` pair is one of `128 * 128 == 16_384`
/// generated input sets. Exhaustive enumeration is the strongest form of a
/// property test here: a property that holds for every pair holds universally.
#[cfg(test)]
mod property_tests {
    use super::*;

    /// Every evidence requirement, indexed so a bitmask can address each one.
    const ALL_EVIDENCE: [LiabilityEvidenceRequirement; 7] = [
        LiabilityEvidenceRequirement::BehavioralFeed,
        LiabilityEvidenceRequirement::UnderwritingDecision,
        LiabilityEvidenceRequirement::CreditProviderRiskPackage,
        LiabilityEvidenceRequirement::RuntimeAttestationAppraisal,
        LiabilityEvidenceRequirement::CertificationArtifact,
        LiabilityEvidenceRequirement::CreditBond,
        LiabilityEvidenceRequirement::AuthorizationReviewPack,
    ];

    /// Number of distinct evidence requirements. The powerset enumerated by the
    /// properties below has `1 << EVIDENCE_COUNT` members.
    const EVIDENCE_COUNT: u8 = 7;

    /// Exclusive upper bound for a subset bitmask: one past the last subset.
    const SUBSET_COUNT: u16 = 1 << EVIDENCE_COUNT;

    /// Materialise the subset of [`ALL_EVIDENCE`] selected by `mask`, in index
    /// order, as a `Vec`.
    fn subset_vec(mask: u8) -> Vec<LiabilityEvidenceRequirement> {
        (0..EVIDENCE_COUNT)
            .filter(|bit| mask & (1u8 << bit) != 0)
            .map(|bit| ALL_EVIDENCE[usize::from(bit)])
            .collect()
    }

    /// Materialise the subset of [`ALL_EVIDENCE`] selected by `mask` as a set.
    fn subset_set(mask: u8) -> BTreeSet<LiabilityEvidenceRequirement> {
        subset_vec(mask).into_iter().collect()
    }

    /// Reorder and duplicate `items` deterministically from `seed`, returning a
    /// slice whose canonical set is identical but whose order and multiplicity
    /// differ. Used to prove that grading ignores input ordering and duplicates.
    fn reorder_with_duplicates(
        items: &[LiabilityEvidenceRequirement],
        seed: u8,
    ) -> Vec<LiabilityEvidenceRequirement> {
        if items.is_empty() {
            return Vec::new();
        }
        let rotate = usize::from(seed) % items.len();
        let mut mangled = Vec::new();
        // A rotated copy: same elements, different starting point.
        for offset in 0..items.len() {
            mangled.push(items[(offset + rotate) % items.len()]);
        }
        // A reversed copy appended, so every element now appears at least twice.
        for item in items.iter().rev() {
            mangled.push(*item);
        }
        // A seed-dependent number of extra duplicates of the first element.
        for _ in 0..usize::from(seed % 3) {
            mangled.push(items[0]);
        }
        mangled
    }

    /// DETERMINISM: `grade(required, verified)` is a pure function of its two
    /// sets. Re-evaluating with identical inputs, grading the same sets through
    /// `from_slices`, and grading reordered/duplicated slices all yield an
    /// identical grade. The emitted `missing_evidence` is itself deterministic
    /// and sorted.
    #[test]
    fn property_grade_is_deterministic_over_powerset() {
        for required_mask_wide in 0..SUBSET_COUNT {
            let required_mask = required_mask_wide as u8;
            let required = subset_set(required_mask);
            let required_vec = subset_vec(required_mask);
            for verified_mask_wide in 0..SUBSET_COUNT {
                let verified_mask = verified_mask_wide as u8;
                let verified = subset_set(verified_mask);
                let verified_vec = subset_vec(verified_mask);

                let baseline = VerifiabilityGrade::grade(&required, &verified);

                // Re-evaluating the same inputs is identical.
                assert_eq!(
                    baseline,
                    VerifiabilityGrade::grade(&required, &verified),
                    "grade must be a pure function of its inputs"
                );

                // Grading the same sets via the slice entry point is identical.
                assert_eq!(
                    baseline,
                    VerifiabilityGrade::from_slices(&required_vec, &verified_vec),
                    "from_slices must agree with grade on the same sets"
                );

                // Reordered and duplicated inputs grade identically.
                let seed = required_mask ^ verified_mask;
                let mangled_required = reorder_with_duplicates(&required_vec, seed);
                let mangled_verified = reorder_with_duplicates(&verified_vec, seed.rotate_left(3));
                let reordered =
                    VerifiabilityGrade::from_slices(&mangled_required, &mangled_verified);
                assert_eq!(
                    baseline, reordered,
                    "ordering and duplicates must not change the grade \
                     (required {required_mask:#010b}, verified {verified_mask:#010b})"
                );

                // Missing evidence is emitted in deterministic sorted order.
                let mut sorted_missing = baseline.missing_evidence.clone();
                sorted_missing.sort();
                assert_eq!(
                    baseline.missing_evidence, sorted_missing,
                    "missing evidence must be deterministic and sorted"
                );
            }
        }
    }

    /// STRICT-LOWER MONOTONICITY (removal): dropping a verified item that is also
    /// required yields a strictly lower grade. The verified score falls by
    /// exactly that item's weight, the dropped item resurfaces as missing
    /// evidence, and the band can never rise.
    #[test]
    fn property_removing_required_verified_item_strictly_lowers_grade() {
        for required_mask_wide in 1..SUBSET_COUNT {
            let required_mask = required_mask_wide as u8;
            let required = subset_set(required_mask);
            for verified_mask_wide in 0..SUBSET_COUNT {
                let verified_mask = verified_mask_wide as u8;
                let verified = subset_set(verified_mask);
                let fuller = VerifiabilityGrade::grade(&required, &verified);

                for bit in 0..EVIDENCE_COUNT {
                    let item_mask = 1u8 << bit;
                    let in_required = required_mask & item_mask != 0;
                    let in_verified = verified_mask & item_mask != 0;
                    // Only items that are both required and verified are eligible
                    // to be dropped: those are the ones contributing to the score.
                    if !(in_required && in_verified) {
                        continue;
                    }
                    let removed = ALL_EVIDENCE[usize::from(bit)];
                    let lesser_set = subset_set(verified_mask & !item_mask);
                    let lesser = VerifiabilityGrade::grade(&required, &lesser_set);

                    assert!(
                        lesser < fuller,
                        "dropping required+verified {removed:?} must strictly lower \
                         the grade: {lesser:?} !< {fuller:?}"
                    );
                    assert!(
                        lesser.verified_score < fuller.verified_score,
                        "dropping {removed:?} must strictly lower the verified score"
                    );
                    assert_eq!(
                        fuller.verified_score - lesser.verified_score,
                        evidence_weight(removed),
                        "the verified score must fall by exactly the removed weight"
                    );
                    assert!(
                        lesser.missing_evidence.contains(&removed),
                        "the dropped item must resurface as missing evidence"
                    );
                    assert!(
                        lesser.band <= fuller.band,
                        "removing verification can never raise the band"
                    );
                    assert_eq!(
                        lesser.required_score, fuller.required_score,
                        "the requirement set is unchanged, so required_score holds"
                    );
                }
            }
        }
    }

    /// MONOTONICITY (addition): adding a verified item never lowers the grade.
    /// Adding a *required* item strictly raises it; adding a non-required item
    /// leaves the grade untouched. The band and verified score are likewise
    /// non-decreasing.
    #[test]
    fn property_adding_verified_item_never_lowers_grade() {
        for required_mask_wide in 0..SUBSET_COUNT {
            let required_mask = required_mask_wide as u8;
            let required = subset_set(required_mask);
            for verified_mask_wide in 0..SUBSET_COUNT {
                let verified_mask = verified_mask_wide as u8;
                let verified = subset_set(verified_mask);
                let base = VerifiabilityGrade::grade(&required, &verified);

                for bit in 0..EVIDENCE_COUNT {
                    let item_mask = 1u8 << bit;
                    if verified_mask & item_mask != 0 {
                        continue; // already verified
                    }
                    let added = ALL_EVIDENCE[usize::from(bit)];
                    let richer_set = subset_set(verified_mask | item_mask);
                    let richer = VerifiabilityGrade::grade(&required, &richer_set);

                    assert!(
                        richer >= base,
                        "adding verified {added:?} must never lower the grade: \
                         {richer:?} < {base:?}"
                    );
                    assert!(
                        richer.verified_score >= base.verified_score,
                        "adding verified evidence must never lower the verified score"
                    );
                    assert!(
                        richer.band >= base.band,
                        "adding verified evidence must never lower the band"
                    );

                    if required_mask & item_mask != 0 {
                        assert!(
                            richer > base,
                            "adding a required+verified item must strictly raise \
                             the grade: {richer:?} !> {base:?}"
                        );
                    } else {
                        assert_eq!(
                            richer, base,
                            "adding non-required evidence must not change the grade"
                        );
                    }
                }
            }
        }
    }

    /// DOMINANCE: full verification strictly dominates every partial
    /// verification of the same requirement set. A verification is full exactly
    /// when it covers every required item; every other verification grades
    /// strictly lower than the fully verified grade.
    #[test]
    fn property_full_verification_strictly_dominates_every_partial() {
        for required_mask_wide in 1..SUBSET_COUNT {
            let required_mask = required_mask_wide as u8;
            let required = subset_set(required_mask);

            // Full verification: every required item is verified.
            let full = VerifiabilityGrade::grade(&required, &required);
            assert!(full.is_fully_verified());
            assert_eq!(full.band, VerifiabilityBand::Full);
            assert!(full.missing_evidence.is_empty());
            assert_eq!(full.verified_score, full.required_score);

            for verified_mask_wide in 0..SUBSET_COUNT {
                let verified_mask = verified_mask_wide as u8;
                // `verified` is a full verification exactly when it covers every
                // required item; skip those and test only genuine partials.
                let covers_all_required = required_mask & verified_mask == required_mask;
                if covers_all_required {
                    continue;
                }
                let verified = subset_set(verified_mask);
                let partial = VerifiabilityGrade::grade(&required, &verified);

                assert!(
                    partial < full,
                    "full verification must strictly dominate partial: \
                     {partial:?} !< {full:?}"
                );
                assert!(
                    !partial.is_fully_verified(),
                    "a verification missing required evidence is not full"
                );
                assert!(
                    partial.verified_score < full.verified_score,
                    "partial verification must score strictly below full"
                );
                assert!(
                    !partial.missing_evidence.is_empty(),
                    "a partial verification must report missing evidence"
                );
            }
        }
    }
}
