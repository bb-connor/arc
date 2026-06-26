//! Pass portable-reputation eligibility + trust-tier reconciliation bound to the
//! shipped provider-admission substrate (M1-16, WS-PASS-ELIG).
//!
//! This module is ADDITIVE: it does not re-derive a parallel tier or selection
//! path. Pass portable-reputation eligibility is obtained by routing through the
//! already-shipped [`crate::artifacts::validate_reputation_import`] gate (a
//! trusted issuer, an `accepted` import verdict, a non-empty `subject_binding_ref`
//! and a policy-capped `local_weight`), and the Pass coarse trust tier is
//! reconciled from the SAME [`TrustScorecardSnapshot`] `computed_score` that
//! `validate_selection` already binds into the order context. There is no second
//! authority and no green-field spine: the only verification authority is the
//! market-authority kernel-key set the trust-market verifier already pins.
//!
//! ELIGIBILITY != SOLVENCY. Portable reputation can never become a
//! collateral/solvency claim. The substrate gate refuses any reputation import
//! whose declared `usage` is not `scoring_input`, and the eligibility value
//! produced here is structurally incapable of carrying capital: it exposes only a
//! subject, the order/discovery/selection ids it is bound to, the policy-capped
//! reputation weight and the reconciled coarse tier. Collateral and solvency
//! continue to flow exclusively from the collateral-position / guarantee /
//! jurisdiction artifacts, never from a reputation import.

use chio_credentials::{synthesize_trust_tier, TrustTier};
use chio_transaction_passport::TransactionPassportError;

use crate::artifacts::{
    validate_reputation_import, ProviderDiscoverySnapshot, ProviderSelectionReport,
    ReputationImportReport, TrustScorecardSnapshot,
};

/// The compliance-score scale (0..=`PASS_COMPLIANCE_SCALE_MAX`) that the Pass
/// [`synthesize_trust_tier`] thresholds (`TRUST_TIER_ATTESTED_MIN` etc.) are
/// expressed against. A scorecard `computed_score` lives on its own
/// `[score_floor, score_ceiling]` range, so reconciliation projects it onto this
/// scale before reusing the canonical Pass tier function. The two tier notions
/// therefore cannot fork: there is a single tier function and a single, pinned
/// projection.
pub const PASS_COMPLIANCE_SCALE_MAX: u64 = 1000;

/// Pass portable-reputation eligibility derived from the provider-admission
/// substrate.
///
/// This value is produced ONLY after the reputation import clears
/// [`validate_reputation_import`], so a present `PassReputationEligibility` is a
/// proof that a trusted issuer's `accepted` import was bound to the subject under
/// a policy-capped weight. It deliberately carries no collateral, solvency,
/// capital, coverage or premium field: eligibility is never a solvency claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassReputationEligibility {
    /// The provider/subject DID the eligibility is scoped to (the scorecard
    /// subject, which `validate_selection` binds to the selected provider).
    pub subject: String,
    /// The order id the eligibility is bound to (the selection report order id,
    /// which `validate_selection` binds to the discovery snapshot order id).
    pub order_id: String,
    /// The discovery snapshot the selection (and therefore this eligibility) is
    /// bound to.
    pub discovery_snapshot_ref: String,
    /// The selection report the eligibility is bound to.
    pub selection_report_ref: String,
    /// The policy-capped portable-reputation weight that fed the local scorecard.
    /// Never a capital amount; bounded by the verifier policy
    /// `max_reputation_import_weight`.
    pub capped_local_weight: u64,
    /// The coarse Pass [`TrustTier`] reconciled from the scorecard
    /// `computed_score`. Governs allotment SIZE/refill only; never a solvency
    /// signal.
    pub reconciled_trust_tier: TrustTier,
}

/// Reconcile a scorecard `computed_score` to the coarse Pass [`TrustTier`].
///
/// The scorecard score lives on its own `[score_floor, score_ceiling]` range; this
/// projects it onto the 0..=[`PASS_COMPLIANCE_SCALE_MAX`] compliance scale and
/// reuses the canonical Pass [`synthesize_trust_tier`] so the marketplace tier and
/// the Pass tier are the SAME function of the SAME score and cannot fork.
/// `behavioral_anomaly` is threaded straight through to `synthesize_trust_tier`,
/// where it blocks the jump to `Premier`.
///
/// # Errors
///
/// Fails closed when the scorecard range is degenerate (`score_floor >=
/// score_ceiling`) or when `computed_score` lies outside `[score_floor,
/// score_ceiling]`.
pub fn reconcile_pass_trust_tier(
    computed_score: u64,
    score_floor: u64,
    score_ceiling: u64,
    behavioral_anomaly: bool,
) -> Result<TrustTier, TransactionPassportError> {
    if score_floor >= score_ceiling {
        return Err(claim_failed(
            "scorecard range is invalid for Pass trust-tier reconciliation",
        ));
    }
    if computed_score < score_floor || computed_score > score_ceiling {
        return Err(claim_failed(
            "scorecard computed score outside range for Pass trust-tier reconciliation",
        ));
    }
    let span = score_ceiling - score_floor;
    let offset = computed_score - score_floor;
    // offset <= span, so the projected value never exceeds PASS_COMPLIANCE_SCALE_MAX.
    let compliance_score = offset.saturating_mul(PASS_COMPLIANCE_SCALE_MAX) / span;
    let compliance_score = u32::try_from(compliance_score).map_err(|_| {
        claim_failed("projected compliance score overflows the Pass trust-tier scale")
    })?;
    Ok(synthesize_trust_tier(compliance_score, behavioral_anomaly))
}

/// Reconcile a CLAIMED Pass [`TrustTier`] against the scorecard `computed_score`,
/// rejecting fail-closed when the claim forks the reconciled tier.
///
/// This is the guard that stops the Pass-side tier and the marketplace scorecard
/// from diverging: a Pass that asserts a tier the scorecard score does not support
/// is rejected rather than honoured.
///
/// # Errors
///
/// Propagates [`reconcile_pass_trust_tier`] range errors, and fails closed when
/// `claimed_tier` differs from the reconciled tier.
pub fn reconcile_claimed_pass_trust_tier(
    computed_score: u64,
    score_floor: u64,
    score_ceiling: u64,
    behavioral_anomaly: bool,
    claimed_tier: TrustTier,
) -> Result<TrustTier, TransactionPassportError> {
    let reconciled = reconcile_pass_trust_tier(
        computed_score,
        score_floor,
        score_ceiling,
        behavioral_anomaly,
    )?;
    if reconciled != claimed_tier {
        return Err(claim_failed(format!(
            "Pass trust tier {} forks scorecard computed score (reconciles to {})",
            claimed_tier.label(),
            reconciled.label()
        )));
    }
    Ok(reconciled)
}

/// Reconcile the coarse Pass [`TrustTier`] for a verified scorecard, binding the
/// behavioral-anomaly signal to the scorecard's own `downgrade_reasons`: a
/// downgraded scorecard carries an anomaly and so can never reconcile to
/// `Premier`.
pub(super) fn reconcile_pass_trust_tier_for_scorecard(
    scorecard: &TrustScorecardSnapshot,
) -> Result<TrustTier, TransactionPassportError> {
    let behavioral_anomaly = !scorecard.downgrade_reasons.is_empty();
    reconcile_pass_trust_tier(
        scorecard.computed_score,
        scorecard.score_floor,
        scorecard.score_ceiling,
        behavioral_anomaly,
    )
}

/// Route Pass portable-reputation eligibility through the shipped
/// provider-admission reputation gate and reconcile the coarse Pass tier.
///
/// The reputation import is first put through
/// [`validate_reputation_import`] (trusted issuer, `accepted` verdict,
/// subject binding, capped weight, `scoring_input`-only usage); only then is the
/// eligibility assembled and the tier reconciled from the same scorecard score the
/// selection is bound to. This is the single point through which Pass eligibility
/// is admitted: there is no parallel admission path.
///
/// # Errors
///
/// Propagates the [`validate_reputation_import`] fail-closed errors (including the
/// "reputation import cannot prove collateral or solvency" refusal) and the
/// [`reconcile_pass_trust_tier`] range errors.
pub(super) fn evaluate_pass_reputation_eligibility(
    discovery: &ProviderDiscoverySnapshot,
    selection: &ProviderSelectionReport,
    reputation_import: &ReputationImportReport,
    scorecard: &TrustScorecardSnapshot,
    max_reputation_import_weight: u64,
) -> Result<PassReputationEligibility, TransactionPassportError> {
    validate_reputation_import(reputation_import, scorecard, max_reputation_import_weight)?;
    let reconciled_trust_tier = reconcile_pass_trust_tier_for_scorecard(scorecard)?;
    Ok(PassReputationEligibility {
        subject: scorecard.subject.clone(),
        order_id: selection.order_id.clone(),
        discovery_snapshot_ref: discovery.id.clone(),
        selection_report_ref: selection.id.clone(),
        capped_local_weight: reputation_import.local_weight,
        reconciled_trust_tier,
    })
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::TrustMarketClaimFailed(message.into())
}
