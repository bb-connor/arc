//! Pure helpers shared by runtime code and formal verification lanes.
//!
//! This module deliberately avoids heap allocation, IO, crypto, async, and
//! external crates so Kani, Creusot wrappers, and Aeneas can reason about the
//! same branch logic used by the portable kernel core.

use crate::formal_aeneas;

/// Time-window classification for capability validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeWindowStatus {
    /// `issued_at <= now < expires_at`.
    Valid,
    /// `now < issued_at`.
    NotYetValid,
    /// `now >= expires_at`.
    Expired,
}

/// Classify a capability time window at `now`.
#[must_use]
pub fn classify_time_window(now: u64, issued_at: u64, expires_at: u64) -> TimeWindowStatus {
    match formal_aeneas::classify_time_window_code(now, issued_at, expires_at) {
        0 => TimeWindowStatus::Valid,
        1 => TimeWindowStatus::NotYetValid,
        _ => TimeWindowStatus::Expired,
    }
}

/// Predicate form of [`classify_time_window`].
#[must_use]
#[allow(dead_code)]
pub fn time_window_valid(now: u64, issued_at: u64, expires_at: u64) -> bool {
    matches!(
        classify_time_window(now, issued_at, expires_at),
        TimeWindowStatus::Valid
    )
}

/// Exact match with `*` parent wildcard.
#[must_use]
pub fn exact_or_wildcard_covers(parent: &str, child: &str) -> bool {
    formal_aeneas::exact_or_wildcard_covers_by_flags(parent == "*", parent == child)
}

/// Exact match, `*`, or parent suffix wildcard (`prefix*`) coverage.
#[must_use]
pub fn prefix_wildcard_or_exact_covers(parent: &str, child: &str) -> bool {
    let parent_is_wildcard = parent == "*";
    let parent_prefix = parent.strip_suffix('*');
    let parent_has_prefix_wildcard = parent_prefix.is_some();
    let prefix_matches = parent_prefix.is_some_and(|prefix| child.starts_with(prefix));
    formal_aeneas::prefix_wildcard_or_exact_covers_by_flags(
        parent_is_wildcard,
        parent_has_prefix_wildcard,
        prefix_matches,
        parent == child,
    )
}

/// Optional u32 cap subset predicate.
///
/// If the parent has no cap, every child cap state is a subset. If the parent
/// has a cap, the child must also have one and it must be no larger.
#[must_use]
pub fn optional_u32_cap_is_subset(
    child_has_cap: bool,
    child_value: u32,
    parent_has_cap: bool,
    parent_value: u32,
) -> bool {
    formal_aeneas::optional_u32_cap_is_subset(
        child_has_cap,
        child_value,
        parent_has_cap,
        parent_value,
    )
}

/// Required-true preservation for boolean constraints such as DPoP.
#[must_use]
pub fn required_true_is_preserved(parent_requires_true: bool, child_requires_true: bool) -> bool {
    formal_aeneas::required_true_is_preserved(parent_requires_true, child_requires_true)
}

/// Optional monetary cap subset predicate with currency equality projected by
/// the caller.
#[must_use]
pub fn monetary_cap_is_subset_by_parts(
    child_has_cap: bool,
    child_units: u64,
    parent_has_cap: bool,
    parent_units: u64,
    currency_matches: bool,
) -> bool {
    formal_aeneas::monetary_cap_is_subset_by_parts(
        child_has_cap,
        child_units,
        parent_has_cap,
        parent_units,
        currency_matches,
    )
}

/// Bounded budget precheck used by the Lean model, Kani harnesses, and
/// Creusot wrapper contracts.
#[must_use]
pub fn budget_precheck(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> bool {
    formal_aeneas::budget_precheck(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    )
}

/// Result of a pure budget commit model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetCommitResult {
    pub accepted: bool,
    pub remaining_invocations: u64,
    pub remaining_units: u64,
}

/// Commit against the bounded budget model.
#[must_use]
pub fn budget_commit(
    remaining_invocations: u64,
    remaining_units: u64,
    invocation_cost: u64,
    unit_cost: u64,
) -> BudgetCommitResult {
    let committed = formal_aeneas::budget_commit(
        remaining_invocations,
        remaining_units,
        invocation_cost,
        unit_cost,
    );
    BudgetCommitResult {
        accepted: committed.accepted,
        remaining_invocations: committed.remaining_invocations,
        remaining_units: committed.remaining_units,
    }
}

/// Failure produced while projecting runtime budget state into the bounded
/// admission model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAdmissionProjectionError {
    /// Adding the requested cost to the committed total overflowed `u64`.
    TotalCostOverflow,
}

/// Project an invocation counter and optional cap into the bounded budget
/// admission predicate used by production budget stores.
#[must_use]
pub fn budget_increment_admits(invocation_count: u32, max_invocations: Option<u32>) -> bool {
    max_invocations.is_none_or(|max| {
        budget_precheck(
            u64::from(max.saturating_sub(invocation_count)),
            u64::MAX,
            1,
            0,
        )
    })
}

/// Project a production budget row and optional caps into the bounded budget
/// admission predicates.
///
/// The overflow result is distinct from a cap denial so callers retain their
/// existing fail-closed error attribution.
pub fn budget_charge_admits(
    invocation_count: u32,
    committed_cost_units: u64,
    cost_units: u64,
    max_invocations: Option<u32>,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
) -> Result<bool, BudgetAdmissionProjectionError> {
    let invocation_allowed = max_invocations.is_none_or(|max| {
        budget_commit(
            u64::from(max.saturating_sub(invocation_count)),
            u64::MAX,
            1,
            0,
        )
        .accepted
    });
    let per_invocation_allowed = max_cost_per_invocation
        .is_none_or(|max| budget_commit(u64::MAX, max, 0, cost_units).accepted);
    let total_allowed = match max_total_cost_units {
        Some(max_total) => {
            let new_total = committed_cost_units
                .checked_add(cost_units)
                .ok_or(BudgetAdmissionProjectionError::TotalCostOverflow)?;
            committed_cost_units <= max_total
                && budget_commit(
                    u64::MAX,
                    max_total.saturating_sub(committed_cost_units),
                    0,
                    cost_units,
                )
                .accepted
                && new_total <= max_total
        }
        None => true,
    };

    Ok(invocation_allowed && per_invocation_allowed && total_allowed)
}

/// DPoP freshness window check with saturating arithmetic.
#[must_use]
pub fn dpop_freshness_valid(now: u64, issued_at: u64, ttl_secs: u64, max_skew_secs: u64) -> bool {
    formal_aeneas::dpop_freshness_valid(now, issued_at, ttl_secs, max_skew_secs)
}

/// DPoP admission model for grant-required proof checks.
#[must_use]
pub fn dpop_admits(
    dpop_required: bool,
    proof_present: bool,
    proof_valid: bool,
    nonce_fresh: bool,
) -> bool {
    formal_aeneas::dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh)
}

/// Project the atomic production verifier result into the four-axis DPoP
/// admission model.
#[must_use]
pub fn dpop_verification_admits(
    dpop_required: bool,
    proof_present: bool,
    verification_succeeded: bool,
) -> bool {
    dpop_admits(
        dpop_required,
        proof_present,
        verification_succeeded,
        verification_succeeded,
    )
}

/// Nonce model: an already-live nonce must not be accepted again.
#[must_use]
pub fn nonce_admits(already_live: bool) -> bool {
    formal_aeneas::nonce_admits(already_live)
}

/// Guard outcome used by the pure guard-composition model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardStep {
    Allow,
    Deny,
    Error,
}

impl From<crate::Verdict> for GuardStep {
    fn from(verdict: crate::Verdict) -> Self {
        match verdict {
            crate::Verdict::Allow => Self::Allow,
            crate::Verdict::Deny => Self::Deny,
            crate::Verdict::PendingApproval => Self::Error,
        }
    }
}

/// Guard pipeline model. Core authorization must pass, and every guard must
/// return allow. Deny and error are both fail-closed.
#[must_use]
pub fn guard_pipeline_allows(core_authorized: bool, guards: &[GuardStep]) -> bool {
    guards.iter().fold(core_authorized, |allowed, guard| {
        formal_aeneas::guard_step_allows(allowed, matches!(guard, GuardStep::Allow))
    })
}

/// Decide whether one projected guard result permits pipeline continuation.
#[must_use]
pub fn guard_step_admits(step: GuardStep) -> bool {
    guard_pipeline_allows(true, core::slice::from_ref(&step))
}

/// Require the verified projection and the observed guard step to agree before
/// runtime continuation. A mismatched allow result remains fail-closed.
#[must_use]
pub fn guard_projection_allows_continuation(
    projected_allows: bool,
    observed_step: GuardStep,
) -> bool {
    projected_allows && matches!(observed_step, GuardStep::Allow)
}

/// Runtime branch represented by a revocation lookup result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationCheckTarget {
    /// The capability presented for dispatch.
    PresentedToken,
    /// One capability in the presented delegation chain.
    Ancestor,
}

/// Revocation projection model for the presented token and its ancestors.
#[must_use]
pub fn revocation_snapshot_denies(token_revoked: bool, ancestor_revoked: bool) -> bool {
    formal_aeneas::revocation_snapshot_denies(token_revoked, ancestor_revoked)
}

/// Project one production revocation lookup into the verified snapshot
/// predicate while preserving lazy lookup and error attribution.
#[must_use]
pub fn revocation_lookup_denies(target: RevocationCheckTarget, is_revoked: bool) -> bool {
    match target {
        RevocationCheckTarget::PresentedToken => revocation_snapshot_denies(is_revoked, false),
        RevocationCheckTarget::Ancestor => revocation_snapshot_denies(false, is_revoked),
    }
}

/// Receipt coupling model for the fields that make a decision auditable.
#[must_use]
pub fn receipt_fields_coupled(
    capability_matches: bool,
    request_matches: bool,
    verdict_matches: bool,
    policy_hash_matches: bool,
    evidence_class_matches: bool,
) -> bool {
    formal_aeneas::receipt_fields_coupled(
        capability_matches,
        request_matches,
        verdict_matches,
        policy_hash_matches,
        evidence_class_matches,
    )
}

/// Result of a bounded three-key composite quota authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositeQuotaResult {
    pub accepted: bool,
    pub captured: [u8; 3],
}

/// Authorize one invocation against every applicable quota or none.
#[must_use]
pub fn composite_quota_authorize(
    captured: [u8; 3],
    maximum: [u8; 3],
    applicable: [bool; 3],
) -> CompositeQuotaResult {
    let mut next = captured;
    for index in 0..3 {
        if !applicable[index] {
            continue;
        }
        let Some(value) = captured[index].checked_add(1) else {
            return CompositeQuotaResult {
                accepted: false,
                captured,
            };
        };
        if value > maximum[index] {
            return CompositeQuotaResult {
                accepted: false,
                captured,
            };
        }
        next[index] = value;
    }
    CompositeQuotaResult {
        accepted: true,
        captured: next,
    }
}

/// Existing quota keys preserve the maximum established on first use.
#[must_use]
pub const fn quota_maximum_compatible(
    initialized: bool,
    existing_maximum: u8,
    presented_maximum: u8,
) -> bool {
    !initialized || existing_maximum == presented_maximum
}

/// Projection of the signed family-binding preservation predicate.
#[must_use]
pub const fn family_binding_preserved(
    fields_match: [bool; 8],
    root_maximum: u8,
    descendant_maximum: u8,
) -> bool {
    fields_match[0]
        && fields_match[1]
        && fields_match[2]
        && fields_match[3]
        && fields_match[4]
        && fields_match[5]
        && fields_match[6]
        && fields_match[7]
        && root_maximum == descendant_maximum
}

/// Count distinct eligible signer IDs in a bounded three-token approval set.
#[must_use]
pub fn threshold_distinct_eligible_signers(
    signer_ids: [u8; 3],
    present: [bool; 3],
    eligible: [bool; 3],
) -> u8 {
    let mut seen = [false; 3];
    let mut count = 0_u8;
    for index in 0..3 {
        if !present[index] {
            continue;
        }
        let signer = usize::from(signer_ids[index]);
        if signer >= eligible.len() || !eligible[signer] || seen[signer] {
            continue;
        }
        seen[signer] = true;
        count += 1;
    }
    count
}

/// Result of one bounded composite invocation-quota authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompositeQuotaAuthorization {
    pub accepted: bool,
    pub counts: [u32; 3],
}

/// Atomically reserve one unit from every applicable quota.
///
/// Corrupt pre-state and exhaustion both fail without changing any count.
#[must_use]
pub fn authorize_composite_quotas(
    counts: [u32; 3],
    maxima: [u32; 3],
    applicable: [bool; 3],
) -> CompositeQuotaAuthorization {
    let mut accepted = true;
    let mut index = 0;
    while index < counts.len() {
        if counts[index] > maxima[index] || (applicable[index] && counts[index] >= maxima[index]) {
            accepted = false;
        }
        index += 1;
    }

    if !accepted {
        return CompositeQuotaAuthorization {
            accepted: false,
            counts,
        };
    }

    let mut next = counts;
    let mut index = 0;
    while index < next.len() {
        if applicable[index] {
            next[index] += 1;
        }
        index += 1;
    }

    CompositeQuotaAuthorization {
        accepted: true,
        counts: next,
    }
}

/// Result of presenting an immutable maximum for one quota key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaMaximumAdmission {
    pub accepted: bool,
    pub maximum: u32,
}

/// Admit a quota maximum without permitting an existing key to change it.
#[must_use]
pub fn admit_quota_maximum(
    key_exists: bool,
    stored_maximum: u32,
    presented_maximum: u32,
) -> QuotaMaximumAdmission {
    if key_exists && stored_maximum != presented_maximum {
        QuotaMaximumAdmission {
            accepted: false,
            maximum: stored_maximum,
        }
    } else {
        QuotaMaximumAdmission {
            accepted: true,
            maximum: if key_exists {
                stored_maximum
            } else {
                presented_maximum
            },
        }
    }
}

/// Result of one invocation-reservation capture in the bounded model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvocationCapture {
    pub accepted: bool,
    pub count: u32,
}

/// Capture one invocation without decreasing or exceeding the signed maximum.
#[must_use]
pub fn capture_invocation_count(count: u32, maximum: u32) -> InvocationCapture {
    let Some(next) = count.checked_add(1) else {
        return InvocationCapture {
            accepted: false,
            count,
        };
    };
    if count > maximum || next > maximum {
        InvocationCapture {
            accepted: false,
            count,
        }
    } else {
        InvocationCapture {
            accepted: true,
            count: next,
        }
    }
}

/// Result of reserving one replay fingerprint in a bounded set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayFingerprintReservation {
    pub accepted: bool,
    pub fingerprints: [u8; 4],
    pub count: u8,
}

/// Insert a fingerprint exactly once into a bounded replay set.
#[must_use]
pub fn reserve_replay_fingerprint(
    fingerprints: [u8; 4],
    count: u8,
    candidate: u8,
) -> ReplayFingerprintReservation {
    if count > 4 {
        return ReplayFingerprintReservation {
            accepted: false,
            fingerprints,
            count,
        };
    }

    let mut index = 0_usize;
    while index < usize::from(count) {
        if fingerprints[index] == candidate {
            return ReplayFingerprintReservation {
                accepted: false,
                fingerprints,
                count,
            };
        }

        let mut prior = 0_usize;
        while prior < index {
            if fingerprints[prior] == fingerprints[index] {
                return ReplayFingerprintReservation {
                    accepted: false,
                    fingerprints,
                    count,
                };
            }
            prior += 1;
        }
        index += 1;
    }

    if count == 4 {
        return ReplayFingerprintReservation {
            accepted: false,
            fingerprints,
            count,
        };
    }

    let mut next = fingerprints;
    next[usize::from(count)] = candidate;
    ReplayFingerprintReservation {
        accepted: true,
        fingerprints: next,
        count: count + 1,
    }
}

/// Authenticated fields required to preserve a delegation-family quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyBindingPreservation {
    pub root_binding_matches: bool,
    pub root_capability_matches: bool,
    pub root_subject_matches: bool,
    pub root_scope_matches: bool,
    pub descendant_expiry_within_root: bool,
    pub parent_maximum: u32,
    pub descendant_maximum: u32,
}

/// Require exact family authority and immutable-maximum preservation.
#[must_use]
pub fn family_binding_is_preserved(binding: FamilyBindingPreservation) -> bool {
    binding.root_binding_matches
        && binding.root_capability_matches
        && binding.root_subject_matches
        && binding.root_scope_matches
        && binding.descendant_expiry_within_root
        && binding.parent_maximum == binding.descendant_maximum
}

/// Result of bounded threshold signer validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdSignerValidation {
    pub valid: bool,
    pub accepted: bool,
    pub distinct_signers: u8,
}

/// Validate a bounded signer list against a bounded eligible-key set.
///
/// Both slices are represented as fixed arrays plus lengths so the same
/// routine remains tractable for bounded model checking. Duplicate or
/// ineligible signers invalidate the complete set.
#[must_use]
pub fn validate_threshold_signers(
    signers: [u8; 4],
    signer_count: u8,
    eligible: [u8; 4],
    eligible_count: u8,
    required: u8,
) -> ThresholdSignerValidation {
    if signer_count > 4 || eligible_count > 4 || required == 0 {
        return ThresholdSignerValidation {
            valid: false,
            accepted: false,
            distinct_signers: 0,
        };
    }

    let mut distinct_signers = 0_u8;
    let mut signer_index = 0_usize;
    while signer_index < usize::from(signer_count) {
        let signer = signers[signer_index];
        let mut is_eligible = false;
        let mut eligible_index = 0_usize;
        while eligible_index < usize::from(eligible_count) {
            if eligible[eligible_index] == signer {
                is_eligible = true;
            }
            eligible_index += 1;
        }

        let mut duplicate = false;
        let mut prior_index = 0_usize;
        while prior_index < signer_index {
            if signers[prior_index] == signer {
                duplicate = true;
            }
            prior_index += 1;
        }

        if !is_eligible || duplicate {
            return ThresholdSignerValidation {
                valid: false,
                accepted: false,
                distinct_signers,
            };
        }

        distinct_signers += 1;
        signer_index += 1;
    }

    ThresholdSignerValidation {
        valid: true,
        accepted: distinct_signers >= required,
        distinct_signers,
    }
}

#[cfg(test)]
mod protocol_primitive_tests {
    use super::{
        admit_quota_maximum, authorize_composite_quotas, capture_invocation_count,
        family_binding_is_preserved, reserve_replay_fingerprint, validate_threshold_signers,
        FamilyBindingPreservation,
    };

    #[test]
    fn composite_quota_authorization_changes_every_applicable_count_or_none() {
        let accepted = authorize_composite_quotas([0, 1, 4], [1, 2, 5], [true; 3]);
        assert!(accepted.accepted);
        assert_eq!(accepted.counts, [1, 2, 5]);

        let denied = authorize_composite_quotas([0, 2, 4], [1, 2, 5], [true; 3]);
        assert!(!denied.accepted);
        assert_eq!(denied.counts, [0, 2, 4]);
    }

    #[test]
    fn family_maximum_and_threshold_signers_are_authority_bound() {
        assert!(!family_binding_is_preserved(FamilyBindingPreservation {
            root_binding_matches: true,
            root_capability_matches: true,
            root_subject_matches: true,
            root_scope_matches: true,
            descendant_expiry_within_root: true,
            parent_maximum: 3,
            descendant_maximum: 2,
        }));

        let maximum = admit_quota_maximum(true, 3, 2);
        assert!(!maximum.accepted);
        assert_eq!(maximum.maximum, 3);

        let threshold = validate_threshold_signers([7, 7, 0, 0], 2, [7, 8, 0, 0], 2, 2);
        assert!(!threshold.valid);
        assert!(!threshold.accepted);
    }

    #[test]
    fn captured_invocation_count_is_monotonic_and_bounded() {
        let captured = capture_invocation_count(2, 3);
        assert!(captured.accepted);
        assert_eq!(captured.count, 3);

        let exhausted = capture_invocation_count(3, 3);
        assert!(!exhausted.accepted);
        assert_eq!(exhausted.count, 3);

        let corrupt = capture_invocation_count(4, 3);
        assert!(!corrupt.accepted);
        assert_eq!(corrupt.count, 4);
    }

    #[test]
    fn replay_fingerprint_reservation_is_unique() {
        let reserved = reserve_replay_fingerprint([7, 9, 0, 0], 2, 11);
        assert!(reserved.accepted);
        assert_eq!(reserved.count, 3);
        assert_eq!(reserved.fingerprints, [7, 9, 11, 0]);

        let duplicate = reserve_replay_fingerprint([7, 9, 0, 0], 2, 9);
        assert!(!duplicate.accepted);
        assert_eq!(duplicate.count, 2);
        assert_eq!(duplicate.fingerprints, [7, 9, 0, 0]);

        let full = reserve_replay_fingerprint([1, 2, 3, 4], 4, 5);
        assert!(!full.accepted);
        assert_eq!(full.count, 4);
        assert_eq!(full.fingerprints, [1, 2, 3, 4]);
    }
}
