# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 2 Synthesis

- **Timestamp**: `20261025-003540 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1661.41s` across 4 parallel passes
- **Total Output**: `166,733` characters (`20,480` words)
- **Claude Max Quota Before Wave 2**: 5-hour `32.0%` | 7-day `77.0%`
- **Claude Max Quota After Wave 2**: 5-hour `39.0%` | 7-day `78.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave2_angle_1_slice_p1_formal_core_and_aeneas_exact_spec` | `0` | `success (completed treatise in pass 1)` | `['claude-fable-5-1']` | `none` | `4,042` | `34,994` | `1661.39` |
| `wave2_angle_2_slice_p2_two_phase_guard_optimal_stopping` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,419` | `37,582` | `886.9` |
| `wave2_angle_3_slice_p3_copley_composer_and_receipt_witness` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,516` | `44,673` | `746.51` |
| `wave2_angle_4_cross_workstream_unification` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6,503` | `49,484` | `495.12` |

---

# Verbatim Treatise - `wave2_angle_1_slice_p1_formal_core_and_aeneas_exact_spec`

## P1.1 Seam contract

Nothing above the marker `// ---- Slice P1 (additive) ----` in `formal_aeneas.rs` or `formal_core.rs` changes. `ledger_apply`, `classify_time_window_code`, `budget_precheck`, `budget_commit`, and `receipt_fields_coupled` keep their signatures and bodies, so `formal/proof-manifest.toml` and `formal/lean4/Chio/` only gain new obligations. Every new scalar below is total, panic-free, and uses only `checked_*`, `saturating_*`, `u32::from`/`i64::from` widening, and `TryFrom` narrowing. Lean models use `Nat`, whose truncated subtraction coincides with `saturating_sub` on the reachable domain, so the Rust and Lean bodies are line-for-line aligned.

The learned choice enters each theorem as a universally quantified scalar. In Lean that is the bound variable `p`, in Kani it is `kani::any()`. No property depends on calibration quality; calibration only decides how often the `Honored` branch is taken.

## P1.2 `formal_aeneas.rs` additions

```rust
// ---- Slice P1 (additive) ----
#[cfg(chio_creusot_contracts)]
use creusot_contracts::prelude::*;

pub const Q16_ONE: i32 = 65_536;
const Q16_ONE_I64: i64 = 65_536;
const EXP2_SEG_SHIFT: u32 = 12;
const EXP2_SEG_WIDTH: u32 = 4_096;

fn or_zero_u32(v: Option<u32>) -> u32 {
    match v { Some(x) => x, None => 0 }
}

#[cfg_attr(chio_creusot_contracts, ensures(result.1 ==> result.0@ == a@ + b@))]
#[cfg_attr(chio_creusot_contracts, ensures(!result.1 ==> result.0@ == 0))]
pub fn q16_checked_add(a: i32, b: i32) -> (i32, bool) {
    match a.checked_add(b) { Some(v) => (v, true), None => (0, false) }
}

#[cfg_attr(chio_creusot_contracts, ensures(result@ >= i32::MIN@ && result@ <= i32::MAX@))]
pub fn q16_saturating_add(a: i32, b: i32) -> i32 { a.saturating_add(b) }

/// Floor((a*b) / 2^16). Floor, not truncation, so the result is monotone in each argument.
#[cfg_attr(chio_creusot_contracts, ensures(result.1 ==>
    result.0@ * 65536 <= a@ * b@ && a@ * b@ < (result.0@ + 1) * 65536))]
pub fn q16_checked_mul(a: i32, b: i32) -> (i32, bool) {
    let Some(prod) = i64::from(a).checked_mul(i64::from(b)) else { return (0, false) };
    let Some(floored) = prod.checked_div_euclid(Q16_ONE_I64) else { return (0, false) };
    match i32::try_from(floored) { Ok(v) => (v, true), Err(_) => (0, false) }
}

/// 2^(-k/16) in Q16.16, k = 0..=16. Strictly decreasing; endpoints exact.
fn exp2_neg_frac_lut(k: u32) -> u32 {
    match k {
        0 => 65_536, 1 => 62_757, 2 => 60_097, 3 => 57_549, 4 => 55_109, 5 => 52_772,
        6 => 50_535, 7 => 48_393, 8 => 46_341, 9 => 44_376, 10 => 42_495, 11 => 40_693,
        12 => 38_968, 13 => 37_316, 14 => 35_734, 15 => 34_219, _ => 32_768,
    }
}

/// 2^(-x) for x >= 0 in Q16.16: 16-segment LUT plus linear interpolation, then a right shift
/// by the integer part. Non-increasing in x, bounded in [0, 65536], exact at x = 0 and x = 1.0.
#[cfg_attr(chio_creusot_contracts, ensures(result.1 == (x@ >= 0)))]
#[cfg_attr(chio_creusot_contracts, ensures(0 <= result.0@ && result.0@ <= 65536))]
#[cfg_attr(chio_creusot_contracts, ensures(x@ == 0 ==> result.0@ == 65536))]
pub fn exp2_neg_q16(x: i32) -> (i32, bool) {
    if x < 0 { return (0, false); }
    let Ok(ux) = u32::try_from(x) else { return (0, false) };
    let n = or_zero_u32(ux.checked_shr(16));
    let r = or_zero_u32(ux.checked_rem(65_536));
    let k = or_zero_u32(r.checked_shr(EXP2_SEG_SHIFT));
    let t = or_zero_u32(r.checked_rem(EXP2_SEG_WIDTH));
    let lo = exp2_neg_frac_lut(k);
    let hi = exp2_neg_frac_lut(k.saturating_add(1));
    let span = lo.saturating_sub(hi);
    let step = or_zero_u32(or_zero_u32(span.checked_mul(t)).checked_shr(EXP2_SEG_SHIFT));
    let y = lo.saturating_sub(step);
    if n >= 31 { return (0, true); }
    let shifted = or_zero_u32(y.checked_shr(n));
    match i32::try_from(shifted) { Ok(v) => (v, true), Err(_) => (0, false) }
}

/// Shadow-price shrinkage: floor(p * 2^16 / (2^16 + lambda)). Closed-form argmax of
/// -(g-p)^2/2 - lambda*g^2/2, so lambda = 0 is the identity and the result never exceeds p.
#[cfg_attr(chio_creusot_contracts, ensures(result.1 == (lambda_q16@ >= 0)))]
#[cfg_attr(chio_creusot_contracts, ensures(result.1 ==> result.0@ <= proposed_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(lambda_q16@ == 0 ==> result.0@ == proposed_bps@))]
pub fn penalize_bps_by_shadow_price_q16(proposed_bps: u16, lambda_q16: i32) -> (u16, bool) {
    if lambda_q16 < 0 { return (0, false); }
    let Ok(lambda) = u64::try_from(lambda_q16) else { return (0, false) };
    let Some(num) = u64::from(proposed_bps).checked_mul(65_536) else { return (0, false) };
    let Some(den) = lambda.checked_add(65_536) else { return (0, false) };
    let Some(q) = num.checked_div(den) else { return (0, false) };
    match u16::try_from(q) { Ok(v) => (v, true), Err(_) => (0, false) }
}

/// Dual-mirror-descent primal projection with floor-division residue.
/// Envelope: {0} ∪ [floor, min(cap, parent_remaining, floor + pool + residue)].
/// Draw order: pool first, then residue. Returns (granted, residue_after, clamped).
#[cfg_attr(chio_creusot_contracts, ensures(result.0@ <= max_cap_bps@ && result.0@ <= parent_remaining_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.0@ == 0 || result.0@ >= static_floor_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.0@ <= static_floor_bps@ + dynamic_pool_remaining_bps@ + residue_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.1@ <= residue_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.0@ == 0 || residue_bps@ - result.1@ <= result.0@ - static_floor_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.0@ == 0 ||
    (result.0@ - static_floor_bps@) - (residue_bps@ - result.1@) <= dynamic_pool_remaining_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.2 == (result.0 != proposed_bps)))]
pub fn project_dynamic_share_bps(
    proposed_bps: u16, static_floor_bps: u16, dynamic_pool_remaining_bps: u16,
    residue_bps: u16, parent_remaining_bps: u16, max_cap_bps: u16,
) -> (u16, u16, bool) {
    if static_floor_bps > max_cap_bps || static_floor_bps > parent_remaining_bps {
        return (0, residue_bps, 0 != proposed_bps);
    }
    let avail = u32::from(dynamic_pool_remaining_bps).saturating_add(u32::from(residue_bps));
    let ceiling = u32::from(static_floor_bps).saturating_add(avail);
    let hard = u32::from(max_cap_bps).min(u32::from(parent_remaining_bps));
    let hi = match u16::try_from(hard.min(ceiling)) { Ok(v) => v, Err(_) => max_cap_bps };
    let granted = if proposed_bps == 0 { 0 } else { static_floor_bps.max(proposed_bps.min(hi)) };
    let draw = granted.saturating_sub(static_floor_bps);
    let from_pool = draw.min(dynamic_pool_remaining_bps);
    let from_residue = draw.saturating_sub(from_pool);
    let new_residue = residue_bps.saturating_sub(from_residue);
    (granted, new_residue, granted != proposed_bps)
}

/// Release path: returned dynamic bps rejoin the pool; the pool is re-aligned to the quantum
/// and the floor-division remainder becomes the residue. Conserves pool + residue + returned.
#[cfg_attr(chio_creusot_contracts, ensures(result.2 ==> result.0@ + result.1@ == pool_bps@ + residue_bps@ + returned_bps@))]
#[cfg_attr(chio_creusot_contracts, ensures(result.2 ==> result.1@ < quantum_bps@))]
pub fn requantize_dynamic_pool_bps(pool_bps: u16, residue_bps: u16, returned_bps: u16, quantum_bps: u16) -> (u16, u16, bool) {
    let total = u32::from(pool_bps).saturating_add(u32::from(residue_bps)).saturating_add(u32::from(returned_bps));
    let Some(rem) = total.checked_rem(u32::from(quantum_bps)) else { return (0, 0, false) };
    let aligned = total.saturating_sub(rem);
    match (u16::try_from(aligned), u16::try_from(rem)) { (Ok(d), Ok(r)) => (d, r, true), _ => (0, 0, false) }
}

/// Slack ratio (pool + residue) / mass in Q16.16, 1.0 when the pool is disabled.
#[cfg_attr(chio_creusot_contracts, ensures(result.1 ==> 0 <= result.0@ && result.0@ <= 65536))]
pub fn slack_ratio_q16(avail_bps: u32, mass_bps: u32) -> (i32, bool) {
    if mass_bps == 0 { return (Q16_ONE, true); }
    if avail_bps > mass_bps { return (0, false); }
    let Some(num) = u64::from(avail_bps).checked_mul(65_536) else { return (0, false) };
    let Some(q) = num.checked_div(u64::from(mass_bps)) else { return (0, false) };
    match i32::try_from(q) { Ok(v) => (v, true), Err(_) => (0, false) }
}

/// Strict refinement of `receipt_fields_coupled`: a decision receipt must also bind the weights
/// digest, the calibration digest, and a valid projection outcome.
#[cfg_attr(chio_creusot_contracts, ensures(result ==> receipt_fields_coupled(
    capability_matches, request_matches, verdict_matches, policy_hash_matches, evidence_class_matches)))]
#[cfg_attr(chio_creusot_contracts, ensures(result ==> weights_digest_matches && calibration_digest_matches && projection_outcome_valid))]
pub fn receipt_fields_coupled_with_decision_witness(
    capability_matches: bool, request_matches: bool, verdict_matches: bool,
    policy_hash_matches: bool, evidence_class_matches: bool,
    weights_digest_matches: bool, calibration_digest_matches: bool, projection_outcome_valid: bool,
) -> bool {
    receipt_fields_coupled(capability_matches, request_matches, verdict_matches, policy_hash_matches, evidence_class_matches)
        && weights_digest_matches && calibration_digest_matches && projection_outcome_valid
}
```

Extraction note: the only non-arithmetic core items used are `TryFrom` for scalar narrowing and `Option` matching. Both are in Charon's builtin scalar set. `let ... else` lowers to a plain `match` in MIR.

## P1.3 `formal_core.rs` wrappers

```rust
// ---- Slice P1 (additive) ----
use crate::formal_aeneas;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(formal_aeneas::Q16_ONE);

    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let (v, ok) = formal_aeneas::q16_checked_add(self.0, rhs.0);
        ok.then_some(Self(v))
    }
    #[must_use]
    pub fn saturating_add(self, rhs: Self) -> Self { Self(formal_aeneas::q16_saturating_add(self.0, rhs.0)) }
    #[must_use]
    pub fn checked_mul_q16(self, rhs: Self) -> Option<Self> {
        let (v, ok) = formal_aeneas::q16_checked_mul(self.0, rhs.0);
        ok.then_some(Self(v))
    }
    /// `None` iff `self < 0`.
    #[must_use]
    pub fn exp2_neg_q16(self) -> Option<Self> {
        let (v, ok) = formal_aeneas::exp2_neg_q16(self.0);
        ok.then_some(Self(v))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicShareInput {
    pub proposed_bps: u16, pub static_floor_bps: u16, pub dynamic_pool_remaining_bps: u16,
    pub residue_bps: u16, pub parent_remaining_bps: u16, pub max_cap_bps: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicShareProjection { pub granted_bps: u16, pub residue_after_bps: u16, pub clamped: bool }

pub fn project_dynamic_share(input: DynamicShareInput) -> DynamicShareProjection {
    let (granted_bps, residue_after_bps, clamped) = formal_aeneas::project_dynamic_share_bps(
        input.proposed_bps, input.static_floor_bps, input.dynamic_pool_remaining_bps,
        input.residue_bps, input.parent_remaining_bps, input.max_cap_bps,
    );
    DynamicShareProjection { granted_bps, residue_after_bps, clamped }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionWitnessCoupling {
    pub capability_matches: bool, pub request_matches: bool, pub verdict_matches: bool,
    pub policy_hash_matches: bool, pub evidence_class_matches: bool,
    pub weights_digest_matches: bool, pub calibration_digest_matches: bool, pub projection_outcome_valid: bool,
}

pub fn receipt_coupled_with_decision_witness(w: DecisionWitnessCoupling) -> bool {
    formal_aeneas::receipt_fields_coupled_with_decision_witness(
        w.capability_matches, w.request_matches, w.verdict_matches, w.policy_hash_matches,
        w.evidence_class_matches, w.weights_digest_matches, w.calibration_digest_matches, w.projection_outcome_valid,
    )
}
```

The `weights_digest_matches` input is produced by `evaluate_weights_binding` against the `LoadedWeights::loaded_weights_hash` of the active provider. The `projection_outcome_valid` input is `true` exactly when the receipt's `model_metadata` carries a `ProjectionOutcome` whose action is reconstructible from the envelope.

## P1.4 `decision_envelope.rs`

```rust
//! The only path from a learned proposal to an executable action.
//! Crate attributes in force: `#![no_std]`, `#![forbid(unsafe_code)]`. This module is alloc-free.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects, clippy::as_conversions, clippy::indexing_slicing))]

use crate::formal_core::FixedQ16_16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProjectionOutcome {
    /// Proposal was feasible and confident; executed as proposed.
    Honored { index: usize },
    /// Proposal was infeasible; replaced by the feasible argmax of the shadow-priced score.
    Projected { index: usize },
    /// Proposal was below threshold or the envelope was empty; conservative action taken.
    Fallback,
}

/// Output of a Tier-0 or Tier-1 predictor. Carries no public accessor to its payload.
#[derive(Debug)]
pub struct RawModelProposal<A> { proposal: A, score_q16: FixedQ16_16 }

impl<A> RawModelProposal<A> {
    pub const fn new(proposal: A, score_q16: FixedQ16_16) -> Self { Self { proposal, score_q16 } }
    pub const fn score_q16(&self) -> FixedQ16_16 { self.score_q16 }
    pub(crate) fn into_parts(self) -> (A, FixedQ16_16) { (self.proposal, self.score_q16) }
}

/// Unshielded proposals cannot become `ShieldedAction`s.
///
/// The constructor is not nameable outside the crate:
/// ```compile_fail,E0451
/// use chio_kernel_core::decision_envelope::{ProjectionOutcome, ShieldedAction};
/// let _s: ShieldedAction<u16> = ShieldedAction { action: 7u16, outcome: ProjectionOutcome::Fallback };
/// ```
/// The payload accessor is crate-private:
/// ```compile_fail,E0624
/// use chio_kernel_core::decision_envelope::RawModelProposal;
/// use chio_kernel_core::formal_core::FixedQ16_16;
/// let raw = RawModelProposal::new(7u16, FixedQ16_16::ONE);
/// let (_payload, _score) = raw.into_parts();
/// ```
/// No `From`/`Into` bridge exists:
/// ```compile_fail,E0277
/// use chio_kernel_core::decision_envelope::{RawModelProposal, ShieldedAction};
/// use chio_kernel_core::formal_core::FixedQ16_16;
/// let raw = RawModelProposal::new(7u16, FixedQ16_16::ONE);
/// let _s: ShieldedAction<u16> = raw.into();
/// ```
/// The only constructor path:
/// ```
/// use chio_kernel_core::decision_envelope::{FeasibleSlice, ProjectionOutcome, RawModelProposal};
/// use chio_kernel_core::formal_core::FixedQ16_16;
/// let feasible = [25u16, 50, 100];
/// let hold = 0u16;
/// let env = FeasibleSlice::new(&feasible, &hold);
/// let shielded = env.select_by_q16_score(
///     RawModelProposal::new(75u16, FixedQ16_16::ONE), FixedQ16_16(32_768), |a| FixedQ16_16(i32::from(*a)));
/// assert_eq!(**shielded.action(), 100);
/// assert_eq!(shielded.outcome(), ProjectionOutcome::Projected { index: 2 });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldedAction<A> { action: A, outcome: ProjectionOutcome }

impl<A> ShieldedAction<A> {
    pub(crate) const fn from_verified_projection(action: A, outcome: ProjectionOutcome) -> Self { Self { action, outcome } }
    pub const fn action(&self) -> &A { &self.action }
    pub fn into_action(self) -> A { self.action }
    pub const fn outcome(&self) -> ProjectionOutcome { self.outcome }
}

/// The feasible envelope `C(x) = feasible ∪ {fallback}`, computed exactly upstream.
pub struct FeasibleSlice<'a, A> { feasible: &'a [A], fallback: &'a A }

impl<'a, A: PartialEq> FeasibleSlice<'a, A> {
    pub const fn new(feasible: &'a [A], fallback: &'a A) -> Self { Self { feasible, fallback } }
    pub const fn len(&self) -> usize { self.feasible.len() }
    pub const fn is_empty(&self) -> bool { self.feasible.is_empty() }
    pub const fn fallback(&self) -> ShieldedAction<&'a A> {
        ShieldedAction::from_verified_projection(self.fallback, ProjectionOutcome::Fallback)
    }

    /// `Π_{C(x)}`: honor a confident feasible proposal, else take the earliest feasible argmax
    /// of `score`, else fall back. Consumes the proposal so it cannot be re-presented.
    pub fn select_by_q16_score<F>(&self, proposal: RawModelProposal<A>, tau_q16: FixedQ16_16, score: F) -> ShieldedAction<&'a A>
    where F: Fn(&A) -> FixedQ16_16 {
        let (proposed, confidence) = proposal.into_parts();
        if confidence < tau_q16 { return self.fallback(); }
        if let Some(index) = self.feasible.iter().position(|a| *a == proposed) {
            if let Some(a) = self.feasible.get(index) {
                return ShieldedAction::from_verified_projection(a, ProjectionOutcome::Honored { index });
            }
        }
        let mut best: Option<(usize, &'a A, FixedQ16_16)> = None;
        for (index, a) in self.feasible.iter().enumerate() {
            let s = score(a);
            let better = match best { None => true, Some((_, _, bs)) => s > bs };
            if better { best = Some((index, a, s)); }
        }
        match best {
            Some((index, a, _)) => ShieldedAction::from_verified_projection(a, ProjectionOutcome::Projected { index }),
            None => self.fallback(),
        }
    }
}
```

The strict `>` in the scan makes the earliest index win ties. The Lean `argmaxIdx` below uses the same rule, so the two agree on the index as well as the action.

## P1.5 `budget_split.rs` additions

One private field is added to `BudgetSplit`: `dynamic: DynamicPoolState`. The existing constructor initializes it with `DynamicPoolState::default()`, which means pool, residue, and granted mass are all zero. Existing methods never read it, so their behavior is unchanged.

```rust
// ---- Slice P1 (additive) ----
use crate::decision_envelope::{ProjectionOutcome, RawModelProposal, ShieldedAction};
use crate::formal_aeneas::{penalize_bps_by_shadow_price_q16, project_dynamic_share_bps, requantize_dynamic_pool_bps, slack_ratio_q16};
use crate::formal_core::FixedQ16_16;

pub const DYNAMIC_POOL_QUANTUM_BPS: u16 = 25;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DynamicPoolState {
    dynamic_pool_bps: u16,
    residue_bps: u16,
    dynamic_granted_bps: u16,
    dynamic_part: BTreeMap<String, u16>,
    shadow_price_q16: FixedQ16_16,
    shadow_price_max_q16: FixedQ16_16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeAdmissionError {
    Split(BudgetSplitError),
    StaticHeadroomExhausted { parent_token_id: String, floor_bps: u16, headroom_bps: u16 },
    DynamicPoolExceedsParent { parent_token_id: String, pool_bps: u16, headroom_bps: u32 },
    UnknownChild { child_id: String },
    ArithmeticInvariantViolated { parent_token_id: String },
    ShadowPriceInvalid,
}

impl From<BudgetSplitError> for EnvelopeAdmissionError {
    fn from(e: BudgetSplitError) -> Self { Self::Split(e) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopedAdmission { pub shielded: ShieldedAction<u16>, pub admitted: bool, pub clamped: bool }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopedRelease { HolderRetained { holders: usize }, Removed { share_bps: u16, dynamic_part_bps: u16 } }

impl BudgetSplit {
    pub fn dynamic_pool_bps(&self) -> u16 { self.dynamic.dynamic_pool_bps }
    pub fn residue_bps(&self) -> u16 { self.dynamic.residue_bps }
    pub fn shadow_price_q16(&self) -> FixedQ16_16 { self.dynamic.shadow_price_q16 }

    /// Conserved dynamic mass T = pool + residue + granted.
    pub fn dynamic_mass_bps(&self) -> u32 {
        u32::from(self.dynamic.dynamic_pool_bps)
            .saturating_add(u32::from(self.dynamic.residue_bps))
            .saturating_add(u32::from(self.dynamic.dynamic_granted_bps))
    }

    fn enveloped_total_child_bps(&self) -> u32 {
        self.children.values().fold(0u32, |acc, c| acc.saturating_add(u32::from(c.share_bps)))
    }

    fn invariant_err(&self) -> EnvelopeAdmissionError {
        EnvelopeAdmissionError::ArithmeticInvariantViolated { parent_token_id: self.parent_token_id.clone() }
    }

    /// Moves `pool_bps` from the unallocated parent share into the dynamic pool.
    pub fn enable_dynamic_pool(&mut self, pool_bps: u16, shadow_price_max_q16: FixedQ16_16) -> Result<(), EnvelopeAdmissionError> {
        if shadow_price_max_q16 < FixedQ16_16::ZERO { return Err(EnvelopeAdmissionError::ShadowPriceInvalid); }
        let committed = self.enveloped_total_child_bps().saturating_add(self.dynamic_mass_bps());
        let headroom = u32::from(self.parent_share_bps).saturating_sub(committed);
        if u32::from(pool_bps) > headroom {
            return Err(EnvelopeAdmissionError::DynamicPoolExceedsParent {
                parent_token_id: self.parent_token_id.clone(), pool_bps, headroom_bps: headroom });
        }
        let (d, r, ok) = requantize_dynamic_pool_bps(
            self.dynamic.dynamic_pool_bps, self.dynamic.residue_bps, pool_bps, DYNAMIC_POOL_QUANTUM_BPS);
        if !ok { return Err(self.invariant_err()); }
        self.dynamic.dynamic_pool_bps = d;
        self.dynamic.residue_bps = r;
        self.dynamic.shadow_price_max_q16 = shadow_price_max_q16;
        self.dynamic.shadow_price_q16 = shadow_price_max_q16;
        Ok(())
    }

    /// Shielded admission. No state is mutated unless every check and every checked
    /// arithmetic step has succeeded. A `Fallback` result is a valid, non-mutating decision.
    pub fn admit_child_enveloped(
        &mut self, child_id: &str, proposal: RawModelProposal<u16>,
        static_floor_bps: u16, max_cap_bps: u16, tau_q16: FixedQ16_16,
    ) -> Result<EnvelopedAdmission, EnvelopeAdmissionError> {
        let inv = self.invariant_err();
        if self.children.contains_key(child_id) {
            return Err(BudgetSplitError::DuplicateChild { child_id: child_id.to_string() }.into());
        }
        let capacity_err = || BudgetSplitError::ChildCapacityExhausted { parent_token_id: self.parent_token_id.clone() };
        if self.children.len() >= MAX_CHILDREN_PER_PARENT { return Err(capacity_err().into()); }
        let retained_after = self.retained_child_id_bytes.checked_add(child_id.len()).ok_or_else(|| capacity_err())?;
        if retained_after > MAX_RETAINED_CHILD_ID_BYTES { return Err(capacity_err().into()); }
        if static_floor_bps > MAX_BUDGET_SHARE_BPS {
            return Err(BudgetSplitError::ChildShareExceedsCap { child_id: child_id.to_string(), share_bps: static_floor_bps }.into());
        }
        let cap = max_cap_bps.min(MAX_BUDGET_SHARE_BPS);

        let (proposed, confidence) = proposal.into_parts();
        let effective = if confidence < tau_q16 {
            static_floor_bps
        } else {
            let (pen, ok) = penalize_bps_by_shadow_price_q16(proposed, self.dynamic.shadow_price_q16.0);
            if !ok { return Err(EnvelopeAdmissionError::ShadowPriceInvalid); }
            pen
        };

        let pool = self.dynamic.dynamic_pool_bps;
        let residue = self.dynamic.residue_bps;
        let total = self.enveloped_total_child_bps();
        let parent_remaining = u16::try_from(u32::from(self.parent_share_bps).saturating_sub(total)).unwrap_or(0);
        let avail = u32::from(pool).saturating_add(u32::from(residue));
        let headroom = u32::from(parent_remaining).saturating_sub(avail);
        if u32::from(static_floor_bps) > headroom {
            return Err(EnvelopeAdmissionError::StaticHeadroomExhausted {
                parent_token_id: self.parent_token_id.clone(), floor_bps: static_floor_bps,
                headroom_bps: u16::try_from(headroom).unwrap_or(u16::MAX) });
        }

        let (granted, new_residue, clamped) =
            project_dynamic_share_bps(effective, static_floor_bps, pool, residue, parent_remaining, cap);
        if granted == 0 {
            return Ok(EnvelopedAdmission {
                shielded: ShieldedAction::from_verified_projection(0, ProjectionOutcome::Fallback), admitted: false, clamped });
        }
        let draw = granted.checked_sub(static_floor_bps).ok_or_else(|| inv.clone())?;
        let from_residue = residue.checked_sub(new_residue).ok_or_else(|| inv.clone())?;
        let from_pool = draw.checked_sub(from_residue).ok_or_else(|| inv.clone())?;
        let pool_after = pool.checked_sub(from_pool).ok_or_else(|| inv.clone())?;
        let granted_after = self.dynamic.dynamic_granted_bps.checked_add(draw).ok_or(inv)?;

        self.dynamic.dynamic_pool_bps = pool_after;
        self.dynamic.residue_bps = new_residue;
        self.dynamic.dynamic_granted_bps = granted_after;
        self.dynamic.dynamic_part.insert(child_id.to_string(), draw);
        self.children.insert(child_id.to_string(), ChildAdmission { share_bps: granted, holders: 1 });
        self.retained_child_id_bytes = retained_after;

        let index = usize::from(granted);
        let outcome = if clamped { ProjectionOutcome::Projected { index } } else { ProjectionOutcome::Honored { index } };
        Ok(EnvelopedAdmission { shielded: ShieldedAction::from_verified_projection(granted, outcome), admitted: true, clamped })
    }

    /// Decrements the holder refcount; removes the child and returns its dynamic part to the
    /// pool only when the count reaches zero. Children admitted by the legacy path have no
    /// dynamic part and return wholly to the static reserve.
    pub fn release_child_enveloped(&mut self, child_id: &str) -> Result<EnvelopedRelease, EnvelopeAdmissionError> {
        let inv = self.invariant_err();
        let (holders, share) = match self.children.get(child_id) {
            Some(a) => (a.holders, a.share_bps),
            None => return Err(EnvelopeAdmissionError::UnknownChild { child_id: child_id.to_string() }),
        };
        let holders_after = holders.checked_sub(1).ok_or_else(|| inv.clone())?;
        if holders_after > 0 {
            if let Some(a) = self.children.get_mut(child_id) { a.holders = holders_after; }
            return Ok(EnvelopedRelease::HolderRetained { holders: holders_after });
        }
        let dyn_part = self.dynamic.dynamic_part.get(child_id).copied().unwrap_or(0);
        let (d, r, ok) = requantize_dynamic_pool_bps(
            self.dynamic.dynamic_pool_bps, self.dynamic.residue_bps, dyn_part, DYNAMIC_POOL_QUANTUM_BPS);
        if !ok { return Err(inv); }
        let granted_after = self.dynamic.dynamic_granted_bps.checked_sub(dyn_part).ok_or_else(|| inv.clone())?;
        let retained_after = self.retained_child_id_bytes.checked_sub(child_id.len()).ok_or(inv)?;

        self.children.remove(child_id);
        self.dynamic.dynamic_part.remove(child_id);
        self.dynamic.dynamic_pool_bps = d;
        self.dynamic.residue_bps = r;
        self.dynamic.dynamic_granted_bps = granted_after;
        self.retained_child_id_bytes = retained_after;
        Ok(EnvelopedRelease::Removed { share_bps: share, dynamic_part_bps: dyn_part })
    }

    /// Anchored exponentiated-gradient dual step: lambda = lambda_max * 2^(-eta * slack),
    /// slack = (pool + residue) / mass in [0, 1]. Bounded in [0, lambda_max], non-increasing in slack.
    pub fn update_dual_mirror_descent_step(&mut self, eta_q16: FixedQ16_16) -> Result<FixedQ16_16, EnvelopeAdmissionError> {
        if eta_q16 < FixedQ16_16::ZERO { return Err(EnvelopeAdmissionError::ShadowPriceInvalid); }
        let avail = u32::from(self.dynamic.dynamic_pool_bps).saturating_add(u32::from(self.dynamic.residue_bps));
        let (slack, ok) = slack_ratio_q16(avail, self.dynamic_mass_bps());
        if !ok { return Err(self.invariant_err()); }
        let exponent = eta_q16.checked_mul_q16(FixedQ16_16(slack)).ok_or(EnvelopeAdmissionError::ShadowPriceInvalid)?;
        let decay = exponent.exp2_neg_q16().ok_or(EnvelopeAdmissionError::ShadowPriceInvalid)?;
        let lambda = self.dynamic.shadow_price_max_q16.checked_mul_q16(decay).ok_or(EnvelopeAdmissionError::ShadowPriceInvalid)?;
        self.dynamic.shadow_price_q16 = lambda;
        Ok(lambda)
    }
}
```

Invariants preserved by every method above, with $S$ the parent share, $\Sigma$ the sum of child shares, $D$ the pool, $\varrho$ the residue, and $G$ the granted dynamic mass:

- **$\mathsf{I}_1$ (parent cap):** $\Sigma + D + \varrho \le S \le 10\,000$. Admission adds $f + d$ to $\Sigma$ and removes $d$ from $D + \varrho$, so the left side grows by exactly $f$, which the static-headroom check bounds.
- **$\mathsf{I}_2$ (mass conservation):** $D + \varrho + G$ is constant across admit and release. Admission moves $d$ from pool-plus-residue into $G$. Release moves it back and requantizes without loss.
- **$\mathsf{I}_3$ (refcount):** every `ChildAdmission` has `holders >= 1`, and an entry is removed only when the count would reach zero.

## P1.6 `formal/lean4/Chio/Proofs/DecisionEnvelope.lean`

```lean
/-
  Slice P1: decision envelope, dynamic pool residue conservation, projection idempotence.
  Core Lean 4 only (`omega` with min/max/ite support, Lean >= 4.8). No Mathlib.
-/
namespace Chio.DecisionEnvelope

/-! ## 1. Discrete shielded selection (mirrors `decision_envelope.rs`) -/

inductive Outcome where
  | honored (i : Nat)
  | projected (i : Nat)
  | fallback
  deriving DecidableEq, Repr

variable {α : Type} [DecidableEq α]

/-- Earliest index of the maximal score; a strictly greater later score is required to displace. -/
def argmaxIdx (score : α → Int) : List α → Option (Nat × α)
  | [] => none
  | a :: as =>
    match argmaxIdx score as with
    | none => some (0, a)
    | some (i, b) => if score a < score b then some (i + 1, b) else some (0, a)

theorem argmaxIdx_mem (score : α → Int) :
    ∀ (l : List α) (i : Nat) (b : α), argmaxIdx score l = some (i, b) → b ∈ l := by
  intro l
  induction l with
  | nil => intro i b h; simp [argmaxIdx] at h
  | cons a as ih =>
    intro i b h
    simp only [argmaxIdx] at h
    cases hrec : argmaxIdx score as with
    | none =>
      simp only [hrec] at h
      cases h
      exact List.mem_cons_self a as
    | some ib =>
      obtain ⟨i', b'⟩ := ib
      simp only [hrec] at h
      split at h
      · cases h; exact List.mem_cons_of_mem a (ih i' b' hrec)
      · cases h; exact List.mem_cons_self a as

/-- Mirrors `FeasibleSlice::select_by_q16_score`. -/
def select (feasible : List α) (fallback proposal : α) (score : α → Int) (tau s : Int) : α × Outcome :=
  if s < tau then (fallback, .fallback)
  else if proposal ∈ feasible then (proposal, .honored (feasible.indexOf proposal))
  else
    match argmaxIdx score feasible with
    | some (i, b) => (b, .projected i)
    | none => (fallback, .fallback)

/-- Envelope Preservation: the executed action is feasible or is the fallback. -/
theorem envelope_preservation (feasible : List α) (fallback proposal : α)
    (score : α → Int) (tau s : Int) :
    (select feasible fallback proposal score tau s).1 ∈ feasible ∨
    (select feasible fallback proposal score tau s).1 = fallback := by
  unfold select
  split
  · exact Or.inr rfl
  · split
    · rename_i hmem; exact Or.inl hmem
    · split
      · rename_i i b hrec; exact Or.inl (argmaxIdx_mem score feasible i b hrec)
      · exact Or.inr rfl

/-! ## 2. Dynamic pool projection on Nat (mirrors `project_dynamic_share_bps`) -/

structure Proj where
  granted : Nat
  residue : Nat
  clamped : Bool

def projectDynamicShare (p f D ϱ R M : Nat) : Proj :=
  if f > M ∨ f > R then ⟨0, ϱ, decide (0 ≠ p)⟩
  else
    let hi := min (min M R) (f + D + ϱ)
    let g := if p = 0 then 0 else max f (min p hi)
    let draw := g - f
    let fromPool := min draw D
    let fromRes := draw - fromPool
    ⟨g, ϱ - fromRes, decide (g ≠ p)⟩

theorem grant_in_envelope (p f D ϱ R M : Nat) :
    let pr := projectDynamicShare p f D ϱ R M
    pr.granted ≤ M ∧ pr.granted ≤ R ∧ (pr.granted = 0 ∨ f ≤ pr.granted) ∧
    pr.granted ≤ f + D + ϱ := by
  intro pr
  simp only [pr, projectDynamicShare]
  split <;> repeat' (first | omega | split)

/-- Exact basis-point conservation of one draw: draw + pool_after + residue_after = D + ϱ. -/
theorem dynamic_pool_residue_conservation (p f D ϱ R M : Nat) :
    let pr := projectDynamicShare p f D ϱ R M
    let draw := pr.granted - f
    let fromRes := ϱ - pr.residue
    pr.residue ≤ ϱ ∧ fromRes ≤ draw ∧ draw - fromRes ≤ D ∧
    draw + (D - (draw - fromRes)) + pr.residue = D + ϱ := by
  intro pr draw fromRes
  simp only [pr, draw, fromRes, projectDynamicShare]
  split <;> repeat' (first | omega | split)

/-- Π is idempotent: re-projecting the granted share changes neither grant nor residue. -/
theorem mirror_descent_projection_idempotent (p f D ϱ R M : Nat) :
    let g := (projectDynamicShare p f D ϱ R M).granted
    (projectDynamicShare g f D ϱ R M).granted = g ∧
    (projectDynamicShare g f D ϱ R M).residue = (projectDynamicShare p f D ϱ R M).residue := by
  intro g
  simp only [g, projectDynamicShare]
  split <;> repeat' (first | omega | split)

/-! ## 3. Release-path requantization (mirrors `requantize_dynamic_pool_bps`) -/

def requantize (D ϱ r Q : Nat) : Nat × Nat :=
  let total := D + ϱ + r
  (total - total % Q, total % Q)

theorem requantize_conserves (D ϱ r Q : Nat) :
    (requantize D ϱ r Q).1 + (requantize D ϱ r Q).2 = D + ϱ + r := by
  simp only [requantize]
  have := Nat.mod_le (D + ϱ + r) Q
  omega

theorem requantize_residue_lt (D ϱ r Q : Nat) (hQ : 0 < Q) : (requantize D ϱ r Q).2 < Q := by
  simp only [requantize]
  exact Nat.mod_lt _ hQ

/-- Mass conservation across one admit followed by the matching release. -/
theorem split_release_cycle_conserves (p f D ϱ R M G Q : Nat) :
    let pr := projectDynamicShare p f D ϱ R M
    let draw := pr.granted - f
    let D₁ := D - (draw - (ϱ - pr.residue))
    let rq := requantize D₁ pr.residue draw Q
    rq.1 + rq.2 + G = D + ϱ + G := by
  intro pr draw D₁ rq
  have h := dynamic_pool_residue_conservation p f D ϱ R M
  have hc := requantize_conserves D₁ pr.residue draw Q
  simp only [pr, draw, D₁, rq] at *
  omega

end Chio.DecisionEnvelope
```

The Aeneas side adds one refinement obligation per new scalar, discharged with `progress` against the extracted `Funs.lean`: for `project_dynamic_share_bps` the statement is that the extracted function returns `ok (g, r, c)` with `(g.val, r.val, c)` equal to the `projectDynamicShare` triple on the `.val` projections. Because the Rust body uses only saturating and min/max operations whose Nat images are exact on the reachable domain, this is a `simp` plus `omega` lemma.

## P1.7 `kani_public_harnesses.rs` additions

```rust
#[cfg(kani)]
mod slice_p1 {
    use crate::budget_split::DYNAMIC_POOL_QUANTUM_BPS;
    use crate::decision_envelope::{FeasibleSlice, ProjectionOutcome, RawModelProposal};
    use crate::formal_aeneas::{exp2_neg_q16, project_dynamic_share_bps, q16_checked

---

# Verbatim Treatise - `wave2_angle_2_slice_p2_two_phase_guard_optimal_stopping`

I'll write the Slice P2 specification now: the fold analysis of the current pipeline, the two-phase trait and pipeline with both deny-witness modes, the redaction patch, the Q16.16 Wald test, and the Kani and Loom harnesses.

One correction to the framing before the proofs. Theorem 2 shows that any pipeline whose verdict and evidence are bit-identical to registration order must obtain the pure-phase result of every guard up to the minimal denier. The ratio-ordered scan therefore cannot reduce single-threaded pure-phase work in canonical mode. What it buys is still exact and worth having: elision of every stateful commit on the Deny path, strict expected-cost optimality in `AnyValidDenier` mode, and the provably best dispatch order when pure guards are evaluated concurrently. Everything below is built as requested, and the cost theorems claim only what holds.

## 1. Sticky state and commutativity in `GuardPipeline::evaluate`

Fix registration order $g_0,\dots,g_{n-1}$ and a context $x$. Each guard yields one of four results: $\mathsf{A}(E_i)$, $\mathsf{P}(E_i)$, $\mathsf{D}(E_i)$, or $\mathsf{Err}$, where $E_i$ is its evidence list. Let $\rho(\mathsf A)=0$, $\rho(\mathsf P)=1$, $\rho(\mathsf D)=\rho(\mathsf{Err})=2$. Lines 63-106 of `pipeline.rs` are the left fold

$$
\mathrm{step}\big((v,\mathcal E), r_i\big)=
\begin{cases}
\mathrm{halt}\big(\mathsf D,\ \mathcal E\cdot E_i\cdot m^{\mathsf D}_i\big) & r_i=\mathsf D(E_i)\\
\mathrm{halt}\big(\mathsf D,\ \mathcal E\cdot m^{\mathsf{Err}}_i\big) & r_i=\mathsf{Err}\\
\big(\mathsf P,\ \mathcal E\cdot E_i\big) & r_i=\mathsf P(E_i)\\
\big(v,\ \mathcal E\cdot[E_i]_\kappa\big) & r_i=\mathsf A(E_i)
\end{cases}
$$

from the initial state $(\mathsf A,\varepsilon)$. Here $m^{\mathsf D}_i$ and $m^{\mathsf{Err}}_i$ are the synthetic markers pushed at lines 83-99, and $[E]_\kappa$ is $E$ if the `Allow` arm retains the guard's evidence and $\varepsilon$ if it drops it. The source reads `Verdict::Allow => continue`, which is consistent with either placement of `evidence.extend`. The constant `KEEP_ALLOW_EVIDENCE` below pins the reading, and the differential harness in Section 3 compares against the real `GuardPipeline`, so a wrong pin fails the proof rather than the receipt.

**Theorem 1, prefix determination.** Let $k^*=\min\big(\{i:\rho(r_i)=2\}\cup\{n\}\big)$ and $\mathcal E_{<k}=\prod_{i<k}\mathrm{contrib}(r_i)$ in index order. Then

$$
\mathrm{Obs}(x)=
\begin{cases}
\big(\mathsf D,\ \mathcal E_{<k^*}\cdot E_{k^*}\cdot m^{\mathsf D}_{k^*}\big) & k^*<n,\ r_{k^*}=\mathsf D(E_{k^*})\\
\big(\mathsf D,\ \mathcal E_{<k^*}\cdot m^{\mathsf{Err}}_{k^*}\big) & k^*<n,\ r_{k^*}=\mathsf{Err}\\
\big(\textstyle\bigvee_{i<n}\rho(r_i),\ \mathcal E_{<n}\big) & k^*=n.
\end{cases}
$$

*Proof.* Induction on the loop index. Before step $i$ the accumulator is $(\bigvee_{j<i}\rho(r_j),\ \mathcal E_{<i})$, because the two non-halting arms only join the verdict and append. The halting arms are the only exits and fire exactly at $k^*$. $\square$

**Corollary 1.1, irrelevance.** $\mathrm{Obs}(x)$ is a function of $(r_i)_{i\le k^*}$ alone. Guards above $k^*$ may be skipped without changing any receipt byte.

**Corollary 1.2, what commutes.** The verdict component is the join in the chain $\mathsf A<\mathsf P<\mathsf D$. That join is commutative, associative, and idempotent, so the sticky `PendingApproval` state needs no ordering. The evidence component lives in the free monoid over `GuardEvidence`, which is not commutative. A reordering pipeline must rebuild the concatenation by index; it cannot inherit it from the fold.

**Theorem 2, minimal work.** Any procedure that outputs $\mathrm{Obs}(x)$ for every result profile must obtain $r_i$ for every $i\le k^*$.

*Proof.* Take a profile with minimal denier $k^*$ and some $j<k^*$ whose result the procedure never obtains. Replace $r_j$ by $\mathsf D(E_j)$. The new profile has minimal denier $j$; its output contains $m^{\mathsf D}_j$ and no contribution from $g_{k^*}$, so the outputs differ, yet the procedure sees identical inputs. If $r_{k^*}$ itself is never obtained, replacing it by $\mathsf A(\varepsilon)$ changes the verdict or the denier. $\square$

Theorem 2 is the budget law for this slice. Write a guard's cost as $c_i=c_i^{\mathrm{pre}}+c_i^{\mathrm{commit}}$. Equivalence forces every $c^{\mathrm{pre}}_i$ with $i\le k^*$ to be paid. The only work a canonical pipeline can drop is $c^{\mathrm{commit}}_j$ for stateful $j<k^*$ on the Deny path, plus whatever latency concurrency recovers. This is the split already present in `formal_aeneas.rs`: `budget_precheck` and the value-returning `budget_commit` are pure functions of a snapshot, and only storing the resulting `BudgetCommitResult` through `ledger_apply` with op `1` is an effect.

A guard declares `SafePure` when `evaluate_pure` is a deterministic function of the context with no effect, and `StatefulCommit` otherwise. Only `SafePure` guards may be reordered or speculated. A false `SafePure` declaration voids every theorem below, which is why the adapter for legacy guards declares `StatefulCommit`.

```rust
//! crates/guards/chio-guards/src/two_phase.rs   (additive: `pub mod two_phase;` in lib.rs)
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

extern crate alloc;
use alloc::{boxed::Box, string::{String, ToString}, vec::Vec};
use core::{any::Any, cmp::Ordering};
// Same items `pipeline.rs` imports today.
use crate::{Guard, GuardContext, GuardDecision, GuardEvidence, KernelError, Verdict};

pub const GUARD_DENY_PUBLIC_REASON: &str = "action=deny; reason=guard denied request";
pub const GUARD_ERROR_PUBLIC_REASON: &str = "action=error; reason=fail-closed";
/// Pins what the `Allow` arm of pipeline.rs:63-106 does with evidence.
pub const KEEP_ALLOW_EVIDENCE: bool = true;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(transparent)]
pub struct FixedQ16_16(pub u32);
impl FixedQ16_16 { pub const ZERO: Self = Self(0); pub const ONE: Self = Self(1 << 16); }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GuardEvidenceDeclaration { SafePure, StatefulCommit }

/// Private-constructor token, same discipline as `ShieldedAction<A>`.
pub struct PreparedGuardToken { effect: Box<dyn Any + Send> }
impl PreparedGuardToken {
    pub fn new<T: Any + Send>(effect: T) -> Self { Self { effect: Box::new(effect) } }
    pub fn into_effect<T: Any>(self) -> Option<Box<T>> { self.effect.downcast::<T>().ok() }
}

pub struct PreparedGuardDecision {
    pub verdict: Verdict,
    pub evidence: Vec<GuardEvidence>,
    pub token: Option<PreparedGuardToken>,
}

pub trait TwoPhaseGuard: Send + Sync {
    fn name(&self) -> &str;
    fn declaration(&self) -> GuardEvidenceDeclaration;
    fn evaluate_pure(&self, ctx: &GuardContext) -> Result<PreparedGuardDecision, KernelError>;
    fn commit_prepared(&self, prepared: PreparedGuardToken) -> GuardEvidence;
    fn estimated_cost_us(&self) -> u32;
    fn empirical_deny_prob_q16(&self, ctx: &GuardContext) -> FixedQ16_16;
}

/// Conservative wrapper: runs the legacy guard whole, only ever inside the registration-order sweep.
pub struct LegacyAdapter<G: Guard> { pub inner: G, pub cost_us: u32 }
impl<G: Guard + Send + Sync> TwoPhaseGuard for LegacyAdapter<G> {
    fn name(&self) -> &str { self.inner.name() }
    fn declaration(&self) -> GuardEvidenceDeclaration { GuardEvidenceDeclaration::StatefulCommit }
    fn evaluate_pure(&self, ctx: &GuardContext) -> Result<PreparedGuardDecision, KernelError> {
        let d = self.inner.evaluate(ctx)?;
        Ok(PreparedGuardDecision { verdict: d.verdict, evidence: d.evidence, token: None })
    }
    fn commit_prepared(&self, _: PreparedGuardToken) -> GuardEvidence {
        GuardEvidence { guard_name: self.name().to_string(), verdict: true, details: None }
    }
    fn estimated_cost_us(&self) -> u32 { self.cost_us }
    fn empirical_deny_prob_q16(&self, _: &GuardContext) -> FixedQ16_16 { FixedQ16_16::ZERO }
}
```

In Wave 1 terms the feasible envelope is the set of evaluation schedules that cover $[0,k^*]$, with $\bot_x$ the registration-order schedule. The projection $\Pi$ is the flatten-by-index at the end of `run_in_order`. Because $\mathrm{Obs}$ is constant on the envelope by Theorem 3, the learned scores $q_i(x)$ enter the proofs only as `kani::any()`, exactly as the Verification Transfer Theorem prescribes.

## 2. Deny-witness modes, the index rule, and redaction

**Theorem 5, index rule.** Let pure guards be independent with deny probability $q_i$ and cost $c_i>0$. For a schedule $\pi$ that stops at the first denier, the expected cost is $\mathbb E[\pi]=\sum_k c_{\pi(k)}\prod_{m<k}(1-q_{\pi(m)})$. Swapping adjacent guards $i,j$ changes the expectation by $\Pi_{\text{prefix}}\,(q_j c_i - q_i c_j)$, so $i$ should precede $j$ iff $q_i c_j \ge q_j c_i$, that is iff $q_i/c_i\ge q_j/c_j$. Any schedule not sorted by descending ratio has an adjacent inversion whose swap does not increase cost; hence descending $q_i/c_i$ is optimal. $\square$

The comparator below never divides. It compares $q_i c_j$ with $q_j c_i$ in `u64`, which is exact for `u32` inputs, and breaks ties by index so the order is a total, deterministic function of the scores.

This is Weitzman's Pandora rule in disguise. Model pure guard $i$ as a box with opening cost $c_i$ holding prize $R$ with probability $q_i$ and $0$ otherwise. Its reservation value solves $c_i=q_i\,(R-z_i)^+$, so $z_i=R-c_i/q_i$. Pandora's theorem says open boxes in descending $z_i$ and stop when the best realized prize exceeds every unopened $z_j$. A realized prize $R$ exceeds every $z_j<R$, so the rule stops at the first denier, and descending $z_i$ is descending $q_i/c_i$. `AnyValidDenier` is therefore exactly Pandora's rule, and Theorem 5 re-derives it by exchange.

**`CanonicalRegistrationOrder`, the algorithm.** Snapshot $q_i$ and $c_i$ once. Sort the pure candidates by ratio. Speculate: walk the candidates, skipping any index at or above the current candidate denier $k_{\text{cand}}$, evaluating at most `speculation_budget` guards, lowering $k_{\text{cand}}$ whenever a speculated guard denies or errors, and memoizing every result. Then run the registration-order sweep over $0..n$, consuming memoized results and evaluating the rest. The sweep is the fold of Theorem 1, so it halts at the true $k^*\le k_{\text{cand}}$. Stateful guards are never speculated; their prechecks run in the sweep in registration order, and their tokens are committed in registration order only when the final verdict is not Deny. Contributions are collected per guard and flattened by index, which is the sort by registration index the task asks for, done without a sort.

**Theorem 3, schedule invariance.** For every speculation budget $b$ and every `OrderPolicy`, `CanonicalRegistrationOrder` returns the same `GuardDecision` as $b=0$, which is the registration-order two-phase fold.

*Proof.* The speculative phase evaluates only `SafePure` guards, whose results are deterministic functions of the context, and stores them in `memo`. The sweep consumes `memo[i]` or evaluates $g_i$, so it observes the same result sequence the $b=0$ sweep observes. By Theorem 1 both halt at the same $k^*$ with the same contributions, and the flatten is by index in both. Stateful prechecks and commits run in registration order in both. $\square$

**Theorem 4, legacy refinement.** With every guard wrapped in `LegacyAdapter`, canonical mode at any budget equals the patched `GuardPipeline`. *Proof.* Adapters are `StatefulCommit`, so the speculative phase is empty, the sweep calls `Guard::evaluate` in registration order with the same four arms and the same markers, and no tokens exist, so the commit loop is a no-op. $\square$ Native two-phase guards owe a per-guard refinement obligation: pure-phase verdict and evidence followed by commit evidence must equal the legacy guard's output. Deferring commits is sound under the independence contract that distinct guards' tokens touch disjoint state.

**Cost accounting.** With $S$ the stateful set and $\mathrm{Spec}$ the speculated set,

$$
\mathbb E[\mathrm{cost}_{\mathrm{legacy}}]=\mathbb E\Big[\sum_{i\le k^*}c_i^{\mathrm{pre}}+\sum_{j\in S,\,j<k^*}c_j^{\mathrm{commit}}\Big],\qquad
\mathbb E[\mathrm{cost}_{\mathrm{canon}}]=\mathbb E\Big[\sum_{i\le k^*}c_i^{\mathrm{pre}}+\sum_{i\in\mathrm{Spec},\,i>k^*}c_i+\mathbb 1[k^*=n]\sum_{j\in S}c_j^{\mathrm{commit}}\Big].
$$

The first term is forced by Theorem 2. Speculating on candidate $i$ is wasted exactly when $k^*<i$, which under independence has probability $1-\prod_{j<i}(1-q_j)$. The exact single-thread rule is to speculate on $i$ only if the latency recovered by overlapping it exceeds $c_i\,[1-\prod_{j<i}(1-q_j)]$. With no concurrency that recovery is zero, so the default budget is 0, and the ratio order is exported through `candidates` as the dispatch order for a concurrent executor.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate { pub idx: usize, pub q: FixedQ16_16, pub c: u32 }

/// Descending q/c by exact cross-multiplication; ties by ascending index.
pub fn ratio_cmp(a: &Candidate, b: &Candidate) -> Ordering {
    let lhs = u64::from(a.q.0).checked_mul(u64::from(b.c));
    let rhs = u64::from(b.q.0).checked_mul(u64::from(a.c));
    match (lhs, rhs) {
        (Some(l), Some(r)) => r.cmp(&l).then_with(|| a.idx.cmp(&b.idx)),
        _ => a.idx.cmp(&b.idx),
    }
}

pub trait OrderPolicy: Send + Sync { fn order(&self, candidates: &mut [Candidate]); }
#[derive(Default)]
pub struct RatioOrder;
impl OrderPolicy for RatioOrder {
    fn order(&self, c: &mut [Candidate]) { c.sort_unstable_by(ratio_cmp); }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyWitnessMode { AnyValidDenier, CanonicalRegistrationOrder }

pub struct GuardInternalDiagnostic { pub guard_index: usize, pub guard_name: String, pub error: KernelError }
pub trait DiagnosticSink: Send + Sync { fn record(&self, diagnostic: GuardInternalDiagnostic); }
pub struct NullDiagnosticSink;
impl DiagnosticSink for NullDiagnosticSink { fn record(&self, _: GuardInternalDiagnostic) {} }

fn marker(name: &str, reason: &'static str) -> GuardEvidence {
    GuardEvidence { guard_name: name.to_string(), verdict: false, details: Some(reason.to_string()) }
}

type PureResult = Result<PreparedGuardDecision, KernelError>;
fn halts(r: &PureResult) -> bool { matches!(r, Err(_)) || matches!(r, Ok(p) if matches!(p.verdict, Verdict::Deny)) }

pub struct TwoPhaseGuardPipeline<O: OrderPolicy = RatioOrder> {
    guards: Vec<Box<dyn TwoPhaseGuard>>,
    mode: DenyWitnessMode,
    speculation_budget: u32,
    order: O,
    sink: Box<dyn DiagnosticSink>,
}

impl<O: OrderPolicy> TwoPhaseGuardPipeline<O> {
    pub fn new(guards: Vec<Box<dyn TwoPhaseGuard>>, mode: DenyWitnessMode,
               speculation_budget: u32, order: O, sink: Box<dyn DiagnosticSink>) -> Self {
        Self { guards, mode, speculation_budget, order, sink }
    }

    /// Ratio-ordered pure candidates plus stateful indices in registration order.
    /// Also the dispatch order for a concurrent executor.
    pub fn candidates(&self, ctx: &GuardContext) -> (Vec<Candidate>, Vec<usize>) {
        let (mut pure, mut stateful) = (Vec::new(), Vec::new());
        for (idx, g) in self.guards.iter().enumerate() {
            match g.declaration() {
                GuardEvidenceDeclaration::SafePure => pure.push(Candidate {
                    idx, q: g.empirical_deny_prob_q16(ctx), c: g.estimated_cost_us().max(1) }),
                GuardEvidenceDeclaration::StatefulCommit => stateful.push(idx),
            }
        }
        self.order.order(&mut pure);
        (pure, stateful)
    }

    pub fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let n = self.guards.len();
        let mut memo: Vec<Option<PureResult>> = (0..n).map(|_| None).collect();
        let (pure, stateful) = self.candidates(ctx);
        let order: Vec<usize> = match self.mode {
            DenyWitnessMode::AnyValidDenier =>
                pure.iter().map(|c| c.idx).chain(stateful).collect(),
            DenyWitnessMode::CanonicalRegistrationOrder => {
                let (mut k_cand, mut spent) = (n, 0u32);
                for cand in &pure {
                    if spent >= self.speculation_budget { break; }
                    if cand.idx >= k_cand { continue; }
                    let (Some(g), Some(slot)) = (self.guards.get(cand.idx), memo.get_mut(cand.idx)) else { continue };
                    let r = g.evaluate_pure(ctx);
                    spent = spent.saturating_add(1);
                    if halts(&r) { k_cand = cand.idx; }
                    *slot = Some(r);
                }
                (0..n).collect()
            }
        };
        Ok(self.run_in_order(ctx, &order, &mut memo))
    }

    /// The fold of Theorem 1 over `order`, then commits in registration order, then flatten by `order`.
    fn run_in_order(&self, ctx: &GuardContext, order: &[usize], memo: &mut [Option<PureResult>]) -> GuardDecision {
        let n = self.guards.len();
        let mut contribs: Vec<Vec<GuardEvidence>> = (0..n).map(|_| Vec::new()).collect();
        let mut tokens: Vec<Option<PreparedGuardToken>> = (0..n).map(|_| None).collect();
        let mut verdict = Verdict::Allow;
        for &i in order {
            let (Some(guard), Some(slot), Some(contrib), Some(tok)) =
                (self.guards.get(i), memo.get_mut(i), contribs.get_mut(i), tokens.get_mut(i)) else { continue };
            let result = match slot.take() { Some(r) => r, None => guard.evaluate_pure(ctx) };
            match result {
                Ok(p) => match p.verdict {
                    Verdict::Allow => { if KEEP_ALLOW_EVIDENCE { *contrib = p.evidence; } *tok = p.token; }
                    Verdict::PendingApproval => { *contrib = p.evidence; *tok = p.token; verdict = Verdict::PendingApproval; }
                    Verdict::Deny => {
                        *contrib = p.evidence;
                        contrib.push(marker(guard.name(), GUARD_DENY_PUBLIC_REASON));
                        verdict = Verdict::Deny; break;
                    }
                },
                Err(error) => {
                    self.sink.record(GuardInternalDiagnostic { guard_index: i, guard_name: guard.name().to_string(), error });
                    contrib.push(marker(guard.name(), GUARD_ERROR_PUBLIC_REASON));
                    verdict = Verdict::Deny; break;
                }
            }
        }
        if !matches!(verdict, Verdict::Deny) {
            for (i, tok) in tokens.iter_mut().enumerate() {
                if let (Some(t), Some(g), Some(c)) = (tok.take(), self.guards.get(i), contribs.get_mut(i)) {
                    c.push(g.commit_prepared(t));
                }
            }
        }
        let evidence: Vec<GuardEvidence> = order.iter()
            .filter_map(|&i| contribs.get_mut(i)).flat_map(core::mem::take).collect();
        match verdict {
            Verdict::Deny => GuardDecision::deny(evidence),
            verdict => GuardDecision { verdict, evidence }, // or the crate's non-deny constructor
        }
    }
}
```

Tokens on the Deny path are dropped, which is release-on-deny by construction. A budget guard built on `formal_aeneas` puts the `BudgetCommitResult` computed by the pure `budget_commit` into its token during `evaluate_pure`, and `commit_prepared` stores it through `ledger_apply` with op `1`. If `budget_precheck` fails, the pure phase returns `Deny` and no token.

**Redaction patch for `pipeline.rs:92-99`.** The `Err(e)` arm currently interpolates the error into the public receipt. Replace it with the static reason and route the payload to the sink. The pipeline gains one additive field, `diagnostics: Box<dyn DiagnosticSink>`, defaulting to `NullDiagnosticSink`, and the loop becomes `for (guard_index, guard) in self.guards.iter().enumerate()`.

```rust
Err(e) => {
    self.diagnostics.record(GuardInternalDiagnostic {
        guard_index, guard_name: guard.name().to_string(), error: e });
    evidence.push(GuardEvidence {
        guard_name: guard.name().to_string(),
        verdict: false,
        details: Some(GUARD_ERROR_PUBLIC_REASON.to_string()),
    });
    return Ok(GuardDecision::deny(evidence));
}
```

**Lemma 6, redaction.** After the patch, `GuardDecision` is a function of guard names, verdicts, and guard-emitted evidence only. The error value is not in that function's domain, so no receipt hash, including every `ChioReceipt` carrying a key from `RESERVED_RECEIPT_METADATA_KEYS`, can depend on error content, and two runs that differ only in error text produce identical receipts. $\square$ This is the one intentional public-output change in Slice P2; all equivalence claims are against the patched pipeline.

## 3. Wald SPRT for streaming guards, and the harnesses

A chunked guard such as `OutputSanitizer` or `BehavioralProfileGuard` receives a Q16.16 log-likelihood-ratio increment $z_k=\ln\frac{p_1(x_k)}{p_0(x_k)}$ per chunk from its Tier-0 micro-model, where $H_1$ is "deny". Wald's test accumulates $\Lambda_n=\sum_{k\le n}z_k$ and stops at the first $n$ with $\Lambda_n\ge A$, deciding Deny, or $\Lambda_n\le B$, deciding Allow, where $A=\ln\frac{1-\beta}{\alpha}$ and $B=\ln\frac{\beta}{1-\alpha}$. Wald's inequalities bound the realized errors by $\alpha'\le\frac{\alpha}{1-\beta}$, $\beta'\le\frac{\beta}{1-\alpha}$, and $\alpha'+\beta'\le\alpha+\beta$. The expected chunk counts are $\mathbb E_0[N]\approx\frac{(1-\alpha)B+\alpha A}{\mathbb E_0[z]}$ and $\mathbb E_1[N]\approx\frac{\beta B+(1-\beta)A}{\mathbb E_1[z]}$. In Kleene terms, Continue is $\bot$, Allow is $+$, Deny is $-$. Truncation at `max_chunks` resolves $\bot$ to the conservative fallback, Deny or `PendingApproval`, and accumulator overflow always resolves to Deny.

| $\alpha=\beta$ | $A$ in nats | $A$ in Q16.16 |
|---|---|---|
| 0.05 | 2.944 | 192 967 |
| 0.01 | 4.595 | 301 146 |
| 0.001 | 6.907 | 452 641 |

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Llr16(pub i32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SprtVerdict { Continue, Deny, Allow, Escalate }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TruncationPolicy { Deny, PendingApproval }

#[derive(Clone, Copy, Debug)]
pub struct SprtConfig { upper_a: i64, lower_b: i64, max_chunks: u32, truncation: TruncationPolicy }

impl SprtConfig {
    pub const ALPHA_BETA_5E2: (i64, i64) = (192_967, -192_967);
    pub const ALPHA_BETA_1E2: (i64, i64) = (301_146, -301_146);
    pub const ALPHA_BETA_1E3: (i64, i64) = (452_641, -452_641);
    pub const fn new(upper_a: i64, lower_b: i64, max_chunks: u32, truncation: TruncationPolicy) -> Option<Self> {
        if lower_b < 0 && upper_a > 0 && max_chunks >= 1 {
            Some(Self { upper_a, lower_b, max_chunks, truncation })
        } else { None }
    }
}

pub struct SprtGuardState { cfg: SprtConfig, lambda: i64, chunks: u32, decided: Option<SprtVerdict> }

impl SprtGuardState {
    pub const fn new(cfg: SprtConfig) -> Self { Self { cfg, lambda: 0, chunks: 0, decided: None } }
    pub fn llr(&self) -> i64 { self.lambda }
    pub fn chunks_seen(&self) -> u32 { self.chunks }
    pub fn decided(&self) -> Option<SprtVerdict> { self.decided }

    pub fn step(&mut self, z: Llr16) -> SprtVerdict {
        if let Some(d) = self.decided { return d; }
        let Some(next) = self.lambda.checked_add(i64::from(z.0)) else {
            return self.decide(SprtVerdict::Deny);
        };
        self.lambda = next;
        self.chunks = self.chunks.saturating_add(1);
        if next >= self.cfg.upper_a { return self.decide(SprtVerdict::Deny); }
        if next <= self.cfg.lower_b { return self.decide(SprtVerdict::Allow); }
        if self.chunks >= self.cfg.max_chunks {
            return self.decide(match self.cfg.truncation {
                TruncationPolicy::Deny => SprtVerdict::Deny,
                TruncationPolicy::PendingApproval => SprtVerdict::Escalate,
            });
        }
        SprtVerdict::Continue
    }
    fn decide(&mut self, v: SprtVerdict) -> SprtVerdict { self.decided = Some(v); v }
}
```

The harnesses use one symbolic guard type that implements both `Guard` and `TwoPhaseGuard`, so the real `GuardPipeline` and the two-phase pipeline see literally the same guards. Verdicts come from `kani::any()` and never from the scores, which is the model of the learned predictor as unconstrained nondeterminism. The permutation is injected through `OrderPolicy`, so every ordering is covered, not only those the ratio comparator happens to produce.

```rust
#[cfg(any(kani, loom, test))]
mod sym {
    use super::*;
    pub const N: usize = 4;
    pub const NAMES: [&str; N] = ["g0", "g1", "g2", "g3"];

    #[derive(Clone)]
    pub struct SymGuard { pub idx: usize, pub pure: bool, pub code: u8, pub with_evidence: bool, pub q: u32, pub c: u32 }

    fn sym_error() -> KernelError { KernelError::from("sym") } // any existing constructor

    impl SymGuard {
        fn produce(&self) -> Result<(Verdict, Vec<GuardEvidence>), KernelError> {
            let name = NAMES.get(self.idx).copied().unwrap_or("g?");
            let verdict = match self.code { 0 => Verdict::Allow, 1 => Verdict::PendingApproval, 2 => Verdict::Deny, _ => return Err(sym_error()) };
            let ev = if self.with_evidence {
                alloc::vec![GuardEvidence { guard_name: name.to_string(), verdict: self.code != 2, details: None }]
            } else { Vec::new() };
            Ok((verdict, ev))
        }
    }
    impl Guard for SymGuard {
        fn name(&self) -> &str { NAMES.get(self.idx).copied().unwrap_or("g?") }
        fn evaluate(&self, _: &GuardContext) -> Result<GuardDecision, KernelError> {
            let (verdict, evidence) = self.produce()?;
            Ok(match verdict { Verdict::Deny => GuardDecision::deny(evidence), verdict => GuardDecision { verdict, evidence } })
        }
    }
    impl TwoPhaseGuard for SymGuard {
        fn name(&self) -> &str { Guard::name(self) }
        fn declaration(&self) -> GuardEvidenceDeclaration {
            if self.pure { GuardEvidenceDeclaration::SafePure } else { GuardEvidenceDeclaration::StatefulCommit }
        }
        fn evaluate_pure(&self, _: &GuardContext) -> Result<PreparedGuardDecision, KernelError> {
            let (verdict, evidence) = self.produce()?;
            Ok(PreparedGuardDecision { verdict, evidence, token: None })
        }
        fn commit_prepared(&self, _: PreparedGuardToken) -> GuardEvidence {
            GuardEvidence { guard_name: Guard::name(self).to_string(), verdict: true, details: None }
        }
        fn estimated_cost_us(&self) -> u32 { self.c }
        fn empirical_deny_prob_q16(&self, _: &GuardContext) -> FixedQ16_16 { FixedQ16_16(self.q) }
    }

    pub struct FixedOrder { pub rank: [u8; N] }
    impl OrderPolicy for FixedOrder {
        fn order(&self, c: &mut [Candidate]) {
            c.sort_unstable_by_key(|cand| self.rank.get(cand.idx).copied().unwrap_or(u8::MAX));
        }
    }
    pub fn is_permutation(p: &[u8; N]) -> bool {
        let mut seen = [false; N];
        for &i in p {
            let Some(s) = seen.get_mut(usize::from(i)) else { return false };
            if *s { return false; }
            *s = true;
        }
        true
    }
    pub fn same(a: &GuardDecision, b: &GuardDecision) -> bool {
        matches!((&a.verdict, &b.verdict), (Verdict::Allow, Verdict::Allow)
            | (Verdict::PendingApproval, Verdict::PendingApproval) | (Verdict::Deny, Verdict::Deny))
            && a.evidence.len() == b.evidence.len()
            && a.evidence.iter().zip(&b.evidence).all(|(x, y)|
                x.guard_name == y.guard_name && x.verdict == y.verdict && x.details == y.details)
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{sym::*, *};

    #[kani::proof]
    #[kani::unwind(6)]
    fn canonical_mode_equals_real_pipeline_for_all_orders_profiles_budgets() {
        let codes: [u8; N] = kani::any();
        kani::assume(codes.iter().all(|c| *c < 4));
        let pure: [bool; N] = kani::any();
        let with_evidence: [bool; N] = kani::any();
        let scores: [u32; N] = kani::any();
        let rank: [u8; N] = kani::any();
        kani::assume(is_permutation(&rank));
        let budget: u32 = kani::any();
        kani::assume(budget <= N as u32);

        let guards: Vec<SymGuard> = (0..N).map(|i| SymGuard {
            idx: i, pure: pure[i], code: codes[i], with_evidence: with_evidence[i], q: scores[i], c: 1 }).collect();
        let ctx = GuardContext::default();

        let legacy = crate::pipeline::GuardPipeline::new(
            guards.iter().cloned().map(|g| Box::new(g) as Box<dyn Guard>).collect());
        let reference = legacy.evaluate(&ctx).unwrap();

        let two_phase = TwoPhaseGuardPipeline::new(
            guards.into_iter().map(|g| Box::new(g) as Box<dyn TwoPhaseGuard>).collect(),
            DenyWitnessMode::CanonicalRegistrationOrder, budget, FixedOrder { rank }, Box::new(NullDiagnosticSink));
        let got = two_phase.evaluate(&ctx).unwrap();
        assert!(same(&got, &reference));
    }

    #[kani::proof]
    fn ratio_cmp_is_a_total_order() {
        let a: Candidate = Candidate { idx: 0, q: FixedQ16_16(kani::any()), c: kani::any() };
        let b: Candidate = Candidate { idx: 1, q: FixedQ16_16(kani::any()), c: kani::any() };
        let c: Candidate = Candidate { idx: 2, q: FixedQ16_16(kani::any()), c: kani::any() };
        kani::assume(a.c >= 1 && b.c >= 1 && c.c >= 1);
        assert_eq!(ratio_cmp(&a, &b), ratio_cmp(&b, &a).reverse());
        if ratio_cmp(&a, &b) != Ordering::Greater && ratio_cmp(&b, &c) != Ordering::Greater {
            assert_ne!(ratio_cmp(&a, &c), Ordering::Greater);
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn sprt_is_terminal_and_threshold_sound() {
        let (a, b) = SprtConfig::ALPHA_BETA_1E2;
        let mut st = SprtGuardState::new(SprtConfig::new(a, b, 4, TruncationPolicy::Deny).unwrap());
        let mut first: Option<SprtVerdict> = None;
        for _ in 0..5 {
            let before = st.llr();
            let z: i32 = kani::any();
            let v = st.step(Llr16(z));
            match first {
                Some(f) => assert_eq!(f, v),
                None => match v {
                    SprtVerdict::Continue => assert!(st.llr() < a && st.llr() > b && st.chunks_seen() < 4),
                    SprtVerdict::Allow => { assert!(st.llr() <= b); first = Some(v); }
                    SprtVerdict::Deny => {
                        assert!(st.llr() >= a || st.chunks_seen() >= 4 || before.checked_add(i64::from(z)).is_none());
                        first = Some(v);
                    }
                    SprtVerdict::Escalate => assert!(false, "policy is Deny"),
                },
            }
        }
    }
}
```

The Loom harness models the `ArcSwap` weight table as an atomic generation counter. Production code reads the table through an `ArcSwap::load` in `empirical_deny_prob_q16`; the loom guard reads a `loom::sync::atomic::AtomicU32` instead. The property is stronger than snapshot consistency: because scores only choose the order and Theorem 3 makes the output order-invariant, the decision equals the registration-order reference under every interleaving, torn or not.

```rust
#[cfg(loom)]
mod loom_tests {
    use super::{sym::*, *};
    use loom::sync::{atomic::{AtomicU32, Ordering as AO}, Arc};

    struct ScoredGuard { inner: SymGuard, weights: Arc<AtomicU32> }
    impl TwoPhaseGuard for ScoredGuard {
        fn name(&self) -> &str { TwoPhaseGuard::name(&self.inner) }
        fn declaration(&self) -> GuardEvidenceDeclaration { self.inner.declaration() }
        fn evaluate_pure(&self, ctx: &GuardContext) -> Result<PreparedGuardDecision, KernelError> { self.inner.evaluate_pure(ctx) }
        fn commit_prepared(&self, t: PreparedGuardToken) -> GuardEvidence { self.inner.commit_prepared(t) }
        fn estimated_cost_us(&self) -> u32 { self.inner.c }
        fn empirical_deny_prob_q16(&self, _: &GuardContext) -> FixedQ16_16 {
            // One load per evaluate, like `ArcSwap::load`; the weight update races with the pipeline.
            FixedQ16_16(self.weights.load(AO::Acquire).wrapping_mul(0x9E37_79B9).wrapping_add(self.inner.idx as u32))
        }
    }

    #[test]
    fn canonical_mode_is_invariant_under_concurrent_weight_updates() {
        loom::model(|| {
            let codes = [0u8, 2, 1, 2];
            let pure = [true, true, false, true];
            

```rust
            let weights = Arc::new(AtomicU32::new(0));
            let guards: Vec<Box<dyn TwoPhaseGuard>> = (0..N).map(|i| Box::new(ScoredGuard {
                inner: SymGuard { idx: i, pure: pure[i], code: codes[i], with_evidence: true, q: 0, c: 1 },
                weights: weights.clone(),
            }) as Box<dyn TwoPhaseGuard>).collect();
            let pipeline = Arc::new(TwoPhaseGuardPipeline::new(
                guards, DenyWitnessMode::CanonicalRegistrationOrder, N as u32, RatioOrder, Box::new(NullDiagnosticSink)));

            let writer_weights = weights.clone();
            let writer = loom::thread::spawn(move || {
                writer_weights.store(1, AO::Release);
                writer_weights.store(2, AO::Release);
            });
            let ctx = GuardContext::default();
            let got = pipeline.evaluate(&ctx).unwrap();
            writer.join().unwrap();

            // Registration-order reference: budget 0, identity order, same guards without weights.
            let reference_guards: Vec<Box<dyn TwoPhaseGuard>> = (0..N).map(|i| Box::new(
                SymGuard { idx: i, pure: pure[i], code: codes[i], with_evidence: true, q: 0, c: 1 }) as Box<dyn TwoPhaseGuard>).collect();
            let reference = TwoPhaseGuardPipeline::new(
                reference_guards, DenyWitnessMode::CanonicalRegistrationOrder, 0, RatioOrder, Box::new(NullDiagnosticSink))
                .evaluate(&ctx).unwrap();
            assert!(same(&got, &reference));
        });
    }
}
```

With the profile above, the minimal denier is guard 1, so the reference evidence is the evidence of guard 0, then the evidence of guard 1, then the deny marker naming guard 1. Guard 3 denies too, and whichever generation the writer has reached decides whether the speculative phase visits guard 3 before guard 1. Loom explores every interleaving, and the assertion holds in all of them because the sweep halts at index 1 and never emits anything from index 3.

Two Loom runs are worth keeping in the manifest. The run above uses budget `N` and real `RatioOrder`, so the speculative phase actually depends on the racing weights. A second run with budget `0` is the degenerate check that the reference itself is weight-independent, and it costs nothing.

**Manifest wiring.** `formal/proof-manifest.toml` gains three entries under a new `[[harness]]` table: the two Kani proofs over the pipeline and comparator, and the SPRT proof. The Loom tests register under `cargo test --features loom` with `RUSTFLAGS="--cfg loom"`. No entry in `formal/lean4/Chio/` changes, and none of the pinned signatures in `formal_aeneas.rs`, `formal_core.rs`, or `budget_split.rs` is touched. The only edit to an existing file is the `Err(e)` arm of `pipeline.rs` plus the additive `diagnostics` field with a `NullDiagnosticSink` default, so every existing proof that mentions `GuardPipeline` continues to discharge.

**Recap.** Slice P2 adds a `two_phase` module to `chio-guards` with a `TwoPhaseGuard` trait, a `TwoPhaseGuardPipeline` offering `AnyValidDenier` and `CanonicalRegistrationOrder` modes, an integer SPRT state machine for chunked guards, and Kani and Loom harnesses that check the canonical mode against the real `GuardPipeline` for every result profile, evaluation order, speculation budget, and weight-update interleaving.

- **Theorem 1** gives the exact closed form of the current pipeline's output as a function of the minimal denier $k^*$, and Corollary 1.2 pins down what commutes: the verdict join does, evidence concatenation does not.
- **Theorem 2** is the honest limit. Bit-identical canonical output forces evaluating every guard up to $k^*$, so ratio ordering saves pure-phase work only in `AnyValidDenier` mode or as a concurrent dispatch order. Canonical mode's real saving is commit elision on the Deny path.
- **Theorem 5 and the Pandora reading** prove descending $q_i/c_i$ is cost-optimal for `AnyValidDenier`, implemented without division by exact `u64` cross-multiplication.
- **Theorems 3 and 4** prove canonical mode is invariant under any speculation budget and any order, and that `LegacyAdapter` wrapping reproduces the patched pipeline exactly.
- **The redaction patch** replaces interpolated error text with the static reason and routes the payload to a `DiagnosticSink`, which Lemma 6 shows removes error content from every receipt hash.
- **The SPRT** uses precomputed Q16.16 thresholds, checked accumulation, terminal decisions, and fail-closed truncation and overflow.

Open obligations, in order of value: the per-guard refinement proof for each native `StatefulCommit` guard, which is a small Kani harness per guard comparing pure-phase plus commit evidence to the legacy output; the concurrent executor that consumes `candidates` as its dispatch order, which is where the ratio rule pays in latency; and the `KEEP_ALLOW_EVIDENCE` pin, which the differential harness settles on first run.

---

# Verbatim Treatise - `wave2_angle_3_slice_p3_copley_composer_and_receipt_witness`

I'll lay out Slice P3 as a `#![no_std]` crate design, the exact bridge into `chio-semantic-contracts`, the receipt-metadata diff, and the Lean 4 / Kani / Apalache obligations, in that order.

**Grounding caveats.** No tools are available in this session, so I worked from the signatures listed in the task. Four items are marked `ASSUMED` in the code and must be reconciled on apply: the arity of `require_exact` and `require_lowercase_hex_chars`, the error constructor used by `DeliveryContract::validate`, the debit method on `VerificationBudget`, and the fields of `WeightsBindingRequest`. Everything else is additive and touches no existing proof.

## 1. `chio-copley-composer`: dimensions, zero-allocation structures, evaluation

**Decision model.** Slice P3 instantiates the Wave 1 tuple at Tier-1. The exact computation $C(x)$ is the rule DAG over Kleene trits. The calibrated predictor $P(x;\theta)$ is UltraBERT's 537 sigmoid scores. The projection $\Pi$ maps rule outcomes onto the envelope $\{\text{Allow}, \text{Deny}, \text{Defer}\}$, where `Defer` is the always-feasible fallback $\bot_x$. The learned model only ever moves a score across a threshold. It never computes a conjunction, a disjunction, or a decision.

**Trit semantics.** For predicate $j$ with score $s_j \in [0,1]$ in Q16.16 and thresholds $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$:

$$t_j(s) = \begin{cases} + & s_j \ge \tau^{\text{pos}}_j \\ - & s_j < \tau^{\text{neg}}_j \\ \bot & \tau^{\text{neg}}_j \le s_j < \tau^{\text{pos}}_j \end{cases}$$

The three sets $A = \{j : t_j = +\}$ (`pos_active`), $B = \{j : t_j = -\}$ (`neg_blocked`), $U = \{j : t_j = \bot\}$ (`abstained`) partition $[0, 537)$. Rules are in disjunctive normal form. A clause is a conjunction of positive literals $P$, negative literals $N$, and an exact-fact lane described in Part 2. A rule is the Kleene disjunction of at most 9 clauses. With $W = 9$ words of 64 bits, every clause evaluates in bitset algebra:

$$\text{clause} = \begin{cases} - & (P \cap B) \cup (N \cap A) \neq \emptyset \\ + & P \subseteq A \wedge N \subseteq B \\ \bot & \text{otherwise} \end{cases}$$

The generic shape is `SymbolicRuleDag<N, W, K, R>` with `N` predicates, `W` predicate words, `K` clauses per rule, `R` rules. Production pins `<537, 9, 9, 236>`.

**Memory footprint.** One clause is two 72-byte bitsets plus two bytes of exact-lane mask, padded to 152 bytes. One rule is 1,376 bytes. The whole DAG is about 317 KiB of const-initialised `.rodata`. No heap, no stack copies. The hot loop is bounded by $236 \cdot 9$ clause evaluations of roughly 40 word operations each, well under the 0.5 ms Tier-1 floor. This is a Tier-1 structure, not a Tier-0 one.

```rust
// crates/security/chio-copley-composer/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const N_PREDICATES: usize = 537;
pub const PREDICATE_WORDS: usize = 9;
pub const MAX_CLAUSES_PER_RULE: usize = 9;
pub const N_RULES: usize = 236;
pub const RULE_WORDS: usize = 4;
pub const N_EXACT_FACTS: usize = 8;
/// = N_PREDICATES + N_RULES * MAX_CLAUSES_PER_RULE; asserted in tests.
pub const COMPOSE_FUEL_UPPER_BOUND: u64 = 2_661;
/// CommandLine 0..345, Image 345..442, OriginalFileName 442..499, ParentImage 499..537.
pub const FIELD_OFFSETS: [usize; 5] = [0, 345, 442, 499, 537];
const _: () = assert!(PREDICATE_WORDS << 6 >= N_PREDICATES);
const _: () = assert!(RULE_WORDS << 6 >= N_RULES);
const _: () = assert!(FIELD_OFFSETS[4] == N_PREDICATES);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecField { CommandLine, Image, OriginalFileName, ParentImage }
impl ExecField {
    pub const fn of_predicate(j: usize) -> Option<Self> {
        if j < FIELD_OFFSETS[1] { Some(Self::CommandLine) }
        else if j < FIELD_OFFSETS[2] { Some(Self::Image) }
        else if j < FIELD_OFFSETS[3] { Some(Self::OriginalFileName) }
        else if j < FIELD_OFFSETS[4] { Some(Self::ParentImage) }
        else { None }
    }
}

// ---- fixed.rs ----
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(transparent)]
pub struct FixedQ16_16(pub i32);
impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1 << 16);
    pub const fn in_unit_range(self) -> bool { 0 <= self.0 && self.0 <= Self::ONE.0 }
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) { Some(v) => Some(Self(v)), None => None }
    }
    pub const fn min(self, rhs: Self) -> Self { if self.0 <= rhs.0 { self } else { rhs } }
}

// ---- bitset.rs ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitIndexOutOfRange { pub bit: usize }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitSet<const W: usize>(pub [u64; W]);
impl<const W: usize> BitSet<W> {
    pub const EMPTY: Self = Self([0u64; W]);
    /// Only shift sites in the crate: `j & 63 < 64`, so neither can overflow.
    #[inline] const fn locate(j: usize) -> (usize, u64) { (j >> 6, 1u64 << (j & 63)) }
    pub const fn get(&self, j: usize) -> Option<bool> {
        let (w, m) = Self::locate(j);
        if w >= W { return None; }
        Some((self.0[w] & m) != 0)
    }
    pub fn set(&mut self, j: usize) -> Result<(), BitIndexOutOfRange> {
        let (w, m) = Self::locate(j);
        match self.0.get_mut(w) {
            Some(word) => { *word |= m; Ok(()) }
            None => Err(BitIndexOutOfRange { bit: j }),
        }
    }
    pub fn intersects(&self, o: &Self) -> bool { (0..W).any(|w| (self.0[w] & o.0[w]) != 0) }
    pub fn is_disjoint(&self, o: &Self) -> bool { !self.intersects(o) }
    pub fn is_subset_of(&self, o: &Self) -> bool { (0..W).all(|w| (self.0[w] & !o.0[w]) == 0) }
    pub fn is_empty(&self) -> bool { self.0.iter().all(|&x| x == 0) }
    pub fn union(&self, o: &Self) -> Self {
        let mut out = Self::EMPTY;
        for w in 0..W { out.0[w] = self.0[w] | o.0[w]; }
        out
    }
    pub fn count_ones(&self) -> u32 {
        self.0.iter().fold(0u32, |acc, x| acc.saturating_add(x.count_ones()))
    }
    /// True iff every bit at index >= n is clear.
    pub fn fits_within(&self, n: usize) -> bool {
        (0..W).all(|w| {
            let keep = n.saturating_sub(w << 6);
            if keep >= 64 { true } else { (self.0[w] >> keep) == 0 }
        })
    }
}

// ---- kleene.rs ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Trit { False, True, Unknown }
impl Trit {
    pub const fn not(self) -> Self {
        match self { Self::True => Self::False, Self::False => Self::True, Self::Unknown => Self::Unknown }
    }
    pub const fn and(self, o: Self) -> Self {
        match (self, o) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    pub const fn or(self, o: Self) -> Self {
        match (self, o) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
    pub const fn is_decided(self) -> bool { !matches!(self, Self::Unknown) }
}

// ---- calibration.rs ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CalibrationError { ThresholdOrder { predicate: usize }, OutOfUnitRange { predicate: usize } }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ScoreOutOfRange { pub predicate: usize }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvalError { Fuel(FuelExhausted), Index, Arithmetic }

/// Private fields: the only constructor enforces `neg[j] <= pos[j]` for every j.
pub struct ThresholdTable<const N: usize> { pos: [FixedQ16_16; N], neg: [FixedQ16_16; N] }
pub struct PredicateScores<const N: usize> { scores: [FixedQ16_16; N] }
impl<const N: usize> PredicateScores<N> {
    pub fn new(scores: [FixedQ16_16; N]) -> Result<Self, ScoreOutOfRange> {
        for (j, s) in scores.iter().enumerate() {
            if !s.in_unit_range() { return Err(ScoreOutOfRange { predicate: j }); }
        }
        Ok(Self { scores })
    }
}

/// Private fields: `pos_active`, `neg_blocked`, `abstained` are pairwise disjoint and cover 0..N.
pub struct TritPartition<const W: usize> { pos_active: BitSet<W>, neg_blocked: BitSet<W>, abstained: BitSet<W> }
impl<const W: usize> TritPartition<W> {
    pub const fn pos_active(&self) -> &BitSet<W> { &self.pos_active }
    pub const fn neg_blocked(&self) -> &BitSet<W> { &self.neg_blocked }
    pub const fn abstained(&self) -> &BitSet<W> { &self.abstained }
    pub fn trit(&self, j: usize) -> Option<Trit> {
        match (self.pos_active.get(j)?, self.neg_blocked.get(j)?, self.abstained.get(j)?) {
            (true, false, false) => Some(Trit::True),
            (false, true, false) => Some(Trit::False),
            (false, false, true) => Some(Trit::Unknown),
            _ => None,
        }
    }
    /// Test/Kani constructor; abstained is the complement of the decided sets below `n`.
    pub fn from_decided(pos_active: BitSet<W>, neg_blocked: BitSet<W>, n: usize) -> Option<Self> {
        if !pos_active.is_disjoint(&neg_blocked) || !pos_active.fits_within(n) || !neg_blocked.fits_within(n) {
            return None;
        }
        let mut abstained = BitSet::EMPTY;
        for j in 0..n {
            if pos_active.get(j) != Some(true) && neg_blocked.get(j) != Some(true) { abstained.set(j).ok()?; }
        }
        Some(Self { pos_active, neg_blocked, abstained })
    }
}

impl<const N: usize> ThresholdTable<N> {
    pub fn new(pos: [FixedQ16_16; N], neg: [FixedQ16_16; N]) -> Result<Self, CalibrationError> {
        for j in 0..N {
            if !(pos[j].in_unit_range() && neg[j].in_unit_range()) {
                return Err(CalibrationError::OutOfUnitRange { predicate: j });
            }
            if neg[j] > pos[j] { return Err(CalibrationError::ThresholdOrder { predicate: j }); }
        }
        Ok(Self { pos, neg })
    }
    pub fn classify(&self, j: usize, s: FixedQ16_16) -> Option<Trit> {
        let (pos, neg) = (*self.pos.get(j)?, *self.neg.get(j)?);
        Some(if s >= pos { Trit::True } else if s < neg { Trit::False } else { Trit::Unknown })
    }
    /// Distance to the threshold that decided the trit; `None` when abstained.
    pub fn margin(&self, j: usize, s: FixedQ16_16) -> Option<FixedQ16_16> {
        match self.classify(j, s)? {
            Trit::True => s.checked_sub(*self.pos.get(j)?),
            Trit::False => self.neg.get(j)?.checked_sub(s),
            Trit::Unknown => None,
        }
    }
    /// One pass over N predicates; min margin ranges over decided predicates in `referenced`.
    pub fn partition<const W: usize>(
        &self, scores: &PredicateScores<N>, referenced: &BitSet<W>,
    ) -> Result<(TritPartition<W>, FixedQ16_16), EvalError> {
        let mut p = TritPartition { pos_active: BitSet::EMPTY, neg_blocked: BitSet::EMPTY, abstained: BitSet::EMPTY };
        let mut min_margin = FixedQ16_16::ONE;
        for j in 0..N {
            let s = *scores.scores.get(j).ok_or(EvalError::Index)?;
            let trit = self.classify(j, s).ok_or(EvalError::Index)?;
            let target = match trit {
                Trit::True => &mut p.pos_active, Trit::False => &mut p.neg_blocked, Trit::Unknown => &mut p.abstained,
            };
            target.set(j).map_err(|_| EvalError::Index)?;
            if trit.is_decided() && referenced.get(j) == Some(true) {
                let m = self.margin(j, s).ok_or(EvalError::Arithmetic)?;
                min_margin = min_margin.min(m);
            }
        }
        Ok((p, min_margin))
    }
}

// ---- fuel.rs ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FuelExhausted;
pub trait FuelMeter { fn charge(&mut self, units: u64) -> Result<(), FuelExhausted>; }

// ---- dag.rs ----
/// Exact-fact lane F_0..F_7; `pos & neg == 0`, a clear bit in both means Unknown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExactFacts { pos: u8, neg: u8 }
impl ExactFacts {
    pub const NONE: Self = Self { pos: 0, neg: 0 };
    pub const fn new(pos: u8, neg: u8) -> Option<Self> { if (pos & neg) != 0 { None } else { Some(Self { pos, neg }) } }
    pub const fn pos(self) -> u8 { self.pos }
    pub const fn neg(self) -> u8 { self.neg }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Clause<const W: usize> { pub pos: BitSet<W>, pub neg: BitSet<W>, pub exact_pos: u8, pub exact_neg: u8 }
impl<const W: usize> Clause<W> {
    pub const EMPTY: Self = Self { pos: BitSet::EMPTY, neg: BitSet::EMPTY, exact_pos: 0, exact_neg: 0 };
    pub fn eval(&self, p: &TritPartition<W>, x: ExactFacts) -> Trit {
        let refuted = self.pos.intersects(&p.neg_blocked) || self.neg.intersects(&p.pos_active)
            || (self.exact_pos & x.neg) != 0 || (self.exact_neg & x.pos) != 0;
        if refuted { return Trit::False; }
        let satisfied = self.pos.is_subset_of(&p.pos_active) && self.neg.is_subset_of(&p.neg_blocked)
            && (self.exact_pos & !x.pos) == 0 && (self.exact_neg & !x.neg) == 0;
        if satisfied { Trit::True } else { Trit::Unknown }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule<const W: usize, const K: usize> { pub clauses: [Clause<W>; K], pub clause_count: u8 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DagError {
    WordWidthTooSmall, TooManyRules, ClauseCountOutOfRange { rule: usize },
    PredicateOutOfRange { rule: usize, clause: usize }, ContradictoryClause { rule: usize, clause: usize },
    EmptyClause { rule: usize, clause: usize },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TriggeredRuleBitmap(pub [u64; RULE_WORDS]);
impl TriggeredRuleBitmap {
    pub const EMPTY: Self = Self([0u64; RULE_WORDS]);
    pub fn set(&mut self, r: usize) -> Result<(), BitIndexOutOfRange> {
        let mut b = BitSet(self.0); b.set(r)?; self.0 = b.0; Ok(())
    }
    pub fn is_empty(&self) -> bool { self.0.iter().all(|&w| w == 0) }
}

pub struct RuleOutcome { pub triggered: TriggeredRuleBitmap, pub unknown: TriggeredRuleBitmap }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProjectionOutcome { Allow, Deny, Defer }
impl ProjectionOutcome {
    pub const FALLBACK: Self = Self::Defer;
    pub const fn as_str(self) -> &'static str {
        match self { Self::Allow => "allow", Self::Deny => "deny", Self::Defer => "defer" }
    }
}
impl RuleOutcome {
    pub fn project(&self) -> ProjectionOutcome {
        if !self.triggered.is_empty() { ProjectionOutcome::Deny }
        else if !self.unknown.is_empty() { ProjectionOutcome::Defer }
        else { ProjectionOutcome::Allow }
    }
}

pub struct SymbolicRuleDag<const N: usize, const W: usize, const K: usize, const R: usize> {
    rules: [Rule<W, K>; R], referenced: BitSet<W>, exact_referenced: u8,
}
pub type CopleyDag = SymbolicRuleDag<N_PREDICATES, PREDICATE_WORDS, MAX_CLAUSES_PER_RULE, N_RULES>;

impl<const N: usize, const W: usize, const K: usize, const R: usize> SymbolicRuleDag<N, W, K, R> {
    pub fn new(rules: [Rule<W, K>; R]) -> Result<Self, DagError> {
        if (W << 6) < N { return Err(DagError::WordWidthTooSmall); }
        if R > (RULE_WORDS << 6) || K > usize::from(u8::MAX) { return Err(DagError::TooManyRules); }
        let mut referenced = BitSet::EMPTY;
        let mut exact_referenced = 0u8;
        for (r, rule) in rules.iter().enumerate() {
            let count = usize::from(rule.clause_count);
            if count == 0 || count > K { return Err(DagError::ClauseCountOutOfRange { rule: r }); }
            for (c, cl) in rule.clauses.iter().enumerate().take(count) {
                if !cl.pos.fits_within(N) || !cl.neg.fits_within(N) {
                    return Err(DagError::PredicateOutOfRange { rule: r, clause: c });
                }
                if cl.pos.intersects(&cl.neg) || (cl.exact_pos & cl.exact_neg) != 0 {
                    return Err(DagError::ContradictoryClause { rule: r, clause: c });
                }
                if cl.pos.is_empty() && cl.neg.is_empty() && cl.exact_pos == 0 && cl.exact_neg == 0 {
                    return Err(DagError::EmptyClause { rule: r, clause: c });
                }
                referenced = referenced.union(&cl.pos).union(&cl.neg);
                exact_referenced |= cl.exact_pos | cl.exact_neg;
            }
        }
        Ok(Self { rules, referenced, exact_referenced })
    }
    pub const fn referenced(&self) -> &BitSet<W> { &self.referenced }
    pub const fn exact_referenced(&self) -> u8 { self.exact_referenced }
    /// Exact, data-independent fuel: sum of clause counts.
    pub fn fuel_cost(&self) -> u64 {
        self.rules.iter().fold(0u64, |a, r| a.saturating_add(u64::from(r.clause_count)))
    }
    /// Single fixed-bound pass. No short-circuit, so fuel and timing do not depend on scores.
    pub fn evaluate<M: FuelMeter>(
        &self, p: &TritPartition<W>, x: ExactFacts, meter: &mut M,
    ) -> Result<RuleOutcome, EvalError> {
        let mut triggered = TriggeredRuleBitmap::EMPTY;
        let mut unknown = TriggeredRuleBitmap::EMPTY;
        for (r, rule) in self.rules.iter().enumerate() {
            let mut acc = Trit::False;
            for cl in rule.clauses.iter().take(usize::from(rule.clause_count)) {
                meter.charge(1).map_err(EvalError::Fuel)?;
                acc = acc.or(cl.eval(p, x));
            }
            match acc {
                Trit::True => triggered.set(r).map_err(|_| EvalError::Index)?,
                Trit::Unknown => unknown.set(r).map_err(|_| EvalError::Index)?,
                Trit::False => {}
            }
        }
        Ok(RuleOutcome { triggered, unknown })
    }
}

// ---- compose.rs ----
/// Constructed only by `compose`; carries everything the receipt witness serialises.
pub struct CopleyWitness<const W: usize> {
    pub partition: TritPartition<W>, pub exact: ExactFacts,
    pub triggered: TriggeredRuleBitmap, pub unknown_rules: TriggeredRuleBitmap,
    pub min_margin_q16: FixedQ16_16, pub fuel_charged: u64, pub outcome: ProjectionOutcome,
}

pub fn compose<M: FuelMeter>(
    dag: &CopleyDag, table: &ThresholdTable<N_PREDICATES>, scores: &PredicateScores<N_PREDICATES>,
    exact: ExactFacts, meter: &mut M,
) -> Result<CopleyWitness<PREDICATE_WORDS>, EvalError> {
    meter.charge(N_PREDICATES as u64).map_err(EvalError::Fuel)?;
    let (partition, min_margin_q16) = table.partition(scores, dag.referenced())?;
    let out = dag.evaluate(&partition, exact, meter)?;
    let fuel_charged = (N_PREDICATES as u64).saturating_add(dag.fuel_cost());
    Ok(CopleyWitness {
        partition, exact, triggered: out.triggered, unknown_rules: out.unknown,
        min_margin_q16, fuel_charged, outcome: out.project(),
    })
}
```

**Lemma 1 (role-asymmetric soundness).** Under $\tau^{\text{neg}} \le \tau^{\text{pos}}$, `classify` is exhaustive and exclusive, and $t_j = + \Rightarrow s \ge \tau^{\text{pos}} \ge \tau^{\text{neg}}$, $t_j = - \Rightarrow s < \tau^{\text{neg}} \le \tau^{\text{pos}}$. *Proof.* The if-chain is exclusive by construction. For soundness, the chain alone would classify $s \ge \tau^{\text{pos}}$ as $+$ even if $s < \tau^{\text{neg}}$ when the thresholds were inverted. The invariant rules that out, so every $+$ is above both thresholds and every $-$ is below both. This is why the constructor is the only path to a `ThresholdTable`. $\square$

**Lemma 2 (clause evaluation is the Kleene conjunction).** `Clause::eval` equals $\bigwedge_{p \in P} t_p \wedge \bigwedge_{p \in N} \neg t_p$ under strong Kleene semantics. *Proof.* A Kleene conjunction is $-$ iff some literal is $-$, $+$ iff all are $+$, else $\bot$. Literal $p$ is $-$ iff $p \in B$. Literal $\neg p$ is $-$ iff $p \in A$. So the conjunction is $-$ iff $(P \cap B) \cup (N \cap A) \ne \emptyset$. It is $+$ iff $P \subseteq A$ and $N \subseteq B$. The two conditions are disjoint since $A \cap B = \emptyset$. The exact lane follows the same argument with `u8` masks. $\square$

**Theorem 1 (margin stability).** Let $m$ be `min_margin_q16` for scores $s$. For any perturbation $\delta$ with $\|\delta\|_\infty < m$, every decided referenced trit is unchanged, so $\text{Triggered}(s) \subseteq \text{Triggered}(s + \delta)$ and $\text{Refuted}(s) \subseteq \text{Refuted}(s + \delta)$. Outcome `Deny` and outcome `Allow` are stable. Only `Defer` may refine. *Proof.* For $t_j = +$, $m_j = s_j - \tau^{\text{pos}}_j$ and $|\delta_j| < m_j$ gives $s_j + \delta_j > \tau^{\text{pos}}_j$. For $t_j = -$, $m_j = \tau^{\text{neg}}_j - s_j$ gives $s_j + \delta_j < \tau^{\text{neg}}_j$. Abstained trits may become decided, which is a refinement $\bot \sqsubseteq \pm$ in the information order. Kleene $\wedge$, $\vee$, $\neg$ are monotone in that order, so every rule that was $+$ or $-$ keeps its value. `Deny` iff some rule is $+$ and `Allow` iff all rules are $-$, both preserved. $\square$

**Theorem 2 (totality, determinism, exact fuel).** `compose` is a total function of its inputs. It never panics, never allocates, and charges exactly $537 + \sum_r \text{clause\_count}_r \le 2{,}661$ units regardless of scores. *Proof.* Every index passes through `get`/`set` returning `Option`/`Result`. Every subtraction is `checked_sub`, and the unit-range contracts on scores and thresholds make `None` unreachable. The loop bounds are the const generics. There is no short-circuit, so the charge sequence is fixed by the DAG alone. $\square$ This bound is what the existing `budget_precheck` and `budget_commit` consume, with `invocation_cost = 1` and `unit_cost = COMPOSE_FUEL_UPPER_BOUND`.

**Theorem 3 (envelope preservation and verification transfer).** Lemmas 1 and 2 and Theorems 1 and 2 quantify over all trit partitions. No statement mentions $\theta$ or the threshold values beyond $\tau^{\text{neg}} \le \tau^{\text{pos}}$. Recalibrating or retraining UltraBERT therefore reproves nothing. It only changes the two digests carried in the witness of Part 3. `Defer` is in the envelope unconditionally, so $\bot_x \in \mathcal{C}(x)$ holds for every $x$.

**Lean 4 obligations.** File `formal/lean4/Chio/Copley/Kleene.lean`, additive.

```lean
namespace Chio.Copley

inductive Trit | T | F | U deriving DecidableEq, Repr

namespace Trit
def not : Trit → Trit | T => F | F => T | U => U
def and : Trit → Trit → Trit | F, _ => F | _, F => F | T, T => T | _, _ => U
def or  : Trit → Trit → Trit | T, _ => T | _, T => T | F, F => F | _, _ => U
/-- Information order: U below everything, decided values only below themselves. -/
def le : Trit → Trit → Prop | U, _ => True | a, b => a = b

theorem and_mono {a a' b b'} (ha : le a a') (hb : le b b') : le (and a b) (and a' b') := by
  cases a <;> cases a' <;> cases b <;> cases b' <;> simp_all [le, and]
theorem or_mono {a a' b b'} (ha : le a a') (hb : le b b') : le (or a b) (or a' b') := by
  cases a <;> cases a' <;> cases b <;> cases b' <;> simp_all [le, or]
theorem not_mono {a a'} (h : le a a') : le (not a) (not a') := by
  cases a <;> cases a' <;> simp_all [le, not]
end Trit

structure Thresholds where
  pos : Int
  neg : Int
  order : neg ≤ pos

def classify (t : Thresholds) (s : Int) : Trit :=
  if t.pos ≤ s then .T else if s < t.neg then .F else .U

theorem classify_T_iff (t : Thresholds) (s : Int) : classify t s = .T ↔ t.pos ≤ s := by
  unfold classify; have := t.order; split <;> split <;> simp_all <;> omega
theorem classify_F_iff (t : Thresholds) (s : Int) : classify t s = .F ↔ s < t.neg := by
  unfold classify; have := t.order; split <;> split <;> simp_all <;> omega
theorem classify_U_iff (t : Thresholds) (s : Int) : classify t s = .U ↔ t.neg ≤ s ∧ s < t.pos := by
  unfold classify; have := t.order; split <;> split <;> simp_all <;> omega

def margin (t : Thresholds) (s : Int) : Int :=
  match classify t s with | .T => s - t.pos | .F => t.neg - s | .U => 0

/-- Theorem 1, per predicate: a sub-margin perturbation never flips a decided trit. -/
theorem margin_stable (t : Thresholds) (s d : Int)
    (hdec : classify t s ≠ .U) (hd : |d| < margin t s) :
    classify t (s + d) = classify t s := by
  have ho := t.order
  rcases h : classify t s with _ | _ | _
  · rw [classify_T_iff] at h ⊢; simp [margin, classify_T_iff.mpr h] at hd
    rw [abs_lt] at hd; omega
  · rw [classify_F_iff] at h ⊢; simp [margin, classify_F_iff.mpr h] at hd
    rw [abs_lt] at hd; omega
  · exact absurd h hdec

end Chio.Copley
```

Aeneas translates `Trit::{and,or,not}`, `ThresholdTable::{classify,margin}`, `Clause::eval`, and `RuleOutcome::project` into `Chio/Copley/Generated.lean`. The refinement lemma `clause_eval_spec` equates the generated `Clause::eval` with a `Finset` fold of `Trit.and`, which is Lemma 2. The manifest entry is a new `[[module]]` block:

```toml
# formal/proof-manifest.toml (additive)
[[module]]
crate     = "chio-copley-composer"
path      = "crates/security/chio-copley-composer/src/lib.rs"
lean_out  = "formal/lean4/Chio/Copley/Generated.lean"
functions = ["Trit::and", "Trit::or", "Trit::not", "ThresholdTable::classify",
             "ThresholdTable::margin", "Clause::eval", "RuleOutcome::project"]
```

**Kani harnesses.** The learned choice is `kani::any()`. The bitset lemma is checked at `W = 1`, which is representative because every operation is word-wise identical.

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn classify_partitions_scoreline_and_margin_is_stable() {
        let pos = FixedQ16_16(kani::any());
        let neg = FixedQ16_16(kani::any());
        kani::assume(pos.in_unit_range() && neg.in_unit_range() && neg <= pos);
        let table = ThresholdTable::<1>::new([pos], [neg]).unwrap();
        let s = FixedQ16_16(kani::any());
        kani::assume(s.in_unit_range());
        let t = table.classify(0, s).unwrap();
        assert!((t == Trit::True) == (s >= pos));
        assert!((t == Trit::False) == (s < neg));
        assert!((t == Trit::Unknown) == (neg <= s && s < pos));
        if let Some(m) = table.margin(0, s) {
            assert!(m.0 >= 0);
            let d: i32 = kani::any();
            kani::assume(d.unsigned_abs() < m.0.unsigned_abs());
            let s2 = FixedQ16_16(s.0.checked_add(d).unwrap());
            assert_eq!(table.classify(0, s2), Some(t));
        }
    }

    #[kani::proof]
    fn clause_eval_is_kleene_conjunction() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume((a & b) == 0);
        let p = TritPartition::<1>::from_decided(BitSet([a]), BitSet([b]), 64).unwrap();
        let cl = Clause::<1> { pos: BitSet([kani::any()]), neg: BitSet([kani::any()]), exact_pos: 0, exact_neg: 0 };
        kani::assume(!cl.pos.intersects(&cl.neg));
        let mut expect = Trit::True;
        for j in 0..64 {
            if cl.pos.get(j) == Some(true) { expect = expect.and(p.trit(j).unwrap()); }
            if cl.neg.get(j) == Some(true) { expect = expect.and(p.trit(j).unwrap().not()); }
        }
        assert_eq!(cl.eval(&p, ExactFacts::NONE), expect);
    }

    #[kani::proof]
    fn projection_in_envelope_and_deny_iff_triggered() {
        let out = RuleOutcome { triggered: TriggeredRuleBitmap(kani::any()), unknown: TriggeredRuleBitmap(kani::any()) };
        let o = out.project();
        assert!(matches!(o, ProjectionOutcome::Allow | ProjectionOutcome::Deny | ProjectionOutcome::Defer));
        assert_eq!(o == ProjectionOutcome::Deny, !out.triggered.is_empty());
    }
}
```

**Apalache TLA+.** `formal/tla/CopleyProjection.tla` models the predictor as `\E s`, the Verification Transfer form.

```tla
---------------------------- MODULE CopleyProjection ----------------------------
EXTENDS Integers, FiniteSets
CONSTANTS
  \* @type: Int;                                        N,
  \* @type: Int;                                        R,
  \* @type: Int -> Int;                                 Pos,
  \* @type: Int -> Int;                                 Neg,
  \* @type: Int -> Set({pos: Set(Int), neg: Set(Int)}); Rules
ASSUME \A j \in 0..N-1 : Neg[j] <= Pos[j]
VARIABLES
  \* @type: Int -> Int;  score,
  \* @type: Str;         outcome

Pred == 0..N-1
Unit == 0..65536
Trit(sc, j) == IF sc[j] >= Pos[j] THEN "T" ELSE IF sc[j] < Neg[j] THEN "F" ELSE "U"
Act(sc) == {j \in Pred : Trit(sc, j) = "T"}
Blk(sc) == {j \in Pred : Trit(sc, j) = "F"}
ClauseVal(sc, c) ==
  IF c.pos \cap Blk(sc) # {} \/ c.neg \cap Act(sc) # {} THEN "F"
  ELSE IF c.pos \subseteq Act(sc) /\ c.neg \subseteq Blk(sc) THEN "T" ELSE "U"
RuleVal(sc, r) ==
  IF \E c \in Rules[r] : ClauseVal(sc, c) = "T" THEN "T"
  ELSE IF \A c \in Rules[r] : ClauseVal(sc, c) = "F" THEN "F" ELSE "U"
Triggered(sc) == {r \in 0..R-1 : RuleVal(sc, r) = "T"}
Unknown(sc)   == {r \in 0..R-1 : RuleVal(sc, r) = "U"}
Feasible == {"allow", "deny", "defer"}
Project(sc) == IF Triggered(sc) # {} THEN "deny" ELSE IF Unknown(sc) # {} THEN "defer" ELSE "allow"

Init == score \in [Pred -> Unit] /\ outcome = Project(score)
\* The learned predictor is unconstrained nondeterminism.
Next == \E s \in [Pred -> Unit] : score' = s /\ outcome' = Project(s)

EnvelopeInv        == outcome \in Feasible /\ "defer" \in Feasible
DenyIffTriggered   == (outcome = "deny") <=> (Triggered(score) # {})
AllowAllRefuted    == outcome = "allow" => \A r \in 0..R-1 : RuleVal(score, r) = "F"
===============================================================================
```

Check with `apalache-mc check --inv=EnvelopeInv,DenyIffTriggered,AllowAllRefuted --length=3 MC_CopleyProjection.tla` on an instance with `N = 8`, `R = 3`. The invariants are state predicates over `score`, so three steps suffice.

## 2. Bridge into `chio-semantic-contracts`: $C(x) \oplus P(x)$

The exact lane is a second, independent input to `Clause::eval`. Its eight trits come only from `formal_core`, `formal_aeneas`, and the witness types of `chio-semantic-contracts`. The learned lane comes only from scores. The DAG combines them with Kleene operators and nothing else. That is the epistemic partition stated mechanically: the type of `compose` admits no path from a score to an exact bit, and no path from an exact bit to a threshold.

**Binding of $F_0 \ldots F_7$** to existing signatures. An absent input yields $\bot$, never $-$. Absence of evidence is not evidence of refusal, and a rule that needs the fact abstains, which projects to `Defer`.

| Fact | Source expression |
|------|-------------------|
| $F_0$ TimeWindowValid | `classify_time_window_code(now, issued_at, expires_at) == 0` |
| $F_1$ BudgetPrecheckOk | `budget_precheck(ri, ru, ic, uc)` |
| $F_2$ BudgetCommitAccepted | `budget_commit(ri, ru, ic, uc).accepted` |
| $F_3$ ReceiptFieldsCoupled | `receipt_fields_coupled(a, b, c, d, e)` |
| $F_4$ LedgerTerminal | `ledger_is_terminal(state)` via a new `pub` wrapper |
| $F_5$ LedgerOpAccepted | `ledger_apply(state, op, amount).1` |
| $F_6$ DependencyGraphValidated | a `&ValidatedDependencyGraph` is present |
| $F_7$ InvocationVerified | a `&VerifiedSemanticInvocationV1` is present |

$F_4$ needs one additive line in `formal_aeneas.rs`, because the existing function is `pub(crate)`:

```rust
/// Additive public wrapper for the Copley exact lane; the proved function is unchanged.
pub fn ledger_terminal(state: ReservationLedger) -> bool { ledger_is_terminal(state) }
```

```rust
// crates/security/chio-copley-composer/src/semantic_bridge.rs   (feature = "semantic-bridge")
use crate::{ExactFacts, FuelExhausted, FuelMeter};
use chio_kernel_core::formal_aeneas::{ledger_apply, ledger_terminal, ReservationLedger};
use chio_kernel_core::formal_core::{budget_commit, budget_precheck, classify_time_window_code, receipt_fields_coupled};
use chio_semantic_contracts::{ValidatedDependencyGraph, VerificationBudget, VerifiedSemanticInvocationV1};

/// Index assignment is pinned in formal/proof-manifest.toml; never renumber.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum ExactFact {
    TimeWindowValid = 0, BudgetPrecheckOk = 1, BudgetCommitAccepted = 2, ReceiptFieldsCoupled = 3,
    LedgerTerminal = 4, LedgerOpAccepted = 5, DependencyGraphValidated = 6, InvocationVerified = 7,
}

pub struct ExactInputs<'a> {
    pub time: Option<(u64, u64, u64)>,
    pub budget: Option<(u64, u64, u64, u64)>,
    pub receipt_coupling: Option<[bool; 5]>,
    pub ledger: Option<ReservationLedger>,
    pub ledger_op: Option<(ReservationLedger, u8, u64)>,
    pub graph: Option<&'a ValidatedDependencyGraph>,
    pub invocation: Option<&'a VerifiedSemanticInvocationV1>,
}

#[derive(Default)]
struct FactBuilder { pos: u8, neg: u8 }
impl FactBuilder {
    fn put(&mut self, f: ExactFact, v: Option<bool>) {
        let m = 1u8 << (f as u8); // f as u8 <= 7
        match v { Some(true) => self.pos |= m, Some(false) => self.neg |= m, None => {} }
    }
    fn finish(self) -> ExactFacts { ExactFacts::new(self.pos, self.neg).unwrap_or(ExactFacts::NONE) }
}

/// Exact lane: every bit is a function of formal_core / formal_aeneas / contract witnesses only.
pub fn exact_facts(i: ExactInputs<'_>) -> ExactFacts {
    let mut f = FactBuilder::default();
    f.put(ExactFact::TimeWindowValid, i.time.map(|(now, iss, exp)| classify_time_window_code(now, iss, exp) == 0));
    f.put(ExactFact::BudgetPrecheckOk, i.budget.map(|(ri, ru, ic, uc)| budget_precheck(ri, ru, ic, uc)));
    f.put(ExactFact::BudgetCommitAccepted, i.budget.map(|(ri, ru, ic, uc)| budget_commit(ri, ru, ic, uc).accepted));
    f.put(ExactFact::ReceiptFieldsCoupled, i.receipt_coupling.map(|[a, b, c, d, e]| receipt_fields_coupled(a, b, c, d, e)));
    f.put(ExactFact::LedgerTerminal, i.ledger.map(ledger_terminal));
    f.put(ExactFact::LedgerOpAccepted, i.ledger_op.map(|(s, op, amt)| ledger_apply(s, op, amt).1));
    f.put(ExactFact::DependencyGraphValidated, i.graph.map(|_| true));
    f.put(ExactFact::InvocationVerified, i.invocation.map(|_| true));
    f.finish()
}

/// Meters `compose` against the contract crate's VerificationBudget.
pub struct SemanticFuel<'a>(pub &'a mut VerificationBudget);
impl FuelMeter for SemanticFuel<'_> {
    fn charge(&mut self, units: u64) -> Result<(), FuelExhausted> {
        // ASSUMED: the fallible debit on VerificationBudget; substitute its real name on apply.
        self.0.try_consume(units).map_err(|_| FuelExhausted)
    }
}
```

The admission sequence at the call site is: run `budget_precheck(remaining_invocations, remaining_units, 1, COMPOSE_FUEL_UPPER_BOUND)`, build `exact_facts`, call `compose` with `SemanticFuel`, then `budget_commit(..., 1, witness.fuel_charged)`. Both budget functions are already proved, so the composer adds no new budget obligation.

**Construction-time guard against shadowing.** The Wave 1 law forbids asking the model to approximate what $C(x)$ already solves. The calibration manifest carries a `shadowed_predicates` list, and `CopleyDag::new` is wrapped by a loader that rejects any rule referencing a learned predicate whose documented semantics duplicate one of $F_0 \ldots F_7$. The check is a bitset intersection against `referenced()`.

## 3. Receipt metadata, `LoadedWeights`, and `weights_binding`

**Exact diff** to `crates/core/chio-core-types/src/receipt/metadata.rs`. The new key is appended so existing positions are unchanged. The key is distinct from every current entry.

```diff
+pub const CHIO_COPLEY_WITNESS_METADATA_KEY: &str = "chio_copley_witness";
+pub const CHIO_COPLEY_WITNESS_SCHEMA: &str = "chio.copley.witness.v1";
+
-pub const RESERVED_RECEIPT_METADATA_KEYS: [&str; 35] = [
+pub const RESERVED_RECEIPT_METADATA_KEYS: [&str; 36] = [
     "admission_operation",
     "attribution",
     "chio_manifest_security_v1",
     "protocol_admission",
     BUDGET_AUTHORITY_METADATA_KEY,
     /* ... 30 existing entries unchanged ... */
+    CHIO_COPLEY_WITNESS_METADATA_KEY,
 ];
```

**Witness struct and validation.** Bitmaps are serialised word 0 first, each word as 16 lowercase hex digits, most significant nibble first. `neg_blocked` is omitted because it is the complement of `pos_active` and `abstained` below bit 537, and the validator checks exactly that partition structure.

```rust
// crates/core/chio-core-types/src/receipt/metadata.rs (additive)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopleyWitnessReceiptMetadata {
    pub schema: String,                   // CHIO_COPLEY_WITNESS_SCHEMA
    pub model_card_sha256: String,        // 64 hex, bound via evaluate_weights_binding
    pub calibration_table_sha256: String, // 64 hex, over (pos_thresh, neg_thresh) canonical bytes
    pub rule_dag_sha256: String,          // 64 hex, over the 236-rule table canonical bytes
    pub segment_input_digest: String,     // 64 hex, over the 4 visible fields as segmented
    pub pos_active_bitmap_hex: String,    // 144 hex = 9 words
    pub abstained_bitmap_hex: String,     // 144 hex = 9 words
    pub triggered_rules_hex: String,      // 64 hex  = 4 words
    pub min_margin_q16: i32,              // 0..=65536
    pub projection_outcome: String,       // "allow" | "deny" | "defer"
}

const COPLEY_PREDICATE_BITS: usize = 537;
const COPLEY_RULE_BITS: usize = 236;

impl CopleyWitnessReceiptMetadata {
    pub fn validate(&self) -> Result<()> {
        // ASSUMED arities, matching DeliveryContract::validate and FindingStatusProofMetadata::validate:
        //   require_exact(field, actual, expected) and require_lowercase_hex_chars(field, value, len).
        require_exact("chio_copley_witness.schema", &self.schema, CHIO_COPLEY_WITNESS_SCHEMA)?;
        require_lowercase_hex_chars("chio_copley_witness.model_card_sha256", &self.model_card_sha256, 64)?;
        require_lowercase_hex_chars("chio_copley_witness.calibration_table_sha256", &self.calibration_table_sha256, 64)?;
        require_lowercase_hex_chars("chio_copley_witness.rule_dag_sha256", &self.rule_dag_sha256, 64)?;
        require_lowercase_hex_chars("chio_copley_witness.segment_input_digest", &self.segment_input_digest, 64)?;
        require_lowercase_hex_chars("chio_copley_witness.pos_active_bitmap_hex", &self.pos_active_bitmap_hex, 144)?;
        require_lowercase_hex_chars("chio_copley_witness.abstained_bitmap_hex", &self.abstained_bitmap_hex, 144)?;
        require_lowercase_hex_chars("chio_copley_witness.triggered_rules_hex", &self.triggered_rules_hex, 64)?;

        let pos = decode_hex_words::<9>("chio_copley_witness.pos_active_bitmap_hex", &self.pos_active_bitmap_hex)?;
        let abst = decode_hex_words::<9>("chio_copley_witness.abstained_bitmap_hex", &self.abstained_bitmap_hex)?;
        let trig = decode_hex_words::<4>("chio_copley_witness.triggered_rules_hex", &self.triggered_rules_hex)?;
        require_bits_clear_from("chio_copley_witness.pos_active_bitmap_hex", &pos, COPLEY_PREDICATE_BITS)?;
        require_bits_clear_from("chio_copley_witness.abstained_bitmap_hex", &abst, COPLEY_PREDICATE_BITS)?;
        require_bits_clear_from("chio_copley_witness.triggered_rules_hex", &trig, COPLEY_RULE_BITS)?;
        if pos.iter().zip(abst.iter()).any(|(a, b)| (a & b) != 0) {
            return Err(invalid_receipt_metadata("chio_copley_witness", "pos_active and abstained overlap"));
        }
        if !(0..=65_536).contains(&self.min_margin_q16) {
            return Err(invalid_receipt_metadata("chio_copley_witness.min_margin_q16", "outside unit range"));
        }
        let triggered = trig.iter().any(|w| *w != 0);
        match (self.projection_outcome.as_str(), triggered) {
            ("deny", true) | ("defer", false) | ("allow", false) => Ok(()),
            ("deny", false) => Err(invalid_receipt_metadata("chio_copley_witness.projection_outcome", "deny without triggered rule")),
            ("allow", true) | ("defer", true) => Err(invalid_receipt_metadata("chio_copley_witness.projection_outcome", "triggered rule without deny")),
            _ => Err(invalid_receipt_metadata("chio_copley_witness.projection_outcome", "unknown outcome")),
        }
    }
}

fn decode_hex_words<const W: usize>(field: &'static str, hex: &str) -> Result<[u64; W]> {
    let mut out = [0u64; W];
    for (i, chunk) in hex.as_bytes().chunks(16).enumerate().take(W) {
        let s = core::str::from_utf8(chunk).map_err(|_| invalid_receipt_metadata(field, "non-utf8 hex"))?;
        out[i] = u64::from_str_radix(s, 16).map_err(|_| invalid_receipt_metadata(field, "bad hex word"))?;
    }
    Ok(out)
}

fn require_bits_clear_from(field: &'static str, words: &[u64], n: usize) -> Result<()> {
    for (w, word) in words.iter().enumerate() {
        let keep = n.saturating_sub(w << 6);
        let dirty = if keep >= 64 { false } else { (word >> keep) != 0 };
        if dirty { return Err(invalid_receipt_metadata(field, "padding bits set")); }
    }
    Ok(())
}
// `invalid_receipt_metadata` is the error constructor DeliveryContract::validate uses. ASSUMED name.
```

**Stamping in the kernel.** `chio-core-types` cannot depend on the kernel, so the weights binding happens where the witness is created. The order is fixed: bind first, serialise second, validate third. A receipt is never written for weights the card does not bind.

```rust
// crates/kernel/chio-kernel/src/copley_witness.rs (new)
use chio_copley_composer::{CopleyWitness, PREDICATE_WORDS};
use chio_core_types::receipt::metadata::{CopleyWitnessReceiptMetadata, CHIO_COPLEY_WITNESS_SCHEMA};
use chio_core_types::loaded_weights::LoadedWeights;
use crate::weights_binding::{evaluate_weights_binding, WeightsBindingError, WeightsBindingRequest};

pub enum WitnessStampError { WeightsBinding(WeightsBindingError), Metadata(chio_core_types::Error) }

pub struct WitnessDigests<'a> {
    pub model_card_sha256: &'a str, pub calibration_table_sha256: &'a str,
    pub rule_dag_sha256: &'a str, pub segment_input_digest: &'a str,
}

pub fn stamp_copley_witness(
    card: &ModelCard, weights: &dyn LoadedWeights, request: &WeightsBindingRequest<'_>,
    d: WitnessDigests<'_>, w: &CopleyWitness<PREDICATE_WORDS>,
) -> Result<CopleyWitnessReceiptMetadata, WitnessStampError> {
    // `request` is built by the existing Tier-1 admission path from weights.loaded_weights_hash()
    // and weights.provider_name(); the composer adds no fields. ASSUMED: request shape.
    evaluate_weights_binding(card, request).map_err(WitnessStampError::WeightsBinding)?;
    let md = CopleyWitnessReceiptMetadata {
        schema: CHIO_COPLEY_WITNESS_SCHEMA.to_owned(),
        model_card_sha256: d.model_card_sha256.to_owned(),
        calibration_table_sha256: d.calibration_table_sha256.to_owned(),
        rule_dag_sha256: d.rule_dag_sha256.to_owned(),
        segment_input_digest: d.segment_input_digest.to_owned(),
        pos_active_bitmap_hex: words_hex(&w.partition.pos_active().0),
        abstained_bitmap_hex: words_hex(&w.partition.abstained().0),
        triggered_rules_hex: words_hex(&w.triggered.0),
        min_margin_q16: w.min_margin_q16.0,
        projection_outcome: w.outcome.as_str().to_owned(),
    };
    md.validate().map_err(WitnessStampError::Metadata)?;
    Ok(md)
}

fn words_hex(words: &[u64]) -> String {
    use core::fmt::Write;
    let mut s = String::new();
    for w in words { let _ = write!(s, "{w:016x}"); }
    s
}
```

**Replay property.** Given the receipt and the three table digests, an auditor can recompute `triggered_rules_hex` from `pos_active_bitmap_hex` and `abstained_bitmap_hex` alone, because `Clause::eval` depends only on the partition and the exact lane, never on raw scores. The `model_card_sha256` field ties that partition to the weights that produced it through `evaluate_weights_binding`. The `min_margin_q16` field tells the auditor how far scores could have moved without changing a `Deny` or `Allow`, which is Theorem 1 in receipt form.

**Recap.** Slice P3 is a `#![no_std]`, `#![forbid(unsafe_code)]` crate whose only arithmetic is checked, holding a 537-predicate role-asymmetric threshold table with a constructor-enforced $\tau^{\text{neg}} \le \tau^{\text{pos}}$ invariant, a disjoint trit partition over `BitSet<9>`, and a `SymbolicRuleDag<537, 9, 9, 236>` that evaluates every clause in a single data-independent pass charging at most 2,661 fuel units through the existing `budget_precheck` and `budget_commit`. Exact facts $F_0 \ldots F_7$ enter through a separate lane fed only by `formal_core`, `formal_aeneas`, and the contract witness types, with one additive `pub` wrapper needed for the ledger fact. The receipt gains one reserved key, a validated witness struct, and a kernel-side stamping path that binds weights before serialising. The proofs quantify over arbitrary trits, so recalibration changes digests and nothing else. Reconcile the four `ASSUMED` markers against the real helper signatures before merging.

---

# Verbatim Treatise - `wave2_angle_4_cross_workstream_unification`

Writing the Wave 2 Angle 4 treatise now, grounded in the pinned signatures from the brief. Assumption stated up front: every listing below is a proposed additive module. Nothing redefines a signature pinned in `formal/proof-manifest.toml`, so the existing Lean 4, Aeneas, Kani, and Apalache obligations discharge unchanged.

## 0. The unifying law: every enforcement substrate is a sensor and a sink

All five workstreams reduce to one statement about the canonical tuple $\mathcal{D}_\ell = (\mathcal{X}_\ell, C_\ell, P_\ell, \mathcal{C}_\ell, \Pi_{\mathcal{C}_\ell(x)}, W_\ell)$. Each platform contributes two things and only two things. It is a **sensor** that produces $x \in \mathcal{X}_\ell$, which the exact core maps to facts $C_\ell(x) \in \mathbb{K}_3^{F_\ell}$. And it is a **sink** that consumes a `ShieldedAction<A>` and realizes it with platform primitives. The learned predictor never touches the sink. The sink never consults the predictor. This is the whole architecture, and it is what makes the five workstreams one workstream.

**Theorem 0 (Envelope Preservation and Verification Transfer).** Let $\mathcal{C}: \mathcal{X} \to 2^{\mathcal{A}}$ satisfy $\bot_x \in \mathcal{C}(x)$ for all $x$, and let $\Pi_{\mathcal{C}(x)}: \mathcal{A} \to \mathcal{C}(x)$ be any total map that is the identity on $\mathcal{C}(x)$. Let $\phi$ be a safety property such that for every reachable state $s$ and every $a \in \mathcal{C}(x(s))$, the successor $\mathrm{step}(s,a)$ preserves $\phi$. Then for every predictor $P$, with any parameters $\theta$ and any shadow-price vector $\boldsymbol{\lambda}$, the closed loop $s \mapsto \mathrm{step}(s, \Pi_{\mathcal{C}(x(s))}(P(x(s);\theta,\boldsymbol\lambda)))$ satisfies $\phi$.

*Proof.* By induction on the trace. The initial state satisfies $\phi$ by assumption. At step $k$, $\Pi(P(x_k)) \in \mathcal{C}(x_k)$ by totality of $\Pi$. The preservation hypothesis then gives $\phi$ at step $k+1$. The predictor appears nowhere in the induction, so the conclusion is uniform in $(\theta, \boldsymbol\lambda)$. $\square$

The preservation hypothesis is exactly what `kani::any()` and `\E a \in Feasible(s)` express. Two design rules follow and recur in every section. First, when a fact in $C_\ell(x)$ is $\bot$, the envelope is the intersection over both resolutions of that fact, so unknown telemetry can only shrink $\mathcal{C}_\ell(x)$. Second, the trusted computing base is $C_\ell$, $\Pi$, and the sensor path. On Linux the sensor path is the LSM hook. On macOS it is EndpointSecurity. In the economy it is the signed receipt. The predictor is outside the TCB on all three.

The following shared primitives are used by every section.

```rust
// crates/kernel/chio-kernel-core/src/shadow.rs  (proposed, additive)
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

/// Q16.16 signed fixed point over i64. Integer-only so the Tier-0 hot path
/// is deterministic and provable; every operation is checked.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedQ16_16(i64);

impl FixedQ16_16 {
    pub const SCALE: i64 = 65_536;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(Self::SCALE);

    pub const fn from_bits(bits: i64) -> Self { Self(bits) }
    pub const fn to_bits(self) -> i64 { self.0 }
    pub fn from_int(v: i32) -> Option<Self> {
        i64::from(v).checked_mul(Self::SCALE).map(Self)
    }
    pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
    pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(Self) }
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        self.0.checked_mul(o.0).and_then(|p| p.checked_div(Self::SCALE)).map(Self)
    }
    pub fn checked_div(self, o: Self) -> Option<Self> {
        if o.0 == 0 { return None; }
        self.0.checked_mul(Self::SCALE).and_then(|n| n.checked_div(o.0)).map(Self)
    }
    pub fn clamp_nonneg(self) -> Self { if self.0 < 0 { Self::ZERO } else { self } }
    /// Floor to a u16, saturating at `cap`. Used for basis-point shares and weights.
    pub fn floor_u16_capped(self, cap: u16) -> u16 {
        let whole = self.0.checked_div(Self::SCALE).unwrap_or(0);
        if whole <= 0 { 0 } else if whole >= i64::from(cap) { cap } else { whole as u16 }
    }
}

/// Lagrangian shadow prices. One entry per scarce resource in the Tier-0 dual.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowPrices {
    pub budget: FixedQ16_16,
    pub fuel: FixedQ16_16,
    pub latency: FixedQ16_16,
    pub memory: FixedQ16_16,
    pub escrow: FixedQ16_16,
}

/// Witness that a value passed through a projection. Private constructor:
/// the only way to obtain one is a `Shield::project` call in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedAction<A> { inner: A }

impl<A> ShieldedAction<A> {
    pub(crate) const fn seal(inner: A) -> Self { Self { inner } }
    pub fn into_inner(self) -> A { self.inner }
    pub fn as_ref(&self) -> &A { &self.inner }
}

/// Every envelope implements this. `fallback` is the conservative ⊥ that is
/// always a member; `contains` is the exact test the proofs quantify over.
pub trait Envelope {
    type Action: Copy;
    fn fallback(&self) -> Self::Action;
    fn contains(&self, a: Self::Action) -> bool;
}

pub trait Shield: Envelope {
    /// Total, idempotent on members, and O(1) for every envelope in this treatise.
    fn project(&self, proposal: Option<Self::Action>) -> ShieldedAction<Self::Action>;
}
```

## 1. Swarm economy: settlement holds as the algebraic envelope for shadow prices

**Capability roots and the relying-party wedge.** An ID-JAG, the Identity Assertion JWT Authorization Grant, is what a relying party presents to a resource's authorization server to obtain a token scoped to a user's identity assertion. Chio sits as that relying party. The root capability $c_0$ of a `SwarmAuthorityBundle` binds the JAG's `sub`, `aud`, `iat`, and `exp`. Each link in the `SwarmDelegationWitnessChain` is checked with the pinned `classify_time_window_code(now, issued_at, expires_at)`, and a chain is valid only if every link returns code 0. Authority attenuates monotonically along the chain: a child's effective budget share is the parent's share scaled by `share_bps / 10_000`, and `BudgetSplit` refuses `OversubscribedSiblings` when sibling shares would exceed `parent_share_bps`. The wedge is economic rather than only cryptographic. A counterparty that accepts a Chio receipt is accepting a settlement claim whose authority has already been bounded by $C(x)$, so the receipt is worth exactly what the chain says and never more.

**The ledger lattice.** The pinned `ReservationLedger` has four buckets. Define the settled mass $\sigma(l) = \text{committed} + \text{released} + \text{retained}$ and the outstanding hold $\omega(l) = \text{reserved} - \sigma(l)$. The conservation invariant is $\sigma(l) \le \text{reserved}$, and `ledger_is_terminal` holds exactly when $\omega(l) = 0$. A `FindingDeliverySettlementMode::LocalReversibleHold` is a ledger with $\omega(l) > 0$ inside a valid time window. Three facts make this the envelope for every economic controller:

1. **Fan-out feasibility.** A `SwarmBudgetPool` may create child ledgers only while $\sum_c \text{reserved}_c \le \omega(\text{parent})$. This is the `reserve` op gated by the parent's outstanding hold.
2. **Fan-in determinism.** When a child reaches terminal state, its three settled buckets map one-to-one onto parent ops 1, 2, and 3. No learned choice exists here. $C(x)$ computes it.
3. **Expiry is exact.** When the window reports code 2, the hold is released by the exact core. The controllers never decide expiry.

So the economic envelope is
$$F(s) = \Big\{ (\text{op}, a) \;:\; \text{op} \in \{1,2,3\},\ a \le \omega(l_s)\Big\} \cup \Big\{(0, a) : a \le \omega(\text{parent}) - \textstyle\sum_c \text{reserved}_c \Big\} \cup \{\text{Hold}\},$$
with $\text{Hold}$ the fallback $\bot_x$. Share admission has its own envelope, a capped simplex $\{ s \in \mathbb{Z}_{\ge 0} : s \le \min(10{,}000,\ \text{parent\_share\_bps} - \text{current\_total\_child\_bps}) \}$ together with the `Defer` fallback. Both are $O(1)$ to test because `BudgetSplit` already maintains the running sibling total.

**What the controllers optimize.** Tier-0 proposes a sub-delegation share by maximizing a concave surplus against shadow prices,
$$s^\star = \arg\max_s\ \big(a_c s - \tfrac{b_c}{2} s^2\big) - (\lambda_{\text{budget}} + \lambda_{\text{escrow}})\, s \quad\Longrightarrow\quad s^\star = \frac{a_c - \lambda_{\text{budget}} - \lambda_{\text{escrow}}}{b_c},$$
and the shield clamps $s^\star$ into the capped simplex. Pandora's Box decides which additional sub-delegate to probe. Each candidate $c$ has an opening cost $k_c$ in escrow units and a Weitzman reservation index $\sigma_c$ solving $k_c = \mathbb{E}[(V_c - \sigma_c)^+]$. The optimal policy opens the unopened box of highest index whenever that index exceeds the best realized value, and stops otherwise. The shield adds one clause: opening requires a feasible `reserve` of $k_c$. The Sequential Probability Ratio Test decides when a child's reversible hold converts to a commit or a release. Each `FindingDelivery` receipt contributes a log-likelihood increment, positive when `receipt_fields_coupled` returns true for the quintuple and negative otherwise. The walk stops at $A = \log\frac{1-\beta}{\alpha}$ for commit or $B = \log\frac{\beta}{1-\alpha}$ for release. Between the boundaries, the shielded action is `Hold`.

```rust
// crates/kernel/chio-swarm-authority/src/shadow_split.rs  (proposed, additive)
use chio_kernel_core::shadow::{Envelope, FixedQ16_16, Shield, ShieldedAction, ShadowPrices};

pub const MAX_BUDGET_SHARE_BPS: u16 = 10_000; // mirrors budget_split.rs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitAction { Defer, Admit { share_bps: u16 } }

#[derive(Clone, Copy, Debug)]
pub struct SplitEnvelope {
    pub parent_share_bps: u16,
    pub current_total_child_bps: u32,
    pub remaining_child_slots: usize,
}

impl SplitEnvelope {
    pub fn headroom_bps(&self) -> u16 {
        let parent = u32::from(self.parent_share_bps);
        match parent.checked_sub(self.current_total_child_bps) {
            Some(h) if h >= u32::from(MAX_BUDGET_SHARE_BPS) => MAX_BUDGET_SHARE_BPS,
            Some(h) => h as u16,
            None => 0,
        }
    }
}

impl Envelope for SplitEnvelope {
    type Action = SplitAction;
    fn fallback(&self) -> SplitAction { SplitAction::Defer }
    fn contains(&self, a: SplitAction) -> bool {
        match a {
            SplitAction::Defer => true,
            SplitAction::Admit { share_bps } =>
                self.remaining_child_slots > 0 && share_bps > 0 && share_bps <= self.headroom_bps(),
        }
    }
}

impl Shield for SplitEnvelope {
    /// O(1): one subtraction, one min, one branch.
    fn project(&self, proposal: Option<SplitAction>) -> ShieldedAction<SplitAction> {
        let head = self.headroom_bps();
        let out = match proposal {
            Some(SplitAction::Admit { share_bps })
                if self.remaining_child_slots > 0 && head > 0 && share_bps > 0 =>
                SplitAction::Admit { share_bps: share_bps.min(head) },
            _ => SplitAction::Defer,
        };
        ShieldedAction::seal(out)
    }
}

/// Tier-0 proposal: closed-form maximizer of a concave surplus net of prices.
/// Returns None on arithmetic failure; the shield then uses the fallback.
pub fn tier0_propose_share(
    a: FixedQ16_16, b: FixedQ16_16, lambda: ShadowPrices,
) -> Option<SplitAction> {
    let price = lambda.budget.checked_add(lambda.escrow)?;
    let numer = a.checked_sub(price)?.clamp_nonneg();
    let s = numer.checked_div(b)?;
    Some(SplitAction::Admit { share_bps: s.floor_u16_capped(MAX_BUDGET_SHARE_BPS) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationLedger { pub reserved: u64, pub committed: u64, pub released: u64, pub retained: u64 }

pub fn settled(l: ReservationLedger) -> Option<u64> {
    l.committed.checked_add(l.released)?.checked_add(l.retained)
}
pub fn outstanding(l: ReservationLedger) -> Option<u64> { l.reserved.checked_sub(settled(l)?) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleAction { Hold, Commit(u64), Release(u64), Retain(u64), Reserve(u64) }

/// Settlement envelope for one hold inside a pool.
#[derive(Clone, Copy, Debug)]
pub struct EscrowEnvelope {
    pub ledger: ReservationLedger,
    pub pool_outstanding: u64,      // ω(parent) − Σ_c reserved_c
    pub time_window_code: u8,       // from classify_time_window_code
}

impl Envelope for EscrowEnvelope {
    type Action = SettleAction;
    fn fallback(&self) -> SettleAction { SettleAction::Hold }
    fn contains(&self, a: SettleAction) -> bool {
        let Some(w) = outstanding(self.ledger) else { return matches!(a, SettleAction::Hold) };
        match a {
            SettleAction::Hold => true,
            SettleAction::Commit(x) | SettleAction::Retain(x) => self.time_window_code == 0 && x <= w,
            SettleAction::Release(x) => x <= w,
            SettleAction::Reserve(x) => self.time_window_code == 0
                && x <= self.pool_outstanding
                && self.ledger.reserved.checked_add(x).is_some(),
        }
    }
}

impl Shield for EscrowEnvelope {
    fn project(&self, p: Option<SettleAction>) -> ShieldedAction<SettleAction> {
        match p { Some(a) if self.contains(a) => ShieldedAction::seal(a),
                  _ => ShieldedAction::seal(SettleAction::Hold) }
    }
}

/// Map a shielded settlement to the pinned `ledger_apply` op code.
pub fn to_ledger_op(a: SettleAction) -> Option<(u8, u64)> {
    match a {
        SettleAction::Hold => None,
        SettleAction::Reserve(x) => Some((0, x)),
        SettleAction::Commit(x) => Some((1, x)),
        SettleAction::Release(x) => Some((2, x)),
        SettleAction::Retain(x) => Some((3, x)),
    }
}

// --- SPRT over receipt couplings ---------------------------------------
#[derive(Clone, Copy, Debug, Default)]
pub struct SprtState { pub llr: FixedQ16_16, pub samples: u32 }
#[derive(Clone, Copy, Debug)]
pub struct SprtThresholds { pub upper_a: FixedQ16_16, pub lower_b: FixedQ16_16, pub max_samples: u32 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SprtVerdict { Continue, CommitHold, ReleaseHold }

pub fn sprt_step(
    st: SprtState, coupled: bool, inc_pos: FixedQ16_16, inc_neg: FixedQ16_16, th: SprtThresholds,
) -> Option<(SprtState, SprtVerdict)> {
    let inc = if coupled { inc_pos } else { inc_neg };
    let llr = st.llr.checked_add(inc)?;
    let samples = st.samples.checked_add(1)?;
    let v = if llr >= th.upper_a { SprtVerdict::CommitHold }
            else if llr <= th.lower_b { SprtVerdict::ReleaseHold }
            else { SprtVerdict::Continue };
    Some((SprtState { llr, samples }, v))
}

/// SPRT verdict → proposal. The shield decides feasibility; `Continue` is Hold.
pub fn sprt_to_proposal(v: SprtVerdict, w: u64) -> SettleAction {
    match v { SprtVerdict::CommitHold => SettleAction::Commit(w),
              SprtVerdict::ReleaseHold => SettleAction::Release(w),
              SprtVerdict::Continue => SettleAction::Hold }
}

// --- Pandora's Box over sub-delegates -----------------------------------
#[derive(Clone, Copy, Debug)]
pub struct PandoraBox { pub reservation_index: FixedQ16_16, pub open_cost_units: u64, pub opened: bool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PandoraAction { Stop, Open { child: usize, cost_units: u64 } }

/// Weitzman rule as a *proposal*; feasibility is checked by `EscrowEnvelope`.
pub fn pandora_propose(boxes: &[PandoraBox], best_realized: FixedQ16_16) -> PandoraAction {
    let mut best: Option<(usize, FixedQ16_16, u64)> = None;
    for (i, b) in boxes.iter().enumerate() {
        if b.opened { continue; }
        if best.map_or(true, |(_, idx, _)| b.reservation_index > idx) {
            best = Some((i, b.reservation_index, b.open_cost_units));
        }
    }
    match best {
        Some((child, idx, cost_units)) if idx > best_realized => PandoraAction::Open { child, cost_units },
        _ => PandoraAction::Stop,
    }
}
```

Fan-out is `Reserve` on the pool projected through the child's `EscrowEnvelope`. Fan-in is exact: when a child is terminal, the parent applies ops 1, 2, and 3 with the child's three settled buckets, in that order. The `DeliveryContract` and `FindingDelivery` receipt payloads, stored under the reserved keys `DELIVERY_CONTRACT_METADATA_KEY` and `FINDING_DELIVERY_METADATA_KEY`, are canonicalized with RFC 8785 JSON Canonicalization Scheme before hashing, so the SPRT increment is a function of a stable byte string and not of serializer ordering.

**Lean 4 obligation.** The pinned `ledger_apply` is already covered by the proof manifest. The additive theorem is that fan-in from a conserved child into a conserved parent stays conserved.

```lean
-- formal/lean4/Chio/SwarmFanIn.lean  (proposed, additive)
namespace Chio

structure Ledger where
  reserved : Nat
  committed : Nat
  released : Nat
  retained : Nat

def settled (l : Ledger) : Nat := l.committed + l.released + l.retained
def Conserved (l : Ledger) : Prop := settled l ≤ l.reserved
def Terminal (l : Ledger) : Prop := settled l = l.reserved

/-- Model of `ledger_apply` for ops 1,2,3 on a conserved ledger. -/
def apply (l : Ledger) (op : Nat) (a : Nat) : Ledger × Bool :=
  if h : settled l + a ≤ l.reserved then
    if op = 1 then ({ l with committed := l.committed + a }, true)
    else if op = 2 then ({ l with released := l.released + a }, true)
    else if op = 3 then ({ l with retained := l.retained + a }, true)
    else (l, false)
  else (l, false)

theorem apply_preserves (l : Ledger) (op a : Nat) (hc : Conserved l) :
    Conserved (apply l op a).1 := by
  unfold Conserved settled apply at *
  split <;> (try split) <;> (try split) <;> (try split) <;> simp_all <;> omega

/-- Fan-in: a terminal child's settled buckets are absorbed by a parent whose
    outstanding hold covers the child's reservation. -/
theorem fan_in_conserved (p c : Ledger) (hp : Conserved p) (hc : Terminal c)
    (hfit : settled p + c.reserved ≤ p.reserved) :
    Conserved ((apply ((apply ((apply p 1 c.committed).1) 2 c.released).1) 3 c.retained).1) := by
  have h1 := apply_preserves p 1 c.committed hp
  have h2 := apply_preserves _ 2 c.released h1
  exact apply_preserves _ 3 c.retained h2

end Chio
```

**Kani obligation** for the share shield, modeling the learned proposal as `kani::any()`:

```rust
#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn split_projection_is_in_envelope() {
        let env = SplitEnvelope {
            parent_share_bps: kani::any(),
            current_total_child_bps: kani::any(),
            remaining_child_slots: kani::any(),
        };
        let proposal: Option<SplitAction> = kani::any();
        let a = env.project(proposal).into_inner();
        kani::assert(env.contains(a), "shield output outside envelope");
        if let Some(p) = proposal { if env.contains(p) { kani::assert(a == p, "shield not identity on members"); } }
    }
}
```

**Apalache obligation** for pool conservation under nondeterministic controller choice:

```tla
---------------------------- MODULE SwarmPool ----------------------------
EXTENDS Integers, FiniteSets
CONSTANTS Children, Cap
VARIABLES parent, child
\* @type: ( {reserved: Int, committed: Int, released: Int, retained: Int} ) => Int;
Settled(l) == l.committed + l.released + l.retained
Conserved(l) == Settled(l) <= l.reserved /\ l.reserved <= Cap
SumChildRes == LET F[S \in SUBSET Children] ==
  IF S = {} THEN 0 ELSE LET c == CHOOSE x \in S : TRUE IN child[c].reserved + F[S \ {c}] IN F[Children]
Outstanding == parent.reserved - Settled(parent) - SumChildRes
Feasible == {<<c, a>> \in Children \X 0..Cap : a <= Outstanding}
FanOut(c, a) == child' = [child EXCEPT ![c].reserved = @ + a] /\ UNCHANGED parent
FanIn(c) == Settled(child[c]) = child[c].reserved
  /\ parent' = [parent EXCEPT !.committed = @ + child[c].committed,
                               !.released = @ + child[c].released,
                               !.retained = @ + child[c].retained]
  /\ child' = [child EXCEPT ![c] = [reserved |-> 0, committed |-> 0, released |-> 0, retained |-> 0]]
Next == (\E p \in Feasible : FanOut(p[1], p[2])) \/ (\E c \in Children : FanIn(c))
Inv == Conserved(parent) /\ (\A c \in Children : Conserved(child[c])) /\ Outstanding >= 0
=========================================================================
```

The controller is `\E p \in Feasible`. Replace the SPRT thresholds or retrain the Tier-0 surplus coefficients and `Inv` still holds, by Theorem 0.

## 2. Positioning against NVIDIA OpenShell

The OpenShell column below characterizes the perimeter-sandbox architecture class as described in the brief: container isolation as the enforcement boundary, external policy scripts evaluated at runtime, and neural classifiers whose output is acted on directly. Verify specific rows against the current NVIDIA release before external use. The analysis is about the architectural class and is fair to it: perimeter isolation is valuable, and Chio uses it too, as one sink among several.

| Dimension | Perimeter-sandbox class (OpenShell as characterized) | Chio + Copley |
|---|---|---|
| Enforcement locus | Container or sandbox boundary around the agent process | Per-action envelope inside the kernel-adjacent decision core, realized by LSM, Landlock, seccomp, EndpointSecurity, systemd, and the settlement ledger |
| Decision core verifiability | Policy scripts and glue in general-purpose languages, tested but not proved | `#![no_std]` core with Aeneas extraction to Lean 4, Kani harnesses, Apalache models, pinned in `formal/proof-manifest.toml` |
| Learned-component containment | Classifier verdict is the action | Classifier is $P(x)$, projected by $\Pi_{\mathcal{C}(x)}$; by Theorem 0 it cannot violate a shielded property |
| Interpretability | Opaque score or label | 537 atomic concept predicates across four segments, 236 rules, each firing attributable to named predicates with role-asymmetric thresholds |
| Capability algebra | Allow or deny lists per sandbox | Attenuating capability chain with basis-point shares, non-amplification by construction, `BudgetSplit` refusing oversubscription |
| Audit artifact | Logs | RFC 8785 canonical receipts with coupled quintuple checked by `receipt_fields_coupled` |
| Latency structure | Single path, classifier-bound | Tier-0 integer micro-models at tens to hundreds of nanoseconds, Tier-1 UltraBERT at single-digit milliseconds, exact core always |
| Failure semantics | Script error or classifier timeout yields platform default | Fallback $\bot_x$ is a member of every envelope and is `Deny`, `Defer`, or `Hold` |
| Economic delegation | None native | `SwarmBudgetPool`, reversible holds, four-bucket conservation |
| Cross-platform parity | Linux container runtime | Same `EvaluateInput` and same 4-segment bottleneck on Linux, Omarchy, and macOS |

**Formal contrast.** Let $E$ be the event that the predictor errs on a safety-relevant input. In the unshielded class the unsafe-action probability is bounded only by $\Pr[E]$, and that bound is tight because the classifier output is the action. In the shielded architecture the unsafe-action probability for any property encoded in $\mathcal{C}$ is zero by Theorem 0, and prediction error appears only as utility regret, $\max_{a \in \mathcal{C}(x)} u(a) - u(\Pi(P(x)))$. The two architectures therefore fail in different currencies. One fails in safety. The other fails in efficiency. That asymmetry is the whole case.

**Non-amplification.** Along a `SwarmDelegationWitnessChain` $c_0 \succeq c_1 \succeq \cdots \succeq c_k$, define $\text{share}(c_i) = \text{share}(c_{i-1}) \cdot \text{share\_bps}_i / 10{,}000$ with $\text{share}(c_0) = 1$. Since every `share_bps` is at most `MAX_BUDGET_SHARE_BPS`, the sequence is non-increasing, and since `OversubscribedSiblings` is refused, $\sum_{\text{siblings}} \text{share} \le \text{share}(\text{parent})$. By induction the total share of any antichain of descendants is at most 1. A perimeter architecture has no object on which this statement can even be made.

## 3. Linux enforcement in `chio-cage`

**Sensor side.** BPF LSM programs attach to `bprm_check_security`, `file_open`, and `socket_connect`. Each program does two things. It performs an $O(1)$ lookup in a BPF hash map keyed by `(cgroup_id, exe_inode_key)` whose value is a Tier-0 concept state and a cached verdict. And it emits a telemetry record to a ring buffer carrying `pid`, `ppid`, the invoked filename, up to a bounded prefix of `argv`, and the parent's executable path. The 4-segment mapping is:

- `CommandLine`: `argv` joined with single spaces, truncated at a fixed byte bound and marked $\bot$ for the truncated tail predicates.
- `Image`: `bprm->filename` as invoked.
- `OriginalFileName`: the fully resolved path of the executable inode after symlink and overlay resolution, plus the IMA or dm-verity digest when present. Linux has no PE version resource. The core records this semantic gap by setting the predicates that assume PE provenance to $\bot$, which shrinks the envelope rather than widening it.
- `ParentImage`: the resolved executable path of the parent task.

**Decision path.** BPF LSM hooks cannot block on userspace. The design therefore splits by tier. Tier-0 decisions are made in-hook from the cached concept state; a cache miss returns `-EPERM` for the hook when the policy is default-deny for unknown images, which is the envelope fallback. Tier-1 decisions use seccomp user notification on `execve`, `connect`, and `openat`. The supervisor receives the notification, builds `EvaluateInput`, runs UltraBERT within a deadline, validates the notification id before replying to close the time-of-check gap, and replies with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` or an errno. Deadline expiry returns the fallback.

**Sink side.** A `ShieldedAction<CagePlan>` compiles to a Landlock ruleset and a seccomp filter. Landlock is stackable and can only restrict, so compilation is a lattice meet, and the fallback `Deny` is the ruleset that handles every access and allows none.

**Lemma 3 (Landlock attenuation).** Let a process carry rulesets $S = \{R_1,\dots,R_n\}$ and let $\text{acc}(S) = \bigcap_i \text{allowed}(R_i)$ over the handled access set. Enforcing $R$ yields $\text{acc}(S \cup \{R\}) = \text{acc}(S) \cap \text{allowed}(R) \subseteq \text{acc}(S)$. *Proof.* Set intersection is monotone decreasing in the number of operands. $\square$ Hence any `CagePlan`, projected or not, cannot widen access, and the shield's job reduces to choosing a member of $\mathcal{C}(x)$ that is also useful.

```rust
// crates/security/chio-cage/src/plan.rs  (proposed, additive to linux.rs / seccomp.rs)
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const MAX_CAGE_FS_RULES: usize = 64;
pub const MAX_CAGE_NET_RULES: usize = 16;
pub const SYSCALL_WORDS: usize = 8;            // 512 syscall numbers
pub const BPF_MAXINSNS: usize = 4096;

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsRule { pub path_fd_slot: u16, pub allowed_access: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetRule { pub port: u16, pub allowed_access: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CagePlan {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub fs_rules: [Option<FsRule>; MAX_CAGE_FS_RULES],
    pub net_rules: [Option<NetRule>; MAX_CAGE_NET_RULES],
    pub syscall_allow: [u64; SYSCALL_WORDS],
}

impl CagePlan {
    /// The envelope fallback: handle everything, allow nothing.
    pub const fn deny_all(handled_fs: u64, handled_net: u64) -> Self {
        Self { handled_access_fs: handled_fs, handled_access_net: handled_net,
               fs_rules: [None; MAX_CAGE_FS_RULES], net_rules: [None; MAX_CAGE_NET_RULES],
               syscall_allow: [0; SYSCALL_WORDS] }
    }
    /// Lattice order: `self` is at most as permissive as `other`.
    pub fn attenuates(&self, other: &Self) -> bool {
        let fs_ok = self.fs_rules.iter().flatten().all(|r| other.fs_rules.iter().flatten()
            .any(|o| o.path_fd_slot == r.path_fd_slot && (r.allowed_access & !o.allowed_access) == 0));
        let net_ok = self.net_rules.iter().flatten().all(|r| other.net_rules.iter().flatten()
            .any(|o| o.port == r.port && (r.allowed_access & !o.allowed_access) == 0));
        let sys_ok = self.syscall_allow.iter().zip(other.syscall_allow.iter()).all(|(a, b)| (a & !b) == 0);
        fs_ok && net_ok && sys_ok
    }
    /// Meet: used by the shield to project a proposal into the envelope ceiling.
    pub fn meet(&self, ceiling: &Self) -> Self {
        let mut out = Self::deny_all(self.handled_access_fs | ceiling.handled_access_fs,
                                     self.handled_access_net | ceiling.handled_access_net);
        for (i, r) in self.fs_rules.iter().enumerate() {
            if let Some(r) = r {
                if let Some(c) = ceiling.fs_rules.iter().flatten().find(|c| c.path_fd_slot == r.path_fd_slot) {
                    out.fs_rules[i] = Some(FsRule { path_fd_slot: r.path_fd_slot,
                                                    allowed_access: r.allowed_access & c.allowed_access });
                }
            }
        }
        for (i, r) in self.net_rules.iter().enumerate() {
            if let Some(r) = r {
                if let Some(c) = ceiling.net_rules.iter().flatten().find(|c| c.port == r.port) {
                    out.net_rules[i] = Some(NetRule { port: r.port, allowed_access: r.allowed_access & c.allowed_access });
                }
            }
        }
        for (o, (a, b)) in out.syscall_allow.iter_mut().zip(self.syscall_allow.iter().zip(ceiling.syscall_allow.iter())) {
            *o = a & b;
        }
        out
    }
}

/// Classic BPF instruction as consumed by seccomp(2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SockFilter { pub code: u16, pub jt: u8, pub jf: u8, pub k: u32 }

pub const BPF_LD_W_ABS: u16 = 0x20;
pub const BPF_JMP_JEQ_K: u16 = 0x15;
pub const BPF_RET_K: u16 = 0x06;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0000 | 1;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const OFF_NR: u32 = 0;
pub const OFF_ARCH: u32 = 4;
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError { ProgramTooLong, SlotOverflow }

/// Compile the syscall bitset to a cBPF filter. Allowed syscalls return ALLOW;
/// `notify` syscalls (Tier-1 cold path) return USER_NOTIF; everything else EPERM.
pub fn compile_seccomp(
    plan: &CagePlan, notify: &[u64; SYSCALL_WORDS], arch: u32, out: &mut [SockFilter; BPF_MAXINSNS],
) -> Result<usize, CompileError> {
    let mut n: usize = 0;
    let mut push = |ins: SockFilter, n: &mut usize| -> Result<(), CompileError> {
        if *n >= BPF_MAXINSNS { return Err(CompileError::ProgramTooLong); }
        out[*n] = ins; *n = n.checked_add(1).ok_or(CompileError::SlotOverflow)?; Ok(())
    };
    push(SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFF_ARCH }, &mut n)?;
    push(SockFilter { code: BPF_JMP_JEQ_K, jt: 1, jf: 0, k: arch }, &mut n)?;
    push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS }, &mut n)?;
    push(SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFF_NR }, &mut n)?;
    for word in 0..SYSCALL_WORDS {
        for bit in 0..64u32 {
            let nr = (word as u32).checked_mul(64).and_then(|w| w.checked_add(bit)).ok_or(CompileError::SlotOverflow)?;
            let allowed = (plan.syscall_allow[word] >> bit) & 1 == 1;
            let notified = (notify[word] >> bit) & 1 == 1;
            if allowed {
                push(SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 1, k: nr }, &mut n)?;
                push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW }, &mut n)?;
            } else if notified {
                push(SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 1, k: nr }, &mut n)?;
                push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_USER_NOTIF }, &mut n)?;
            }
        }
    }
    push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ERRNO_EPERM }, &mut n)?;
    Ok(n)
}
```

The Landlock compilation in `linux.rs` walks `fs_rules` and `net_rules` into `landlock_create_ruleset`, `landlock_add_rule` with `LANDLOCK_RULE_PATH_BENEATH` and `LANDLOCK_RULE_NET_PORT`, and `landlock_restrict_self`. That code is the only place syscalls are issued and lives outside the `no_std` core. The core guarantees that what reaches it already satisfies `attenuates(&ceiling)`, where the ceiling is the `CagePlan` the exact core derived from the capability chain.

## 4. Omarchy OS as the native supervisor

Omarchy runs Arch with the Hyprland Wayland compositor. Embedding Chio makes the agent supervisor a system service rather than an application: `chio-kernel` runs as a systemd system unit, and `chio-copley-composer` runs as a user unit that receives compositor context over the Hyprland IPC socket. Three bindings matter.

**Window-context provenance.** When an agent requests an action, the composer samples the focused client from the compositor: `pid`, `app_id`, `title`, and workspace. The exact core joins `pid` against the process tree it already tracks through the Linux sensor path from Section 3 and records the join under a namespaced metadata key. The pinned reserved-key array has 35 entries and is typed `[&str; 35]`, so the additive path is a separate `OMARCHY_EXTENSION_METADATA_KEYS` constant and a wrapper that checks both arrays. A compositor-reported focus that does not match a tracked process is $\bot$ and shrinks the envelope.

**Resource slices from shadow prices.** Each agent task is started in a transient unit via the systemd D-Bus `StartTransientUnit` call with `CPUWeight`, `IOWeight`, and `MemoryHigh`. These properties are the primal variables of a dual decomposition. Task $i$ maximizes $v_i(r_i) - \boldsymbol\lambda^\top r_i$ in isolation, and the supervisor updates prices by projected dual ascent on resource slack:
$$\lambda_{t+1} = \big[\lambda_t + \eta\,(\text{usage}_t - \text{capacity})\big]_+ .$$
For strongly concave utilities with modulus $\mu$, the dual is smooth with constant $L = 1/\mu$, and fixed-step ascent with $\eta < 2/L$ converges to an $O(\eta)$ neighborhood of the optimal price. The cgroup controller introduces a sampling delay $d$ in control periods, so stability of the closed loop requires $\eta L \cdot d < \pi/2$ in the small-gain sense. In practice $\eta$ is a Q16.16 constant set from the measured cgroup settling time.

```rust
// crates/kernel/chio-kernel/src/omarchy_slice.rs  (proposed, additive)
use chio_kernel_core::shadow::{FixedQ16_16, ShadowPrices};

pub const CPU_WEIGHT_MIN: u16 = 1;
pub const CPU_WEIGHT_MAX: u16 = 10_000;
pub const IO_WEIGHT_MIN: u16 = 1;
pub const IO_WEIGHT_MAX: u16 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliceProperties { pub cpu_weight: u16, pub io_weight: u16, pub memory_high_bytes: u64 }

/// weight = clamp(value / (1 + λ_resource)) in basis points of the weight range.
fn weight_from(value: FixedQ16_16, lambda: FixedQ16_16, lo: u16, hi: u16) -> Option<u16> {
    let denom = FixedQ16_16::ONE.checked_add(lambda.clamp_nonneg())?;
    let w = value.checked_div(denom)?.floor_u16_capped(hi);
    Some(w.max(lo))
}

pub fn slice_from_prices(
    task_value: FixedQ16_16, memory_reserve_bytes: u64, lambda: ShadowPrices,
) -> Option<SliceProperties> {
    let cpu_weight = weight_from(task_value, lambda.latency, CPU_WEIGHT_MIN, CPU_WEIGHT_MAX)?;
    let io_weight = weight_from(task_value, lambda.fuel, IO_WEIGHT_MIN, IO_WEIGHT_MAX)?;
    // memory_high = reserve / (1 + λ_memory), computed in integer bytes.
    let denom_bits = FixedQ16_16::ONE.checked_add(lambda.memory.clamp_nonneg())?.to_bits();
    let scaled = u128::from(memory_reserve_bytes).checked_mul(FixedQ16_16::SCALE as u128)?;
    let mem = scaled.checked_div(u128::try_from(denom_bits).ok()?)?;
    Some(SliceProperties { cpu_weight, io_weight, memory_high_bytes: u64::try_from(mem).ok()? })
}

/// Projected dual ascent on one resource. Returns None on overflow; the
/// caller then freezes the price, which is the conservative choice.
pub fn dual_ascent_step(
    lambda: FixedQ16_16, usage: FixedQ16_16, capacity: FixedQ16_16, eta: FixedQ16_16,
) -> Option<FixedQ16_16> {
    let slack = usage.checked_sub(capacity)?;
    let delta = eta.checked_mul(slack)?;
    Some(lambda.checked_add(delta)?.clamp_nonneg())
}
```

**Hardware-key receipt signing.** Receipts are canonicalized with RFC 8785 and signed with a hybrid pair. Ed25519 is produced on a local hardware token through its OpenPGP or PIV applet, since Ed25519 is widely available there. ML-DSA-65 is produced by a software signer whose private key is sealed to the platform TPM and unsealed only for the supervisor's measured boot state, because hardware ML-DSA signing is not yet broadly available. The signer is a trait with two backends, and the receipt stores both signatures; verification requires both, so an attacker must defeat both the hardware token and the sealed post-quantum key. The `LoadedWeights` provider hash from `loaded_weights.rs` is included in the signed canonical body, so a receipt attests not only the verdict but the exact Copley weights that proposed it, and `evaluate_weights_binding` rejects a model card whose hash disagrees.

## 5. macOS EndpointSecurity and NetworkExtension

**Deadlines as a hard envelope constraint.** Every authorization message from EndpointSecurity carries a deadline in mach absolute time. A client that misses deadlines is disconnected and its pending events fail open or closed per system policy, so the deadline is itself part of $\mathcal{C}(x)$: an action that cannot be returned in time is not feasible. The design therefore chooses the decision path from the remaining budget before any model runs. If the remaining time, less a safety margin, covers the Tier-1 cost, UltraBERT runs. Otherwise only Tier-0 runs. If even Tier-0 cannot complete, the fallback is returned immediately.

**Segment mapping for `ES_EVENT_TYPE_AUTH_EXEC`.** `CommandLine` comes from the exec argument accessors. `Image` is the target executable path. `OriginalFileName` is the bundle's declared executable name joined with the signing identifier and team identifier, which plays the provenance role PE metadata plays on Windows. `ParentImage` is the executable path of the process named by the parent audit token, resolved from a cache the client maintains from prior notify events. For `ES_EVENT_TYPE_AUTH_OPEN`, the same four segments describe the opening process, and the file path is an additional fact for the exact core. `NEFilterDataProvider` flows map to `socket_connect`: the flow's source application audit token yields the four process segments, and the remote endpoint is an exact fact. The verdict space there is allow, drop, or need-rules, with drop as the fallback.

**Tier-0 cached concept bitmaps.** The 537 predicates fit in nine 64-bit words. Role-asymmetric thresholds produce two bitmaps per input, one for predicates confirmed positive and one for predicates confirmed negative; anything in neither is $\bot$. A rule fires only when every predicate it needs is confirmed. The cache key is the code directory hash plus signing identifier.

**Cache-safety.** EndpointSecurity lets a client ask the system to cache an exec verdict per executable. That is sound only when the verdict depends on nothing that changes between launches of the same binary. With the segment layout CommandLine 0 to 344, Image 345 to 441, OriginalFileName 442 to 498, and ParentImage 499 to 536, caching is permitted exactly when every predicate read by a firing rule lies in 345 to 498. This is a syntactic check on the rule, computed once at rule-compile time.

```rust
// crates/kernel/chio-kernel-core/src/concept_bitmap.rs  (proposed, additive)
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use crate::shadow::{Envelope, Shield, ShieldedAction};

pub const CONCEPT_PREDICATES: usize = 537;
pub const CONCEPT_WORDS: usize = 9;
pub const SEG_COMMANDLINE: core::ops::Range<usize> = 0..345;
pub const SEG_IMAGE: core::ops::Range<usize> = 345..442;
pub const SEG_ORIGINAL_FILE_NAME: core::ops::Range<usize> = 442..499;
pub const SEG_PARENT_IMAGE: core::ops::Range<usize> = 499..537;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConceptBitmap([u64; CONCEPT_WORDS]);

impl ConceptBitmap {
    pub const EMPTY: Self = Self([0; CONCEPT_WORDS]);
    pub fn get(&self, j: usize) -> Option<bool> {
        if j >= CONCEPT_PREDICATES { return None; }
        let (w, b) = (j.checked_div(64)?, j.checked_rem(64)?);
        Some((self.0[w] >> b) & 1 == 1)
    }
    pub fn set(&mut self, j: usize) -> Option<()> {
        if j >= CONCEPT_PREDICATES { return None; }
        let (w, b) = (j.checked_div(64)?, j.checked_rem(64)?);
        self.0[w] |= 1u64 << b; Some(())
    }
    pub fn subset_of(&self, o: &Self) -> bool { self.0.iter().zip(o.0.iter()).all(|(a, b)| (a & !b) == 0) }
    pub fn disjoint(&self, o: &Self) -> bool { self.0.iter().zip(o.0.iter()).all(|(a, b)| (a & b) == 0) }
    /// True when every set bit lies within [lo, hi).
    pub fn within(&self, r: core::ops::Range<usize>) -> bool {
        (0..CONCEPT_PREDICATES).all(|j| !self.get(j).unwrap_or(false) || r.contains(&j))
    }
}

/// Kleene state after role-asymmetric thresholding: pos ∩ neg = ∅ by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConceptState { pub pos: ConceptBitmap, pub neg: ConceptBitmap }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConceptRule { pub requires_pos: ConceptBitmap, pub requires_neg: ConceptBitmap, pub denies: bool }

impl ConceptRule {
    /// Fires only when every required predicate is *confirmed*; ⊥ never fires a rule.
    pub fn fires(&self, s: &ConceptState) -> bool {
        self.requires_pos.subset_of(&s.pos) && self.requires_neg.subset_of(&s.neg)
    }
    /// Cache-safe iff the rule reads only launch-invariant segments.
    pub fn cache_safe(&self) -> bool {
        let r = SEG_IMAGE.start..SEG_ORIGINAL_FILE_NAME.end;
        self.requires_pos.within(r.clone()) && self.requires_neg.within(r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsAuthResult { Allow, Deny }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EsVerdict { pub result: EsAuthResult, pub cache: bool }

/// Envelope for an exec verdict: Deny is always feasible; Allow is feasible only
/// if the capability chain permits exec at all; caching is feasible only if safe.
#[derive(Clone, Copy, Debug)]
pub struct EsExecEnvelope { pub exec_permitted_by_capability: bool, pub all_fired_rules_cache_safe: bool }

impl Envelope for EsExecEnvelope {
    type Action = EsVerdict;
    fn fallback(&self) -> EsVerdict { EsVerdict { result: EsAuthResult::Deny, cache: false } }
    fn contains(&self, a: EsVerdict) -> bool {
        let res_ok = match a.result { EsAuthResult::Deny => true,
                                      EsAuthResult::Allow => self.exec_permitted_by_capability };
        res_ok && (!a.cache || self.all_fired_rules_cache_safe)
    }
}

impl Shield for EsExecEnvelope {
    fn project(&self, p: Option<EsVerdict>) -> ShieldedAction<EsVerdict> {
        let a = match p {
            Some(v) if self.contains(v) => v,
            Some(EsVerdict { result: EsAuthResult::Allow, .. }) if self.exec_permitted_by_capability =>
                EsVerdict { result: EsAuthResult::Allow, cache: false },
            _ => self.fallback(),
        };
        ShieldedAction::seal(a)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsPath { FallbackOnly, Tier0Only, Tier1Allowed }

#[derive(Clone, Copy, Debug)]
pub struct EsDeadlineBudget { pub now_ns: u64, pub deadline_ns: u64, pub tier0_cost_ns: u64, pub tier1_cost_ns: u64, pub margin_ns: u64 }

/// Deadline-aware path selection. Pure integer arithmetic, never panics.
pub fn choose_path(b: EsDeadlineBudget) -> EsPath {
    let Some(remaining) = b.deadline_ns.checked_sub(b.now_ns) else { return EsPath::FallbackOnly };
    let Some(usable) = remaining.checked_sub(b.margin_ns) else { return EsPath::FallbackOnly };
    let tier1_total = b.tier0_cost_ns.checked_add(b.tier1_cost_ns);
    match tier1_total {
        Some(t) if usable >= t => EsPath::Tier1Allowed,
        _ if usable >= b.tier0_cost_ns => EsPath::Tier0Only,
        _ => EsPath::FallbackOnly,
    }
}

/// Tier-0 proposal from cached state: Deny if any denying rule fires, else Allow.
pub fn tier0_exec_proposal(state: &ConceptState, rules: &[ConceptRule]) -> (EsVerdict, bool) {
    let mut deny = false;
    let mut all_cache_safe = true;
    for r in rules {
        if r.fires(state) {
            if r.denies { deny = true; }
            if !r.cache_safe() { all_cache_safe = false; }
        }
    }
    let result = if deny { EsAuthResult::Deny } else { EsAuthResult::Allow };
    (EsVerdict { result, cache: all_cache_safe }, all_cache_safe)
}
```

The system extension's hot path is then: compute the deadline budget, look up the cached `ConceptState` by code directory hash, run `tier0_exec_proposal`, construct the envelope from the capability chain and the cache-safety bit, project, and respond. Every step is $O(\text{rules})$ with a constant bound of 236, and nothing allocates. When the budget allows Tier-1, UltraBERT produces a fresh `ConceptState` whose thresholded bitmaps replace the cache entry, and the same projection runs. The learned path and the cached path produce proposals of the same type and meet the same envelope, which is what Theorem 0 requires.

**Kani obligation shared by Linux and macOS.** One harness covers both sinks because both are `Shield` implementations:

```rust
#[cfg(kani)]
#[kani::proof]
fn es_projection_in_envelope() {
    let env = EsExecEnvelope { exec_permitted_by_capability: kani::any(), all_fired_rules_cache_safe: kani::any() };
    let proposal: Option<EsVerdict> = kani::any();
    let a = env.project(proposal).into_inner();
    kani::assert(env.contains(a), "ES verdict outside envelope");
    kani::assert(!a.cache || env.all_fired_rules_cache_safe, "unsafe cache request escaped shield");
}
```

## 6. What ties the five together

The same three objects appear in every section. The envelope is computed exactly from trusted facts, with $\bot$ facts shrinking it. The projection is total, $O(1)$ or bounded-constant, and the identity on members. The fallback is a member and is the conservative action for that substrate: `Hold` for settlement, `Defer` for admission, the deny-all ruleset for Landlock, `EPERM` for seccomp, and `ES_AUTH_RESULT_DENY` for EndpointSecurity. Because the predictor only ever produces proposals, retraining UltraBERT, changing the 236 rules, or retuning $\boldsymbol\lambda$ leaves every obligation in `formal/proof-manifest.toml` untouched. The receipts close the loop across platforms: a Linux exec decision, an Omarchy slice allocation, a macOS verdict, and a swarm settlement all produce RFC 8785 canonical bodies bound to the same weights hash and the same capability chain, so a relying party reads one artifact type regardless of where the action ran.

**Recap.** This treatise unified the five `arc` workstreams under the Kernel-as-Decision-Model law and Theorem 0, which shows that any learned proposal projected into an exactly computed envelope preserves every shielded safety property for all parameters and shadow prices. For the swarm economy, it defined the settlement and share envelopes over the pinned four-bucket ledger and placed Tier-0 surplus maximization, Pandora's Box probing, and SPRT hold conversion inside them, with Lean 4, Kani, and Apalache obligations that quantify over the controller nondeterministically. It positioned Chio against the perimeter-sandbox class by showing the two architectures fail in different currencies, safety versus efficiency. For Linux, it mapped LSM and seccomp-notification telemetry into the four Copley segments and compiled shielded cage plans into Landlock and seccomp with an attenuation lemma. For Omarchy, it derived systemd slice weights from shadow prices via projected dual ascent with a stated stability condition and specified hybrid hardware-backed receipt signing. For macOS, it made the EndpointSecurity deadline part of the envelope, defined cache-safety as a syntactic segment check, and gave a sub-millisecond Tier-0 path over 9-word concept bitmaps. Open items are the row-by-row verification of the OpenShell column against NVIDIA's current release and the choice of a production ML-DSA-65 signer backend.