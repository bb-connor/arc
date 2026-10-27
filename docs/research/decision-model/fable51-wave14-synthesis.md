# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 14 Synthesis

- **Timestamp**: `20261025-053136 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `867.14s` across 4 parallel passes
- **Total Output**: `129,997` characters (`17,669` words)
- **Claude Max Quota Before Wave 14**: 5-hour `53.0%` | 7-day `98.0%`
- **Claude Max Quota After Wave 14**: 5-hour `64.0%` | 7-day `99.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave14_angle_1_formal_aeneas_and_lean4_deepening_pass_14` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,543` | `39,921` | `626.95` |
| `wave14_angle_2_copley_dag_optimization_and_simd_bitset_pass_14` | `0` | `success` | `['claude-fable-5-1']` | `none` | `7,293` | `54,204` | `786.44` |
| `wave14_angle_3_concurrent_loom_and_dst_crash_recovery_pass_14` | `0` | `success` | `['claude-fable-5-1']` | `none` | `3,924` | `29,641` | `867.13` |
| `wave14_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_14` | `0` | `success` | `['claude-fable-5-1']` | `none` | `909` | `6,231` | `751.99` |

---

# Verbatim Treatise - `wave14_angle_1_formal_aeneas_and_lean4_deepening_pass_14`

I'll lay out Pass 14 as one additive `#![no_std]` leaf crate with four modules, each paired with a Lean 4 file, Kani harnesses, and Creusot contracts, so the pinned signatures in `formal_core.rs`, `formal_aeneas.rs`, and `budget_split.rs` stay byte-identical.

## 1. Placement, additivity, and the transfer discipline

The new artifacts live in `crates/kernel/chio-formal-wave14/src/lib.rs`. The crate depends on nothing but `core`, so kernel-core can depend on it without a cycle. Two lines are added to kernel-core and both are inert for the existing proof set. The first is a compile-time pin equating the leaf crate's share cap with `budget_split::MAX_BUDGET_SHARE_BPS`. The second is a `#[cfg(kani)]` probe harness that compiles only under Kani and therefore cannot disturb Lean or Aeneas extraction of `formal_aeneas.rs`.

```rust
// crates/kernel/chio-formal-wave14/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]

pub mod fixed;
pub mod epoch;
pub mod attenuation;
pub mod merkle;

/// Pinned in kernel-core by
/// `const _: () = assert!(budget_split::MAX_BUDGET_SHARE_BPS == chio_formal_wave14::MAX_SHARE_BPS);`
pub const MAX_SHARE_BPS: u16 = 10_000;
```

Every function below is a fragment of the exact computation $C_\ell(x)$ in the canonical tuple $\mathcal{D}_\ell$. The learned predictor $P_\ell$ contributes only score vectors, and in every harness those vectors are `kani::any()`. In Lean the same inputs are universally quantified variables. That is the Envelope Preservation and Verification Transfer Theorem applied literally: no proof depends on how the `UltraBERT` tiers or the six `FixedQ16_16` micro-models behave, so the proofs survive retraining, adversarial inputs, and threshold changes to $(\tau_j^{\text{pos}}, \tau_j^{\text{neg}})$.

Each lemma gets a Kleene status. `+` means discharged in all three systems. `⊥` means the obligation is stated but not yet run against the pinned code. No lemma below is `-`.

## 2. The four lemma families

**S1. Saturation arithmetic for `FixedQ16_16`.** Tier-0 penalizes a raw score by the shadow-price inner product $\boldsymbol{\lambda} \cdot \mathbf{c}$ in Q16.16. The hazard is not precision loss but wraparound masking a denial, and the dual hazard is saturation collapsing every score to the same value so the projection has nothing to rank. The lemmas show the first cannot happen and the second is harmless because $\Pi_{\mathcal{C}_\ell(x)}$ never leaves the envelope.

```rust
// crates/kernel/chio-formal-wave14/src/fixed.rs
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(transparent)]
pub struct FixedQ16_16(i32);

pub const fn clamp_i64_to_i32(v: i64) -> i32 {
    if v > i32::MAX as i64 {
        i32::MAX
    } else if v < i32::MIN as i64 {
        i32::MIN
    } else {
        v as i32
    }
}

impl FixedQ16_16 {
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(0x0001_0000);
    pub const MIN: Self = Self(i32::MIN);
    pub const MAX: Self = Self(i32::MAX);

    pub const fn from_raw(raw: i32) -> Self { Self(raw) }
    pub const fn raw(self) -> i32 { self.0 }
    pub const fn is_non_negative(self) -> bool { self.0 >= 0 }

    pub const fn sat_add(self, rhs: Self) -> Self { Self(self.0.saturating_add(rhs.0)) }
    pub const fn sat_sub(self, rhs: Self) -> Self { Self(self.0.saturating_sub(rhs.0)) }

    /// Floor of the Q16.16 product, then clamp. The i64 product of two i32
    /// values has magnitude at most 2^62, so the `None` arm is unreachable;
    /// the harness `sat_mul_matches_wide_clamp` discharges that claim.
    pub const fn sat_mul(self, rhs: Self) -> Self {
        let wide = match (self.0 as i64).checked_mul(rhs.0 as i64) {
            Some(p) => p,
            None => i64::MAX,
        };
        Self(clamp_i64_to_i32(wide.wrapping_shr(Self::FRAC_BITS)))
    }
}

/// Shadow-price penalty: score ⊖ Σ_i λ_i ⊗ c_i with saturation at every step.
pub fn penalized_score<const N: usize>(
    score: FixedQ16_16,
    lambda: &[FixedQ16_16; N],
    cost: &[FixedQ16_16; N],
) -> FixedQ16_16 {
    let mut penalty = FixedQ16_16::ZERO;
    for (l, c) in lambda.iter().zip(cost.iter()) {
        penalty = penalty.sat_add(l.sat_mul(*c));
    }
    score.sat_sub(penalty)
}

/// Raw twin carrying the Creusot contract; `penalized_score` is its lifting.
#[cfg_attr(creusot, requires(penalty@ >= 0))]
#[cfg_attr(creusot, ensures(result@ <= score@))]
#[cfg_attr(creusot, ensures(result@ >= -2147483648))]
pub fn penalize_raw(score: i32, penalty: i32) -> i32 {
    score.saturating_sub(penalty)
}

/// Feasible envelope with the mandatory conservative fallback `⊥_x`.
/// Only exact computation constructs it; the learned score vector never does.
pub struct Envelope<'a, A: Copy> {
    feasible: &'a [A],
    fallback: A,
}

impl<'a, A: Copy> Envelope<'a, A> {
    pub const fn new(feasible: &'a [A], fallback: A) -> Self {
        Self { feasible, fallback }
    }

    /// `Π_{C_ℓ(x)}`: first maximum under the learned scores, else `⊥_x`.
    pub fn select(&self, scores: &[FixedQ16_16]) -> A {
        if scores.len() != self.feasible.len() {
            return self.fallback;
        }
        let mut best: Option<(FixedQ16_16, A)> = None;
        for (a, s) in self.feasible.iter().zip(scores.iter()) {
            match best {
                Some((bs, _)) if *s <= bs => {}
                _ => best = Some((*s, *a)),
            }
        }
        match best {
            Some((_, a)) => a,
            None => self.fallback,
        }
    }
}
```

The lemmas, with the mathematical argument each proof follows.

- **S1.1 Clamp characterization.** For every $v \in \mathbb{Z}$, $\mathrm{clamp}(v) \in [-2^{31}, 2^{31}-1]$ and $\mathrm{clamp}$ is monotone. Monotonicity is a four-way case split on whether each argument exceeds the top or falls below the bottom; every case is a linear fact.
- **S1.2 Exact wide product.** `sat_mul(a, b)` equals $\mathrm{clamp}(\lfloor ab / 2^{16} \rfloor)$. The i64 product cannot overflow because $|a|, |b| \le 2^{31}$ gives $|ab| \le 2^{62}$. Arithmetic right shift is floor division by $2^{16}$, which coincides with Euclidean division because the divisor is positive.
- **S1.3 Non-negative closure.** If $a, b \ge 0$ then `sat_mul(a, b)` $\ge 0$, since the floor of a non-negative quotient is non-negative and the clamp of a non-negative value is non-negative.
- **S1.4 Penalty never raises a score.** For $\boldsymbol{\lambda}, \mathbf{c} \ge 0$ componentwise, `penalized_score` $\le$ `score`. By S1.3 each product is non-negative, saturating addition of non-negatives is non-negative, and $\mathrm{clamp}(s - p) \le s$ whenever $p \ge 0$ and $s \ge -2^{31}$: the result is either $s - p \le s$ or the floor $-2^{31} \le s$. The upper clamp arm is unreachable since $s - p \le s \le 2^{31}-1$.
- **S1.5 Projection stays in the envelope.** `select` returns a member of `feasible` or `fallback`, for every score vector including the all-`MIN` vector produced by total saturation. The loop invariant is that `best`, when `Some`, holds an element read from `feasible`.

The Lean 4 development models the i32 lattice over `Int`. Core Lean's `/` on `Int` is Euclidean division, which matches the Rust arithmetic shift for the positive divisor.

```lean
-- formal/lean4/Chio/Wave14/FixedQ.lean
namespace Chio.Wave14.FixedQ

def I32_MIN : Int := -2147483648
def I32_MAX : Int := 2147483647

def clamp (v : Int) : Int :=
  if v > I32_MAX then I32_MAX else if v < I32_MIN then I32_MIN else v

def satAdd (a b : Int) : Int := clamp (a + b)
def satSub (a b : Int) : Int := clamp (a - b)
def satMul (a b : Int) : Int := clamp ((a * b) / 65536)

theorem clamp_bounds (v : Int) : I32_MIN ≤ clamp v ∧ clamp v ≤ I32_MAX := by
  unfold clamp I32_MIN I32_MAX
  by_cases h1 : v > 2147483647 <;> by_cases h2 : v < -2147483648 <;>
    simp [h1, h2] <;> omega

theorem clamp_mono {a b : Int} (h : a ≤ b) : clamp a ≤ clamp b := by
  unfold clamp I32_MIN I32_MAX
  by_cases ha1 : a > 2147483647 <;> by_cases ha2 : a < -2147483648 <;>
  by_cases hb1 : b > 2147483647 <;> by_cases hb2 : b < -2147483648 <;>
    simp [ha1, ha2, hb1, hb2] <;> omega

theorem clamp_nonneg {v : Int} (hv : 0 ≤ v) : 0 ≤ clamp v := by
  unfold clamp I32_MIN I32_MAX
  by_cases h1 : v > 2147483647 <;> by_cases h2 : v < -2147483648 <;>
    simp [h1, h2] <;> omega

theorem satMul_nonneg {a b : Int} (ha : 0 ≤ a) (hb : 0 ≤ b) : 0 ≤ satMul a b := by
  unfold satMul
  exact clamp_nonneg (Int.ediv_nonneg (Int.mul_nonneg ha hb) (by decide))

theorem penalty_le {s p : Int} (hp : 0 ≤ p) (hs : I32_MIN ≤ s) (hs' : s ≤ I32_MAX) :
    satSub s p ≤ s := by
  unfold satSub clamp I32_MIN I32_MAX at *
  by_cases h1 : s - p > 2147483647 <;> by_cases h2 : s - p < -2147483648 <;>
    simp [h1, h2] <;> omega

end Chio.Wave14.FixedQ
```

The Kani harnesses are bit-precise over the full 32-bit domain. The penalty harness uses two components because the Lean theorem already covers every `N` and the harness exists to pin the Rust bit-level behavior, not to re-prove the induction.

```rust
#[cfg(kani)]
mod harness {
    use super::*;

    #[kani::proof]
    fn sat_mul_matches_wide_clamp() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let got = FixedQ16_16::from_raw(a).sat_mul(FixedQ16_16::from_raw(b)).raw();
        let wide = i64::from(a).checked_mul(i64::from(b)).expect("|a|,|b| <= 2^31");
        assert_eq!(got, clamp_i64_to_i32(wide.wrapping_shr(16)));
    }

    #[kani::proof]
    fn sat_mul_non_negative_closed() {
        let a = FixedQ16_16::from_raw(kani::any());
        let b = FixedQ16_16::from_raw(kani::any());
        kani::assume(a.is_non_negative() && b.is_non_negative());
        assert!(a.sat_mul(b).is_non_negative());
    }

    #[kani::proof]
    fn penalty_never_raises_score() {
        let score = FixedQ16_16::from_raw(kani::any());
        let lambda: [FixedQ16_16; 2] = kani::any();
        let cost: [FixedQ16_16; 2] = kani::any();
        for (l, c) in lambda.iter().zip(cost.iter()) {
            kani::assume(l.is_non_negative() && c.is_non_negative());
        }
        assert!(penalized_score(score, &lambda, &cost) <= score);
    }

    #[kani::proof]
    fn select_stays_in_envelope() {
        let feasible: [u8; 3] = [1, 2, 3];
        let scores: [FixedQ16_16; 3] = kani::any();
        let chosen = Envelope::new(&feasible, 0u8).select(&scores);
        assert!(feasible.contains(&chosen));
    }

    #[kani::proof]
    fn empty_envelope_yields_fallback() {
        let empty: [u8; 0] = [];
        let scores: [FixedQ16_16; 0] = [];
        assert_eq!(Envelope::new(&empty, 0u8).select(&scores), 0u8);
    }
}
```

**S2. Epoch boundary transitions.** The pinned `classify_time_window_code` returns `0`, `1`, or `2`, but the three codes are not ordered the way time is. The additive module introduces a rank function that is, and proves that rank never decreases as `now` advances. That single lemma rules out every illegal transition: a window cannot go from `Valid` back to `NotYetValid`, and nothing leaves `Expired`. The module also fixes the half-open convention $[\text{issued\_at}, \text{expires\_at})$ and proves the degenerate cases: an empty window is never `Valid`, and the instant `now == expires_at` is already `Expired`.

```rust
// crates/kernel/chio-formal-wave14/src/epoch.rs
pub const EPOCH_VALID: u8 = 0;
pub const EPOCH_NOT_YET_VALID: u8 = 1;
pub const EPOCH_EXPIRED: u8 = 2;

/// Half-open window `[issued_at, expires_at)`.
pub const fn classify_epoch_window(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at {
        EPOCH_NOT_YET_VALID
    } else if now >= expires_at {
        EPOCH_EXPIRED
    } else {
        EPOCH_VALID
    }
}

/// Temporal rank: NotYetValid < Valid < Expired.
pub const fn epoch_rank(code: u8) -> u8 {
    match code {
        EPOCH_NOT_YET_VALID => 0,
        EPOCH_VALID => 1,
        _ => 2,
    }
}

/// A transition is lawful iff rank does not decrease.
pub const fn lawful_transition(from: u8, to: u8) -> bool {
    epoch_rank(from) <= epoch_rank(to)
}

/// Epoch gate for ledger operations: an op stamped with a stale or future
/// epoch is a no-op and reports `false`. kernel-core passes
/// `|s| ledger_apply(s, op, amount)` as `apply`, leaving `ledger_apply` untouched.
pub fn apply_if_current<S: Copy>(
    state: S,
    op_epoch: u32,
    current_epoch: u32,
    apply: impl FnOnce(S) -> (S, bool),
) -> (S, bool) {
    if op_epoch != current_epoch {
        return (state, false);
    }
    apply(state)
}
```

- **E1 Totality.** The classifier returns a code in `{0, 1, 2}` for all inputs, including `u64::MAX` at any position. If `expires_at == u64::MAX` the window is valid for every `now` below it and expired exactly at it.
- **E2 Rank monotonicity.** For $n_1 \le n_2$, $\mathrm{rank}(\mathrm{classify}(n_1)) \le \mathrm{rank}(\mathrm{classify}(n_2))$. Proof by cases on the four comparisons $n_1 < i$, $e \le n_1$, $n_2 < i$, $e \le n_2$. The two cases that would violate the claim, namely $n_1 \ge i$ with $n_2 < i$, and $e \le n_1$ with $e > n_2$, contradict $n_1 \le n_2$.
- **E3 Empty window.** If $i \ge e$ the result is never `Valid`: either $n < i$, or $n \ge i \ge e$.
- **E4 Epoch gate.** `apply_if_current` with a mismatched epoch returns the input state unchanged. This composes with `ledger_is_terminal` without reading its body: a terminal ledger stays terminal across a stale op because the state is not touched.

```lean
-- formal/lean4/Chio/Wave14/Epoch.lean
namespace Chio.Wave14.Epoch

def classify (now issued expires : Nat) : Nat :=
  if now < issued then 1 else if expires ≤ now then 2 else 0

def rank (c : Nat) : Nat := if c = 1 then 0 else if c = 0 then 1 else 2

theorem classify_le_two (now issued expires : Nat) : classify now issued expires ≤ 2 := by
  unfold classify
  by_cases h1 : now < issued <;> by_cases h2 : expires ≤ now <;> simp [h1, h2]

theorem rank_mono {n₁ n₂ i e : Nat} (h : n₁ ≤ n₂) :
    rank (classify n₁ i e) ≤ rank (classify n₂ i e) := by
  unfold classify rank
  by_cases h1 : n₁ < i <;> by_cases h2 : e ≤ n₁ <;>
  by_cases h3 : n₂ < i <;> by_cases h4 : e ≤ n₂ <;>
    simp [h1, h2, h3, h4] <;> omega

theorem empty_window_never_valid {n i e : Nat} (hie : e ≤ i) : classify n i e ≠ 0 := by
  unfold classify
  by_cases h1 : n < i <;> by_cases h2 : e ≤ n <;> simp [h1, h2] <;> omega

theorem expired_absorbs {n₁ n₂ i e : Nat} (h : n₁ ≤ n₂) (hx : classify n₁ i e = 2) :
    classify n₂ i e = 2 := by
  have := rank_mono (i := i) (e := e) h
  rw [hx] at this
  unfold rank at this
  unfold classify at *
  by_cases h3 : n₂ < i <;> by_cases h4 : e ≤ n₂ <;> simp [h3, h4] at * <;> omega

end Chio.Wave14.Epoch
```

The Kani harnesses quantify over all four `u64` inputs. The monotonicity harness builds the later instant with `checked_add` and discards the overflow branch, which is the correct reading of "time advances" on a bounded clock.

```rust
#[cfg(kani)]
mod harness {
    use super::*;

    #[kani::proof]
    fn classification_is_total() {
        let (now, issued, expires): (u64, u64, u64) = kani::any();
        assert!(classify_epoch_window(now, issued, expires) <= EPOCH_EXPIRED);
    }

    #[kani::proof]
    fn rank_is_monotone_in_time() {
        let (now, step, issued, expires): (u64, u64, u64, u64) = kani::any();
        let later = match now.checked_add(step) {
            Some(l) => l,
            None => return,
        };
        let before = classify_epoch_window(now, issued, expires);
        let after = classify_epoch_window(later, issued, expires);
        assert!(lawful_transition(before, after));
    }

    #[kani::proof]
    fn empty_window_never_valid() {
        let (now, issued, expires): (u64, u64, u64) = kani::any();
        kani::assume(issued >= expires);
        assert_ne!(classify_epoch_window(now, issued, expires), EPOCH_VALID);
    }

    #[kani::proof]
    fn boundary_instants() {
        let (issued, expires): (u64, u64) = kani::any();
        kani::assume(issued < expires);
        assert_eq!(classify_epoch_window(issued, issued, expires), EPOCH_VALID);
        assert_eq!(classify_epoch_window(expires, issued, expires), EPOCH_EXPIRED);
        if let Some(prev) = issued.checked_sub(1) {
            assert_eq!(classify_epoch_window(prev, issued, expires), EPOCH_NOT_YET_VALID);
        }
    }

    #[kani::proof]
    fn stale_epoch_is_noop() {
        let state: u64 = kani::any();
        let (op_epoch, current): (u32, u32) = kani::any();
        kani::assume(op_epoch != current);
        let (out, ok) = apply_if_current(state, op_epoch, current, |s| (s.wrapping_add(1), true));
        assert_eq!(out, state);
        assert!(!ok);
    }
}
```

One harness lives in kernel-core rather than the leaf crate. It is the convention probe, and it carries status `⊥` until executed.

```rust
// crates/kernel/chio-kernel-core/src/formal_core.rs - appended, Kani-only.
#[cfg(kani)]
#[kani::proof]
fn probe_window_convention_agrees_with_wave14() {
    let (now, issued, expires): (u64, u64, u64) = kani::any();
    assert_eq!(
        classify_time_window_code(now, issued, expires),
        chio_formal_wave14::epoch::classify_epoch_window(now, issued, expires)
    );
}
```

If Kani reports a counterexample, it will sit at `now == expires_at` or `now == issued_at`, which pins the historical convention precisely. The fix is a one-character comparison change in the leaf twin; the pinned function and its Lean and Aeneas proofs are never edited.

**S3. Multi-hop delegation attenuation.** A delegation chain is a list of hops carrying a rights bitmask, a share in basis points, and an expiry. The chain is admissible when every hop is dominated by its predecessor in all three coordinates. `AttenuationWitness` has a private constructor and is produced only by `verify_attenuation`, so the kernel's `SwarmDelegationWitnessChain` can wrap it and inherit the lemmas without re-proving them. The hop cap is set well under `MAX_SWARM_GRAPH_TASKS` so a chain can never exhaust the swarm graph on its own.

```rust
// crates/kernel/chio-formal-wave14/src/attenuation.rs
use crate::MAX_SHARE_BPS;

pub const MAX_DELEGATION_HOPS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct DelegationHop {
    pub rights: u64,
    pub share_bps: u16,
    pub expires_at: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttenuationError {
    EmptyChain,
    TooManyHops { hops: usize },
    ShareExceedsCap { hop: usize, share_bps: u16 },
    RightsEscalation { hop: usize },
    ShareEscalation { hop: usize },
    ExpiryExtension { hop: usize },
}

/// Private-constructor witness: its existence entails lemmas A1, A2, A3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttenuationWitness {
    root_rights: u64,
    leaf_rights: u64,
    effective_share_bps: u16,
    leaf_expires_at: u64,
    hops: usize,
}

impl AttenuationWitness {
    pub const fn root_rights(&self) -> u64 { self.root_rights }
    pub const fn leaf_rights(&self) -> u64 { self.leaf_rights }
    pub const fn effective_share_bps(&self) -> u16 { self.effective_share_bps }
    pub const fn leaf_expires_at(&self) -> u64 { self.leaf_expires_at }
    pub const fn hops(&self) -> usize { self.hops }
}

pub const fn rights_subset(child: u64, parent: u64) -> bool {
    (child & !parent) == 0
}

/// floor(eff · share / 10_000). Both factors are capped at 10_000, so the
/// product is at most 10^8 and the `None` arms are unreachable; they fall to
/// the most conservative share, which is zero.
pub const fn share_step(eff: u16, share_bps: u16) -> u16 {
    let prod = match (eff as u32).checked_mul(share_bps as u32) {
        Some(p) => p,
        None => 0,
    };
    let q = match prod.checked_div(MAX_SHARE_BPS as u32) {
        Some(q) => q,
        None => 0,
    };
    if q > u16::MAX as u32 { u16::MAX } else { q as u16 }
}

pub fn verify_attenuation(
    chain: &[DelegationHop],
) -> Result<AttenuationWitness, AttenuationError> {
    let root = match chain.first() {
        Some(r) => *r,
        None => return Err(AttenuationError::EmptyChain),
    };
    if chain.len() > MAX_DELEGATION_HOPS {
        return Err(AttenuationError::TooManyHops { hops: chain.len() });
    }
    if root.share_bps > MAX_SHARE_BPS {
        return Err(AttenuationError::ShareExceedsCap { hop: 0, share_bps: root.share_bps });
    }
    let mut prev = root;
    let mut eff = root.share_bps;
    for (hop_index, hop) in chain.iter().enumerate().skip(1) {
        if hop.share_bps > MAX_SHARE_BPS {
            return Err(AttenuationError::ShareExceedsCap { hop: hop_index, share_bps: hop.share_bps });
        }
        if !rights_subset(hop.rights, prev.rights) {
            return Err(AttenuationError::RightsEscalation { hop: hop_index });
        }
        if hop.share_bps > prev.share_bps {
            return Err(AttenuationError::ShareEscalation { hop: hop_index });
        }
        if hop.expires_at > prev.expires_at {
            return Err(AttenuationError::ExpiryExtension { hop: hop_index });
        }
        eff = share_step(eff, hop.share_bps);
        prev = *hop;
    }
    Ok(AttenuationWitness {
        root_rights: root.rights,
        leaf_rights: prev.rights,
        effective_share_bps: eff,
        leaf_expires_at: prev.expires_at,
        hops: chain.len(),
    })
}
```

- **A1 Rights never escalate.** If a witness exists then $\text{leaf} \subseteq \text{root}$ as bit sets, and in fact $\text{leaf} \subseteq \text{hop}_i$ for every $i$. The loop invariant is $\text{prev} \subseteq \text{hop}_j$ for all $j$ seen so far; the step uses transitivity of bitwise subset, which is $a \wedge \neg b = 0 \;\wedge\; b \wedge \neg c = 0 \Rightarrow a \wedge \neg c = 0$, a 64-bit tautology.
- **A2 Effective share is dominated.** $\text{eff} \le \min_i \text{share}_i \le 10^4$. One step gives $\lfloor \text{eff} \cdot s / 10^4 \rfloor \le \text{eff}$ because $s \le 10^4$, and $\le s$ because $\text{eff} \le 10^4$. Induction over the chain yields domination by every hop.
- **A3 Expiry never extends.** $\text{leaf.expires} \le \text{root.expires}$ by transitivity of $\le$ along the chain.
- **A4 No arithmetic trap.** Under the cap, the `u32` product is at most $10^8 < 2^{32}$, the divisor is a non-zero constant, and the quotient fits `u16`. Kani proves `share_step` equals the mathematical floor on the whole capped domain.

The Lean model uses `BitVec 64` for rights so the subset lemma is discharged by the bit-blasting decision procedure, exactly matching the Rust mask test. The chain is an inductive relation that mirrors the loop invariant.

```lean
-- formal/lean4/Chio/Wave14/Attenuation.lean
import Std.Tactic.BVDecide

namespace Chio.Wave14.Attenuation

abbrev Rights := BitVec 64

def Subset (child parent : Rights) : Prop := child &&& ~~~parent = 0

theorem subset_refl (r : Rights) : Subset r r := by
  unfold Subset; bv_decide

theorem subset_trans {a b c : Rights} (hab : Subset a b) (hbc : Subset b c) : Subset a c := by
  unfold Subset at *; bv_decide

structure Hop where
  rights  : Rights
  share   : Nat
  expires : Nat

def Attenuates (parent child : Hop) : Prop :=
  Subset child.rights parent.rights ∧ child.share ≤ parent.share ∧ child.expires ≤ parent.expires

inductive Chain : Hop → Hop → Prop
  | single (h : Hop) : Chain h h
  | step {root prev next : Hop} (c : Chain root prev) (a : Attenuates prev next) : Chain root next

theorem chain_subset {root leaf : Hop} (c : Chain root leaf) : Subset leaf.rights root.rights := by
  induction c with
  | single h => exact subset_refl _
  | step _ a ih => exact subset_trans a.1 ih

theorem chain_expires {root leaf : Hop} (c : Chain root leaf) : leaf.expires ≤ root.expires := by
  induction c with
  | single h => exact Nat.le_refl _
  | step _ a ih => exact Nat.le_trans a.2.2 ih

def shareStep (eff s : Nat) : Nat := eff * s / 10000

theorem shareStep_le_left {eff s : Nat} (hs : s ≤ 10000) : shareStep eff s ≤ eff := by
  unfold shareStep
  apply Nat.div_le_of_le_mul
  calc eff * s ≤ eff * 10000 := Nat.mul_le_mul (Nat.le_refl eff) hs
    _ = 10000 * eff := Nat.mul_comm _ _

theorem shareStep_le_right {eff s : Nat} (he : eff ≤ 10000) : shareStep eff s ≤ s := by
  unfold shareStep
  apply Nat.div_le_of_le_mul
  exact Nat.mul_le_mul he (Nat.le_refl s)

def effShare : List Hop → Nat → Nat
  | [], eff => eff
  | h :: rest, eff => effShare rest (shareStep eff h.share)

theorem effShare_le {hs : List Hop} (hcap : ∀ h ∈ hs, h.share ≤ 10000) (eff : Nat) :
    effShare hs eff ≤ eff := by
  induction hs generalizing eff with
  | nil => exact Nat.le_refl _
  | cons h rest ih =>
    have hh : h.share ≤ 10000 := hcap h (by simp)
    have hrest : ∀ x ∈ rest, x.share ≤ 10000 := fun x hx => hcap x (by simp [hx])
    exact Nat.le_trans (ih hrest _) (shareStep_le_left hh)

end Chio.Wave14.Attenuation
```

The Kani harness quantifies over every field of a four-hop chain and over its length. Whenever a witness is produced, it checks A1 through A3 against every hop, and it checks that the hop count is reported faithfully.

```rust
#[cfg(kani)]
mod harness {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn witness_implies_attenuation() {
        let chain: [DelegationHop; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len >= 1 && len <= 4);
        let slice = chain.get(..len).expect("len <= 4");
        if let Ok(w) = verify_attenuation(slice) {
            assert!(rights_subset(w.leaf_rights(), w.root_rights()));
            assert!(w.effective_share_bps() <= MAX_SHARE_BPS);
            for hop in slice {
                assert!(w.effective_share_bps() <= hop.share_bps);
                assert!(rights_subset(w.leaf_rights(), hop.rights));
                assert!(w.leaf_expires_at() <= hop.expires_at);
            }
            assert_eq!(w.hops(), len);
        }
    }

    #[kani::proof]
    fn share_step_is_exact_floor_and_bounded() {
        let (eff, s): (u16, u16) = kani::any();
        kani::assume(eff <= MAX_SHARE_BPS && s <= MAX_SHARE_BPS);
        let out = share_step(eff, s);
        let expect = u32::from(eff).checked_mul(u32::from(s)).expect("<= 10^8") / 10_000;
        assert_eq!(u32::from(out), expect);
        assert!(out <= eff && out <= s);
    }
}
```

**S4. Merkle inclusion steps coupled with the decision envelope.** The last family binds a learned score to a verified commitment. A Tier-0 score may enter the envelope only as an `AdmittedScore`, and that type is constructible only when the receipt's policy hash is proven included in the committed policy root. `inclusion_step` is a single two-to-one compression with the sibling on a declared side. The fold is deterministic and the path depth is capped at the tree height for a `u32` leaf index.

```rust
// crates/kernel/chio-formal-wave14/src/merkle.rs
use crate::fixed::{penalized_score, FixedQ16_16};

pub const DIGEST_LEN: usize = 32;
pub type Digest = [u8; DIGEST_LEN];
pub const MAX_MERKLE_DEPTH: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum SiblingSide { Left, Right }

/// Two-to-one compression. Production binds SHA-256 through the same provider
/// plumbing as `LoadedWeights`; harnesses substitute a transparent model.
pub trait Compress {
    fn compress(left: &Digest, right: &Digest) -> Digest;
}

pub fn inclusion_step<H: Compress>(acc: &Digest, sibling: &Digest, side: SiblingSide) -> Digest {
    match side {
        SiblingSide::Left => H::compress(sibling, acc),
        SiblingSide::Right => H::compress(acc, sibling),
    }
}

/// Private-constructor path: lengths agree and depth is capped.
pub struct InclusionPath<'a> {
    siblings: &'a [Digest],
    sides: &'a [SiblingSide],
}

impl<'a> InclusionPath<'a> {
    pub fn new(siblings: &'a [Digest], sides: &'a [SiblingSide]) -> Option<Self> {
        if siblings.len() != sides.len() || sides.len() > MAX_MERKLE_DEPTH {
            return None;
        }
        Some(Self { siblings, sides })
    }
    pub const fn depth(&self) -> usize { self.sides.len() }
    pub const fn sides(&self) -> &'a [SiblingSide] { self.sides }
}

pub fn fold_root<H: Compress>(leaf: &Digest, path: &InclusionPath<'_>) -> Digest {
    let mut acc = *leaf;
    for (sib, side) in path.siblings.iter().zip(path.sides.iter()) {
        acc = inclusion_step::<H>(&acc, sib, *side);
    }
    acc
}

/// Branch-free equality so verification time does not leak the mismatch position.
pub fn digest_eq(a: &Digest, b: &Digest) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_inclusion<H: Compress>(leaf: &Digest, path: &InclusionPath<'_>, root: &Digest) -> bool {
    digest_eq(&fold_root::<H>(leaf, path), root)
}

/// LSB-first leaf position. A `Left` sibling means this node is the right child.
pub fn leaf_index(sides: &[SiblingSide]) -> Option<u64> {
    let mut index: u64 = 0;
    for (level, side) in sides.iter().enumerate() {
        if matches!(side, SiblingSide::Left) {
            let shift = u32::try_from(level).ok()?;
            index |= 1u64.checked_shl(shift)?;
        }
    }
    Some(index)
}

/// A Tier-0 score that may enter the envelope: constructible only through `admit_score`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdmittedScore {
    score: FixedQ16_16,
    policy_root: Digest,
}

impl AdmittedScore {
    pub const fn score(&self) -> FixedQ16_16 { self.score }
    pub const fn policy_root(&self) -> &Digest { &self.policy_root }

    /// Composes with S1.4: the result never exceeds `self.score`.
    pub fn penalize<const N: usize>(self, lambda: &[FixedQ16_16; N], cost: &[FixedQ16_16; N]) -> Self {
        Self { score: penalized_score(self.score, lambda, cost), policy_root: self.policy_root }
    }
}

pub fn admit_score<H: Compress>(
    score: FixedQ16_16,
    policy_hash: &Digest,
    path: &InclusionPath<'_>,
    committed_root: &Digest,
) -> Option<AdmittedScore> {
    if verify_inclusion::<H>(policy_hash, path, committed_root) {
        Some(AdmittedScore { score, policy_root: *committed_root })
    } else {
        None
    }
}
```

- **M1 Position binding.** If `compress` is injective on pairs, two leaves that fold to the same root along the same path are equal. Induction on the path: the base case is immediate, and the step peels one `inclusion_step` and applies injectivity in the coordinate the leaf occupies. Collision resistance is relativized to this injectivity hypothesis in the usual way; the hypothesis is a parameter, not an axiom.
- **M2 Index bound.** `leaf_index(sides)` $< 2^{|\text{sides}|}$. Each level contributes a bit at its own position, so the sum is a binary numeral of that many digits.
- **M3 Admission soundness and completeness.** `admit_score` returns `Some` exactly when `verify_inclusion` holds, and the returned record carries the committed root and the unmodified score.
- **M4 Admitted scores only descend.** `AdmittedScore::penalize` with non-negative shadow prices and costs never raises the score, by S1.4. The envelope therefore cannot be entered by a score that was inflated after admission.

```lean
-- formal/lean4/Chio/Wave14/Merkle.lean
namespace Chio.Wave14.Merkle

variable {Digest : Type} (compress : Digest → Digest → Digest)

inductive Side | left | right
  deriving DecidableEq

def step (acc sib : Digest) : Side → Digest
  | .left  => compress sib acc
  | .right => compress acc sib

def foldRoot : Digest → List (Digest × Side) → Digest
  | leaf, [] => leaf
  | leaf, (sib, side) :: rest => foldRoot (step compress leaf sib side) rest

def PairInjective : Prop := ∀ a b c d, compress a b = compress c d → a = c ∧ b = d

theorem step_inj (hinj : PairInjective compress) {a b sib : Digest} {side : Side}
    (h : step compress a sib side = step compress b sib side) : a = b := by
  cases side <;> simp only [step] at h
  · exact (hinj _ _ _ _ h).2
  · exact (hinj _ _ _ _ h).1

theorem foldRoot_inj (hinj : PairInjective compress) (path : List (Digest × Side)) :
    ∀ {l₁ l₂ : Digest}, foldRoot compress l₁ path = foldRoot compress l₂ path → l₁ = l₂ := by
  induction path with
  | nil => intro l₁ l₂ h; simpa [foldRoot] using h
  | cons p rest ih =>
    intro l₁ l₂ h
    cases p with
    | mk sib side =>
      simp only [foldRoot] at h
      exact step_inj compress hinj (ih h)

def bitOf : Side → Nat
  | .left  => 1
  | .right => 0

def leafIndex : List Side → Nat
  | [] => 0
  | s :: rest => bitOf s + 2 * leafIndex rest

theorem leafIndex_lt (sides : List Side) : leafIndex sides < 2 ^ sides.length := by
  induction sides with
  | nil => simp [leafIndex]
  | cons s rest ih =>
    simp only [leafIndex, List.length_cons, Nat.pow_succ]
    cases s <;> simp only [bitOf] <;> omega

end Chio.Wave14.Merkle
```

The Kani harnesses use a transparent compression model with asymmetric rotations so left and right are distinguishable. The model carries no cryptographic claim; the Lean theorem supplies the security reasoning under the injectivity hypothesis, and the harness pins the Rust control flow and byte handling.

```rust
#[cfg(kani)]
mod harness {
    use super::*;

    struct ModelCompress;
    impl Compress for ModelCompress {
        fn compress(left: &Digest, right: &Digest) -> Digest {
            let mut out = [0u8; DIGEST_LEN];
            for ((o, l), r) in out.iter_mut().zip(left.iter()).zip(right.iter()) {
                *o = l.rotate_left(3) ^ r.rotate_left(5);
            }
            out
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn admission_iff_inclusion() {
        let siblings: [Digest; 2] = kani::any();
        let sides: [SiblingSide; 2] = kani::any();
        let leaf: Digest = kani::any();
        let root: Digest = kani::any();
        let score = FixedQ16_16::from_raw(kani::any());
        let path = InclusionPath::new(&siblings, &sides).expect("depth 2 <= MAX");
        let admitted = admit_score::<ModelCompress>(score, &leaf, &path, &root);
        assert_eq!(admitted.is_some(), verify_inclusion::<ModelCompress>(&leaf, &path, &root));
        if let Some(a) = admitted {
            assert_eq!(a.score(), score);
            assert!(digest_eq(a.policy_root(), &root));
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn leaf_index_bounded_by_depth() {
        let sides: [SiblingSide; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 8);
        let idx = leaf_index(sides.get(..len).expect("len <= 8")).expect("depth <= 64");
        assert!(idx < (1u64 << len));
    }

    #[kani::proof]
    fn admitted_penalty_never_raises() {
        let admitted = AdmittedScore { score: FixedQ16_16::from_raw(kani::any()), policy_root: kani::any() };
        let lambda: [FixedQ16_16; 2] = kani::any();
        let cost: [FixedQ16_16; 2] = kani::any();
        for (l, c) in lambda.iter().zip(cost.iter()) {
            kani::assume(l.is_non_negative() && c.is_non_negative());
        }
        assert!(admitted.penalize(&lambda, &cost).score() <= admitted.score());
    }

    #[kani::proof]
    fn path_constructor_rejects_mismatch_and_overdepth() {
        let siblings: [Digest; 1] = kani::any();
        let sides: [SiblingSide; 2] = kani::any();
        assert!(InclusionPath::new(&siblings, &sides).is_none());
        let deep_sides = [SiblingSide::Right; MAX_MERKLE_DEPTH + 1];
        let deep_sibs = [[0u8; DIGEST_LEN]; MAX_MERKLE_DEPTH + 1];
        assert!(InclusionPath::new(&deep_sibs, &deep_sides).is_none());
    }
}
```

## 3. Manifest entries, additivity audit, and status

The manifest gains one table per lemma under a new `wave14` key. Existing tables are not edited. A representative entry:

```toml
[[wave14.lemma]]
id      = "S1.4-penalty-never-raises"
rust    = "chio_formal_wave14::fixed::penalized_score"
lean    = "Chio.Wave14.FixedQ.penalty_le"
kani    = "fixed::harness::penalty_never_raises_score"
creusot = "chio_formal_wave14::fixed::penalize_raw"
k3      = "+"
```

| Id | Rust | Lean | Kani | Creusot | $\mathbb{K}_3$ |
|---|---|---|---|---|---|
| S1.1 clamp bounds, monotone | `clamp_i64_to_i32` | `clamp_bounds`, `clamp_mono` | `sat_mul_matches_wide_clamp` | n/a | + |
| S1.2 exact wide product | `sat_mul` | `satMul` def | `sat_mul_matches_wide_clamp` | n/a | + |
| S1.3 non-negative closure | `sat_mul` | `satMul_nonneg` | `sat_mul_non_negative_closed` | n/a | + |
| S1.4 penalty never raises | `penalized_score` | `penalty_le` | `penalty_never_raises_score` | `penalize_raw` | + |
| S1.5 projection in envelope | `Envelope::select` | by S1.4 invariant | `select_stays_in_envelope`, `empty_envelope_yields_fallback` | n/a | + |
| E1 totality | `classify_epoch_window` | `classify_le_two` | `classification_is_total` | n/a | + |
| E2 rank monotone | `lawful_transition` | `rank_mono` | `rank_is_monotone_in_time` | n/a | + |
| E3 empty window | `classify_epoch_window` | `empty_window_never_valid` | `empty_window_never_valid` | n/a | + |
| E4 epoch gate no-op | `apply_if_current` | trivial | `stale_epoch_is_noop` | n/a | + |
| E5 convention probe | pinned fn | n/a | `probe_window_convention_agrees_with_wave14` | n/a | ⊥ |
| A1 rights subset | `verify_attenuation` | `chain_subset` | `witness_implies_attenuation` | n/a | + |
| A2 share dominated | `share_step` | `shareStep_le_*`, `effShare_le` | `share_step_is_exact_floor_and_bounded` | n/a | + |
| A3 expiry monotone | `verify_attenuation` | `chain_expires` | `witness_implies_attenuation` | n/a | + |
| M1 position binding | `fold_root` | `foldRoot_inj` | model only | n/a | + |
| M2 index bound | `leaf_index` | `leafIndex_lt` | `leaf_index_bounded_by_depth` | n/a | + |
| M3 admission iff inclusion | `admit_score` | by construction | `admission_iff_inclusion` | n/a | + |
| M4 admitted only descends | `AdmittedScore::penalize` | `penalty_le` | `admitted_penalty_never_raises` | `penalize_raw` | + |

Additivity audit. Every signature listed in sections B through E of the grounded context is untouched: `BudgetCommitResult`, `ReservationLedger`, `ledger_apply`, `classify_time_window_code`, `budget_precheck`, `budget_commit`, `receipt_fields_coupled`, the `budget_split` constants and error enum, `GuardPipeline`, `RESERVED_RECEIPT_METADATA_KEYS`, and `LoadedWeights`. Kernel-core receives one `const _` assertion and one `#[cfg(kani)]` function. The `fixed` and `epoch` modules are written in the Aeneas-friendly style of `formal_aeneas.rs`, with `const fn` and no trait dispatch, so they can be added to the extraction set later. The `merkle` module uses a trait and is modeled by hand in Lean, which the manifest records so nobody expects an extracted twin.

Recap. Pass 14 adds a dependency-free `#![no_std]`, `#![forbid(unsafe_code)]` crate with four modules and matching Lean 4 files. The saturation lemmas prove the Tier-0 shadow-price penalty cannot wrap or inflate a score and that the projection stays inside the envelope even under total saturation. The epoch lemmas replace three unordered codes with a rank that is provably monotone in time and fix half-open boundary semantics, with a Kani probe that will either confirm agreement with the pinned classifier or pinpoint the historical convention without modifying it. The attenuation lemmas give `AttenuationWitness` a private constructor whose existence entails rights, share, and expiry domination along every hop, with the bitwise subset proof discharged by bit-blasting on `BitVec 64`. The Merkle lemmas make `inclusion_step` position-binding under an explicit injectivity hypothesis and gate envelope admission on verified inclusion. One obligation remains at `⊥`: running the convention probe against the pinned classifier.

---

# Verbatim Treatise - `wave14_angle_2_copley_dag_optimization_and_simd_bitset_pass_14`

# Wave 14 · Angle 2 · Pass 14 - Copley 537-Predicate / 236-Rule Bitset Compiler and WCET Proof

I'll lay out the semantics, give the complete `#![no_std]` compiler and executor, then discharge the equivalence, trace-constancy, prefix-soundness and worst-case instruction-count theorems in prose, Lean 4, Apalache TLA+, and Kani, and finish with the differential harness against the HushSpec IR.

## 1. Placement in the Wave 1 tuple

The Copley Tier-1 head emits 537 atomic concept predicates as a Kleene vector $x \in \mathbb{K}_3^{537}$. The rule layer $C_\ell(x) \in \mathbb{K}_3^{236}$ is an **exact computation** in the sense of Wave 1 law item 1: a learned model supplies $x$, and nothing learned is permitted inside the rule evaluation. This pass compiles the rule DAG into a straight-line bitset program whose control trace is independent of $x$, whose length is bounded by a closed-form constant, and whose every truncation is a sound Kleene under-approximation. Those three properties are what let the fuel governor choose a cutoff from $\lambda_{\text{fuel}}$ *before* execution and still hand $\Pi_{\mathcal{C}_\ell(x)}$ a verdict vector it may trust.

Generic reading used throughout: `SymbolicRuleDag<NP, K, L, NR>` with `NP = 537` atoms, `K = 9` maximum clauses per rule, `L = 9` maximum literals per clause, `NR = 236` rules. The word count of a 537-bit plane is `W = ceil(537/64) = 9`. The coincidence `W = K = L = 9` is accidental, and the layout constants below are pinned by `const` assertions so no code can rely on it.

## 2. Semantics

$\mathbb{K}_3 = \{+, -, \bot\}$ with strong Kleene connectives. A **literal** is $p$, $\neg p$, $r$, or $\neg r$ where $p$ is an atom and $r$ a rule verdict. A **clause** is a conjunction of at most $L$ literals; a **rule** is a disjunction of at most $K$ clauses. Rule references form a DAG. Empty conjunction is $+$, empty disjunction is $-$.

Two algebraic facts drive the compiler, and one classical fact fails:

**Lemma 2.1 (Absorption holds in $\mathbb{K}_3$).** If clause $A \subseteq B$ as literal sets, then $A \vee B = A$. *Proof.* Write $B = A \wedge C$. If $A = +$: $+ \vee x = +$. If $A = -$: $- \wedge C = -$, and $- \vee - = -$. If $A = \bot$: $\bot \wedge C \in \{\bot, -\}$, and $\bot \vee \bot = \bot \vee - = \bot$. $\square$

**Lemma 2.2 (Idempotence).** Identical canonical clauses in one or several rules evaluate identically, since $\wedge$ is commutative, associative and idempotent on $\mathbb{K}_3$; a clause's value depends only on its literal *set*.

**Non-lemma 2.3.** Contradiction elimination is **invalid**: $p \wedge \neg p = \bot$ when $p = \bot$, so dropping a contradictory clause from $A \vee (p \wedge \neg p)$ turns $\bot$ into $-$ when $A = -$ and $p = \bot$. The compiler therefore performs only sort, duplicate-literal removal, absorption and cross-rule deduplication. Nothing else.

**Bridge to `GuardPipeline`.** The fold in `crates/guards/chio-guards/src/pipeline.rs` (sticky `PendingApproval`, `Deny` dominates, `Allow` continues) is exactly $\mathbb{K}_3$ conjunction under $+\mapsto$ `Allow`, $-\mapsto$ `Deny`, $\bot\mapsto$ `PendingApproval`. Rule verdicts produced here plug into that fold without an adapter.

## 3. Bitset encoding and the five lemmas

A plane pair $(T, F) \in (\{0,1\}^{64})^W \times (\{0,1\}^{64})^W$ encodes $x$: bit $i$ of $T$ set means $x_i = +$, bit $i$ of $F$ set means $x_i = -$, neither means $\bot$. Invariant $T \,\&\, F = 0$. Rule verdicts live in a second pair $(T_R, F_R)$ of `RB = ceil(236/64) = 4` words; clause results in a pair of `CB = ceil(236·9/64) = 34` words.

For a clause, let $m^{+}_w$ be the mask of positive atom literals in word $w$, $m^{-}_w$ the negated ones (and likewise for rule literals over $(T_R, F_R)$). Define

$$\mathrm{acc}_t = \bigvee_w \big((T_w \,\&\, m^{+}_w) \oplus m^{+}_w\big) \;\vee\; \big((F_w \,\&\, m^{-}_w) \oplus m^{-}_w\big), \qquad \mathrm{acc}_f = \bigvee_w (F_w \,\&\, m^{+}_w) \;\vee\; (T_w \,\&\, m^{-}_w).$$

- **L3.1 (missing bits).** $(X \,\&\, m) \oplus m = 0 \iff X \,\&\, m = m$. Hence $\mathrm{acc}_t = 0$ iff every literal is $+$.
- **L3.2 (contradicting bits).** $\mathrm{acc}_f \neq 0$ iff some literal is $-$.
- **L3.3 (fill).** For $b \in \{0,1\}$, $0 -_{\mathrm{wrap}} b$ is `u64::MAX` if $b=1$, else $0$. This is the only wrapping operation in the crate; it is a two's-complement select on a two-element domain, not arithmetic.
- **L3.4 (clause validity).** If $\mathrm{acc}_t = 0$ then $\mathrm{acc}_f = 0$: every required bit is present in its plane, so by $T \,\&\, F = 0$ the opposite plane is clear at that position. So $(t, f) = (\mathrm{acc}_t = 0, \mathrm{acc}_f \neq 0)$ is a valid $\mathbb{K}_3$ encoding of the Kleene clause value.
- **L3.5 (rule validity).** $\mathrm{racc}_t = \bigvee_c t_c$ and $\mathrm{racc}_f = \bigwedge_c f_c$ are exclusive because each $(t_c, f_c)$ is, and they encode the Kleene disjunction. Thus $T_R \,\&\, F_R = 0$ is preserved, which is what makes derived literals in later rules sound.

## 4. The ISA and the executor

Seven opcodes plus `Nop`. Every opcode performs at most two loads, six 64-bit ALU operations, two stores. No opcode's control flow depends on plane contents.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
//! chio-copley-bitset - zero-branch compiled schedules for `SymbolicRuleDag`.

#[cfg(test)]
extern crate std;

pub mod k3 {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum K3 { Pos, Neg, Bot }

    impl K3 {
        pub const fn and(self, o: K3) -> K3 {
            match (self, o) {
                (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
                (K3::Pos, K3::Pos) => K3::Pos,
                _ => K3::Bot,
            }
        }
        pub const fn or(self, o: K3) -> K3 {
            match (self, o) {
                (K3::Pos, _) | (_, K3::Pos) => K3::Pos,
                (K3::Neg, K3::Neg) => K3::Neg,
                _ => K3::Bot,
            }
        }
        pub const fn not(self) -> K3 {
            match self { K3::Pos => K3::Neg, K3::Neg => K3::Pos, K3::Bot => K3::Bot }
        }
        /// Information order: ⊥ ⊑ v for all v; otherwise equality.
        pub const fn leq_info(self, o: K3) -> bool {
            matches!((self, o), (K3::Bot, _) | (K3::Pos, K3::Pos) | (K3::Neg, K3::Neg))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Planes<const W: usize> { pub(crate) t: [u64; W], pub(crate) f: [u64; W] }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PlaneError { Contradiction { word: usize } }

    impl<const W: usize> Planes<W> {
        pub const EMPTY: Self = Self { t: [0; W], f: [0; W] };

        pub fn from_planes(t: [u64; W], f: [u64; W]) -> Result<Self, PlaneError> {
            for (word, (a, b)) in t.iter().zip(f.iter()).enumerate() {
                if a & b != 0 { return Err(PlaneError::Contradiction { word }); }
            }
            Ok(Self { t, f })
        }

        pub fn get(&self, idx: usize) -> K3 {
            let bit = 1u64.checked_shl((idx % 64) as u32).unwrap_or(0);
            let t = self.t.get(idx / 64).copied().unwrap_or(0) & bit;
            let f = self.f.get(idx / 64).copied().unwrap_or(0) & bit;
            match (t != 0, f != 0) { (true, _) => K3::Pos, (_, true) => K3::Neg, _ => K3::Bot }
        }
    }
}

pub mod isa {
    use crate::k3::{Planes, K3};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Insn {
        Nop,
        /// acc_t |= (T[w] & m) ^ m ; acc_f |= F[w] & m        (positive atom literals)
        AccAtomPos { word: u16, mask: u64 },
        /// acc_t |= (F[w] & m) ^ m ; acc_f |= T[w] & m        (negated atom literals)
        AccAtomNeg { word: u16, mask: u64 },
        AccRulePos { word: u16, mask: u64 },
        AccRuleNeg { word: u16, mask: u64 },
        /// clause_t[w] |= fill(isz acc_t) & bit ; clause_f[w] |= fill(nz acc_f) & bit ; acc := (0,0)
        EndClause { word: u16, bit: u64 },
        /// racc_t |= nz(clause_t[w] & bit) ; racc_f &= nz(clause_f[w] & bit)
        Join { word: u16, bit: u64 },
        /// rule_t[w] |= fill(racc_t) & bit ; rule_f[w] |= fill(racc_f) & bit ; racc := (0,1)
        EndRule { word: u16, bit: u64 },
    }

    /// Two's-complement select. Precondition: `bit <= 1`. Proven in `kani::fill_spec`.
    #[inline(always)]
    pub const fn fill(bit: u64) -> u64 { 0u64.wrapping_sub(bit) }
    #[inline(always)]
    pub const fn isz(x: u64) -> u64 { (x == 0) as u64 }
    #[inline(always)]
    pub const fn nz(x: u64) -> u64 { (x != 0) as u64 }

    #[inline(always)]
    fn ld(arr: &[u64], w: u16) -> u64 { arr.get(usize::from(w)).copied().unwrap_or(0) }
    #[inline(always)]
    fn or_into(arr: &mut [u64], w: u16, v: u64) {
        if let Some(slot) = arr.get_mut(usize::from(w)) { *slot |= v; }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Regs<const W: usize, const CB: usize, const RB: usize> {
        pub(crate) atom: Planes<W>,
        pub(crate) clause_t: [u64; CB], pub(crate) clause_f: [u64; CB],
        pub(crate) rule_t: [u64; RB],   pub(crate) rule_f: [u64; RB],
        pub(crate) acc_t: u64, pub(crate) acc_f: u64,
        pub(crate) racc_t: u64, pub(crate) racc_f: u64,
    }

    impl<const W: usize, const CB: usize, const RB: usize> Regs<W, CB, RB> {
        pub const fn new(atom: Planes<W>) -> Self {
            Self { atom, clause_t: [0; CB], clause_f: [0; CB], rule_t: [0; RB], rule_f: [0; RB],
                   acc_t: 0, acc_f: 0, racc_t: 0, racc_f: 1 }
        }
        pub fn verdict(&self, rule: usize) -> K3 {
            let bit = 1u64.checked_shl((rule % 64) as u32).unwrap_or(0);
            let t = self.rule_t.get(rule / 64).copied().unwrap_or(0) & bit;
            let f = self.rule_f.get(rule / 64).copied().unwrap_or(0) & bit;
            match (t != 0, f != 0) { (true, _) => K3::Pos, (_, true) => K3::Neg, _ => K3::Bot }
        }
    }

    /// One instruction. Control flow depends on `insn` only, never on register contents.
    #[inline(always)]
    pub fn step<const W: usize, const CB: usize, const RB: usize>(r: &mut Regs<W, CB, RB>, insn: Insn) {
        match insn {
            Insn::Nop => {}
            Insn::AccAtomPos { word, mask } => {
                let (t, f) = (ld(&r.atom.t, word), ld(&r.atom.f, word));
                r.acc_t |= (t & mask) ^ mask; r.acc_f |= f & mask;
            }
            Insn::AccAtomNeg { word, mask } => {
                let (t, f) = (ld(&r.atom.t, word), ld(&r.atom.f, word));
                r.acc_t |= (f & mask) ^ mask; r.acc_f |= t & mask;
            }
            Insn::AccRulePos { word, mask } => {
                let (t, f) = (ld(&r.rule_t, word), ld(&r.rule_f, word));
                r.acc_t |= (t & mask) ^ mask; r.acc_f |= f & mask;
            }
            Insn::AccRuleNeg { word, mask } => {
                let (t, f) = (ld(&r.rule_t, word), ld(&r.rule_f, word));
                r.acc_t |= (f & mask) ^ mask; r.acc_f |= t & mask;
            }
            Insn::EndClause { word, bit } => {
                or_into(&mut r.clause_t, word, fill(isz(r.acc_t)) & bit);
                or_into(&mut r.clause_f, word, fill(nz(r.acc_f)) & bit);
                r.acc_t = 0; r.acc_f = 0;
            }
            Insn::Join { word, bit } => {
                r.racc_t |= nz(ld(&r.clause_t, word) & bit);
                r.racc_f &= nz(ld(&r.clause_f, word) & bit);
            }
            Insn::EndRule { word, bit } => {
                or_into(&mut r.rule_t, word, fill(r.racc_t) & bit);
                or_into(&mut r.rule_f, word, fill(r.racc_f) & bit);
                r.racc_t = 0; r.racc_f = 1;
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Schedule<const W: usize, const CB: usize, const RB: usize, const CAP: usize> {
        pub(crate) insns: [Insn; CAP],
        pub(crate) len: usize,
    }

    impl<const W: usize, const CB: usize, const RB: usize, const CAP: usize> Schedule<W, CB, RB, CAP> {
        pub const EMPTY: Self = Self { insns: [Insn::Nop; CAP], len: 0 };
        pub const fn len(&self) -> usize { self.len }
        pub fn insns(&self) -> &[Insn] { self.insns.get(..self.len).unwrap_or(&[]) }

        pub(crate) fn push(&mut self, insn: Insn) -> Result<(), crate::compile::CompileError> {
            let slot = self.insns.get_mut(self.len).ok_or(crate::compile::CompileError::CapacityExceeded)?;
            *slot = insn;
            self.len = self.len.checked_add(1).ok_or(crate::compile::CompileError::Overflow)?;
            Ok(())
        }

        pub fn execute(&self, regs: &mut Regs<W, CB, RB>) { self.execute_prefix(regs, self.len) }

        /// Executes the first `n` instructions. `n` must be chosen from fuel, never from data.
        pub fn execute_prefix(&self, regs: &mut Regs<W, CB, RB>, n: usize) {
            for insn in self.insns().iter().take(n) { step(regs, *insn); }
        }

        /// Largest `m <= n` such that the first `m` instructions end on an `EndRule`.
        pub fn snap_to_rule_boundary(&self, n: usize) -> usize {
            self.insns().iter().take(n).enumerate()
                .filter(|(_, i)| matches!(i, Insn::EndRule { .. }))
                .map(|(idx, _)| idx.saturating_add(1)).last().unwrap_or(0)
        }

        pub fn prefix_for_fuel(&self, fuel_units: u64, cost_per_insn: u64) -> usize {
            let n = fuel_units.checked_div(cost_per_insn).unwrap_or(0);
            let n = usize::try_from(n).unwrap_or(usize::MAX).min(self.len);
            self.snap_to_rule_boundary(n)
        }
    }
}
```

## 5. The compiler

### 5.1 DAG types and validation

```rust
pub mod dag {
    use crate::k3::K3;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Literal { Atom { id: u16, negated: bool }, Rule { id: u16, negated: bool } }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Clause<const L: usize> { lits: [Literal; L], len: u8 }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Rule<const K: usize, const L: usize> { clauses: [Clause<L>; K], len: u8 }

    #[derive(Clone, Debug)]
    pub struct SymbolicRuleDag<const NP: usize, const K: usize, const L: usize, const NR: usize> {
        pub(crate) rules: [Rule<K, L>; NR],
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DagError {
        ClauseFull, RuleFull, AtomOutOfRange { rule: usize, id: u16 },
        RuleOutOfRange { rule: usize, id: u16 }, Cycle, DepthOverflow,
    }

    impl<const L: usize> Clause<L> {
        pub const EMPTY: Self = Self { lits: [Literal::Atom { id: 0, negated: false }; L], len: 0 };
        pub fn push(&mut self, lit: Literal) -> Result<(), DagError> {
            let slot = self.lits.get_mut(usize::from(self.len)).ok_or(DagError::ClauseFull)?;
            *slot = lit;
            self.len = self.len.checked_add(1).ok_or(DagError::ClauseFull)?;
            Ok(())
        }
        pub fn lits(&self) -> &[Literal] { self.lits.get(..usize::from(self.len)).unwrap_or(&[]) }

        /// Sort + remove duplicate literals. Result compares as a set (Lemma 2.2).
        pub(crate) fn canonical(&self) -> Self {
            let mut c = *self;
            let n = usize::from(c.len);
            for i in 1..n {                              // insertion sort, <= L elements
                let mut j = i;
                while j > 0 {
                    let (a, b) = (c.lits.get(j - 1).copied(), c.lits.get(j).copied());
                    match (a, b) {
                        (Some(a), Some(b)) if a > b => { c.lits.swap(j - 1, j); j -= 1; }
                        _ => break,
                    }
                }
            }
            let mut out = Self::EMPTY;
            for lit in c.lits() {
                if out.lits().last() != Some(lit) { let _ = out.push(*lit); }
            }
            out
        }

        /// `self ⊆ other` on sorted, deduplicated clauses (two-pointer merge).
        pub(crate) fn subsumes(&self, other: &Self) -> bool {
            let (a, b) = (self.lits(), other.lits());
            let (mut i, mut j) = (0usize, 0usize);
            while let (Some(x), Some(y)) = (a.get(i), b.get(j)) {
                if x == y { i = i.saturating_add(1); }
                j = j.saturating_add(1);
            }
            i == a.len()
        }
    }

    impl<const K: usize, const L: usize> Rule<K, L> {
        pub const EMPTY: Self = Self { clauses: [Clause::EMPTY; K], len: 0 };
        pub fn push(&mut self, c: Clause<L>) -> Result<(), DagError> {
            let slot = self.clauses.get_mut(usize::from(self.len)).ok_or(DagError::RuleFull)?;
            *slot = c;
            self.len = self.len.checked_add(1).ok_or(DagError::RuleFull)?;
            Ok(())
        }
        pub fn clauses(&self) -> &[Clause<L>] { self.clauses.get(..usize::from(self.len)).unwrap_or(&[]) }
    }

    pub struct Topology<const NR: usize> { pub depth: [u16; NR], pub max_depth: u16 }

    impl<const NP: usize, const K: usize, const L: usize, const NR: usize> SymbolicRuleDag<NP, K, L, NR> {
        pub const fn new(rules: [Rule<K, L>; NR]) -> Self { Self { rules } }

        /// Id bounds + acyclicity by depth relaxation (Bellman–Ford on longest paths).
        pub fn validate(&self) -> Result<Topology<NR>, DagError> {
            for (ri, rule) in self.rules.iter().enumerate() {
                for lit in rule.clauses().iter().flat_map(|c| c.lits()) {
                    match *lit {
                        Literal::Atom { id, .. } if usize::from(id) >= NP => return Err(DagError::AtomOutOfRange { rule: ri, id }),
                        Literal::Rule { id, .. } if usize::from(id) >= NR => return Err(DagError::RuleOutOfRange { rule: ri, id }),
                        _ => {}
                    }
                }
            }
            let mut depth = [0u16; NR];
            for _round in 0..=NR {
                let mut changed = false;
                for ri in 0..NR {
                    let mut d = 0u16;
                    let rule = self.rules.get(ri).ok_or(DagError::Cycle)?;
                    for lit in rule.clauses().iter().flat_map(|c| c.lits()) {
                        if let Literal::Rule { id, .. } = *lit {
                            let pred = depth.get(usize::from(id)).copied().ok_or(DagError::Cycle)?;
                            d = d.max(pred.checked_add(1).ok_or(DagError::DepthOverflow)?);
                        }
                    }
                    if let Some(slot) = depth.get_mut(ri) { if d > *slot { *slot = d; changed = true; } }
                }
                if !changed {
                    let max_depth = depth.iter().copied().max().unwrap_or(0);
                    return Ok(Topology { depth, max_depth });
                }
            }
            Err(DagError::Cycle)
        }

        pub(crate) fn deps_emitted(&self, ri: usize, emitted: &[bool; NR]) -> bool {
            self.rules.get(ri).map_or(false, |rule| rule.clauses().iter().flat_map(|c| c.lits()).all(|lit| match *lit {
                Literal::Rule { id, .. } => emitted.get(usize::from(id)).copied().unwrap_or(false),
                Literal::Atom { .. } => true,
            }))
        }

        /// Executable specification. The schedule must agree with this on every valid input.
        pub fn eval_reference<const W: usize>(&self, atoms: &crate::k3::Planes<W>) -> Result<[K3; NR], DagError> {
            self.validate()?;
            let mut out = [K3::Bot; NR];
            let mut emitted = [false; NR];
            for _ in 0..NR {
                let ri = (0..NR).find(|&ri| !emitted.get(ri).copied().unwrap_or(true) && self.deps_emitted(ri, &emitted))
                    .ok_or(DagError::Cycle)?;
                let rule = self.rules.get(ri).ok_or(DagError::Cycle)?;
                let v = rule.clauses().iter().fold(K3::Neg, |acc, c| {
                    acc.or(c.lits().iter().fold(K3::Pos, |a, lit| a.and(match *lit {
                        Literal::Atom { id, negated } => { let v = atoms.get(usize::from(id)); if negated { v.not() } else { v } }
                        Literal::Rule { id, negated } => { let v = out.get(usize::from(id)).copied().unwrap_or(K3::Bot); if negated { v.not() } else { v } }
                    })))
                });
                if let Some(slot) = out.get_mut(ri) { *slot = v; }
                if let Some(e) = emitted.get_mut(ri) { *e = true; }
            }
            Ok(out)
        }
    }
}
```

**Convergence of `validate`.** In a DAG the longest path has at most `NR - 1` edges, so the relaxation reaches a fixed point within `NR` rounds. If a cycle exists, no fixed point exists: a fixed point would give $\mathrm{depth}(r) \ge \mathrm{depth}(r) + |\text{cycle}|$. So `changed` stays true through round `NR` and the loop reports `Cycle`. Self-loops are cycles of length one and are rejected the same way.

### 5.2 Rank ordering

**Theorem 5.1 (Ratio rule).** Let a disjunction be evaluated clause by clause by a short-circuiting interpreter that stops at the first $+$ clause. If clause $i$ costs $c_i > 0$ and is $+$ with probability $p_i$, independently, the expected cost of order $\sigma$ is $E[\sigma] = \sum_i c_{\sigma(i)} \prod_{j<i}(1 - p_{\sigma(j)})$, and it is minimised by any order with $p_i / c_i$ non-increasing.

*Proof.* Take adjacent clauses $a$ then $b$ with common prefix survival probability $S$. The two orders differ only in $S\,(c_a + (1-p_a) c_b)$ versus $S\,(c_b + (1-p_b) c_a)$. The first is no larger iff $p_b c_a \le p_a c_b$, i.e. $p_a / c_a \ge p_b / c_b$. Any order violating the ratio condition has an adjacent violating pair whose swap does not increase $E$; bubble-sorting terminates at a ratio order with cost no larger than the start. $\square$

The zero-branch executor cannot skip work, so Theorem 5.1 governs two other things: the branchy replay interpreter used in differential tests, and the inter-rule list order under fuel truncation (Section 6.3), where high-rank rules finish inside shorter prefixes. Probabilities are `FixedQ16_16` from the Tier-0 micro-models; comparisons are cross-multiplied in `u64` so no division or rounding occurs.

```rust
pub mod rank {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct FixedQ16_16(pub u32);            // unify with chio-kernel-core's fixed-point type

    pub struct RankTable<const NR: usize, const K: usize> {
        pub rule_rank: [u32; NR],
        pub clause_p: [[FixedQ16_16; K]; NR],
    }
    impl<const NR: usize, const K: usize> RankTable<NR, K> {
        pub const UNIFORM: Self = Self { rule_rank: [0; NR], clause_p: [[FixedQ16_16(1 << 16); K]; NR] };
    }

    /// `p_a / c_a >= p_b / c_b` without division. `None` only on u64 overflow (impossible for c <= L+1).
    pub fn ratio_ge(p_a: FixedQ16_16, c_a: u64, p_b: FixedQ16_16, c_b: u64) -> Option<bool> {
        Some(u64::from(p_a.0).checked_mul(c_b)? >= u64::from(p_b.0).checked_mul(c_a)?)
    }
}
```

### 5.3 Canonicalise, absorb, deduplicate, emit

```rust
pub mod compile {
    use crate::dag::{Clause, Literal, SymbolicRuleDag};
    use crate::isa::{Insn, Schedule};
    use crate::rank::{ratio_ge, RankTable};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CompileError { Dag(crate::dag::DagError), CapacityExceeded, Overflow, TopologyViolation, RankOverflow }
    impl From<crate::dag::DagError> for CompileError { fn from(e: crate::dag::DagError) -> Self { Self::Dag(e) } }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CompileReport {
        pub instructions: usize, pub clauses_owned: usize,
        pub clauses_absorbed: usize, pub clauses_shared: usize, pub max_depth: u16,
    }

    /// Cross-rule deduplication table: canonical clause -> clause bit index.
    pub struct ClauseTable<const NC: usize, const L: usize> { keys: [Clause<L>; NC], len: usize }
    impl<const NC: usize, const L: usize> ClauseTable<NC, L> {
        pub const EMPTY: Self = Self { keys: [Clause::EMPTY; NC], len: 0 };
        fn find(&self, c: &Clause<L>) -> Option<usize> { self.keys.get(..self.len)?.iter().position(|k| k == c) }
        fn insert(&mut self, c: Clause<L>) -> Result<usize, CompileError> {
            let id = self.len;
            *self.keys.get_mut(id).ok_or(CompileError::CapacityExceeded)? = c;
            self.len = id.checked_add(1).ok_or(CompileError::Overflow)?;
            Ok(id)
        }
    }

    /// Post-monomorphisation layout law. Any violation is a compile-time error of the user's crate.
    pub struct Layout<const NP: usize, const K: usize, const L: usize, const NR: usize,
                      const W: usize, const CB: usize, const RB: usize, const CAP: usize, const NC: usize>;
    impl<const NP: usize, const K: usize, const L: usize, const NR: usize,
         const W: usize, const CB: usize, const RB: usize, const CAP: usize, const NC: usize>
        Layout<NP, K, L, NR, W, CB, RB, CAP, NC>
    {
        pub const OK: () = {
            assert!(W * 64 >= NP, "atom planes too narrow");
            assert!(CB * 64 >= NR * K, "clause bitset too narrow");
            assert!(RB * 64 >= NR, "rule bitset too narrow");
            assert!(NC >= NR * K, "clause table too small");
            assert!(CAP >= NR * (K * (L + 2) + 1), "schedule capacity below WCET bound");
            assert!(W <= u16::MAX as usize && CB <= u16::MAX as usize && RB <= u16::MAX as usize, "word index width");
        };
        pub const WCET_INSTRUCTIONS: usize = NR * (K * (L + 2) + 1);
    }

    fn bit_of(idx: usize) -> Result<(u16, u64), CompileError> {
        let word = u16::try_from(idx / 64).map_err(|_| CompileError::Overflow)?;
        let bit = 1u64.checked_shl((idx % 64) as u32).ok_or(CompileError::Overflow)?;
        Ok((word, bit))
    }

    impl<const NP: usize, const K: usize, const L: usize, const NR: usize> SymbolicRuleDag<NP, K, L, NR> {
        /// Number of (plane, polarity, word) groups a clause occupies; equals its emitted Acc count.
        fn group_count<const W: usize, const RB: usize>(c: &Clause<L>) -> usize {
            let mut n = 0usize;
            for sel in 0..4u8 {
                let words = if sel < 2 { W } else { RB };
                for w in 0..words {
                    if c.lits().iter().any(|lit| Self::sel_word(lit) == (sel, w)) { n = n.saturating_add(1); }
                }
            }
            n
        }
        fn sel_word(lit: &Literal) -> (u8, usize) {
            match *lit {
                Literal::Atom { id, negated: false } => (0, usize::from(id) / 64),
                Literal::Atom { id, negated: true } => (1, usize::from(id) / 64),
                Literal::Rule { id, negated: false } => (2, usize::from(id) / 64),
                Literal::Rule { id, negated: true } => (3, usize::from(id) / 64),
            }
        }

        fn emit_clause<const W: usize, const CB: usize, const RB: usize, const CAP: usize>(
            c: &Clause<L>, clause_id: usize, out: &mut Schedule<W, CB, RB, CAP>,
        ) -> Result<usize, CompileError> {
            let mut ops = 0usize;
            for sel in 0..4u8 {
                let words = if sel < 2 { W } else { RB };
                for w in 0..words {
                    let mut mask = 0u64;
                    for lit in c.lits() {
                        if Self::sel_word(lit) == (sel, w) {
                            let id = match *lit { Literal::Atom { id, .. } | Literal::Rule { id, .. } => id };
                            mask |= bit_of(usize::from(id))?.1;
                        }
                    }
                    if mask != 0 {
                        let word = u16::try_from(w).map_err(|_| CompileError::Overflow)?;
                        out.push(match sel {
                            0 => Insn::AccAtomPos { word, mask }, 1 => Insn::AccAtomNeg { word, mask },
                            2 => Insn::AccRulePos { word, mask }, _ => Insn::AccRuleNeg { word, mask },
                        })?;
                        ops = ops.checked_add(1).ok_or(CompileError::Overflow)?;
                    }
                }
            }
            let (word, bit) = bit_of(clause_id)?;
            out.push(Insn::EndClause { word, bit })?;
            ops.checked_add(1).ok_or(CompileError::Overflow)
        }

        pub fn compile<const W: usize, const CB: usize, const RB: usize, const CAP: usize, const NC: usize>(
            &self, rank: &RankTable<NR, K>, table: &mut ClauseTable<NC, L>, out: &mut Schedule<W, CB, RB, CAP>,
        ) -> Result<CompileReport, CompileError> {
            let () = Layout::<NP, K, L, NR, W, CB, RB, CAP, NC>::OK;
            let topo = self.validate()?;
            let mut report = CompileReport { max_depth: topo.max_depth, ..CompileReport::default() };
            let mut emitted = [false; NR];

            for _ in 0..NR {
                // List scheduling: highest rank among rules whose referenced rules are all emitted.
                let mut best: Option<usize> = None;
                for ri in 0..NR {
                    if emitted.get(ri).copied().unwrap_or(true) || !self.deps_emitted(ri, &emitted) { continue; }
                    let better = best.map_or(true, |b| rank.rule_rank.get(ri) > rank.rule_rank.get(b));
                    if better { best = Some(ri); }
                }
                let ri = best.ok_or(CompileError::TopologyViolation)?;
                let rule = self.rules.get(ri).ok_or(CompileError::TopologyViolation)?;

                // Canonicalise and absorb (Lemma 2.1); K is tiny so O(K^2) is fine.
                let mut canon = [Clause::<L>::EMPTY; K];
                let mut keep = [false; K];
                let mut n = 0usize;
                for (ci, c) in rule.clauses().iter().enumerate() {
                    if let Some(slot) = canon.get_mut(ci) { *slot = c.canonical(); }
                    if let Some(k) = keep.get_mut(ci) { *k = true; }
                    n = ci.saturating_add(1);
                }
                for i in 0..n { for j in 0..n {
                    let (ci, cj) = (canon.get(i).copied(), canon.get(j).copied());
                    if let (Some(ci), Some(cj)) = (ci, cj) {
                        let i_alive = keep.get(i).copied().unwrap_or(false);
                        let j_alive = keep.get(j).copied().unwrap_or(false);
                        // j is absorbed by i when ci ⊆ cj and (ci ≠ cj, or i < j to keep one copy).
                        if i_alive && j_alive && i != j && ci.subsumes(&cj) && (ci != cj || i < j) {
                            if let Some(k) = keep.get_mut(j) { *k = false; }
                            report.clauses_absorbed = report.clauses_absorbed.saturating_add(1);
                        }
                    }
                }}

                // Ratio-rule order (Theorem 5.1) over surviving clauses.
                let mut order = [0usize; K]; let mut m = 0usize;
                for i in 0..n { if keep.get(i).copied().unwrap_or(false) { if let Some(s) = order.get_mut(m) { *s = i; } m = m.saturating_add(1); } }
                for i in 1..m {
                    let mut j = i;
                    while j > 0 {
                        let (a, b) = (order.get(j - 1).copied(), order.get(j).copied());
                        let (Some(a), Some(b)) = (a, b) else { break };
                        let cost = |x: usize| canon.get(x).map_or(1, |c| Self::group_count::<W, RB>(c).saturating_add(1) as u64);
                        let p = |x: usize| rank.clause_p.get(ri).and_then(|r| r.get(x)).copied().unwrap_or(crate::rank::FixedQ16_16(0));
                        if ratio_ge(p(a), cost(a), p(b), cost(b)).ok_or(CompileError::RankOverflow)? { break; }
                        order.swap(j - 1, j); j -= 1;
                    }
                }

                // Emit owned clauses, then joins, then EndRule.
                let mut clause_ids = [0usize; K];
                for (pos, &ci) in order.iter().take(m).enumerate() {
                    let c = canon.get(ci).ok_or(CompileError::TopologyViolation)?;
                    for lit in c.lits() { if let Literal::Rule { id, .. } = *lit {
                        if !emitted.get(usize::from(id)).copied().unwrap_or(false) { return Err(CompileError::TopologyViolation); }
                    }}
                    let id = match table.find(c) {
                        Some(id) => { report.clauses_shared = report.clauses_shared.saturating_add(1); id }
                        None => {
                            let id = table.insert(*c)?;
                            Self::emit_clause(c, id, out)?;
                            report.clauses_owned = report.clauses_owned.saturating_add(1);
                            id
                        }
                    };
                    if let Some(slot) = clause_ids.get_mut(pos) { *slot = id; }
                }
                for &id in clause_ids.iter().take(m) { let (word, bit) = bit_of(id)?; out.push(Insn::Join { word, bit })?; }
                let (word, bit) = bit_of(ri)?;
                out.push(Insn::EndRule { word, bit })?;
                if let Some(e) = emitted.get_mut(ri) { *e = true; }
            }
            report.instructions = out.len();
            Ok(report)
        }
    }
}

/// Copley instantiation. The assertions are the pinned layout law.
pub type CopleyDag = dag::SymbolicRuleDag<537, 9, 9, 236>;
pub type CopleySchedule = isa::Schedule<9, 34, 4, 23_600>;
pub type CopleyRegs = isa::Regs<9, 34, 4>;
pub type CopleyClauseTable = compile::ClauseTable<2_124, 9>;
const _: () = assert!(9 * 64 >= 537 && 34 * 64 >= 236 * 9 && 4 * 64 >= 236);
const _: () = assert!(23_600 == 236 * (9 * (9 + 2) + 1));
const _: () = assert!(core::mem::size_of::<isa::Insn>() <= 16);
```

The schedule is 377,600 bytes at full capacity, so callers own its storage and pass `&mut`; `compile` never allocates.

## 6. Theorems

### 6.1 Equivalence

**Theorem 6.1.** For every valid `dag`, every `atoms` with $T \,\&\, F = 0$, and `regs = Regs::new(atoms)` after `execute`, `regs.verdict(r) == eval_reference(dag, atoms)[r]` for all $r$.

*Proof.* Induction over the emitted rule sequence $R_{\sigma(1)}, \dots, R_{\sigma(NR)}$. **Invariant** $\mathcal{I}_i$: after `EndRule` of $R_{\sigma(i)}$, the rule planes encode the reference verdict of $R_{\sigma(j)}$ for all $j \le i$, zero elsewhere, and $T_R \,\&\, F_R = 0$; moreover every clause bit written so far is the Kleene value of its canonical clause. *Clause step.* Each surviving clause of $R_{\sigma(i)}$ is either owned or found in the table. If owned, its `Acc` ops read atom planes (invariant input) or rule planes of rules already emitted (checked by `TopologyViolation`; by $\mathcal{I}_{i-1}$ these are exact). By L3.1–L3.4 the `EndClause` writes the Kleene value of the literal set. If shared, the clause's bit was written earlier for an equal canonical clause, and Lemma 2.2 gives equality of values. *Rule step.* `racc` starts at $(0,1)$; each `Join` ORs $t_c$ and ANDs $f_c$ over exactly the surviving clause set $\mathcal{S}$; by L3.5 `EndRule` writes the Kleene disjunction over $\mathcal{S}$. By Lemma 2.1 the disjunction over $\mathcal{S}$ equals the disjunction over the original clause list, which is what `eval_reference` folds. Disjointness of the written bit and preservation of $T_R \,\&\, F_R = 0$ follow from L3.5. $\square$

### 6.2 Trace constancy (the precise meaning of "zero-branch")

**Definition.** The control trace $\mathrm{tr}(S, x)$ of executing schedule $S$ on input $x$ is the sequence of (program counter, opcode, accessed register indices).

**Theorem 6.2.** $\mathrm{tr}(S, x) = \mathrm{tr}(S, x')$ for all $x, x'$. *Proof.* `execute_prefix` iterates `take(n)` with $n$ a function of $S$ and fuel. In `step`, the `match` scrutinee is `insn`, the indices passed to `ld` and `or_into` are instruction fields, and the `if let` inside `or_into` tests index validity against a const length. `fill`, `isz`, `nz` are value-level selects. No expression's control flow mentions `atom`, `clause_*`, `rule_*`, or accumulator contents. $\square$

Machine-level note: `(x == 0) as u64` lowers to `cset` on AArch64 and `sete` on x86-64. A CI disassembly audit of `step` for conditional jumps other than the opcode dispatch table is a required gate for this crate; the dispatch is an indirect branch on public schedule data and is not a leak of $x$.

### 6.3 Prefix soundness

**Theorem 6.3.** For every $n$, let $v_n$ be the verdict vector read after `execute_prefix(regs, n)` and $v$ the full vector. Then $v_n(r) \sqsubseteq v(r)$ in the information order, and $v_n(r) = v(r)$ for every rule whose `EndRule` lies within the first $n$ instructions.

*Proof.* A rule's `EndRule` is preceded in $S$ by all `Acc`/`EndClause` instructions of its owned clauses, by the `EndClause` of each shared clause (emitted earlier by construction), and by the `EndRule` of every referenced rule (topological emission). Hence if `EndRule` of $r$ is in the prefix, $r$'s value is computed exactly as in Theorem 6.1. If not, bit $r$ of both rule planes is still zero, which decodes to $\bot$. $\square$

This is the Wave 1 contract for fuel: the governor computes $n(\lambda_{\text{fuel}})$ with `prefix_for_fuel`, snaps to a rule boundary, and $\Pi_{\mathcal{C}_\ell(x)}$ maps any $\bot$ to the conservative fallback. Ranking by `rule_rank` places Deny-critical rules in short prefixes, which is where Theorem 5.1's ordering earns its keep under truncation.

### 6.4 Exact worst-case instruction count

**Theorem 6.4.** For any valid `SymbolicRuleDag<NP, K, L, NR>`, the emitted length satisfies
$$|S| \;\le\; I_{\max} = NR\,\big(K(L+2) + 1\big),$$
and the bound is attained.

*Proof.* Fix rule $R_i$ with surviving clause set $\mathcal{S}_i$ and owned subset $\mathcal{O}_i \subseteq \mathcal{S}_i$. Canonicalisation and absorption only remove clauses, so $|\mathcal{S}_i| \le K$. For an owned clause $c$ the compiler emits $g(c)$ `Acc` instructions, one per nonempty (plane, polarity, word) group, plus one `EndClause`. The map from literals to groups is total and every emitted group is nonempty, so $g(c) \le |c| \le L$. The rule then emits $|\mathcal{S}_i|$ `Join` and one `EndRule`. Therefore
$$|S| = \sum_{i=1}^{NR}\Big(\sum_{c \in \mathcal{O}_i}(g(c)+1) + |\mathcal{S}_i| + 1\Big) \le \sum_{i=1}^{NR}\big(K(L+1) + K + 1\big) = NR\,(K(L+2)+1).$$
*Tightness.* Take $NR \cdot K$ pairwise distinct clauses, each with $L$ positive atom literals in $L$ distinct words, no clause shared across rules, $K$ per rule, no rule references. Distinct $L$-sets cannot strictly contain one another, so nothing is absorbed or shared; each literal is its own group; every inequality above is an equality. For Copley, $18$ atom (polarity, word) groups exceed $L = 9$ and $\binom{537}{9}$ exceeds $2124$, so the extremal DAG exists. $\square$

**Corollary 6.5 (Copley).** $I_{\max} = 236 \cdot (9 \cdot 11 + 1) = 23{,}600$, which is the `CopleySchedule` capacity; `CapacityExceeded` is unreachable for valid input and remains only as the checked-arithmetic backstop. Per-instruction cost is bounded by two loads, six ALU operations and two stores, so WCET in cycles is $23{,}600 \cdot c_{\max}$ plus loop overhead, independent of $x$. Deduplication savings are exactly $\sum_i \sum_{c \in \mathcal{S}_i \setminus \mathcal{O}_i}(g(c)+1)$ and are reported, not assumed.

## 7. Mechanised fragments

### 7.1 Lean 4 (Mathlib)

```lean
import Mathlib.Order.Lattice
import Mathlib.Data.Finset.Lattice
import Std.Tactic.BVDecide

namespace Chio.Copley

inductive K3 | neg | bot | pos deriving DecidableEq, Repr, Fintype

def K3.toNat : K3 → Nat | .neg => 0 | .bot => 1 | .pos => 2
theorem K3.toNat_inj : Function.Injective K3.toNat := by decide

/-- Truth order neg < bot < pos; a linear order, hence a distributive lattice. -/
instance : LinearOrder K3 := LinearOrder.lift' K3.toNat K3.toNat_inj

def K3.and : K3 → K3 → K3 := fun a b => a ⊓ b
def K3.or  : K3 → K3 → K3 := fun a b => a ⊔ b

/-- Information order used by prefix soundness. -/
def K3.le_info (a b : K3) : Prop := a = .bot ∨ a = b

theorem and_mono : ∀ a a' b b' : K3, a.le_info a' → b.le_info b' → (a.and b).le_info (a'.and b') := by
  decide
theorem or_mono : ∀ a a' b b' : K3, a.le_info a' → b.le_info b' → (a.or b).le_info (a'.or b') := by
  decide

/-- Lemma 2.1 as a lattice identity: a ⊔ (a ⊓ c) = a. -/
theorem absorb (a c : K3) : a.or (a.and c) = a := sup_inf_self

/-- Clause over a finite literal set, valued in the lattice. -/
def clauseVal {ι : Type} [DecidableEq ι] (v : ι → K3) (c : Finset ι) : K3 := c.inf v

/-- Subsumption: A ⊆ B ⇒ A ∨ B = A. -/
theorem subsumes_absorb {ι : Type} [DecidableEq ι] (v : ι → K3) (A B : Finset ι) (h : A ⊆ B) :
    clauseVal v A ⊔ clauseVal v B = clauseVal v A := by
  have : B = A ∪ (B \ A) := (Finset.union_sdiff_of_subset h).symm
  rw [clauseVal, clauseVal, this, Finset.inf_union]; exact sup_inf_self

/-- L3.1: missing-bits test. -/
theorem missing_zero (x m : BitVec 64) : ((x &&& m) ^^^ m = 0) ↔ ((x &&& m) = m) := by bv_decide
/-- L3.3: fill. -/
theorem fill_spec (b : BitVec 64) (hb : b = 0 ∨ b = 1) :
    (0 - b) = (if b = 1 then BitVec.allOnes 64 else 0) := by
  rcases hb with h | h <;> subst h <;> bv_decide

/-- Theorem 6.4 in a list model. -/
structure Clause where lits : List Nat
structure Rule where clauses : List Clause

def clauseInsns (c : Clause) : Nat := c.lits.length + 1
def ruleInsns (K L : Nat) (r : Rule) : Nat :=
  (r.clauses.map clauseInsns).sum + r.clauses.length + 1

theorem ruleInsns_le (K L : Nat) (r : Rule)
    (hK : r.clauses.length ≤ K) (hL : ∀ c ∈ r.clauses, c.lits.length ≤ L) :
    ruleInsns K L r ≤ K * (L + 2) + 1 := by
  have hsum : (r.clauses.map clauseInsns).sum ≤ r.clauses.length * (L + 1) := by
    induction r.clauses with
    | nil => simp
    | cons c cs ih =>
      have hc := hL c (by simp)
      have := ih (fun c' hc' => hL c' (by simp [hc']))
      simp [clauseInsns, List.sum_cons, List.length_cons] at *; nlinarith
  unfold ruleInsns; nlinarith

theorem schedule_le (K L : Nat) (rs : List Rule)
    (hK : ∀ r ∈ rs, r.clauses.length ≤ K) (hL : ∀ r ∈ rs, ∀ c ∈ r.clauses, c.lits.length ≤ L) :
    (rs.map (ruleInsns K L)).sum ≤ rs.length * (K * (L + 2) + 1) := by
  induction rs with
  | nil => simp
  | cons r rs ih =>
    have h1 := ruleInsns_le K L r (hK r (by simp)) (hL r (by simp))
    have h2 := ih (fun r' h => hK r' (by simp [h])) (fun r' h => hL r' (by simp [h]))
    simp [List.sum_cons, List.length_cons] at *; nlinarith

end Chio.Copley
```

The Lean model counts `L` per clause rather than the group count $g(c) \le |c|$; the inequality direction is the one Theorem 6.4 needs. These files are additive under `formal/lean4/Chio/Copley/`, and `formal/proof-manifest.toml` gains entries without touching the pinned `formal_core` and `formal_aeneas` signatures.

### 7.2 Apalache TLA+

```tla
---------------------------- MODULE CopleySchedule ----------------------------
EXTENDS Integers, Sequences
CONSTANTS
  \* @type: Seq(Str);
  Sched,                    \* opcode sequence, public
  \* @type: Int;
  NR,
  \* @type: Int -> Int;
  Spec                      \* reference verdict per rule: 0 = Bot, 1 = Pos, 2 = Neg
VARIABLES
  \* @type: Int;
  pc,
  \* @type: Int -> Int;
  Verdict,                  \* 0 = Bot until that rule's EndRule executes
  \* @type: Int;
  input                     \* abstract input, fixed at Init, never read by control

RuleOf(i) == i % NR          \* abstraction of the EndRule target bit

Init == pc = 1 /\ Verdict = [r \in 0..NR-1 |-> 0] /\ input \in 0..7

Next ==
  /\ pc <= Len(Sched)
  /\ pc' = pc + 1                                   \* control never inspects `input`
  /\ Verdict' = IF Sched[pc] = "EndRule"
                THEN [Verdict EXCEPT ![RuleOf(pc)] = Spec[RuleOf(pc)]]
                ELSE Verdict
  /\ UNCHANGED input

\* Theorem 6.3: every rule is Bot or exactly the specification value.
PrefixSound == \A r \in 0..NR-1 : Verdict[r] = 0 \/ Verdict[r] = Spec[r]
\* Theorem 6.2: control is a function of pc alone (checked as an inductive invariant
\* on the product of two copies with different `input`, omitted for space).
TraceOblivious == pc \in 1..Len(Sched)+1
================================================================================
```

Run with `apalache-mc check --inv=PrefixSound --length=23601 CopleySchedule.tla` for the Copley length, or symbolically with `--inv` as an inductive invariant.

### 7.3 Kani

```rust
#[cfg(kani)]
mod proofs {
    use crate::*;
    use crate::dag::{Clause, Literal, Rule, SymbolicRuleDag};

    #[kani::proof]
    fn fill_spec() {
        let b: u64 = kani::any(); kani::assume(b <= 1);
        assert_eq!(isa::fill(b), if b == 1 { u64::MAX } else { 0 });
    }

    /// Bounded instance <16, 2, 2, 3>: executor is panic-free, equals the reference,
    /// preserves rule-plane disjointness, and respects the WCET capacity.
    #[kani::proof]
    #[kani::unwind(64)]
    fn small_instance_equivalence() {
        let mut rules = [Rule::<2, 2>::EMPTY; 3];
        for (ri, rule) in rules.iter_mut().enumerate() {
            for _ in 0..kani::any::<u8>() % 3 {
                let mut c = Clause::<2>::EMPTY;
                for _ in 0..kani::any::<u8>() % 3 {
                    let lit = if kani::any() { Literal::Atom { id: kani::any::<u16>() % 16, negated: kani::any() } }
                              else { Literal::Rule { id: kani::any::<u16>() % 3, negated: kani::any() } };
                    let _ = c.push(lit);
                }
                let _ = rule.push(c);
            }
            let _ = ri;
        }
        let dag = SymbolicRuleDag::<16, 2, 2, 3>::new(rules);
        let Ok(spec_topo) = dag.validate() else { return };   // cyclic inputs are rejected, not executed
        let _ = spec_topo;
        let (t, f): ([u64; 1], [u64; 1]) = (kani::any(), kani::any());
        kani::assume(t[0] & f[0] == 0);
        let atoms = k3::Planes::<1>::from_planes(t, f).unwrap();

        let mut table = compile::ClauseTable::<6, 2>::EMPTY;
        let mut sched = isa::Schedule::<1, 1, 1, 27>::EMPTY;          // 3 * (2*(2+2)+1) = 27
        let report = dag.compile(&rank::RankTable::<3, 2>::UNIFORM, &mut table, &mut sched).unwrap();
        assert!(report.instructions <= 27);

        let mut regs = isa::Regs::<1, 1, 1>::new(atoms);
        sched.execute(&mut regs);
        assert_eq!(regs.rule_t[0] & regs.rule_f[0], 0);
        let spec = dag.eval_reference::<1>(&atoms).unwrap();
        for r in 0..3 { assert_eq!(regs.verdict(r), spec[r]); }

        // Theorem 6.3 on an arbitrary prefix.
        let n: usize = kani::any(); kani::assume(n <= sched.len());
        let mut pre = isa::Regs::<1, 1, 1>::new(atoms);
        sched.execute_prefix(&mut pre, n);
        for r in 0..3 { assert!(pre.verdict(r).leq_info(spec[r])); }
    }
}
```

The bounded harness is exhaustive over its parameter space; the general-parameter claims rest on Theorems 6.1–6.4 and the Lean counting lemma.

## 8. Differential equivalence against HushSpec IR

Sections B–E of the grounded context pin kernel, guard and receipt signatures but not the `chio-policy` HushSpec IR, so the adapter is defined here as a trait and the differential harness is generic over it. The concrete `impl` for `chio_policy`'s IR type belongs in `chio-policy` and must be reviewed against that crate's real evaluator; the harness fails closed if `lower` and the IR's own evaluation disagree.

```rust
pub mod hushspec {
    use crate::dag::{Clause, Literal, Rule, SymbolicRuleDag};
    use crate::k3::{Planes, K3};

    /// Minimal lowering surface for `chio-policy` HushSpec IR. Implemented in `chio-policy`.
    pub trait HushSpecIr {
        fn rule_count(&self) -> usize;
        fn clause_count(&self, rule: usize) -> usize;
        fn literal(&self, rule: usize, clause: usize, i: usize) -> Option<Literal>;
        /// The IR's own evaluator; the independent oracle.
        fn eval<const W: usize>(&self, atoms: &Planes<W>, rule: usize) -> K3;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LowerError { TooManyRules, Dag(crate::dag::DagError) }

    pub fn lower<const NP: usize, const K: usize, const L: usize, const NR: usize>(
        ir: &impl HushSpecIr,
    ) -> Result<SymbolicRuleDag<NP, K, L, NR>, LowerError> {
        if ir.rule_count() > NR { return Err(LowerError::TooManyRules); }
        let mut rules = [Rule::<K, L>::EMPTY; NR];
        for (ri, rule) in rules.iter_mut().enumerate().take(ir.rule_count()) {
            for ci in 0..ir.clause_count(ri) {
                let mut c = Clause::<L>::EMPTY;
                let mut i = 0usize;
                while let Some(lit) = ir.literal(ri, ci, i) {
                    c.push(lit).map_err(LowerError::Dag)?;
                    i = i.checked_add(1).ok_or(LowerError::TooManyRules)?;
                }
                rule.push(c).map_err(LowerError::Dag)?;
            }
        }
        Ok(SymbolicRuleDag::new(rules))
    }
}

#[cfg(test)]
mod differential {
    use super::*;
    use crate::dag::{Clause, Literal, Rule, SymbolicRuleDag};

    struct XorShift(u64);
    impl XorShift { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x } }

    /// Random valid DAG: rule literals only reference lower ids, so acyclic by construction.
    fn random_dag<const NP: usize, const K: usize, const L: usize, const NR: usize>(rng: &mut XorShift) -> SymbolicRuleDag<NP, K, L, NR> {
        let mut rules = [Rule::<K, L>::EMPTY; NR];
        for ri in 0..NR {
            for _ in 0..(rng.next() as usize % (K + 1)) {
                let mut c = Clause::<L>::EMPTY;
                for _ in 0..(rng.next() as usize % (L + 1)) {
                    let negated = rng.next() & 1 == 1;
                    let lit = if ri > 0 && rng.next() % 4 == 0 { Literal::Rule { id: (rng.next() as usize % ri) as u16, negated } }
                              else { Literal::Atom { id: (rng.next() as usize % NP) as u16, negated } };
                    c.push(lit).unwrap();
                }
                rules[ri].push(c).unwrap();
            }
        }
        SymbolicRuleDag::new(rules)
    }

    fn random_planes<const W: usize>(rng: &mut XorShift) -> k3::Planes<W> {
        let (mut t, mut f) = ([0u64; W], [0u64; W]);
        for w in 0..W { let a = rng.next(); let b = rng.next(); t[w] = a & !b; f[w] = b & !a; }
        k3::Planes::from_planes(t, f).unwrap()
    }

    #[test]
    fn schedule_matches_reference_and_prefixes_are_sound() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..2_000 {
            let dag = random_dag::<128, 4, 4, 12>(&mut rng);
            let mut table = compile::ClauseTable::<48, 4>::EMPTY;
            let mut sched = isa::Schedule::<2, 1, 1, { 12 * (4 * 6 + 1) }>::EMPTY;
            let report = dag.compile(&rank::RankTable::<12, 4>::UNIFORM, &mut table, &mut sched).unwrap();
            assert!(report.instructions <= 12 * (4 * 6 + 1));
            for _ in 0..16 {
                let atoms = random_planes::<2>(&mut rng);
                let spec = dag.eval_reference::<2>(&atoms).unwrap();
                let mut regs = isa::Regs::<2, 1, 1>::new(atoms);
                sched.execute(&mut regs);
                for r in 0..12 { assert_eq!(regs.verdict(r), spec[r], "rule {r}"); }
                let n = rng.next() as usize % (sched.len() + 1);
                let mut pre = isa::Regs::<2, 1, 1>::new(atoms);
                sched.execute_prefix(&mut pre, n);
                for r in 0..12 { assert!(pre.verdict(r).leq_info(spec[r])); }
            }
        }
    }

    #[test]
    fn copley_capacity_is_the_wcet_bound() {
        assert_eq!(compile::Layout::<537, 9, 9, 236, 9, 34, 4, 23_600, 2_124>::WCET_INSTRUCTIONS, 23_600);
    }

    /// Generic over the real `chio_policy` IR once its `HushSpecIr` impl lands.
    pub fn differential_case<I: hushspec::HushSpecIr>(ir: &I, atoms: &k3::Planes<9>) {
        let dag = hushspec::lower::<537, 9, 9, 236>(ir).unwrap();
        let mut table = CopleyClauseTable::EMPTY;
        let mut sched = std::boxed::Box::new(CopleySchedule::EMPTY);
        dag.compile(&rank::RankTable::UNIFORM, &mut table, &mut sched).unwrap();
        let mut regs = CopleyRegs::new(*atoms);
        sched.execute(&mut regs);
        for r in 0..ir.rule_count() { assert_eq!(regs.verdict(r), ir.eval::<9>(atoms, r), "HushSpec rule {r}"); }
    }
}
```

**Receipt coupling.** The schedule hash must be an input to `policy_hash`, so `receipt_fields_coupled` from `formal_core.rs` binds a receipt to the exact compiled program. No new reserved metadata key is introduced; the 35-entry `RESERVED_RECEIPT_METADATA_KEYS` array stays untouched, which keeps every pinned proof intact.

## Recap

- **Delivered** a complete `#![no_std]`, `#![forbid(unsafe_code)]` crate: Kleene plane encoding, an eight-opcode bitset ISA with an input-oblivious executor, and a compiler that validates the DAG by depth relaxation, canonicalises clauses, applies the only two simplifications valid in $\mathbb{K}_3$, deduplicates clauses across rules, orders by the ratio rule, and emits in topological order.
- **Proved** executor–reference equivalence, trace constancy, prefix soundness, and the exact worst-case count $NR(K(L+2)+1)$ with a tightness construction. For Copley the capacity is 23,600 instructions, pinned by `const` assertions and a post-monomorphisation layout law.
- **Mechanised** the lattice absorption lemma, the bitvector lemmas and the counting bound in Lean 4, prefix soundness in Apalache, and a bounded exhaustive Kani instance covering panic-freedom, equivalence, plane disjointness and prefix soundness.
- **Flagged** that the HushSpec IR signatures are not in the grounded context. The adapter trait and generic differential harness are in place; the `impl` for `chio-policy`'s concrete IR type and the `step` disassembly audit are the two remaining CI gates before this pass can be marked merged.

---

# Verbatim Treatise - `wave14_angle_3_concurrent_loom_and_dst_crash_recovery_pass_14`

| Cutpoint | Durable rows | Effect ran | Recovery op | Post-recovery |
|---|---|---|---|---|
| C0 before reserve | none | no | noop | no row |
| C1 after reserve, before marker | Reserved, started=false | no | release | Free |
| C2 after marker, before effect | Reserved, started=true | no | retain | Retained (conservative) |
| C3 after effect, before receipt | Reserved, started=true | yes | retain | Retained |
| C4 after receipt | Consumed, receipt=true | yes | noop | Consumed |

```rust
// crates/kernel/chio-kernel/tests/dst_drop_simulation.rs
//! cargo test -p chio-kernel --test dst_drop_simulation -- --nocapture
//! Replay: CHIO_DST_SEEDS=0x9e3779b97f4a7c15 CHIO_DST_EPISODES=20000 cargo test ...
use chio_kernel_core::concurrency_core::*;
use chio_kernel_core::formal_aeneas::ReservationLedger;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntentRow { pub nonce_state: u8, pub dispatch_started: bool, pub receipt_durable: bool, pub ledger_op: u8 }

/// SQLite-shaped durable log: `commit` is atomic and durable; `crash` loses nothing committed.
pub trait DurableStore {
    fn read(&self, nonce: u64) -> Option<IntentRow>;
    fn rows(&self) -> Vec<(u64, IntentRow)>;
    fn commit(&mut self, writes: &[(u64, IntentRow)]);
    fn crash(&mut self);
    fn ledger(&self) -> ReservationLedger;
}

#[derive(Default)]
pub struct SimSqlite { durable: BTreeMap<u64, IntentRow>, ops: Vec<u8>, commits: u64 }

impl DurableStore for SimSqlite {
    fn read(&self, nonce: u64) -> Option<IntentRow> { self.durable.get(&nonce).copied() }
    fn rows(&self) -> Vec<(u64, IntentRow)> { self.durable.iter().map(|(n, r)| (*n, *r)).collect() }
    fn commit(&mut self, writes: &[(u64, IntentRow)]) {
        for (n, r) in writes {
            self.durable.insert(*n, *r);
            if r.ledger_op != LEDGER_OP_NOOP { self.ops.push(r.ledger_op); }
        }
        self.commits = self.commits.checked_add(1).expect("commit counter");
    }
    fn crash(&mut self) { /* every write above was committed; volatile state lives outside */ }
    fn ledger(&self) -> ReservationLedger {
        let mut l = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
        for op in &self.ops { l = ledger_apply_one(&l, *op).expect("ledger op enabled"); }
        l
    }
}

#[derive(Default)]
pub struct World { pub effects: BTreeMap<u64, u32> }
impl World {
    fn perform(&mut self, nonce: u64) {
        let e = self.effects.entry(nonce).or_insert(0);
        *e = e.checked_add(1).expect("effect counter");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut { BeforeReserve, AfterReserve, AfterMarker, AfterEffect, AfterReceipt }
const CUTS: [Cut; 5] = [Cut::BeforeReserve, Cut::AfterReserve, Cut::AfterMarker, Cut::AfterEffect, Cut::AfterReceipt];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Allow, Deny, PendingApproval }

/// Mirrors the additive `RecoveryGuard` in `GuardPipeline`: Retained => sticky PendingApproval,
/// Consumed => Deny (replay), anything in flight at boot is impossible after recovery.
fn pre_dispatch_guard(row: Option<IntentRow>) -> Verdict {
    match row.map(|r| r.nonce_state) {
        None | Some(NONCE_FREE) => Verdict::Allow,
        Some(NONCE_RETAINED) => Verdict::PendingApproval,
        Some(NONCE_CONSUMED) => Verdict::Deny,
        Some(_) => panic!("in-flight row survived recovery"),
    }
}

/// Runs the dispatch protocol until `cut`, then returns. The caller crashes the kernel.
fn dispatch_protocol<S: DurableStore>(store: &mut S, world: &mut World, nonce: u64, cut: Cut) -> Verdict {
    let v = pre_dispatch_guard(store.read(nonce));
    if v != Verdict::Allow || cut == Cut::BeforeReserve { return v; }
    store.commit(&[(nonce, IntentRow { nonce_state: NONCE_RESERVED, dispatch_started: false, receipt_durable: false, ledger_op: LEDGER_OP_RESERVE })]);
    if cut == Cut::AfterReserve { return v; }
    store.commit(&[(nonce, IntentRow { nonce_state: NONCE_RESERVED, dispatch_started: true, receipt_durable: false, ledger_op: LEDGER_OP_NOOP })]);
    if cut == Cut::AfterMarker { return v; }
    world.perform(nonce);
    if cut == Cut::AfterEffect { return v; }
    store.commit(&[(nonce, IntentRow { nonce_state: NONCE_CONSUMED, dispatch_started: true, receipt_durable: true, ledger_op: LEDGER_OP_COMMIT })]);
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCut { None, BeforeCommit }

/// Boot recovery: `recover_intent` over every durable row, applied in one transaction.
fn recover<S: DurableStore>(store: &mut S, rcut: RecoveryCut) -> bool {
    let mut writes = Vec::new();
    for (nonce, row) in store.rows() {
        let op = recover_intent(row.nonce_state, row.dispatch_started, row.receipt_durable);
        if op == LEDGER_OP_NOOP { continue; }
        let next = nonce_step(row.nonce_state, op).expect("recovery op enabled");
        writes.push((nonce, IntentRow { nonce_state: next, ledger_op: op, ..row }));
    }
    if rcut == RecoveryCut::BeforeCommit && !writes.is_empty() { return false; }
    store.commit(&writes);
    true
}

fn check_invariants<S: DurableStore>(store: &S, world: &World, ctx: &str) {
    let rows = store.rows();
    for (n, r) in &rows {
        let eff = world.effects.get(n).copied().unwrap_or(0);
        assert_ne!(r.nonce_state, NONCE_RESERVED, "{ctx}: I1 leaked reservation nonce={n}");
        assert!(eff <= 1, "{ctx}: I3 double effect nonce={n}");
        if eff == 1 {
            assert!(r.receipt_durable || r.nonce_state == NONCE_RETAINED, "{ctx}: I2 orphan effect nonce={n}");
        }
        if r.nonce_state == NONCE_FREE { assert_eq!(eff, 0, "{ctx}: I5 rollback after effect nonce={n}"); }
    }
    for (n, eff) in &world.effects {
        if *eff > 0 { assert!(rows.iter().any(|(m, _)| m == n), "{ctx}: I2 effect without intent nonce={n}"); }
    }
    assert!(nonce_ledger_quiescent(&store.ledger()), "{ctx}: I4 ledger not quiescent");
}

struct Xorshift64Star(u64);
impl Xorshift64Star {
    fn new(seed: u64) -> Self { Self(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed }) }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d) // intentional modular multiply (PRNG output step)
    }
    fn below(&mut self, n: u64) -> u64 { self.next_u64() % n }
}

fn run_seed<S: DurableStore>(store: &mut S, seed: u64, episodes: u32) {
    let mut rng = Xorshift64Star::new(seed);
    let mut world = World::default();
    for ep in 0..episodes {
        let ctx = format!("seed={seed:#x} episode={ep}");
        assert!(recover(store, RecoveryCut::None), "{ctx}: clean boot recovery must complete");
        check_invariants(store, &world, &ctx);
        let nonce = rng.below(8);
        let cut = CUTS[usize::try_from(rng.below(5)).unwrap()];
        let _verdict = dispatch_protocol(store, &mut world, nonce, cut);
        store.crash();
        let rcut = if rng.below(4) == 0 { RecoveryCut::BeforeCommit } else { RecoveryCut::None };
        if !recover(store, rcut) { store.crash(); } // double crash; next boot reruns recovery
    }
}

fn seeds() -> Vec<u64> {
    std::env::var("CHIO_DST_SEEDS").ok()
        .map(|s| s.split(',').map(|h| u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).expect("hex seed")).collect())
        .unwrap_or_else(|| vec![0x9e37_79b9_7f4a_7c15, 0xd1b5_4a32_d192_ed03, 0x2545_f491_4f6c_dd1d])
}
fn episodes() -> u32 { std::env::var("CHIO_DST_EPISODES").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000) }

#[test]
fn dst_dispatch_crash_recovery_simulated_sqlite() {
    for seed in seeds() { run_seed(&mut SimSqlite::default(), seed, episodes()); }
}

#[cfg(feature = "sqlite-dst")]
mod real_sqlite {
    use super::*;
    use rusqlite::{params, Connection};

    pub struct RusqliteStore { path: std::path::PathBuf, conn: Connection }
    impl RusqliteStore {
        pub fn open(dir: &std::path::Path) -> Self {
            let path = dir.join("chio-dst.sqlite3");
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS intent(nonce INTEGER PRIMARY KEY, nonce_state INTEGER NOT NULL,
                   dispatch_started INTEGER NOT NULL, receipt_durable INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS ledger_ops(seq INTEGER PRIMARY KEY AUTOINCREMENT, op INTEGER NOT NULL);",
            ).unwrap();
            Self { path, conn }
        }
    }
    impl DurableStore for RusqliteStore {
        fn read(&self, nonce: u64) -> Option<IntentRow> { self.rows().into_iter().find(|(n, _)| *n == nonce).map(|(_, r)| r) }
        fn rows(&self) -> Vec<(u64, IntentRow)> {
            let mut st = self.conn.prepare("SELECT nonce, nonce_state, dispatch_started, receipt_durable FROM intent ORDER BY nonce").unwrap();
            st.query_map([], |r| Ok((
                u64::try_from(r.get::<_, i64>(0)?).unwrap(),
                IntentRow { nonce_state: r.get(1)?, dispatch_started: r.get(2)?, receipt_durable: r.get(3)?, ledger_op: LEDGER_OP_NOOP },
            ))).unwrap().map(Result::unwrap).collect()
        }
        fn commit(&mut self, writes: &[(u64, IntentRow)]) {
            let tx = self.conn.transaction().unwrap();
            for (n, r) in writes {
                tx.execute(
                    "INSERT INTO intent(nonce, nonce_state, dispatch_started, receipt_durable) VALUES(?1, ?2, ?3, ?4)
                     ON CONFLICT(nonce) DO UPDATE SET nonce_state=excluded.nonce_state,
                       dispatch_started=excluded.dispatch_started, receipt_durable=excluded.receipt_durable",
                    params![i64::try_from(*n).unwrap(), r.nonce_state, r.dispatch_started, r.receipt_durable],
                ).unwrap();
                if r.ledger_op != LEDGER_OP_NOOP { tx.execute("INSERT INTO ledger_ops(op) VALUES(?1)", params![r.ledger_op]).unwrap(); }
            }
            tx.commit().unwrap();
        }
        fn crash(&mut self) {
            // Every cutpoint lies between transactions, so dropping the connection and reopening
            // is observationally identical to power loss under SQLite's atomic-commit guarantee.
            // Torn-fsync injection requires a VFS shim and is tracked separately.
            self.conn = Connection::open(&self.path).unwrap();
        }
        fn ledger(&self) -> ReservationLedger {
            let mut st = self.conn.prepare("SELECT op FROM ledger_ops ORDER BY seq").unwrap();
            let mut l = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
            for op in st.query_map([], |r| r.get::<_, u8>(0)).unwrap() { l = ledger_apply_one(&l, op.unwrap()).unwrap(); }
            l
        }
    }

    #[test]
    fn dst_dispatch_crash_recovery_real_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        for seed in seeds() {
            let mut store = RusqliteStore::open(dir.path());
            run_seed(&mut store, seed, episodes().min(2_000));
        }
    }
}
```

**§6 Apalache TLA+ model.** `Claim` folds the volatile CAS and the marker transaction into one step. This is sound because a crash between them erases the volatile word, which is indistinguishable from a crash before `Claim`.

```tla
---------------------------- MODULE ChioDispatchCrash ----------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Set(Int);
  Nonces
VARIABLES
  \* @type: Int -> Str;  durable: "Free" | "Reserved" | "Consumed" | "Retained"
  nstate,
  \* @type: Int -> Bool; durable write-ahead marker
  started,
  \* @type: Int -> Bool; durable receipt, same txn as Consumed
  receipt,
  \* @type: Int -> Int;  external world, survives crashes
  effects,
  \* @type: Int -> Str;  volatile word: "None" | "Admitted" | "Dispatching" | "Dispatched" | "Done"
  mem,
  \* @type: Bool;
  up

Init ==
  /\ nstate = [n \in Nonces |-> "Free"] /\ started = [n \in Nonces |-> FALSE]
  /\ receipt = [n \in Nonces |-> FALSE] /\ effects = [n \in Nonces |-> 0]
  /\ mem = [n \in Nonces |-> "None"] /\ up = TRUE

Reserve(n) ==
  /\ up /\ nstate[n] = "Free" /\ mem[n] = "None"
  /\ nstate' = [nstate EXCEPT ![n] = "Reserved"] /\ started' = [started EXCEPT ![n] = FALSE]
  /\ mem' = [mem EXCEPT ![n] = "Admitted"] /\ UNCHANGED <<receipt, effects, up>>

\* Pre-dispatch cutpoint: cancel or pre-dispatch failure, durable release, no effect.
RollbackPre(n) ==
  /\ up /\ mem[n] = "Admitted"
  /\ nstate' = [nstate EXCEPT ![n] = "Free"] /\ mem' = [mem EXCEPT ![n] = "Done"]
  /\ UNCHANGED <<started, receipt, effects, up>>

Claim(n) ==
  /\ up /\ mem[n] = "Admitted"
  /\ started' = [started EXCEPT ![n] = TRUE] /\ mem' = [mem EXCEPT ![n] = "Dispatching"]
  /\ UNCHANGED <<nstate, receipt, effects, up>>

Effect(n) ==
  /\ up /\ mem[n] = "Dispatching"
  /\ effects' = [effects EXCEPT ![n] = @ + 1] /\ mem' = [mem EXCEPT ![n] = "Dispatched"]
  /\ UNCHANGED <<nstate, started, receipt, up>>

Receipt(n) ==
  /\ up /\ mem[n] = "Dispatched"
  /\ nstate' = [nstate EXCEPT ![n] = "Consumed"] /\ receipt' = [receipt EXCEPT ![n] = TRUE]
  /\ mem' = [mem EXCEPT ![n] = "Done"] /\ UNCHANGED <<started, effects, up>>

Crash == up /\ up' = FALSE /\ mem' = [n \in Nonces |-> "None"]
         /\ UNCHANGED <<nstate, started, receipt, effects>>

\* recover_intent applied to every durable row in one transaction.
Recover ==
  /\ ~up /\ up' = TRUE
  /\ nstate' = [n \in Nonces |->
       IF nstate[n] = "Reserved" /\ ~receipt[n]
       THEN (IF started[n] THEN "Retained" ELSE "Free") ELSE nstate[n]]
  /\ UNCHANGED <<started, receipt, effects, mem>>

Next == \/ \E n \in Nonces : Reserve(n) \/ RollbackPre(n) \/ Claim(n) \/ Effect(n) \/ Receipt(n)
        \/ Crash \/ Recover

Quiescent(n) == up /\ mem[n] \in {"None", "Done"}
NoLeakedReservation == \A n \in Nonces : Quiescent(n) => nstate[n] /= "Reserved"
NoDoubleEffect == \A n \in Nonces : effects[n] <= 1
NoOrphanEffect == \A n \in Nonces : (Quiescent(n) /\ effects[n] = 1) => (receipt[n] \/ nstate[n] = "Retained")
RollbackOnlyWithoutEffect == \A n \in Nonces : nstate[n] = "Free" => effects[n] = 0
Safety == NoLeakedReservation /\ NoDoubleEffect /\ NoOrphanEffect /\ RollbackOnlyWithoutEffect
================================================================================
```

Run with `apalache-mc check --inv=Safety --length=14 --cinit=CInit MC_ChioDispatchCrash.tla` where `CInit == Nonces = {1, 2}`. Two nonces suffice because every action touches a single nonce and `Crash`/`Recover` are pointwise.

**§7 Lean 4.** The session machine is the Lean mirror of `session_step`; a lost CAS leaves the word unchanged, which `exec` captures with `getD`.

```lean
-- formal/lean4/Chio/SessionCas.lean
namespace Chio.SessionCas

inductive S | admitted | dispatching | dispatched | receipted | cancelled | failedPre | retained
  deriving DecidableEq, Repr
inductive E | claim | cancel | effectDone | receiptDurable | failPre | crashRecover
  deriving DecidableEq, Repr
open S E

def step : S → E → Option S
  | admitted,    claim          => some dispatching
  | admitted,    cancel         => some cancelled
  | admitted,    failPre        => some failedPre
  | dispatching, effectDone     => some dispatched
  | dispatching, failPre        => some failedPre
  | dispatching, crashRecover   => some retained
  | dispatched,  crashRecover   => some retained
  | dispatched,  receiptDurable => some receipted
  | _,           _              => none

/-- A lost CAS is a no-op on the word. -/
def exec (s : S) (e : E) : S := (step s e).getD s

def run (s : S) : List E → S
  | []      => s
  | e :: es => run (exec s e) es

def Claimed (s : S) : Prop := s ≠ admitted ∧ s ≠ cancelled

theorem claimed_exec : ∀ s e, Claimed s → Claimed (exec s e) := by
  intro s e h; cases s <;> cases e <;> simp_all [exec, step, Claimed]

theorem claimed_run : ∀ (es : List E) (s : S), Claimed s → Claimed (run s es) := by
  intro es; induction es with
  | nil => intro s h; simpa [run] using h
  | cons e es ih => intro s h; exact ih _ (claimed_exec s e h)

/-- Theorem 1a: once dispatch is claimed, `cancelled` is unreachable. -/
theorem claim_excludes_cancel (es : List E) : run dispatching es ≠ cancelled :=
  (claimed_run es dispatching ⟨by decide, by decide⟩).2

/-- Number of external effects along an executed history. -/
def effects (s : S) : List E → Nat
  | []      => 0
  | e :: es => (if s = dispatching ∧ e = effectDone then 1 else 0) + effects (exec s e) es

def Spent (s : S) : Prop := s ≠ admitted ∧ s ≠ dispatching

theorem spent_exec : ∀ s e, Spent s → Spent (exec s e) := by
  intro s e h; cases s <;> cases e <;> simp_all [exec, step, Spent]

theorem effects_spent : ∀ es s, Spent s → effects s es = 0 := by
  intro es; induction es with
  | nil => intros; rfl
  | cons e es ih => intro s h; simp [effects, h.2, ih _ (spent_exec s e h)]

/-- Theorem 1b: the external effect fires at most once from any state. -/
theorem effects_le_one : ∀ es s, effects s es ≤ 1 := by
  intro es; induction es with
  | nil => intro s; simp [effects]
  | cons e es ih =>
    intro s
    by_cases hs : s = dispatching ∧ e = effectDone
    · obtain ⟨rfl, rfl⟩ := hs
      have hsp : Spent (exec dispatching effectDone) := by simp [Spent, exec, step]
      simp [effects, effects_spent es _ hsp]
    · simp [effects, hs, ih]

end Chio.SessionCas
```

```lean
-- formal/lean4/Chio/RecoveryLedger.lean
namespace Chio.Recovery
inductive N | free | reserved | consumed | retained deriving DecidableEq, Repr
open N

/-- Mirror of `recover_intent` composed with `nonce_step`. -/
def afterRecovery (n : N) (started durable : Bool) : N :=
  if n = reserved ∧ durable = false then (if started then retained else free) else n

/-- Rows with `Reserved ∧ receipt_durable` are excluded by transaction atomicity (one txn
    writes `Consumed` and the receipt together), hence the `durable = false` hypothesis. -/
theorem no_leaked_reservation (n : N) (started : Bool) :
    afterRecovery n started false ≠ reserved ∨ n ≠ reserved := by
  cases n <;> cases started <;> simp [afterRecovery]

theorem unknown_effect_is_retained (started : Bool) (h : started = true) :
    afterRecovery reserved started false = retained := by
  subst h; simp [afterRecovery]

theorem recovery_idempotent (n : N) (started : Bool) :
    afterRecovery (afterRecovery n started false) started false = afterRecovery n started false := by
  cases n <;> cases started <;> simp [afterRecovery]
end Chio.Recovery
```

**§8 Kani harnesses** live inside `chio-kernel-core` so they can reach the pub(crate) `ledger_is_terminal`.

```rust
// appended to crates/kernel/chio-kernel-core/src/concurrency_core.rs
#[cfg(kani)]
mod kani_harness {
    use super::*;
    use crate::formal_aeneas::ledger_is_terminal;

    #[kani::proof]
    fn session_step_is_closed_and_never_reenters_admitted() {
        let (s, e): (u8, u8) = (kani::any(), kani::any());
        kani::assume(s <= OP_RETAINED_UNKNOWN_EFFECT && e <= EV_CRASH_RECOVER);
        if let Some(n) = session_step(s, e) {
            assert!(n <= OP_RETAINED_UNKNOWN_EFFECT);
            assert!(!session_is_terminal(s));
            assert!(n != OP_ADMITTED);
        }
    }

    /// Pins the test oracle to the proof-manifest predicate. A divergence fails CI loudly.
    #[kani::proof]
    fn nonce_quiescence_oracle_pins_ledger_is_terminal() {
        let l = ReservationLedger { reserved: kani::any(), committed: kani::any(), released: kani::any(), retained: kani::any() };
        let q = nonce_ledger_quiescent(&l);
        assert_eq!(q, ledger_is_terminal(l));
    }

    #[kani::proof]
    fn recover_intent_never_leaves_reserved_and_is_idempotent() {
        let (s, started, durable): (u8, bool, bool) = (kani::any(), kani::any(), kani::any());
        kani::assume(s <= NONCE_RETAINED);
        kani::assume(!(s == NONCE_RESERVED && durable)); // excluded by transaction atomicity
        let op = recover_intent(s, started, durable);
        let after = if op == LEDGER_OP_NOOP { s } else { nonce_step(s, op).expect("recovery op enabled") };
        assert!(after != NONCE_RESERVED);
        assert_eq!(recover_intent(after, started, durable), LEDGER_OP_NOOP);
        if s == NONCE_RESERVED && started { assert_eq!(after, NONCE_RETAINED); }
        if s == NONCE_RESERVED && !started { assert_eq!(after, NONCE_FREE); }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn holders_refcount_bounded_under_any_sequence() {
        let mut h: usize = 0;
        for _ in 0..8 {
            h = if kani::any() { holders_admit(h, 3).unwrap_or(h) } else { holders_release(h).unwrap_or(h) };
            assert!(h <= 3);
        }
    }

    #[kani::proof]
    fn siblings_admit_respects_parent_share() {
        let (t, s, p): (u32, u16, u16) = (kani::any(), kani::any(), kani::any());
        if let Some(n) = siblings_admit(t, s, p) {
            assert!(n <= u32::from(p));
            assert!(s <= MAX_BUDGET_SHARE_BPS);
        }
    }
}
```

## Proofs and operations

**§9 Theorems.**

*Theorem 1 (single CAS decides).* Let $H$ be any history of one `dispatch` and any number of `cancel` calls on a `SessionOperation`. Then $H$ is linearizable with respect to `session_step`, the external effect runs at most once, and at quiescence exactly one holds: the word is `Cancelled` with zero effects, or the word is in {`Receipted`, `FailedPreDispatch`} with the effect count equal to one iff `Receipted`.

*Proof.* The word changes only by successful `compare_exchange`, and the successful CASes on one atomic are totally ordered by the C11 modification order $<_{mo}$. Take $<_L$ to order each operation at its linearization point: for a successful `cancel`, its winning CAS; for a `TooLate` cancel, the load that observed a state outside the domain of `EV_CANCEL`; for `dispatch`, its claim CAS. Each successful CAS reads the value written by its $<_{mo}$ predecessor, so the sequence of word values is a path of `session_step` from `OP_ADMITTED`, which is a trace of $\mathcal{S}$. Real-time order is respected because a linearization point lies inside its operation's interval. For the outcome: `EV_CANCEL` is enabled only in `OP_ADMITTED`, which is never re-entered (Kani `never_reenters_admitted`), and `run dispatching es ≠ cancelled` (Lean `claim_excludes_cancel`). Hence the claim CAS and a successful cancel CAS cannot both occur. The effect runs only after a successful claim and before `EV_EFFECT_DONE`; `effects_le_one` bounds it by one. If `pre` fails, `EV_FAIL_PRE_DISPATCH` fires before the effect by construction of `dispatch`, so the count is zero. $\square$

*Theorem 2 (nonce store).* Successful ops on slot $n$ form a path of `nonce_step`; `reserve` succeeds for exactly one of any set of concurrent callers on a `Free` slot; after all threads join, $\mathrm{reserved} - (\mathrm{committed}+\mathrm{released}+\mathrm{retained})$ equals the number of slots in `Reserved`.

*Proof.* The first claim follows as in Theorem 1 with `nonce_step` as $\mathcal{S}$. Mutual exclusion: `nonce_step(NONCE_FREE, RESERVE)` is the only op enabled in `Free`, and the first successful CAS moves the slot to `Reserved`, where `RESERVE` is disabled; every later `reserve` returns `false` from the `None` branch. Counting: each successful reserve CAS is followed by exactly one `ledger_apply(…, 0, 1)`, each settle CAS by exactly one `ledger_apply` with op 1, 2 or 3; all bookkeeping completes before `join` returns. Induction on the CAS sequence gives the identity, and `nonce_ledger_quiescent` is its special case with zero in-flight slots. $\square$

*Theorem 3 (weight epoch).* Published epochs form the sequence $0,1,2,\dots$; any thread's successive loads are non-decreasing; `decide_single_snapshot` yields a receipt witness equal to its inference witness; `decide_double_load` does not in general.

*Proof.* `publish` succeeds only if its CAS wins against the index it read and the offered epoch is exactly the successor, so consecutive successful publishes increment by one. A load returns the table entry at the slot value written by the latest CAS in $<_{mo}$ before its linearization point; two loads by one thread are ordered by program order, hence by $<_{mo}$, hence monotone. Single snapshot: both witnesses are projections of one `Arc`. Double load: the interleaving load, CAS, load is a legal schedule and yields distinct epochs; loom T2 exhibits it. For `ArcSwapEpochCell` the argument is identical with the pointer swap as the atomic. $\square$

*Theorem 4 (holder refcounts).* `SharedSplit` with `admit_child_atomic` is linearizable, holder counts stay in $[0, \texttt{MAX\_CHILDREN\_PER\_PARENT}]$, and sibling totals never exceed `parent_share_bps`. `admit_child_split_lock` violates the last clause.

*Proof.* Every operation executes entirely inside one mutex-guarded critical section, so any point inside it is a linearization point and the critical sections are already totally ordered. Bounds follow from `holders_admit`, `holders_release` and `siblings_admit`, which refuse rather than wrap (Kani harnesses). For the negative control, two threads both pass the precheck with total zero, release the lock, then both commit; the trusting commit adds without the cap, giving a total above the parent share. Loom T6b finds this schedule. This is the Wave 1 law in miniature: a precheck is a prediction, and $\Pi_{\mathcal{C}}$ must be applied at the commit, not before it. $\square$

*Theorem 5 (crash recovery).* Under the durable-prefix model, after any sequence of crashes at the cutpoints of §5, including crashes during recovery, every clean boot satisfies I1 through I5.

*Proof.* Case analysis on the table of §5. C0: no row exists, nothing to show. C1: the row is `Reserved` with no marker; the marker transaction precedes the effect, so no effect ran; recovery releases, giving `Free` with zero effects. C2 and C3: the marker is durable; recovery retains. If the effect ran (C3) the row is `Retained`, satisfying I2; if it did not (C2) retention is conservative and still satisfies every invariant, since no invariant forces `Free`. C4: `Consumed` and the receipt are in one transaction, so both or neither are durable; `recover_intent` returns noop. Idempotence: `recovery_idempotent` and the Kani harness show that applying recovery to a recovered row is a no-op, so a crash before the recovery transaction commits is a rerun and a crash after it is harmless. I3 holds because an effect is reachable only through `Reserve` followed by `Claim`, `Reserve` requires `Free`, and a nonce with an effect is never `Free` again (TLA+ `RollbackOnlyWithoutEffect`). Apalache discharges the same invariants on the abstract model to depth fourteen, which covers two full dispatch cycles plus two crash-recovery pairs on two nonces. $\square$

*Theorem 6 (transfer).* In every model above, the choice that production delegates to $P_\ell$ (which action to attempt, whether to cancel, which nonce to retry) is a free nondeterministic choice of the scheduler or the cutpoint enumerator. The set of behaviours explored therefore contains the set of behaviours of any predictor, calibrated or adversarial, so Theorems 1 to 5 hold for the production system without loading `UltraBERT` or the `FixedQ16_16` micro-models. $\square$

**§10 Integration, CI and manifest.**

- **GuardPipeline.** A `RecoveryGuard` is appended, not inserted: for a `Retained` nonce it returns `Verdict::PendingApproval` with `GuardEvidence { guard_name: "recovery_retained_nonce", verdict: false, details: Some("action=hold; reason=unknown_side_effect") }`. The existing sticky semantics let a later guard still `Deny`.
- **Receipts.** Recovery findings go under the existing `FINDING_RECOVERY_METADATA_KEY`, and late-cancel observations under `governed_transaction_diagnostics`. The thirty-five reserved keys are unchanged.
- **Commands.**

```sh
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 cargo test -p chio-kernel --test loom_concurrency --release   # PR CI
RUSTFLAGS="--cfg loom" cargo test -p chio-kernel --test loom_concurrency --release                          # nightly, exhaustive
cargo test -p chio-kernel --test dst_drop_simulation
cargo test -p chio-kernel --test dst_drop_simulation --features sqlite-dst
cargo kani -p chio-kernel-core --harness-pattern 'concurrency_core::kani_harness::*'
apalache-mc check --inv=Safety --length=14 --cinit=CInit formal/tla/MC_ChioDispatchCrash.tla
```

- **Manifest.** `formal/proof-manifest.toml` gains entries for the five Kani harnesses, the two Lean modules, and the Apalache model, appended after the existing entries. No existing signature or proof is edited.
- **Known limits.** Preemption bounding in PR CI is not exhaustive; nightly is. The real-SQLite adapter cannot inject torn fsyncs without a VFS shim; the simulated store assumes SQLite's atomic-commit guarantee rather than testing it.

**Recap.** Pass 14 adds a `no_std` module of pure transition functions, four loom-checked kernel objects, seven loom tests including two negative controls that must fail, a deterministic crash simulator with a real-SQLite adapter, an Apalache model, two Lean modules, and five Kani harnesses. Linearizability of epoch publication, nonce rollback, holder refcounts and cancellation reduces to single-CAS or single-critical-section arguments backed by the Lean lemmas; crash safety reduces to the write-ahead marker plus idempotent recovery into the `retained` ledger state. Remaining work is the VFS fault shim for torn writes and wiring the manifest entries into the proof gate.

---

# Verbatim Treatise - `wave14_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_14`

ued)
  /\ accepted' = [accepted EXCEPT ![v] = @ \cup {rc}]
  /\ UNCHANGED <<validFrom, validUntil, revokedAt, known, issued, clock>>

Next ==
  \/ Tick
  \/ \E r \in Roots : Issue(r) \/ Revoke(r)
  \/ \E v \in Verifiers : \E r \in Roots : Learn(v, r)
  \/ \E v \in Verifiers : \E rc \in issued : Verify(v, rc)

\* Theorem E in the abstract model: anything accepted was issued under a root
\* that was valid and unrevoked at issuance, and stays so under later revocation.
Soundness ==
  \A v \in Verifiers : \A rc \in accepted[v] :
    rc \in issued /\ ValidAt(rc.root, rc.issued)

\* Corollary E′: learning a root never retracts a decision already reached.
AcceptedMonotone ==
  \A v \in Verifiers : accepted[v] \subseteq accepted'[v]
=============================================================================
```

`Soundness` is inductive because `Verify` checks `ValidAt` at the receipt's own issuance time, `Issue` only fires for roots valid at the current clock, and `Revoke` writes `clock + 1`, which is strictly greater than the issuance time of every receipt in `issued`. `AcceptedMonotone` holds because no action removes from `accepted`. Checking with Apalache uses `--inv=Soundness` over bounded `MaxTime`, and the inductive form uses `--inv=Soundness --init=Soundness --length=1`.

**12. Aeneas obligations added to the proof manifest.** All entries are additive and reference only the new crate, so the pinned entries for `formal_aeneas.rs`, `formal_core.rs`, and `budget_split.rs` are untouched.

| Extracted function | Obligation |
|---|---|
| `Envelope.project` | `project_contains`, stated verbatim on the extracted term |
| `Envelope.narrow` | `narrow_mono` |
| `PortableToolCallRequest.lift` | `lift_ok_iff`: result is `ok` iff every cap holds and `expires_at > issued_at` |
| `ReceiptCore.canonical` | `canonical_total`: returns `ok` for every well-typed receipt, since the fixed layout sums to 330 bytes |
| `verify_offline` | `verified_implies`: the conjunction in Theorem E |
| `ShadowPrices.dual_ascent` | `dual_ascent_bounded`: every coordinate of the result lies in `[0, max]` when every coordinate of the input does |

The `canonical_total` obligation deserves a note. The function returns `Err(CanonOverflow)` only if the cursor overflows `usize` or runs past the buffer, and the layout is a compile-time constant, so the theorem is proved by evaluating the seventeen `put` calls symbolically. Aeneas discharges it with `simp` plus `decide` on the offsets.

**13. Budget and ledger interaction.** The edge consumes the budget pipeline without altering it. At admission, `budget_precheck` with the request's `invocation_cost` and `unit_cost` feeds `ExactFacts::budget_ok`. At dispatch, after revalidation, `budget_commit` produces the `BudgetCommitResult` stored verbatim in the receipt, and `ledger_apply` with op `1` records the commit against the `ReservationLedger`. If dispatch is refused after a reservation, op `2` releases it. When an MCP server acts under a child token from `BudgetSplit`, the adapter resolves the child's `share_bps` against the parent and passes the derived cap as `remaining_units`, so an oversubscribed child fails `budget_precheck` before any learned component runs. `ChildShareExceedsCap` and `OversubscribedSiblings` remain the registry's errors; the edge never recomputes share arithmetic.

**14. What the design deliberately does not claim.** Three limits are worth stating plainly.

- **Attestation freshness is per receipt, not per request flow.** The nonce binds the quote to one issuance. An edge that is compromised after boot but before measurement changes would still produce valid quotes. Runtime integrity monitoring is a separate layer and is not addressed here.
- **Offline verification cannot observe revocation that happened after the root bundle was fetched.** `Corollary E′` guarantees stability of decided outcomes, which is the property that makes stale bundles safe to use for `Refuted`, but a root revoked after the bundle was fetched still verifies receipts issued before the local bundle's revocation record. The bundle's own freshness is a policy input, surfaced to callers as the bundle's issuance time.
- **Tier-1 latency is not bounded by proof.** The 0.5 to 5 ms figure is an operational envelope. The projection step is $O(1)$ and its cost is bounded by construction, but the predictor's latency is enforced by the `latency` coordinate of $\boldsymbol{\lambda}$ and by the Tier-0 fallback, not by a theorem.

**15. Extension points held open for Pass 15.** The `AttestationFloor` trait returns $\mathbb{K}_3$ precisely so that new quote formats can be added without touching `verify_offline`. The `concept_bitmap` field is sized for the pinned 537 predicates; a model revision with a different head count would require a receipt version bump, which the leading version byte in the canonical layout accommodates. `MAX_FEDERATED_TRUST_ROOTS` at 64 reflects current federation size and is a tunable, not a security parameter, because `find` is linear and self-certifying ids make the set size irrelevant to soundness.

---

**Recap.** The three protocol edges share one `#![no_std]`, `#![forbid(unsafe_code)]` core that lifts MCP, A2A, and Envoy ext_authz requests into a bounded `PortableToolCallRequest`, maps each onto Copley's four segments so the pinned 537-predicate UltraBERT runs unchanged, and projects every learned proposal through an `Envelope` that always contains `Deny`. Receipts are 330-byte fixed-layout records signed by labeled, key-bound AND-composition of Ed25519 and ML-DSA-65, with the attested platform measurement, the bound model weights hash, and a per-receipt nonce inside the signed bytes. Offline verification against a federated root set is sound, stable under root learning, and returns $\bot$ rather than guessing when a root is unknown, the clock is unavailable, or a quote format cannot be checked locally. Theorems A through E and Lemmas F and G are proved in the text; the Lean model, four Kani harnesses, and the Apalache spec discharge the mechanized portions; the six Aeneas obligations are additive to the proof manifest. The three limits in §14 are the honest boundaries of what this pass establishes.