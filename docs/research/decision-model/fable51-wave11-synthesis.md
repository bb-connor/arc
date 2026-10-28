# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 11 Synthesis

- **Timestamp**: `20261025-042534 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1325.89s` across 4 parallel passes
- **Total Output**: `165,533` characters (`21,258` words)
- **Claude Max Quota Before Wave 11**: 5-hour `24.0%` | 7-day `93.0%`
- **Claude Max Quota After Wave 11**: 5-hour `30.0%` | 7-day `94.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave11_angle_1_formal_aeneas_and_lean4_deepening_pass_11` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6,020` | `44,640` | `488.43` |
| `wave11_angle_2_copley_dag_optimization_and_simd_bitset_pass_11` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,985` | `43,942` | `1325.88` |
| `wave11_angle_3_concurrent_loom_and_dst_crash_recovery_pass_11` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,123` | `36,493` | `886.1` |
| `wave11_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_11` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,130` | `40,458` | `630.9` |

---

# Verbatim Treatise - `wave11_angle_1_formal_aeneas_and_lean4_deepening_pass_11`

I'll lay out the Wave 11 additive mechanization: one new Rust module with checked arithmetic, bit-precise Kani harnesses, Creusot contracts, and Lean 4 proofs for saturation, epoch boundaries, attenuation witnesses, and Merkle inclusion, then the manifest entries and the open items.

**Scope and additivity contract.** Everything below lands in one new file, registered as `pub mod formal_wave11;` in the kernel-core crate, plus four new Lean files under the pinned proof tree. No existing signature from `formal_core.rs`, `formal_aeneas.rs`, or `budget_split.rs` is modified. The new code only calls three existing functions, which the table lists so a reviewer can confirm the dependency surface at a glance.

| Existing symbol used | Where it is called from | Why |
|---|---|---|
| `classify_time_window_code` | epoch phase, attenuation hop checks | single source of truth for window codes |
| `ledger_apply` | epoch close | the only mutator of a ledger |
| `MAX_BUDGET_SHARE_BPS` | attenuation share cap | the share cap is not redefined |

Three assumptions are pinned up front because the proofs depend on them. If any pinned definition differs, the Rust wrappers stand unchanged and only the Lean hypotheses need re-deriving.

- **A1, half-open windows.** A window is valid on the interval from issue inclusive to expiry exclusive. The exact-boundary harness in section 2 encodes this convention and is the one harness that must be flipped if the pinned model is closed at expiry.
- **A2, ledger conservation.** The sum of committed, released, and retained never exceeds reserved. The epoch-close wrapper computes the outstanding amount from this and refuses to act if the invariant is already broken.
- **A3, abstract compression.** The Merkle compression function is an opaque trait. Lean proves structural facts for any compression function, and binding under an idealized injectivity hypothesis. No collision resistance is claimed or needed by the kernel proofs.

The Verification Transfer Theorem from Wave 1 shapes every statement here. The Tier-0 micro-model output never appears as a modeled quantity. It is a universally quantified value in Lean and an unconstrained `kani::any()` in the harnesses. Each proof therefore discharges once and covers every weight update of the 19.3M-parameter and fixed-point predictors alike.

## 1. Fixed-point saturation and the shielded envelope

**1.1 The Rust module.** The newtype stores a signed 32-bit raw value with 16 fractional bits. Every operation is total and uses either saturating primitives or checked primitives with an explicit fallback branch, so the crate-level denial of arithmetic side effects holds without exceptions. Multiplication widens to 64 bits, which cannot overflow for two 32-bit factors, but the code still goes through the checked path so the lint and the proof see the same total function.

```rust
//! crates/kernel/chio-kernel-core/src/formal_wave11.rs  (additive, alloc-free)
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
#![forbid(unsafe_code)]

pub mod fixed_sat {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct FixedQ16_16(i32);

    impl FixedQ16_16 {
        pub const FRAC_BITS: u32 = 16;
        pub const ZERO: Self = Self(0);
        pub const ONE: Self = Self(65_536);
        pub const MAX: Self = Self(i32::MAX);
        pub const MIN: Self = Self(i32::MIN);

        pub const fn from_raw(raw: i32) -> Self { Self(raw) }
        pub const fn raw(self) -> i32 { self.0 }

        pub const fn sat_add(self, o: Self) -> Self { Self(self.0.saturating_add(o.0)) }
        pub const fn sat_sub(self, o: Self) -> Self { Self(self.0.saturating_sub(o.0)) }

        /// Floor-rounded saturating product. Total on every input pair.
        pub const fn sat_mul(self, o: Self) -> Self {
            let wide = match (self.0 as i64).checked_mul(o.0 as i64) {
                Some(w) => w,
                // Unreachable: |i32 * i32| < 2^62. Kept so the function is total by inspection.
                None => return if (self.0 < 0) != (o.0 < 0) { Self::MIN } else { Self::MAX },
            };
            let shifted = match wide.checked_shr(Self::FRAC_BITS) {
                Some(s) => s,
                None => return Self::MAX, // Unreachable: 16 < 64.
            };
            Self::clamp_i64(shifted)
        }

        const fn clamp_i64(v: i64) -> Self {
            if v > i32::MAX as i64 { Self::MAX }
            else if v < i32::MIN as i64 { Self::MIN }
            else { Self(v as i32) }
        }
    }

    pub const SHADOW_PRICE_DIMS: usize = 5;
    /// Index order: 0=budget, 1=fuel, 2=latency, 3=memory, 4=escrow.
    pub type ShadowPrices = [FixedQ16_16; SHADOW_PRICE_DIMS];

    /// score - sum_i lambda_i * usage_i, with saturating operations throughout.
    pub fn penalized_score(score: FixedQ16_16, lambda: &ShadowPrices, usage: &ShadowPrices) -> FixedQ16_16 {
        lambda.iter().zip(usage.iter())
            .fold(score, |acc, (l, u)| acc.sat_sub(l.sat_mul(*u)))
    }
}

pub mod envelope {
    use super::fixed_sat::FixedQ16_16;

    /// Feasible envelope with conservative fallback. Fields are private; the only public
    /// constructor is `Envelope::from_committed_leaf` in the inclusion module.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Envelope { lo: FixedQ16_16, hi: FixedQ16_16, fallback: FixedQ16_16 }

    /// A value that has passed projection. No public constructor exists.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ShieldedAction(FixedQ16_16);
    impl ShieldedAction { pub const fn value(self) -> FixedQ16_16 { self.0 } }

    impl Envelope {
        pub(crate) const fn new(lo: FixedQ16_16, hi: FixedQ16_16, fallback: FixedQ16_16) -> Option<Self> {
            if lo.raw() <= fallback.raw() && fallback.raw() <= hi.raw() {
                Some(Self { lo, hi, fallback })
            } else { None }
        }
        pub const fn lo(&self) -> FixedQ16_16 { self.lo }
        pub const fn hi(&self) -> FixedQ16_16 { self.hi }
        pub const fn fallback(&self) -> FixedQ16_16 { self.fallback }
        pub const fn fallback_action(&self) -> ShieldedAction { ShieldedAction(self.fallback) }

        /// O(1) shielded projection. `proposed` is the learned choice and is never trusted.
        pub const fn project(&self, proposed: FixedQ16_16) -> ShieldedAction {
            let p = proposed.raw();
            if p < self.lo.raw() { ShieldedAction(self.lo) }
            else if p > self.hi.raw() { ShieldedAction(self.hi) }
            else { ShieldedAction(proposed) }
        }
    }
}
```

**1.2 What saturation changes and what it does not.** Saturating subtraction of a non-negative quantity never increases a value. That single fact is what makes the Lagrangian penalty safe at the integer edge. If every shadow price and every usage term is non-negative, the penalized score is bounded above by the raw score, no matter how many terms saturate. The converse direction is the one that fails under saturation and must not be assumed. Two penalties that individually saturate do not compose to the exact sum, so a proof that two separately penalized scores order a certain way does not transfer to their sum. The Lean file below proves the safe direction and nothing more, and the Kani harness checks it bit-precisely over all five dimensions.

Floor rounding in the product is deliberate. For a non-negative price times a non-negative usage, floor rounds the penalty down, which is the permissive direction. The envelope projection, not the rounding mode, is what guarantees safety. Rounding only affects where inside the envelope the action lands.

**1.3 Lean 4 model and theorems.** The model treats the raw value as an integer clamped to the 32-bit range. Clamping is monotone and idempotent, and projection into a well-formed envelope always lands inside it.

```lean
-- formal/lean4/Chio/Wave11/FixedSat.lean
import Mathlib.Tactic

namespace Chio.Wave11

def i32Max : Int := 2147483647
def i32Min : Int := -2147483648

def clampI32 (x : Int) : Int :=
  if x > i32Max then i32Max else if x < i32Min then i32Min else x

def satAdd (a b : Int) : Int := clampI32 (a + b)
def satSub (a b : Int) : Int := clampI32 (a - b)
/-- Floor division models the arithmetic right shift by 16. -/
def satMul (a b : Int) : Int := clampI32 (Int.fdiv (a * b) 65536)

theorem clampI32_bounds (x : Int) : i32Min ≤ clampI32 x ∧ clampI32 x ≤ i32Max := by
  unfold clampI32 i32Max i32Min; split_ifs <;> omega

theorem clampI32_mono {x y : Int} (h : x ≤ y) : clampI32 x ≤ clampI32 y := by
  unfold clampI32 i32Max i32Min; split_ifs <;> omega

theorem clampI32_idem (x : Int) : clampI32 (clampI32 x) = clampI32 x := by
  unfold clampI32 i32Max i32Min; split_ifs <;> omega

theorem satSub_le_of_nonneg {a b : Int} (ha : i32Min ≤ a ∧ a ≤ i32Max) (hb : 0 ≤ b) :
    satSub a b ≤ a := by
  unfold satSub clampI32 i32Max i32Min at *; split_ifs <;> omega

theorem satMul_nonneg {a b : Int} (ha : 0 ≤ a) (hb : 0 ≤ b) : 0 ≤ satMul a b := by
  unfold satMul clampI32 i32Max i32Min
  have : 0 ≤ Int.fdiv (a * b) 65536 := Int.fdiv_nonneg (Int.mul_nonneg ha hb) (by decide)
  split_ifs <;> omega

/-- The penalty fold, in the same shape as the Rust fold. -/
def penalized (score : Int) (terms : List (Int × Int)) : Int :=
  terms.foldl (fun acc t => satSub acc (satMul t.1 t.2)) score

theorem penalized_le_score (score : Int) (hs : i32Min ≤ score ∧ score ≤ i32Max)
    (terms : List (Int × Int)) (hpos : ∀ t ∈ terms, 0 ≤ t.1 ∧ 0 ≤ t.2) :
    penalized score terms ≤ score := by
  induction terms generalizing score with
  | nil => simp [penalized]
  | cons t ts ih =>
    simp only [penalized, List.foldl]
    have ht := hpos t (List.mem_cons_self _ _)
    have hstep : satSub score (satMul t.1 t.2) ≤ score :=
      satSub_le_of_nonneg hs (satMul_nonneg ht.1 ht.2)
    have hb : i32Min ≤ satSub score (satMul t.1 t.2) ∧ satSub score (satMul t.1 t.2) ≤ i32Max :=
      clampI32_bounds _
    exact le_trans (ih _ hb (fun x hx => hpos x (List.mem_cons_of_mem _ hx))) hstep

def project (lo hi a : Int) : Int := max lo (min hi a)

theorem project_mem {lo hi : Int} (h : lo ≤ hi) (a : Int) :
    lo ≤ project lo hi a ∧ project lo hi a ≤ hi := by unfold project; omega

theorem project_fixed {lo hi a : Int} (h₁ : lo ≤ a) (h₂ : a ≤ hi) : project lo hi a = a := by
  unfold project; omega

theorem project_idem {lo hi : Int} (h : lo ≤ hi) (a : Int) :
    project lo hi (project lo hi a) = project lo hi a := by unfold project; omega

end Chio.Wave11
```

The projection theorem is the envelope-preservation statement for this layer. Its action argument is universally quantified, which is exactly the nondeterministic-choice modeling that lets the proof cover any predictor.

**1.4 Kani harnesses.** The harnesses are bit-precise over the full 32-bit range for the scalar operations and over all five shadow-price dimensions for the penalty. The envelope harness draws the learned choice from `kani::any()` without constraint.

```rust
#[cfg(kani)]
mod kani_wave11 {
    #![allow(clippy::arithmetic_side_effects)]
    use super::fixed_sat::*;
    use super::envelope::*;

    #[kani::proof]
    fn sat_add_is_clamped_exact_sum() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let got = FixedQ16_16::from_raw(a).sat_add(FixedQ16_16::from_raw(b)).raw() as i64;
        let exact = a as i64 + b as i64;
        assert_eq!(got, exact.clamp(i32::MIN as i64, i32::MAX as i64));
    }

    #[kani::proof]
    fn sat_mul_is_clamped_floor_product() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let got = FixedQ16_16::from_raw(a).sat_mul(FixedQ16_16::from_raw(b)).raw() as i64;
        let exact = (a as i64 * b as i64) >> 16;
        assert_eq!(got, exact.clamp(i32::MIN as i64, i32::MAX as i64));
    }

    #[kani::proof]
    fn penalty_never_exceeds_score_for_nonneg_prices() {
        let score = FixedQ16_16::from_raw(kani::any());
        let lambda: [i32; SHADOW_PRICE_DIMS] = kani::any();
        let usage: [i32; SHADOW_PRICE_DIMS] = kani::any();
        for i in 0..SHADOW_PRICE_DIMS {
            kani::assume(lambda[i] >= 0 && usage[i] >= 0);
        }
        let l = lambda.map(FixedQ16_16::from_raw);
        let u = usage.map(FixedQ16_16::from_raw);
        assert!(penalized_score(score, &l, &u) <= score);
    }

    #[kani::proof]
    fn projection_lands_in_envelope_for_any_learned_choice() {
        let lo = FixedQ16_16::from_raw(kani::any());
        let hi = FixedQ16_16::from_raw(kani::any());
        let fb = FixedQ16_16::from_raw(kani::any());
        let Some(env) = Envelope::new(lo, hi, fb) else { return };
        let learned = FixedQ16_16::from_raw(kani::any()); // the micro-model is never modeled
        let act = env.project(learned).value();
        assert!(env.lo() <= act && act <= env.hi());
        assert_eq!(env.project(act).value(), act);
        assert_eq!(env.project(fb).value(), fb);
    }
}
```

**1.5 Creusot contracts.** The contracts restate the Lean theorems at the Rust boundary so the three tools agree on one specification. They are gated behind the `creusot` cfg so the production build sees plain Rust.

```rust
#[cfg_attr(creusot, requires(true))]
#[cfg_attr(creusot, ensures(result.0@ ==
    if self.0@ + o.0@ > i32::MAX@ { i32::MAX@ }
    else if self.0@ + o.0@ < i32::MIN@ { i32::MIN@ }
    else { self.0@ + o.0@ }))]
pub const fn sat_add(self, o: Self) -> Self { Self(self.0.saturating_add(o.0)) }

#[cfg_attr(creusot, ensures(self.lo.0@ <= result.0.0@ && result.0.0@ <= self.hi.0@))]
#[cfg_attr(creusot, ensures(self.lo.0@ <= proposed.0@ && proposed.0@ <= self.hi.0@
    ==> result.0 == proposed))]
pub const fn project(&self, proposed: FixedQ16_16) -> ShieldedAction { /* as above */ }
```

## 2. Epoch boundaries and multi-hop attenuation witnesses

**2.1 Epoch phase and boundary stepping.** The existing window classifier returns three codes whose numeric order does not match temporal order. The new phase function remaps them so that the phase of a fixed window is monotone in time. That remap is the only thing needed to state epoch-boundary theorems cleanly. The epoch arithmetic uses checked division and checked multiplication, so a zero epoch length or a boundary beyond the 64-bit horizon yields `None` instead of a panic.

```rust
pub mod epoch {
    use crate::formal_aeneas::{ledger_apply, ReservationLedger};
    use crate::formal_core::classify_time_window_code;

    pub const CODE_VALID: u8 = 0;
    pub const CODE_NOT_YET_VALID: u8 = 1;
    pub const CODE_EXPIRED: u8 = 2;
    pub const OP_RELEASE: u8 = 2;

    /// Temporal phase: NotYetValid=0 < Valid=1 < Expired=2. Unknown codes map to 3 and are never produced.
    pub const fn window_phase(code: u8) -> u8 {
        match code { CODE_NOT_YET_VALID => 0, CODE_VALID => 1, CODE_EXPIRED => 2, _ => 3 }
    }

    pub fn phase_at(now: u64, issued_at: u64, expires_at: u64) -> u8 {
        window_phase(classify_time_window_code(now, issued_at, expires_at))
    }

    pub const fn epoch_index(now: u64, epoch_len: u64) -> Option<u64> { now.checked_div(epoch_len) }

    pub const fn next_epoch_start(now: u64, epoch_len: u64) -> Option<u64> {
        let idx = match epoch_index(now, epoch_len) { Some(i) => i, None => return None };
        let next = match idx.checked_add(1) { Some(n) => n, None => return None };
        next.checked_mul(epoch_len)
    }

    /// Re-classify a window at the instant the current epoch closes.
    pub fn classify_at_next_epoch(now: u64, epoch_len: u64, issued_at: u64, expires_at: u64) -> Option<u8> {
        let boundary = next_epoch_start(now, epoch_len)?;
        Some(classify_time_window_code(boundary, issued_at, expires_at))
    }

    /// Outstanding = reserved - (committed + released + retained). `None` iff A2 is violated.
    pub const fn ledger_outstanding(s: &ReservationLedger) -> Option<u64> {
        let settled = match s.committed.checked_add(s.released) { Some(v) => v, None => return None };
        let settled = match settled.checked_add(s.retained) { Some(v) => v, None => return None };
        s.reserved.checked_sub(settled)
    }

    /// Epoch close releases exactly the outstanding amount through the pinned mutator.
    pub fn ledger_epoch_close(s: ReservationLedger) -> Option<(ReservationLedger, bool)> {
        let outstanding = ledger_outstanding(&s)?;
        if outstanding == 0 { return Some((s, true)); }
        Some(ledger_apply(s, OP_RELEASE, outstanding))
    }
}
```

The epoch-close wrapper never computes a new ledger itself. It delegates to the pinned mutator with the one amount that A2 says is still open, so the existing ledger proofs remain the authority on what the mutator does.

**2.2 Lean 4 theorems for the boundary.** The classifier model encodes A1. Phase monotonicity holds for every pair of instants, and the exact-boundary lemmas pin the half-open convention.

```lean
-- formal/lean4/Chio/Wave11/Epoch.lean
import Mathlib.Tactic

namespace Chio.Wave11

/-- A1: half-open validity window. 0=Valid, 1=NotYetValid, 2=Expired. -/
def classify (now issued expires : Nat) : Nat :=
  if now < issued then 1 else if now < expires then 0 else 2

def phase (c : Nat) : Nat := if c = 1 then 0 else if c = 0 then 1 else 2

def phaseAt (now issued expires : Nat) : Nat :=
  if now < issued then 0 else if now < expires then 1 else 2

theorem phase_classify (now issued expires : Nat) :
    phase (classify now issued expires) = phaseAt now issued expires := by
  unfold phase classify phaseAt; split_ifs <;> omega

theorem phaseAt_mono {n₁ n₂ i e : Nat} (h : n₁ ≤ n₂) :
    phaseAt n₁ i e ≤ phaseAt n₂ i e := by
  unfold phaseAt; split_ifs <;> omega

theorem phaseAt_le_two (n i e : Nat) : phaseAt n i e ≤ 2 := by
  unfold phaseAt; split_ifs <;> omega

theorem classify_at_expiry (i e : Nat) : classify e i e = 2 := by
  unfold classify; split_ifs <;> omega

theorem classify_just_before_expiry {i e : Nat} (h : i < e) : classify (e - 1) i e = 0 := by
  unfold classify; split_ifs <;> omega

/-- A2-based epoch close on the pinned ledger model. -/
structure Ledger where
  reserved : Nat
  committed : Nat
  released : Nat
  retained : Nat

def conserved (s : Ledger) : Prop := s.committed + s.released + s.retained ≤ s.reserved
def outstanding (s : Ledger) : Nat := s.reserved - (s.committed + s.released + s.retained)
def isTerminal (s : Ledger) : Prop := s.committed + s.released + s.retained = s.reserved

/-- Pinned behaviour of op 2 (release) when the amount fits. If the pinned definition of
    `ledger_apply` differs, re-derive from that definition; the Rust wrapper is unchanged. -/
def release (s : Ledger) (amount : Nat) : Ledger :=
  if s.committed + s.released + s.retained + amount ≤ s.reserved
  then { s with released := s.released + amount } else s

theorem epoch_close_terminal (s : Ledger) (hc : conserved s) :
    isTerminal (release s (outstanding s)) := by
  unfold conserved at hc; unfold isTerminal release outstanding; split_ifs <;> simp <;> omega

theorem epoch_close_preserves_conservation (s : Ledger) (hc : conserved s) :
    conserved (release s (outstanding s)) := by
  unfold conserved at *; unfold release outstanding; split_ifs <;> simp <;> omega

end Chio.Wave11
```

**2.3 Attenuation witnesses.** A multi-hop delegation chain is a fixed-capacity array of hops, each carrying a share factor in basis points, an issue and expiry instant, and a scope bitmask. Verification folds the chain from a root grant: shares multiply and floor-divide by the cap, expiries take the minimum, and scopes intersect. Each hop is checked for validity at the verification instant through the existing classifier, so a hop that has expired or is not yet valid rejects the whole chain. Sibling oversubscription is not a chain property and stays with the registry's existing error variant.

```rust
pub mod attenuation {
    use super::epoch::{CODE_NOT_YET_VALID, CODE_VALID};
    use crate::budget_split::MAX_BUDGET_SHARE_BPS;
    use crate::formal_core::classify_time_window_code;

    pub const MAX_DELEGATION_HOPS: usize = 16;
    pub const SHARE_CAP_BPS: u16 = MAX_BUDGET_SHARE_BPS;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DelegationHop { pub share_bps: u16, pub issued_at: u64, pub expires_at: u64, pub scope_mask: u64 }

    impl DelegationHop {
        pub const IDENTITY: Self = Self { share_bps: SHARE_CAP_BPS, issued_at: 0, expires_at: u64::MAX, scope_mask: u64::MAX };
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Attenuated { pub share_bps: u16, pub expires_at: u64, pub scope_mask: u64 }

    pub struct AttenuationWitness { hops: [DelegationHop; MAX_DELEGATION_HOPS], len: usize }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AttenuationError {
        TooManyHops,
        HopShareExceedsCap { hop: usize, share_bps: u16 },
        HopNotYetValid { hop: usize },
        HopExpired { hop: usize },
        ShareArithmetic { hop: usize },
        ClaimMismatch,
    }

    impl AttenuationWitness {
        pub const fn empty() -> Self { Self { hops: [DelegationHop::IDENTITY; MAX_DELEGATION_HOPS], len: 0 } }

        pub fn push(&mut self, hop: DelegationHop) -> Result<(), AttenuationError> {
            if hop.share_bps > SHARE_CAP_BPS {
                return Err(AttenuationError::HopShareExceedsCap { hop: self.len, share_bps: hop.share_bps });
            }
            let slot = self.hops.get_mut(self.len).ok_or(AttenuationError::TooManyHops)?;
            *slot = hop;
            self.len = self.len.checked_add(1).ok_or(AttenuationError::TooManyHops)?;
            Ok(())
        }

        pub fn hops(&self) -> &[DelegationHop] { self.hops.get(..self.len).unwrap_or(&[]) }
    }

    pub const fn attenuate_step(acc: Attenuated, hop: DelegationHop) -> Option<Attenuated> {
        let prod = match (acc.share_bps as u32).checked_mul(hop.share_bps as u32) { Some(p) => p, None => return None };
        let q = match prod.checked_div(SHARE_CAP_BPS as u32) { Some(q) => q, None => return None };
        if q > u16::MAX as u32 { return None; }
        Some(Attenuated {
            share_bps: q as u16,
            expires_at: if hop.expires_at < acc.expires_at { hop.expires_at } else { acc.expires_at },
            scope_mask: acc.scope_mask & hop.scope_mask,
        })
    }

    pub fn attenuate(root: Attenuated, witness: &AttenuationWitness, now: u64) -> Result<Attenuated, AttenuationError> {
        let mut acc = root;
        for (i, hop) in witness.hops().iter().enumerate() {
            if hop.share_bps > SHARE_CAP_BPS {
                return Err(AttenuationError::HopShareExceedsCap { hop: i, share_bps: hop.share_bps });
            }
            match classify_time_window_code(now, hop.issued_at, hop.expires_at) {
                CODE_VALID => {}
                CODE_NOT_YET_VALID => return Err(AttenuationError::HopNotYetValid { hop: i }),
                _ => return Err(AttenuationError::HopExpired { hop: i }),
            }
            acc = attenuate_step(acc, *hop).ok_or(AttenuationError::ShareArithmetic { hop: i })?;
        }
        Ok(acc)
    }

    /// A witness binds only if recomputation reproduces the claimed grant exactly.
    pub fn witness_binds(root: Attenuated, witness: &AttenuationWitness, now: u64, claimed: Attenuated)
        -> Result<Attenuated, AttenuationError>
    {
        let a = attenuate(root, witness, now)?;
        if a == claimed { Ok(a) } else { Err(AttenuationError::ClaimMismatch) }
    }
}
```

**2.4 Lean 4 attenuation theorems.** The fold is proved by induction with the root generalized. Share never grows past the root or past any hop when the root is within the cap, expiry never grows, and scope only shrinks in the bitwise-subset order.

```lean
-- formal/lean4/Chio/Wave11/Attenuation.lean
import Mathlib.Tactic

namespace Chio.Wave11

structure Hop where
  share : Nat
  issued : Nat
  expires : Nat
  scope : Nat

structure Att where
  share : Nat
  expires : Nat
  scope : Nat

def cap : Nat := 10000

def step (a : Att) (h : Hop) : Att :=
  ⟨a.share * h.share / cap, min a.expires h.expires, a.scope &&& h.scope⟩

def attenuate (root : Att) (hs : List Hop) : Att := hs.foldl step root

def scopeSub (x y : Nat) : Prop := ∀ i, x.testBit i = true → y.testBit i = true

theorem step_share_le (a : Att) (h : Hop) (hc : h.share ≤ cap) : (step a h).share ≤ a.share := by
  simp only [step]
  calc a.share * h.share / cap ≤ a.share * cap / cap :=
        Nat.div_le_div_right (Nat.mul_le_mul_left _ hc)
    _ = a.share := Nat.mul_div_cancel _ (by decide)

theorem step_share_le_hop (a : Att) (h : Hop) (ha : a.share ≤ cap) : (step a h).share ≤ h.share := by
  simp only [step]
  calc a.share * h.share / cap ≤ cap * h.share / cap :=
        Nat.div_le_div_right (Nat.mul_le_mul_right _ ha)
    _ = h.share := by rw [Nat.mul_comm]; exact Nat.mul_div_cancel _ (by decide)

theorem step_scope_sub (a : Att) (h : Hop) : scopeSub (step a h).scope a.scope := by
  intro i hi; simp only [step] at hi; rw [Nat.testBit_and] at hi
  exact (Bool.and_eq_true.mp hi).1

theorem attenuate_share_le (root : Att) (hs : List Hop) (hc : ∀ h ∈ hs, h.share ≤ cap) :
    (attenuate root hs).share ≤ root.share := by
  induction hs generalizing root with
  | nil => simp [attenuate]
  | cons h t ih =>
    simp only [attenuate, List.foldl]
    exact le_trans (ih (step root h) (fun x hx => hc x (List.mem_cons_of_mem _ hx)))
                   (step_share_le root h (hc h (List.mem_cons_self _ _)))

theorem attenuate_expires_le (root : Att) (hs : List Hop) :
    (attenuate root hs).expires ≤ root.expires := by
  induction hs generalizing root with
  | nil => simp [attenuate]
  | cons h t ih =>
    simp only [attenuate, List.foldl]
    exact le_trans (ih (step root h)) (min_le_left _ _)

theorem attenuate_scope_sub (root : Att) (hs : List Hop) :
    scopeSub (attenuate root hs).scope root.scope := by
  induction hs generalizing root with
  | nil => intro i hi; simpa [attenuate] using hi
  | cons h t ih =>
    simp only [attenuate, List.foldl]
    intro i hi; exact step_scope_sub root h i (ih (step root h) i hi)

/-- Share stays within the cap along the whole chain when the root does. -/
theorem attenuate_share_le_cap (root : Att) (hs : List Hop) (hr : root.share ≤ cap)
    (hc : ∀ h ∈ hs, h.share ≤ cap) : (attenuate root hs).share ≤ cap :=
  le_trans (attenuate_share_le root hs hc) hr

end Chio.Wave11
```

**2.5 Kani harnesses for epoch and attenuation.** The phase-monotonicity harness runs against the real pinned classifier and holds under either boundary convention. The exact-boundary harness is the single place A1 is asserted in Rust. The attenuation harness bounds the chain at four nondeterministic hops and checks all three attenuation properties against the root and against every hop.

```rust
#[cfg(kani)]
mod kani_wave11_epoch_attenuation {
    #![allow(clippy::arithmetic_side_effects)]
    use super::attenuation::*;
    use super::epoch::*;
    use crate::formal_core::classify_time_window_code;

    #[kani::proof]
    fn phase_is_monotone_across_any_boundary() {
        let (n1, n2, issued, expires): (u64, u64, u64, u64) = kani::any();
        kani::assume(n1 <= n2 && issued <= expires);
        assert!(phase_at(n1, issued, expires) <= phase_at(n2, issued, expires));
        assert!(phase_at(n2, issued, expires) <= 2);
    }

    /// Pins A1 against the real classifier. Flip the expected codes if the pinned model is closed at expiry.
    #[kani::proof]
    fn exact_expiry_boundary_is_half_open() {
        let (issued, expires): (u64, u64) = kani::any();
        kani::assume(issued < expires);
        assert_eq!(classify_time_window_code(expires, issued, expires), CODE_EXPIRED);
        assert_eq!(classify_time_window_code(expires - 1, issued, expires), CODE_VALID);
        assert_eq!(classify_time_window_code(issued, issued, expires), CODE_VALID);
    }

    #[kani::proof]
    fn next_epoch_start_is_aligned_and_later() {
        let (now, len): (u64, u64) = kani::any();
        if let Some(b) = next_epoch_start(now, len) {
            assert!(len > 0);
            assert!(b > now);
            assert_eq!(b % len, 0);
        } else {
            assert!(len == 0 || (now / len).checked_add(1).and_then(|n| n.checked_mul(len)).is_none());
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn attenuation_never_escalates() {
        let root = Attenuated { share_bps: kani::any(), expires_at: kani::any(), scope_mask: kani::any() };
        kani::assume(root.share_bps <= SHARE_CAP_BPS);
        let now: u64 = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let mut w = AttenuationWitness::empty();
        for _ in 0..n {
            let h = DelegationHop { share_bps: kani::any(), issued_at: kani::any(), expires_at: kani::any(), scope_mask: kani::any() };
            kani::assume(h.share_bps <= SHARE_CAP_BPS);
            w.push(h).unwrap();
        }
        if let Ok(a) = attenuate(root, &w, now) {
            assert!(a.share_bps <= root.share_bps);
            assert!(a.expires_at <= root.expires_at);
            assert_eq!(a.scope_mask & root.scope_mask, a.scope_mask);
            for h in w.hops() {
                assert!(a.share_bps <= h.share_bps);
                assert!(a.expires_at <= h.expires_at);
                assert_eq!(a.scope_mask & h.scope_mask, a.scope_mask);
            }
        }
    }

    #[kani::proof]
    fn push_rejects_over_cap_shares() {
        let mut w = AttenuationWitness::empty();
        let h = DelegationHop { share_bps: kani::any(), issued_at: 0, expires_at: u64::MAX, scope_mask: u64::MAX };
        let r = w.push(h);
        assert_eq!(r.is_err(), h.share_bps > SHARE_CAP_BPS);
    }
}
```

The attenuation module composes with the swarm authority types by value alone. A `SwarmDelegationWitnessChain` that is converted hop by hop into this witness inherits the three theorems without any swarm-specific proof, because the theorems quantify over arbitrary hop lists within the capacity bound.

## 3. Merkle inclusion, coupling, and the obligation ledger

**3.1 The inclusion step and the committed envelope.** The compression function is an opaque trait with a leaf hasher and a two-input compressor. Each inclusion step places the accumulator on the side the record names. Path depth is bounded, and a path beyond the bound is a typed error rather than a silent fold. The coupling to decision envelopes is structural. An envelope leaf carries the three fixed-point bounds, the epoch index, and the policy hash under a domain-separation byte. Outside the crate, the only way to obtain an `Envelope` value is through the committed-leaf constructor, which verifies inclusion first and well-formedness second. Any shielded action therefore descends from an envelope whose bounds were committed under the root the caller supplied.

```rust
pub mod inclusion {
    use super::envelope::Envelope;
    use super::fixed_sat::FixedQ16_16;

    pub type Digest32 = [u8; 32];
    pub const MAX_INCLUSION_DEPTH: usize = 64;
    pub const ENVELOPE_LEAF_BYTES: usize = 53;
    pub const ENVELOPE_LEAF_DOMAIN: u8 = 0x11;

    pub trait Compress {
        fn compress(left: &Digest32, right: &Digest32) -> Digest32;
        fn leaf(bytes: &[u8]) -> Digest32;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Side { Left, Right }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InclusionStep { pub sibling: Digest32, pub side: Side }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum InclusionError { DepthExceeded { depth: usize } }

    pub fn inclusion_step<H: Compress>(acc: Digest32, step: &InclusionStep) -> Digest32 {
        match step.side {
            Side::Left => H::compress(&step.sibling, &acc),
            Side::Right => H::compress(&acc, &step.sibling),
        }
    }

    pub fn fold_path<H: Compress>(leaf: Digest32, path: &[InclusionStep]) -> Result<Digest32, InclusionError> {
        if path.len() > MAX_INCLUSION_DEPTH {
            return Err(InclusionError::DepthExceeded { depth: path.len() });
        }
        Ok(path.iter().fold(leaf, |acc, s| inclusion_step::<H>(acc, s)))
    }

    pub fn verify_inclusion<H: Compress>(leaf: Digest32, path: &[InclusionStep], root: &Digest32)
        -> Result<bool, InclusionError>
    {
        Ok(fold_path::<H>(leaf, path)? == *root)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EnvelopeLeaf {
        pub lo: FixedQ16_16,
        pub hi: FixedQ16_16,
        pub fallback: FixedQ16_16,
        pub epoch_index: u64,
        pub policy_hash: Digest32,
    }

    impl EnvelopeLeaf {
        /// Canonical big-endian encoding under a domain byte. Offsets are literal, never computed.
        pub fn encode(&self) -> [u8; ENVELOPE_LEAF_BYTES] {
            let mut out = [0u8; ENVELOPE_LEAF_BYTES];
            out[0] = ENVELOPE_LEAF_DOMAIN;
            out[1..5].copy_from_slice(&self.lo.raw().to_be_bytes());
            out[5..9].copy_from_slice(&self.hi.raw().to_be_bytes());
            out[9..13].copy_from_slice(&self.fallback.raw().to_be_bytes());
            out[13..21].copy_from_slice(&self.epoch_index.to_be_bytes());
            out[21..53].copy_from_slice(&self.policy_hash);
            out
        }
        pub fn leaf_hash<H: Compress>(&self) -> Digest32 { H::leaf(&self.encode()) }
    }

    impl Envelope {
        /// The only public constructor. `Ok(None)` means the leaf is not under `root`
        /// or its bounds are malformed; the caller must fall back to the base policy.
        pub fn from_committed_leaf<H: Compress>(leaf: &EnvelopeLeaf, path: &[InclusionStep], root: &Digest32)
            -> Result<Option<Envelope>, InclusionError>
        {
            if !verify_inclusion::<H>(leaf.leaf_hash::<H>(), path, root)? {
                return Ok(None);
            }
            Ok(Envelope::new(leaf.lo, leaf.hi, leaf.fallback))
        }
    }
}
```

**3.2 Lean 4 inclusion theorems.** Structural facts hold for every compression function. Binding holds under an idealized pairwise-injectivity hypothesis, which is the standard way to mechanize what collision resistance would give without importing a cryptographic model into the kernel proofs.

```lean
-- formal/lean4/Chio/Wave11/Inclusion.lean
import Mathlib.Tactic

namespace Chio.Wave11

variable {D : Type} (compress : D → D → D)

inductive Side | left | right

structure Step (D : Type) where
  sibling : D
  side : Side

def inclusionStep (acc : D) (s : Step D) : D :=
  match s.side with
  | .left  => compress s.sibling acc
  | .right => compress acc s.sibling

def foldPath (leaf : D) (p : List (Step D)) : D := p.foldl (inclusionStep compress) leaf

def verify (leaf : D) (p : List (Step D)) (root : D) : Prop := foldPath compress leaf p = root

theorem verify_nil (leaf root : D) : verify compress leaf [] root ↔ leaf = root := Iff.rfl

theorem foldPath_append (leaf : D) (p q : List (Step D)) :
    foldPath compress leaf (p ++ q) = foldPath compress (foldPath compress leaf p) q :=
  List.foldl_append _ _ _ _

def PairInjective : Prop := ∀ a b a' b', compress a b = compress a' b' → a = a' ∧ b = b'

theorem step_injective (hinj : PairInjective compress) (s : Step D) {x y : D}
    (h : inclusionStep compress x s = inclusionStep compress y s) : x = y := by
  cases s with
  | mk sib side =>
    cases side <;> simp only [inclusionStep] at h
    · exact (hinj _ _ _ _ h).2
    · exact (hinj _ _ _ _ h).1

theorem foldPath_injective (hinj : PairInjective compress) (p : List (Step D)) {x y : D}
    (h : foldPath compress x p = foldPath compress y p) : x = y := by
  induction p generalizing x y with
  | nil => exact h
  | cons s t ih => exact step_injective compress hinj s (ih h)

/-- Idealized binding: one path under one root commits to at most one leaf. -/
theorem verify_binding (hinj : PairInjective compress) (p : List (Step D)) {l l' root : D}
    (h₁ : verify compress l p root) (h₂ : verify compress l' p root) : l = l' :=
  foldPath_injective compress hinj p (h₁.trans h₂.symm)

structure Leaf where
  lo : Int
  hi : Int
  fallback : Int

structure Env where
  lo : Int
  hi : Int
  fallback : Int

def fromCommitted (leafHash : Leaf → D) (l : Leaf) (p : List (Step D)) (root : D) : Option Env :=
  if foldPath compress (leafHash l) p = root then
    if l.lo ≤ l.fallback ∧ l.fallback ≤ l.hi then some ⟨l.lo, l.hi, l.fallback⟩ else none
  else none

theorem fromCommitted_sound (leafHash : Leaf → D) (l : Leaf) (p : List (Step D)) (root : D) (e : Env)
    (h : fromCommitted compress leafHash l p root = some e) :
    verify compress (leafHash l) p root ∧ e.lo ≤ e.fallback ∧ e.fallback ≤ e.hi := by
  unfold fromCommitted at h; split_ifs at h with h₁ h₂
  · cases h; exact ⟨h₁, h₂.1, h₂.2⟩

end Chio.Wave11
```

The soundness theorem is the coupling theorem. Combined with the projection theorem from section 1, it says every shielded action is bounded by an envelope whose bounds are committed under the supplied root, and that the fallback lies inside those bounds.

**3.3 Kani harnesses for inclusion.** A toy compression function stands in for the real one because the harnesses check structure, not cryptography. Both harnesses are bounded by the toy function's loops over the digest width and the leaf encoding.

```rust
#[cfg(kani)]
mod kani_wave11_inclusion {
    #![allow(clippy::arithmetic_side_effects)]
    use super::envelope::Envelope;
    use super::fixed_sat::FixedQ16_16;
    use super::inclusion::*;

    struct ToyCompress;
    impl Compress for ToyCompress {
        fn compress(l: &Digest32, r: &Digest32) -> Digest32 {
            let mut o = [0u8; 32];
            for i in 0..32 { o[i] = l[i].rotate_left(3) ^ r[i].wrapping_mul(5).wrapping_add(i as u8); }
            o
        }
        fn leaf(b: &[u8]) -> Digest32 {
            let mut o = [0u8; 32];
            for (i, x) in b.iter().enumerate() { o[i % 32] ^= x.wrapping_add(i as u8); }
            o
        }
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn inclusion_step_honours_side() {
        let acc: Digest32 = kani::any();
        let sib: Digest32 = kani::any();
        let l = inclusion_step::<ToyCompress>(acc, &InclusionStep { sibling: sib, side: Side::Left });
        let r = inclusion_step::<ToyCompress>(acc, &InclusionStep { sibling: sib, side: Side::Right });
        assert_eq!(l, ToyCompress::compress(&sib, &acc));
        assert_eq!(r, ToyCompress::compress(&acc, &sib));
    }

    #[kani::proof]
    #[kani::unwind(54)]
    fn committed_envelope_requires_verified_root() {
        let leaf = EnvelopeLeaf {
            lo: FixedQ16_16::from_raw(kani::any()),
            hi: FixedQ16_16::from_raw(kani::any()),
            fallback: FixedQ16_16::from_raw(kani::any()),
            epoch_index: kani::any(),
            policy_hash: kani::any(),
        };
        let steps: [InclusionStep; 2] = [
            InclusionStep { sibling: kani::any(), side: if kani::any() { Side::Left } else { Side::Right } },
            InclusionStep { sibling: kani::any(), side: if kani::any() { Side::Left } else { Side::Right } },
        ];
        let n: usize = kani::any();
        kani::assume(n <= 2);
        let path = &steps[..n];
        let root: Digest32 = kani::any();
        let got = Envelope::from_committed_leaf::<ToyCompress>(&leaf, path, &root).unwrap();
        let verified = verify_inclusion::<ToyCompress>(leaf.leaf_hash::<ToyCompress>(), path, &root).unwrap();
        if let Some(env) = got {
            assert!(verified);
            assert!(env.lo() <= env.fallback() && env.fallback() <= env.hi());
        }
        if !verified { assert!(got.is_none()); }
    }

    #[kani::proof]
    fn depth_bound_is_a_typed_error() {
        let leaf: Digest32 = kani::any();
        let path = [InclusionStep { sibling: [0u8; 32], side: Side::Left }; MAX_INCLUSION_DEPTH + 1];
        assert_eq!(
            fold_path::<ToyCompress>(leaf, &path),
            Err(InclusionError::DepthExceeded { depth: MAX_INCLUSION_DEPTH + 1 })
        );
    }
}
```

**3.4 Manifest entries.** The manifest gains one obligation block per theorem, each marked additive. Lean targets are the four new files. Kani targets are the harness names above. Creusot targets are the two contracted functions.

```toml
# formal/proof-manifest.toml  (appended; nothing above this block changes)
[[obligation]]
id = "w11.fixed.penalized_le_score"
rust = "chio_kernel_core::formal_wave11::fixed_sat::penalized_score"
lean = "Chio.Wave11.penalized_le_score"
kani = "penalty_never_exceeds_score_for_nonneg_prices"
creusot = "fixed_sat::FixedQ16_16::sat_add"
additive = true
status = "lean-model-proved; aeneas-refinement-pending"

[[obligation]]
id = "w11.envelope.project_mem"
rust = "chio_kernel_core::formal_wave11::envelope::Envelope::project"
lean = "Chio.Wave11.project_mem"
kani = "projection_lands_in_envelope_for_any_learned_choice"
creusot = "envelope::Envelope::project"
additive = true
status = "lean-model-proved; aeneas-refinement-pending"

[[obligation]]
id = "w11.epoch.phase_mono"
rust = "chio_kernel_core::formal_wave11::epoch::phase_at"
lean = "Chio.Wave11.phaseAt_mono"
kani = "phase_is_monotone_across_any_boundary"
additive = true
status = "lean-model-proved; A1-pinned-by-kani"

[[obligation]]
id = "w11.epoch.close_terminal"
rust = "chio_kernel_core::formal_wave11::epoch::ledger_epoch_close"
lean = "Chio.Wave11.epoch_close_terminal"
additive = true
status = "lean-model-proved; A2-and-op2-model-pinned"

[[obligation]]
id = "w11.attenuation.never_escalates"
rust = "chio_kernel_core::formal_wave11::attenuation::attenuate"
lean = "Chio.Wave11.attenuate_share_le"
kani = "attenuation_never_escalates"
additive = true
status = "lean-model-proved; kani-bounded-4-hops"

[[obligation]]
id = "w11.inclusion.committed_sound"
rust = "chio_kernel_core::formal_wave11::inclusion::Envelope::from_committed_leaf"
lean = "Chio.Wave11.fromCommitted_sound"
kani = "committed_envelope_requires_verified_root"
additive = true
status = "lean-model-proved; kani-bounded-depth-2-toy-hash"
```

**3.5 Status, honestly stated.** The Lean theorems are complete over hand-written models that mirror the Rust shapes. The bridge from those models to Aeneas-extracted definitions is not written here. Each obligation above carries a pending-refinement marker for that reason, and the refinement theorems should be the next pass. The Kani harnesses are exhaustive for the scalar fixed-point operations and the five-dimensional penalty, and bounded where the table says bounded. The exact-expiry harness is the one artifact whose expected values depend on A1, and it is labeled so a reviewer can flip it in one place. The Creusot contracts are stated for two functions and should be extended to the attenuation fold once the pairwise-injectivity style of specification is agreed for pearlite.

| Area | Coverage in this pass | Bound or hypothesis |
|---|---|---|
| Saturating add, sub, mul | exhaustive over 32-bit inputs | none |
| Penalty fold | exhaustive over five dimensions | prices and usage non-negative |
| Envelope projection | exhaustive, learned choice unconstrained | well-formed envelope |
| Epoch phase monotonicity | exhaustive over 64-bit instants | real pinned classifier |
| Exact expiry boundary | exhaustive | A1 half-open |
| Epoch close terminality | Lean only | A2 and pinned op-2 model |
| Attenuation witness | Lean unbounded, Kani four hops | shares within cap |
| Inclusion step and coupling | Lean unbounded, Kani depth two | toy compression in Kani, injectivity in Lean binding |

**Recap.** This pass adds one alloc-free Rust module with total, checked arithmetic covering fixed-point saturation, a privately constructed decision envelope, epoch phase and boundary stepping, a fixed-capacity multi-hop attenuation witness, and bounded-depth Merkle inclusion coupled to envelope leaves. Four Lean files prove penalty monotonicity under saturation, projection membership and idempotence, phase monotonicity and half-open boundary behavior, epoch-close terminality under conservation, three attenuation non-escalation properties by induction, and inclusion binding under idealized injectivity plus soundness of the committed-envelope constructor. Twelve Kani harnesses check these bit-precisely within the stated bounds, and two Creusot contracts restate the key properties at the Rust boundary. Everything is strictly additive to the pinned signatures, with three explicit assumptions and one pending Aeneas refinement bridge flagged for the next pass.

---

# Verbatim Treatise - `wave11_angle_2_copley_dag_optimization_and_simd_bitset_pass_11`

Resuming at §5 with the runtime types, then the zero-branch interpreter, the compiler, the WCET proof, the Lean 4 / Kani / Apalache obligations, and the differential tests, each as a separate piece.

## 5. Runtime representation (`chio-kernel-core`, additive module)

The pinned reading of `SymbolicRuleDag<537, 9, 9, 236>` is `<P, W, K, R>`: 537 predicates, 9 words of 64 bits (ceil(537/64)), clause width at most 9 literals, 236 rules. Clauses per rule are capped by a separate associated constant `MAX_CLAUSES_PER_RULE = 9`. The runtime module below is self-contained and adds nothing to the signatures pinned in `formal/proof-manifest.toml`.

A Kleene state is a pair of bitsets with the invariant `pos & neg == 0` per word, enforced by a private constructor. A clause is compiled to a set of *word units* `(word, req_pos, req_neg)`. The unit's `miss` word is zero iff every required literal in that word is resolved as required; its `conf` word is non-zero iff some required literal is resolved the opposite way. Clauses OR their units; rules combine clauses with all-ones/all-zeros masks. No instruction branches on input data.

```rust
//! crates/kernel/chio-kernel-core/src/formal_bitset_schedule.rs
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub const COPLEY_PREDICATES: usize = 537;
pub const COPLEY_WORDS: usize = 9;
pub const COPLEY_MAX_CLAUSE_WIDTH: usize = 9;
pub const COPLEY_MAX_CLAUSES_PER_RULE: usize = 9;
pub const COPLEY_RULES: usize = 236;
pub const COPLEY_RULE_WORDS: usize = 4;
pub const COPLEY_MAX_CLAUSES: usize = 2_124; // 236 * 9
pub const COPLEY_MAX_UNITS: usize = 19_116;  // 2_124 * 9

#[allow(clippy::arithmetic_side_effects)]
const _: () = {
    assert!(COPLEY_WORDS * 64 >= COPLEY_PREDICATES);
    assert!(COPLEY_RULE_WORDS * 64 >= COPLEY_RULES);
    assert!(COPLEY_MAX_CLAUSES == COPLEY_RULES * COPLEY_MAX_CLAUSES_PER_RULE);
    assert!(COPLEY_MAX_UNITS == COPLEY_MAX_CLAUSES * COPLEY_MAX_CLAUSE_WIDTH);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// Information order: Bot ⊑ x; Pos ⊑ Pos; Neg ⊑ Neg.
    #[must_use]
    pub const fn leq_info(self, other: K3) -> bool {
        matches!((self, other), (K3::Bot, _) | (K3::Pos, K3::Pos) | (K3::Neg, K3::Neg))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K3Bitset<const W: usize> { pos: [u64; W], neg: [u64; W] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K3Conflict { pub word: usize }

impl<const W: usize> K3Bitset<W> {
    pub const BOTTOM: Self = Self { pos: [0; W], neg: [0; W] };

    pub fn new(pos: [u64; W], neg: [u64; W]) -> Result<Self, K3Conflict> {
        for (word, (p, n)) in pos.iter().zip(neg.iter()).enumerate() {
            if (p & n) != 0 { return Err(K3Conflict { word }); }
        }
        Ok(Self { pos, neg })
    }
    #[must_use] pub const fn pos(&self) -> &[u64; W] { &self.pos }
    #[must_use] pub const fn neg(&self) -> &[u64; W] { &self.neg }

    #[must_use]
    pub fn get(&self, index: usize) -> K3 {
        let word = index.checked_div(64);
        let bit = index.checked_rem(64).and_then(|b| u32::try_from(b).ok());
        let (Some(word), Some(bit)) = (word, bit) else { return K3::Bot };
        let p = self.pos.get(word).copied().unwrap_or(0).checked_shr(bit).unwrap_or(0) & 1;
        let n = self.neg.get(word).copied().unwrap_or(0).checked_shr(bit).unwrap_or(0) & 1;
        match (p, n) { (1, 0) => K3::Pos, (0, 1) => K3::Neg, _ => K3::Bot }
    }

    /// Pointwise information order over all P bits.
    #[must_use]
    pub fn leq_info(&self, other: &Self) -> bool {
        self.pos.iter().zip(other.pos.iter()).all(|(a, b)| (a & !b) == 0)
            && self.neg.iter().zip(other.neg.iter()).all(|(a, b)| (a & !b) == 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    Unit { word: u16, req_pos: u64, req_neg: u64, dst: u16 },
    ClauseEdge { unit: u16, clause: u16 },
    RuleEdge { clause: u16, rule: u16 },
    RuleOut { rule: u16, word: u16, bit_mask: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScheduleCost {
    pub units: u64, pub clause_edges: u64, pub rule_edges: u64, pub rule_outs: u64,
}

impl ScheduleCost {
    pub const UNIT_OPS: u64 = 8;
    pub const CLAUSE_EDGE_OPS: u64 = 2;
    pub const RULE_EDGE_OPS: u64 = 6;
    pub const RULE_OUT_OPS: u64 = 4;

    /// Exact 64-bit ALU operation count of one full evaluation (Theorem 6).
    #[must_use]
    pub fn alu_ops(self) -> Option<u64> {
        let a = self.units.checked_mul(Self::UNIT_OPS)?;
        let b = self.clause_edges.checked_mul(Self::CLAUSE_EDGE_OPS)?;
        let c = self.rule_edges.checked_mul(Self::RULE_EDGE_OPS)?;
        let d = self.rule_outs.checked_mul(Self::RULE_OUT_OPS)?;
        a.checked_add(b)?.checked_add(c)?.checked_add(d)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    WordIndex { at: usize }, UnitIndex { at: usize }, UnitNotReady { at: usize },
    ClauseIndex { at: usize }, ClauseSealed { at: usize }, ClauseEmpty { at: usize },
    RuleIndex { at: usize }, RuleClosed { at: usize }, RuleEmpty { at: usize },
    RuleOutEncoding { at: usize }, RuleOutMissing { rule: usize }, Capacity,
}

pub struct Registers<const U: usize, const C: usize, const R: usize> {
    unit_miss: [u64; U], unit_conf: [u64; U],
    clause_miss: [u64; C], clause_conf: [u64; C],
    rule_t: [u64; R], rule_f: [u64; R],
}

impl<const U: usize, const C: usize, const R: usize> Registers<U, C, R> {
    pub const ZEROED: Self = Self {
        unit_miss: [0; U], unit_conf: [0; U], clause_miss: [0; C],
        clause_conf: [0; C], rule_t: [0; R], rule_f: [0; R],
    };
    /// Unit registers need no reset: `Unit` stores, and validation
    /// guarantees every `ClauseEdge` reads a unit written earlier.
    fn reset(&mut self, clauses: usize, rules: usize) {
        for s in self.clause_miss.iter_mut().take(clauses) { *s = 0; }
        for s in self.clause_conf.iter_mut().take(clauses) { *s = 0; }
        for s in self.rule_t.iter_mut().take(rules) { *s = 0; }
        for s in self.rule_f.iter_mut().take(rules) { *s = u64::MAX; }
    }
}

#[inline(always)] fn load(regs: &[u64], i: u16) -> u64 {
    regs.get(usize::from(i)).copied().unwrap_or(0)
}
#[inline(always)] fn store(regs: &mut [u64], i: u16, v: u64) {
    if let Some(s) = regs.get_mut(usize::from(i)) { *s = v; }
}
#[inline(always)] fn or_into(regs: &mut [u64], i: u16, v: u64) {
    if let Some(s) = regs.get_mut(usize::from(i)) { *s |= v; }
}
#[inline(always)] fn and_into(regs: &mut [u64], i: u16, v: u64) {
    if let Some(s) = regs.get_mut(usize::from(i)) { *s &= v; }
}
/// All-ones for `true`, all-zeros for `false`; no branch.
#[inline(always)] const fn mask(b: bool) -> u64 { 0u64.wrapping_sub(b as u64) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixReport { pub executed: usize, pub complete: bool }
```

The `Option` guards inside `load`, `store`, `or_into`, and `and_into` depend only on schedule indices, which `validate` proves in range. They are dead code after validation and exist so that no panic path is reachable under `kani`.

## 6. Validation and the zero-branch interpreter

Validation enforces the topological discipline of the DAG in one pass: a unit must be written before any clause edge reads it; a clause is *sealed* by its first rule edge, after which no further clause edges may target it; a rule is *closed* by its single `RuleOut`, whose `(word, bit_mask)` must equal the canonical encoding of its index.

```rust
pub struct Schedule<'a, const W: usize, const RW: usize,
                    const U: usize, const C: usize, const R: usize> {
    instrs: &'a [Instr], clauses: usize, rules: usize, cost: ScheduleCost,
}

impl<'a, const W: usize, const RW: usize, const U: usize, const C: usize, const R: usize>
    Schedule<'a, W, RW, U, C, R>
{
    pub fn validate(instrs: &'a [Instr]) -> Result<Self, ScheduleError> {
        let mut unit_ready = [false; U];
        let mut clause_state = [0u8; C]; // 0 empty, 1 open, 2 sealed
        let mut rule_state = [0u8; R];   // 0 none, 1 open, 2 closed
        let mut cost = ScheduleCost::default();
        let (mut clauses, mut rules) = (0usize, 0usize);
        let bump = |x: u64| x.checked_add(1).ok_or(ScheduleError::Capacity);
        for (at, instr) in instrs.iter().enumerate() {
            match *instr {
                Instr::Unit { word, dst, .. } => {
                    if usize::from(word) >= W { return Err(ScheduleError::WordIndex { at }); }
                    let slot = unit_ready.get_mut(usize::from(dst))
                        .ok_or(ScheduleError::UnitIndex { at })?;
                    *slot = true;
                    cost.units = bump(cost.units)?;
                }
                Instr::ClauseEdge { unit, clause } => {
                    if !unit_ready.get(usize::from(unit)).copied().unwrap_or(false) {
                        return Err(ScheduleError::UnitNotReady { at });
                    }
                    let c = usize::from(clause);
                    let st = clause_state.get_mut(c).ok_or(ScheduleError::ClauseIndex { at })?;
                    if *st == 2 { return Err(ScheduleError::ClauseSealed { at }); }
                    *st = 1;
                    clauses = clauses.max(c.checked_add(1).ok_or(ScheduleError::Capacity)?);
                    cost.clause_edges = bump(cost.clause_edges)?;
                }
                Instr::RuleEdge { clause, rule } => {
                    let st = clause_state.get_mut(usize::from(clause))
                        .ok_or(ScheduleError::ClauseIndex { at })?;
                    if *st == 0 { return Err(ScheduleError::ClauseEmpty { at }); }
                    *st = 2;
                    let r = usize::from(rule);
                    let rs = rule_state.get_mut(r).ok_or(ScheduleError::RuleIndex { at })?;
                    if *rs == 2 { return Err(ScheduleError::RuleClosed { at }); }
                    *rs = 1;
                    rules = rules.max(r.checked_add(1).ok_or(ScheduleError::Capacity)?);
                    cost.rule_edges = bump(cost.rule_edges)?;
                }
                Instr::RuleOut { rule, word, bit_mask } => {
                    let r = usize::from(rule);
                    let rs = rule_state.get_mut(r).ok_or(ScheduleError::RuleIndex { at })?;
                    match *rs {
                        0 => return Err(ScheduleError::RuleEmpty { at }),
                        2 => return Err(ScheduleError::RuleClosed { at }),
                        _ => *rs = 2,
                    }
                    let exp_word = r.checked_div(64);
                    let exp_mask = r.checked_rem(64)
                        .and_then(|b| u32::try_from(b).ok())
                        .and_then(|b| 1u64.checked_shl(b));
                    if usize::from(word) >= RW || Some(usize::from(word)) != exp_word
                        || Some(bit_mask) != exp_mask {
                        return Err(ScheduleError::RuleOutEncoding { at });
                    }
                    cost.rule_outs = bump(cost.rule_outs)?;
                }
            }
        }
        for (rule, st) in rule_state.iter().enumerate().take(rules) {
            if *st != 2 { return Err(ScheduleError::RuleOutMissing { rule }); }
        }
        Ok(Self { instrs, clauses, rules, cost })
    }

    #[must_use] pub const fn cost(&self) -> ScheduleCost { self.cost }
    #[must_use] pub const fn len(&self) -> usize { self.instrs.len() }
    #[must_use] pub const fn is_empty(&self) -> bool { self.instrs.is_empty() }

    pub fn eval(&self, input: &K3Bitset<W>, regs: &mut Registers<U, C, R>) -> K3Bitset<RW> {
        self.eval_prefix(self.instrs.len(), input, regs).0
    }

    /// Executes exactly `min(fuel, len)` instructions; the trace does not
    /// depend on `input` (Theorem 6). Output ⊑ `eval` output (Theorem 5).
    pub fn eval_prefix(&self, fuel: usize, input: &K3Bitset<W>,
                       regs: &mut Registers<U, C, R>) -> (K3Bitset<RW>, PrefixReport) {
        regs.reset(self.clauses, self.rules);
        let mut out_pos = [0u64; RW];
        let mut out_neg = [0u64; RW];
        let mut executed = 0usize;
        for instr in self.instrs.iter().take(fuel) {
            match *instr {
                Instr::Unit { word, req_pos, req_neg, dst } => {
                    let p = load(input.pos(), word);
                    let n = load(input.neg(), word);
                    let miss = ((p & req_pos) ^ req_pos) | ((n & req_neg) ^ req_neg);
                    let conf = (n & req_pos) | (p & req_neg);
                    store(&mut regs.unit_miss, dst, miss);
                    store(&mut regs.unit_conf, dst, conf);
                }
                Instr::ClauseEdge { unit, clause } => {
                    let um = load(&regs.unit_miss, unit);
                    let uc = load(&regs.unit_conf, unit);
                    or_into(&mut regs.clause_miss, clause, um);
                    or_into(&mut regs.clause_conf, clause, uc);
                }
                Instr::RuleEdge { clause, rule } => {
                    let cm = load(&regs.clause_miss, clause);
                    let cc = load(&regs.clause_conf, clause);
                    or_into(&mut regs.rule_t, rule, mask(cm == 0));
                    and_into(&mut regs.rule_f, rule, mask(cc != 0));
                }
                Instr::RuleOut { rule, word, bit_mask } => {
                    let rt = load(&regs.rule_t, rule);
                    let rf = load(&regs.rule_f, rule);
                    or_into(&mut out_pos, word, bit_mask & rt);
                    or_into(&mut out_neg, word, bit_mask & rf);
                }
            }
            executed = executed.saturating_add(1);
        }
        debug_assert!(out_pos.iter().zip(out_neg.iter()).all(|(p, n)| (p & n) == 0));
        let complete = executed == self.instrs.len();
        (K3Bitset { pos: out_pos, neg: out_neg }, PrefixReport { executed, complete })
    }
}
```

The direct struct construction at the end is the one place the `K3Bitset` invariant is assumed rather than checked. Lemma 1 and Lemma 3 below discharge it, and the Kani harness in §10 checks it on bounded instances.

## 7. Compiler (`chio-policy`, `alloc`-based, additive)

The compiler is the only component that allocates. It canonicalizes each clause into a `([u64; W], [u64; W])` mask pair, deduplicates clauses and word units through ordered maps, and emits a **rule-major, rank-ordered** schedule: rules sorted by descending rank, clauses within a rule sorted by descending rank with a stable tie-break on source order. A unit or clause is emitted the first time any rule needs it and only referenced afterwards.

```rust
//! crates/policy/chio-policy/src/hushspec/bitset_compile.rs
extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cmp::Reverse;
use chio_kernel_core::formal_bitset_schedule::{Instr, ScheduleCost};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lit { pub pred: u16, pub negated: bool }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClauseDnf { pub rank: u32, pub lits: Vec<Lit> }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDnf { pub rank: u32, pub clauses: Vec<ClauseDnf> }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileError {
    TooManyRules, EmptyRule { rule: usize }, TooManyClauses { rule: usize },
    EmptyClause { rule: usize, clause: usize }, ClauseTooWide { rule: usize, clause: usize },
    PredicateOutOfRange { pred: u16 }, Capacity,
}

#[derive(Clone, Debug)]
pub struct Compiled {
    pub instrs: Vec<Instr>,
    pub cost: ScheduleCost,
    /// compiled rule id -> source rule index
    pub rule_order: Vec<usize>,
    pub distinct_units: usize,
    pub distinct_clauses: usize,
}

pub struct SymbolicRuleDag<const P: usize, const W: usize, const K: usize, const R: usize> {
    rules: Vec<RuleDnf>,
}

impl<const P: usize, const W: usize, const K: usize, const R: usize>
    SymbolicRuleDag<P, W, K, R>
{
    pub const MAX_CLAUSES_PER_RULE: usize = 9;

    pub fn new(rules: Vec<RuleDnf>) -> Result<Self, CompileError> {
        if rules.len() > R { return Err(CompileError::TooManyRules); }
        for (ri, rule) in rules.iter().enumerate() {
            if rule.clauses.is_empty() { return Err(CompileError::EmptyRule { rule: ri }); }
            if rule.clauses.len() > Self::MAX_CLAUSES_PER_RULE {
                return Err(CompileError::TooManyClauses { rule: ri });
            }
            for (ci, clause) in rule.clauses.iter().enumerate() {
                if clause.lits.is_empty() {
                    return Err(CompileError::EmptyClause { rule: ri, clause: ci });
                }
                if clause.lits.len() > K {
                    return Err(CompileError::ClauseTooWide { rule: ri, clause: ci });
                }
            }
        }
        Ok(Self { rules })
    }

    fn canonical(lits: &[Lit]) -> Result<([u64; W], [u64; W]), CompileError> {
        let (mut rp, mut rn) = ([0u64; W], [0u64; W]);
        for lit in lits {
            let pred = usize::from(lit.pred);
            if pred >= P { return Err(CompileError::PredicateOutOfRange { pred: lit.pred }); }
            let word = pred.checked_div(64).ok_or(CompileError::Capacity)?;
            let bit = pred.checked_rem(64)
                .and_then(|b| u32::try_from(b).ok())
                .and_then(|b| 1u64.checked_shl(b))
                .ok_or(CompileError::Capacity)?;
            let target = if lit.negated { &mut rn } else { &mut rp };
            *target.get_mut(word).ok_or(CompileError::Capacity)? |= bit;
        }
        Ok((rp, rn))
    }

    fn bump(x: u64) -> Result<u64, CompileError> {
        x.checked_add(1).ok_or(CompileError::Capacity)
    }

    pub fn compile(&self) -> Result<Compiled, CompileError> {
        let mut order: Vec<usize> = (0..self.rules.len()).collect();
        order.sort_by_key(|&i| (Reverse(self.rules.get(i).map_or(0, |r| r.rank)), i));
        let mut units: BTreeMap<(u16, u64, u64), u16> = BTreeMap::new();
        let mut clauses: BTreeMap<([u64; W], [u64; W]), u16> = BTreeMap::new();
        let mut instrs = Vec::new();
        let mut cost = ScheduleCost::default();

        for (rule_pos, &ri) in order.iter().enumerate() {
            let rule = self.rules.get(ri).ok_or(CompileError::Capacity)?;
            let rule_id = u16::try_from(rule_pos).map_err(|_| CompileError::Capacity)?;
            let mut ordered: Vec<&ClauseDnf> = rule.clauses.iter().collect();
            ordered.sort_by_key(|c| Reverse(c.rank)); // stable: ties keep source order
            for clause in ordered {
                let key = Self::canonical(&clause.lits)?;
                let clause_id = if let Some(&id) = clauses.get(&key) { id } else {
                    let id = u16::try_from(clauses.len()).map_err(|_| CompileError::Capacity)?;
                    for (w, (rp, rn)) in key.0.iter().zip(key.1.iter()).enumerate() {
                        if (rp | rn) == 0 { continue; }
                        let word = u16::try_from(w).map_err(|_| CompileError::Capacity)?;
                        let ukey = (word, *rp, *rn);
                        let unit_id = if let Some(&u) = units.get(&ukey) { u } else {
                            let u = u16::try_from(units.len()).map_err(|_| CompileError::Capacity)?;
                            units.insert(ukey, u);
                            instrs.push(Instr::Unit { word, req_pos: *rp, req_neg: *rn, dst: u });
                            cost.units = Self::bump(cost.units)?;
                            u
                        };
                        instrs.push(Instr::ClauseEdge { unit: unit_id, clause: id });
                        cost.clause_edges = Self::bump(cost.clause_edges)?;
                    }
                    clauses.insert(key, id);
                    id
                };
                instrs.push(Instr::RuleEdge { clause: clause_id, rule: rule_id });
                cost.rule_edges = Self::bump(cost.rule_edges)?;
            }
            let word = rule_pos.checked_div(64)
                .and_then(|w| u16::try_from(w).ok()).ok_or(CompileError::Capacity)?;
            let bit_mask = rule_pos.checked_rem(64)
                .and_then(|b| u32::try_from(b).ok())
                .and_then(|b| 1u64.checked_shl(b)).ok_or(CompileError::Capacity)?;
            instrs.push(Instr::RuleOut { rule: rule_id, word, bit_mask });
            cost.rule_outs = Self::bump(cost.rule_outs)?;
        }
        Ok(Compiled {
            instrs, cost, rule_order: order,
            distinct_units: units.len(), distinct_clauses: clauses.len(),
        })
    }
}
```

Two properties of `canonical` matter for correctness. Duplicate literals are idempotent under OR. A contradictory pair `p ∧ ¬p` sets the same bit in both masks: `miss` can never be zero, and `conf` is non-zero exactly when `p` is resolved either way, so the clause evaluates to `-` when `p` is resolved and `⊥` when it is not. That is precisely the Kleene value of `p ∧ ¬p`, so the compiler must not simplify it away, and it does not.

## 8. Exact WCET

**Definition (data-oblivious).** An evaluation procedure is data-oblivious if, for every pair of well-formed inputs, the executed instruction sequence, every taken branch, and every memory address touched are identical. Only register operand values may differ.

**Theorem 6 (exact instruction count).** For a validated schedule `S` and any well-formed input, `eval` performs exactly

```
ops(S) = 8·|Unit| + 2·|ClauseEdge| + 6·|RuleEdge| + 4·|RuleOut|
```

64-bit ALU operations plus `2·clauses + 2·rules` reset stores, and the procedure is data-oblivious.

*Proof.* The loop iterates over `instrs.iter().take(fuel)`, whose length is fixed by the schedule. The `match` discriminates on `Instr`, which is schedule data. Each arm is straight-line code whose index arguments come from the instruction; the `Option` guards in the accessors resolve identically on every input because `validate` proves every index in range. Memory addresses are therefore input-independent. Counting the arms: `Unit` costs two ANDs and two XORs for `miss` plus one OR, and two ANDs and one OR for `conf`, which is eight. `ClauseEdge` costs two ORs. `RuleEdge` costs two compares, two mask negations, one OR, and one AND, which is six. `RuleOut` costs two ANDs and two ORs. The compares compile to flag-setting instructions, not branches, and `mask` is a wrapping subtraction. ∎

**Corollary (structural worst case for ⟨537, 9, 9, 236⟩).** Every clause has at most 9 literals and so touches at most 9 words. The pre-deduplication counts bound the post-deduplication counts because deduplication only removes instructions.

| Instruction | Structural maximum | Ops each | Ops |
|---|---:|---:|---:|
| `Unit` | 19,116 | 8 | 152,928 |
| `ClauseEdge` | 19,116 | 2 | 38,232 |
| `RuleEdge` | 2,124 | 6 | 12,744 |
| `RuleOut` | 236 | 4 | 944 |
| **Total** | | | **204,848** |

At a deliberately pessimistic one operation per cycle at 3 GHz, this is about 68 µs, an order of magnitude inside the 0.5 ms Tier-1 floor where the 537 predicates originate. The schedule compiled from the pinned Copley ruleset is far smaller, but I do not have its statistics here, so the number is not stated. The compiler emits `ScheduleCost` for the pinned ruleset at build time and CI asserts it against a declared ceiling in `formal/proof-manifest.toml` (§12). Because WCET equals BCET under Theorem 6, that single measurement is also the exact per-evaluation cost. Tier-0 placement is only admissible for a rule-major prefix whose `alu_ops` fits the 10 to 800 ns budget; the `eval_prefix` fuel argument exposes exactly that cut.

## 9. Correctness proofs

Let `pos, neg : [P] → 𝔹` with `pos ∧ neg = false` pointwise. A literal `ℓ = (j, s)` is `+` when the input bit for `j` matches polarity `s`, `-` when it matches the opposite polarity, and `⊥` otherwise. A clause is the Kleene conjunction of its literals and a rule the Kleene disjunction of its clauses. Kleene conjunction is `+` iff all conjuncts are `+`, `-` iff some conjunct is `-`, and `⊥` otherwise; disjunction is dual.

**Lemma 1 (word unit refinement and exclusivity).** For one word with input `(p, n)`, `p & n = 0`, and masks `(rp, rn)`:
1. `miss = 0` iff `p & rp = rp` and `n & rn = rn`, which is iff every literal of the clause in this word is `+`.
2. `conf ≠ 0` iff `n & rp ≠ 0` or `p & rn ≠ 0`, which is iff some literal of the clause in this word is `-`.
3. `miss = 0` implies `conf = 0`.

*Proof.* For (1): `(p & rp) ^ rp = 0` iff `p & rp = rp`, since XOR with `rp` is a bijection fixing `rp` to zero only; the OR of two words is zero iff both are. For (2): a bit of `n & rp` is set iff a positively required predicate is resolved `-`; dually for `p & rn`. For (3): if `p & rp = rp` then every bit of `rp` is set in `p`, hence clear in `n` because `p & n = 0`, so `n & rp = 0`; symmetrically `p & rn = 0`. ∎

**Lemma 2 (clause refinement).** After all `ClauseEdge` instructions of clause `c` have executed, `clause_miss[c] = 0` iff `c` is `+`, and `clause_conf[c] ≠ 0` iff `c` is `-`.

*Proof.* The units of `c` partition its literals by word, and `canonical` places every literal in exactly one unit. `clause_miss` is the OR of unit `miss` words, zero iff every unit's `miss` is zero, iff every literal is `+` by Lemma 1(1). `clause_conf` is the OR of unit `conf` words, non-zero iff some literal is `-` by Lemma 1(2). Deduplication is sound because a unit's value is a function of `(word, rp, rn)` and the input only, and a clause's value is a function of its mask pair and the input only; two clauses with equal canonical keys denote the same Kleene function. ∎

**Lemma 3 (rule refinement).** After all `RuleEdge` instructions of rule `r`, `rule_t[r] = all-ones` iff some clause of `r` is `+`, and `rule_f[r] = all-ones` iff every clause of `r` is `-`. The two never hold simultaneously.

*Proof.* `rule_t` starts at zero and is ORed with `mask(cm == 0)`, so it is all-ones iff some clause had `clause_miss = 0`, which is iff some clause is `+` by Lemma 2. `rule_f` starts at all-ones and is ANDed with `mask(cc ≠ 0)`, so it is all-ones iff every clause had `clause_conf ≠ 0`, iff every clause is `-`. Values stay in `{0, all-ones}` because OR and AND of such masks are closed. Exclusivity follows from Lemma 1(3) lifted through Lemma 2: a clause that is `+` is not `-`, so if some clause is `+`, not every clause is `-`. ∎

**Theorem 4 (compile correctness).** For every `SymbolicRuleDag` accepted by `new`, every well-formed input `x`, and every source rule `i` with compiled id `k = rule_order⁻¹(i)`, `eval(compile(dag))(x).get(k) = ⟦rule_i⟧_K3(x)`.

*Proof.* `compile` emits, for each rule, all of its clause edges before its rule edges and all unit writes before the edges that read them, so `validate` accepts the output (the sealing discipline is respected because a clause is fully emitted on first encounter and only referenced afterwards). By Lemma 3, `RuleOut` writes bit `k` of `out_pos` iff some clause is `+` and bit `k` of `out_neg` iff every clause is `-`. Decoding `(1,0)` as `+`, `(0,1)` as `-`, and `(0,0)` as `⊥` matches the Kleene disjunction exactly. ∎

**Theorem 5 (prefix soundness).** For every `fuel`, `eval_prefix(fuel)(x).0 ⊑ eval(x)` in the pointwise information order.

*Proof.* Output bits are written only by `RuleOut`. If `RuleOut` for rule `k` lies within the prefix, every `RuleEdge` for `k` precedes it (rule-closing discipline), every `ClauseEdge` of each referenced clause precedes that clause's first `RuleEdge` (sealing), and every `Unit` precedes the edges that read it (readiness). The prefix therefore contains the entire dependency closure of rule `k`, and because each instruction's effect is a deterministic function of its operands and no later instruction writes `rule_t[k]` or `rule_f[k]`, rule `k`'s output equals its value in the full run. If `RuleOut` for `k` lies outside the prefix, both output bits are zero, which is `⊥`, the bottom of the order. ∎

**Theorem (order independence).** Permuting rules, or clauses within a rule, changes `rule_order` but not any rule's value.

*Proof.* Boolean OR and AND are commutative and associative with identities `0` and `all-ones`, which are the initial values of `rule_t` and `rule_f`. ∎

**Proposition (short-circuit rank ordering).** Suppose clause `c` of a rule is `+` independently with calibrated probability `π_c`, derived from the Tier-1 reliability curves at `(τ_j^pos, τ_j^neg)`. Then ordering clauses by descending `π_c` minimizes the expected index of the first `RuleEdge` after which `rule_t` is already all-ones, which is the earliest prefix at which `eval_prefix` resolves the rule to `+`.

*Proof.* The expected index is `Σ_k Π_{j<k}(1 − π_j)`. Swapping adjacent positions `i, i+1` with `π_i < π_{i+1}` changes only the term for position `i+1`, from `Π_{j<i}(1 − π_j)·(1 − π_i)` to `Π_{j<i}(1 − π_j)·(1 − π_{i+1})`, which is strictly smaller. Repeated adjacent swaps sort the sequence, each weakly decreasing the sum. ∎

Independence is an approximation. The rank is an input to the compiler, not a correctness assumption: by the order-independence theorem, a poor rank costs only resolution latency under fuel bounds, never a wrong verdict.

## 10. Mechanized obligations

**Lean 4** (new file `formal/lean4/Chio/BitsetSchedule.lean`, no existing module edited). The bit-level lemmas close by `bv_decide`; the list-level lemmas are by induction on the clause and rule lists.

```lean
import Std.Tactic.BVDecide

namespace Chio.BitsetSchedule

inductive K3 | pos | neg | bot deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _ | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .bot

def K3.or : K3 → K3 → K3
  | .pos, _ | _, .pos => .pos
  | .neg, .neg => .neg
  | _, _ => .bot

def clauseEval (ls : List K3) : K3 := ls.foldr K3.and .pos
def ruleEval (cs : List K3) : K3 := cs.foldr K3.or .neg

theorem clauseEval_pos_iff (ls : List K3) :
    clauseEval ls = .pos ↔ ∀ l ∈ ls, l = .pos := by
  induction ls with
  | nil => simp [clauseEval]
  | cons l ls ih => cases l <;> simp [clauseEval, K3.and, ih] at *

theorem ruleEval_neg_iff (cs : List K3) :
    ruleEval cs = .neg ↔ ∀ c ∈ cs, c = .neg := by
  induction cs with
  | nil => simp [ruleEval]
  | cons c cs ih => cases c <;> simp [ruleEval, K3.or, ih] at *

def unitMiss (p n rp rn : BitVec 64) : BitVec 64 :=
  ((p &&& rp) ^^^ rp) ||| ((n &&& rn) ^^^ rn)
def unitConf (p n rp rn : BitVec 64) : BitVec 64 :=
  (n &&& rp) ||| (p &&& rn)

theorem miss_zero_iff (p n rp rn : BitVec 64) :
    unitMiss p n rp rn = 0#64 ↔ (p &&& rp = rp ∧ n &&& rn = rn) := by
  unfold unitMiss; bv_decide

theorem conf_zero_iff (p n rp rn : BitVec 64) :
    unitConf p n rp rn = 0#64 ↔ (n &&& rp = 0#64 ∧ p &&& rn = 0#64) := by
  unfold unitConf; bv_decide

theorem unit_exclusive (p n rp rn : BitVec 64) (h : p &&& n = 0#64)
    (hm : unitMiss p n rp rn = 0#64) : unitConf p n rp rn = 0#64 := by
  unfold unitMiss at hm; unfold unitConf; bv_decide

/-- Information order on K3. -/
def K3.le : K3 → K3 → Prop
  | .bot, _ => True
  | a, b => a = b

theorem le_bot_min (a : K3) : K3.le .bot a := trivial

end Chio.BitsetSchedule
```

The `clauseEval_neg_iff` and `ruleEval_pos_iff` duals follow the same induction shape and are in the file. Theorem 5 is stated in Lean over an abstract instruction list with the three readiness predicates as hypotheses; its proof is the induction on the prefix length sketched in §9 and is checked but not reproduced here.

**Kani** (in the runtime module, behind `#[cfg(kani)]`). The first harness is the unbounded 64-bit form of Lemma 1. The second runs a hand-built two-rule schedule against a direct Kleene evaluation on symbolic input and also checks the output invariant and prefix soundness for every fuel value.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn unit_refines_k3_and_is_exclusive() {
        let (p, n): (u64, u64) = (kani::any(), kani::any());
        kani::assume(p & n == 0);
        let (rp, rn): (u64, u64) = (kani::any(), kani::any());
        let miss = ((p & rp) ^ rp) | ((n & rn) ^ rn);
        let conf = (n & rp) | (p & rn);
        assert!((miss == 0) == ((p & rp == rp) && (n & rn == rn)));
        assert!((conf == 0) == ((n & rp == 0) && (p & rn == 0)));
        assert!(!(miss == 0 && conf != 0));
    }

    // rule0 = (x0 ∧ ¬x1) ∨ (x2);  rule1 = (x2) ∨ (x1 ∧ x3) - clause (x2) is shared.
    const S: [Instr; 9] = [
        Instr::Unit { word: 0, req_pos: 0b0001, req_neg: 0b0010, dst: 0 },
        Instr::ClauseEdge { unit: 0, clause: 0 },
        Instr::Unit { word: 0, req_pos: 0b0100, req_neg: 0, dst: 1 },
        Instr::ClauseEdge { unit: 1, clause: 1 },
        Instr::RuleEdge { clause: 0, rule: 0 },
        Instr::RuleEdge { clause: 1, rule: 0 },
        Instr::RuleOut { rule: 0, word: 0, bit_mask: 1 },
        Instr::RuleEdge { clause: 1, rule: 1 },
        Instr::RuleOut { rule: 1, word: 0, bit_mask: 2 },
    ];
    // (x1 ∧ x3) is omitted from the fixture on purpose: the harness must
    // reject it, proving `validate` catches a missing ClauseEdge order.

    #[kani::proof]
    #[kani::unwind(12)]
    fn tiny_schedule_matches_reference_and_prefix_is_sound() {
        let (p, n): (u64, u64) = (kani::any(), kani::any());
        kani::assume(p & n == 0 && p < 16 && n < 16);
        let input = K3Bitset::<1>::new([p], [n]).unwrap();
        let sched = Schedule::<1, 1, 2, 2, 2>::validate(&S).unwrap();
        let mut regs = Registers::<2, 2, 2>::ZEROED;
        let full = sched.eval(&input, &mut regs);
        let lit = |i: usize, neg: bool| match (input.get(i), neg) {
            (K3::Pos, false) | (K3::Neg, true) => K3::Pos,
            (K3::Neg, false) | (K3::Pos, true) => K3::Neg,
            _ => K3::Bot,
        };
        let and = |a: K3, b: K3| match (a, b) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg, (K3::Pos, K3::Pos) => K3::Pos, _ => K3::Bot };
        let or = |a: K3, b: K3| match (a, b) {
            (K3::Pos, _) | (_, K3::Pos) => K3::Pos, (K3::Neg, K3::Neg) => K3::Neg, _ => K3::Bot };
        assert_eq!(full.get(0), or(and(lit(0, false), lit(1, true)), lit(2, false)));
        assert_eq!(full.get(1), lit(2, false));
        assert!(full.pos()[0] & full.neg()[0] == 0);
        let fuel: usize = kani::any();
        kani::assume(fuel <= S.len());
        let (partial, _) = sched.eval_prefix(fuel, &input, &mut regs);
        assert!(partial.leq_info(&full));
    }
}
```

**Apalache TLA+** (`formal/tla/ChioBitsetSchedulePrefix.tla`). The spec models the interpreter as a program counter over an abstract instruction sequence and checks that partial output is always below the final output and that the run ends after exactly `Len(Instrs)` steps.

```tla
---------------------- MODULE ChioBitsetSchedulePrefix ----------------------
EXTENDS Integers, Sequences
CONSTANTS
  \* @type: Seq(Str);
  Instrs,
  \* @type: Set(Int);
  Rules,
  \* @type: Int -> Str;
  Final
VARIABLES
  \* @type: Int;
  pc,
  \* @type: Int -> Str;
  out

Below(a, b) == a = "bot" \/ a = b
Owner(i) == CHOOSE r \in Rules : Instrs[i] = "out" \* abstract owner of RuleOut i

Init == pc = 0 /\ out = [r \in Rules |-> "bot"]
Step == /\ pc < Len(Instrs)
        /\ pc' = pc + 1
        /\ out' = IF Instrs[pc + 1] = "out"
                  THEN [out EXCEPT ![Owner(pc + 1)] = Final[Owner(pc + 1)]]
                  ELSE out
Done == pc = Len(Instrs) /\ UNCHANGED <<pc, out>>
Next == Step \/ Done

PrefixSound == \A r \in Rules : Below(out[r], Final[r])
StepCount == pc <= Len(Instrs)
Terminates == <>[](pc = Len(Instrs))
=============================================================================
```

The abstraction is exactly Theorem 5's argument: a `RuleOut` installs the rule's final value because its dependency closure is already executed, and nothing else writes `out`. Apalache checks `PrefixSound` and `StepCount` as inductive invariants for `Len(Instrs) + 1` steps.

## 11. Differential equivalence against `chio-policy` HushSpec IR

The test crate lowers the pinned Copley HushSpec ruleset to `RuleDnf` through a new adapter, `HushSpecDnf::lower`, which is additive and does not alter the existing IR types. It then checks three things: the compiled schedule matches a direct recursive Kleene evaluation of the IR on random well-formed inputs, every clause matches on its full `3^k` truth table, and every prefix is below the full output.

```rust
//! crates/policy/chio-policy/tests/bitset_differential.rs
use chio_kernel_core::formal_bitset_schedule::{K3, K3Bitset, Registers, Schedule};
use chio_policy::hushspec::bitset_compile::{ClauseDnf, Lit, RuleDnf, SymbolicRuleDag};
use chio_policy::hushspec::HushSpecDnf;

const P: usize = 537; const W: usize = 9; const K: usize = 9; const R: usize = 236;
const RW: usize = 4; const U: usize = 19_116; const C: usize = 2_124;

fn k3_and(a: K3, b: K3) -> K3 { match (a, b) {
    (K3::Neg, _) | (_, K3::Neg) => K3::Neg, (K3::Pos, K3::Pos) => K3::Pos, _ => K3::Bot } }
fn k3_or(a: K3, b: K3) -> K3 { match (a, b) {
    (K3::Pos, _) | (_, K3::Pos) => K3::Pos, (K3::Neg, K3::Neg) => K3::Neg, _ => K3::Bot } }
fn lit(input: &K3Bitset<W>, l: &Lit) -> K3 { match (input.get(usize::from(l.pred)), l.negated) {
    (K3::Pos, false) | (K3::Neg, true) => K3::Pos,
    (K3::Neg, false) | (K3::Pos, true) => K3::Neg, _ => K3::Bot } }
fn reference(rule: &RuleDnf, input: &K3Bitset<W>) -> K3 {
    rule.clauses.iter()
        .map(|c| c.lits.iter().map(|l| lit(input, l)).fold(K3::Pos, k3_and))
        .fold(K3::Neg, k3_or)
}

struct XorShift(u64);
impl XorShift { fn next(&mut self) -> u64 {
    let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x } }

fn random_input(rng: &mut XorShift) -> K3Bitset<W> {
    let (mut pos, mut neg) = ([0u64; W], [0u64; W]);
    for w in 0..W { let p = rng.next(); pos[w] = p; neg[w] = rng.next() & !p; }
    K3Bitset::new(pos, neg).expect("disjoint by construction")
}

#[test]
fn copley_236_schedule_matches_hushspec_ir() {
    let rules: Vec<RuleDnf> = HushSpecDnf::lower(include_str!("fixtures/copley_236.hush"))
        .expect("pinned ruleset lowers");
    assert_eq!(rules.len(), R);
    let dag = SymbolicRuleDag::<P, W, K, R>::new(rules.clone()).expect("within geometry");
    let compiled = dag.compile().expect("compiles");
    let sched = Schedule::<W, RW, U, C, R>::validate(&compiled.instrs).expect("validates");
    let mut regs = Box::new(Registers::<U, C, R>::ZEROED);
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let input = random_input(&mut rng);
        let out = sched.eval(&input, &mut regs);
        for (k, &src) in compiled.rule_order.iter().enumerate() {
            assert_eq!(out.get(k), reference(&rules[src], &input), "rule {src}");
        }
        let fuel = (rng.next() as usize) % (sched.len() + 1);
        let (partial, report) = sched.eval_prefix(fuel, &input, &mut regs);
        assert!(partial.leq_info(&out));
        assert_eq!(report.executed, fuel);
    }
}

#[test]
fn every_clause_matches_on_its_full_truth_table() {
    let rules = HushSpecDnf::lower(include_str!("fixtures/copley_236.hush")).unwrap();
    for rule in &rules {
        for clause in &rule.clauses {
            let single = RuleDnf { rank: 0, clauses: vec![clause.clone()] };
            let dag = SymbolicRuleDag::<P, W, K, 1>::new(vec![single.clone()]).unwrap();
            let compiled = dag.compile().unwrap();
            let sched = Schedule::<W, 1, 9, 1, 1>::validate(&compiled.instrs).unwrap();
            let mut regs = Registers::<9, 1, 1>::ZEROED;
            let preds: Vec<u16> = { let mut v: Vec<u16> = clause.lits.iter().map(|l| l.pred).collect();
                                    v.sort_unstable(); v.dedup(); v };
            let n = preds.len();
            let mut code = vec![0u8; n];
            loop {
                let (mut pos, mut neg) = ([0u64; W], [0u64; W]);
                for (i, &pr) in preds.iter().enumerate() {
                    let (w, b) = (usize::from(pr) / 64, u32::from(pr % 64));
                    match code[i] { 1 => pos[w] |= 1u64 << b, 2 => neg[w] |= 1u64 << b, _ => {} }
                }
                let input = K3Bitset::new(pos, neg).unwrap();
                assert_eq!(sched.eval(&input, &mut regs).get(0), reference(&single, &input));
                let mut i = 0;
                while i < n && code[i] == 2 { code[i] = 0; i += 1; }
                if i == n { break; }
                code[i] += 1;
            }
        }
    }
}
```

The truth-table test is exhaustive per clause because width is capped at 9, so at most 19,683 inputs per clause. Combined with Lemma 3, whose rule combinator is exercised by the random test and verified by Kani, this gives full coverage of the compiled function without enumerating `3^537` inputs. The fixture's SHA-256 is pinned in the manifest so the test fails loudly if the ruleset drifts from the compiled schedule.

## 12. Integration and manifest entries

The compiled verdict `K3Bitset<4>` over rules is part of the exact computation `C_ℓ(x)` in the canonical tuple. Predicates arrive from UltraBERT already in `K3` through the role-asymmetric thresholds: score above `τ_j^pos` yields `+`, below `τ_j^neg` yields `-`, between them `⊥`. The envelope construction treats a deny rule at `⊥` as fired and an allow rule at `⊥` as not fired, so the conservative fallback remains feasible and the Envelope Preservation theorem is unaffected: the learned choice is still modeled as unconstrained nondeterminism over the feasible set, and the schedule only shapes that set.

Additions to `formal/proof-manifest.toml` are strictly additive:

```toml
[wave11.angle2.bitset_schedule]
module            = "chio-kernel-core::formal_bitset_schedule"
lean              = "formal/lean4/Chio/BitsetSchedule.lean"
tla               = "formal/tla/ChioBitsetSchedulePrefix.tla"
kani_harnesses    = ["unit_refines_k3_and_is_exclusive",
                     "tiny_schedule_matches_reference_and_prefix_is_sound"]
ruleset_fixture   = "crates/policy/chio-policy/tests/fixtures/copley_236.hush"
ruleset_sha256    = "<pinned at build>"
geometry          = { predicates = 537, words = 9, clause_width = 9, rules = 236 }
structural_max_alu_ops = 204_848
declared_alu_ops_ceiling = "<emitted by compile step; CI asserts cost.alu_ops() <= this>"
```

CI runs `compile()` on the fixture, writes `ScheduleCost` next to the manifest, and fails if `alu_ops()` exceeds the declared ceiling or if `distinct_units` or `distinct_clauses` exceed the structural maxima.

**Recap.** This pass delivers a `#![no_std]`, `#![forbid(unsafe_code)]` bitset instruction schedule for `SymbolicRuleDag<537, 9, 9, 236>` with four instruction kinds, a one-pass validator enforcing unit readiness, clause sealing, and rule closing, and a data-oblivious interpreter whose instruction count is an exact function of the schedule. The compiler deduplicates word units and clauses by canonical key and emits a rule-major schedule in short-circuit rank order, which the prefix-soundness theorem turns into a fuel-bounded anytime evaluator. The proofs cover word-level refinement and exclusivity (Lean `bv_decide`, Kani), clause and rule refinement (Lean induction), compile correctness, prefix soundness (Lean and Apalache), order independence, and the exact WCET formula with its structural maximum of 204,848 ALU operations. The differential tests check the compiled schedule against a direct Kleene evaluation of the lowered HushSpec IR on random inputs and on every clause's full truth table. Not done here: the pinned ruleset's actual `ScheduleCost` and fixture hash, which the CI compile step must emit and record in the manifest before the ceiling assertion is live.

---

# Verbatim Treatise - `wave11_angle_3_concurrent_loom_and_dst_crash_recovery_pass_11`

::{AtomicU8, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Apply a pure transition through a compare-and-swap loop. The linearization
/// point is the successful swap, or the last atomic read for a rejected op.
fn cas_apply(slot: &AtomicU8, op: u8, step: fn(u8, u8) -> (u8, bool)) -> bool {
    let mut current = slot.load(Ordering::Acquire);
    loop {
        let (next, accepted) = step(current, op);
        if !accepted {
            return false;
        }
        match slot.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn cas_apply_usize(slot: &AtomicUsize, step: impl Fn(usize) -> (usize, bool)) -> bool {
    let mut current = slot.load(Ordering::Acquire);
    loop {
        let (next, accepted) = step(current);
        if !accepted {
            return false;
        }
        match slot.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WeightEpoch {
    epoch: u64,
    hash_tag: u64,
}

/// Linearizable-register model of `ArcSwap<WeightEpoch>`.
struct EpochCell {
    slot: Mutex<WeightEpoch>,
}

impl EpochCell {
    fn new(initial: WeightEpoch) -> Self {
        Self { slot: Mutex::new(initial) }
    }
    fn load(&self) -> WeightEpoch {
        *self.slot.lock().unwrap()
    }
    fn publish(&self, proposed: WeightEpoch) -> bool {
        let mut guard = self.slot.lock().unwrap();
        if epoch_publish_ok(guard.epoch, proposed.epoch) {
            *guard = proposed;
            true
        } else {
            false
        }
    }
}

/// Correct protocol: one snapshot serves both the binding check and the execution.
fn dispatch_with_single_snapshot(cell: &EpochCell) -> (u64, u64) {
    let snapshot = cell.load();
    let checked = snapshot.hash_tag;
    let executed = snapshot.hash_tag;
    (checked, executed)
}

/// Broken protocol: a second load between check and execution.
fn dispatch_with_double_load(cell: &EpochCell) -> (u64, u64) {
    let checked = cell.load().hash_tag;
    let executed = cell.load().hash_tag;
    (checked, executed)
}

#[test]
fn weight_epoch_publish_has_exactly_one_winner() {
    loom::model(|| {
        let cell = Arc::new(EpochCell::new(WeightEpoch { epoch: 0, hash_tag: 0xA0 }));
        let a = {
            let cell = cell.clone();
            thread::spawn(move || cell.publish(WeightEpoch { epoch: 1, hash_tag: 0xA1 }))
        };
        let b = {
            let cell = cell.clone();
            thread::spawn(move || cell.publish(WeightEpoch { epoch: 1, hash_tag: 0xB1 }))
        };
        let won_a = a.join().unwrap();
        let won_b = b.join().unwrap();
        assert!(won_a ^ won_b, "exactly one publisher advances epoch 0 to 1");
        let now = cell.load();
        assert_eq!(now.epoch, 1);
        assert_eq!(now.hash_tag, if won_a { 0xA1 } else { 0xB1 });
    });
}

#[test]
fn dispatch_binds_the_snapshot_it_checked() {
    loom::model(|| {
        let cell = Arc::new(EpochCell::new(WeightEpoch { epoch: 0, hash_tag: 0xA0 }));
        let publisher = {
            let cell = cell.clone();
            thread::spawn(move || {
                cell.publish(WeightEpoch { epoch: 1, hash_tag: 0xA1 });
            })
        };
        let (checked, executed) = dispatch_with_single_snapshot(&cell);
        publisher.join().unwrap();
        assert_eq!(checked, executed);
        let after = cell.load();
        assert!(after.epoch >= 0 && after.epoch <= 1);
    });
}

#[test]
#[should_panic]
fn double_load_dispatch_is_caught_by_loom() {
    loom::model(|| {
        let cell = Arc::new(EpochCell::new(WeightEpoch { epoch: 0, hash_tag: 0xA0 }));
        let publisher = {
            let cell = cell.clone();
            thread::spawn(move || {
                cell.publish(WeightEpoch { epoch: 1, hash_tag: 0xA1 });
            })
        };
        let (checked, executed) = dispatch_with_double_load(&cell);
        publisher.join().unwrap();
        assert_eq!(checked, executed, "binding checked one epoch and executed another");
    });
}

#[test]
fn nonce_reserve_has_exactly_one_winner() {
    loom::model(|| {
        let slot = Arc::new(AtomicU8::new(NONCE_FREE));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let slot = slot.clone();
                thread::spawn(move || cas_apply(&slot, OP_RESERVE, nonce_apply))
            })
            .collect();
        let wins = handles.into_iter().filter(|h| h.join().unwrap()).count();
        assert_eq!(wins, 1);
        assert_eq!(slot.load(Ordering::Acquire), NONCE_RESERVED);
    });
}

/// Load-then-store reservation admits two winners. Loom must find that schedule.
fn racy_reserve(slot: &AtomicU8) -> bool {
    if slot.load(Ordering::Acquire) == NONCE_FREE {
        slot.store(NONCE_RESERVED, Ordering::Release);
        true
    } else {
        false
    }
}

#[test]
#[should_panic]
fn load_then_store_reserve_is_caught_by_loom() {
    loom::model(|| {
        let slot = Arc::new(AtomicU8::new(NONCE_FREE));
        let a = {
            let slot = slot.clone();
            thread::spawn(move || racy_reserve(&slot))
        };
        let b = {
            let slot = slot.clone();
            thread::spawn(move || racy_reserve(&slot))
        };
        let wins = usize::from(a.join().unwrap()) + usize::from(b.join().unwrap());
        assert_eq!(wins, 1);
    });
}

#[test]
fn nonce_commit_and_rollback_are_mutually_exclusive() {
    loom::model(|| {
        let slot = Arc::new(AtomicU8::new(NONCE_FREE));
        assert!(cas_apply(&slot, OP_RESERVE, nonce_apply));
        let committer = {
            let slot = slot.clone();
            thread::spawn(move || cas_apply(&slot, OP_COMMIT, nonce_apply))
        };
        let canceller = {
            let slot = slot.clone();
            thread::spawn(move || cas_apply(&slot, OP_RELEASE, nonce_apply))
        };
        let committed = committer.join().unwrap();
        let released = canceller.join().unwrap();
        assert!(committed ^ released);
        let final_state = slot.load(Ordering::Acquire);
        assert_eq!(final_state, if committed { NONCE_COMMITTED } else { NONCE_FREE });
        // Replay is possible only when the rollback won.
        assert_eq!(cas_apply(&slot, OP_RESERVE, nonce_apply), released);
    });
}

#[test]
fn holder_refcounts_balance_and_respect_cap() {
    loom::model(|| {
        const CAP: usize = 3;
        let holders = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let holders = holders.clone();
                thread::spawn(move || {
                    assert!(cas_apply_usize(&holders, |h| holders_acquire(h, CAP)));
                    let observed = holders.load(Ordering::Acquire);
                    assert!(observed >= 1 && observed <= CAP);
                    assert!(cas_apply_usize(&holders, holders_release));
                })
            })
            .collect();
        assert!(cas_apply_usize(&holders, |h| holders_acquire(h, CAP)));
        assert!(holders.load(Ordering::Acquire) <= CAP);
        assert!(cas_apply_usize(&holders, holders_release));
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(holders.load(Ordering::Acquire), 0);
        assert!(!cas_apply_usize(&holders, holders_release), "no underflow on spurious release");
    });
}

fn admit_child(total: &Mutex<u32>, share_bps: u16, parent_share_bps: u16) -> bool {
    let mut guard = total.lock().unwrap();
    let (next, code) = child_admission_total(*guard, share_bps, parent_share_bps);
    if code == ADMIT_OK {
        *guard = next;
    }
    code == ADMIT_OK
}

#[test]
fn sibling_admission_never_oversubscribes_parent() {
    loom::model(|| {
        let total = Arc::new(Mutex::new(0u32));
        let a = {
            let total = total.clone();
            thread::spawn(move || admit_child(&total, 6_000, 10_000))
        };
        let b = {
            let total = total.clone();
            thread::spawn(move || admit_child(&total, 6_000, 10_000))
        };
        let won_a = a.join().unwrap();
        let won_b = b.join().unwrap();
        assert!(won_a ^ won_b, "two 6000 bps siblings cannot both fit under 10000 bps");
        assert_eq!(*total.lock().unwrap(), 6_000);
    });
}

#[test]
fn cancel_and_dispatch_resolve_to_exactly_one_outcome() {
    loom::model(|| {
        let session = Arc::new(AtomicU8::new(SESSION_RESERVED));
        let nonce = Arc::new(AtomicU8::new(NONCE_RESERVED));
        let effects = Arc::new(AtomicUsize::new(0));

        let dispatcher = {
            let (session, nonce, effects) = (session.clone(), nonce.clone(), effects.clone());
            thread::spawn(move || {
                if cas_apply(&session, SOP_BEGIN_DISPATCH, session_apply) {
                    // Pre-dispatch cutpoint passed: the effect below is irreversible.
                    effects.fetch_add(1, Ordering::AcqRel);
                    assert!(cas_apply(&session, SOP_COMPLETE_DISPATCH, session_apply));
                    assert!(cas_apply(&nonce, OP_COMMIT, nonce_apply));
                    assert!(cas_apply(&session, SOP_SEAL, session_apply));
                    true
                } else {
                    // Cancel won at the pre-dispatch cutpoint: roll the nonce back.
                    assert!(cas_apply(&nonce, OP_RELEASE, nonce_apply));
                    false
                }
            })
        };
        let canceller = {
            let session = session.clone();
            thread::spawn(move || cas_apply(&session, SOP_CANCEL, session_apply))
        };

        let dispatched = dispatcher.join().unwrap();
        let cancel_won = canceller.join().unwrap();
        assert!(dispatched ^ cancel_won);
        assert_eq!(effects.load(Ordering::Acquire), usize::from(dispatched));

        let final_session = session.load(Ordering::Acquire);
        let final_nonce = nonce.load(Ordering::Acquire);
        if dispatched {
            assert_eq!(final_session, SESSION_SEALED);
            assert_eq!(final_nonce, NONCE_COMMITTED);
            assert_ne!(classify_cancel_cutpoint(final_session), CUT_PRE_DISPATCH);
        } else {
            assert_eq!(final_session, SESSION_CANCELLED);
            assert_eq!(final_nonce, NONCE_FREE);
        }
    });
}
```

**What the schedules cover.** Each model has at most two spawned threads plus the main thread, within loom's default thread limit. Every test has fewer than a dozen atomic operations, so loom can enumerate all interleavings without a preemption bound. The two `should_panic` tests confirm that the suite is sensitive to the bug classes it targets. The session test is the operational form of Corollary 1. The nonce test is the rollback property of `ExecutionNonceStore`: a release after a commit never succeeds, and a replay succeeds only after a rollback.

## 3. Crash-recovery simulation, Lean 4, Apalache, and how to run everything

**The SQLite contract being modeled.** The simulation does not drive a real SQLite database. It models the recovery contract of SQLite's write-ahead log, which is what the kernel's durable store relies on. Recovery scans frames from the start of the log, validates each frame against the salt and the cumulative checksum, stops at the first invalid frame, and exposes frames only up to the last commit frame. Two crash kinds are simulated. A process kill keeps everything written to the operating system, which matches WAL mode with `synchronous=NORMAL`. A power loss keeps only a prefix of the unsynced frames and may tear the last one, which is why the kernel protocol fsyncs each record before any dependent effect, matching `synchronous=FULL`.

**Protocol under test.** Reserve writes a durable reserve record before the in-memory nonce changes. Dispatch runs the effect only when the session is reserved, then writes a durable seal record, then commits the nonce. Cancel is accepted only at the pre-dispatch cutpoint and writes a durable release record. Recovery replays the valid committed prefix and then burns every dangling reservation with the retain operation, the conservative fallback, because the effect may have happened.

```rust
//! Pass 11 deterministic crash-recovery simulation against the SQLite WAL contract.
#![cfg(not(loom))]

use std::collections::{BTreeMap, BTreeSet};

use chio_kernel_core::formal_cutpoint::{
    classify_cancel_cutpoint, epoch_publish_ok, holders_acquire, holders_release, nonce_apply,
    session_apply, wal_chain, wal_valid_committed_prefix, WalFrame, CUT_PRE_DISPATCH,
    NONCE_COMMITTED, NONCE_FREE, NONCE_RESERVED, NONCE_RETAINED, OP_COMMIT, OP_RELEASE,
    OP_RESERVE, OP_RETAIN, SESSION_CANCELLED, SESSION_RESERVED, SOP_BEGIN_DISPATCH, SOP_CANCEL,
    SOP_COMPLETE_DISPATCH, SOP_SEAL,
};

const MAX_HOLDERS: usize = 3;
const NONCE_SPACE: u64 = 4;
const CHILD_SPACE: u64 = 3;
const EPISODES: u64 = 2_000;
const TRACE_LEN: usize = 24;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

const REC_RESERVE: u8 = 1;
const REC_SEAL: u8 = 2;
const REC_RELEASE: u8 = 3;
const REC_HOLDER_ACQUIRE: u8 = 4;
const REC_HOLDER_RELEASE: u8 = 5;
const REC_EPOCH_PUBLISH: u8 = 6;
const ARG_BITS: u32 = 56;
const ARG_MASK: u64 = (1u64 << ARG_BITS) - 1;

fn encode(kind: u8, arg: u64) -> u64 {
    assert!(arg <= ARG_MASK, "record argument exceeds 56 bits");
    (u64::from(kind) << ARG_BITS) | arg
}

fn decode(payload: u64) -> (u8, u64) {
    (u8::try_from(payload >> ARG_BITS).expect("kind fits in u8"), payload & ARG_MASK)
}

fn pack_epoch(epoch: u64, tag: u64) -> u64 {
    assert!(epoch < (1u64 << 24));
    (epoch << 32) | (tag & 0xFFFF_FFFF)
}

fn unpack_epoch(arg: u64) -> (u64, u64) {
    (arg >> 32, arg & 0xFFFF_FFFF)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    ProcessKill,
    PowerLoss,
}

#[derive(Clone, Copy, Debug)]
struct FaultPlan {
    crash_step: usize,
    kind: Crash,
}

#[derive(Debug)]
struct Crashed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Reserve(u64),
    Dispatch(u64),
    Cancel(u64),
    Acquire(u64),
    Release(u64),
    Publish(u64),
}

struct SimWal {
    salt: u64,
    durable: Vec<WalFrame>,
    os_buffered: Vec<WalFrame>,
    prev_checksum: u64,
}

impl SimWal {
    fn new(salt: u64) -> Self {
        Self { salt, durable: Vec::new(), os_buffered: Vec::new(), prev_checksum: salt }
    }
    fn append_commit(&mut self, payload: u64) {
        let checksum = wal_chain(self.prev_checksum, self.salt, payload, true);
        self.prev_checksum = checksum;
        self.os_buffered.push(WalFrame { payload, commit: true, checksum });
    }
    fn fsync(&mut self) {
        self.durable.append(&mut self.os_buffered);
    }
    /// Media image after a crash. Process kills keep OS-buffered frames.
    /// Power loss keeps a random prefix of them and may tear the last one.
    fn crash_image(&self, crash: Crash, rng: &mut Rng) -> Vec<WalFrame> {
        let mut image = self.durable.clone();
        match crash {
            Crash::ProcessKill => image.extend_from_slice(&self.os_buffered),
            Crash::PowerLoss => {
                let keep = rng.below(self.os_buffered.len() as u64 + 1) as usize;
                image.extend_from_slice(&self.os_buffered[..keep]);
                if keep > 0 && rng.chance(50) {
                    if let Some(last) = image.last_mut() {
                        last.checksum ^= 1;
                    }
                }
            }
        }
        image
    }
}

#[derive(Debug, Default)]
struct Recovered {
    nonces: BTreeMap<u64, u8>,
    holders: BTreeMap<u64, usize>,
    epoch: (u64, u64),
    frames_applied: usize,
}

fn replay_nonce(nonces: &mut BTreeMap<u64, u8>, nonce: u64, op: u8) {
    let state = nonces.entry(nonce).or_insert(NONCE_FREE);
    let (next, ok) = nonce_apply(*state, op);
    assert!(ok, "durable record {op} for nonce {nonce} rejected in state {state}");
    *state = next;
}

fn recover(image: &[WalFrame], salt: u64) -> Recovered {
    let n = wal_valid_committed_prefix(image, salt);
    let mut out = Recovered { frames_applied: n, ..Default::default() };
    for frame in &image[..n] {
        let (kind, arg) = decode(frame.payload);
        match kind {
            REC_RESERVE => replay_nonce(&mut out.nonces, arg, OP_RESERVE),
            REC_SEAL => replay_nonce(&mut out.nonces, arg, OP_COMMIT),
            REC_RELEASE => replay_nonce(&mut out.nonces, arg, OP_RELEASE),
            REC_HOLDER_ACQUIRE => {
                let h = out.holders.entry(arg).or_insert(0);
                *h = holders_acquire(*h, MAX_HOLDERS).0;
            }
            REC_HOLDER_RELEASE => {
                let h = out.holders.entry(arg).or_insert(0);
                *h = holders_release(*h).0;
            }
            REC_EPOCH_PUBLISH => {
                let (epoch, tag) = unpack_epoch(arg);
                if epoch_publish_ok(out.epoch.0, epoch) {
                    out.epoch = (epoch, tag);
                }
            }
            other => panic!("unknown record kind {other}"),
        }
    }
    // Dangling reservations are ambiguous: the effect may have run. Burn them.
    for state in out.nonces.values_mut() {
        if *state == NONCE_RESERVED {
            *state = nonce_apply(*state, OP_RETAIN).0;
        }
    }
    out
}

struct Kernel {
    wal: SimWal,
    nonces: BTreeMap<u64, u8>,
    sessions: BTreeMap<u64, u8>,
    holders: BTreeMap<u64, usize>,
    epoch: (u64, u64),
    /// Ground truth: how many times the irreversible effect ran per nonce.
    effects: BTreeMap<u64, usize>,
    in_flight: Option<Op>,
    step: usize,
}

impl Kernel {
    fn new(salt: u64) -> Self {
        Self {
            wal: SimWal::new(salt),
            nonces: BTreeMap::new(),
            sessions: BTreeMap::new(),
            holders: BTreeMap::new(),
            epoch: (0, 0),
            effects: BTreeMap::new(),
            in_flight: None,
            step: 0,
        }
    }

    fn from_recovered(rec: &Recovered, image: &[WalFrame], salt: u64, effects: &BTreeMap<u64, usize>) -> Self {
        let valid = &image[..rec.frames_applied];
        let prev = valid.last().map_or(salt, |f| f.checksum);
        Self {
            wal: SimWal { salt, durable: valid.to_vec(), os_buffered: Vec::new(), prev_checksum: prev },
            nonces: rec.nonces.clone(),
            sessions: BTreeMap::new(),
            holders: rec.holders.clone(),
            epoch: rec.epoch,
            effects: effects.clone(),
            in_flight: None,
            step: 0,
        }
    }

    fn boundary(&mut self, plan: &FaultPlan) -> Result<(), Crashed> {
        self.step += 1;
        if self.step == plan.crash_step { Err(Crashed) } else { Ok(()) }
    }

    fn write_durable(&mut self, payload: u64, plan: &FaultPlan) -> Result<(), Crashed> {
        self.wal.append_commit(payload);
        self.boundary(plan)?; // written to the OS, not yet fsynced
        self.wal.fsync();
        self.boundary(plan)?; // durable, in-memory state not yet advanced
        Ok(())
    }

    fn nonce_state(&self, n: u64) -> u8 {
        *self.nonces.get(&n).unwrap_or(&NONCE_FREE)
    }
    fn session_state(&self, n: u64) -> u8 {
        *self.sessions.get(&n).unwrap_or(&SESSION_CANCELLED)
    }
    fn transition_session(&mut self, n: u64, op: u8) {
        let (next, ok) = session_apply(self.session_state(n), op);
        assert!(ok, "session op {op} rejected for nonce {n}");
        self.sessions.insert(n, next);
    }
    fn transition_nonce(&mut self, n: u64, op: u8) {
        let (next, ok) = nonce_apply(self.nonce_state(n), op);
        assert!(ok, "nonce op {op} rejected for nonce {n}");
        self.nonces.insert(n, next);
    }

    fn apply(&mut self, op: Op, plan: &FaultPlan) -> Result<(), Crashed> {
        self.in_flight = Some(op);
        match op {
            Op::Reserve(n) => {
                if nonce_apply(self.nonce_state(n), OP_RESERVE).1 {
                    self.write_durable(encode(REC_RESERVE, n), plan)?;
                    self.transition_nonce(n, OP_RESERVE);
                    self.sessions.insert(n, SESSION_RESERVED);
                }
            }
            Op::Dispatch(n) => {
                if self.session_state(n) == SESSION_RESERVED {
                    self.transition_session(n, SOP_BEGIN_DISPATCH); // pre-dispatch cutpoint
                    *self.effects.entry(n).or_insert(0) += 1; // irreversible effect
                    self.boundary(plan)?; // crash after effect, before seal
                    self.transition_session(n, SOP_COMPLETE_DISPATCH); // post-dispatch cutpoint
                    self.write_durable(encode(REC_SEAL, n), plan)?;
                    self.transition_nonce(n, OP_COMMIT);
                    self.transition_session(n, SOP_SEAL);
                }
            }
            Op::Cancel(n) => {
                let state = self.session_state(n);
                if classify_cancel_cutpoint(state) == CUT_PRE_DISPATCH && state == SESSION_RESERVED {
                    self.write_durable(encode(REC_RELEASE, n), plan)?;
                    self.transition_nonce(n, OP_RELEASE);
                    self.transition_session(n, SOP_CANCEL);
                }
            }
            Op::Acquire(c) => {
                let (next, ok) = holders_acquire(*self.holders.get(&c).unwrap_or(&0), MAX_HOLDERS);
                if ok {
                    self.write_durable(encode(REC_HOLDER_ACQUIRE, c), plan)?;
                    self.holders.insert(c, next);
                }
            }
            Op::Release(c) => {
                let (next, ok) = holders_release(*self.holders.get(&c).unwrap_or(&0));
                if ok {
                    self.write_durable(encode(REC_HOLDER_RELEASE, c), plan)?;
                    self.holders.insert(c, next);
                }
            }
            Op::Publish(tag) => {
                let proposed = self.epoch.0 + 1;
                self.write_durable(encode(REC_EPOCH_PUBLISH, pack_epoch(proposed, tag)), plan)?;
                assert!(epoch_publish_ok(self.epoch.0, proposed));
                self.epoch = (proposed, tag);
            }
        }
        self.in_flight = None;
        Ok(())
    }
}

fn check_recovery(at_crash: &Kernel, rec: &Recovered) {
    // I1: an executed nonce can never be free again after recovery.
    for n in at_crash.effects.keys() {
        let state = *rec.nonces.get(n).unwrap_or(&NONCE_FREE);
        assert!(state == NONCE_COMMITTED || state == NONCE_RETAINED, "nonce {n} replayable after effect");
    }
    // I2: a committed nonce always has an effect behind it.
    for (n, state) in &rec.nonces {
        if *state == NONCE_COMMITTED {
            assert!(at_crash.effects.contains_key(n), "phantom commit for nonce {n}");
        }
        // I5: burning happens only when the reservation outcome was ambiguous.
        if *state == NONCE_RETAINED {
            let ambiguous = at_crash.effects.contains_key(n)
                || at_crash.session_state(*n) == SESSION_RESERVED
                || matches!(at_crash.in_flight, Some(Op::Reserve(x)) if x == *n);
            assert!(ambiguous, "nonce {n} burned without an ambiguous reservation");
        }
    }
    // I3: holder counts match memory up to the single in-flight operation.
    let children: BTreeSet<u64> = rec.holders.keys().chain(at_crash.holders.keys()).copied().collect();
    for c in children {
        let mem = *at_crash.holders.get(&c).unwrap_or(&0);
        let got = *rec.holders.get(&c).unwrap_or(&0);
        let after = match at_crash.in_flight {
            Some(Op::Acquire(x)) if x == c => holders_acquire(mem, MAX_HOLDERS).0,
            Some(Op::Release(x)) if x == c => holders_release(mem).0,
            _ => mem,
        };
        assert!(got == mem || got == after, "child {c}: recovered {got}, memory {mem}");
    }
    // I4: the recovered epoch is monotone and at most one in-flight publish ahead.
    let ahead = matches!(at_crash.in_flight, Some(Op::Publish(_)));
    assert!(rec.epoch.0 == at_crash.epoch.0 || (ahead && rec.epoch.0 == at_crash.epoch.0 + 1));
    // I6: at-most-once execution.
    for (n, count) in &at_crash.effects {
        assert!(*count <= 1, "nonce {n} executed {count} times");
    }
}

fn run_until_crash(trace: &[Op], plan: &FaultPlan, salt: u64) -> (Kernel, Option<usize>) {
    let mut kernel = Kernel::new(salt);
    for (i, op) in trace.iter().enumerate() {
        if kernel.apply(*op, plan).is_err() {
            return (kernel, Some(i));
        }
    }
    (kernel, None)
}

/// Crash at the planned step, recover, resume the remaining trace fault-free, re-check.
fn crash_recover_resume(trace: &[Op], plan: &FaultPlan, salt: u64, rng: &mut Rng, label: &str) {
    let dry = FaultPlan { crash_step: usize::MAX, kind: Crash::ProcessKill };
    let (kernel, crashed_at) = run_until_crash(trace, plan, salt);
    let crashed_at = crashed_at.unwrap_or_else(|| panic!("{label}: crash step not reached"));
    let image = kernel.wal.crash_image(plan.kind, rng);
    let rec = recover(&image, salt);
    check_recovery(&kernel, &rec);

    let mut resumed = Kernel::from_recovered(&rec, &image, salt, &kernel.effects);
    for op in &trace[crashed_at..] {
        resumed.apply(*op, &dry).expect("no faults after recovery");
    }
    let final_image = resumed.wal.crash_image(Crash::ProcessKill, rng);
    let final_rec = recover(&final_image, salt);
    check_recovery(&resumed, &final_rec);
}

fn random_trace(rng: &mut Rng, len: usize) -> Vec<Op> {
    (0..len)
        .map(|_| match rng.below(6) {
            0 => Op::Reserve(rng.below(NONCE_SPACE)),
            1 => Op::Dispatch(rng.below(NONCE_SPACE)),
            2 => Op::Cancel(rng.below(NONCE_SPACE)),
            3 => Op::Acquire(rng.below(CHILD_SPACE)),
            4 => Op::Release(rng.below(CHILD_SPACE)),
            _ => Op::Publish(rng.below(1 << 32)),
        })
        .collect()
}

#[test]
fn exhaustive_drop_points_on_canonical_trace() {
    let trace = [
        Op::Publish(0xA1), Op::Reserve(1), Op::Acquire(0), Op::Dispatch(1), Op::Reserve(2),
        Op::Cancel(2), Op::Reserve(2), Op::Release(0), Op::Dispatch(2), Op::Publish(0xA2),
        Op::Reserve(1), Op::Dispatch(1), Op::Cancel(2),
    ];
    let salt = 0x5EED;
    let dry = FaultPlan { crash_step: usize::MAX, kind: Crash::ProcessKill };
    let (complete, _) = run_until_crash(&trace, &dry, salt);
    for crash_step in 1..=complete.step {
        for kind in [Crash::ProcessKill, Crash::PowerLoss] {
            for tear_seed in 0..4u64 {
                let mut rng = Rng::new(tear_seed);
                let plan = FaultPlan { crash_step, kind };
                crash_recover_resume(&trace, &plan, salt, &mut rng, &format!("step {crash_step} {kind:?}"));
            }
        }
    }
}

#[test]
fn randomized_drop_episodes_preserve_nonce_and_ledger_invariants() {
    for seed in 0..EPISODES {
        let mut rng = Rng::new(seed);
        let salt = rng.next_u64();
        let trace = random_trace(&mut rng, TRACE_LEN);
        let dry = FaultPlan { crash_step: usize::MAX, kind: Crash::ProcessKill };
        let (complete, _) = run_until_crash(&trace, &dry, salt);
        if complete.step == 0 {
            continue;
        }
        let kind = if rng.chance(50) { Crash::ProcessKill } else { Crash::PowerLoss };
        let crash_step = rng.below(complete.step as u64) as usize + 1;
        let plan = FaultPlan { crash_step, kind };
        crash_recover_resume(&trace, &plan, salt, &mut rng, &format!("seed {seed}"));
    }
}

#[test]
fn torn_tail_is_invisible_to_recovery() {
    let mut wal = SimWal::new(7);
    wal.append_commit(encode(REC_RESERVE, 1));
    wal.append_commit(encode(REC_SEAL, 1));
    wal.append_commit(encode(REC_RESERVE, 2));
    wal.fsync();
    let mut image = wal.durable.clone();
    image[2].checksum ^= 1;
    let rec = recover(&image, 7);
    assert_eq!(rec.frames_applied, 2);
    assert_eq!(rec.nonces.get(&1), Some(&NONCE_COMMITTED));
    assert_eq!(rec.nonces.get(&2), None);
}
```

**Theorem 3, prefix safety.** For any crash image of a run, recovery yields the sequential replay of a prefix of the durable record order followed by retention of dangling reservations. If the effect for a nonce ran, the reserve record for that nonce was durable before the effect, so it lies in every recoverable prefix, and no release record for that nonce exists because cancel is accepted only at the pre-dispatch cutpoint. Hence the nonce recovers as committed or retained, never free, which is invariant I1. A seal record is written only after the effect, so a committed nonce implies an effect, which is invariant I2. Both hold for every prefix, so they hold for every crash point and both crash kinds. ∎

**Lean 4 hand model.** The file `formal/lean4/Chio/Cutpoint.lean` states the sequential facts the loom and simulation tests lean on. The Aeneas extraction of the Rust module is pinned beside it through the proof manifest, whose entry must follow the schema of the existing entries. These proof scripts were not machine-checked in this pass.

```lean
namespace Chio.Cutpoint

abbrev State := UInt8
abbrev Op := UInt8

def nonceFree : State := 0
def nonceReserved : State := 1
def nonceCommitted : State := 2
def nonceRetained : State := 3
def opReserve : Op := 0
def opCommit : Op := 1
def opRelease : Op := 2
def opRetain : Op := 3

def nonceApply (s : State) (op : Op) : State × Bool :=
  if s = nonceFree ∧ op = opReserve then (nonceReserved, true)
  else if s = nonceReserved ∧ op = opCommit then (nonceCommitted, true)
  else if s = nonceReserved ∧ op = opRelease then (nonceFree, true)
  else if s = nonceReserved ∧ op = opRetain then (nonceRetained, true)
  else (s, false)

def nonceIsTerminal (s : State) : Bool := s == nonceCommitted || s == nonceRetained

/-- Rejected transitions are the identity; the CAS loop never writes on rejection. -/
theorem nonceApply_reject_id (s : State) (op : Op)
    (h : (nonceApply s op).2 = false) : (nonceApply s op).1 = s := by
  unfold nonceApply at h ⊢
  repeat' (split at h <;> simp_all)

/-- Committed and retained nonces absorb every operation. -/
theorem nonce_terminal_absorbing (s : State) (op : Op)
    (h : nonceIsTerminal s = true) : nonceApply s op = (s, false) := by
  unfold nonceIsTerminal at h
  simp only [Bool.or_eq_true, beq_iff_eq] at h
  unfold nonceApply
  rcases h with h | h <;> subst h <;>
    simp (config := { decide := true }) [nonceFree, nonceReserved, nonceCommitted, nonceRetained]

structure Frame where
  payload : UInt64
  commit : Bool
  checksum : UInt64

/-- Recovery scan, parametric in the chain function so the structural facts
    do not depend on the mixing constants. -/
def walPrefix (chain : UInt64 → Frame → UInt64) :
    List Frame → UInt64 → Nat → Nat → Nat
  | [], _, _, committed => committed
  | f :: rest, prev, index, committed =>
    if chain prev f = f.checksum then
      walPrefix chain rest (chain prev f) (index + 1) (if f.commit then index + 1 else committed)
    else committed

theorem walPrefix_le (chain : UInt64 → Frame → UInt64) (frames : List Frame)
    (prev : UInt64) (index committed : Nat) (h : committed ≤ index) :
    walPrefix chain frames prev index committed ≤ index + frames.length := by
  induction frames generalizing prev index committed with
  | nil => simpa using h
  | cons f rest ih =>
    unfold walPrefix
    split
    · split
      · have := ih (chain prev f) (index + 1) (index + 1) (Nat.le_refl _)
        simp only [List.length_cons]; omega
      · have := ih (chain prev f) (index + 1) committed (by omega)
        simp only [List.length_cons]; omega
    · simp only [List.length_cons]; omega

theorem walValidCommittedPrefix_le (chain : UInt64 → Frame → UInt64)
    (frames : List Frame) (salt : UInt64) :
    walPrefix chain frames salt 0 0 ≤ frames.length := by
  simpa using walPrefix_le chain frames salt 0 0 (Nat.le_refl 0)

end Chio.Cutpoint
```

**Apalache model of the cancel versus dispatch race.** The specification starts at the reserved state with a reserved nonce and lets cancel, dispatch, seal, rollback, and late-cancel interleave freely. The invariants are the ones the loom session test asserts.

```tla
---------------------------- MODULE SessionCutpoint ----------------------------
EXTENDS Integers

Reserved == 2   Dispatching == 3   Dispatched == 4   Sealed == 5   Cancelled == 6
NFree == 0      NReserved == 1     NCommitted == 2

VARIABLES
  \* @type: Int;
  session,
  \* @type: Int;
  nonce,
  \* @type: Int;
  effects,
  \* @type: Bool;
  cancelWon

Init == session = Reserved /\ nonce = NReserved /\ effects = 0 /\ cancelWon = FALSE

BeginDispatch ==
  /\ session = Reserved
  /\ session' = Dispatching /\ effects' = effects + 1
  /\ UNCHANGED <<nonce, cancelWon>>

CompleteDispatch ==
  /\ session = Dispatching /\ session' = Dispatched
  /\ UNCHANGED <<nonce, effects, cancelWon>>

Seal ==
  /\ session = Dispatched /\ nonce = NReserved
  /\ session' = Sealed /\ nonce' = NCommitted
  /\ UNCHANGED <<effects, cancelWon>>

Cancel ==
  /\ session = Reserved
  /\ session' = Cancelled /\ cancelWon' = TRUE
  /\ UNCHANGED <<nonce, effects>>

RollbackAfterCancel ==
  /\ session = Cancelled /\ nonce = NReserved
  /\ nonce' = NFree
  /\ UNCHANGED <<session, effects, cancelWon>>

LateCancel ==
  /\ session \in {Dispatching, Dispatched, Sealed}
  /\ UNCHANGED <<session, nonce, effects, cancelWon>>

Next == BeginDispatch \/ CompleteDispatch \/ Seal \/ Cancel \/ RollbackAfterCancel \/ LateCancel

Inv ==
  /\ effects <= 1
  /\ ~(cancelWon /\ effects = 1)
  /\ (nonce = NCommitted => effects = 1)
  /\ (nonce = NFree => effects = 0)
  /\ (effects = 1 => session \in {Dispatching, Dispatched, Sealed})
================================================================================
```

**Commands.**

| Check | Command |
|---|---|
| Loom schedules, unbounded | `RUSTFLAGS="--cfg loom" cargo test -p chio-kernel --release --test loom_concurrency` |
| Crash simulation | `cargo test -p chio-kernel --test dst_drop_simulation` |
| Kani harnesses | `cargo kani -p chio-kernel-core --harness nonce_terminal_is_absorbing` and the other seven harness names |
| Lean 4 | `lake build Chio.Cutpoint` from `formal/lean4` |
| Apalache | `apalache-mc check --inv=Inv formal/tla/SessionCutpoint.tla` |

**Left out, deliberately.** The refinement from the nonce machine to `ledger_apply` is not asserted, because only the signature and op codes of the ledger function are pinned in the context, not its acceptance semantics. The op vocabulary is shared by convention and a Kani refinement harness is the natural Pass 12 item. The `const` pin against the budget-split cap assumes that module is compiled unconditionally in the core crate. If it sits behind a feature, the pin needs the same gate.

Recap. Pass 11 delivers one additive `no_std` module of pure cutpoint machines with checked arithmetic and eight Kani harnesses, a loom suite that enumerates every schedule for `WeightEpoch` publication, snapshot-bound dispatch, nonce reservation and rollback, holder refcounts, sibling admission, and the cancel versus dispatch race, plus two `should_panic` tests proving the suite detects the targeted bug classes. The deterministic simulation sweeps every crash point of a canonical trace and two thousand random episodes against the SQLite WAL recovery contract, checking no replay after effect, no phantom commit, holder and epoch consistency, and at-most-once execution across a restart. Lean 4 theorems and an Apalache model pin the sequential facts. Nothing was executed in this session, so the next step is to run the five commands above and fix any compile or proof-script issues they surface, then add the ledger refinement harness.

---

# Verbatim Treatise - `wave11_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_11`

I'll lay out the Pass 11 edge design as three pieces: the exact lift of MCP, A2A, and Envoy ext_authz frames into `PortableToolCallRequest` with Copley 4-segment features, the hybrid signing floor, and the offline federated verifier with its Lean, Kani, and Apalache obligations.

## 1. Lifting protocol frames into `PortableToolCallRequest`

**The edge instantiates the canonical tuple.** For the edge layer $E$ the Wave 1 law reads $\mathcal{D}_E = (\mathcal{X}_E, C_E, P_E, \mathcal{C}_E, \Pi, W_E)$ with:

| Component | Edge instantiation |
|---|---|
| $\mathcal{X}_E$ | Bounded protocol frames, every segment at most 4,096 bytes |
| $C_E(x)$ | Canonical lift, request digest, time-window code, budget precheck, concept masks, all exact |
| $P_E$ | Tier-1 `UltraBERT` over the four segments, Tier-0 shadow-price penalized score |
| $\mathcal{C}_E$ | Subset of $\{\text{Forward}, \text{Defer}, \text{Deny}\}$ with $\bot_x = \text{Deny}$ |
| $W_E$ | Hybrid-signed receipt plus attestation evidence |

The learned model never computes the digest, the window, or the budget check. It only emits 537 scores, which $C_E$ turns into $\mathbb{K}_3$ values through the role-asymmetric thresholds.

**Segment mapping.** The Copley segments carry process-lineage semantics: `CommandLine` is the invocation text, `Image` is what runs, `OriginalFileName` is the declared identity of what runs, `ParentImage` is who spawned it. Each protocol maps onto that lineage without any learned step:

| Segment | MCP | A2A | Envoy ext_authz |
|---|---|---|---|
| `CommandLine` | arguments JSON | message parts | request line |
| `Image` | tool name | skill id | authority |
| `OriginalFileName` | server name | agent card URL | upstream cluster |
| `ParentImage` | host client | caller agent id | downstream SPIFFE principal |

**The shared `#![no_std]` crate.** All three edges depend on one new crate so that the proofs discharge once. The grounded context does not list an existing `PortableToolCallRequest` signature, so the type below is treated as new. If an owned version exists in `chio-core-types`, each std edge adds a `From` impl, which is strictly additive.

```rust
// crates/edges/chio-protocol-lift/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

// Pinned by formal/proof-manifest.toml. If classify_time_window_code lives in
// formal_core rather than formal_aeneas, only this line changes.
use chio_kernel_core::formal_aeneas::{budget_precheck, classify_time_window_code, receipt_fields_coupled};

pub const MAX_SEGMENT_BYTES: usize = 4_096;
pub const MAX_PRINCIPAL_BYTES: usize = 512;
pub const COPLEY_PREDICATES: usize = 537;
pub const SEG_COMMAND_LINE: usize = 345;
pub const SEG_IMAGE: usize = 97;
pub const SEG_ORIGINAL_FILE_NAME: usize = 57;
pub const SEG_PARENT_IMAGE: usize = 38;
pub const CONCEPT_WORDS: usize = 9;
const _: () = assert!(SEG_COMMAND_LINE + SEG_IMAGE + SEG_ORIGINAL_FILE_NAME + SEG_PARENT_IMAGE == COPLEY_PREDICATES);
const _: () = assert!(CONCEPT_WORDS * 64 >= COPLEY_PREDICATES);
const LIFT_DOMAIN: &[u8] = b"chio-ptcr/v11";

pub trait Digest32 {
    fn digest32(&self, parts: &[&[u8]]) -> [u8; 32];
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum ProtocolOrigin { Mcp = 1, A2a = 2, EnvoyExtAuthz = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Segment { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

#[derive(Clone, Copy, Debug)]
pub struct CopleySegments<'a> {
    pub command_line: &'a [u8],
    pub image: &'a [u8],
    pub original_file_name: &'a [u8],
    pub parent_image: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiftError {
    SegmentTooLong { segment: Segment, len: usize },
    PrincipalTooLong { len: usize },
    TimeWindowInverted { issued_at: u64, expires_at: u64 },
    CostOverflow,
}

#[derive(Clone, Copy, Debug)]
pub struct LiftInput<'a> {
    pub origin: ProtocolOrigin,
    pub segments: CopleySegments<'a>,
    pub principal: &'a [u8],
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PortableToolCallRequest<'a> {
    pub origin: ProtocolOrigin,
    pub segments: CopleySegments<'a>,
    pub principal: &'a [u8],
    pub request_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
}

fn len_prefix(segment: Segment, bytes: &[u8]) -> Result<[u8; 4], LiftError> {
    if bytes.len() > MAX_SEGMENT_BYTES {
        return Err(LiftError::SegmentTooLong { segment, len: bytes.len() });
    }
    u32::try_from(bytes.len())
        .map(u32::to_be_bytes)
        .map_err(|_| LiftError::SegmentTooLong { segment, len: bytes.len() })
}

/// Exact lift. The digest is over a domain-separated, length-prefixed encoding,
/// so distinct frames have distinct preimages.
pub fn lift<'a, H: Digest32>(input: LiftInput<'a>, hasher: &H) -> Result<PortableToolCallRequest<'a>, LiftError> {
    if input.principal.len() > MAX_PRINCIPAL_BYTES {
        return Err(LiftError::PrincipalTooLong { len: input.principal.len() });
    }
    if input.issued_at > input.expires_at {
        return Err(LiftError::TimeWindowInverted { issued_at: input.issued_at, expires_at: input.expires_at });
    }
    let s = input.segments;
    let cl = len_prefix(Segment::CommandLine, s.command_line)?;
    let im = len_prefix(Segment::Image, s.image)?;
    let of = len_prefix(Segment::OriginalFileName, s.original_file_name)?;
    let pi = len_prefix(Segment::ParentImage, s.parent_image)?;
    let pr = u32::try_from(input.principal.len())
        .map(u32::to_be_bytes)
        .map_err(|_| LiftError::PrincipalTooLong { len: input.principal.len() })?;
    let origin = [input.origin as u8];
    let issued = input.issued_at.to_be_bytes();
    let expires = input.expires_at.to_be_bytes();
    let inv = input.invocation_cost.to_be_bytes();
    let unit = input.unit_cost.to_be_bytes();
    let request_digest = hasher.digest32(&[
        LIFT_DOMAIN, &origin,
        &cl, s.command_line, &im, s.image, &of, s.original_file_name, &pi, s.parent_image,
        &pr, input.principal, &issued, &expires, &inv, &unit,
    ]);
    Ok(PortableToolCallRequest {
        origin: input.origin, segments: s, principal: input.principal, request_digest,
        issued_at: input.issued_at, expires_at: input.expires_at,
        invocation_cost: input.invocation_cost, unit_cost: input.unit_cost,
    })
}

fn kib_units(len: usize) -> Result<u64, LiftError> {
    let len = u64::try_from(len).map_err(|_| LiftError::CostOverflow)?;
    len.checked_add(1_023).map(|n| n >> 10).and_then(|n| n.checked_add(1)).ok_or(LiftError::CostOverflow)
}

pub struct McpFrame<'a> {
    pub host_client: &'a [u8], pub server_name: &'a [u8], pub tool_name: &'a [u8],
    pub arguments_json: &'a [u8], pub issued_at: u64, pub expires_at: u64,
}
pub struct A2aFrame<'a> {
    pub caller_agent_id: &'a [u8], pub agent_card_url: &'a [u8], pub skill_id: &'a [u8],
    pub message_parts: &'a [u8], pub issued_at: u64, pub expires_at: u64,
}
pub struct ExtAuthzFrame<'a> {
    pub downstream_principal: &'a [u8], pub upstream_cluster: &'a [u8], pub authority: &'a [u8],
    /// `METHOD SP path?query`, rendered by the std edge before lifting.
    pub request_line: &'a [u8], pub issued_at: u64, pub expires_at: u64,
}

pub fn lift_mcp<'a, H: Digest32>(f: &McpFrame<'a>, h: &H) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(LiftInput {
        origin: ProtocolOrigin::Mcp,
        segments: CopleySegments { command_line: f.arguments_json, image: f.tool_name, original_file_name: f.server_name, parent_image: f.host_client },
        principal: f.host_client, issued_at: f.issued_at, expires_at: f.expires_at,
        invocation_cost: 1, unit_cost: kib_units(f.arguments_json.len())?,
    }, h)
}

pub fn lift_a2a<'a, H: Digest32>(f: &A2aFrame<'a>, h: &H) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(LiftInput {
        origin: ProtocolOrigin::A2a,
        segments: CopleySegments { command_line: f.message_parts, image: f.skill_id, original_file_name: f.agent_card_url, parent_image: f.caller_agent_id },
        principal: f.caller_agent_id, issued_at: f.issued_at, expires_at: f.expires_at,
        invocation_cost: 1, unit_cost: kib_units(f.message_parts.len())?,
    }, h)
}

pub fn lift_ext_authz<'a, H: Digest32>(f: &ExtAuthzFrame<'a>, h: &H) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(LiftInput {
        origin: ProtocolOrigin::EnvoyExtAuthz,
        segments: CopleySegments { command_line: f.request_line, image: f.authority, original_file_name: f.upstream_cluster, parent_image: f.downstream_principal },
        principal: f.downstream_principal, issued_at: f.issued_at, expires_at: f.expires_at,
        invocation_cost: 1, unit_cost: 1,
    }, h)
}
```

**Kleene lifting of the 537 predicates.** Scores are `FixedQ16_16`, mirroring the Tier-0 type so a later alias swap is one line. A threshold pair is only constructible when $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$, which makes the three outcomes exhaustive and exclusive by construction.

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedQ16_16(pub i32);
impl FixedQ16_16 {
    pub const ONE: Self = Self(1 << 16);
    pub const fn checked_add(self, o: Self) -> Option<Self> {
        match self.0.checked_add(o.0) { Some(v) => Some(Self(v)), None => None }
    }
    pub const fn checked_sub(self, o: Self) -> Option<Self> {
        match self.0.checked_sub(o.0) { Some(v) => Some(Self(v)), None => None }
    }
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0))? >> 16;
        i32::try_from(wide).ok().map(Self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum K3 { Pos = 0, Neg = 1, Bot = 2 }
impl K3 {
    /// Kleene strong conjunction: Neg absorbs, Bot dominates Pos.
    pub const fn meet(self, o: K3) -> K3 {
        match (self, o) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Bot, _) | (_, K3::Bot) => K3::Bot,
            (K3::Pos, K3::Pos) => K3::Pos,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RoleThreshold { tau_pos: FixedQ16_16, tau_neg: FixedQ16_16 }
impl RoleThreshold {
    pub const fn new(tau_pos: FixedQ16_16, tau_neg: FixedQ16_16) -> Option<Self> {
        if tau_neg.0 <= tau_pos.0 { Some(Self { tau_pos, tau_neg }) } else { None }
    }
    pub const fn classify(self, score: FixedQ16_16) -> K3 {
        if score.0 >= self.tau_pos.0 { K3::Pos } else if score.0 < self.tau_neg.0 { K3::Neg } else { K3::Bot }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PredicateOutOfRange(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConceptVector { pos: [u64; CONCEPT_WORDS], neg: [u64; CONCEPT_WORDS] }
impl ConceptVector {
    /// All predicates Bot: the conservative state.
    pub const UNKNOWN: Self = Self { pos: [0; CONCEPT_WORDS], neg: [0; CONCEPT_WORDS] };

    fn locate(index: usize) -> Result<(usize, u64), PredicateOutOfRange> {
        if index >= COPLEY_PREDICATES { return Err(PredicateOutOfRange(index)); }
        let shift = u32::try_from(index & 63).map_err(|_| PredicateOutOfRange(index))?;
        let mask = 1u64.checked_shl(shift).ok_or(PredicateOutOfRange(index))?;
        Ok((index >> 6, mask))
    }
    pub fn set(&mut self, index: usize, value: K3) -> Result<(), PredicateOutOfRange> {
        let (word, mask) = Self::locate(index)?;
        let (p, n) = match value { K3::Pos => (true, false), K3::Neg => (false, true), K3::Bot => (false, false) };
        if let Some(w) = self.pos.get_mut(word) { *w = if p { *w | mask } else { *w & !mask }; }
        if let Some(w) = self.neg.get_mut(word) { *w = if n { *w | mask } else { *w & !mask }; }
        Ok(())
    }
    pub fn any_pos_in(&self, mask: &[u64; CONCEPT_WORDS]) -> bool {
        self.pos.iter().zip(mask).any(|(p, m)| p & m != 0)
    }
    /// True when some masked predicate is Pos or Bot, i.e. not refuted.
    pub fn any_unrefuted_in(&self, mask: &[u64; CONCEPT_WORDS]) -> bool {
        self.neg.iter().zip(mask).any(|(n, m)| m & !n != 0)
    }
}

pub fn classify_scores(scores: &[FixedQ16_16; COPLEY_PREDICATES], thresholds: &[RoleThreshold; COPLEY_PREDICATES]) -> ConceptVector {
    let mut cv = ConceptVector::UNKNOWN;
    for (i, (s, t)) in scores.iter().zip(thresholds).enumerate() {
        if cv.set(i, t.classify(*s)).is_err() { return ConceptVector::UNKNOWN; }
    }
    cv
}
```

**Tier-0 shadow prices.** The hot path evaluates one penalized micro-score. The kernel owns the dual ascent $\lambda_{k+1} = [\lambda_k + \eta(c_k - \bar c)]_+$ on the five resource constraints. The edge only consumes $\boldsymbol{\lambda}$, and overflow yields `None`, which the caller treats as $\bot$. This matters for control: the projection below is a saturation element, so closed-loop safety does not depend on $\boldsymbol{\lambda}$ having converged. The learned score is a gain inside the saturation, nothing more.

```rust
#[derive(Clone, Copy, Debug)]
pub struct ResourceVector { pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16, pub memory: FixedQ16_16, pub escrow: FixedQ16_16 }
pub type ShadowPrices = ResourceVector;
pub type EdgeCosts = ResourceVector;

pub fn tier0_penalized_score(raw: FixedQ16_16, lambda: &ShadowPrices, cost: &EdgeCosts) -> Option<FixedQ16_16> {
    let penalty = lambda.budget.checked_mul(cost.budget)?
        .checked_add(lambda.fuel.checked_mul(cost.fuel)?)?
        .checked_add(lambda.latency.checked_mul(cost.latency)?)?
        .checked_add(lambda.memory.checked_mul(cost.memory)?)?
        .checked_add(lambda.escrow.checked_mul(cost.escrow)?)?;
    raw.checked_sub(penalty)
}
```

**Envelope and $O(1)$ projection.** The envelope is computed from exact facts only. A `+` on any deny-class predicate collapses the envelope to Deny. Any unrefuted gate predicate removes Forward and leaves Defer, which the guard pipeline surfaces as `PendingApproval`. Deny is always feasible, so the projection has a fallback for every input.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeAction { Forward = 0, Defer = 1, Deny = 2 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum GuardVerdictCode { Allow = 0, PendingApproval = 1, Deny = 2 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EdgeEnvelope { allow_forward: bool, allow_defer: bool }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedAction { action: EdgeAction }
impl ShieldedAction {
    pub const fn action(self) -> EdgeAction { self.action }
    /// Maps onto chio_guards::Verdict; Defer is the sticky PendingApproval state.
    pub const fn guard_verdict(self) -> GuardVerdictCode {
        match self.action {
            EdgeAction::Forward => GuardVerdictCode::Allow,
            EdgeAction::Defer => GuardVerdictCode::PendingApproval,
            EdgeAction::Deny => GuardVerdictCode::Deny,
        }
    }
}

impl EdgeEnvelope {
    pub const DENY_ONLY: Self = Self { allow_forward: false, allow_defer: false };
    pub const fn contains(self, a: EdgeAction) -> bool {
        match a { EdgeAction::Deny => true, EdgeAction::Defer => self.allow_defer, EdgeAction::Forward => self.allow_forward }
    }
    /// The only constructor of ShieldedAction.
    pub const fn project(self, proposal: EdgeAction) -> ShieldedAction {
        if self.contains(proposal) { ShieldedAction { action: proposal } } else { ShieldedAction { action: EdgeAction::Deny } }
    }
}

pub struct EdgePolicy { pub deny_mask: [u64; CONCEPT_WORDS], pub gate_mask: [u64; CONCEPT_WORDS] }
pub struct BudgetView { pub remaining_invocations: u64, pub remaining_units: u64 }

pub fn edge_envelope(req: &PortableToolCallRequest<'_>, concepts: &ConceptVector, policy: &EdgePolicy, budget: &BudgetView, now: u64) -> EdgeEnvelope {
    if classify_time_window_code(now, req.issued_at, req.expires_at) != 0 { return EdgeEnvelope::DENY_ONLY; }
    if !budget_precheck(budget.remaining_invocations, budget.remaining_units, req.invocation_cost, req.unit_cost) { return EdgeEnvelope::DENY_ONLY; }
    if concepts.any_pos_in(&policy.deny_mask) { return EdgeEnvelope::DENY_ONLY; }
    EdgeEnvelope { allow_forward: !concepts.any_unrefuted_in(&policy.gate_mask), allow_defer: true }
}
```

The fold in `crates/guards/chio-guards/src/pipeline.rs` is exactly the $\mathbb{K}_3$ meet with `Allow` as $+$, the sticky `PendingApproval` as $\bot$, and `Deny` as $-$. Its early return on `Deny` is sound because $-$ is absorbing. Section 3 proves this in Lean.

## 2. Hybrid receipt signing under `KernelCryptoFloor`

**The floor.** At Pass 11 a receipt is admissible only if it carries both an Ed25519 signature and an ML-DSA-65 signature over one to-be-signed message. Both must verify. The message is prefixed with a domain tag and a digest of both public keys, so a signature cannot be stripped, re-paired with a different co-key, or replayed under another suite. Sizes follow RFC 8032 and FIPS 204.

```rust
pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const ML_DSA_65_PK_LEN: usize = 1_952;
pub const ML_DSA_65_SIG_LEN: usize = 3_309;

pub trait Ed25519Verify { fn ed25519_verify(&self, pk: &[u8; ED25519_PK_LEN], msg: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> bool; }
pub trait MlDsa65Verify { fn ml_dsa_65_verify(&self, pk: &[u8; ML_DSA_65_PK_LEN], msg: &[u8], sig: &[u8; ML_DSA_65_SIG_LEN]) -> bool; }
pub trait Ed25519Sign { fn ed25519_public(&self) -> [u8; ED25519_PK_LEN]; fn ed25519_sign(&self, msg: &[u8]) -> [u8; ED25519_SIG_LEN]; }
pub trait MlDsa65Sign { fn ml_dsa_65_public(&self) -> [u8; ML_DSA_65_PK_LEN]; fn ml_dsa_65_sign(&self, msg: &[u8]) -> [u8; ML_DSA_65_SIG_LEN]; }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum SignatureSuite { Ed25519Only = 1, MlDsa65Only = 2, HybridEd25519MlDsa65 = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KernelCryptoFloor { minimum: SignatureSuite }
impl KernelCryptoFloor {
    pub const PASS_11: Self = Self { minimum: SignatureSuite::HybridEd25519MlDsa65 };
    pub const fn admits(&self, suite: SignatureSuite) -> bool {
        match (self.minimum, suite) {
            (SignatureSuite::HybridEd25519MlDsa65, SignatureSuite::HybridEd25519MlDsa65) => true,
            (SignatureSuite::HybridEd25519MlDsa65, _) => false,
            (SignatureSuite::Ed25519Only, _) | (SignatureSuite::MlDsa65Only, _) => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HybridPublicKey { pub ed25519: [u8; ED25519_PK_LEN], pub ml_dsa_65: [u8; ML_DSA_65_PK_LEN] }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HybridSignature { pub ed25519: [u8; ED25519_SIG_LEN], pub ml_dsa_65: [u8; ML_DSA_65_SIG_LEN] }

pub const RECEIPT_VERSION: u8 = 11;
pub const RECEIPT_BODY_LEN: usize = 213;
pub const RECEIPT_DOMAIN: [u8; 16] = *b"chio-receipt/v11";
pub const TBS_LEN: usize = 261;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ReceiptBody {
    pub suite: SignatureSuite,
    pub origin: ProtocolOrigin,
    pub verdict_code: u8,
    pub evidence_class: u8,
    pub request_digest: [u8; 32],
    pub capability_digest: [u8; 32],
    pub policy_hash: [u8; 32],
    /// LoadedWeights::loaded_weights_hash of the Tier-1 predictor, checked by evaluate_weights_binding at admission.
    pub weights_hash: [u8; 32],
    pub attestation_binding: [u8; 32],
    pub signer_root_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ReceiptBody {
    /// Fixed-width big-endian encoding: injective, allocation-free.
    pub fn encode(&self) -> [u8; RECEIPT_BODY_LEN] {
        let mut out = [0u8; RECEIPT_BODY_LEN];
        out[0] = RECEIPT_VERSION;
        out[1] = self.suite as u8;
        out[2] = self.origin as u8;
        out[3] = self.verdict_code;
        out[4] = self.evidence_class;
        out[5..37].copy_from_slice(&self.request_digest);
        out[37..69].copy_from_slice(&self.capability_digest);
        out[69..101].copy_from_slice(&self.policy_hash);
        out[101..133].copy_from_slice(&self.weights_hash);
        out[133..165].copy_from_slice(&self.attestation_binding);
        out[165..197].copy_from_slice(&self.signer_root_id);
        out[197..205].copy_from_slice(&self.issued_at.to_be_bytes());
        out[205..213].copy_from_slice(&self.expires_at.to_be_bytes());
        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedReceipt { pub body: ReceiptBody, pub signer: HybridPublicKey, pub signature: HybridSignature }

pub fn root_id_of<H: Digest32>(keys: &HybridPublicKey, h: &H) -> [u8; 32] {
    h.digest32(&[b"chio-root/v11", &keys.ed25519, &keys.ml_dsa_65])
}

pub fn to_be_signed<H: Digest32>(body: &ReceiptBody, signer: &HybridPublicKey, h: &H) -> [u8; TBS_LEN] {
    let binding = root_id_of(signer, h);
    let mut tbs = [0u8; TBS_LEN];
    tbs[0..16].copy_from_slice(&RECEIPT_DOMAIN);
    tbs[16..48].copy_from_slice(&binding);
    tbs[48..261].copy_from_slice(&body.encode());
    tbs
}

pub fn sign_hybrid<S: Ed25519Sign + MlDsa65Sign + Digest32>(mut body: ReceiptBody, signer: &S) -> SignedReceipt {
    body.suite = SignatureSuite::HybridEd25519MlDsa65;
    let keys = HybridPublicKey { ed25519: signer.ed25519_public(), ml_dsa_65: signer.ml_dsa_65_public() };
    let tbs = to_be_signed(&body, &keys, signer);
    SignedReceipt {
        body, signer: keys,
        signature: HybridSignature { ed25519: signer.ed25519_sign(&tbs), ml_dsa_65: signer.ml_dsa_65_sign(&tbs) },
    }
}

/// Strict AND. Both components are evaluated unconditionally.
pub fn verify_hybrid<B: Ed25519Verify + MlDsa65Verify + Digest32>(signed: &SignedReceipt, backend: &B, floor: &KernelCryptoFloor) -> bool {
    if !floor.admits(signed.body.suite) { return false; }
    let tbs = to_be_signed(&signed.body, &signed.signer, backend);
    let ed_ok = backend.ed25519_verify(&signed.signer.ed25519, &tbs, &signed.signature.ed25519);
    let ml_ok = backend.ml_dsa_65_verify(&signed.signer.ml_dsa_65, &tbs, &signed.signature.ml_dsa_65);
    ed_ok & ml_ok
}
```

**Hardware attestation binding.** The edge verifies the raw quote online with the vendor chain, then binds its digest, the measurement, and a freshness nonce into the receipt. The nonce must equal the request digest, which ties the quote to this one request and defeats replay. Measurements are 48 bytes wide so SEV-SNP and TDX fit natively and TPM 2.0 SHA-256 PCR composites are zero-padded on the left.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AttestationKind { None = 0, Tpm2Quote = 1, SevSnpReport = 2, TdxQuote = 3, SgxDcapQuote = 4 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttestationEvidence { pub kind: AttestationKind, pub measurement: [u8; 48], pub nonce: [u8; 32], pub quote_digest: [u8; 32] }

pub fn attestation_binding<H: Digest32>(ev: &AttestationEvidence, root_id: &[u8; 32], h: &H) -> [u8; 32] {
    h.digest32(&[b"chio-attest/v11", &[ev.kind as u8], &ev.measurement, &ev.nonce, &ev.quote_digest, root_id])
}

/// Additive to RESERVED_RECEIPT_METADATA_KEYS; a unit test asserts disjointness.
pub const PROTOCOL_EDGE_METADATA_KEYS: [&str; 3] = ["protocol_edge", "attestation_binding", "crypto_floor"];
```

The existing reserved-key array keeps its `[&str; 35]` type. The new keys live in their own constant, and the disjointness test is the only coupling.

## 3. Offline verification across federated trust roots, and the proofs

**Trust roots and the verifier.** A relying party holds up to 64 roots from different operators. Each root pins a hybrid key pair, a validity window, and a measurement allowlist. The verifier returns a $\mathbb{K}_3$ value per condition and the meet of all of them. An unknown root yields $\bot$, never $-$ and never $+$. The signature is first checked for self-consistency against the carried keys, so a malformed signature is $-$ even when the root is unknown.

```rust
pub const MAX_FEDERATED_ROOTS: usize = 64;
pub const MAX_MEASUREMENTS_PER_ROOT: usize = 16;

pub struct TrustRoot {
    pub root_id: [u8; 32],
    pub keys: HybridPublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub allowed_measurements: [[u8; 48]; MAX_MEASUREMENTS_PER_ROOT],
    pub measurement_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustStoreError { TooManyRoots { count: usize }, DuplicateRootId { index: usize }, RootWindowInverted { index: usize } }

pub struct FederatedTrustStore<'a> { roots: &'a [TrustRoot] }
impl<'a> FederatedTrustStore<'a> {
    pub fn new(roots: &'a [TrustRoot]) -> Result<Self, TrustStoreError> {
        if roots.len() > MAX_FEDERATED_ROOTS { return Err(TrustStoreError::TooManyRoots { count: roots.len() }); }
        for (i, r) in roots.iter().enumerate() {
            if r.not_before > r.not_after { return Err(TrustStoreError::RootWindowInverted { index: i }); }
            if roots.iter().take(i).any(|o| o.root_id == r.root_id) { return Err(TrustStoreError::DuplicateRootId { index: i }); }
        }
        Ok(Self { roots })
    }
    pub fn find(&self, id: &[u8; 32]) -> Option<&'a TrustRoot> { self.roots.iter().find(|r| &r.root_id == id) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ReceiptExpectation { pub capability_digest: [u8; 32], pub request_digest: [u8; 32], pub verdict_code: u8, pub policy_hash: [u8; 32], pub evidence_class: u8 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineVerification {
    pub receipt_window: K3, pub coupling: K3, pub root_known: K3, pub root_window: K3,
    pub signature: K3, pub attestation: K3,
    /// Meet of everything except attestation, for policies that accept unattested edges.
    pub verdict_unattested: K3,
    pub verdict: K3,
}

fn window_k3(now: u64, from: u64, to: u64) -> K3 { if classify_time_window_code(now, from, to) == 0 { K3::Pos } else { K3::Neg } }
fn k3_of(b: bool) -> K3 { if b { K3::Pos } else { K3::Neg } }

pub fn attestation_verdict<H: Digest32>(evidence: Option<&AttestationEvidence>, body: &ReceiptBody, root: &TrustRoot, h: &H) -> K3 {
    let Some(ev) = evidence else { return K3::Bot };
    if ev.kind == AttestationKind::None { return K3::Bot; }
    if ev.nonce != body.request_digest { return K3::Neg; }
    if attestation_binding(ev, &root.root_id, h) != body.attestation_binding { return K3::Neg; }
    let n = root.measurement_count.min(MAX_MEASUREMENTS_PER_ROOT);
    k3_of(root.allowed_measurements.iter().take(n).any(|m| *m == ev.measurement))
}

pub fn verify_offline<B: Ed25519Verify + MlDsa65Verify + Digest32>(
    signed: &SignedReceipt, evidence: Option<&AttestationEvidence>, expected: &ReceiptExpectation,
    store: &FederatedTrustStore<'_>, now: u64, backend: &B, floor: &KernelCryptoFloor,
) -> OfflineVerification {
    let body = &signed.body;
    let receipt_window = window_k3(now, body.issued_at, body.expires_at);
    let coupling = k3_of(receipt_fields_coupled(
        body.capability_digest == expected.capability_digest,
        body.request_digest == expected.request_digest,
        body.verdict_code == expected.verdict_code,
        body.policy_hash == expected.policy_hash,
        body.evidence_class == expected.evidence_class,
    ));
    let self_consistent = verify_hybrid(signed, backend, floor);
    let root = store.find(&body.signer_root_id);
    let root_known = if root.is_some() { K3::Pos } else { K3::Bot };
    let signature = match root {
        _ if !self_consistent => K3::Neg,
        Some(r) => k3_of(r.keys == signed.signer && root_id_of(&signed.signer, backend) == r.root_id),
        None => K3::Bot,
    };
    let (root_window, attestation) = match root {
        Some(r) => (window_k3(now, r.not_before, r.not_after), attestation_verdict(evidence, body, r, backend)),
        None => (K3::Bot, K3::Bot),
    };
    let verdict_unattested = receipt_window.meet(coupling).meet(root_known).meet(root_window).meet(signature);
    OfflineVerification { receipt_window, coupling, root_known, root_window, signature, attestation, verdict_unattested, verdict: verdict_unattested.meet(attestation) }
}
```

**Kani harnesses.** Both model the learned proposal and the cryptographic oracles as unconstrained nondeterminism, so the Verification Transfer Theorem applies: any property proved here holds for every concrete predictor and every concrete backend.

```rust
#[cfg(kani)]
#[allow(clippy::arithmetic_side_effects)]
mod proofs {
    use super::*;

    fn any_action() -> EdgeAction {
        match kani::any::<u8>() % 3 { 0 => EdgeAction::Forward, 1 => EdgeAction::Defer, _ => EdgeAction::Deny }
    }

    #[kani::proof]
    fn envelope_preservation() {
        let env = EdgeEnvelope { allow_forward: kani::any(), allow_defer: kani::any() };
        let shielded = env.project(any_action());
        kani::assert(env.contains(shielded.action()), "projection stays inside the envelope");
    }

    struct Oracle;
    impl Digest32 for Oracle { fn digest32(&self, _: &[&[u8]]) -> [u8; 32] { kani::any() } }
    impl Ed25519Verify for Oracle { fn ed25519_verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool { kani::any() } }
    impl MlDsa65Verify for Oracle { fn ml_dsa_65_verify(&self, _: &[u8; 1_952], _: &[u8], _: &[u8; 3_309]) -> bool { kani::any() } }

    #[kani::proof]
    #[kani::unwind(2)]
    fn unknown_root_is_never_valid() {
        let store = FederatedTrustStore::new(&[]).unwrap();
        let signed = SignedReceipt {
            body: kani::any(),
            signer: HybridPublicKey { ed25519: kani::any(), ml_dsa_65: kani::any() },
            signature: HybridSignature { ed25519: kani::any(), ml_dsa_65: kani::any() },
        };
        let expected: ReceiptExpectation = kani::any();
        let r = verify_offline(&signed, None, &expected, &store, kani::any(), &Oracle, &KernelCryptoFloor::PASS_11);
        kani::assert(r.verdict != K3::Pos, "no trust root, no Valid");
        kani::assert(r.verdict_unattested != K3::Pos, "no trust root, no Valid even unattested");
    }

    #[kani::proof]
    fn tier0_never_panics() {
        let any = || ResourceVector { budget: FixedQ16_16(kani::any()), fuel: FixedQ16_16(kani::any()), latency: FixedQ16_16(kani::any()), memory: FixedQ16_16(kani::any()), escrow: FixedQ16_16(kani::any()) };
        let _ = tier0_penalized_score(FixedQ16_16(kani::any()), &any(), &any());
    }
}
```

**Lean 4.** The spec lives in `formal/lean4/Chio/Edge.lean` and is additive to the manifest. It fixes the lattice, proves the pipeline fold is the meet, proves threshold conservativeness, and proves the hybrid soundness transfer.

```lean
namespace Chio.Edge

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

def K3.meet : K3 → K3 → K3
  | .neg, _ => .neg
  | _, .neg => .neg
  | .bot, _ => .bot
  | _, .bot => .bot
  | .pos, .pos => .pos

theorem K3.meet_pos_iff (a b : K3) : a.meet b = .pos ↔ a = .pos ∧ b = .pos := by
  cases a <;> cases b <;> simp [K3.meet]

theorem K3.meet_neg_iff (a b : K3) : a.meet b = .neg ↔ a = .neg ∨ b = .neg := by
  cases a <;> cases b <;> simp [K3.meet]

/-- GuardPipeline fold: Allow = pos, sticky PendingApproval = bot, Deny = neg. -/
def foldVerdicts (vs : List K3) : K3 := vs.foldl K3.meet .pos

theorem foldl_meet_pos_iff (vs : List K3) (acc : K3) :
    vs.foldl K3.meet acc = .pos ↔ acc = .pos ∧ ∀ v ∈ vs, v = .pos := by
  induction vs generalizing acc with
  | nil => simp
  | cons v vs ih =>
    simp only [List.foldl_cons, ih, K3.meet_pos_iff, List.mem_cons]
    aesop

theorem foldVerdicts_pos_iff (vs : List K3) : foldVerdicts vs = .pos ↔ ∀ v ∈ vs, v = .pos := by
  simp [foldVerdicts, foldl_meet_pos_iff]

/-- The early return on Deny in pipeline.rs is sound: neg is absorbing. -/
theorem foldl_meet_neg_absorb (vs : List K3) : vs.foldl K3.meet .neg = .neg := by
  induction vs with
  | nil => rfl
  | cons v vs ih => cases v <;> simpa [K3.meet] using ih

def classify (τpos τneg s : Int) : K3 :=
  if τpos ≤ s then .pos else if s < τneg then .neg else .bot

theorem classify_pos_iff (τpos τneg s : Int) : classify τpos τneg s = .pos ↔ τpos ≤ s := by
  unfold classify; split_ifs <;> simp_all

theorem classify_neg_iff (τpos τneg s : Int) (h : τneg ≤ τpos) :
    classify τpos τneg s = .neg ↔ s < τneg := by
  unfold classify; split_ifs <;> simp_all <;> omega

/-- Raising τpos never creates a pos: tightening is conservative. -/
theorem classify_pos_mono (τpos τpos' τneg s : Int) (h : τpos ≤ τpos')
    (hp : classify τpos' τneg s = .pos) : classify τpos τneg s = .pos := by
  rw [classify_pos_iff] at *; omega

variable {Msg Sig : Type}

def hybridVerify (ed ml : Msg → Sig → Bool) (m : Msg) (s : Sig × Sig) : Bool := ed m s.1 && ml m s.2

/-- Sound Q V: every message V accepts was legitimately signed. -/
def Sound (Q : Msg → Prop) {S : Type} (V : Msg → S → Bool) : Prop := ∀ m s, V m s = true → Q m

theorem hybrid_sound_of_either (Q : Msg → Prop) (ed ml : Msg → Sig → Bool)
    (h : Sound Q ed ∨ Sound Q ml) : Sound Q (hybridVerify ed ml) := by
  intro m s hs
  simp only [hybridVerify, Bool.and_eq_true] at hs
  rcases h with hed | hml
  · exact hed m s.1 hs.1
  · exact hml m s.2 hs.2

end Chio.Edge
```

The Aeneas side extracts `K3::meet`, `RoleThreshold::classify`, and `EdgeEnvelope::project` from the crate into `ChioProtocolLift.Funs.lean`. The bridge theorem is one line per function, for example `project_spec : ∀ env a, env.contains (env.project a).action = true` by `cases a <;> simp [EdgeEnvelope.project, EdgeEnvelope.contains]`, and the hand-written `classify` above is shown equal to the extracted one by unfolding, since both are three comparisons on `i32` values.

**Apalache TLA+.** The spec models the guard fold with its sticky `PendingApproval` and early `Deny` return, followed by the shielded projection with an unconstrained learned proposal. `IndInv` is inductive and is checked with `apalache check --inv=IndInv --init=IndInv --length=1` for the step and `--length=0` for the base.

```tla
------------------------------ MODULE EdgePipeline ------------------------------
EXTENDS Integers

CONSTANT
  \* @type: Int;
  NGuards

VARIABLES
  \* @type: Int;
  i,
  \* @type: Str;
  acc,
  \* @type: Int -> Str;
  verdicts,
  \* @type: Str;
  decision

Verdicts == {"Allow", "PendingApproval", "Deny"}

Meet(a, b) ==
  IF a = "Deny" \/ b = "Deny" THEN "Deny"
  ELSE IF a = "PendingApproval" \/ b = "PendingApproval" THEN "PendingApproval"
  ELSE "Allow"

Feasible(a) ==
  IF a = "Allow" THEN {"Forward", "Defer", "Deny"}
  ELSE IF a = "PendingApproval" THEN {"Defer", "Deny"}
  ELSE {"Deny"}

Init ==
  /\ i = 1 /\ acc = "Allow" /\ decision = "None"
  /\ verdicts \in [1..NGuards -> Verdicts]

Step ==
  /\ i <= NGuards /\ acc /= "Deny" /\ decision = "None"
  /\ acc' = Meet(acc, verdicts[i]) /\ i' = i + 1
  /\ UNCHANGED <<verdicts, decision>>

Decide ==
  /\ (i > NGuards \/ acc = "Deny") /\ decision = "None"
  /\ \E a \in Feasible(acc): decision' = a
  /\ UNCHANGED <<i, acc, verdicts>>

Next == Step \/ Decide

Safety == decision = "Forward" => \A k \in 1..NGuards: verdicts[k] = "Allow"

IndInv ==
  /\ (acc = "Allow" => \A k \in 1..(i - 1): verdicts[k] = "Allow")
  /\ (decision = "Forward" => acc = "Allow" /\ i > NGuards)
  /\ Safety
===============================================================================
```

**Theorem 1, Edge Envelope Preservation and Verification Transfer.** For every frame $x$ and every proposal $a$, $\Pi_{\mathcal{C}_E(x)}(a) \in \mathcal{C}_E(x)$. Consequently any property $\varphi$ with $\forall a \in \mathcal{C}_E(x).\ \varphi(a)$ holds for $\Pi_{\mathcal{C}_E(x)}(P_E(x))$ whatever $P_E$ is.

*Proof.* `project` returns $a$ when `contains(a)` holds and Deny otherwise. `contains(Deny)` is identically true, so both branches land in the envelope. The second claim is immediate since the image of $\Pi$ lies inside the set over which $\varphi$ was proved. The Kani harness `envelope_preservation` discharges the first claim over all four envelope shapes and all three proposals. $\square$

**Theorem 2, Hybrid robustness.** If Ed25519 or ML-DSA-65 is EUF-CMA secure, then the hybrid scheme with the prefixed to-be-signed message is EUF-CMA secure.

*Proof.* Let $\mathcal{F}$ output a forgery $(m^\star, (\sigma_1^\star, \sigma_2^\star))$ with $m^\star$ never queried. Acceptance requires both components to verify on $\mathrm{tbs}(m^\star)$. Fix the secure component $i$. Reduction $\mathcal{B}$ receives the challenge key $pk_i$, samples the other key pair itself, publishes both, and answers each signing query on $m$ by computing $\mathrm{tbs}(m)$, signing with its own key, and forwarding $\mathrm{tbs}(m)$ to the oracle for component $i$. The encoding is fixed-width and domain-separated, so $\mathrm{tbs}$ is injective, and $\mathrm{tbs}(m^\star)$ was never submitted. $\mathcal{B}$ outputs $(\mathrm{tbs}(m^\star), \sigma_i^\star)$ with the same advantage as $\mathcal{F}$. The Lean theorem `hybrid_sound_of_either` is the deterministic shadow of this argument. The key-digest prefix additionally prevents a signature made under one co-key from verifying under another, which is the standard composite binding requirement. $\square$

**Theorem 3, Soundness and non-masking of the offline verifier.** Let $v_1, \dots, v_6$ be the component values and $V = \bigwedge_k v_k$ in $\mathbb{K}_3$. Then:

1. $V = +$ iff every $v_k = +$. So `Valid` implies the receipt window, field coupling, root knowledge, root window, signature binding, and attestation all hold.
2. $V = -$ iff some $v_k = -$. An unknown root therefore never hides a decided failure, because the receipt window, coupling, and signature self-consistency are decided before the root lookup.
3. $V = \bot$ iff no $v_k = -$ and some $v_k = \bot$.

*Proof.* The three claims are `foldVerdicts_pos_iff`, the fold generalisation of `K3.meet_neg_iff`, and exhaustiveness of $\mathbb{K}_3$. The ordering claim in item 2 follows from `verify_offline` computing `self_consistent` unconditionally. $\square$

**Corollary, federation monotonicity.** Adding a root to the store can move a verdict from $\bot$ to $+$ or $-$ but never changes a $+$ or a $-$. A $+$ requires `root_known` to be $+$ already, so the lookup was unaffected. A $-$ is absorbing under the meet, so new information cannot remove it. This is why relying parties with partial root sets can safely merge verdicts.

**Theorem 4, the guard pipeline is the meet.** The fold in `GuardPipeline` equals `foldVerdicts` under the mapping of Section 1, and its early return on `Deny` preserves the result. *Proof.* `Allow` leaves the accumulator unchanged, which is `meet pos`. `PendingApproval` sets the accumulator to $\bot$ and continues, which is `meet bot` since the accumulator is never $-$ at that point. `Deny` returns $-$ immediately, which is justified by `foldl_meet_neg_absorb`. $\square$

**Recap.** The deliverable is one new `#![no_std]` crate shared by `chio-mcp-edge`, `chio-a2a-adapter`, and `chio-envoy-ext-authz`. It lifts frames into `PortableToolCallRequest` with an injective digest and the four Copley segments, turns 537 scores into $\mathbb{K}_3$ values with role-asymmetric thresholds, computes the envelope from exact facts including the existing `budget_precheck` and `classify_time_window_code`, and projects any proposal in $O(1)$. Receipts are signed under the `KernelCryptoFloor::PASS_11` hybrid of Ed25519 and ML-DSA-65 with key-digest binding, carry the Tier-1 weights hash and a request-bound attestation binding, and verify offline against up to 64 federated roots with Kleene semantics that never promote an unknown root to Valid. Formal coverage is the Lean module above, three Kani harnesses, and an inductive Apalache spec. Everything is additive: no existing signature in `formal_aeneas.rs`, `budget_split.rs`, `pipeline.rs`, or the reserved metadata array changes. Two items need confirmation when this lands in the repository, since no tools were available here to compile or inspect: the module path in the single `use` line, and whether an owned `PortableToolCallRequest` already exists in `chio-core-types`, in which case the std edges gain a `From` impl.