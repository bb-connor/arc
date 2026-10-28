# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 13 Synthesis

- **Timestamp**: `20261025-051441 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1013.94s` across 4 parallel passes
- **Total Output**: `149,376` characters (`19,598` words)
- **Claude Max Quota Before Wave 13**: 5-hour `42.0%` | 7-day `96.0%`
- **Claude Max Quota After Wave 13**: 5-hour `53.0%` | 7-day `98.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave13_angle_1_formal_aeneas_and_lean4_deepening_pass_13` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,476` | `36,394` | `617.16` |
| `wave13_angle_2_copley_dag_optimization_and_simd_bitset_pass_13` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,538` | `33,957` | `1010.55` |
| `wave13_angle_3_concurrent_loom_and_dst_crash_recovery_pass_13` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,344` | `35,967` | `1013.93` |
| `wave13_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_13` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,240` | `43,058` | `644.37` |

---

# Verbatim Treatise - `wave13_angle_1_formal_aeneas_and_lean4_deepening_pass_13`

I'm producing the Pass 13 additive mechanization package: new `#![no_std]` Rust lemma functions, Kani bit-precise harnesses, Creusot contracts, and Lean 4 proofs for saturation, epoch boundaries, attenuation witnesses, and Merkle inclusion, layered under the pinned `formal_core` signatures. No compiler or prover exists in this session, so every artifact below is written against the exact signatures in the grounded context but is reported as unexecuted.

## Scope and the additive contract

Pass 13 adds one module tree, `crates/kernel/chio-kernel-core/src/formal_pass13/`, with four files and a public re-export. Nothing in `formal_core.rs`, `formal_aeneas.rs`, or `budget_split.rs` is edited. The only cross-references are read-only calls to `classify_time_window_code` and the constant `MAX_BUDGET_SHARE_BPS`. Lean proofs live in the new namespace `Chio.Pass13`, and the manifest gains appended `[[lemma]]` blocks only.

Three design rules keep the pass inside the Wave 1 law.

- **Kleene codes stay primitive.** Every new function returns a `u8` code or a `bool` flag next to its value, exactly like `ledger_apply` and `classify_time_window_code`. The code `0` is always the exact `+` carrier, and higher codes are `⊥` carriers that the projection must collapse to the fallback.
- **The learned value is never trusted.** The Tier-0 score enters the projection as an arbitrary `i32` plus a code. Kani models it as `kani::any()`, Lean quantifies over all of `Int`, and the Envelope Preservation theorem is discharged once for all predictors.
- **Reserved metadata stays fixed.** The reserved-key array has the pinned type `[&str; 35]`. Adding a thirty-sixth key would change that type and break pinned proofs, so the witness and the inclusion path are nested under the existing `receipt_context` key rather than registered as new reserved keys.

The lemma identifiers used throughout are `P13-S*` for saturation, `P13-E*` for epochs, `P13-A*` for attenuation, `P13-M*` for Merkle inclusion, and `P13-Π` for the coupled envelope.

## Mechanized artifacts

**S. FixedQ16_16 saturation algebra.** The Tier-0 micro-models compute in Q16.16 over `i32`. Pass 13 fixes a clamp semantics and proves four facts: the saturation flag is sound and complete, saturating addition is monotone in both arguments, the product has floor rounding error in the unit interval, and the Lagrangian penalty is dominated by the raw score and antitone in every shadow price. The last fact is the safety-relevant one. It says that raising any $\lambda_i$ can move a decision from admit to fallback but never the reverse, even when the intermediate arithmetic saturates.

```rust
//! crates/kernel/chio-kernel-core/src/formal_pass13/q16.rs  (Pass 13, additive)
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const Q16_ONE: i32 = 65_536;
const Q16_ONE_I64: i64 = 65_536;
pub const Q16_MAX: i32 = i32::MAX;
pub const Q16_MIN: i32 = i32::MIN;

/// Kleene carrier codes for a Tier-0 scalar. `0` is the exact `+` carrier; both others are `⊥`.
pub const Q16_EXACT: u8 = 0;
pub const Q16_SATURATED: u8 = 1;
pub const Q16_UNDEFINED: u8 = 2;

/// Kleene join on carrier codes: `⊥` absorbs.
pub fn kleene_join(a: u8, b: u8) -> u8 { if a >= b { a } else { b } }

pub fn q16_add(a: i32, b: i32) -> (i32, u8) {
    match a.checked_add(b) {
        Some(v) => (v, Q16_EXACT),
        None => (if a < 0 { Q16_MIN } else { Q16_MAX }, Q16_SATURATED),
    }
}

pub fn q16_sub(a: i32, b: i32) -> (i32, u8) {
    match a.checked_sub(b) {
        Some(v) => (v, Q16_EXACT),
        None => (if b < 0 { Q16_MAX } else { Q16_MIN }, Q16_SATURATED),
    }
}

/// Floor-rounded Q16.16 product. The `i64` intermediate cannot overflow and the divisor is a
/// non-zero constant, so both `None` arms are dead; harness `p13_s4` proves it.
pub fn q16_mul(a: i32, b: i32) -> (i32, u8) {
    let Some(wide) = i64::from(a).checked_mul(i64::from(b)) else { return (0, Q16_UNDEFINED); };
    let Some(scaled) = wide.checked_div_euclid(Q16_ONE_I64) else { return (0, Q16_UNDEFINED); };
    match i32::try_from(scaled) {
        Ok(v) => (v, Q16_EXACT),
        Err(_) => (if scaled < 0 { Q16_MIN } else { Q16_MAX }, Q16_SATURATED),
    }
}

/// `score − Σ λ_i·c_i` over the five shadow prices (budget, fuel, latency, memory, escrow).
/// A negative price or cost is a protocol violation and collapses to `(Q16_MIN, ⊥)`.
pub fn q16_vector_penalty(score: i32, lambdas: [i32; 5], costs: [i32; 5]) -> (i32, u8) {
    let mut acc = score;
    let mut code = Q16_EXACT;
    for (lam, cost) in lambdas.iter().zip(costs.iter()) {
        if *lam < 0 || *cost < 0 { return (Q16_MIN, Q16_UNDEFINED); }
        let (p, pc) = q16_mul(*lam, *cost);
        let (r, rc) = q16_sub(acc, p);
        acc = r;
        code = kleene_join(code, kleene_join(pc, rc));
    }
    (acc, code)
}
```

The overflow direction in `q16_add` is decided by the sign of one operand because a two's-complement sum can only overflow upward when both operands are positive and downward when both are negative. The same argument justifies the `b < 0` test in `q16_sub`. These are exactly the cases Kani checks bit-precisely.

```rust
#[cfg(kani)]
mod kani_q16 {
    use super::*;

    #[kani::proof]
    fn p13_s1_add_flag_sound() {
        let (a, b): (i32, i32) = kani::any();
        let exact = i64::from(a) + i64::from(b);
        let (r, c) = q16_add(a, b);
        if c == Q16_EXACT {
            assert_eq!(i64::from(r), exact);
        } else {
            assert_eq!(c, Q16_SATURATED);
            assert!(exact > i64::from(i32::MAX) || exact < i64::from(i32::MIN));
            assert_eq!(r, if exact > 0 { i32::MAX } else { i32::MIN });
        }
    }

    #[kani::proof]
    fn p13_s2_add_monotone() {
        let (a, a2, b, b2): (i32, i32, i32, i32) = kani::any();
        kani::assume(a <= a2 && b <= b2);
        assert!(q16_add(a, b).0 <= q16_add(a2, b2).0);
    }

    #[kani::proof]
    fn p13_s4_mul_floor_error() {
        let (a, b): (i32, i32) = kani::any();
        let (v, c) = q16_mul(a, b);
        assert_ne!(c, Q16_UNDEFINED);
        if c == Q16_EXACT {
            let wide = i64::from(a) * i64::from(b);
            let lo = i64::from(v) * Q16_ONE_I64;
            assert!(lo <= wide && wide < lo + Q16_ONE_I64);
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn p13_s5_penalty_dominated_and_lambda_monotone() {
        let s: i32 = kani::any();
        let (l, l2, c): ([i32; 5], [i32; 5], [i32; 5]) = kani::any();
        assert!(q16_vector_penalty(s, l, c).0 <= s);
        kani::assume((0..5).all(|i| 0 <= l[i] && l[i] <= l2[i] && 0 <= c[i]));
        let (r, rc) = q16_vector_penalty(s, l, c);
        let (r2, rc2) = q16_vector_penalty(s, l2, c);
        assert!(r2 <= r);
        assert!(rc <= rc2); // raising a shadow price never clears a ⊥
    }
}
```

The five-wide harness bit-blasts ten symbolic 32-bit multiplications per path, which is a nightly job. The CI variant fixes four of the five pairs to zero and is logically sufficient because the proof of antitonicity is per-component.

The Lean side proves the same algebra over `Int`, where `clamp` is the mathematical model of every saturating operation. The refinement obligation for Aeneas is that the extracted `q16_add a b` equals `ok (r, c)` with `r.val = clamp (a.val + b.val)` and `c.val = 0` exactly when the sum is representable, discharged by `progress` over the `I32.checked_add` specification lemma.

```lean
namespace Chio.Pass13.FixedQ16

def imin : Int := -2147483648
def imax : Int := 2147483647
def clamp (x : Int) : Int := max imin (min imax x)

theorem clamp_mono {x y : Int} (h : x ≤ y) : clamp x ≤ clamp y := by
  unfold clamp
  exact max_le_max (le_refl _) (min_le_min (le_refl _) h)

theorem clamp_id {x : Int} (hlo : imin ≤ x) (hhi : x ≤ imax) : clamp x = x := by
  unfold clamp
  rw [min_eq_right hhi, max_eq_right hlo]

/-- P13-S1 in the model: the flag is clear exactly on the representable range. -/
theorem clamp_eq_self_iff (x : Int) : clamp x = x ↔ (imin ≤ x ∧ x ≤ imax) := by
  constructor
  · intro h
    refine ⟨?_, ?_⟩
    · calc imin ≤ max imin (min imax x) := le_max_left _ _
        _ = x := h
    · calc x = max imin (min imax x) := h.symm
        _ ≤ imax := max_le (by unfold imin imax; omega) (min_le_left _ _)
  · rintro ⟨h1, h2⟩
    exact clamp_id h1 h2

/-- P13-S2 in the model. -/
theorem satAdd_mono {a a' b b' : Int} (ha : a ≤ a') (hb : b ≤ b') :
    clamp (a + b) ≤ clamp (a' + b') := clamp_mono (add_le_add ha hb)

/-- P13-S5 dominance: a non-negative penalty never raises an in-range score. -/
theorem shadowPenalty_le_score (s p : Int) (hs : imin ≤ s ∧ s ≤ imax) (hp : 0 ≤ p) :
    clamp (s - p) ≤ s := by
  calc clamp (s - p) ≤ clamp s := clamp_mono (by omega)
    _ = s := clamp_id hs.1 hs.2

/-- P13-S5 antitonicity: a larger penalty cannot newly clear a threshold. -/
theorem admit_antitone {s p p' τ : Int} (hp : p ≤ p') (h : τ ≤ clamp (s - p')) :
    τ ≤ clamp (s - p) :=
  le_trans h (clamp_mono (by omega))

end Chio.Pass13.FixedQ16
```

**E. Epoch boundary transitions.** Epochs partition time into half-open intervals $[k\,\ell,(k+1)\,\ell)$. The pass adds an index function, a transition classifier, and a coupling lemma against the existing window classifier. The coupling is stated against the pinned function's outputs rather than a re-encoding of its comparison operators, so it transfers whatever the operator convention is. One harness, `p13_e2`, deliberately pins the convention that a window whose expiry equals a boundary is dead at that boundary. If the pinned function uses the other convention, that harness fails loudly instead of letting epoch accounting drift silently.

```rust
//! crates/kernel/chio-kernel-core/src/formal_pass13/epoch.rs
use crate::formal_core::classify_time_window_code;

pub const EPOCH_SAME: u8 = 0;
pub const EPOCH_ADVANCE: u8 = 1;   // exactly one boundary crossed
pub const EPOCH_SKIP: u8 = 2;      // two or more crossed: the envelope must re-anchor
pub const EPOCH_REGRESS: u8 = 3;   // clock moved backwards: ⊥
pub const EPOCH_UNDEFINED: u8 = 4; // epoch_len == 0: ⊥

/// Half-open epochs `[k·len, (k+1)·len)`. `len == 0` is `⊥`.
pub fn epoch_index(now: u64, epoch_len: u64) -> (u64, bool) {
    match now.checked_div(epoch_len) { Some(k) => (k, true), None => (0, false) }
}

pub fn epoch_transition_code(prev_now: u64, now: u64, epoch_len: u64) -> u8 {
    if now < prev_now { return EPOCH_REGRESS; }
    let (k0, ok0) = epoch_index(prev_now, epoch_len);
    let (k1, ok1) = epoch_index(now, epoch_len);
    if !(ok0 && ok1) { return EPOCH_UNDEFINED; }
    match k1.checked_sub(k0) {
        Some(0) => EPOCH_SAME,
        Some(1) => EPOCH_ADVANCE,
        Some(_) => EPOCH_SKIP,
        None => EPOCH_REGRESS, // dead: now ≥ prev_now implies k1 ≥ k0
    }
}

/// Rank of the pinned window codes along increasing time: NotYetValid < Valid < Expired.
pub fn window_phase_rank(code: u8) -> u8 { match code { 1 => 0, 0 => 1, 2 => 2, _ => 3 } }

/// True iff the window is live on both sides of `boundary`.
pub fn window_survives_boundary(issued_at: u64, expires_at: u64, boundary: u64) -> bool {
    match boundary.checked_sub(1) {
        None => false,
        Some(tick_before) =>
            classify_time_window_code(tick_before, issued_at, expires_at) == 0
            && classify_time_window_code(boundary, issued_at, expires_at) == 0,
    }
}

#[cfg(kani)]
mod kani_epoch {
    use super::*;

    /// P13-E1: the pinned classifier is three-phase monotone in `now`, for every operator convention.
    #[kani::proof]
    fn p13_e1_window_three_phase() {
        let (issued, expires, n1, n2): (u64, u64, u64, u64) = kani::any();
        kani::assume(n1 <= n2);
        let c1 = classify_time_window_code(n1, issued, expires);
        let c2 = classify_time_window_code(n2, issued, expires);
        assert!(c1 <= 2 && c2 <= 2);
        assert!(window_phase_rank(c1) <= window_phase_rank(c2));
    }

    /// P13-E2: half-open boundaries, and the expiry convention pin.
    #[kani::proof]
    fn p13_e2_boundary_half_open() {
        let (k, len, issued): (u64, u64, u64) = kani::any();
        kani::assume(1 <= len && len <= 1 << 20 && k <= 1 << 20);
        let boundary = k * len;
        assert_eq!(epoch_index(boundary, len), (k, true));
        kani::assume(issued <= boundary);
        assert_eq!(classify_time_window_code(boundary, issued, boundary), 2);
        if k >= 1 {
            assert_eq!(epoch_index(boundary - 1, len), (k - 1, true));
            assert!(!window_survives_boundary(issued, boundary, boundary));
            assert_eq!(window_survives_boundary(issued, boundary + 1, boundary), issued < boundary);
        }
    }

    /// P13-E3: a step shorter than one epoch crosses at most one boundary; the classifier is total.
    #[kani::proof]
    fn p13_e3_advance_at_most_once() {
        let (a, b, len): (u64, u64, u64) = kani::any();
        kani::assume(len >= 1 && a <= b && b - a < len);
        let code = epoch_transition_code(a, b, len);
        assert!(code == EPOCH_SAME || code == EPOCH_ADVANCE);
        let (p, n, l): (u64, u64, u64) = kani::any();
        assert!(epoch_transition_code(p, n, l) <= EPOCH_UNDEFINED);
    }
}
```

The Lean proofs are floor-division facts over `Nat`. The multiplication terms are atoms for `omega`, which is enough once the successor product is rewritten.

```lean
namespace Chio.Pass13.Epoch

/-- P13-E2: a boundary instant belongs to the epoch it opens. -/
theorem boundary_index {k len : Nat} (hlen : 0 < len) : (k * len) / len = k :=
  Nat.mul_div_cancel k hlen

/-- P13-E2: the tick before a boundary belongs to the previous epoch. -/
theorem tick_before_boundary {j len : Nat} (hlen : 0 < len) :
    (j * len + len - 1) / len = j := by
  apply Nat.div_eq_of_lt_le
  · omega
  · simp only [Nat.succ_mul, Nat.add_mul, Nat.one_mul]; omega

/-- P13-E3: a step shorter than one epoch advances the index by at most one. -/
theorem advance_at_most_one {a b len : Nat} (hlen : 0 < len) (hab : a ≤ b)
    (hlt : b < a + len) : b / len - a / len ≤ 1 := by
  have h1 : a / len ≤ b / len := Nat.div_le_div_right hab
  have h2 : b / len ≤ (a + len) / len := Nat.div_le_div_right (Nat.le_of_lt hlt)
  rw [Nat.add_div_right a hlen] at h2
  omega

end Chio.Pass13.Epoch
```

The ledger is epoch-agnostic by construction, since `ReservationLedger` carries no time field. The policy consequence enforced by the projection below is that `EPOCH_SKIP`, `EPOCH_REGRESS`, and `EPOCH_UNDEFINED` all force the fallback, so a reservation that straddles a skipped epoch can only be retained or released by an exact `ledger_apply` step, never admitted on a stale score.

**A. Multi-hop delegation attenuation witnesses.** An `AttenuationWitness` is a chain of hops rooted at depth zero. Each hop carries a share in basis points, an expiry, a scope bitmask over at most sixty-four concept predicates per witness page, and a depth. One edge attenuates when the child gains no share, no time, no scope, and sits exactly one level deeper. The chain predicate is the conjunction over consecutive edges, and the effective share is the floored product of hop shares.

Two different invariants meet here and must not be confused. `BudgetSplit` rejects `OversubscribedSiblings` when the sum of sibling shares exceeds the parent share. The witness bounds the product along a single root-to-leaf path. Both hold simultaneously, and the product bound is what a verifier at depth sixteen needs without walking the sibling set.

```rust
//! crates/kernel/chio-kernel-core/src/formal_pass13/attenuation.rs
use crate::budget_split::MAX_BUDGET_SHARE_BPS;

pub const MAX_ATTENUATION_DEPTH: u8 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct AttenuationHop {
    pub share_bps: u16,
    pub expires_at: u64,
    pub scope_mask: u64,
    pub depth: u8,
}

/// One delegation edge: the child never gains share, time, or scope.
pub fn attenuation_step_ok(parent: AttenuationHop, child: AttenuationHop) -> bool {
    parent.share_bps <= MAX_BUDGET_SHARE_BPS
        && child.share_bps <= parent.share_bps
        && child.expires_at <= parent.expires_at
        && (child.scope_mask & !parent.scope_mask) == 0
        && parent.depth.checked_add(1) == Some(child.depth)
        && child.depth <= MAX_ATTENUATION_DEPTH
}

/// A witness is a non-empty chain rooted at depth 0 whose consecutive hops attenuate.
pub fn attenuation_witness_ok(hops: &[AttenuationHop]) -> bool {
    let Some(root) = hops.first() else { return false; };
    if root.depth != 0 || root.share_bps > MAX_BUDGET_SHARE_BPS { return false; }
    let mut prev = *root;
    for hop in hops.iter().skip(1) {
        if !attenuation_step_ok(prev, *hop) { return false; }
        prev = *hop;
    }
    true
}

/// Floored product of hop shares in basis points. `(0, false)` is `⊥`.
#[cfg_attr(creusot, requires(forall<i: Int> 0 <= i && i < hops@.len() ==> hops@[i].share_bps@ <= 10000))]
#[cfg_attr(creusot, ensures(result.1 ==> result.0@ <= 10000))]
#[cfg_attr(creusot, ensures(result.1 ==>
    forall<i: Int> 0 <= i && i < hops@.len() ==> result.0@ <= hops@[i].share_bps@))]
pub fn effective_share_bps(hops: &[AttenuationHop]) -> (u16, bool) {
    let cap = u32::from(MAX_BUDGET_SHARE_BPS);
    let mut acc: u32 = cap;
    #[cfg_attr(creusot, invariant(acc@ <= 10000))]
    for hop in hops {
        if hop.share_bps > MAX_BUDGET_SHARE_BPS { return (0, false); }
        let Some(prod) = acc.checked_mul(u32::from(hop.share_bps)) else { return (0, false); };
        let Some(next) = prod.checked_div(cap) else { return (0, false); };
        acc = next;
    }
    match u16::try_from(acc) { Ok(v) => (v, true), Err(_) => (0, false) }
}

#[cfg(kani)]
mod kani_attenuation {
    use super::*;
    const N: usize = 5;

    /// P13-A2: the root dominates every hop, and depth equals position.
    #[kani::proof]
    #[kani::unwind(6)]
    fn p13_a2_root_dominates_leaf() {
        let hops: [AttenuationHop; N] = kani::any();
        kani::assume(attenuation_witness_ok(&hops));
        let root = hops[0];
        for h in &hops {
            assert!(h.share_bps <= root.share_bps && h.expires_at <= root.expires_at);
            assert_eq!(h.scope_mask & !root.scope_mask, 0);
        }
        assert_eq!(usize::from(hops[N - 1].depth), N - 1);
    }

    /// P13-A3 and P13-A4: the product is capped, below every hop, and prefix-monotone.
    #[kani::proof]
    #[kani::unwind(6)]
    fn p13_a3_effective_share_bounds() {
        let hops: [AttenuationHop; N] = kani::any();
        kani::assume(hops.iter().all(|h| h.share_bps <= MAX_BUDGET_SHARE_BPS));
        let (eff, ok) = effective_share_bps(&hops);
        assert!(ok && eff <= MAX_BUDGET_SHARE_BPS);
        for h in &hops { assert!(eff <= h.share_bps); }
        let (prefix, _) = effective_share_bps(&hops[..N - 1]);
        assert!(eff <= prefix);
    }
}
```

The loop invariant `acc ≤ 10 000` is what makes every checked operation total. The product of two values at most ten thousand is below $2^{32}$, and the floored quotient by ten thousand is again at most the previous accumulator. Creusot discharges the invariant and both postconditions; Kani confirms the same facts bit-precisely for five hops; Lean proves them for all chain lengths.

```lean
namespace Chio.Pass13.Attenuation

structure Hop where
  share   : Nat
  expires : Nat
  scope   : Nat → Bool

/-- Dominance drops the depth-successor clause and is the transitive closure of a step. -/
def Dominates (p c : Hop) : Prop :=
  c.share ≤ p.share ∧ c.expires ≤ p.expires ∧ ∀ i, c.scope i = true → p.scope i = true

theorem Dominates.refl (h : Hop) : Dominates h h := ⟨le_refl _, le_refl _, fun _ hi => hi⟩

theorem Dominates.trans {a b c : Hop} (hab : Dominates a b) (hbc : Dominates b c) :
    Dominates a c :=
  ⟨le_trans hbc.1 hab.1, le_trans hbc.2.1 hab.2.1, fun i hi => hab.2.2 i (hbc.2.2 i hi)⟩

def ChainOk : List Hop → Prop
  | [] => False
  | [_] => True
  | p :: c :: rest => Dominates p c ∧ ChainOk (c :: rest)

/-- P13-A2: the root of a valid witness dominates every hop in it. -/
theorem chain_root_dominates {root : Hop} : ∀ {rest : List Hop},
    ChainOk (root :: rest) → ∀ h ∈ root :: rest, Dominates root h := by
  intro rest
  induction rest generalizing root with
  | nil =>
    intro _ h hm
    simp only [List.mem_singleton] at hm
    subst hm
    exact Dominates.refl _
  | cons c rest ih =>
    intro hok h hm
    obtain ⟨hrc, hrest⟩ := hok
    simp only [List.mem_cons] at hm
    rcases hm with rfl | rfl | hm'
    · exact Dominates.refl _
    · exact hrc
    · exact Dominates.trans hrc (ih hrest h (List.mem_cons_of_mem c hm'))

/-- Floored product of shares in basis points, the model of `effective_share_bps`. -/
def effShare : List Nat → Nat
  | [] => 10000
  | s :: rest => effShare rest * s / 10000

theorem effShare_le_cap : ∀ {l : List Nat}, (∀ s ∈ l, s ≤ 10000) → effShare l ≤ 10000
  | [], _ => le_refl _
  | s :: rest, h => by
    simp only [effShare]
    have hs : s ≤ 10000 := h s (List.mem_cons_self _ _)
    have hr : effShare rest ≤ 10000 :=
      effShare_le_cap (fun t ht => h t (List.mem_cons_of_mem _ ht))
    calc effShare rest * s / 10000 ≤ 10000 * 10000 / 10000 :=
          Nat.div_le_div_right (Nat.mul_le_mul hr hs)
      _ = 10000 := by decide

/-- P13-A3: the effective share is below every hop share. -/
theorem effShare_le_mem : ∀ {l : List Nat}, (∀ s ∈ l, s ≤ 10000) → ∀ t ∈ l, effShare l ≤ t
  | [], _, t, ht => by simp at ht
  | s :: rest, h, t, ht => by
    simp only [effShare]
    have hs : s ≤ 10000 := h s (List.mem_cons_self _ _)
    have hr : effShare rest ≤ 10000 :=
      effShare_le_cap (fun u hu => h u (List.mem_cons_of_mem _ hu))
    rcases List.mem_cons.mp ht with hts | ht'
    · rw [hts]
      calc effShare rest * s / 10000 ≤ 10000 * s / 10000 :=
            Nat.div_le_div_right (Nat.mul_le_mul_right _ hr)
        _ = s := Nat.mul_div_cancel_left s (by decide)
    · calc effShare rest * s / 10000 ≤ effShare rest * 10000 / 10000 :=
            Nat.div_le_div_right (Nat.mul_le_mul_left _ hs)
        _ = effShare rest := Nat.mul_div_cancel _ (by decide)
        _ ≤ t := effShare_le_mem (fun u hu => h u (List.mem_cons_of_mem _ hu)) t ht'

end Chio.Pass13.Attenuation
```

The Lean model folds from the right while the Rust loop folds from the left. The bound does not depend on the order, and the Aeneas refinement obligation is stated on the loop invariant `acc ≤ 10000 ∧ ∀ visited hop, acc ≤ hop.share`, which is exactly the Creusot invariant strengthened with the visited prefix.

**M. Merkle inclusion steps.** The Tier-0 path checks that the per-predicate threshold page and the `loaded_weights_hash` of the model card are included in a pinned root before any score is allowed to matter. Pass 13 abstracts the hash behind a trait so the structural lemmas hold for any digest, and leaves collision resistance as an explicit injectivity hypothesis in Lean.

```rust
//! crates/kernel/chio-kernel-core/src/formal_pass13/inclusion.rs
pub const MAX_INCLUSION_DEPTH: usize = 40;

pub trait Digest32 {
    /// Domain-separated internal node. Implementors hash `0x01 ‖ left ‖ right`; leaves hash `0x00 ‖ leaf`.
    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct InclusionStep { pub sibling: [u8; 32], pub sibling_is_left: bool }

pub fn inclusion_step<D: Digest32>(acc: &[u8; 32], step: &InclusionStep) -> [u8; 32] {
    if step.sibling_is_left { D::node(&step.sibling, acc) } else { D::node(acc, &step.sibling) }
}

/// `(root, true)`, or `(leaf, false)` as `⊥` when the path exceeds the depth cap.
pub fn inclusion_fold<D: Digest32>(leaf: [u8; 32], path: &[InclusionStep]) -> ([u8; 32], bool) {
    if path.len() > MAX_INCLUSION_DEPTH { return (leaf, false); }
    let mut acc = leaf;
    for step in path { acc = inclusion_step::<D>(&acc, step); }
    (acc, true)
}

/// Leaf index encoded by the direction bits, least significant bit first.
pub fn path_index(path: &[InclusionStep]) -> (u64, bool) {
    if path.len() > MAX_INCLUSION_DEPTH { return (0, false); }
    let mut idx: u64 = 0;
    for (i, step) in path.iter().enumerate() {
        let Ok(shift) = u32::try_from(i) else { return (0, false); };
        let Some(bit) = 1u64.checked_shl(shift) else { return (0, false); };
        if step.sibling_is_left { idx |= bit; }
    }
    (idx, true)
}
```

The depth cap of forty levels admits far more leaves than the predicate table needs, which is the five hundred thirty-seven concept predicates times four `UltraBERT` segments times the epoch pages retained per model card. The cap exists so that `checked_shl` is provably total and so the fold is bounded for Kani.

```lean
namespace Chio.Pass13.Inclusion

variable {α : Type} (H : α → α → α)

inductive Dir | L | R

def step (acc : α) (s : α × Dir) : α :=
  match s.2 with
  | .L => H s.1 acc
  | .R => H acc s.1

def fold (leaf : α) (p : List (α × Dir)) : α := p.foldl (step H) leaf

/-- P13-M1 and P13-M2 are definitional: `fold leaf [] = leaf` and `fold leaf (p ++ q) = fold (fold leaf p) q`. -/
theorem fold_nil (leaf : α) : fold H leaf [] = leaf := rfl
theorem fold_append (leaf : α) (p q : List (α × Dir)) :
    fold H leaf (p ++ q) = fold H (fold H leaf p) q := List.foldl_append _ _ _ _

section Injective
variable (hinj : ∀ a b a' b', H a b = H a' b' → a = a' ∧ b = b')

theorem step_inj {acc acc' sib : α} {d : Dir}
    (h : step H acc (sib, d) = step H acc' (sib, d)) : acc = acc' := by
  cases d
  · simp only [step] at h; exact (hinj _ _ _ _ h).2
  · simp only [step] at h; exact (hinj _ _ _ _ h).1

/-- P13-M4: under pairwise injectivity, one path authenticates at most one leaf. -/
theorem fold_inj : ∀ (p : List (α × Dir)) {l l' : α}, fold H l p = fold H l' p → l = l'
  | [], _, _, h => h
  | (sib, d) :: rest, l, l', h => by
    have h' : fold H (step H l (sib, d)) rest = fold H (step H l' (sib, d)) rest := h
    exact step_inj H hinj (fold_inj rest h')

end Injective
end Chio.Pass13.Inclusion
```

Injectivity of the pair is the idealization of second-preimage resistance with domain separation. It is a hypothesis, not a theorem, and the manifest records it as an assumption attached to the concrete digest provider named by `LoadedWeights::provider_name`.

**Π. The coupled decision envelope.** The four strands meet in one function. The projection reads the penalized score and its code, the epoch transition code, the witness verdict, and the inclusion verdict, and emits either the fallback or an admission. The role-asymmetric thresholds produce a three-valued verdict; a crossed threshold pair is itself `⊥`.

```rust
//! crates/kernel/chio-kernel-core/src/formal_pass13/envelope.rs
use super::epoch::EPOCH_ADVANCE;
use super::q16::Q16_EXACT;

pub const ENVELOPE_FALLBACK: u8 = 0; // ⊥_x : Deny, Defer, Hold, or pi_base, chosen by the layer
pub const ENVELOPE_ADMIT: u8 = 1;

pub const VERDICT_POS: u8 = 0;
pub const VERDICT_NEG: u8 = 1;
pub const VERDICT_BOT: u8 = 2;

/// Role-asymmetric three-valued verdict for one concept predicate.
pub fn kleene_verdict(score: i32, tau_pos: i32, tau_neg: i32) -> u8 {
    if tau_neg > tau_pos { return VERDICT_BOT; }
    if score >= tau_pos { VERDICT_POS } else if score < tau_neg { VERDICT_NEG } else { VERDICT_BOT }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EnvelopeInputs {
    pub score: i32,         // `q16_vector_penalty(...).0`
    pub score_code: u8,     // `q16_vector_penalty(...).1`
    pub tau_pos: i32,
    pub tau_neg: i32,
    pub epoch_code: u8,     // `epoch_transition_code(...)`
    pub witness_ok: bool,   // `attenuation_witness_ok(...)`
    pub root_matches: bool, // `inclusion_fold::<D>(leaf, path) == (pinned_root, true)`
}

/// Tier-0 shielded projection `Π_{C(x)}` for one concept predicate.
pub fn shielded_project_q16(i: EnvelopeInputs) -> u8 {
    if i.score_code != Q16_EXACT || i.epoch_code > EPOCH_ADVANCE { return ENVELOPE_FALLBACK; }
    if !(i.witness_ok && i.root_matches) { return ENVELOPE_FALLBACK; }
    if kleene_verdict(i.score, i.tau_pos, i.tau_neg) == VERDICT_POS { ENVELOPE_ADMIT } else { ENVELOPE_FALLBACK }
}

#[cfg(kani)]
mod kani_envelope {
    use super::*;
    use super::super::inclusion::*;

    struct TestDigest;
    impl Digest32 for TestDigest {
        fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..32 { out[i] = l[i].rotate_left(3) ^ r[i].wrapping_mul(0x9f) ^ 0x5c; }
            out
        }
    }

    /// P13-M1 to P13-M3 for any digest: identity, composition, index range and direction-determinism.
    #[kani::proof]
    #[kani::unwind(5)]
    fn p13_m_fold_structure() {
        let leaf: [u8; 32] = kani::any();
        assert_eq!(inclusion_fold::<TestDigest>(leaf, &[]), (leaf, true));
        let (p, q): ([InclusionStep; 2], [InclusionStep; 2]) = kani::any();
        let pq = [p[0], p[1], q[0], q[1]];
        let (mid, _) = inclusion_fold::<TestDigest>(leaf, &p);
        assert_eq!(inclusion_fold::<TestDigest>(leaf, &pq), inclusion_fold::<TestDigest>(mid, &q));
        let (idx, ok) = path_index(&pq);
        assert!(ok && idx < 16);
        let mut other = pq;
        for s in other.iter_mut() { s.sibling = kani::any(); }
        assert_eq!(path_index(&other).0, idx);
    }

    /// P13-Π: Envelope Preservation with the learned score as unconstrained nondeterminism.
    #[kani::proof]
    fn p13_pi_envelope_preservation() {
        let i: EnvelopeInputs = kani::any();
        let out = shielded_project_q16(i);
        assert!(out == ENVELOPE_FALLBACK || out == ENVELOPE_ADMIT);
        if out == ENVELOPE_ADMIT {
            assert!(i.score_code == Q16_EXACT && i.epoch_code <= EPOCH_ADVANCE);
            assert!(i.witness_ok && i.root_matches && i.tau_neg <= i.tau_pos && i.score >= i.tau_pos);
        }
        let v = kleene_verdict(i.score, i.tau_pos, i.tau_neg);
        assert!(v <= VERDICT_BOT);
        if v == VERDICT_POS { assert!(!(i.score < i.tau_neg)); } // + and − are exclusive
    }
}
```

The Lean mirror of the projection is decidable by construction, so Envelope Preservation and its soundness direction are a `split` away.

```lean
namespace Chio.Pass13.Envelope

structure Inputs where
  score : Int
  scoreCode : Nat
  tauPos : Int
  tauNeg : Int
  epochCode : Nat
  witnessOk : Bool
  rootMatches : Bool

def project (i : Inputs) : Nat :=
  if i.tauNeg ≤ i.tauPos ∧ i.scoreCode = 0 ∧ i.epochCode ≤ 1 ∧ i.witnessOk = true ∧
     i.rootMatches = true ∧ i.tauPos ≤ i.score then 1 else 0

/-- P13-Π: the projection never leaves the two-point envelope. -/
theorem project_envelope (i : Inputs) : project i = 0 ∨ project i = 1 := by
  unfold project; split <;> simp

/-- P13-Π soundness: admission certifies every exact precondition. -/
theorem project_admit_sound (i : Inputs) (h : project i = 1) :
    i.tauNeg ≤ i.tauPos ∧ i.scoreCode = 0 ∧ i.epochCode ≤ 1 ∧ i.witnessOk = true ∧
    i.rootMatches = true ∧ i.tauPos ≤ i.score := by
  unfold project at h
  split at h
  · assumption
  · exact absurd h (by decide)

end Chio.Pass13.Envelope
```

Composed with `admit_antitone` from the saturation namespace, the projection is antitone in every shadow price: for fixed exact inputs, a larger penalty can only lower the score, and lowering the score can only turn admission into fallback. The combination of `p13_s5` and `p13_pi_envelope_preservation` is the bit-precise statement of the same fact, with saturation included because a `⊥` code forces fallback before the threshold is ever consulted.

At the pipeline boundary the mapping is fixed by the existing sticky semantics in `GuardPipeline`. A fallback that arises from `⊥` on the score or an `EPOCH_SKIP` is surfaced as `Verdict::PendingApproval`, which stays sticky and lets a later guard still deny. A fallback that arises from a failed witness or a failed inclusion is surfaced as `Verdict::Deny` with the existing evidence shape, because those are integrity failures rather than uncertainty.

## Manifest entries, obligations, and recap

The manifest gains one appended block per lemma. The shape follows the existing entries and adds an `additive` flag that the manifest linter requires for any block whose `rust` path lies under `formal_pass13`.

```toml
# formal/proof-manifest.toml  (appended; existing [[lemma]] blocks untouched)
[[lemma]]
id        = "P13-S5"
statement = "q16_vector_penalty(s, λ, c).0 ≤ s for all inputs; antitone in λ when λ, c ≥ 0"
rust      = "chio_kernel_core::formal_pass13::q16::q16_vector_penalty"
lean      = ["Chio.Pass13.FixedQ16.shadowPenalty_le_score", "Chio.Pass13.FixedQ16.admit_antitone"]
kani      = "kani_q16::p13_s5_penalty_dominated_and_lambda_monotone"
aeneas    = "formal/aeneas/Pass13/Q16.Funs.lean"
additive  = true
```

The full set of obligations and their discharge routes:

| Lemma | Statement | Rust | Lean | Kani | Creusot |
|---|---|---|---|---|---|
| P13-S1 | Saturation flag sound and complete | `q16_add`, `q16_sub` | `clamp_eq_self_iff` | `p13_s1` | none |
| P13-S2 | Saturating add monotone | `q16_add` | `satAdd_mono` | `p13_s2` | none |
| P13-S4 | Product floor error in unit interval, no dead-arm reach | `q16_mul` | Aeneas spec | `p13_s4` | none |
| P13-S5 | Penalty dominated, antitone in λ, code non-decreasing | `q16_vector_penalty` | `shadowPenalty_le_score`, `admit_antitone` | `p13_s5` | none |
| P13-E1 | Pinned window classifier three-phase monotone | `window_phase_rank` | pending | `p13_e1` | none |
| P13-E2 | Half-open boundary, expiry convention pin | `epoch_index` | `boundary_index`, `tick_before_boundary` | `p13_e2` | none |
| P13-E3 | At most one advance per sub-epoch step, classifier total | `epoch_transition_code` | `advance_at_most_one` | `p13_e3` | none |
| P13-A2 | Root dominates every hop | `attenuation_witness_ok` | `chain_root_dominates` | `p13_a2` | none |
| P13-A3 | Effective share capped and below every hop | `effective_share_bps` | `effShare_le_cap`, `effShare_le_mem` | `p13_a3` | contract |
| P13-A4 | Effective share prefix-monotone | `effective_share_bps` | pending | `p13_a3` | invariant |
| P13-M1 | Empty path is identity | `inclusion_fold` | `fold_nil` | `p13_m` | none |
| P13-M2 | Fold composes over concatenation | `inclusion_fold` | `fold_append` | `p13_m` | none |
| P13-M3 | Index below two to the depth, direction-determined | `path_index` | pending | `p13_m` | none |
| P13-M4 | One path authenticates one leaf under injectivity | abstract | `fold_inj` | not applicable | none |
| P13-Π | Envelope preservation and admission soundness | `shielded_project_q16` | `project_envelope`, `project_admit_sound` | `p13_pi` | none |

Three Lean entries are marked pending and are not claimed. P13-E1 is a property of the pinned function and is covered by Kani for all 64-bit inputs; its Lean version requires the Aeneas extraction of `classify_time_window_code`, which exists but is not re-run here. P13-A4 and P13-M3 are bounded by Kani and need short `Nat.testBit` and fold-prefix inductions to close.

Verification transfer holds for every entry because no proof inspects the predictor. The score enters `shielded_project_q16` as a free `i32`, `kani::any()` on the Rust side and a universally quantified `Int` on the Lean side, and the Apalache model continues to write the choice as `\E a \in Feasible(s)`. Pass 13 therefore adds obligations without adding any dependence on the 19.3-million-parameter model or on the six Tier-0 micro-models.

**Recap.** Pass 13 adds a self-contained `formal_pass13` module with saturating Q16.16 arithmetic, epoch classification, attenuation witnesses, Merkle inclusion folding, and the coupled Tier-0 projection, each with Kleene codes in the existing primitive style. Eleven Kani harnesses, two Creusot contracts, and five Lean namespaces cover the fifteen lemmas above, with three Lean proofs explicitly left pending. Nothing pinned is modified: the reserved metadata array keeps its type, existing signatures are only called, and the manifest is append-only. None of the artifacts were compiled or checked in this session because no tools were available, so the next step is to run the Kani and Lean jobs and confirm the expiry-convention pin in `p13_e2` against the live `classify_time_window_code`.

---

# Verbatim Treatise - `wave13_angle_2_copley_dag_optimization_and_simd_bitset_pass_13`

ros() >> 6) as u64 }

/// Operation meter. `NoMeter` folds away; `Counting` certifies the WCET.
pub trait Meter { fn tick(&mut self, ops: u64); }
pub struct NoMeter;
impl Meter for NoMeter { #[inline(always)] fn tick(&mut self, _ops: u64) {} }
pub struct Counting(pub u64);
impl Meter for Counting { fn tick(&mut self, ops: u64) { self.0 = self.0.saturating_add(ops); } }

/// Dense K3 assignment. Invariant: `pos[i] & neg[i] == 0` for every word.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Assignment<const W: usize> { pos: [u64; W], neg: [u64; W] }

impl<const W: usize> Assignment<W> {
    pub const UNKNOWN: Self = Self { pos: [0; W], neg: [0; W] };

    pub fn from_raw(pos: [u64; W], neg: [u64; W]) -> Option<Self> {
        let overlap = pos.iter().zip(neg.iter()).fold(0u64, |acc, (p, n)| acc | (*p & *n));
        if overlap == 0 { Some(Self { pos, neg }) } else { None }
    }

    /// Role-asymmetric thresholding of Q16.16 scores; branch-free per predicate.
    pub fn from_scores<const P: usize>(scores: &[i32; P], tau: &[(i32, i32); P]) -> Self {
        let () = Layout::<P, W>::OK;
        let mut a = Self::UNKNOWN;
        for (p, (s, (tau_pos, tau_neg))) in scores.iter().zip(tau.iter()).enumerate() {
            let hi = u64::from(*s >= *tau_pos);
            let lo = u64::from(*s <= *tau_neg) & (hi ^ 1);
            let bit = (p & 63) as u32;
            a.pos[p >> 6] |= hi.rotate_left(bit);
            a.neg[p >> 6] |= lo.rotate_left(bit);
        }
        a
    }

    pub fn get(&self, p: usize) -> Trit {
        let bit = 1u64.rotate_left((p & 63) as u32);
        let hit = |ws: &[u64; W]| ws.get(p >> 6).map_or(0, |w| w & bit);
        match (hit(&self.pos), hit(&self.neg)) {
            (0, 0) => Trit::Unknown,
            (_, 0) => Trit::Pos,
            _ => Trit::Neg,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClauseMask<const W: usize> { pub req_pos: [u64; W], pub req_neg: [u64; W] }

impl<const W: usize> ClauseMask<W> {
    pub const EMPTY: Self = Self { req_pos: [0; W], req_neg: [0; W] };

    pub fn with_literal(mut self, predicate: usize, positive: bool) -> Result<Self, CompileError> {
        let bit = 1u64.rotate_left((predicate & 63) as u32);
        let target = if positive { &mut self.req_pos } else { &mut self.req_neg };
        let word = target.get_mut(predicate >> 6)
            .ok_or(CompileError::PredicateOutOfRange { predicate })?;
        *word |= bit;
        Ok(self)
    }
}

/// Hot path, Theorem 1. Returns `(true_bit, false_bit)`.
#[inline(always)]
fn eval_clause<const W: usize, M: Meter>(x: &Assignment<W>, c: &ClauseMask<W>, m: &mut M) -> (u64, u64) {
    let mut miss = 0u64;
    let mut viol = 0u64;
    let words = x.pos.iter().zip(x.neg.iter()).zip(c.req_pos.iter().zip(c.req_neg.iter()));
    for ((p, n), (rp, rn)) in words {
        let (p, n, rp, rn) = (*p, *n, *rp, *rn);
        miss |= (rp & !p) | (rn & !n); // a required literal is not established
        viol |= (rp & n) | (rn & p);   // a required literal is refuted
        m.tick(CLAUSE_OPS_PER_WORD);
    }
    m.tick(CLAUSE_TAIL_OPS);
    (is_zero(miss), is_zero(viol) ^ 1)
}
```

The DAG, the compiled schedule, and the executor:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleNode<const W: usize, const D: usize> {
    pub id: u16,
    pub rank: u8,
    pub action: Action,
    pub clause_count: u8,
    pub clauses: [ClauseMask<W>; D],
}

#[derive(Clone, Debug)]
pub struct SymbolicRuleDag<const P: usize, const W: usize, const D: usize, const R: usize> {
    pub rules: [RuleNode<W, D>; R],
}

pub type CopleyDag = SymbolicRuleDag<537, 9, 9, 236>;
pub const COPLEY_CLAUSE_CAPACITY: usize = 2_124;
pub type CopleySchedule = CompiledSchedule<9, 9, 236, COPLEY_CLAUSE_CAPACITY>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClauseSlot { pub index: u16, pub live: u8, pub dead: u8 }
impl ClauseSlot { pub const DEAD: Self = Self { index: 0, live: 0x00, dead: 0xFF }; }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleSched<const D: usize> {
    pub id: u16,
    pub rank: u8,
    pub deny_mask: u8,
    pub hold_mask: u8,
    pub slots: [ClauseSlot; D],
}
impl<const D: usize> RuleSched<D> {
    const PAD: Self = Self { id: 0, rank: u8::MAX, deny_mask: 0, hold_mask: 0, slots: [ClauseSlot::DEAD; D] };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WcetCertificate {
    pub word_ops_by_cut: [u64; MAX_RANKS],
    pub clause_end_by_cut: [u16; MAX_RANKS],
}

/// Private fields: the only constructor is `compile`, which establishes
/// `slot.index < clause_len <= C` and `clause_end_by_cut[ρ] <= clause_len`.
#[derive(Clone, Debug)]
pub struct CompiledSchedule<const W: usize, const D: usize, const R: usize, const C: usize> {
    clauses: [ClauseMask<W>; C],
    clause_len: u16,
    rules: [RuleSched<D>; R],
    certificate: WcetCertificate,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Evaluation<const R: usize> {
    pub rule_true: [u8; R],
    pub rule_false: [u8; R],
    pub verdict_code: u8,
    pub rank_cut: u8,
}

impl<const R: usize> Evaluation<R> {
    pub fn verdict(&self) -> Verdict {
        match self.verdict_code { 0 => Verdict::Allow, 1 => Verdict::PendingApproval, _ => Verdict::Deny }
    }
    pub fn rule_value(&self, r: usize) -> Trit {
        match (self.rule_true.get(r).copied(), self.rule_false.get(r).copied()) {
            (Some(1), _) => Trit::Pos,
            (_, Some(1)) => Trit::Neg,
            _ => Trit::Unknown,
        }
    }
}

/// Closed form of Theorem 4.
pub fn word_ops(w: u64, d: u64, clauses: u64, rules: u64) -> Option<u64> {
    let per_clause = w.checked_mul(CLAUSE_OPS_PER_WORD)?.checked_add(CLAUSE_TAIL_OPS)?;
    let per_rule = d.checked_mul(SLOT_OPS)?.checked_add(RULE_TAIL_OPS)?;
    clauses.checked_mul(per_clause)?
        .checked_add(rules.checked_mul(per_rule)?)?
        .checked_add(VERDICT_OPS)
}

impl<const W: usize, const D: usize, const R: usize, const C: usize> CompiledSchedule<W, D, R, C> {
    pub fn clause_len(&self) -> usize { usize::from(self.clause_len) }
    pub fn certificate(&self) -> &WcetCertificate { &self.certificate }
    pub fn rules(&self) -> &[RuleSched<D>; R] { &self.rules }

    pub fn execute(&self, x: &Assignment<W>, rank_cut: u8) -> Evaluation<R> {
        self.execute_metered(x, rank_cut, &mut NoMeter)
    }

    /// Hot path. Control flow is a function of `(self, rank_cut)` only (Theorem 4).
    /// No `if`, `?`, `&&`, `||`, or early return below this line.
    pub fn execute_metered<M: Meter>(&self, x: &Assignment<W>, rank_cut: u8, m: &mut M) -> Evaluation<R> {
        let rank_cut = rank_cut & 15;
        let clause_end = usize::from(self.certificate.clause_end_by_cut[usize::from(rank_cut)]);

        // Level 1: distinct clauses, bit0 = true, bit1 = false, unevaluated = 0b00 = ⊥.
        let mut scratch = [0u8; C];
        for (slot, mask) in scratch.iter_mut().zip(self.clauses.iter()).take(clause_end) {
            let (t, f) = eval_clause(x, mask, m);
            *slot = (t | (f << 1)) as u8;
        }

        // Level 2: rules, then the GuardPipeline projection (Theorem 5).
        let mut rule_true = [0u8; R];
        let mut rule_false = [0u8; R];
        let mut deny = 0u8;
        let mut pend = 0u8;
        for ((rule, out_t), out_f) in self.rules.iter().zip(rule_true.iter_mut()).zip(rule_false.iter_mut()) {
            let live_rule = MASK8[usize::from(rule.rank <= rank_cut)];
            let mut t = 0u8;
            let mut f = 1u8;
            for s in rule.slots.iter() {
                let v = scratch[usize::from(s.index)];
                t |= (v & 1) & s.live;
                f &= ((v >> 1) & 1) | s.dead;
                m.tick(SLOT_OPS);
            }
            t &= live_rule;
            f &= live_rule;
            let u = (t | f) ^ 1;
            deny |= t & rule.deny_mask;
            pend |= (u & rule.deny_mask) | ((t | u) & rule.hold_mask);
            *out_t = t;
            *out_f = f;
            m.tick(RULE_TAIL_OPS);
        }
        m.tick(VERDICT_OPS);
        Evaluation { rule_true, rule_false, verdict_code: (deny << 1) | (pend & !deny), rank_cut }
    }
}
```

The compiler. It is the sole constructor of `CompiledSchedule`, so its postconditions are the executor's invariants.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompileError {
    IndexWidthExceeded,
    PredicateOutOfRange { predicate: usize },
    MaskOutOfRange { rule: u16, word: usize },
    EmptyRule { rule: u16 },
    TooManyClauses { rule: u16 },
    ContradictoryClause { rule: u16, clause: u8 },
    RankOutOfRange { rule: u16, rank: u8 },
    ClauseCapacityExceeded { capacity: usize },
    Arithmetic,
}

/// Bits of word `word` that name predicates below `p`.
fn allowed_bits(p: usize, word: usize) -> Option<u64> {
    let lo = word.checked_mul(64)?;
    if lo >= p { return Some(0); }
    let n = p.checked_sub(lo)?;
    if n >= 64 { return Some(u64::MAX); }
    let shift = u32::try_from(64usize.checked_sub(n)?).ok()?;
    u64::MAX.checked_shr(shift)
}

/// Lookup accelerator only; equality is always confirmed on the full masks.
fn fnv1a<const W: usize>(m: &ClauseMask<W>) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325_u64;
    for w in m.req_pos.iter().chain(m.req_neg.iter()) {
        for b in w.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// Stable sort by (rank, original index); O(R²) at load time, Kani-friendly.
fn insertion_sort_by_rank<const R: usize, const W: usize, const D: usize>(
    order: &mut [u16; R], rules: &[RuleNode<W, D>; R],
) {
    let key = |i: u16| (rules.get(usize::from(i)).map_or(u8::MAX, |r| r.rank), i);
    for i in 1..R {
        let mut j = i;
        while let Some(prev) = j.checked_sub(1) {
            if key(order[prev]) <= key(order[j]) { break; }
            order.swap(prev, j);
            j = prev;
        }
    }
}

pub fn compile<const P: usize, const W: usize, const D: usize, const R: usize, const C: usize>(
    dag: &SymbolicRuleDag<P, W, D, R>,
) -> Result<CompiledSchedule<W, D, R, C>, CompileError> {
    let () = Layout::<P, W>::OK;
    if C > usize::from(u16::MAX) || R > usize::from(u16::MAX) || D > usize::from(u8::MAX) {
        return Err(CompileError::IndexWidthExceeded);
    }

    // Phase 1: well-formedness against the predicate universe and K3.
    for rule in dag.rules.iter() {
        if rule.clause_count == 0 { return Err(CompileError::EmptyRule { rule: rule.id }); }
        if usize::from(rule.clause_count) > D { return Err(CompileError::TooManyClauses { rule: rule.id }); }
        if usize::from(rule.rank) >= MAX_RANKS {
            return Err(CompileError::RankOutOfRange { rule: rule.id, rank: rule.rank });
        }
        for (k, c) in rule.clauses.iter().take(usize::from(rule.clause_count)).enumerate() {
            for (i, (rp, rn)) in c.req_pos.iter().zip(c.req_neg.iter()).enumerate() {
                let allowed = allowed_bits(P, i).ok_or(CompileError::Arithmetic)?;
                if ((rp | rn) & !allowed) != 0 {
                    return Err(CompileError::MaskOutOfRange { rule: rule.id, word: i });
                }
                if (rp & rn) != 0 {
                    return Err(CompileError::ContradictoryClause { rule: rule.id, clause: k as u8 });
                }
            }
        }
    }

    // Phase 2: stable rank order (Theorem 3 precondition).
    let mut order = [0u16; R];
    for (i, o) in order.iter_mut().enumerate() {
        *o = u16::try_from(i).map_err(|_| CompileError::IndexWidthExceeded)?;
    }
    insertion_sort_by_rank(&mut order, &dag.rules);

    // Phase 3: topological dedup in first-use order plus the cut table (Theorems 2, 3).
    let mut clauses = [ClauseMask::<W>::EMPTY; C];
    let mut hashes = [0u64; C];
    let mut len = 0usize;
    let mut rules = [RuleSched::<D>::PAD; R];
    let mut clause_end_by_cut = [0u16; MAX_RANKS];
    for (pos, &ri) in order.iter().enumerate() {
        let rule = dag.rules.get(usize::from(ri)).ok_or(CompileError::IndexWidthExceeded)?;
        let mut sched = RuleSched {
            id: rule.id,
            rank: rule.rank,
            deny_mask: MASK8[usize::from(matches!(rule.action, Action::Deny))],
            hold_mask: MASK8[usize::from(matches!(rule.action, Action::Hold))],
            slots: [ClauseSlot::DEAD; D],
        };
        let refs = sched.slots.iter_mut().zip(rule.clauses.iter()).take(usize::from(rule.clause_count));
        for (slot, mask) in refs {
            let h = fnv1a(mask);
            let found = hashes[..len].iter().zip(clauses[..len].iter())
                .position(|(hh, c)| *hh == h && c == mask);
            let idx = match found {
                Some(i) => i,
                None => {
                    let i = len;
                    let dst = clauses.get_mut(i).ok_or(CompileError::ClauseCapacityExceeded { capacity: C })?;
                    *dst = *mask;
                    hashes[i] = h;
                    len = len.checked_add(1).ok_or(CompileError::Arithmetic)?;
                    i
                }
            };
            let index = u16::try_from(idx).map_err(|_| CompileError::IndexWidthExceeded)?;
            *slot = ClauseSlot { index, live: 0xFF, dead: 0x00 };
        }
        rules[pos] = sched;
        let len16 = u16::try_from(len).map_err(|_| CompileError::IndexWidthExceeded)?;
        for end in clause_end_by_cut.iter_mut().skip(usize::from(rule.rank)) { *end = len16; }
    }

    // Phase 4: the WCET certificate (Theorem 4).
    let mut word_ops_by_cut = [0u64; MAX_RANKS];
    for (ops, end) in word_ops_by_cut.iter_mut().zip(clause_end_by_cut.iter()) {
        *ops = word_ops(W as u64, D as u64, u64::from(*end), R as u64).ok_or(CompileError::Arithmetic)?;
    }
    let clause_len = u16::try_from(len).map_err(|_| CompileError::IndexWidthExceeded)?;
    Ok(CompiledSchedule {
        clauses, clause_len, rules,
        certificate: WcetCertificate { word_ops_by_cut, clause_end_by_cut },
    })
}
```

Two notes on the lint discipline. The `wrapping_mul` in the hash and the `saturating_add` in the meter are explicitly saturating or wrapping methods, which `clippy::arithmetic_side_effects` permits, and neither is on the hot path. Every index and count uses `checked_*` or `try_from`. The executor contains no arithmetic at all beyond bitwise operations and shifts by literals.

## 3. Verification artifacts, differential tests, integration

**Lean 4 specification**, `formal/lean4/Chio/Copley/BitsetDag.lean`, Mathlib-free and additive to `formal/proof-manifest.toml`. It states Theorem 1 at the level of the mask abstraction that `eval_clause` refines, and the information-order refinement behind Theorem 3.

```lean
namespace Chio.Copley

inductive K3 | pos | neg | unk
  deriving DecidableEq, Repr

namespace K3
def not : K3 → K3 | pos => neg | neg => pos | unk => unk
def and : K3 → K3 → K3
  | neg, _ => neg | _, neg => neg | pos, pos => pos | _, _ => unk
def or : K3 → K3 → K3
  | pos, _ => pos | _, pos => pos | neg, neg => neg | _, _ => unk
/-- Information order: `unk` is bottom, everything else is discrete. -/
def le (a b : K3) : Prop := a = unk ∨ a = b
end K3

/-- The `Assignment<W>` abstraction: two disjoint bit-vectors over `Fin P`. -/
structure Assign (P : Nat) where
  pos : Fin P → Bool
  neg : Fin P → Bool
  disjoint : ∀ i, pos i = true → neg i = false

def Assign.val (x : Assign P) (i : Fin P) : K3 :=
  if x.pos i then .pos else if x.neg i then .neg else .unk

/-- The `ClauseMask<W>` abstraction. -/
structure Clause (P : Nat) where
  reqPos : Fin P → Bool
  reqNeg : Fin P → Bool

/-- Literal-level K3 semantics over an explicit literal list `ls`. -/
def clauseFold (x : Assign P) (c : Clause P) : List (Fin P) → K3
  | [] => .pos
  | i :: t =>
      let a := if c.reqPos i then x.val i else .pos
      let b := if c.reqNeg i then (x.val i).not else .pos
      (a.and b).and (clauseFold x c t)

/-- Bitset semantics computed word-wise by `eval_clause`, folded over the same list. -/
def missFold (x : Assign P) (c : Clause P) : List (Fin P) → Bool
  | [] => false
  | i :: t => ((c.reqPos i && !x.pos i) || (c.reqNeg i && !x.neg i)) || missFold x c t
def violFold (x : Assign P) (c : Clause P) : List (Fin P) → Bool
  | [] => false
  | i :: t => ((c.reqPos i && x.neg i) || (c.reqNeg i && x.pos i)) || violFold x c t

theorem fold_pos_iff (x : Assign P) (c : Clause P) (ls : List (Fin P)) :
    clauseFold x c ls = .pos ↔ missFold x c ls = false := by
  induction ls with
  | nil => simp [clauseFold, missFold]
  | cons i t ih =>
    have hd := x.disjoint i
    cases hp : c.reqPos i <;> cases hn : c.reqNeg i <;>
      cases hx : x.pos i <;> cases hy : x.neg i <;>
      simp_all [clauseFold, missFold, Assign.val, K3.and, K3.not]

theorem fold_neg_iff (x : Assign P) (c : Clause P) (ls : List (Fin P)) :
    clauseFold x c ls = .neg ↔ violFold x c ls = true := by
  induction ls with
  | nil => simp [clauseFold, violFold]
  | cons i t ih =>
    have hd := x.disjoint i
    cases hp : c.reqPos i <;> cases hn : c.reqNeg i <;>
      cases hx : x.pos i <;> cases hy : x.neg i <;>
      simp_all [clauseFold, violFold, Assign.val, K3.and, K3.not]

/-- Theorem 1, instantiated at the full predicate universe. -/
def Clause.eval (x : Assign P) (c : Clause P) : K3 := clauseFold x c (List.finRange P)
def Clause.miss (x : Assign P) (c : Clause P) : Bool := missFold x c (List.finRange P)
def Clause.viol (x : Assign P) (c : Clause P) : Bool := violFold x c (List.finRange P)

theorem eval_pos_iff (x : Assign P) (c : Clause P) : c.eval x = .pos ↔ c.miss x = false :=
  fold_pos_iff x c _
theorem eval_neg_iff (x : Assign P) (c : Clause P) : c.eval x = .neg ↔ c.viol x = true :=
  fold_neg_iff x c _

/-- Theorem 2: evaluation is a function of the masks alone. -/
theorem eval_ext (x : Assign P) (c₁ c₂ : Clause P)
    (h₁ : c₁.reqPos = c₂.reqPos) (h₂ : c₁.reqNeg = c₂.reqNeg) : c₁.eval x = c₂.eval x := by
  cases c₁; cases c₂; cases h₁; cases h₂; rfl

/-- Theorem 3, rule level: masking a rule to `unk` is below its exact value. -/
theorem masked_le (v : K3) (live : Bool) :
    K3.le (if live then v else .unk) v := by
  cases live <;> simp [K3.le]

end Chio.Copley
```

The Aeneas side stays monomorphic: `word_ops` and `is_zero` are trait-free and loop-free, so they extract directly in the style of `budget_precheck` and `classify_time_window_code`, and the extracted `is_zero` is proved equal to `fun x => decide (x = 0)` by a 64-bit case analysis on `leading_zeros`.

**Kani harnesses**, same crate under `#[cfg(kani)]`. The learned choice is already absent from this layer, so the harness quantifies over the assignment, the DAG, and the cut with plain `kani::any()`, exactly as the Envelope Preservation theorem prescribes. The textbook K3 reference below is the oracle for both Kani and the differential tests.

```rust
#[cfg(any(test, kani))]
pub mod reference {
    use super::*;
    pub fn k3_not(a: Trit) -> Trit {
        match a { Trit::Pos => Trit::Neg, Trit::Neg => Trit::Pos, Trit::Unknown => Trit::Unknown }
    }
    pub fn k3_and(a: Trit, b: Trit) -> Trit {
        match (a, b) {
            (Trit::Neg, _) | (_, Trit::Neg) => Trit::Neg,
            (Trit::Pos, Trit::Pos) => Trit::Pos,
            _ => Trit::Unknown,
        }
    }
    pub fn k3_or(a: Trit, b: Trit) -> Trit {
        match (a, b) {
            (Trit::Pos, _) | (_, Trit::Pos) => Trit::Pos,
            (Trit::Neg, Trit::Neg) => Trit::Neg,
            _ => Trit::Unknown,
        }
    }
    /// Literal-by-literal Kleene meet; no bit tricks.
    pub fn clause<const P: usize, const W: usize>(x: &Assignment<W>, c: &ClauseMask<W>) -> Trit {
        let mut acc = Trit::Pos;
        for p in 0..P {
            let bit = 1u64.rotate_left((p & 63) as u32);
            if c.req_pos[p >> 6] & bit != 0 { acc = k3_and(acc, x.get(p)); }
            if c.req_neg[p >> 6] & bit != 0 { acc = k3_and(acc, k3_not(x.get(p))); }
        }
        acc
    }
    pub fn rule<const P: usize, const W: usize, const D: usize>(x: &Assignment<W>, r: &RuleNode<W, D>) -> Trit {
        r.clauses.iter().take(usize::from(r.clause_count))
            .fold(Trit::Neg, |acc, c| k3_or(acc, clause::<P, W>(x, c)))
    }
    /// GuardPipeline algebra: Deny wins, PendingApproval is sticky, Allow otherwise.
    pub fn verdict<const P: usize, const W: usize, const D: usize, const R: usize>(
        x: &Assignment<W>, dag: &SymbolicRuleDag<P, W, D, R>, rank_cut: u8,
    ) -> Verdict {
        let mut v = Verdict::Allow;
        for r in dag.rules.iter() {
            let val = if r.rank <= rank_cut { rule::<P, W, D>(x, r) } else { Trit::Unknown };
            v = match (r.action, val) {
                (Action::Deny, Trit::Pos) => Verdict::Deny,
                (Action::Deny, Trit::Unknown) | (Action::Hold, Trit::Pos) | (Action::Hold, Trit::Unknown) =>
                    v.max(Verdict::PendingApproval),
                _ => v,
            };
        }
        v
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    const P: usize = 8; const W: usize = 1; const D: usize = 2; const R: usize = 3; const C: usize = 6;

    fn any_mask() -> ClauseMask<W> {
        let rp: u64 = kani::any(); let rn: u64 = kani::any();
        kani::assume(rp & !0xFF == 0); kani::assume(rn & !0xFF == 0); kani::assume(rp & rn == 0);
        ClauseMask { req_pos: [rp], req_neg: [rn] }
    }
    fn any_rule(id: u16) -> RuleNode<W, D> {
        let count: u8 = kani::any(); kani::assume(count >= 1 && count <= 2);
        let rank: u8 = kani::any(); kani::assume(rank < 16);
        let action = match kani::any::<u8>() % 3 { 0 => Action::Deny, 1 => Action::Hold, _ => Action::Observe };
        RuleNode { id, rank, action, clause_count: count, clauses: [any_mask(), any_mask()] }
    }
    fn any_dag() -> SymbolicRuleDag<P, W, D, R> {
        SymbolicRuleDag { rules: [any_rule(0), any_rule(1), any_rule(2)] }
    }
    fn any_assignment() -> Assignment<W> {
        let pos: u64 = kani::any(); let neg: u64 = kani::any();
        kani::assume(pos & !0xFF == 0); kani::assume(neg & !0xFF == 0); kani::assume(pos & neg == 0);
        Assignment::from_raw([pos], [neg]).unwrap()
    }

    #[kani::proof] #[kani::unwind(12)]
    fn compiled_schedule_equals_k3_reference() {
        let dag = any_dag();
        let sched = compile::<P, W, D, R, C>(&dag).unwrap();
        let x = any_assignment();
        let cut: u8 = kani::any(); kani::assume(cut < 16);
        let ev = sched.execute(&x, cut);
        for (pos, rs) in sched.rules().iter().enumerate() {
            let src = &dag.rules[usize::from(rs.id)];
            let expect = if src.rank <= cut { reference::rule::<P, W, D>(&x, src) } else { Trit::Unknown };
            assert_eq!(ev.rule_value(pos), expect);
        }
        assert_eq!(ev.verdict(), reference::verdict(&x, &dag, cut));
    }

    #[kani::proof] #[kani::unwind(12)]
    fn word_ops_are_data_independent_and_certified() {
        let dag = any_dag();
        let sched = compile::<P, W, D, R, C>(&dag).unwrap();
        let cut: u8 = kani::any(); kani::assume(cut < 16);
        let (mut m1, mut m2) = (Counting(0), Counting(0));
        sched.execute_metered(&any_assignment(), cut, &mut m1);
        sched.execute_metered(&any_assignment(), cut, &mut m2);
        assert_eq!(m1.0, m2.0);
        assert_eq!(m1.0, sched.certificate().word_ops_by_cut[usize::from(cut)]);
    }

    #[kani::proof] #[kani::unwind(12)]
    fn prefix_refines_full_verdict() {
        let dag = any_dag();
        let sched = compile::<P, W, D, R, C>(&dag).unwrap();
        let x = any_assignment();
        let cut: u8 = kani::any(); kani::assume(cut < 16);
        let (partial, full) = (sched.execute(&x, cut).verdict(), sched.execute(&x, 15).verdict());
        assert!(partial == Verdict::PendingApproval || partial == full);
    }
}
```

**Apalache TLA+**, `formal/tla/CopleyPrefix.tla`, models the anytime cut as a refinement of the full verdict and checks Theorem 3 as invariants plus Deny stability as an action property. Run with `--cinit=CInit --inv=Sound --length=17`.

```tla
------------------------------ MODULE CopleyPrefix ------------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Int;
  R,
  \* @type: Int -> Int;
  Rank,
  \* @type: Int -> Str;
  Act,
  \* @type: Int -> Str;
  Full
VARIABLES
  \* @type: Int;
  cut,
  \* @type: Int -> Str;
  val

Rules == 1..R
CInit == R = 3 /\ Rank \in [Rules -> 0..15]
             /\ Act \in [Rules -> {"Deny", "Hold", "Observe"}]
             /\ Full \in [Rules -> {"pos", "neg", "unk"}]

Verdict(f) ==
  IF \E r \in Rules : Act[r] = "Deny" /\ f[r] = "pos" THEN "Deny"
  ELSE IF \E r \in Rules : (Act[r] = "Deny" /\ f[r] = "unk")
                         \/ (Act[r] = "Hold" /\ f[r] # "neg") THEN "Pending"
  ELSE "Allow"
Proj(k) == [r \in Rules |-> IF Rank[r] <= k THEN Full[r] ELSE "unk"]

Init == cut = -1 /\ val = Proj(cut)
Next == cut < 15 /\ cut' = cut + 1 /\ val' = Proj(cut')

Refines    == \A r \in Rules : val[r] = "unk" \/ val[r] = Full[r]
Sound      == Verdict(val) = "Pending" \/ Verdict(val) = Verdict(Full)
Complete   == cut = 15 => Verdict(val) = Verdict(Full)
DenyStable == [][Verdict(val) = "Deny" => Verdict(val') = "Deny"]_<<cut, val>>
===============================================================================
```

**Differential equivalence against HushSpec IR.** The `chio-policy` IR signatures were not pinned in the grounding context, so the test defines a minimal mirror and the production adapter is a single `From` impl in `chio-policy` onto `IrRule`. The oracle is the literal-level K3 evaluator over the IR, which never sees a mask. Dedup is forced by cloning clauses across rules, and the WCET certificate is checked against both the metered run and the closed form.

```rust
#[cfg(test)]
mod differential {
    extern crate std;
    use super::*;
    use std::{boxed::Box, collections::BTreeSet, vec::Vec};

    pub struct IrLiteral { pub predicate: u16, pub positive: bool }
    pub struct IrClause { pub literals: Vec<IrLiteral> }
    pub struct IrRule { pub id: u16, pub rank: u8, pub action: Action, pub clauses: Vec<IrClause> }

    fn k3_rule(x: &[Trit], r: &IrRule) -> Trit {
        r.clauses.iter()
            .map(|c| c.literals.iter().fold(Trit::Pos, |a, l| {
                let v = x[usize::from(l.predicate)];
                reference::k3_and(a, if l.positive { v } else { reference::k3_not(v) })
            }))
            .fold(Trit::Neg, reference::k3_or)
    }

    fn lower<const P: usize, const W: usize, const D: usize, const R: usize>(
        ir: &[IrRule],
    ) -> Result<SymbolicRuleDag<P, W, D, R>, CompileError> {
        let mut rules = Vec::with_capacity(R);
        for r in ir {
            let mut clauses = [ClauseMask::<W>::EMPTY; D];
            for (dst, c) in clauses.iter_mut().zip(r.clauses.iter()) {
                *dst = c.literals.iter().try_fold(ClauseMask::EMPTY, |m, l| {
                    m.with_literal(usize::from(l.predicate), l.positive)
                })?;
            }
            rules.push(RuleNode { id: r.id, rank: r.rank, action: r.action,
                                  clause_count: r.clauses.len() as u8, clauses });
        }
        Ok(SymbolicRuleDag { rules: rules.try_into().map_err(|_| CompileError::IndexWidthExceeded)? })
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x
        }
        fn below(&mut self, n: u64) -> u64 { self.next() % n }
    }

    fn random_ir(rng: &mut Rng) -> Vec<IrRule> {
        let mut ir: Vec<IrRule> = (0..236u16).map(|id| {
            let clauses = (0..1 + rng.below(9)).map(|_| {
                let preds: BTreeSet<u16> = (0..rng.below(10)).map(|_| rng.below(537) as u16).collect();
                IrClause { literals: preds.into_iter()
                    .map(|p| IrLiteral { predicate: p, positive: rng.below(2) == 0 }).collect() }
            }).collect();
            let action = match rng.below(3) { 0 => Action::Deny, 1 => Action::Hold, _ => Action::Observe };
            IrRule { id, rank: rng.below(16) as u8, action, clauses }
        }).collect();
        // Force clause sharing so dedup is exercised.
        for i in 1..ir.len() {
            if rng.below(3) == 0 {
                let donor = rng.below(i as u64) as usize;
                let copy: Vec<IrLiteral> = ir[donor].clauses[0].literals.iter()
                    .map(|l| IrLiteral { predicate: l.predicate, positive: l.positive }).collect();
                ir[i].clauses[0] = IrClause { literals: copy };
            }
        }
        ir
    }

    fn random_trits(rng: &mut Rng) -> Vec<Trit> {
        (0..537).map(|_| match rng.below(3) { 0 => Trit::Pos, 1 => Trit::Neg, _ => Trit::Unknown }).collect()
    }

    fn pack(trits: &[Trit]) -> Assignment<9> {
        let (mut pos, mut neg) = ([0u64; 9], [0u64; 9]);
        for (p, t) in trits.iter().enumerate() {
            let bit = 1u64 << (p & 63);
            match t { Trit::Pos => pos[p >> 6] |= bit, Trit::Neg => neg[p >> 6] |= bit, Trit::Unknown => {} }
        }
        Assignment::from_raw(pos, neg).unwrap()
    }

    #[test]
    fn schedule_matches_hushspec_k3_semantics_at_copley_shape() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..8 {
            let ir = random_ir(&mut rng);
            let dag: CopleyDag = lower::<537, 9, 9, 236>(&ir).unwrap();
            let sched: Box<CopleySchedule> = Box::new(compile(&dag).unwrap());
            let total: usize = ir.iter().map(|r| r.clauses.len()).sum();
            assert!(sched.clause_len() < total, "forced sharing must dedup");
            for _ in 0..64 {
                let trits = random_trits(&mut rng);
                let x = pack(&trits);
                let full = sched.execute(&x, 15).verdict();
                for cut in [15u8, 7, 3, 0] {
                    let ev = sched.execute(&x, cut);
                    for (pos, rs) in sched.rules().iter().enumerate() {
                        let src = &ir[usize::from(rs.id)];
                        let expect = if src.rank <= cut { k3_rule(&trits, src) } else { Trit::Unknown };
                        assert_eq!(ev.rule_value(pos), expect, "rule {} cut {cut}", rs.id);
                    }
                    assert_eq!(ev.verdict(), reference::verdict(&x, &dag, cut));
                    assert!(ev.verdict() == Verdict::PendingApproval || ev.verdict() == full);
                }
            }
        }
    }

    #[test]
    fn copley_certificate_matches_metered_run_and_closed_form() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        let ir = random_ir(&mut rng);
        let dag: CopleyDag = lower::<537, 9, 9, 236>(&ir).unwrap();
        let sched: Box<CopleySchedule> = Box::new(compile(&dag).unwrap());
        for cut in 0u8..16 {
            let mut m = Counting(0);
            sched.execute_metered(&pack(&random_trits(&mut rng)), cut, &mut m);
            let cert = sched.certificate();
            assert_eq!(m.0, cert.word_ops_by_cut[usize::from(cut)]);
            assert_eq!(m.0, 95 * u64::from(cert.clause_end_by_cut[usize::from(cut)]) + 75 * 236 + 4);
            assert!(m.0 <= 219_484);
        }
    }
}
```

**Integration under the additivity constraint.** Four points keep every existing proof intact.

- **Guard wrapping.** `CopleyBitsetGuard` in `chio-guards` implements `Guard::check` by mapping the verdict code onto `Verdict::Allow`, `Verdict::PendingApproval`, and `Verdict::Deny`. Its Deny evidence uses the pipeline's existing string shape, `action=deny; reason=rule <id> rank <r> cut <ρ>`, so `GuardPipeline` consumers parse it unchanged. The executor is total, so the pipeline's `Err` branch is unreachable for this guard.
- **Receipts.** `RESERVED_RECEIPT_METADATA_KEYS` is typed `[&str; 35]`, and lengthening it changes the type that `formal/lean4/Chio/` pins. The schedule fingerprint, `clause_len`, `rank_cut`, and the certified `word_ops` therefore nest under the existing `model_metadata` key as `copley_bitset_v1`. The policy-side hash of the compiled schedule is what `policy_hash_matches` compares inside `receipt_fields_coupled`.
- **Weights binding.** UltraBERT weights bind through `LoadedWeights::loaded_weights_hash` and `evaluate_weights_binding`. The threshold vector $\tau$ lives in the `ModelCard`, so a card change forces a re-bind without touching the schedule.
- **Proof manifest.** A new `[copley_bitset]` section lists the Lean file, the three Kani harness names, and the Apalache module. Nothing in `formal_core.rs` or `formal_aeneas.rs` changes.

The fuel coupling is a single table: the Tier-0 controller maps the current $\lambda_{\text{fuel}}$ tier to a rank cut, the cut indexes `word_ops_by_cut`, and the kernel admits the evaluation only if that certified count fits the remaining fuel. Because Theorem 4 makes the count data-independent, the admission check itself leaks nothing about the classified telemetry.

**Recap.** This pass delivers the `chio-copley-bitset` crate with a zero-data-branch executor, a four-phase compiler that performs exact-mask clause deduplication in rank order and emits a per-cut WCET certificate, and proofs that the compiled schedule is Kleene-exact, that any rank prefix refines the full verdict to PendingApproval or agrees with it, and that the worst case for the 537-predicate, 236-rule instance is 219,484 word-ops, well inside the Tier-1 floor. The Lean file, Kani harnesses, Apalache module, and differential tests are written but were not executed in this environment, which has no tools. The next step is to land the crate and run `cargo kani`, `lake build`, and the Apalache check in CI, then replace the test-only IR mirror with the one-line adapter onto the real `chio-policy` HushSpec types.

---

# Verbatim Treatise - `wave13_angle_3_concurrent_loom_and_dst_crash_recovery_pass_13`

```rust
        3 => SessionState::Completed,
        _ => SessionState::Cancelled,
    };
    (state, word & SESSION_CANCEL_REQUESTED != 0)
}

/// Sequential specification of a session operation. Cancel from Pending is the pre-dispatch cutpoint.
/// Cancel from Dispatching or Dispatched only raises the flag: the post-dispatch cutpoint.
pub const fn session_step(word: u8, ev: SessionEvent) -> Option<u8> {
    let (state, req) = session_unpack(word);
    match (state, ev) {
        (SessionState::Pending, SessionEvent::BeginDispatch) => Some(session_pack(SessionState::Dispatching, false)),
        (SessionState::Pending, SessionEvent::Cancel) => Some(session_pack(SessionState::Cancelled, true)),
        (SessionState::Dispatching, SessionEvent::DispatchDone) => Some(session_pack(SessionState::Dispatched, req)),
        (SessionState::Dispatched, SessionEvent::Complete) => Some(session_pack(SessionState::Completed, req)),
        (SessionState::Dispatching, SessionEvent::Cancel) | (SessionState::Dispatched, SessionEvent::Cancel) => {
            Some(session_pack(state, true))
        }
        (SessionState::Cancelled, SessionEvent::Cancel) => Some(word),
        _ => None,
    }
}

pub const fn cancel_cutpoint(word: u8) -> Cutpoint {
    match session_unpack(word) {
        (SessionState::Cancelled, _) => Cutpoint::PreDispatch,
        (_, true) => Cutpoint::PostDispatch,
        (_, false) => Cutpoint::NotCancelled,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPublish { pub generation: u32, pub hash_index: u32 }

pub const fn epoch_pack(generation: u32, hash_index: u32) -> u64 { ((generation as u64) << 32) | (hash_index as u64) }
pub const fn epoch_unpack(word: u64) -> (u32, u32) { ((word >> 32) as u32, (word & 0xFFFF_FFFF) as u32) }

/// Monotone publication: only the next generation is accepted. This is the `compare_and_swap`
/// discipline a `WeightEpoch` publisher must follow so a stale publisher loses.
pub const fn epoch_step(word: u64, p: EpochPublish) -> Option<u64> {
    match epoch_unpack(word).0.checked_add(1) {
        Some(next) => if next == p.generation { Some(epoch_pack(p.generation, p.hash_index)) } else { None },
        None => None,
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn nonce_pack_unpack_roundtrip() {
        let op_id: u64 = kani::any();
        kani::assume(op_id <= NONCE_OP_ID_MAX);
        let state = nonce_unpack(kani::any()).0;
        let word = nonce_pack(state, op_id).unwrap();
        assert_eq!(nonce_unpack(word), (state, op_id));
    }

    #[kani::proof]
    fn nonce_terminals_absorb_and_commit_needs_matching_owner() {
        let word: u64 = kani::any();
        let cmd: NonceCmd = kani::any();
        let (s0, owner) = nonce_unpack(word);
        if let Some(next) = nonce_step(word, cmd) {
            assert!(s0 != NonceState::Committed && s0 != NonceState::Burned);
            let (s1, o1) = nonce_unpack(next);
            if s1 == NonceState::Committed { assert!(s0 == NonceState::Reserved && owner == cmd.op_id && o1 == cmd.op_id); }
            if s0 == NonceState::Reserved { assert!(owner == cmd.op_id); }
        }
    }

    #[kani::proof]
    fn session_cancel_and_dispatch_are_exclusive() {
        let word: u8 = kani::any();
        if let Some(dispatching) = session_step(word, SessionEvent::BeginDispatch) {
            let cancelled = session_step(word, SessionEvent::Cancel).unwrap();
            assert_eq!(session_unpack(cancelled).0, SessionState::Cancelled);
            assert!(session_step(cancelled, SessionEvent::BeginDispatch).is_none());
            let late = session_step(dispatching, SessionEvent::Cancel).unwrap();
            assert_eq!(cancel_cutpoint(late), Cutpoint::PostDispatch);
        }
    }

    #[kani::proof]
    fn holder_count_stays_in_bounds() {
        let n: usize = kani::any();
        kani::assume(n <= MAX_HOLDERS_PER_CHILD);
        if let Some(m) = holder_step(n, HolderOp::Acquire) { assert!(m <= MAX_HOLDERS_PER_CHILD && Some(m) == n.checked_add(1)); }
        if let Some(m) = holder_step(n, HolderOp::Release) { assert!(n >= 1 && Some(n) == m.checked_add(1)); }
    }
}
```

**Sync facade and atomic cells in `chio-kernel`.** The facade lets the same cell code run under std and under loom.

```rust
// crates/kernel/chio-kernel/src/sync.rs
#[cfg(loom)]
pub use loom::sync::{atomic, Arc, Mutex};
#[cfg(not(loom))]
pub use std::sync::{atomic, Arc, Mutex};
```

```rust
// crates/kernel/chio-kernel/src/concurrency.rs
use crate::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
pub use chio_kernel_core::concurrency_words::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected<W> { pub observed: W }

macro_rules! single_word_cell {
    ($name:ident, $atomic:ty, $word:ty, $op:ty, $step:path) => {
        pub struct $name($atomic);
        impl $name {
            pub fn new(initial: $word) -> Self { Self(<$atomic>::new(initial)) }
            pub fn load(&self) -> $word { self.0.load(Ordering::Acquire) }
            /// Linearization point: the successful CAS, or the final read that made `$step` reject.
            pub fn apply(&self, op: $op) -> Result<$word, Rejected<$word>> {
                let mut cur = self.0.load(Ordering::Acquire);
                loop {
                    let next = $step(cur, op).ok_or(Rejected { observed: cur })?;
                    match self.0.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => return Ok(next),
                        Err(actual) => cur = actual,
                    }
                }
            }
        }
    };
}

single_word_cell!(NonceCell, AtomicU64, u64, NonceCmd, nonce_step);
single_word_cell!(HolderCell, AtomicUsize, usize, HolderOp, holder_step);
single_word_cell!(SessionCell, AtomicU8, u8, SessionEvent, session_step);
single_word_cell!(EpochCell, AtomicU64, u64, EpochPublish, epoch_step);
```

**Loom permutation tests.** Run with the flags in the header comment. The two negative tests are expected to panic inside the model, which is what `should_panic` records.

```rust
// crates/kernel/chio-kernel/tests/loom_concurrency.rs
// RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 cargo test -p chio-kernel --test loom_concurrency --release
#![cfg(loom)]
#![forbid(unsafe_code)]

use chio_kernel::concurrency::*;
use chio_kernel::sync::{atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst}, Arc, Mutex};
use loom::thread;

const PARENT_SHARE_BPS: u32 = 10_000; // MAX_BUDGET_SHARE_BPS
const CHILD_ASK_BPS: u32 = 6_000;

fn hash_of(generation: u64) -> u64 { generation.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03 }

#[test]
#[should_panic]
fn weight_epoch_two_word_publication_tears() {
    loom::model(|| {
        let gen = Arc::new(AtomicU64::new(0));
        let hash = Arc::new(AtomicU64::new(hash_of(0)));
        let (g, h) = (Arc::clone(&gen), Arc::clone(&hash));
        let writer = thread::spawn(move || { h.store(hash_of(1), SeqCst); g.store(1, SeqCst); });
        let seen_gen = gen.load(SeqCst);
        let seen_hash = hash.load(SeqCst);
        writer.join().unwrap();
        assert_eq!(seen_hash, hash_of(seen_gen), "reader bound a weights hash from another epoch");
    });
}

#[test]
fn weight_epoch_single_word_publication_is_linearizable() {
    loom::model(|| {
        let table: Arc<[u64; 3]> = Arc::new([hash_of(0), hash_of(1), hash_of(2)]);
        let cell = Arc::new(EpochCell::new(epoch_pack(0, 0)));
        let publisher = { let c = Arc::clone(&cell); thread::spawn(move || {
            assert!(c.apply(EpochPublish { generation: 1, hash_index: 1 }).is_ok());
            assert!(c.apply(EpochPublish { generation: 2, hash_index: 2 }).is_ok());
            assert!(c.apply(EpochPublish { generation: 2, hash_index: 0 }).is_err(), "stale publisher must lose");
        }) };
        let reader = { let (c, t) = (Arc::clone(&cell), Arc::clone(&table)); thread::spawn(move || {
            let mut last_gen = 0u32;
            for _ in 0..2 {
                let (g, idx) = epoch_unpack(c.load());
                assert_eq!(t[idx as usize], hash_of(u64::from(g)), "torn epoch");
                assert!(g >= last_gen, "generation went backwards within one reader");
                last_gen = g;
            }
        }) };
        publisher.join().unwrap();
        reader.join().unwrap();
    });
}

#[test]
fn execution_nonce_reserve_commit_has_a_single_winner() {
    loom::model(|| {
        let nonce = Arc::new(NonceCell::new(0));
        let commits = Arc::new(AtomicUsize::new(0));
        let spawn = |op_id: u64| { let (n, c) = (Arc::clone(&nonce), Arc::clone(&commits)); thread::spawn(move || {
            if n.apply(NonceCmd { op: NonceOp::Reserve, op_id }).is_ok() {
                n.apply(NonceCmd { op: NonceOp::Commit, op_id }).expect("owner commit cannot be rejected");
                c.fetch_add(1, SeqCst);
            }
        }) };
        let (a, b) = (spawn(1), spawn(2));
        a.join().unwrap();
        b.join().unwrap();
        assert_eq!(commits.load(SeqCst), 1);
        let (state, owner) = nonce_unpack(nonce.load());
        assert_eq!(state, NonceState::Committed);
        let loser = if owner == 1 { 2 } else { 1 };
        assert!(nonce.apply(NonceCmd { op: NonceOp::Commit, op_id: loser }).is_err());
    });
}

#[test]
fn execution_nonce_rollback_hands_off_exactly_once() {
    loom::model(|| {
        let nonce = Arc::new(NonceCell::new(0));
        nonce.apply(NonceCmd { op: NonceOp::Reserve, op_id: 7 }).unwrap();
        let n = Arc::clone(&nonce);
        let contender = thread::spawn(move || n.apply(NonceCmd { op: NonceOp::Reserve, op_id: 9 }).is_ok());
        assert!(nonce.apply(NonceCmd { op: NonceOp::RollbackPreDispatch, op_id: 7 }).is_ok());
        let contender_won = contender.join().unwrap();
        let (state, owner) = nonce_unpack(nonce.load());
        if contender_won { assert_eq!((state, owner), (NonceState::Reserved, 9)); } else { assert_eq!(state, NonceState::Free); }
        assert!(nonce.apply(NonceCmd { op: NonceOp::Commit, op_id: 7 }).is_err(), "rolled-back owner must never commit");
    });
}

struct SplitTable { parent_share_bps: u32, total_child_bps: u32 }

fn precheck(t: &SplitTable, ask: u32) -> bool {
    t.total_child_bps.checked_add(ask).is_some_and(|sum| sum <= t.parent_share_bps)
}

fn admit_atomic(t: &mut SplitTable, ask: u32) -> bool {
    if precheck(t, ask) { t.total_child_bps = t.total_child_bps.checked_add(ask).unwrap(); true } else { false }
}

#[test]
#[should_panic]
fn budget_split_two_phase_admission_oversubscribes_siblings() {
    loom::model(|| {
        let table = Arc::new(Mutex::new(SplitTable { parent_share_bps: PARENT_SHARE_BPS, total_child_bps: 0 }));
        let spawn = || { let t = Arc::clone(&table); thread::spawn(move || {
            let ok = precheck(&t.lock().unwrap(), CHILD_ASK_BPS); // lock 1: advisory check, Kleene bottom
            if ok {                                                // lock 2: act on a stale observation
                let mut g = t.lock().unwrap();
                g.total_child_bps = g.total_child_bps.checked_add(CHILD_ASK_BPS).unwrap();
            }
        }) };
        let (a, b) = (spawn(), spawn());
        a.join().unwrap();
        b.join().unwrap();
        assert!(table.lock().unwrap().total_child_bps <= PARENT_SHARE_BPS, "OversubscribedSiblings");
    });
}

#[test]
fn budget_split_atomic_admission_and_holder_refcounts() {
    loom::model(|| {
        let table = Arc::new(Mutex::new(SplitTable { parent_share_bps: PARENT_SHARE_BPS, total_child_bps: 0 }));
        let holders = Arc::new(HolderCell::new(0));
        let zero_to_one = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicUsize::new(0));
        let spawn = || {
            let (t, h, z, r) = (Arc::clone(&table), Arc::clone(&holders), Arc::clone(&zero_to_one), Arc::clone(&retired));
            thread::spawn(move || {
                let admitted = admit_atomic(&mut t.lock().unwrap(), CHILD_ASK_BPS); // one critical section
                if h.apply(HolderOp::Acquire).expect("below cap") == 1 { z.fetch_add(1, SeqCst); }
                if h.apply(HolderOp::Release).expect("owned") == 0 { r.fetch_add(1, SeqCst); }
                admitted
            })
        };
        let (a, b) = (spawn(), spawn());
        let admitted = usize::from(a.join().unwrap()) + usize::from(b.join().unwrap());
        assert_eq!(admitted, 1, "exactly one 6000 bps child fits under a 10000 bps parent");
        assert_eq!(holders.load(), 0);
        assert_eq!(retired.load(SeqCst), zero_to_one.load(SeqCst), "exactly one retirer per zero epoch");
    });
}

#[test]
fn session_cancellation_is_exclusive_with_dispatch_at_both_cutpoints() {
    loom::model(|| {
        let session = Arc::new(SessionCell::new(session_pack(SessionState::Pending, false)));
        let nonce = Arc::new(NonceCell::new(0));
        let side_effects = Arc::new(AtomicUsize::new(0));
        nonce.apply(NonceCmd { op: NonceOp::Reserve, op_id: 1 }).unwrap();

        let dispatcher = {
            let (s, n, e) = (Arc::clone(&session), Arc::clone(&nonce), Arc::clone(&side_effects));
            thread::spawn(move || match s.apply(SessionEvent::BeginDispatch) {
                Err(_) => { n.apply(NonceCmd { op: NonceOp::RollbackPreDispatch, op_id: 1 }).unwrap(); }
                Ok(_) => {
                    e.fetch_add(1, SeqCst); // the irreversible external effect
                    s.apply(SessionEvent::DispatchDone).unwrap();
                    n.apply(NonceCmd { op: NonceOp::Commit, op_id: 1 }).unwrap();
                    s.apply(SessionEvent::Complete).unwrap();
                }
            })
        };
        let canceller = { let s = Arc::clone(&session); thread::spawn(move || s.apply(SessionEvent::Cancel).map(cancel_cutpoint)) };

        let cancel = canceller.join().unwrap();
        dispatcher.join().unwrap();
        let effects = side_effects.load(SeqCst);
        let (nonce_state, _) = nonce_unpack(nonce.load());
        match cancel {
            Ok(Cutpoint::PreDispatch) => { assert_eq!(effects, 0); assert_eq!(nonce_state, NonceState::Free); }
            Ok(Cutpoint::PostDispatch) => { assert_eq!(effects, 1); assert!(session_unpack(session.load()).1); }
            Ok(Cutpoint::NotCancelled) => unreachable!("an accepted Cancel always records a cutpoint"),
            Err(_) => assert_eq!(effects, 1), // Cancel arrived after Complete
        }
        assert!(!(effects == 1 && nonce_state == NonceState::Free), "effect with a free nonce is a replay window");
    });
}
```

**Deterministic crash and drop simulation.** A simulated write-ahead log with chained checksums models the SQLite WAL. Power loss is modeled by forgetting the in-flight guard, so `Drop` does not run. Unwinding is modeled by dropping it, so `Drop` runs. Recovery takes the longest checksum-valid prefix and discards any trailing partial transaction, which is the SQLite replay rule.

```rust
// crates/kernel/chio-kernel/tests/dst_drop_simulation.rs
#![forbid(unsafe_code)]

use std::{cell::RefCell, rc::Rc};
use chio_kernel_core::concurrency_words::*;
use chio_kernel_core::formal_aeneas::{ledger_apply, ReservationLedger};

const CHECKSUM_SEED: u64 = 0xCBF2_9CE4_8422_2325;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame { Ledger { op: u8, op_id: u64, amount: u64 }, DispatchIntent { op_id: u64 }, TxEnd }

fn mix(acc: u64, x: u64) -> u64 { (acc ^ x).wrapping_mul(0x0000_0100_0000_01B3) } // FNV-1a step, modular by design

fn chain(prev: u64, f: &Frame) -> u64 {
    match *f {
        Frame::Ledger { op, op_id, amount } => mix(mix(mix(mix(prev, 1), u64::from(op)), op_id), amount),
        Frame::DispatchIntent { op_id } => mix(mix(prev, 2), op_id),
        Frame::TxEnd => mix(prev, 3),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FsyncModel { Honest, LastLost } // LastLost: the final fsync before the crash was acknowledged but not durable

struct SimDisk { log: Vec<(Frame, u64)>, synced: Vec<usize>, fsync: FsyncModel, torn_tail: bool }

impl SimDisk {
    fn new(fsync: FsyncModel, torn_tail: bool) -> Self { Self { log: Vec::new(), synced: vec![0], fsync, torn_tail } }
    fn append(&mut self, f: Frame) {
        let prev = self.log.last().map_or(CHECKSUM_SEED, |e| e.1);
        let c = chain(prev, &f);
        self.log.push((f, c));
    }
    fn fsync(&mut self) { self.synced.push(self.log.len()); }
    /// Power loss: the volatile tail vanishes; a torn tail leaves one frame with a bad checksum.
    fn crash(&self) -> Vec<Frame> {
        let durable = match self.fsync {
            FsyncModel::Honest => *self.synced.last().unwrap_or(&0),
            FsyncModel::LastLost => self.synced.len().checked_sub(2).map_or(0, |i| self.synced[i]),
        };
        let mut raw: Vec<(Frame, u64)> = self.log[..durable].to_vec();
        if self.torn_tail { if let Some(&(f, c)) = self.log.get(durable) { raw.push((f, c ^ 1)); } }
        recover(&raw)
    }
}

fn recover(raw: &[(Frame, u64)]) -> Vec<Frame> {
    let mut prev = CHECKSUM_SEED;
    let mut valid = Vec::new();
    for &(f, c) in raw { if chain(prev, &f) != c { break; } valid.push(f); prev = c; }
    let keep = valid.iter().rposition(|f| matches!(f, Frame::TxEnd)).map_or(0, |i| i.saturating_add(1));
    valid.truncate(keep);
    valid
}

/// The in-memory mirror of the cutpoint. On unwind it settles conservatively; on power loss it never runs.
struct ReservationGuard { disk: Rc<RefCell<SimDisk>>, op_id: u64, amount: u64, dispatch_started: bool, settled: bool }

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if self.settled { return; }
        let op = if self.dispatch_started { 3 } else { 2 }; // retain after the cutpoint, release before it
        let mut d = self.disk.borrow_mut();
        d.append(Frame::Ledger { op, op_id: self.op_id, amount: self.amount });
        d.append(Frame::TxEnd);
        d.fsync();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut { BeforeReserveSync, AfterReserveSync, AfterIntentSync, AfterDispatch, BeforeCommitSync, AfterCommitSync, Never }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure { PowerLoss, Unwind }

struct Outcome { ledger: ReservationLedger, nonce: u64, effect: bool, acked: bool }

fn episode(cut: Cut, failure: Failure, fsync: FsyncModel, torn: bool, amount: u64) -> Outcome {
    let disk = Rc::new(RefCell::new(SimDisk::new(fsync, torn)));
    let op_id = 1u64;
    let (mut effect, mut acked) = (false, false);
    let mut guard = ReservationGuard { disk: Rc::clone(&disk), op_id, amount, dispatch_started: false, settled: false };
    let stop = |at: Cut| at == cut;
    'run: {
        { let mut d = disk.borrow_mut(); d.append(Frame::Ledger { op: 0, op_id, amount }); d.append(Frame::TxEnd); }
        if stop(Cut::BeforeReserveSync) { break 'run; }
        disk.borrow_mut().fsync();
        if stop(Cut::AfterReserveSync) { break 'run; }
        { let mut d = disk.borrow_mut(); d.append(Frame::DispatchIntent { op_id }); d.append(Frame::TxEnd); d.fsync(); }
        guard.dispatch_started = true; // write-ahead intent is durable before the effect
        if stop(Cut::AfterIntentSync) { break 'run; }
        effect = true; // irreversible external effect
        if stop(Cut::AfterDispatch) { break 'run; }
        { let mut d = disk.borrow_mut(); d.append(Frame::Ledger { op: 1, op_id, amount }); d.append(Frame::TxEnd); }
        guard.settled = true;
        if stop(Cut::BeforeCommitSync) { break 'run; }
        disk.borrow_mut().fsync();
        acked = true;
        if stop(Cut::AfterCommitSync) { break 'run; }
    }
    let frames = match failure {
        Failure::Unwind => { drop(guard); disk.borrow().log.iter().map(|e| e.0).collect::<Vec<_>>() }
        Failure::PowerLoss => { std::mem::forget(guard); disk.borrow().crash() }
    };
    let (ledger, nonce) = settle(&frames);
    Outcome { ledger, nonce, effect, acked }
}

/// Replay durable frames through the real `ledger_apply`, then settle any in-flight reservation.
fn settle(frames: &[Frame]) -> (ReservationLedger, u64) {
    let mut ledger = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
    let (mut nonce, mut intent, mut pending) = (0u64, false, None::<(u64, u64)>);
    for f in frames {
        match *f {
            Frame::Ledger { op, op_id, amount } => {
                let (next, accepted) = ledger_apply(ledger, op, amount);
                assert!(accepted, "replay of a durable frame must be accepted (A1): {f:?}");
                ledger = next;
                let cmd = match op { 0 => NonceOp::Reserve, 1 => NonceOp::Commit, 2 => NonceOp::RollbackPreDispatch, _ => NonceOp::BurnPostDispatch };
                nonce = nonce_step(nonce, NonceCmd { op: cmd, op_id }).expect("durable frames follow the nonce machine");
                pending = if op == 0 { Some((op_id, amount)) } else { None };
            }
            Frame::DispatchIntent { .. } => intent = true,
            Frame::TxEnd => {}
        }
    }
    if let Some((op_id, amount)) = pending { // crashed in flight: bottom is settled conservatively
        let (op, cmd) = if intent { (3, NonceOp::BurnPostDispatch) } else { (2, NonceOp::RollbackPreDispatch) };
        let (next, accepted) = ledger_apply(ledger, op, amount);
        assert!(accepted);
        ledger = next;
        nonce = nonce_step(nonce, NonceCmd { op: cmd, op_id }).unwrap();
    }
    (ledger, nonce)
}

fn check(o: &Outcome, fsync: FsyncModel, failure: Failure) {
    let settled = o.ledger.committed.checked_add(o.ledger.released).and_then(|s| s.checked_add(o.ledger.retained)).unwrap();
    assert!(settled <= o.ledger.reserved, "I1 conservation");
    assert_eq!(settled, o.ledger.reserved, "I2 terminal after settlement (mirror of ledger_is_terminal, A2)");
    if !o.effect { assert_eq!(o.ledger.committed, 0, "I4 no commit without an effect"); }
    if o.effect && (fsync == FsyncModel::Honest || failure == Failure::Unwind) {
        let state = nonce_unpack(o.nonce).0;
        assert!(matches!(state, NonceState::Committed | NonceState::Burned), "I3 no replay window");
        assert_eq!(o.ledger.released, 0, "I3 an effect is never released");
    }
    if o.acked && fsync == FsyncModel::Honest { assert_eq!(o.ledger.committed, o.ledger.reserved, "I5 acknowledged commit is durable"); }
}

#[test]
fn deterministic_crash_and_drop_episodes() {
    const CUTS: [Cut; 7] = [Cut::BeforeReserveSync, Cut::AfterReserveSync, Cut::AfterIntentSync, Cut::AfterDispatch, Cut::BeforeCommitSync, Cut::AfterCommitSync, Cut::Never];
    let mut replay_windows_under_lying_fsync = 0usize;
    for seed in 0..16u64 {
        let amount = seed.saturating_mul(97).saturating_add(1);
        for cut in CUTS { for failure in [Failure::PowerLoss, Failure::Unwind] { for fsync in [FsyncModel::Honest, FsyncModel::LastLost] { for torn in [false, true] {
            let o = episode(cut, failure, fsync, torn, amount);
            check(&o, fsync, failure);
            if o.effect && nonce_unpack(o.nonce).0 == NonceState::Free { replay_windows_under_lying_fsync = replay_windows_under_lying_fsync.saturating_add(1); }
        } } } }
    }
    assert!(replay_windows_under_lying_fsync > 0, "oracle sensitivity: a lying fsync on the intent frame must be caught");
}
```

## 3. Formal obligations, wiring, and expected results

**Lean 4, additive file, no Mathlib.** Designed to elaborate under the toolchain pinned in `formal/lean4/lean-toolchain`. It was not elaborated in this session.

```lean
-- formal/lean4/Chio/ConcurrencyWords.lean
namespace Chio.ConcurrencyWords

inductive LedgerOp | reserve | commit | release | retain deriving DecidableEq, Repr

structure Ledger where
  reserved : Nat
  committed : Nat
  released : Nat
  retained : Nat
  deriving Repr

def Ledger.settled (l : Ledger) : Nat := l.committed + l.released + l.retained
def Ledger.conserved (l : Ledger) : Prop := l.settled ≤ l.reserved
def Ledger.terminal (l : Ledger) : Prop := l.settled = l.reserved

/-- Mirror of `ledger_apply(state, op, amount) -> (ReservationLedger, bool)` under assumption A1. -/
def Ledger.apply (l : Ledger) (op : LedgerOp) (amt : Nat) : Ledger × Bool :=
  match op with
  | .reserve => ({ l with reserved := l.reserved + amt }, true)
  | .commit  => if l.settled + amt ≤ l.reserved then ({ l with committed := l.committed + amt }, true) else (l, false)
  | .release => if l.settled + amt ≤ l.reserved then ({ l with released := l.released + amt }, true) else (l, false)
  | .retain  => if l.settled + amt ≤ l.reserved then ({ l with retained := l.retained + amt }, true) else (l, false)

theorem apply_conserved (l : Ledger) (op : LedgerOp) (amt : Nat) (h : l.conserved) :
    (l.apply op amt).1.conserved := by
  cases op <;> simp only [Ledger.apply, Ledger.conserved, Ledger.settled] at h ⊢ <;> (try split) <;> dsimp only <;> omega

/-- Settling the single in-flight reservation by commit, release, or retain reaches the terminal ledger. -/
theorem settle_pending_terminal (l : Ledger) (amt : Nat) (op : LedgerOp) (hop : op ≠ .reserve)
    (h : l.settled + amt = l.reserved) : (l.apply op amt).1.terminal := by
  cases op with
  | reserve => exact absurd rfl hop
  | commit | release | retain =>
    simp only [Ledger.apply, Ledger.terminal, Ledger.settled] at h ⊢ <;> split <;> dsimp only <;> omega

inductive NonceState | free | reserved | committed | burned deriving DecidableEq, Repr
inductive NonceOp | reserve | commit | rollbackPre | burnPost deriving DecidableEq, Repr
structure NonceWord where
  state : NonceState
  owner : Nat
  deriving DecidableEq, Repr

def nonceStep (w : NonceWord) (op : NonceOp) (opId : Nat) : Option NonceWord :=
  match w.state, op with
  | .free, .reserve         => some ⟨.reserved, opId⟩
  | .reserved, .commit      => if w.owner = opId then some ⟨.committed, opId⟩ else none
  | .reserved, .rollbackPre => if w.owner = opId then some ⟨.free, 0⟩ else none
  | .reserved, .burnPost    => if w.owner = opId then some ⟨.burned, opId⟩ else none
  | _, _ => none

theorem committed_absorbing (o : Nat) (op : NonceOp) (i : Nat) : nonceStep ⟨.committed, o⟩ op i = none := by
  cases op <;> rfl
theorem burned_absorbing (o : Nat) (op : NonceOp) (i : Nat) : nonceStep ⟨.burned, o⟩ op i = none := by
  cases op <;> rfl
theorem reserve_requires_free (w : NonceWord) (i : Nat) (h : w.state ≠ .free) : nonceStep w .reserve i = none := by
  obtain ⟨s, o⟩ := w
  cases s <;> first | exact absurd rfl h | rfl

inductive SState | pending | dispatching | dispatched | completed | cancelled deriving DecidableEq, Repr
inductive SEv | beginDispatch | dispatchDone | complete | cancel deriving DecidableEq, Repr
structure SWord where
  st : SState
  req : Bool
  deriving DecidableEq, Repr

def sstep (w : SWord) (e : SEv) : Option SWord :=
  match w.st, e with
  | .pending, .beginDispatch   => some ⟨.dispatching, false⟩
  | .pending, .cancel          => some ⟨.cancelled, true⟩
  | .dispatching, .dispatchDone => some ⟨.dispatched, w.req⟩
  | .dispatched, .complete     => some ⟨.completed, w.req⟩
  | .dispatching, .cancel      => some ⟨.dispatching, true⟩
  | .dispatched, .cancel       => some ⟨.dispatched, true⟩
  | .cancelled, .cancel        => some w
  | _, _ => none

theorem cancelled_blocks_dispatch (b : Bool) : sstep ⟨.cancelled, b⟩ .beginDispatch = none := rfl
theorem dispatch_blocks_cancellation (b : Bool) : sstep ⟨.dispatching, b⟩ .cancel = some ⟨.dispatching, true⟩ := rfl
theorem dispatch_enabled_iff_pending (w : SWord) : (sstep w .beginDispatch).isSome ↔ w.st = .pending := by
  obtain ⟨s, r⟩ := w
  cases s <;> simp [sstep]

end Chio.ConcurrencyWords
```

**Apalache TLA+.** The crash loses volatile state; durability is carried by the intent and commit flags. Check with the command in the trailing comment.

```tla
---------------------------- MODULE SessionCancelCrash ----------------------------
EXTENDS Integers
CONSTANT
  \* @type: Int;
  AMT
VARIABLES
  \* @type: Str;
  st,
  \* @type: Str;
  nonce,
  \* @type: Bool;
  cancelReq,
  \* @type: Bool;
  effect,
  \* @type: Bool;
  intentDurable,
  \* @type: Bool;
  commitDurable,
  \* @type: Bool;
  crashed,
  \* @type: Int;
  committed,
  \* @type: Int;
  released,
  \* @type: Int;
  retained

ConstInit == AMT = 100
Init == /\ st = "pending" /\ nonce = "reserved" /\ cancelReq = FALSE /\ effect = FALSE
        /\ intentDurable = FALSE /\ commitDurable = FALSE /\ crashed = FALSE
        /\ committed = 0 /\ released = 0 /\ retained = 0
Live == ~crashed

BeginDispatch == Live /\ st = "pending" /\ st' = "dispatching"
  /\ UNCHANGED <<nonce, cancelReq, effect, intentDurable, commitDurable, crashed, committed, released, retained>>
SyncIntent == Live /\ st = "dispatching" /\ ~intentDurable /\ intentDurable' = TRUE
  /\ UNCHANGED <<st, nonce, cancelReq, effect, commitDurable, crashed, committed, released, retained>>
Dispatch == Live /\ st = "dispatching" /\ intentDurable /\ ~effect /\ effect' = TRUE /\ st' = "dispatched"
  /\ UNCHANGED <<nonce, cancelReq, intentDurable, commitDurable, crashed, committed, released, retained>>
CommitTx == Live /\ st = "dispatched" /\ nonce = "reserved" /\ nonce' = "committed"
  /\ committed' = committed + AMT /\ commitDurable' = TRUE /\ st' = "completed"
  /\ UNCHANGED <<cancelReq, effect, intentDurable, crashed, released, retained>>
CancelPre == Live /\ st = "pending" /\ st' = "cancelled" /\ cancelReq' = TRUE
  /\ nonce' = "free" /\ released' = released + AMT
  /\ UNCHANGED <<effect, intentDurable, commitDurable, crashed, committed, retained>>
CancelPost == Live /\ st \in {"dispatching", "dispatched"} /\ cancelReq' = TRUE
  /\ UNCHANGED <<st, nonce, effect, intentDurable, commitDurable, crashed, committed, released, retained>>
Crash == Live /\ st \notin {"completed", "cancelled"} /\ crashed' = TRUE
  /\ UNCHANGED <<st, nonce, cancelReq, effect, intentDurable, commitDurable, committed, released, retained>>
Recover == crashed /\ nonce = "reserved" /\ crashed' = FALSE /\ st' = "recovered"
  /\ IF intentDurable THEN nonce' = "burned" /\ retained' = retained + AMT /\ released' = released
                      ELSE nonce' = "free" /\ released' = released + AMT /\ retained' = retained
  /\ UNCHANGED <<cancelReq, effect, intentDurable, commitDurable, committed>>

Next == BeginDispatch \/ SyncIntent \/ Dispatch \/ CommitTx \/ CancelPre \/ CancelPost \/ Crash \/ Recover

NoGhostEffect == st = "cancelled" => ~effect
NoReplay      == effect => nonce # "free"
Conservation  == committed + released + retained <= AMT
Terminal      == st \in {"completed", "cancelled", "recovered"} => committed + released + retained = AMT
Safety == NoGhostEffect /\ NoReplay /\ Conservation /\ Terminal
\* apalache-mc check --cinit=ConstInit --inv=Safety --length=12 SessionCancelCrash.tla
===================================================================================
```

**Theorem 2 (nonce single commit, exact rollback).** In any history, each reservation epoch of a nonce is followed by at most one commit, a rolled-back owner can never commit, and a losing reserver observes the winner's word. *Proof.* By the Lean lemmas, Committed and Burned are absorbing and Reserve is enabled only from Free. Commit, rollback, and burn require the owner stored in the word, so after a rollback the stale owner finds Free or a different owner and is rejected. Two reservers both read Free, but only one compare-and-swap can succeed in the modification order and the other re-reads Reserved. Theorem 1 lifts these sequential facts to every interleaving. ∎

**Theorem 3 (holder bounds and the unique retirer).** The count stays within zero and the cap, and each transition to zero is observed by exactly one releaser. *Proof.* Both bounds are inductive over `holder_step`, as the Kani harness states. Any two successful transitions to zero are distinct writes in the modification order, and between them some acquire must have moved the count off zero. So each zero epoch has exactly one retirement write, and only the releaser that produced it observes zero. The two-phase admission fails because the check linearizes at the first lock release and the insertion at the second, so the composite is not a single-word object and the sibling bound is checked against a stale state. Checking and inserting under one lock acquisition restores a single linearization point. ∎

**Theorem 4 (cancel and dispatch exclusivity).** Dispatch implies the session word is never Cancelled, and Cancelled implies no external effect ever occurs. *Proof.* `BeginDispatch` and the cancelling transition are both enabled only from Pending without the flag, so exactly one compare-and-swap wins. If cancel wins, the dispatcher re-reads Cancelled and `session_step` rejects, so the effect is never issued and the nonce rolls back to Free. If dispatch wins, cancel re-reads Dispatching or Dispatched and can only raise the flag, which records the post-dispatch cutpoint without undoing anything. The Kani harness checks exactly these two re-reads. ∎

**Theorem 5 (crash recovery).** After recovery and settlement, conservation holds, the ledger is terminal, no commit exists without an effect, and under an honest disk no effect leaves a Free nonce. *Proof.* Durable frames form a prefix of the written sequence because fsync is monotone, and recovery truncates to a checksum-valid prefix ending at a transaction boundary. Replaying it through `ledger_apply` preserves conservation by `apply_conserved`. The effect is issued only after the intent frame is durable, so a missing durable intent proves the crash was pre-dispatch and release is safe. A durable intent makes the outcome unknowable, so settlement retains the amount and burns the nonce, never commits and never releases. `settle_pending_terminal` then gives the terminal ledger. A disk that loses the intent fsync breaks the write-ahead premise, which is why the suite tallies those replay windows instead of asserting their absence. ∎

**Wiring.** Add `loom` under `[target.'cfg(loom)'.dependencies]` in the `chio-kernel` manifest. Add the Lean file and the four Kani harnesses to `formal/proof-manifest.toml` as new entries, leaving every pinned signature untouched. Record the cutpoint as a nested field under the existing `receipt_context` metadata key rather than growing the reserved-key array, whose length is pinned. A `revalidate_before_dispatch` denial maps to Cancel at Pending, which is the pre-dispatch cutpoint with a release. A sticky `PendingApproval` keeps the word at Pending, so a racing approval and cancel are resolved by the same compare-and-swap.

**Expected results, not observed.**

| Test or check | Expected |
|---|---|
| two-word epoch tear | loom panics, `should_panic` passes |
| single-word epoch | exhaustive, passes |
| nonce single winner, rollback hand-off | exhaustive, pass |
| two-phase admission | loom panics, `should_panic` passes |
| atomic admission and holder refcounts | passes |
| session cutpoints | passes |
| crash and drop episodes | 896 episodes pass, replay-window tally positive |
| Kani harnesses | 4 verified |
| Apalache `Safety` to depth 12 | no violation |

Recap. The pass reduces all four concurrent objects to single-word state machines whose linearizability follows from one theorem, with the predictor appearing only as nondeterminism. The loom suite pins the two bug classes that ordering flags cannot fix, torn multi-word publication and two-phase check-then-act. The crash simulation establishes conservation and terminality under power loss, unwinding, torn tails, and a lying fsync, with the `retained` bucket carrying the Kleene bottom mass. Nothing here was compiled or run. The next step is to compile the two kernel modules, run the loom and simulation suites, elaborate the Lean file, and run the Kani and Apalache checks against assumptions A1 and A2.

---

# Verbatim Treatise - `wave13_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_13`

I'll lay out the L3 protocol-edge design as one `#![no_std]` crate with three lifts, the Copley segment mapping, the hybrid signing floor, federated offline verification, attestation coupling, and then the Lean 4, Apalache, and Kani obligations with proofs.

## 1. Lifting MCP, A2A, and Envoy into one exact request

**Where this sits in the decision tuple.** The protocol edge is the L3 instance of $\mathcal{D}_\ell$. The lift from a wire envelope to `PortableToolCallRequest` is part of $C_{L3}(x)$: it is total, deterministic, and never approximated by a model. Its output is the input $x$ to the Copley predictor $P_{L3}$. The envelope $\mathcal{C}_{L3}$ always contains `Deny`. The projection $\Pi$ is a single match on a three-valued evidence term. Everything below is strictly additive to `formal_core.rs`: the new crate calls `classify_time_window_code`, `budget_precheck`, and `receipt_fields_coupled` by their pinned signatures and introduces no new arithmetic path into them.

**Crate layout.** One `no_std` crate, `chio-protocol-lift`, owns the canonical types and the three lifts as modules. The crates `chio-mcp-edge`, `chio-a2a-adapter`, and `chio-envoy-ext-authz` are `std` shells that parse JSON-RPC, A2A JSON, and the ext_authz protobuf, canonicalize `arguments` with RFC 8785 JSON Canonicalization Scheme, authenticate the peer, and hand borrowed byte slices into the lift. Keeping the constructor `pub(crate)` means a `PortableToolCallRequest` can only exist as the result of a lift.

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use chio_kernel_core::formal_core::{budget_precheck, classify_time_window_code, receipt_fields_coupled};

pub const COMMAND_LINE_CAP: usize = 4096;
pub const IMAGE_CAP: usize = 512;
pub const ORIGINAL_FILE_NAME_CAP: usize = 256;
pub const PARENT_IMAGE_CAP: usize = 512;
pub const MAX_A2A_TEXT_PARTS: usize = 64;
pub const A2A_PART_SEPARATOR: u8 = 0x1F;
pub const LIFT_DOMAIN: &[u8] = b"chio-portable-tool-call-v1";

#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// Strong Kleene conjunction: Neg absorbs, Pos needs both, otherwise Bot.
    pub const fn and(self, rhs: K3) -> K3 {
        match (self, rhs) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Pos, K3::Pos) => K3::Pos,
            _ => K3::Bot,
        }
    }
    pub const fn from_bool(b: bool) -> K3 { if b { K3::Pos } else { K3::Neg } }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SegmentRole { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiftError {
    SegmentOverflow { segment: SegmentRole, len: usize, cap: usize },
    PartCountOverflow { parts: usize },
    TimeWindowOverflow,
    NotYetValid,
    Expired,
    EmptyPrincipal,
    EmptyTarget,
    CostOverflow,
    Encoding,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment<const N: usize> { len: usize, bytes: [u8; N] }

impl<const N: usize> Segment<N> {
    pub const fn empty() -> Self { Self { len: 0, bytes: [0u8; N] } }

    pub fn try_from_slice(role: SegmentRole, src: &[u8]) -> Result<Self, LiftError> {
        let len = src.len();
        if len > N { return Err(LiftError::SegmentOverflow { segment: role, len, cap: N }); }
        let mut bytes = [0u8; N];
        if let Some(dst) = bytes.get_mut(..len) { dst.copy_from_slice(src); }
        Ok(Self { len, bytes })
    }

    pub fn try_push(&mut self, role: SegmentRole, src: &[u8]) -> Result<(), LiftError> {
        let end = self.len.checked_add(src.len())
            .ok_or(LiftError::SegmentOverflow { segment: role, len: usize::MAX, cap: N })?;
        if end > N { return Err(LiftError::SegmentOverflow { segment: role, len: end, cap: N }); }
        if let Some(dst) = self.bytes.get_mut(self.len..end) { dst.copy_from_slice(src); }
        self.len = end;
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] { self.bytes.get(..self.len).unwrap_or(&[]) }
    pub const fn len(&self) -> usize { self.len }
    pub const fn is_empty(&self) -> bool { self.len == 0 }
}
```

**Canonical hashing.** The crate never allocates, so canonical encoding is a streaming tag-length-value absorb into a caller-supplied digest. The digest backend is a trait so the same code runs against SHA3-256 on the kernel and against a vendored implementation on an air-gapped verifier.

```rust
pub trait Digest256 { fn update(&mut self, bytes: &[u8]); fn finalize(self) -> [u8; 32]; }
pub trait DigestFactory { type D: Digest256; fn new_digest(&self) -> Self::D; }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CanonicalEncodingError;

impl From<CanonicalEncodingError> for LiftError {
    fn from(_: CanonicalEncodingError) -> Self { LiftError::Encoding }
}

fn absorb_field<D: Digest256>(d: &mut D, tag: u8, bytes: &[u8]) -> Result<(), CanonicalEncodingError> {
    let len = u32::try_from(bytes.len()).map_err(|_| CanonicalEncodingError)?;
    d.update(&[tag]);
    d.update(&len.to_be_bytes());
    d.update(bytes);
    Ok(())
}

fn absorb_u64<D: Digest256>(d: &mut D, tag: u8, v: u64) {
    d.update(&[tag]);
    d.update(&v.to_be_bytes());
}
```

**The portable request.** Fields are private. The time window is validated with the existing `classify_time_window_code`, and budget admissibility delegates to the existing `budget_precheck`.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopleySegments {
    pub command_line: Segment<COMMAND_LINE_CAP>,
    pub image: Segment<IMAGE_CAP>,
    pub original_file_name: Segment<ORIGINAL_FILE_NAME_CAP>,
    pub parent_image: Segment<PARENT_IMAGE_CAP>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtocolOrigin { McpToolsCall = 1, A2aTasksSend = 2, EnvoyExtAuthzCheck = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortableToolCallRequest {
    origin: ProtocolOrigin,
    issued_at: u64,
    expires_at: u64,
    request_hash: [u8; 32],
    segments: CopleySegments,
    invocation_cost: u64,
    unit_cost: u64,
}

impl PortableToolCallRequest {
    pub(crate) fn seal<D: DigestFactory>(
        df: &D, origin: ProtocolOrigin, issued_at: u64, ttl: u64,
        segments: CopleySegments, now: u64,
    ) -> Result<Self, LiftError> {
        let expires_at = issued_at.checked_add(ttl).ok_or(LiftError::TimeWindowOverflow)?;
        match classify_time_window_code(now, issued_at, expires_at) {
            0 => {}
            1 => return Err(LiftError::NotYetValid),
            _ => return Err(LiftError::Expired),
        }
        let total = segments.command_line.len()
            .checked_add(segments.image.len())
            .and_then(|t| t.checked_add(segments.original_file_name.len()))
            .and_then(|t| t.checked_add(segments.parent_image.len()))
            .ok_or(LiftError::CostOverflow)?;
        let unit_cost = u64::try_from(total).map_err(|_| LiftError::CostOverflow)?;

        let mut d = df.new_digest();
        absorb_field(&mut d, 0x00, LIFT_DOMAIN)?;
        d.update(&[origin as u8]);
        absorb_u64(&mut d, 0x01, issued_at);
        absorb_u64(&mut d, 0x02, expires_at);
        absorb_field(&mut d, 0x10, segments.command_line.as_bytes())?;
        absorb_field(&mut d, 0x11, segments.image.as_bytes())?;
        absorb_field(&mut d, 0x12, segments.original_file_name.as_bytes())?;
        absorb_field(&mut d, 0x13, segments.parent_image.as_bytes())?;

        Ok(Self { origin, issued_at, expires_at, request_hash: d.finalize(), segments, invocation_cost: 1, unit_cost })
    }

    pub const fn origin(&self) -> ProtocolOrigin { self.origin }
    pub const fn request_hash(&self) -> &[u8; 32] { &self.request_hash }
    pub const fn segments(&self) -> &CopleySegments { &self.segments }
    pub const fn unit_cost(&self) -> u64 { self.unit_cost }

    pub fn budget_admissible(&self, remaining_invocations: u64, remaining_units: u64) -> bool {
        budget_precheck(remaining_invocations, remaining_units, self.invocation_cost, self.unit_cost)
    }
}

pub trait ProtocolLift {
    type Wire<'w>;
    fn lift<'w, D: DigestFactory>(&self, df: &D, wire: &Self::Wire<'w>, now: u64)
        -> Result<PortableToolCallRequest, LiftError>;
}
```

**Segment mapping.** The Copley model was trained on endpoint telemetry, so each protocol field is assigned to the segment whose telemetry role it plays. The `Image` is the thing being executed, the `ParentImage` is who asked for it, the `CommandLine` is what it was asked to do, and the `OriginalFileName` is the resource it touches.

| Segment | MCP `tools/call` | A2A `tasks/send` | Envoy `CheckRequest` |
|---|---|---|---|
| CommandLine | JCS-canonical `arguments` | text parts joined by `0x1F` | method, space, `:path` |
| Image | `params.name` | `skillId` | destination principal |
| OriginalFileName | `arguments.{path,uri,file}` hint | artifact file name | basename of `:path` |
| ParentImage | pinned MCP server name | authenticated caller agent id | source principal |

```rust
pub struct McpToolsCallWire<'w> {
    pub server_name: &'w [u8],
    pub tool_name: &'w [u8],
    pub arguments_jcs: &'w [u8],
    pub resource_hint: Option<&'w [u8]>,
    pub received_at: u64,
    pub ttl: u64,
}
pub struct McpLift;

impl ProtocolLift for McpLift {
    type Wire<'w> = McpToolsCallWire<'w>;
    fn lift<'w, D: DigestFactory>(&self, df: &D, w: &McpToolsCallWire<'w>, now: u64)
        -> Result<PortableToolCallRequest, LiftError> {
        if w.tool_name.is_empty() { return Err(LiftError::EmptyTarget); }
        if w.server_name.is_empty() { return Err(LiftError::EmptyPrincipal); }
        let segments = CopleySegments {
            command_line: Segment::try_from_slice(SegmentRole::CommandLine, w.arguments_jcs)?,
            image: Segment::try_from_slice(SegmentRole::Image, w.tool_name)?,
            original_file_name: Segment::try_from_slice(SegmentRole::OriginalFileName, w.resource_hint.unwrap_or(&[]))?,
            parent_image: Segment::try_from_slice(SegmentRole::ParentImage, w.server_name)?,
        };
        PortableToolCallRequest::seal(df, ProtocolOrigin::McpToolsCall, w.received_at, w.ttl, segments, now)
    }
}

pub struct A2aTasksSendWire<'w> {
    pub caller_agent_id: &'w [u8],
    pub skill_id: &'w [u8],
    pub text_parts: &'w [&'w [u8]],
    pub artifact_name: Option<&'w [u8]>,
    pub received_at: u64,
    pub ttl: u64,
}
pub struct A2aLift;

impl ProtocolLift for A2aLift {
    type Wire<'w> = A2aTasksSendWire<'w>;
    fn lift<'w, D: DigestFactory>(&self, df: &D, w: &A2aTasksSendWire<'w>, now: u64)
        -> Result<PortableToolCallRequest, LiftError> {
        if w.caller_agent_id.is_empty() { return Err(LiftError::EmptyPrincipal); }
        if w.skill_id.is_empty() { return Err(LiftError::EmptyTarget); }
        if w.text_parts.len() > MAX_A2A_TEXT_PARTS {
            return Err(LiftError::PartCountOverflow { parts: w.text_parts.len() });
        }
        let mut command_line = Segment::<COMMAND_LINE_CAP>::empty();
        for (i, part) in w.text_parts.iter().enumerate() {
            if i > 0 { command_line.try_push(SegmentRole::CommandLine, &[A2A_PART_SEPARATOR])?; }
            command_line.try_push(SegmentRole::CommandLine, part)?;
        }
        let segments = CopleySegments {
            command_line,
            image: Segment::try_from_slice(SegmentRole::Image, w.skill_id)?,
            original_file_name: Segment::try_from_slice(SegmentRole::OriginalFileName, w.artifact_name.unwrap_or(&[]))?,
            parent_image: Segment::try_from_slice(SegmentRole::ParentImage, w.caller_agent_id)?,
        };
        PortableToolCallRequest::seal(df, ProtocolOrigin::A2aTasksSend, w.received_at, w.ttl, segments, now)
    }
}

pub struct EnvoyCheckWire<'w> {
    pub method: &'w [u8],
    pub path: &'w [u8],
    pub source_principal: &'w [u8],
    pub destination_principal: &'w [u8],
    pub received_at: u64,
    pub ttl: u64,
}
pub struct EnvoyExtAuthzLift;

fn path_basename(path: &[u8]) -> &[u8] {
    let without_query = path.split(|b| *b == b'?').next().unwrap_or(path);
    without_query.rsplit(|b| *b == b'/').next().unwrap_or(without_query)
}

impl ProtocolLift for EnvoyExtAuthzLift {
    type Wire<'w> = EnvoyCheckWire<'w>;
    fn lift<'w, D: DigestFactory>(&self, df: &D, w: &EnvoyCheckWire<'w>, now: u64)
        -> Result<PortableToolCallRequest, LiftError> {
        if w.source_principal.is_empty() { return Err(LiftError::EmptyPrincipal); }
        if w.destination_principal.is_empty() { return Err(LiftError::EmptyTarget); }
        let mut command_line = Segment::<COMMAND_LINE_CAP>::empty();
        command_line.try_push(SegmentRole::CommandLine, w.method)?;
        command_line.try_push(SegmentRole::CommandLine, b" ")?;
        command_line.try_push(SegmentRole::CommandLine, w.path)?;
        let segments = CopleySegments {
            command_line,
            image: Segment::try_from_slice(SegmentRole::Image, w.destination_principal)?,
            original_file_name: Segment::try_from_slice(SegmentRole::OriginalFileName, path_basename(w.path))?,
            parent_image: Segment::try_from_slice(SegmentRole::ParentImage, w.source_principal)?,
        };
        PortableToolCallRequest::seal(df, ProtocolOrigin::EnvoyExtAuthzCheck, w.received_at, w.ttl, segments, now)
    }
}
```

For A2A the caller identity must be the head of the `SwarmDelegationWitnessChain` that the adapter already verifies, not a self-asserted field in the message body. For Envoy the principals are the SPIFFE identities from mutual TLS, which Envoy populates only after certificate validation.

**Tier-0 prefilter with shadow prices.** The four segments go to the Tier-1 `UltraBERT` unchanged. Before that, a Tier-0 micro-model in `FixedQ16_16` scores eight cheap integer features and subtracts the Lagrangian penalty $\boldsymbol{\lambda}^\top c(x)$. Overflow anywhere yields $\bot$, which the shield turns into `Deny`.

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const fn from_int(v: i16) -> Self {
        match (v as i32).checked_mul(65_536) { Some(x) => Self(x), None => Self(i32::MAX) }
    }
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(rhs.0))?;
        i32::try_from(wide.checked_div(65_536)?).ok().map(Self)
    }
    pub fn checked_add(self, rhs: Self) -> Option<Self> { self.0.checked_add(rhs.0).map(Self) }
    pub fn checked_sub(self, rhs: Self) -> Option<Self> { self.0.checked_sub(rhs.0).map(Self) }
}

pub struct ShadowPrices {
    pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16,
    pub memory: FixedQ16_16, pub escrow: FixedQ16_16,
}
pub struct TierZeroMicroModel { pub weights: [FixedQ16_16; 8], pub bias: FixedQ16_16 }

/// Private constructor enforces the role-asymmetric invariant `neg <= pos`.
pub struct RoleThresholds { neg: FixedQ16_16, pos: FixedQ16_16 }
impl RoleThresholds {
    pub const fn new(neg: FixedQ16_16, pos: FixedQ16_16) -> Option<Self> {
        if neg.0 <= pos.0 { Some(Self { neg, pos }) } else { None }
    }
}

fn bit_length(n: usize) -> u16 {
    u16::try_from(usize::BITS.checked_sub(n.leading_zeros()).unwrap_or(0)).unwrap_or(u16::MAX)
}
fn count_where(bytes: &[u8], pred: impl Fn(u8) -> bool) -> u16 {
    u16::try_from(bytes.iter().filter(|b| pred(**b)).count()).unwrap_or(u16::MAX)
}
fn saturating_i16(v: u64) -> i16 { i16::try_from(v).unwrap_or(i16::MAX) }

pub fn phi(req: &PortableToolCallRequest) -> [u16; 8] {
    let s = req.segments();
    let cl = s.command_line.as_bytes();
    [
        bit_length(s.command_line.len()),
        bit_length(s.image.len()),
        bit_length(s.original_file_name.len()),
        bit_length(s.parent_image.len()),
        count_where(cl, |b| matches!(b, b'|' | b';' | b'&' | b'`' | b'$' | b'>' | b'<')),
        count_where(cl, |b| b < 0x20 || b == 0x7F),
        u16::from(cl.windows(2).any(|w| w == b"..")),
        req.origin() as u16,
    ]
}

/// Non-negative resource costs c(x) in the order of the shadow-price vector.
pub fn resource_costs(req: &PortableToolCallRequest) -> [i16; 5] {
    let kib = saturating_i16(req.unit_cost().checked_div(1024).unwrap_or(0));
    let escrow = if matches!(req.origin(), ProtocolOrigin::A2aTasksSend) { 1 } else { 0 };
    [kib, 1, saturating_i16(u64::from(bit_length(req.segments().command_line.len()))), kib, escrow]
}

pub fn tier0_score(model: &TierZeroMicroModel, lambda: &ShadowPrices, req: &PortableToolCallRequest) -> Option<FixedQ16_16> {
    let mut acc = model.bias;
    for (w, f) in model.weights.iter().zip(phi(req).iter()) {
        let fq = FixedQ16_16::from_int(i16::try_from(*f).ok()?);
        acc = acc.checked_add(w.checked_mul(fq)?)?;
    }
    let prices = [lambda.budget, lambda.fuel, lambda.latency, lambda.memory, lambda.escrow];
    for (l, c) in prices.iter().zip(resource_costs(req).iter()) {
        acc = acc.checked_sub(l.checked_mul(FixedQ16_16::from_int(*c))?)?;
    }
    Some(acc)
}

pub fn tier0_predicate(model: &TierZeroMicroModel, th: &RoleThresholds, lambda: &ShadowPrices, req: &PortableToolCallRequest) -> K3 {
    match tier0_score(model, lambda, req) {
        None => K3::Bot,
        Some(s) if s >= th.pos => K3::Pos,
        Some(s) if s < th.neg => K3::Neg,
        Some(_) => K3::Bot,
    }
}
```

## 2. Hybrid signing floor and federated offline verification

**Why a floor and not a fallback.** `KernelCryptoFloor` signs every receipt with both Ed25519 and ML-DSA-65 and refuses to issue a receipt if either backend is unavailable. Verification is the Kleene conjunction of the two checks. A verifier that lacks ML-DSA returns $\bot$ rather than $-$ or $+$, so a classical-only verifier can never silently accept, and the shield maps $\bot$ to `Deny`. The suite byte is inside the signed body, so an attacker cannot strip the post-quantum half and relabel the receipt.

| Component | Public key bytes | Signature bytes |
|---|---|---|
| Ed25519 | 32 | 64 |
| ML-DSA-65 | 1952 | 3309 |

```rust
pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA65_PK_LEN: usize = 1952;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub const RECEIPT_DOMAIN: &[u8] = b"chio-portable-receipt-v1";
pub const ROOT_DOMAIN: &[u8] = b"chio-trust-root-v1";
pub const ATTEST_DOMAIN: &[u8] = b"chio-attestation-report-data-v1";
pub const SUITE_HYBRID_ED25519_MLDSA65: u8 = 0x21;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HybridSignature { pub ed25519: [u8; ED25519_SIG_LEN], pub mldsa65: [u8; MLDSA65_SIG_LEN] }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReceiptBody {
    pub suite: u8,
    pub root_id: [u8; 32],
    pub request_hash: [u8; 32],
    pub capability_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub weights_hash: [u8; 32],
    pub attestation_measurement: [u8; 48],
    pub evidence_class: u8,
    pub verdict_code: u8,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ReceiptBody {
    pub fn canonical_digest<D: DigestFactory>(&self, df: &D) -> Result<[u8; 32], CanonicalEncodingError> {
        let mut d = df.new_digest();
        absorb_field(&mut d, 0x00, RECEIPT_DOMAIN)?;
        d.update(&[self.suite, self.evidence_class, self.verdict_code]);
        absorb_field(&mut d, 0x01, &self.root_id)?;
        absorb_field(&mut d, 0x02, &self.request_hash)?;
        absorb_field(&mut d, 0x03, &self.capability_hash)?;
        absorb_field(&mut d, 0x04, &self.policy_hash)?;
        absorb_field(&mut d, 0x05, &self.weights_hash)?;
        absorb_field(&mut d, 0x06, &self.attestation_measurement)?;
        absorb_u64(&mut d, 0x07, self.issued_at);
        absorb_u64(&mut d, 0x08, self.expires_at);
        Ok(d.finalize())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedReceipt { pub body: ReceiptBody, pub signature: HybridSignature }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CryptoFloorError { Ed25519Unavailable, MlDsa65Unavailable, Encoding }

pub trait KernelCryptoFloor {
    fn root_id(&self) -> [u8; 32];
    fn sign_ed25519(&self, digest: &[u8; 32]) -> Result<[u8; ED25519_SIG_LEN], CryptoFloorError>;
    fn sign_mldsa65(&self, digest: &[u8; 32], ctx: &[u8]) -> Result<[u8; MLDSA65_SIG_LEN], CryptoFloorError>;
}

pub fn sign_receipt<F: KernelCryptoFloor, D: DigestFactory>(floor: &F, df: &D, mut body: ReceiptBody)
    -> Result<SignedReceipt, CryptoFloorError> {
    body.suite = SUITE_HYBRID_ED25519_MLDSA65;
    body.root_id = floor.root_id();
    let digest = body.canonical_digest(df).map_err(|_| CryptoFloorError::Encoding)?;
    let ed25519 = floor.sign_ed25519(&digest)?;
    let mldsa65 = floor.sign_mldsa65(&digest, RECEIPT_DOMAIN)?;
    Ok(SignedReceipt { body, signature: HybridSignature { ed25519, mldsa65 } })
}

pub trait HybridVerifier {
    fn verify_ed25519(&self, pk: &[u8; ED25519_PK_LEN], digest: &[u8; 32], sig: &[u8; ED25519_SIG_LEN]) -> K3;
    fn verify_mldsa65(&self, pk: &[u8; MLDSA65_PK_LEN], digest: &[u8; 32], ctx: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> K3;
}
```

The ML-DSA context string is the receipt domain, per FIPS 204, so a receipt signature can never be replayed as a root-certification or attestation signature under the same key.

**Federated trust roots.** A root is identified by a hash of both public keys, and `insert` recomputes that hash. Two federations therefore cannot register the same root id with different keys unless they find a hash collision. Duplicate ids are rejected rather than shadowed, which is what makes the monotonicity theorem in section 3 true.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TrustRoot {
    pub root_id: [u8; 32],
    pub federation_id: [u8; 32],
    pub ed25519_pk: [u8; ED25519_PK_LEN],
    pub mldsa65_pk: [u8; MLDSA65_PK_LEN],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrustStoreError { Full, DuplicateRootId, InvalidWindow, RootIdMismatch, Encoding }

pub fn derive_root_id<D: DigestFactory>(df: &D, ed25519_pk: &[u8; ED25519_PK_LEN], mldsa65_pk: &[u8; MLDSA65_PK_LEN])
    -> Result<[u8; 32], CanonicalEncodingError> {
    let mut d = df.new_digest();
    absorb_field(&mut d, 0x00, ROOT_DOMAIN)?;
    absorb_field(&mut d, 0x01, ed25519_pk)?;
    absorb_field(&mut d, 0x02, mldsa65_pk)?;
    Ok(d.finalize())
}

pub struct FederatedTrustStore<const N: usize> { len: usize, roots: [Option<TrustRoot>; N] }

impl<const N: usize> FederatedTrustStore<N> {
    pub const fn new() -> Self { Self { len: 0, roots: [None; N] } }

    pub fn insert<D: DigestFactory>(&mut self, df: &D, root: TrustRoot) -> Result<(), TrustStoreError> {
        if root.not_before >= root.not_after { return Err(TrustStoreError::InvalidWindow); }
        let expected = derive_root_id(df, &root.ed25519_pk, &root.mldsa65_pk).map_err(|_| TrustStoreError::Encoding)?;
        if expected != root.root_id { return Err(TrustStoreError::RootIdMismatch); }
        if self.find(&root.root_id).is_some() { return Err(TrustStoreError::DuplicateRootId); }
        let slot = self.roots.get_mut(self.len).ok_or(TrustStoreError::Full)?;
        *slot = Some(root);
        self.len = self.len.checked_add(1).ok_or(TrustStoreError::Full)?;
        Ok(())
    }

    pub fn find(&self, root_id: &[u8; 32]) -> Option<&TrustRoot> {
        self.roots.iter().take(self.len).flatten().find(|r| r.root_id == *root_id)
    }

    /// Revocation clears the slot; `find` skips it. Capacity is not reclaimed, by design.
    pub fn revoke(&mut self, root_id: &[u8; 32]) -> bool {
        let mut hit = false;
        for slot in self.roots.iter_mut().take(self.len) {
            if slot.map_or(false, |r| r.root_id == *root_id) { *slot = None; hit = true; }
        }
        hit
    }
}

pub fn verify_receipt_offline<V: HybridVerifier, D: DigestFactory, const N: usize>(
    verifier: &V, df: &D, store: &FederatedTrustStore<N>, receipt: &SignedReceipt, now: u64,
) -> K3 {
    if receipt.body.suite != SUITE_HYBRID_ED25519_MLDSA65 { return K3::Neg; }
    let Some(root) = store.find(&receipt.body.root_id) else { return K3::Bot };
    if classify_time_window_code(now, receipt.body.issued_at, receipt.body.expires_at) != 0 { return K3::Neg; }
    if classify_time_window_code(receipt.body.issued_at, root.not_before, root.not_after) != 0 { return K3::Neg; }
    let Ok(digest) = receipt.body.canonical_digest(df) else { return K3::Bot };
    verifier
        .verify_ed25519(&root.ed25519_pk, &digest, &receipt.signature.ed25519)
        .and(verifier.verify_mldsa65(&root.mldsa65_pk, &digest, RECEIPT_DOMAIN, &receipt.signature.mldsa65))
}
```

An unknown root yields $\bot$, not $-$. The receipt may be valid under a federation this verifier has never imported, so "cannot determine" is the honest value. The shield still denies. Revocation state is local to the store, and offline verification cannot observe revocations that happened after the store was exported. That is a stated limit of offline mode, not a hidden one.

**Hardware attestation coupling.** The vendor certificate chain of an SEV-SNP, TDX, or TPM quote is verified in the `std` edge. The `no_std` core receives the parsed quote and answers one boolean: does this quote bind exactly this receipt. That boolean becomes the fifth argument of the existing `receipt_fields_coupled`, so no existing proof about that function changes. The quote's report data must equal a hash over the root id, the loaded weights hash, and the policy hash. The weights hash comes from `LoadedWeights::loaded_weights_hash` after `evaluate_weights_binding` has accepted the model card. This closes the loop: the attested kernel measurement covers the exact Tier-1 weights whose prediction the receipt records.

```rust
pub const EVIDENCE_CLASS_SOFTWARE_ONLY: u8 = 0;
pub const EVIDENCE_CLASS_TPM_PCR: u8 = 1;
pub const EVIDENCE_CLASS_SEV_SNP: u8 = 2;
pub const EVIDENCE_CLASS_TDX: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttestationQuote {
    pub evidence_class: u8,
    pub measurement: [u8; 48],
    pub report_data: [u8; 32],
    pub root_id: [u8; 32],
}

pub fn expected_report_data<D: DigestFactory>(df: &D, body: &ReceiptBody) -> Result<[u8; 32], CanonicalEncodingError> {
    let mut d = df.new_digest();
    absorb_field(&mut d, 0x00, ATTEST_DOMAIN)?;
    absorb_field(&mut d, 0x01, &body.root_id)?;
    absorb_field(&mut d, 0x02, &body.weights_hash)?;
    absorb_field(&mut d, 0x03, &body.policy_hash)?;
    Ok(d.finalize())
}

pub fn attestation_binds_receipt<D: DigestFactory>(
    df: &D, quote: &AttestationQuote, body: &ReceiptBody, expected_weights_hash: &[u8; 32], minimum_class: u8,
) -> bool {
    let Ok(report) = expected_report_data(df, body) else { return false };
    quote.evidence_class >= minimum_class
        && quote.evidence_class == body.evidence_class
        && quote.measurement == body.attestation_measurement
        && quote.root_id == body.root_id
        && quote.report_data == report
        && body.weights_hash == *expected_weights_hash
}

pub fn receipt_coupled_with_attestation<D: DigestFactory>(
    df: &D, quote: &AttestationQuote, body: &ReceiptBody, expected_weights_hash: &[u8; 32], minimum_class: u8,
    capability_matches: bool, request_matches: bool, verdict_matches: bool, policy_hash_matches: bool,
) -> bool {
    let evidence_class_matches = attestation_binds_receipt(df, quote, body, expected_weights_hash, minimum_class);
    receipt_fields_coupled(capability_matches, request_matches, verdict_matches, policy_hash_matches, evidence_class_matches)
}
```

**The shield.** This is $\Pi_{\mathcal{C}_{L3}(x)}$. The learned verdict is accepted verbatim only when the exact evidence is $+$. Any other evidence collapses the envelope to the singleton `Deny`.

```rust
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeVerdict { Deny = 0, Allow = 1, PendingApproval = 2 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldedEdgeVerdict { verdict: EdgeVerdict, evidence: K3, projected: bool }

impl ShieldedEdgeVerdict {
    pub const fn project(evidence: K3, proposed: EdgeVerdict) -> Self {
        match evidence {
            K3::Pos => Self { verdict: proposed, evidence, projected: false },
            K3::Neg | K3::Bot => Self {
                verdict: EdgeVerdict::Deny, evidence,
                projected: !matches!(proposed, EdgeVerdict::Deny),
            },
        }
    }
    pub const fn verdict(&self) -> EdgeVerdict { self.verdict }
    pub const fn was_projected(&self) -> bool { self.projected }
    pub const fn in_envelope(&self) -> bool {
        matches!(self.verdict, EdgeVerdict::Deny) || matches!(self.evidence, K3::Pos)
    }
}
```

In `GuardPipeline`, the edge guard maps `Allow` to `Verdict::Allow`, `PendingApproval` to the sticky `Verdict::PendingApproval`, and `Deny` to a pushed `GuardEvidence` with `verdict: false` and a details string naming the evidence value, followed by `GuardDecision::deny`. The guard never upgrades a verdict, so the pipeline's sticky semantics are untouched. Receipt metadata uses a new additive constant rather than resizing the pinned 35-key array:

```rust
pub const RESERVED_PROTOCOL_EDGE_METADATA_KEYS: [&str; 3] =
    ["protocol_edge", "protocol_edge_attestation", "protocol_edge_trust_root"];

pub fn is_reserved_receipt_metadata_key(key: &str) -> bool {
    RESERVED_RECEIPT_METADATA_KEYS.contains(&key) || RESERVED_PROTOCOL_EDGE_METADATA_KEYS.contains(&key)
}
```

## 3. Formal obligations and proofs

**Lean 4** at `formal/lean4/Chio/ProtocolEdge.lean` models the evidence lattice, the shield, and the store lookup.

```lean
namespace Chio.ProtocolEdge

inductive K3 | pos | neg | bot deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _ => .neg
  | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .bot

theorem K3.and_pos_iff (a b : K3) : a.and b = .pos ↔ a = .pos ∧ b = .pos := by
  cases a <;> cases b <;> simp [K3.and]

inductive Verdict | deny | allow | pending deriving DecidableEq, Repr

def feasible (k : K3) (a : Verdict) : Prop := a = .deny ∨ k = .pos

def shield (k : K3) (a : Verdict) : Verdict :=
  match k with
  | .pos => a
  | _ => .deny

theorem deny_always_feasible (k : K3) : feasible k .deny := Or.inl rfl

theorem shield_in_envelope (k : K3) (a : Verdict) : feasible k (shield k a) := by
  cases k <;> simp [shield, feasible]

theorem shield_id_on_envelope (k : K3) (a : Verdict) (h : feasible k a) : shield k a = a := by
  cases k <;> simp_all [shield, feasible]

/-- Verification transfer: any property that holds on the envelope holds after shielding. -/
theorem transfer (φ : Verdict → Prop) (hφ : ∀ k a, feasible k a → φ a) (k : K3) (a : Verdict) :
    φ (shield k a) := hφ k _ (shield_in_envelope k a)

def windowOk (now lo hi : Nat) : Bool := decide (lo ≤ now ∧ now < hi)

structure Root where
  id : Nat
  nb : Nat
  na : Nat

structure Receipt where
  rootId : Nat
  issued : Nat
  expires : Nat
  edOk : K3
  mlOk : K3

def verify (s : List Root) (r : Receipt) (now : Nat) : K3 :=
  match s.find? (fun ρ => ρ.id == r.rootId) with
  | none => .bot
  | some ρ =>
    if windowOk now r.issued r.expires && windowOk r.issued ρ.nb ρ.na
    then r.edOk.and r.mlOk else .neg

theorem verify_pos_sound (s : List Root) (r : Receipt) (now : Nat)
    (h : verify s r now = .pos) : r.edOk = .pos ∧ r.mlOk = .pos := by
  unfold verify at h
  split at h
  · simp at h
  · split at h
    · exact (K3.and_pos_iff _ _).mp h
    · simp at h

theorem verify_fresh_root (s : List Root) (ρ : Root) (r : Receipt) (now : Nat)
    (hfresh : ρ.id ≠ r.rootId) : verify (ρ :: s) r now = verify s r now := by
  simp [verify, List.find?_cons, beq_iff_eq, hfresh]

end Chio.ProtocolEdge
```

**Apalache TLA+** at `formal/tla/ProtocolEdge.tla` checks the same envelope under time, issuance, and revocation. The learned choice is the existential over `Feasible(k)`.

```tla
---------------------------- MODULE ProtocolEdge ----------------------------
EXTENDS Integers, FiniteSets

CONSTANTS
  \* @type: Set(Str);
  ROOT_IDS,
  \* @type: Int;
  HORIZON

VARIABLES
  \* @type: Int;
  now,
  \* @type: Str -> [nb: Int, na: Int, active: Bool];
  store,
  \* @type: Set([rid: Str, issued: Int, expires: Int, verdict: Str, ed: Str, ml: Str]);
  receipts

K3 == {"pos", "neg", "bot"}
And3(a, b) == IF a = "neg" \/ b = "neg" THEN "neg"
              ELSE IF a = "pos" /\ b = "pos" THEN "pos" ELSE "bot"
Window(t, lo, hi) == lo <= t /\ t < hi
Feasible(k) == IF k = "pos" THEN {"deny", "allow", "pending"} ELSE {"deny"}

Verify(rc) ==
  IF ~store[rc.rid].active THEN "bot"
  ELSE IF ~Window(now, rc.issued, rc.expires)
       \/ ~Window(rc.issued, store[rc.rid].nb, store[rc.rid].na) THEN "neg"
  ELSE And3(rc.ed, rc.ml)

Init == now = 0
     /\ store = [rid \in ROOT_IDS |-> [nb |-> 0, na |-> HORIZON, active |-> TRUE]]
     /\ receipts = {}

Tick == now < HORIZON /\ now' = now + 1 /\ UNCHANGED <<store, receipts>>

Issue ==
  \E rid \in ROOT_IDS, ttl \in 1..HORIZON, ed \in K3, ml \in K3 :
    \E a \in Feasible(And3(ed, ml)) :
      receipts' = receipts \cup
        {[rid |-> rid, issued |-> now, expires |-> now + ttl, verdict |-> a, ed |-> ed, ml |-> ml]}
      /\ UNCHANGED <<now, store>>

Revoke == \E rid \in ROOT_IDS :
  store' = [store EXCEPT ![rid].active = FALSE] /\ UNCHANGED <<now, receipts>>

Next == Tick \/ Issue \/ Revoke

DenyAlwaysFeasible == \A k \in K3 : "deny" \in Feasible(k)
NonDenyImpliesBothPos == \A rc \in receipts : rc.verdict # "deny" => rc.ed = "pos" /\ rc.ml = "pos"
RevokedNeverPos == \A rc \in receipts : ~store[rc.rid].active => Verify(rc) # "pos"
=============================================================================
```

**Kani** harnesses live behind `#[cfg(kani)]` in the lift crate. The digest stand-in is deliberately trivial because these harnesses prove absence of panics, overflow, and envelope escape, not cryptographic strength.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    struct FoldDigest(u8);
    impl Digest256 for FoldDigest {
        fn update(&mut self, b: &[u8]) { for x in b { self.0 = self.0.wrapping_add(*x); } }
        fn finalize(self) -> [u8; 32] { [self.0; 32] }
    }
    struct FoldFactory;
    impl DigestFactory for FoldFactory { type D = FoldDigest; fn new_digest(&self) -> FoldDigest { FoldDigest(0) } }

    #[kani::proof]
    fn k3_and_pos_iff() {
        let a: K3 = kani::any();
        let b: K3 = kani::any();
        assert_eq!(a.and(b) == K3::Pos, a == K3::Pos && b == K3::Pos);
    }

    #[kani::proof]
    fn shield_in_envelope_and_identity() {
        let k: K3 = kani::any();
        let a: EdgeVerdict = kani::any();
        let s = ShieldedEdgeVerdict::project(k, a);
        assert!(s.in_envelope());
        if k == K3::Pos { assert_eq!(s.verdict(), a); } else { assert_eq!(s.verdict(), EdgeVerdict::Deny); }
    }

    #[kani::proof]
    #[kani::unwind(130)]
    fn envoy_lift_is_total() {
        let method: [u8; 8] = kani::any();
        let path: [u8; 64] = kani::any();
        let src: [u8; 32] = kani::any();
        let dst: [u8; 32] = kani::any();
        let plen: usize = kani::any();
        kani::assume(plen <= 64);
        let wire = EnvoyCheckWire {
            method: &method, path: &path[..plen], source_principal: &src, destination_principal: &dst,
            received_at: kani::any(), ttl: kani::any(),
        };
        let _ = EnvoyExtAuthzLift.lift(&FoldFactory, &wire, kani::any());
    }

    #[kani::proof]
    fn role_thresholds_reject_inversion() {
        let neg = FixedQ16_16(kani::any());
        let pos = FixedQ16_16(kani::any());
        assert_eq!(RoleThresholds::new(neg, pos).is_some(), neg.0 <= pos.0);
    }
}
```

Additions to `formal/proof-manifest.toml` bind each theorem to the Rust symbol it covers:

```toml
[[obligation]]
id = "protocol_edge.shield_in_envelope"
tool = "lean4"
theorem = "Chio.ProtocolEdge.shield_in_envelope"
rust_symbol = "chio_protocol_lift::ShieldedEdgeVerdict::project"

[[obligation]]
id = "protocol_edge.verify_pos_sound"
tool = "lean4"
theorem = "Chio.ProtocolEdge.verify_pos_sound"
rust_symbol = "chio_protocol_lift::verify_receipt_offline"

[[obligation]]
id = "protocol_edge.revoked_never_pos"
tool = "apalache"
module = "ProtocolEdge"
invariants = ["DenyAlwaysFeasible", "NonDenyImpliesBothPos", "RevokedNeverPos"]

[[obligation]]
id = "protocol_edge.envoy_lift_total"
tool = "kani"
harness = "verification::envoy_lift_is_total"
```

**Theorem 1 (the lift is exact and injective up to the hash).** Let $\mathsf{TLV}(w)$ be the byte string absorbed in `seal`: the domain field, the origin byte, two tagged timestamps, then four tagged, length-prefixed segments in fixed order. $\mathsf{TLV}$ is injective on the lifted tuple $(o, t_i, t_e, s_0, s_1, s_2, s_3)$. Proof. Define a left-to-right decoder: the domain field has a fixed tag and a four-byte length, the origin is one byte, each timestamp is a tag and eight bytes, and each segment is a tag, a four-byte big-endian length, then exactly that many bytes. The decoder is a deterministic function, and a function with a left inverse is injective. Since `request_hash` is $H(\mathsf{TLV}(w))$, two lifted requests with distinct tuples and equal hashes exhibit a collision of $H$. Totality follows by inspection: every arithmetic operation is `checked_*` or a `try_from`, every slice write is guarded by `get_mut`, and every branch returns `Ok` or `Err`. The Kani harness discharges this mechanically for the Envoy path. Hence the lift belongs to $C_{L3}$ and is never approximated.

**Theorem 2 (the hybrid floor is at least as strong as its stronger member).** Let $\Sigma_1$ and $\Sigma_2$ be signature schemes and let $\Sigma_\wedge$ sign $m$ as $(\sigma_1, \sigma_2)$ and verify iff both components verify. If an adversary $\mathcal{A}$ wins EUF-CMA against $\Sigma_\wedge$ with advantage $\varepsilon$, then there is $\mathcal{B}_1$ against $\Sigma_1$ with advantage at least $\varepsilon$, and symmetrically $\mathcal{B}_2$ against $\Sigma_2$. Proof. $\mathcal{B}_1$ receives $\mathsf{pk}_1$, generates $(\mathsf{sk}_2, \mathsf{pk}_2)$ itself, and gives $\mathcal{A}$ the pair. On a signing query $m$, it queries its own oracle for $\sigma_1$ and computes $\sigma_2$ locally. When $\mathcal{A}$ outputs $(m^*, \sigma_1^*, \sigma_2^*)$ with $m^*$ never queried and both components valid, $\mathcal{B}_1$ outputs $(m^*, \sigma_1^*)$, which is a valid fresh forgery. The simulation is perfect, so $\mathrm{Adv}_{\Sigma_\wedge} \le \min(\mathrm{Adv}_{\Sigma_1}, \mathrm{Adv}_{\Sigma_2})$. Because both components sign $H(\mathsf{TLV}(\mathrm{body}))$, the hash-then-sign step adds at most the collision advantage against $H$. Downgrade is excluded by two facts: the suite byte is inside the signed body, and `verify_receipt_offline` returns $\bot$ whenever a verifier lacks an algorithm, which the shield denies. The Lean theorem `K3.and_pos_iff` and the Kani harness `k3_and_pos_iff` are the mechanized form of "acceptance requires both".

**Theorem 3 (offline federated verification).** (a) Soundness: if `verify_receipt_offline` returns $+$, then the store holds a root with the receipt's id whose derived id matches its keys, the root was valid at issuance, the receipt is within its window at `now`, and both signatures verify under that root. This is `verify_pos_sound` plus the two window guards, each of which is the pinned `classify_time_window_code` returning zero. (b) Fresh-root monotonicity: inserting a root whose id differs from the receipt's leaves the result unchanged, by `verify_fresh_root`. Inserting a root with the receipt's id can only move $\bot$ to a definite value, never flip $+$ and $-$, because `insert` rejects duplicates, so at most one root ever answers a given id. (c) Revocation is fail-closed: clearing a slot can change the result only for receipts naming that root, and for those it becomes $\bot$ via the `find` miss, which the shield denies. Apalache checks this as `RevokedNeverPos`. (d) Cross-federation key substitution is excluded: `insert` recomputes the id from both public keys, so two federations presenting the same id with different keys exhibit a collision of $H$.

**Theorem 4 (envelope preservation and verification transfer at L3).** For every evidence value $k$ and every proposed verdict $a$, including an adversarially chosen one, $\Pi_k(a) \in \mathcal{C}(k)$, `Deny` is in $\mathcal{C}(k)$, and $\Pi_k$ is the identity on $\mathcal{C}(k)$. These are `shield_in_envelope`, `deny_always_feasible`, and `shield_id_on_envelope`. Let $S^{\mathrm{nd}}$ be the transition system in which the verdict is drawn from $\mathcal{C}(k)$ by unconstrained nondeterminism, as the TLA+ `Issue` action and the Kani `kani::any()` do, and let $S^{P}$ be the system in which the verdict is $\Pi_k(P(x))$ for the Copley predictor. Every transition of $S^{P}$ is a transition of $S^{\mathrm{nd}}$, so $\mathrm{Traces}(S^{P}) \subseteq \mathrm{Traces}(S^{\mathrm{nd}})$. Safety properties are closed under trace inclusion, so every safety invariant checked against $S^{\mathrm{nd}}$ holds for $S^{P}$ with any weights, including weights that are later retrained. The Lean `transfer` theorem is this argument in one line. The transfer does not cover liveness: a predictor stuck at $\bot$ denies forever, and availability remains a separate obligation on the Tier-1 calibration.

**Lemma 5 (shadow-price tightening is fail-closed).** The Tier-0 score is $w^\top\phi(x) - \boldsymbol{\lambda}^\top c(x)$ with $c(x) \ge 0$ componentwise by construction of `resource_costs`. For $\boldsymbol{\lambda}' \ge \boldsymbol{\lambda}$ componentwise, the score under $\boldsymbol{\lambda}'$ is no larger, so the set scored $+$ shrinks and the set scored $-$ grows. Any fixed-point overflow yields `None`, hence $\bot$, hence `Deny`. A Lagrangian controller that raises prices under budget, fuel, latency, memory, or escrow pressure can therefore only move the edge toward refusal, never toward admission.

**Recap.** The three protocol edges now share one `no_std` lift into `PortableToolCallRequest` with the four Copley segments assigned by telemetry role, a Tier-0 fixed-point prefilter penalized by the shadow-price vector, and a hybrid Ed25519 plus ML-DSA-65 signing floor that refuses to issue single-algorithm receipts. Offline verification across federated trust roots returns Kleene three-valued evidence, with unknown roots and missing algorithms mapped to $\bot$ and shielded to `Deny`. Hardware attestation enters only as the fifth boolean of the existing `receipt_fields_coupled`, and metadata keys are added through a new constant rather than by resizing the pinned array, so no existing Lean, Aeneas, Apalache, or Kani proof changes. The remaining open items are wiring the `std` shells for JCS canonicalization and vendor quote-chain validation, and running the four new manifest obligations in CI.