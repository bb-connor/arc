# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 9 Synthesis

- **Timestamp**: `20261025-034451 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1527.63s` across 4 parallel passes
- **Total Output**: `160,276` characters (`21,147` words)
- **Claude Max Quota Before Wave 9**: 5-hour `9.0%` | 7-day `90.0%`
- **Claude Max Quota After Wave 9**: 5-hour `20.0%` | 7-day `92.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave9_angle_1_formal_aeneas_and_lean4_deepening_pass_9` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,345` | `37,722` | `706.64` |
| `wave9_angle_2_copley_dag_optimization_and_simd_bitset_pass_9` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,467` | `38,177` | `1527.62` |
| `wave9_angle_3_concurrent_loom_and_dst_crash_recovery_pass_9` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,105` | `42,907` | `787.64` |
| `wave9_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_9` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,230` | `41,470` | `924.3` |

---

# Verbatim Treatise - `wave9_angle_1_formal_aeneas_and_lean4_deepening_pass_9`

I'll lay out the Wave 9 additive verification surface: one new `no_std` crate, in-crate Kani pins for the existing kernel signatures, Lean 4 modules, Creusot contracts, and an Apalache spec. Nothing here was compiled or model-checked in this session because no tools are available. Every artifact is written to build as-is, and the recap lists the exact commands that discharge it.

## 1. Saturation-safe `FixedQ16_16` envelopes on the Tier-0 hot path

**Design.** Tier-0 computes a penalized score $s(x) = b(x) - \boldsymbol{\lambda}^\top \mathbf{c}(x)$ in Q16.16 fixed point. The Wave 1 law requires that a learned quantity never silently clamps into a plausible value. Saturation is therefore allowed only where it is provably benign, and every path that cannot represent the exact result returns `None`, which the envelope reads as $\bot$ and projects to the fallback. The exact arithmetic facts are:

- **Clamp soundness.** With $\mathrm{clamp}(z) = \max(lo, \min(hi, z))$ for $lo = -2^{31}$, $hi = 2^{31}-1$: $\mathrm{clamp}(z) \in [lo, hi]$, clamp is monotone, and clamp is the identity on $[lo, hi]$. Hence `saturating_add` equals exact addition whenever representable and otherwise returns the nearest bound.
- **Bit-precise product.** For all $a, b \in \mathbb{Z}_{i32}$, $|ab| \le 2^{62}$ fits `i64` exactly. Arithmetic right shift on two's complement equals $\lfloor ab / 2^{16} \rfloor$. The range test is exact, so `checked_mul` returns `Some(⌊ab/2^16⌋)` iff that value fits `i32`, else `None`.
- **Envelope preservation.** For every choice $c$, $\Pi(c) \in \mathcal{C}(x) \cup \{\bot_x\}$, and $\Pi(c) \neq \bot_x \Rightarrow c = \mathrm{Some}(\Pi(c))$. This is the only fact the Verification Transfer Theorem needs, so the predictor is modeled as `kani::any()` everywhere below.

New crate `crates/kernel/chio-formal-wave9/src/lib.rs`:

```rust
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

/// Strong Kleene three-valued verdict, same meaning as the Wave 1 `K3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// `Neg` annihilates; `Bot` absorbs everything else.
    pub const fn and(self, other: K3) -> K3 {
        match (self, other) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Pos, K3::Pos) => K3::Pos,
            _ => K3::Bot,
        }
    }
    pub const fn is_pos(self) -> bool { matches!(self, K3::Pos) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct FixedQ16_16(i32);

impl FixedQ16_16 {
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(65_536);
    pub const MAX: Self = Self(i32::MAX);
    pub const MIN: Self = Self(i32::MIN);

    pub const fn from_bits(bits: i32) -> Self { Self(bits) }
    pub const fn to_bits(self) -> i32 { self.0 }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) { Some(v) => Some(Self(v)), None => None }
    }
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) { Some(v) => Some(Self(v)), None => None }
    }
    pub const fn saturating_add(self, rhs: Self) -> Self { Self(self.0.saturating_add(rhs.0)) }

    /// Exact Q16.16 product rounded toward negative infinity.
    /// `None` iff the mathematically exact result lies outside the i32 range.
    pub const fn checked_mul(self, rhs: Self) -> Option<Self> {
        let wide: i64 = match (self.0 as i64).checked_mul(rhs.0 as i64) {
            Some(w) => w,
            None => return None, // unreachable: |a|,|b| <= 2^31 so |a*b| <= 2^62
        };
        let shifted: i64 = match wide.checked_shr(Self::FRAC_BITS) {
            Some(s) => s,
            None => return None, // unreachable: 16 < 64
        };
        if shifted > (i32::MAX as i64) || shifted < (i32::MIN as i64) {
            None
        } else {
            Some(Self(shifted as i32))
        }
    }
}

/// Five-dimensional shadow-price or cost vector:
/// (budget, fuel, latency, memory, escrow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Vec5(pub [FixedQ16_16; 5]);
pub type ShadowPrices = Vec5;
pub type Costs = Vec5;

/// Σ_i λ_i · c_i. `None` iff any partial product or partial sum is unrepresentable.
pub fn dot5(lambda: &ShadowPrices, cost: &Costs) -> Option<FixedQ16_16> {
    let mut acc = FixedQ16_16::ZERO;
    for (l, c) in lambda.0.iter().zip(cost.0.iter()) {
        let term = l.checked_mul(*c)?;
        acc = acc.checked_add(term)?;
    }
    Some(acc)
}

/// base − Σ λ_i c_i, or `None` when the exact value is not representable.
pub fn penalized_score(base: FixedQ16_16, lambda: &ShadowPrices, cost: &Costs) -> Option<FixedQ16_16> {
    base.checked_sub(dot5(lambda, cost)?)
}

/// Possession of a value is proof of admissibility: the field is private and the
/// only constructor is `Envelope::project`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedAction<A: Copy + Eq> { action: A }

impl<A: Copy + Eq> ShieldedAction<A> {
    pub const fn into_inner(self) -> A { self.action }
}

pub struct Envelope<'a, A: Copy + Eq> { candidates: &'a [A], fallback: A }

impl<'a, A: Copy + Eq> Envelope<'a, A> {
    pub const fn new(candidates: &'a [A], fallback: A) -> Self { Self { candidates, fallback } }
    pub const fn fallback(&self) -> A { self.fallback }
    pub fn admits(&self, a: &A) -> bool { self.candidates.contains(a) || *a == self.fallback }

    /// O(1) in the number of hot-path decisions; linear only in the tiny candidate slice.
    pub fn project(&self, choice: Option<A>) -> ShieldedAction<A> {
        match choice {
            Some(a) if self.candidates.contains(&a) => ShieldedAction { action: a },
            _ => ShieldedAction { action: self.fallback },
        }
    }
}
```

Kani harnesses for this section. Reference arithmetic inside harnesses is intentionally raw, hence the module-level allow:

```rust
#[cfg(kani)]
#[allow(clippy::arithmetic_side_effects)]
mod kani_q16 {
    use super::*;

    #[kani::proof]
    fn q16_checked_mul_is_bit_precise() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let exact: i128 = (a as i128) * (b as i128);
        let floor: i128 = exact >> 16; // arithmetic shift == floor division by 2^16
        let expected = if floor >= i32::MIN as i128 && floor <= i32::MAX as i128 {
            Some(FixedQ16_16::from_bits(floor as i32))
        } else {
            None
        };
        assert_eq!(FixedQ16_16::from_bits(a).checked_mul(FixedQ16_16::from_bits(b)), expected);
    }

    #[kani::proof]
    fn q16_saturating_add_is_exact_or_nearest_bound() {
        let x: FixedQ16_16 = kani::any();
        let y: FixedQ16_16 = kani::any();
        match x.checked_add(y) {
            Some(v) => assert_eq!(x.saturating_add(y), v),
            None => {
                let s = x.saturating_add(y);
                let exact = x.to_bits() as i64 + y.to_bits() as i64;
                assert_eq!(s, if exact > i32::MAX as i64 { FixedQ16_16::MAX } else { FixedQ16_16::MIN });
            }
        }
    }

    #[kani::proof]
    fn envelope_projection_is_total_and_feasible() {
        let candidates: [u8; 4] = kani::any();
        let fallback: u8 = kani::any();
        let env = Envelope::new(&candidates, fallback);
        let choice: Option<u8> = kani::any();
        let out = env.project(choice).into_inner();
        assert!(env.admits(&out));
        if out != fallback {
            assert_eq!(choice, Some(out));
        }
    }
}
```

Lean 4 mechanization, `formal/lean4/Chio/Wave9/Saturation.lean`. The clamp lemmas are the exact content of the `saturating_add` harness over $\mathbb{Z}$, and the envelope theorem is the single fact that every downstream proof instantiates:

```lean
import Mathlib.Tactic

namespace Chio.Wave9

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

namespace K3
def and : K3 → K3 → K3
  | neg, _ => neg
  | _, neg => neg
  | pos, pos => pos
  | _, _ => bot

theorem and_eq_pos_iff (a b : K3) : and a b = pos ↔ a = pos ∧ b = pos := by
  cases a <;> cases b <;> simp [and]

theorem and_bot_absorbs {a : K3} (h : a ≠ neg) : and a bot = bot := by
  cases a <;> simp_all [and]
end K3

namespace Q16
def lo : Int := -(2 : Int) ^ 31
def hi : Int := (2 : Int) ^ 31 - 1
def clamp (z : Int) : Int := max lo (min hi z)
def satAdd (a b : Int) : Int := clamp (a + b)

theorem lo_le_hi : lo ≤ hi := by norm_num [lo, hi]

theorem clamp_mem (z : Int) : lo ≤ clamp z ∧ clamp z ≤ hi := by
  unfold clamp
  exact ⟨le_max_left _ _, max_le lo_le_hi (min_le_left _ _)⟩

theorem clamp_mono {x y : Int} (h : x ≤ y) : clamp x ≤ clamp y := by
  unfold clamp
  exact max_le_max (le_refl _) (min_le_min (le_refl _) h)

theorem clamp_id_of_mem {z : Int} (h1 : lo ≤ z) (h2 : z ≤ hi) : clamp z = z := by
  unfold clamp
  rw [min_eq_right h2, max_eq_right h1]

theorem satAdd_exact {a b : Int} (h1 : lo ≤ a + b) (h2 : a + b ≤ hi) : satAdd a b = a + b :=
  clamp_id_of_mem h1 h2

theorem satAdd_mono_left {a a' b : Int} (h : a ≤ a') : satAdd a b ≤ satAdd a' b :=
  clamp_mono (by omega)
end Q16

structure Envelope (α : Type) where
  candidates : List α
  fallback : α

namespace Envelope
variable {α : Type} [DecidableEq α]

def feasible (e : Envelope α) (a : α) : Prop := a ∈ e.candidates ∨ a = e.fallback

def project (e : Envelope α) (choice : Option α) : α :=
  match choice with
  | some a => if a ∈ e.candidates then a else e.fallback
  | none => e.fallback

/-- Envelope Preservation: every projection lands in the feasible set. -/
theorem project_feasible (e : Envelope α) (c : Option α) : e.feasible (e.project c) := by
  unfold feasible project
  cases c with
  | none => exact Or.inr rfl
  | some a =>
    by_cases h : a ∈ e.candidates
    · simp [h]
    · simp [h]

/-- Verification Transfer: a property proved for every choice holds for the learned choice. -/
theorem transfer (e : Envelope α) (P : α → Prop) (h : ∀ c, P (e.project c)) (learned : Option α) :
    P (e.project learned) := h learned
end Envelope
end Chio.Wave9
```

## 2. Epoch boundaries, window classification, and ledger pins

**Window rank.** The kernel encodes windows as `0 = Valid, 1 = NotYetValid, 2 = Expired`. Those codes are labels, not an order. The verification-relevant order is temporal: $\mathrm{NotYetValid} \prec \mathrm{Valid} \prec \mathrm{Expired}$. I add a `window_rank` that maps codes onto that chain, and a reference model that pins the half-open semantics $[\,issued\_at, expires\_at)$. The model is the spec; the refinement harness is the oracle. If `classify_time_window_code` ever disagrees, the harness fails and the manifest entry has found a semantic drift rather than hiding it.

- **Theorem (window monotonicity).** For $now_1 \le now_2$, $\mathrm{rank}(now_1) \le \mathrm{rank}(now_2)$. A capability crosses each boundary at most once, and a degenerate window with $expires\_at \le issued\_at$ is never Valid.
- **Theorem (epoch transitions).** $\mathrm{epoch}(now) = \lfloor now / len \rfloor$ is monotone, `Regressed` is returned only when the clock went backwards, and the step from $k \cdot len - 1$ to $k \cdot len$ is exactly `Advanced { by: 1 }`. No addition is performed on `u64` clocks, so `expires_at = u64::MAX` is a legal sentinel with no overflow path.

```rust
pub const WINDOW_VALID: u8 = 0;
pub const WINDOW_NOT_YET_VALID: u8 = 1;
pub const WINDOW_EXPIRED: u8 = 2;

/// Temporal rank of a window code: NotYetValid < Valid < Expired.
pub const fn window_rank(code: u8) -> Option<u8> {
    match code {
        WINDOW_NOT_YET_VALID => Some(0),
        WINDOW_VALID => Some(1),
        WINDOW_EXPIRED => Some(2),
        _ => None,
    }
}

/// Pinned reference semantics for `classify_time_window_code`: half-open window.
pub const fn classify_time_window_model(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at {
        WINDOW_NOT_YET_VALID
    } else if now >= expires_at {
        WINDOW_EXPIRED
    } else {
        WINDOW_VALID
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochLen(u64);

impl EpochLen {
    pub const fn new(len: u64) -> Option<Self> { if len == 0 { None } else { Some(Self(len)) } }
    pub const fn get(self) -> u64 { self.0 }
}

pub const fn epoch_of(now: u64, len: EpochLen) -> u64 {
    match now.checked_div(len.0) { Some(e) => e, None => 0 } // None unreachable: len.0 != 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochTransition { Same, Advanced { by: u64 }, Regressed }

pub const fn epoch_transition(prev_now: u64, now: u64, len: EpochLen) -> EpochTransition {
    let e0 = epoch_of(prev_now, len);
    let e1 = epoch_of(now, len);
    match e1.checked_sub(e0) {
        Some(0) => EpochTransition::Same,
        Some(by) => EpochTransition::Advanced { by },
        None => EpochTransition::Regressed,
    }
}
```

In-crate harnesses for `chio-kernel-core`. These need `pub(crate)` access, so they live in a new file `crates/kernel/chio-kernel-core/src/kani_wave9.rs` declared by one added line `#[cfg(kani)] mod kani_wave9;` in `lib.rs`, with the new crate pulled in only under `[target.'cfg(kani)'.dependencies]`. Normal builds and every existing proof are untouched.

```rust
#![allow(clippy::arithmetic_side_effects)]
use crate::formal_core::{budget_commit, budget_precheck, classify_time_window_code};
use crate::formal_aeneas::{ledger_apply, ledger_is_terminal, ReservationLedger};
use chio_formal_wave9::*;

const _: () = assert!(MAX_BUDGET_SHARE_BPS == crate::budget_split::MAX_BUDGET_SHARE_BPS);

#[kani::proof]
fn window_code_refines_pinned_model() {
    let (now, issued_at, expires_at): (u64, u64, u64) = kani::any();
    assert_eq!(
        classify_time_window_code(now, issued_at, expires_at),
        classify_time_window_model(now, issued_at, expires_at)
    );
}

#[kani::proof]
fn window_rank_is_monotone_in_now() {
    let (n1, n2, i, e): (u64, u64, u64, u64) = kani::any();
    kani::assume(n1 <= n2);
    let r1 = window_rank(classify_time_window_model(n1, i, e));
    let r2 = window_rank(classify_time_window_model(n2, i, e));
    assert!(r1.is_some() && r2.is_some());
    assert!(r1 <= r2);
}

#[kani::proof]
fn epoch_regression_implies_clock_went_backwards() {
    let (p, n, l): (u64, u64, u64) = kani::any();
    kani::assume(l != 0);
    let len = EpochLen::new(l).unwrap();
    assert_eq!(epoch_of(n, len), n / l);
    match epoch_transition(p, n, len) {
        EpochTransition::Regressed => assert!(n < p),
        EpochTransition::Same => assert_eq!(p / l, n / l),
        EpochTransition::Advanced { by } => assert_eq!(n / l, p / l + by),
    }
}

#[kani::proof]
fn epoch_boundary_advances_by_exactly_one() {
    let (k, l): (u64, u64) = kani::any();
    kani::assume(l != 0 && k >= 1 && k <= u64::MAX / l);
    let len = EpochLen::new(l).unwrap();
    let boundary = k * l;
    assert_eq!(epoch_transition(boundary - 1, boundary, len), EpochTransition::Advanced { by: 1 });
}

fn conserved(reserved: u64, committed: u64, released: u64, retained: u64) -> bool {
    committed
        .checked_add(released)
        .and_then(|x| x.checked_add(retained))
        .map_or(false, |spent| spent <= reserved)
}

/// Pins the Wave 1 conservation invariant committed + released + retained <= reserved.
#[kani::proof]
fn ledger_step_preserves_conservation() {
    let (reserved, committed, released, retained): (u64, u64, u64, u64) = kani::any();
    kani::assume(conserved(reserved, committed, released, retained));
    let s = ReservationLedger { reserved, committed, released, retained };
    let (op, amount): (u8, u64) = kani::any();
    let (s2, _accepted) = ledger_apply(s, op, amount);
    assert!(conserved(s2.reserved, s2.committed, s2.released, s2.retained));
}

/// Pins terminality as an absorbing state: no op is accepted and no field moves.
#[kani::proof]
fn terminal_ledger_is_absorbing() {
    let (reserved, committed, released, retained): (u64, u64, u64, u64) = kani::any();
    let s = ReservationLedger { reserved, committed, released, retained };
    kani::assume(ledger_is_terminal(s));
    let (op, amount): (u8, u64) = kani::any();
    let s_again = ReservationLedger { reserved, committed, released, retained };
    let (s2, accepted) = ledger_apply(s_again, op, amount);
    assert!(!accepted);
    assert!(s2.reserved == reserved && s2.committed == committed);
    assert!(s2.released == released && s2.retained == retained);
}

#[kani::proof]
fn budget_commit_agrees_with_precheck() {
    let (ri, ru, ci, cu): (u64, u64, u64, u64) = kani::any();
    let r = budget_commit(ri, ru, ci, cu);
    assert_eq!(r.accepted, budget_precheck(ri, ru, ci, cu));
    if r.accepted {
        assert_eq!(Some(r.remaining_invocations), ri.checked_sub(ci));
        assert_eq!(Some(r.remaining_units), ru.checked_sub(cu));
    } else {
        assert_eq!((r.remaining_invocations, r.remaining_units), (ri, ru));
    }
}
```

The three ledger and budget harnesses encode the invariants documented in Wave 1. They are pins, not restatements of code I have read. If one fails on the real `ledger_apply`, that is a finding about the gap between the documented invariant and the implementation, and the manifest entry should record whichever side is corrected. The two 64-bit divisions in the epoch harnesses bit-blast slowly under CBMC; if wall-clock is a concern, add `kani::assume(l <= 1 << 20)` as a documented bound.

Lean 4, `formal/lean4/Chio/Wave9/Epoch.lean`:

```lean
import Mathlib.Tactic

namespace Chio.Wave9.Epoch

/-- Temporal rank: NotYetValid = 0, Valid = 1, Expired = 2, half-open window. -/
def rank (now issued expires : Nat) : Nat :=
  if now < issued then 0 else if expires ≤ now then 2 else 1

theorem rank_mono {n₁ n₂ i e : Nat} (h : n₁ ≤ n₂) : rank n₁ i e ≤ rank n₂ i e := by
  unfold rank; split_ifs <;> omega

theorem rank_le_two (n i e : Nat) : rank n i e ≤ 2 := by
  unfold rank; split_ifs <;> omega

/-- A degenerate window never classifies Valid. -/
theorem degenerate_never_valid {n i e : Nat} (h : e ≤ i) : rank n i e ≠ 1 := by
  unfold rank; split_ifs <;> omega

def epochOf (now len : Nat) : Nat := now / len

theorem epochOf_mono {a b len : Nat} (h : a ≤ b) : epochOf a len ≤ epochOf b len :=
  Nat.div_le_div_right h

end Chio.Wave9.Epoch
```

Apalache TLA+, `formal/tla/ChioEpochEnvelope.tla`. The learned verdict is `\E a \in Feasible(now')`, so the state invariant is a direct instance of Envelope Preservation and the action invariant is epoch monotonicity:

```tla
---------------------------- MODULE ChioEpochEnvelope ----------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Int;
  Len,
  \* @type: Int;
  Issued,
  \* @type: Int;
  Expires
VARIABLES
  \* @type: Int;
  now,
  \* @type: Int;
  epoch,
  \* @type: Str;
  verdict

ASSUME Len > 0 /\ 0 <= Issued /\ Issued <= Expires

Window(t) == IF t < Issued THEN "NotYetValid"
             ELSE IF t >= Expires THEN "Expired" ELSE "Valid"

\* Outside the window only the fallback is admissible.
Feasible(t) == IF Window(t) = "Valid" THEN {"Allow", "Defer", "Deny"} ELSE {"Deny"}

Init == now = 0 /\ epoch = 0 /\ verdict = "Deny"

Next ==
  \E d \in 0..Len :
    /\ now' = now + d
    /\ epoch' = now' \div Len
    /\ \E a \in Feasible(now') : verdict' = a

ShieldInv == verdict \in Feasible(now)
EpochMonoAction == epoch' >= epoch
=================================================================================
```

Run with `apalache-mc check --inv=ShieldInv --action-inv=EpochMonoAction ChioEpochEnvelope.tla` and a `ConstInit` that picks concrete `Len`, `Issued`, `Expires`.

## 3. Attenuation witnesses and Merkle-gated decisions

**Attenuation.** A delegation hop may only shrink authority. Formally, with $\mathcal{A} = (share, units, inv, issued, expires)$, define
$$c \preceq p \;\iff\; c.share \le p.share \wedge c.units \le p.units \wedge c.inv \le p.inv \wedge p.issued \le c.issued \wedge c.expires \le p.expires.$$
This is a preorder. The witness is the root plus the hop list, and verification folds $\preceq$ along the chain and then asks the kernel classifier whether the leaf is Valid now. Three consequences are mechanized:

- **Chain soundness.** If every hop attenuates its predecessor, the leaf attenuates the root.
- **Upward validity.** A leaf Valid at $now$ forces every ancestor Valid at $now$, because windows nest. A valid child can never outlive its root.
- **Share contraction.** Effective share is folded with $\mathrm{mul\_bps}(a, b) = \lfloor ab / 10^4 \rfloor \le \min(a, b)$ for $a, b \le 10^4$, so it never exceeds the root share. The sibling-sum lemma shows that the `u32` field `current_total_child_bps` in `OversubscribedSiblings` cannot overflow under the existing caps, since $10^4 \cdot 10^4 = 10^8 < 2^{32}$.

**Merkle inclusion.** `inclusion_step` is one hash of the running digest with its sibling, ordered by the sibling's side. `verify_inclusion` returns $\bot$ above depth 64 before any hashing, $+$ on a root match, $-$ otherwise. The Tier-0 gate admits a proposed action only when inclusion and the score are both $+$ in Kleene conjunction; any $\bot$ from saturation, unknown codes, or an over-long path collapses to the fallback.

```rust
/// Mirrors `budget_split::MAX_BUDGET_SHARE_BPS`; equality is const-asserted in kani_wave9.rs.
pub const MAX_BUDGET_SHARE_BPS: u16 = 10_000;
pub const MAX_ATTENUATION_HOPS: usize = 16;
pub const MAX_MERKLE_DEPTH: usize = 64;

/// floor(a·b / 10_000). `None` only on an intermediate overflow, which cannot happen
/// for u16 inputs since 65_535² < 2^32.
pub const fn mul_bps(a: u16, b: u16) -> Option<u16> {
    let prod = match (a as u32).checked_mul(b as u32) { Some(p) => p, None => return None };
    let q = match prod.checked_div(MAX_BUDGET_SHARE_BPS as u32) { Some(q) => q, None => return None };
    if q > (u16::MAX as u32) { None } else { Some(q as u16) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Authority {
    pub share_bps: u16,
    pub max_units: u64,
    pub max_invocations: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Authority {
    pub const fn well_formed(&self) -> bool {
        self.share_bps <= MAX_BUDGET_SHARE_BPS && self.issued_at <= self.expires_at
    }
    /// `child` attenuates `parent`: no dimension grows and the window nests.
    pub const fn attenuates(child: &Authority, parent: &Authority) -> bool {
        child.share_bps <= parent.share_bps
            && child.max_units <= parent.max_units
            && child.max_invocations <= parent.max_invocations
            && parent.issued_at <= child.issued_at
            && child.expires_at <= parent.expires_at
    }
}

pub struct AttenuationWitness<'a> { root: Authority, hops: &'a [Authority] }

impl<'a> AttenuationWitness<'a> {
    pub const fn new(root: Authority, hops: &'a [Authority]) -> Self { Self { root, hops } }

    pub fn leaf(&self) -> Authority { self.hops.last().copied().unwrap_or(self.root) }

    /// Pos: well-formed root, every hop attenuates its predecessor, leaf Valid at `now`.
    /// Bot: too many hops, or the classifier returned an unknown code. Neg otherwise.
    /// `classify` is injected so the kernel wires `classify_time_window_code` and the
    /// harnesses wire the pinned model.
    pub fn verify<F>(&self, now: u64, classify: F) -> K3
    where
        F: Fn(u64, u64, u64) -> u8,
    {
        if self.hops.len() > MAX_ATTENUATION_HOPS { return K3::Bot; }
        if !self.root.well_formed() { return K3::Neg; }
        let mut parent = self.root;
        for hop in self.hops {
            if !(hop.well_formed() && Authority::attenuates(hop, &parent)) { return K3::Neg; }
            parent = *hop;
        }
        match window_rank(classify(now, parent.issued_at, parent.expires_at)) {
            Some(1) => K3::Pos,
            Some(_) => K3::Neg,
            None => K3::Bot,
        }
    }

    /// Π share_i folded with `mul_bps`; never exceeds the root share.
    pub fn effective_share_bps(&self) -> Option<u16> {
        let mut acc = self.root.share_bps;
        for hop in self.hops { acc = mul_bps(acc, hop.share_bps)?; }
        Some(acc)
    }
}

pub type Digest = [u8; 32];

/// Domain-separated two-to-one compression. Implementors MUST tag interior nodes
/// distinctly from leaves (RFC 6962 style 0x00 / 0x01 prefixes), otherwise a leaf
/// can be reinterpreted as a node and the Pos verdict is unsound.
pub trait Hash32 { fn hash_pair(left: &Digest, right: &Digest) -> Digest; }

/// Which side the sibling occupies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Side { Left, Right }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct PathStep { pub sibling: Digest, pub side: Side }

pub fn inclusion_step<H: Hash32>(acc: &Digest, step: &PathStep) -> Digest {
    match step.side {
        Side::Left => H::hash_pair(&step.sibling, acc),
        Side::Right => H::hash_pair(acc, &step.sibling),
    }
}

pub fn fold_path<H: Hash32>(leaf: &Digest, path: &[PathStep]) -> Digest {
    let mut acc = *leaf;
    for step in path { acc = inclusion_step::<H>(&acc, step); }
    acc
}

pub fn verify_inclusion<H: Hash32>(leaf: &Digest, path: &[PathStep], root: &Digest) -> K3 {
    if path.len() > MAX_MERKLE_DEPTH { return K3::Bot; }
    if fold_path::<H>(leaf, path) == *root { K3::Pos } else { K3::Neg }
}

pub struct Tier0Inputs<'p> {
    pub weights_leaf: Digest,
    pub path: &'p [PathStep],
    pub pinned_root: Digest,
    pub base: FixedQ16_16,
    pub lambda: ShadowPrices,
    pub cost: Costs,
    pub tau: FixedQ16_16,
}

pub fn score_verdict(base: FixedQ16_16, lambda: &ShadowPrices, cost: &Costs, tau: FixedQ16_16) -> K3 {
    match penalized_score(base, lambda, cost) {
        Some(s) if s >= tau => K3::Pos,
        Some(_) => K3::Neg,
        None => K3::Bot,
    }
}

/// The Tier-0 micro-model may move the choice off the fallback only when its weights
/// digest is included under the pinned model-card root AND the penalized score is
/// finite and clears τ. Any ⊥ collapses to the fallback.
pub fn gate_tier0<A: Copy + Eq, H: Hash32>(
    env: &Envelope<'_, A>,
    inp: &Tier0Inputs<'_>,
    proposed: A,
) -> ShieldedAction<A> {
    let inclusion = verify_inclusion::<H>(&inp.weights_leaf, inp.path, &inp.pinned_root);
    let admit = inclusion.and(score_verdict(inp.base, &inp.lambda, &inp.cost, inp.tau));
    env.project(if admit.is_pos() { Some(proposed) } else { None })
}
```

Kani harnesses for this section. The stand-in hash is a cheap concrete compression, so these harnesses cover the fold and gate logic for every leaf, sibling, and side at bounded depth. The Lean theorem below covers the fold for an arbitrary abstract hash.

```rust
#[cfg(kani)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod kani_wave9_auth {
    use super::*;

    struct XorHash;
    impl Hash32 for XorHash {
        fn hash_pair(l: &Digest, r: &Digest) -> Digest {
            let mut out = [0u8; 32];
            for (o, (a, b)) in out.iter_mut().zip(l.iter().zip(r.iter())) {
                *o = a.rotate_left(1) ^ *b;
            }
            out
        }
    }

    #[kani::proof]
    fn mul_bps_is_floor_and_contracting() {
        let (a, b): (u16, u16) = kani::any();
        let r = mul_bps(a, b);
        assert_eq!(r, Some(((a as u32 * b as u32) / 10_000) as u16));
        if a <= 10_000 && b <= 10_000 {
            let v = r.unwrap();
            assert!(v <= a && v <= b);
        }
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn witness_pos_implies_leaf_attenuates_root_and_root_valid() {
        let root: Authority = kani::any();
        let hops: [Authority; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let now: u64 = kani::any();
        let w = AttenuationWitness::new(root, &hops[..n]);
        if w.verify(now, classify_time_window_model) == K3::Pos {
            let leaf = w.leaf();
            assert!(Authority::attenuates(&leaf, &root));
            assert_eq!(classify_time_window_model(now, root.issued_at, root.expires_at), WINDOW_VALID);
            assert!(w.effective_share_bps().map_or(false, |s| s <= root.share_bps));
        }
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn fold_then_verify_is_pos() {
        let leaf: Digest = kani::any();
        let steps: [PathStep; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let root = fold_path::<XorHash>(&leaf, &steps[..n]);
        assert_eq!(verify_inclusion::<XorHash>(&leaf, &steps[..n], &root), K3::Pos);
    }

    #[kani::proof]
    fn over_depth_is_bot_without_hashing() {
        let leaf: Digest = kani::any();
        let root: Digest = kani::any();
        let path = [PathStep { sibling: [0u8; 32], side: Side::Left }; 65];
        assert_eq!(verify_inclusion::<XorHash>(&leaf, &path, &root), K3::Bot);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn gate_leaves_fallback_only_when_included_and_scored() {
        let candidates: [u8; 3] = kani::any();
        let fallback: u8 = kani::any();
        let env = Envelope::new(&candidates, fallback);
        let steps: [PathStep; 2] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 2);
        let inp = Tier0Inputs {
            weights_leaf: kani::any(),
            path: &steps[..n],
            pinned_root: kani::any(),
            base: kani::any(),
            lambda: kani::any(),
            cost: kani::any(),
            tau: kani::any(),
        };
        let proposed: u8 = kani::any();
        let out = gate_tier0::<u8, XorHash>(&env, &inp, proposed).into_inner();
        assert!(env.admits(&out));
        if out != fallback {
            assert_eq!(verify_inclusion::<XorHash>(&inp.weights_leaf, inp.path, &inp.pinned_root), K3::Pos);
            assert_eq!(score_verdict(inp.base, &inp.lambda, &inp.cost, inp.tau), K3::Pos);
            assert_eq!(out, proposed);
        }
    }
}
```

Creusot contracts in a sibling module compiled only under `cfg(creusot)`. Creusot proves absence of overflow from the preconditions, so this module uses raw operators. The shipped `no_std` functions use checked operators, and the `mul_bps_is_floor_and_contracting` harness above shows the two agree extensionally on the precondition domain.

```rust
#[cfg(creusot)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod creusot_wave9 {
    use super::Authority;
    use creusot_contracts::*;

    #[requires(a@ <= 10_000 && b@ <= 10_000)]
    #[ensures(result@ == (a@ * b@) / 10_000)]
    #[ensures(result@ <= a@ && result@ <= b@)]
    pub fn mul_bps_total(a: u16, b: u16) -> u16 {
        let prod: u32 = (a as u32) * (b as u32);
        (prod / 10_000) as u16
    }

    #[requires(root@ <= 10_000)]
    #[requires(forall<i: Int> 0 <= i && i < hops@.len() ==> hops@[i].share_bps@ <= 10_000)]
    #[ensures(result@ <= root@)]
    pub fn effective_share_bps_total(root: u16, hops: &[Authority]) -> u16 {
        let mut acc = root;
        let mut i: usize = 0;
        #[invariant(acc@ <= root@)]
        #[invariant(acc@ <= 10_000)]
        #[invariant(i@ <= hops@.len())]
        while i < hops.len() {
            acc = mul_bps_total(acc, hops[i].share_bps);
            i += 1;
        }
        acc
    }
}
```

Lean 4, `formal/lean4/Chio/Wave9/Attenuation.lean` and `Merkle.lean`:

```lean
import Mathlib.Tactic
import Chio.Wave9.Saturation

namespace Chio.Wave9.Attenuation

structure Auth where
  share : Nat
  units : Nat
  inv : Nat
  issuedAt : Nat
  expiresAt : Nat

def Att (c p : Auth) : Prop :=
  c.share ≤ p.share ∧ c.units ≤ p.units ∧ c.inv ≤ p.inv ∧
  p.issuedAt ≤ c.issuedAt ∧ c.expiresAt ≤ p.expiresAt

theorem Att.refl (a : Auth) : Att a a :=
  ⟨le_refl _, le_refl _, le_refl _, le_refl _, le_refl _⟩

theorem Att.trans {a b c : Auth} (h₁ : Att a b) (h₂ : Att b c) : Att a c :=
  ⟨le_trans h₁.1 h₂.1, le_trans h₁.2.1 h₂.2.1, le_trans h₁.2.2.1 h₂.2.2.1,
   le_trans h₂.2.2.2.1 h₁.2.2.2.1, le_trans h₁.2.2.2.2 h₂.2.2.2.2⟩

def ChainOk : Auth → List Auth → Prop
  | _, [] => True
  | p, c :: rest => Att c p ∧ ChainOk c rest

def leaf : Auth → List Auth → Auth
  | p, [] => p
  | _, c :: rest => leaf c rest

/-- Chain soundness: the leaf attenuates the root. -/
theorem leaf_att_root : ∀ (root : Auth) (hops : List Auth), ChainOk root hops → Att (leaf root hops) root := by
  intro root hops
  induction hops generalizing root with
  | nil => intro _; exact Att.refl root
  | cons c rest ih =>
    intro h
    obtain ⟨hc, hrest⟩ := h
    exact Att.trans (ih c hrest) hc

def ValidAt (now : Nat) (a : Auth) : Prop := a.issuedAt ≤ now ∧ now < a.expiresAt

/-- Upward validity: a valid child can never outlive its parent. -/
theorem validAt_of_att {now : Nat} {c p : Auth} (h : Att c p) (hv : ValidAt now c) : ValidAt now p :=
  ⟨le_trans h.2.2.2.1 hv.1, lt_of_lt_of_le hv.2 h.2.2.2.2⟩

theorem validAt_iff_rank {now : Nat} (a : Auth) :
    ValidAt now a ↔ Epoch.rank now a.issuedAt a.expiresAt = 1 := by
  simp only [ValidAt, Epoch.rank]; split_ifs <;> omega

/-- Share contraction for one hop. -/
theorem mul_bps_le_left {a b : Nat} (hb : b ≤ 10000) : a * b / 10000 ≤ a :=
  Nat.div_le_of_le_mul (by rw [Nat.mul_comm 10000 a]; exact Nat.mul_le_mul_left a hb)

theorem sum_le_len_mul {B : Nat} : ∀ xs : List Nat, (∀ x ∈ xs, x ≤ B) → xs.sum ≤ xs.length * B
  | [], _ => by simp
  | x :: rest, h => by
    have hx : x ≤ B := h x (List.mem_cons.mpr (Or.inl rfl))
    have ih := sum_le_len_mul rest (fun y hy => h y (List.mem_cons.mpr (Or.inr hy)))
    simp only [List.sum_cons, List.length_cons]
    nlinarith [hx, ih]

/-- The u32 accumulator in `OversubscribedSiblings` cannot overflow under the caps. -/
theorem sibling_total_fits_u32 (xs : List Nat) (hlen : xs.length ≤ 10000)
    (hcap : ∀ x ∈ xs, x ≤ 10000) : xs.sum < 4294967296 := by
  have h1 := sum_le_len_mul xs hcap
  have h2 : xs.length * 10000 ≤ 10000 * 10000 := Nat.mul_le_mul_right _ hlen
  omega

end Chio.Wave9.Attenuation

namespace Chio.Wave9.Merkle

inductive MTree (D : Type)
  | leaf : D → MTree D
  | node : MTree D → MTree D → MTree D

inductive Side | left | right

variable {D : Type} (h : D → D → D)

def root : MTree D → D
  | .leaf d => d
  | .node l r => h (root l) (root r)

def step (acc : D) : Side × D → D
  | (.left, s) => h s acc
  | (.right, s) => h acc s

def fold (lf : D) (path : List (Side × D)) : D := path.foldl (step h) lf

def leftmostPath : MTree D → List (Side × D)
  | .leaf _ => []
  | .node l r => leftmostPath l ++ [(.right, root h r)]

def leftmostLeaf : MTree D → D
  | .leaf d => d
  | .node l _ => leftmostLeaf l

theorem fold_append (lf : D) (p q : List (Side × D)) :
    fold h lf (p ++ q) = fold h (fold h lf p) q := by
  simp [fold, List.foldl_append]

/-- Fold completeness for an arbitrary compression function. -/
theorem fold_leftmost : ∀ t : MTree D, fold h (leftmostLeaf t) (leftmostPath h t) = root h t := by
  intro t
  induction t with
  | leaf d => simp [fold, leftmostPath, leftmostLeaf, root]
  | node l r ihl _ =>
    simp only [leftmostPath, leftmostLeaf, root, fold_append]
    rw [ihl]
    simp [fold, step]

/-- Gate soundness: leaving the fallback requires both verdicts to be Pos. -/
theorem gate_off_fallback_implies_pos (incl score : K3) (hp : K3.and incl score = .pos) :
    incl = .pos ∧ score = .pos :=
  (K3.and_eq_pos_iff incl score).mp hp

end Chio.Wave9.Merkle
```

The leftmost-path theorem generalizes to any leaf index by the same induction with a `Fin` index and a `Side` chosen per level. Soundness in the other direction, that a `Pos` verdict implies genuine membership, rests on collision resistance of the concrete hash and on the domain-separation requirement in the `Hash32` doc comment. That assumption sits outside every mechanized artifact here and must be stated as an axiom boundary in the manifest.

Manifest additions mirror the existing entry shape: one `[[kani]]` group per harness module above, one `[[lean]]` module per file under `Chio.Wave9`, one `[[apalache]]` entry for the TLA+ module, and one `[[creusot]]` entry. All entries are additive. No pinned Wave 1 signature changes, so the existing proof set is unaffected.

Recap. I produced a new `no_std`, `forbid(unsafe_code)` crate with checked arithmetic that adds a bit-precise `FixedQ16_16`, a private-constructor envelope, epoch and window ranking, an `AttenuationWitness` with injected classifier, Merkle `inclusion_step` and verification, and a Tier-0 gate that conjoins inclusion and score in Kleene logic. Twelve Kani harnesses cover exhaustive `i32` multiply and saturate, envelope totality, window refinement and monotonicity, epoch boundaries, ledger conservation and terminality pins, budget commit agreement, share contraction, witness soundness, Merkle fold completeness, and gate soundness. Lean 4 mechanizes clamp soundness, envelope preservation and transfer, window monotonicity, attenuation as a preorder with chain and upward-validity theorems, the `u32` sibling-sum bound, and fold completeness for an abstract hash. Creusot contracts and an Apalache spec close the remaining angles. None of it was compiled or checked here, so the next step is to add the crate and the one-line module declaration, then run `cargo kani -p chio-kernel-core -p chio-formal-wave9`, `lake build Chio.Wave9`, `cargo creusot`, and the Apalache command above. If any of the three ledger or budget pins fails, treat it as a documented-invariant discrepancy to resolve explicitly, not as a harness bug.

---

# Verbatim Treatise - `wave9_angle_2_copley_dag_optimization_and_simd_bitset_pass_9`

# Wave 9 Angle 2, Pass 9: Copley 537/236 Bitset Compiler and WCET Proof

## Part I. Representation, semantics, and the compiler

**Piece 1. Where the compiler sits in the decision tuple.** Tier-1 `UltraBERT` emits a score per atomic predicate. Thresholding with the pinned role-asymmetric pair turns each score into a Kleene value, and that is the last point at which a learned model is consulted. Everything downstream of the threshold is the exact computation $C_\ell(x)$ of the canonical tuple: the 236 rules are a fixed Boolean structure over the 537 predicates, and the Wave 1 law forbids asking the model to approximate what this structure computes exactly. `SymbolicRuleDag<537, 9, 9, 236>` is therefore compiled to a straight-line bitset program whose instruction count does not depend on the input, and whose every stage prefix returns a sound but possibly less informative answer. The conservative fallback $\bot_x$ of the envelope law is the Kleene value $\bot$ itself, mapped by the guard layer to `Verdict::PendingApproval`, which `GuardPipeline` already treats as sticky and later-deniable.

Thresholding is fixed as $+ \iff s_j \ge \tau_j^{\text{pos}}$ and $- \iff s_j < \tau_j^{\text{neg}}$. Because the manifest pins $\tau_j^{\text{neg}} \le \tau_j^{\text{pos}}$, the two conditions are exclusive, which is exactly the plane-disjointness invariant the whole construction rests on.

**Piece 2. Two-plane Kleene vectors.** A $\mathbb{K}_3$ vector over 537 predicates is two 9-word bit planes. A predicate is $+$ when its `pos` bit is set, $-$ when its `neg` bit is set, and $\bot$ when neither is set. Both set is a contradiction and is unrepresentable through the public constructor. Word 8 carries 25 valid bits; the 39 padding bits must be zero in both planes so that no mask can ever observe them.

```rust
//! crates/security/copley-rule-bitset/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const NUM_PREDICATES: usize = 537;
pub const NUM_WORDS: usize = 9;
pub const MAX_LITERALS_PER_CLAUSE: usize = 9;
pub const MAX_CLAUSES_PER_RULE: usize = 9;
pub const NUM_RULES: usize = 236;
pub const MAX_UNIQUE_CLAUSES: usize = NUM_RULES * MAX_CLAUSES_PER_RULE; // 2_124
pub const MAX_WORD_OPS: usize = MAX_UNIQUE_CLAUSES * NUM_WORDS;         // 19_116
pub const LAST_WORD_MASK: u64 = u64::MAX >> 39;                          // 25 valid bits
pub const TRUE_CLAUSE: u16 = MAX_UNIQUE_CLAUSES as u16;                  // identity of Kleene AND

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum K3VecError { Contradiction { word: usize }, PaddingSet }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct K3Vec { pos: [u64; NUM_WORDS], neg: [u64; NUM_WORDS] }

impl K3Vec {
    pub const BOTTOM: Self = Self { pos: [0; NUM_WORDS], neg: [0; NUM_WORDS] };

    /// The only public constructor. Rejects `pos & neg != 0` and any padding bit.
    pub fn new(pos: [u64; NUM_WORDS], neg: [u64; NUM_WORDS]) -> Result<Self, K3VecError> {
        for word in 0..NUM_WORDS {
            if pos[word] & neg[word] != 0 {
                return Err(K3VecError::Contradiction { word });
            }
        }
        if (pos[NUM_WORDS - 1] | neg[NUM_WORDS - 1]) & !LAST_WORD_MASK != 0 {
            return Err(K3VecError::PaddingSet);
        }
        Ok(Self { pos, neg })
    }
}

/// `1 << index`, total: out-of-range shifts yield 0 instead of a panic path.
#[inline(always)]
pub const fn bit(index: u32) -> u64 {
    match 1u64.checked_shl(index) { Some(b) => b, None => 0 }
}
```

**Piece 3. Clause and rule semantics in $\mathbb{K}_3$.** A Sigma detection lowers to a conjunction of at most 9 clauses, each a disjunction of at most 9 literals, where a literal is a predicate or its negation. Strong Kleene connectives are used: a disjunction is $+$ if any disjunct is $+$, $-$ if all disjuncts are $-$, else $\bot$; a conjunction is $-$ if any conjunct is $-$, $+$ if all are $+$, else $\bot$; negation swaps $+$ and $-$ and fixes $\bot$.

Two canonicalisation facts matter. Duplicate literals may be dropped because disjunction is idempotent in $\mathbb{K}_3$. Complementary pairs may **not** be simplified, because $p \vee \neg p$ evaluates to $\bot$ when $p = \bot$; the compiler keeps both literals and the bit formulas below handle the overlap exactly.

Let $M^+$ and $M^-$ be the 9-word masks of positive and negated literals of a clause, and let $(\mathit{pos}, \mathit{neg})$ be the input planes. The two bit-level lemmas are:

$$\text{clause} = + \iff \bigvee_{w} \big[(\mathit{pos}_w \wedge M^+_w) \vee (\mathit{neg}_w \wedge M^-_w)\big] \ne 0$$

$$\text{clause} = - \iff \bigvee_{w} \big[(M^+_w \wedge \neg \mathit{neg}_w) \vee (M^-_w \wedge \neg \mathit{pos}_w)\big] = 0$$

*Proof.* A positive literal $p_j$ is $+$ exactly when $\mathit{pos}_j$, and a negated literal $\neg p_j$ is $+$ exactly when $\mathit{neg}_j$; the first formula is the union over literals of these tests, so it is nonzero iff some literal is $+$. A positive literal is $-$ exactly when $\mathit{neg}_j$, so the "mismatch" bits $M^+ \wedge \neg\mathit{neg}$ are the positive literals that are not $-$; symmetrically $M^- \wedge \neg\mathit{pos}$ are the negated literals that are not $-$. The disjunction of mismatches is zero iff every literal is $-$. For a predicate appearing in both $M^+$ and $M^-$, both mismatch terms must vanish, requiring $\mathit{pos}_j$ and $\mathit{neg}_j$ simultaneously, which plane disjointness forbids; so such a clause is never $-$, matching $p \vee \neg p \in \{+, \bot\}$. Exclusivity of the two tests for a nonempty clause follows from plane disjointness: a literal cannot be both $+$ and $-$. $\square$

Because the second formula handles complementary pairs by itself, the earlier $(M^+ \mid M^-)$ XOR form used in Pass 8 is retired; it was unsound on overlapping bits.

**Piece 4. Canonical clauses, interning, and masks.** The compiler is `#![no_std]` with fixed capacity so it can be run under Kani and translated by Aeneas. Interning is a linear scan over the sorted-literal canonical form; the bipartite rule-to-clause DAG makes "topological" order trivial for evaluation (all clauses, then all rules), and the real ordering constraint is rank consistency, handled in Piece 5.

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Literal { pub predicate: u16, pub negated: bool }

impl Literal { pub const DEFAULT: Self = Self { predicate: 0, negated: false }; }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Clause { lits: [Literal; MAX_LITERALS_PER_CLAUSE], len: u8 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompileError {
    EmptyClause, EmptyRule, TooManyLiterals, TooManyClauses,
    PredicateOutOfRange { predicate: u16 }, CapacityExhausted, Arithmetic,
}

impl Clause {
    /// Sorted, duplicate-free literal set. Complementary pairs are kept (Piece 3).
    pub fn canonical(input: &[Literal]) -> Result<Self, CompileError> {
        if input.is_empty() { return Err(CompileError::EmptyClause); }
        if input.len() > MAX_LITERALS_PER_CLAUSE { return Err(CompileError::TooManyLiterals); }
        let mut sorted = [Literal::DEFAULT; MAX_LITERALS_PER_CLAUSE];
        for (slot, &lit) in sorted.iter_mut().zip(input) {
            if usize::from(lit.predicate) >= NUM_PREDICATES {
                return Err(CompileError::PredicateOutOfRange { predicate: lit.predicate });
            }
            *slot = lit;
        }
        sorted[..input.len()].sort_unstable();
        let mut lits = [Literal::DEFAULT; MAX_LITERALS_PER_CLAUSE];
        let mut len = 0usize;
        let mut last: Option<Literal> = None;
        for &lit in &sorted[..input.len()] {
            if last != Some(lit) {
                lits[len] = lit;
                len = len.checked_add(1).ok_or(CompileError::Arithmetic)?;
                last = Some(lit);
            }
        }
        let len = u8::try_from(len).map_err(|_| CompileError::Arithmetic)?;
        Ok(Self { lits, len })
    }

    pub fn literals(&self) -> &[Literal] { &self.lits[..usize::from(self.len)] }

    /// Positive and negated masks over the 9 words.
    pub fn masks(&self) -> ([u64; NUM_WORDS], [u64; NUM_WORDS]) {
        let (mut mp, mut mn) = ([0u64; NUM_WORDS], [0u64; NUM_WORDS]);
        for lit in self.literals() {
            let word = usize::from(lit.predicate / 64);
            let b = bit(u32::from(lit.predicate % 64));
            mp[word] |= b & !u64::from(lit.negated).wrapping_neg();
            mn[word] |= b & u64::from(lit.negated).wrapping_neg();
        }
        (mp, mn)
    }

    /// Number of words the clause touches; this is its op count.
    pub fn words_touched(&self) -> u32 {
        let (mp, mn) = self.masks();
        let mut n = 0u32;
        for w in 0..NUM_WORDS { n = n.saturating_add(u32::from((mp[w] | mn[w]) != 0)); }
        n
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule { clauses: [Clause; MAX_CLAUSES_PER_RULE], len: u8 }

impl Rule {
    pub fn new(clauses: &[Clause]) -> Result<Self, CompileError> {
        if clauses.is_empty() { return Err(CompileError::EmptyRule); }
        if clauses.len() > MAX_CLAUSES_PER_RULE { return Err(CompileError::TooManyClauses); }
        let mut arr = [Clause { lits: [Literal::DEFAULT; MAX_LITERALS_PER_CLAUSE], len: 0 }; MAX_CLAUSES_PER_RULE];
        for (slot, c) in arr.iter_mut().zip(clauses) { *slot = *c; }
        let len = u8::try_from(clauses.len()).map_err(|_| CompileError::Arithmetic)?;
        Ok(Self { clauses: arr, len })
    }
    pub fn clauses(&self) -> &[Clause] { &self.clauses[..usize::from(self.len)] }
}
```

The `wrapping_neg` on a 0/1 value is the branch-free select mask and cannot overflow; it is the one deliberately wrapping operation in the crate, and the lint accepts the method form.

**Piece 5. Short-circuit rank ordering.** Within a rule, clause order is chosen by a ratio rule. Let $\hat p_c$ be the calibration-set frequency, in basis points, with which clause $c$ evaluates to $-$, and let $\kappa_c$ be its op cost. Kleene conjunction is false-dominant, so a clause that is $-$ settles the rule regardless of the others. Order clauses by decreasing $\rho_c = \hat p_c / \kappa_c$, compared without division as $\hat p_a \kappa_b \ge \hat p_b \kappa_a$ in checked `u64`.

*Theorem (exchange).* For the sequential reference interpreter that stops at the first $-$ clause, and independent clause outcomes, the $\rho$-descending order minimises expected cost. *Proof.* For adjacent clauses $a$ before $b$, expected cost of the pair is $\kappa_a + (1 - \hat p_a)\kappa_b$; swapped, it is $\kappa_b + (1-\hat p_b)\kappa_a$. The first is no larger iff $\hat p_a \kappa_b \ge \hat p_b \kappa_a$, which is $\rho_a \ge \rho_b$. Any order not sorted by $\rho$ has an adjacent inversion whose swap does not increase cost; repeating yields the sorted order. $\square$

The zero-branch evaluator cannot stop early, so the ordering buys something different there: it defines the **rank** of each clause, and ranks are the stage boundaries of the anytime schedule in Piece 7. A clause shared by several rules takes the minimum of its positions, so that it is evaluated as early as any rule needs it. The interned table is then sorted by (rank, canonical key); this is a linear extension of the rank partial order, and it is the only "topological" step with content.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WordOp { pub word: u8, pub mp: u64, pub mn: u64 }

pub struct Schedule {
    pub ops: [WordOp; MAX_WORD_OPS],
    pub n_ops: usize,
    /// `ops[start..end]` for clause `c`; contiguous and in table order.
    pub clause_span: [(u16, u16); MAX_UNIQUE_CLAUSES],
    pub n_clauses: usize,
    /// Rule `r` combines exactly nine clause indices, padded with `TRUE_CLAUSE`.
    pub rule_clauses: [[u16; MAX_CLAUSES_PER_RULE]; NUM_RULES],
    /// `rank_clause_end[k]` = number of clauses with rank `< k`; index 9 is `n_clauses`.
    pub rank_clause_end: [usize; MAX_CLAUSES_PER_RULE + 1],
    /// Exact op count of running ranks `< k`, from `wcet_ops` (Piece 8).
    pub prefix_cost: [u32; MAX_CLAUSES_PER_RULE + 1],
}

struct Interner { table: [Clause; MAX_UNIQUE_CLAUSES], rank: [u8; MAX_UNIQUE_CLAUSES], n: usize }

impl Interner {
    fn intern(&mut self, c: Clause, pos: u8) -> Result<usize, CompileError> {
        if let Some(i) = self.table[..self.n].iter().position(|t| *t == c) {
            self.rank[i] = self.rank[i].min(pos);
            return Ok(i);
        }
        if self.n >= MAX_UNIQUE_CLAUSES { return Err(CompileError::CapacityExhausted); }
        let i = self.n;
        self.table[i] = c;
        self.rank[i] = pos;
        self.n = i.checked_add(1).ok_or(CompileError::Arithmetic)?;
        Ok(i)
    }
}

/// Rank-order the clauses of one rule in place by decreasing `p_false / cost`.
fn rank_order(clauses: &mut [Clause], p_false_bps: &dyn Fn(&Clause) -> u16) -> Result<(), CompileError> {
    let key = |c: &Clause| -> Result<(u64, u64), CompileError> {
        let cost = OPS_PER_WORD.checked_mul(c.words_touched()).and_then(|v| v.checked_add(OPS_PER_CLAUSE))
            .ok_or(CompileError::Arithmetic)?;
        Ok((u64::from(p_false_bps(c)), u64::from(cost)))
    };
    // Insertion sort on at most nine elements; stable, deterministic.
    for i in 1..clauses.len() {
        let mut j = i;
        while j > 0 {
            let prev = j.checked_sub(1).ok_or(CompileError::Arithmetic)?;
            let (pa, ka) = key(&clauses[prev])?;
            let (pb, kb) = key(&clauses[j])?;
            let lhs = pa.checked_mul(kb).ok_or(CompileError::Arithmetic)?;
            let rhs = pb.checked_mul(ka).ok_or(CompileError::Arithmetic)?;
            if lhs >= rhs { break; }
            clauses.swap(prev, j);
            j = prev;
        }
    }
    Ok(())
}
```

**Piece 6. Layout and emission.** After interning, the table is permuted by (rank, clause) with an old-to-new index map, rule slots are rewritten and padded, ops are emitted per clause in table order, and the rank prefixes and their exact costs are recorded.

```rust
pub fn compile(rules: &[Rule; NUM_RULES], p_false_bps: &dyn Fn(&Clause) -> u16) -> Result<Schedule, CompileError> {
    let empty = Clause { lits: [Literal::DEFAULT; MAX_LITERALS_PER_CLAUSE], len: 0 };
    let mut intern = Interner { table: [empty; MAX_UNIQUE_CLAUSES], rank: [u8::MAX; MAX_UNIQUE_CLAUSES], n: 0 };
    let mut old_slots = [[TRUE_CLAUSE; MAX_CLAUSES_PER_RULE]; NUM_RULES];
    for (r, rule) in rules.iter().enumerate() {
        let mut ordered = *rule;
        let len = usize::from(ordered.len);
        rank_order(&mut ordered.clauses[..len], p_false_bps)?;
        for (pos, c) in ordered.clauses[..len].iter().enumerate() {
            let pos8 = u8::try_from(pos).map_err(|_| CompileError::Arithmetic)?;
            old_slots[r][pos] = u16::try_from(intern.intern(*c, pos8)?).map_err(|_| CompileError::Arithmetic)?;
        }
    }
    // Permutation sorted by (rank, canonical clause).
    let mut perm = [0usize; MAX_UNIQUE_CLAUSES];
    for (i, p) in perm.iter_mut().enumerate().take(intern.n) { *p = i; }
    perm[..intern.n].sort_unstable_by_key(|&i| (intern.rank[i], intern.table[i]));
    let mut remap = [TRUE_CLAUSE; MAX_UNIQUE_CLAUSES];
    for (new, &old) in perm[..intern.n].iter().enumerate() {
        remap[old] = u16::try_from(new).map_err(|_| CompileError::Arithmetic)?;
    }
    let mut sched = Schedule {
        ops: [WordOp { word: 0, mp: 0, mn: 0 }; MAX_WORD_OPS], n_ops: 0,
        clause_span: [(0, 0); MAX_UNIQUE_CLAUSES], n_clauses: intern.n,
        rule_clauses: [[TRUE_CLAUSE; MAX_CLAUSES_PER_RULE]; NUM_RULES],
        rank_clause_end: [0; MAX_CLAUSES_PER_RULE + 1], prefix_cost: [0; MAX_CLAUSES_PER_RULE + 1],
    };
    for r in 0..NUM_RULES {
        for s in 0..MAX_CLAUSES_PER_RULE {
            let old = old_slots[r][s];
            sched.rule_clauses[r][s] = if old == TRUE_CLAUSE { TRUE_CLAUSE } else { remap[usize::from(old)] };
        }
    }
    for (new, &old) in perm[..intern.n].iter().enumerate() {
        let start = u16::try_from(sched.n_ops).map_err(|_| CompileError::Arithmetic)?;
        let (mp, mn) = intern.table[old].masks();
        for w in 0..NUM_WORDS {
            if mp[w] | mn[w] != 0 {
                if sched.n_ops >= MAX_WORD_OPS { return Err(CompileError::CapacityExhausted); }
                sched.ops[sched.n_ops] = WordOp { word: u8::try_from(w).map_err(|_| CompileError::Arithmetic)?, mp: mp[w], mn: mn[w] };
                sched.n_ops = sched.n_ops.checked_add(1).ok_or(CompileError::Arithmetic)?;
            }
        }
        let end = u16::try_from(sched.n_ops).map_err(|_| CompileError::Arithmetic)?;
        sched.clause_span[new] = (start, end);
    }
    for k in 0..=MAX_CLAUSES_PER_RULE {
        let count = perm[..intern.n].iter().filter(|&&old| usize::from(intern.rank[old]) < k).count();
        sched.rank_clause_end[k] = count;
        let ops_in_prefix = if count == 0 { 0 } else { u32::from(sched.clause_span[count.checked_sub(1).ok_or(CompileError::Arithmetic)?].1) };
        let count32 = u32::try_from(count).map_err(|_| CompileError::Arithmetic)?;
        sched.prefix_cost[k] = wcet_ops(ops_in_prefix, count32).ok_or(CompileError::Arithmetic)?;
    }
    Ok(sched)
}
```

## Part II. The zero-branch evaluator and its WCET

**Piece 7. Evaluation and the anytime stage prefix.** The evaluator has two counted loops whose trip counts come from the schedule, never from the input. Within a clause, two accumulators collect the any-true bits and the mismatch bits from Piece 3. A clause outside the executed rank prefix is never touched and reports $(t, f) = (0, 0)$, which is $\bot$; the sentinel clause reports $(1, 0)$, the identity of Kleene conjunction. Rule combination is nine unconditional AND/OR pairs.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleVerdicts { pub code: [u8; NUM_RULES] } // 0 = ⊥, 1 = +, 2 = −

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum K3 { Top, Bot, Unknown }

impl RuleVerdicts {
    /// Fail closed: the unreachable code 3 decodes as ⊥.
    pub fn get(&self, r: usize) -> K3 {
        match self.code.get(r) { Some(1) => K3::Top, Some(2) => K3::Bot, _ => K3::Unknown }
    }
}

/// Run ranks `< ranks` (0..=9). `ranks == 9` is the full exact evaluation.
pub fn evaluate(sched: &Schedule, x: &K3Vec, ranks: u8) -> RuleVerdicts {
    let ranks = usize::from(ranks).min(MAX_CLAUSES_PER_RULE);
    let active = sched.rank_clause_end[ranks];
    let mut t = [0u8; MAX_UNIQUE_CLAUSES + 1];
    let mut f = [0u8; MAX_UNIQUE_CLAUSES + 1];
    t[MAX_UNIQUE_CLAUSES] = 1;
    for c in 0..active {
        let (start, end) = sched.clause_span[c];
        let (mut acc_t, mut acc_f) = (0u64, 0u64);
        for op in &sched.ops[usize::from(start)..usize::from(end)] {
            let p = x.pos[usize::from(op.word)];
            let n = x.neg[usize::from(op.word)];
            acc_t |= (p & op.mp) | (n & op.mn);
            acc_f |= (op.mp & !n) | (op.mn & !p);
        }
        t[c] = u8::from(acc_t != 0);
        f[c] = u8::from(acc_f == 0);
    }
    let mut out = RuleVerdicts { code: [0u8; NUM_RULES] };
    for (r, slots) in sched.rule_clauses.iter().enumerate() {
        let (mut rt, mut rf) = (1u8, 0u8);
        for &ci in slots {
            rt &= t[usize::from(ci)];
            rf |= f[usize::from(ci)];
        }
        out.code[r] = rt | (rf << 1);
    }
    out
}

/// Largest rank prefix whose exact cost fits the fuel the λ_latency controller granted.
pub fn ranks_for_fuel(sched: &Schedule, fuel: u32) -> u8 {
    let mut k = 0u8;
    for (i, &cost) in sched.prefix_cost.iter().enumerate() {
        let i8 = u8::try_from(i).unwrap_or(u8::MAX);
        k = if cost <= fuel { i8 } else { k };
    }
    k
}
```

Array indexing carries bounds checks, which are machine-level branches, but every index derives from the schedule, not from `x`. A `validate(&Schedule)` pass (Piece 11) establishes `word < 9`, contiguous spans within `n_ops`, slot indices at most `TRUE_CLAUSE`, monotone rank prefixes ending at `n_clauses`, and masks clear of padding; under that predicate Kani shows the panic paths are unreachable, so the compiled text is straight-line modulo the two counted loops.

*Theorem (truncation monotonicity).* For every rule $r$ and every $k \le 9$, the verdict after ranks $< k$ is below the verdict after ranks $< k{+}1$ in the information order $\bot \sqsubseteq +$, $\bot \sqsubseteq -$, and the verdict at $k = 9$ equals the exact Kleene value. *Proof.* Untouched clauses contribute $(0,0)$. Adding a rank changes some clauses from $(0,0)$ to their true pair. The rule's $rf$ is a disjunction, so it can only rise from $0$ to $1$, and if it was $1$ it stays $1$ because an evaluated clause's $f$ bit is exact and never retracted. The rule's $rt$ is a conjunction that is $0$ whenever any clause is untouched; it can become $1$ only when all clauses are evaluated and all are $+$, which is the exact $+$ condition. A verdict therefore moves only from $\bot$ to a definite value, never between definite values. At $k = 9$ every clause is evaluated and Piece 3 gives exactness. $\square$

**Piece 8. Exact instruction count.** The cost model counts 64-bit ALU operations in the straight-line expansion of `evaluate`, excluding loads and loop bookkeeping, which are proportional and target-pinned separately. Per word-op the any-true half costs two ANDs, one OR, and one OR-accumulate; the all-false half costs two AND-NOTs, one OR, and one OR-accumulate. Without BMI1 or AArch64 `bic`, add two for the explicit NOTs.

```rust
pub const OPS_PER_WORD: u32 = 8;
pub const OPS_PER_CLAUSE: u32 = 2;      // two zero tests
pub const OPS_PER_RULE_SLOT: u32 = 2;   // AND, OR
pub const OPS_PER_RULE: u32 = 2;        // shift, OR

pub const fn wcet_ops(n_ops: u32, n_clauses: u32) -> Option<u32> {
    const RULES: u32 = (OPS_PER_RULE_SLOT * (MAX_CLAUSES_PER_RULE as u32) + OPS_PER_RULE) * (NUM_RULES as u32);
    let words = match OPS_PER_WORD.checked_mul(n_ops) { Some(v) => v, None => return None };
    let clauses = match OPS_PER_CLAUSE.checked_mul(n_clauses) { Some(v) => v, None => return None };
    let acc = match words.checked_add(clauses) { Some(v) => v, None => return None };
    acc.checked_add(RULES)
}

pub const WCET_FULL_UPPER_BOUND: u32 = 161_896;
const _: () = assert!(matches!(
    wcet_ops(MAX_WORD_OPS as u32, MAX_UNIQUE_CLAUSES as u32),
    Some(WCET_FULL_UPPER_BOUND)
));
```

*Theorem (exact WCET).* For a validated schedule $S$ with $n_{\text{ops}}$ word-ops and $n_{\text{cl}}$ unique clauses, the op count of `evaluate(S, x, 9)` equals $8\, n_{\text{ops}} + 2\, n_{\text{cl}} + 20 \cdot 236$ for every input $x$, and the stage prefix for $k$ costs exactly `prefix_cost[k]`. *Proof.* The outer loop runs `rank_clause_end[k]` times and the inner loop runs over a span whose length is fixed by the schedule; both bounds are schedule fields. Each inner iteration executes the same eight operations and each outer iteration the same two tests, with no data-dependent control flow. The rule loop executes exactly nine slot combines and one output pack per rule, for all 236 rules, regardless of the prefix. Summation over the fixed iteration counts gives the closed form; the prefix form substitutes the end offset of the last active clause for $n_{\text{ops}}$. Independence from $x$ is immediate because $x$ appears only as an operand. $\square$

*Corollary (a priori bound).* A clause with at most 9 literals touches at most 9 words, and at most 2,124 distinct clauses exist, so the compile-time assertion above pins the universal bound. The table gives the components.

| Component | Count | Ops |
|---|---|---|
| Word-ops, worst case | 19,116 | 152,928 |
| Clause zero-tests | 2,124 | 4,248 |
| Rule slot combines and packs | 236 × 20 | 4,720 |
| Total upper bound | | 161,896 |

Field locality sharpens the per-clause bound. Predicate indices are laid out by field in the order CommandLine, Image, OriginalFileName, ParentImage, so a single-field Sigma selection spans at most 6 words for CommandLine and 2 for each other field. The compiler emits a `ClauseSpansFields` diagnostic when a clause mixes fields, and the exact count for the real 236-rule set is whatever `prefix_cost[9]` of the generated schedule says, bound into the receipt in Piece 13. At a nominal four ops per nanosecond the universal bound sits well inside the Tier-1 envelope and far outside Tier-0, which is why the schedule is a Tier-1 exact-computation stage and not a Tier-0 micro-model.

## Part III. Verification and integration

**Piece 9. Lean 4 semantics and the two core theorems.** The Lean development models a valuation as a function into $\mathbb{K}_3$, which makes plane disjointness definitional. The abstract any-true and all-false tests are the per-literal view of the mask formulas; the word-packing step is a bijection on finite index sets and is a separate lemma.

```lean
namespace Copley.Bitset

inductive K3 | top | bot | unk
deriving DecidableEq, Repr

def K3.or : K3 → K3 → K3
  | .top, _ => .top | _, .top => .top | .bot, .bot => .bot | _, _ => .unk
def K3.and : K3 → K3 → K3
  | .bot, _ => .bot | _, .bot => .bot | .top, .top => .top | _, _ => .unk
def K3.not : K3 → K3 | .top => .bot | .bot => .top | .unk => .unk
/-- Information order: ⊥ is below everything, definite values are incomparable. -/
def K3.le (a b : K3) : Prop := a = .unk ∨ a = b

abbrev Lit := Fin 537 × Bool
abbrev Val := Fin 537 → K3

def litVal (v : Val) (l : Lit) : K3 := if l.2 then (v l.1).not else v l.1

def clauseK3 (v : Val) (c : List Lit) : K3 := c.foldr (fun l acc => (litVal v l).or acc) .bot
def anyTrue  (v : Val) (c : List Lit) : Bool := c.any (fun l => litVal v l == .top)
def allFalse (v : Val) (c : List Lit) : Bool := c.all (fun l => litVal v l == .bot)
def clauseBits (v : Val) (c : List Lit) : K3 :=
  if anyTrue v c then .top else if allFalse v c then .bot else .unk

theorem or_top_left  (b : K3) : K3.or .top b = .top := by cases b <;> rfl
theorem or_bot_bot            : K3.or .bot .bot = .bot := rfl
theorem or_unk (a b : K3) (ha : a ≠ .top) (hb : b ≠ .top) (h : ¬(a = .bot ∧ b = .bot)) :
    K3.or a b = .unk := by cases a <;> cases b <;> simp_all [K3.or]

theorem clauseBits_correct (v : Val) (c : List Lit) (h : c ≠ []) :
    clauseBits v c = clauseK3 v c := by
  induction c with
  | nil => exact absurd rfl h
  | cons l t ih =>
    cases t with
    | nil =>
      simp only [clauseBits, anyTrue, allFalse, clauseK3, List.any, List.all, List.foldr]
      cases litVal v l <;> simp [K3.or]
    | cons l' t' =>
      have ih' := ih (by simp)
      simp only [clauseBits, anyTrue, allFalse, clauseK3, List.any_cons, List.all_cons, List.foldr] at *
      cases hl : litVal v l <;> cases hr : clauseK3 v (l' :: t') <;> simp_all [K3.or]

def ruleK3 (v : Val) (r : List (List Lit)) : K3 :=
  r.foldr (fun c acc => (clauseK3 v c).and acc) .top

/-- Evaluate only the first `k` clauses; the rest are ⊥ (untouched). -/
def rulePartial (v : Val) (r : List (List Lit)) (k : Nat) : K3 :=
  let seen := r.take k
  if seen.any (fun c => clauseBits v c == .bot) then .bot
  else if k ≥ r.length ∧ seen.all (fun c => clauseBits v c == .top) then .top
  else .unk

theorem rulePartial_mono (v : Val) (r : List (List Lit)) (k : Nat) :
    K3.le (rulePartial v r k) (rulePartial v r (k + 1)) := by
  unfold rulePartial K3.le
  by_cases hb : (r.take k).any (fun c => clauseBits v c == .bot)
  · right
    have : (r.take (k+1)).any (fun c => clauseBits v c == .bot) := by
      rcases List.any_eq_true.mp hb with ⟨c, hc, hv⟩
      exact List.any_eq_true.mpr ⟨c, List.take_subset_take (Nat.le_succ k) hc, hv⟩
    simp [hb, this]
  · by_cases ht : k ≥ r.length ∧ (r.take k).all (fun c => clauseBits v c == .top)
    · right
      have hlen : r.take (k+1) = r.take k := List.take_of_length_le (by omega) ▸
        (List.take_of_length_le ht.1).symm ▸ rfl
      simp [hb, ht, hlen, Nat.le_succ_of_le ht.1]
    · left; simp [hb, ht]

theorem rulePartial_full (v : Val) (r : List (List Lit)) (hne : ∀ c ∈ r, c ≠ []) :
    rulePartial v r r.length = ruleK3 v r := by
  induction r with
  | nil => rfl
  | cons c t ih =>
    have hc := clauseBits_correct v c (hne c (by simp))
    simp only [rulePartial, ruleK3, List.take_length, List.any_cons, List.all_cons, List.foldr] at *
    cases hcv : clauseK3 v c <;> cases hr : ruleK3 v t <;>
      simp_all [K3.and, ih (fun d hd => hne d (by simp [hd]))]

/-- Cost model of the instrumented evaluator; `v` does not occur on the right. -/
def cost (nOps nClauses : Nat) : Nat := 8 * nOps + 2 * nClauses + 20 * 236
theorem cost_bound (nOps nClauses : Nat) (ho : nOps ≤ 19116) (hc : nClauses ≤ 2124) :
    cost nOps nClauses ≤ 161896 := by unfold cost; omega

end Copley.Bitset
```

The Aeneas obligations are the refinement of the translated `evaluate` to `rulePartial` composed with the word-packing bijection, and the refinement of the translated `wcet_ops` to `cost`. Both are additive files under `formal/lean4/Copley/`, pinned by new `[[proof]]` entries in `formal/proof-manifest.toml`; no existing `Chio/` theorem is touched.

**Piece 10. Kani harnesses.** The reference evaluator is the tree-walking strong-Kleene interpreter over the same `Rule` type; it is the executable twin of `ruleK3` and the shape that the HushSpec IR interpreter has. Harnesses quantify over symbolic planes with the disjointness and padding invariants assumed.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    fn any_k3vec() -> K3Vec {
        let pos: [u64; NUM_WORDS] = kani::any();
        let raw: [u64; NUM_WORDS] = kani::any();
        let mut p = [0u64; NUM_WORDS];
        let mut n = [0u64; NUM_WORDS];
        for w in 0..NUM_WORDS { p[w] = pos[w]; n[w] = raw[w] & !pos[w]; }
        p[NUM_WORDS - 1] &= LAST_WORD_MASK;
        n[NUM_WORDS - 1] &= LAST_WORD_MASK;
        K3Vec::new(p, n).unwrap()
    }

    fn any_clause() -> Clause {
        let len: usize = kani::any();
        kani::assume((1..=MAX_LITERALS_PER_CLAUSE).contains(&len));
        let mut lits = [Literal::DEFAULT; MAX_LITERALS_PER_CLAUSE];
        for slot in lits.iter_mut().take(len) {
            let predicate: u16 = kani::any();
            kani::assume(usize::from(predicate) < NUM_PREDICATES);
            *slot = Literal { predicate, negated: kani::any() };
        }
        Clause::canonical(&lits[..len]).unwrap()
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn clause_schedule_matches_reference() {
        let clause = any_clause();
        let x = any_k3vec();
        assert_eq!(eval_single_clause(&clause, &x), reference::eval_clause(&clause, &x));
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn clause_verdicts_are_exclusive() {
        let clause = any_clause();
        let x = any_k3vec();
        let (t, f) = clause_bits(&clause, &x);
        assert!(!(t == 1 && f == 1));
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn truncation_is_monotone_for_one_rule() {
        let rule = any_rule();
        let x = any_k3vec();
        let mut prev = K3::Unknown;
        for k in 0..=MAX_CLAUSES_PER_RULE as u8 {
            let cur = eval_single_rule_prefix(&rule, &x, k);
            assert!(prev == K3::Unknown || prev == cur);
            prev = cur;
        }
        assert_eq!(prev, reference::eval_rule(&rule, &x));
    }
}
```

The helpers `eval_single_clause`, `clause_bits`, and `eval_single_rule_prefix` are `pub(crate)` wrappers that compile one clause or one rule through the same emission path as `compile` and run the same inner loop as `evaluate`, so the harnesses exercise the production code rather than a copy.

**Piece 11. Differential tests against HushSpec IR.** The grounded context pins no HushSpec IR signature, so the harness binds through a two-method adapter trait rather than a guessed path: one method lowers an IR detection to `Rule`, the other evaluates the IR directly on a $\mathbb{K}_3$ assignment. Binding it to `chio-policy` is a one-file change in the test crate. Three test families run under `std`.

- **Exhaustive per clause.** For each unique clause with $k$ literals, enumerate all $3^k$ assignments to its literals' predicates, leaving every other predicate $\bot$, and compare the compiled clause bit pair with the IR verdict. For $k = 9$ this is 19,683 cases per clause.
- **Randomised full vectors.** Sample `pos` and `neg` as independent Bernoulli planes, clear the collision bits from `neg`, mask padding, and compare all 236 compiled verdicts against the IR for every rank prefix, asserting information-order monotonicity between consecutive prefixes and exact equality at the full prefix.
- **Schedule validation.** `validate(&compiled)` must accept the generated schedule, and every mutation in a small set of hand-written corruptions must be rejected, which is what licenses the no-panic claim in Piece 7.

```rust
#[cfg(test)]
mod differential {
    use super::*;

    pub trait HushSpecAdapter {
        fn lower(&self) -> Result<Rule, CompileError>;
        fn evaluate_ir(&self, x: &K3Vec) -> K3;
    }

    pub fn check_against_ir<A: HushSpecAdapter>(ir: &[A; NUM_RULES], sched: &Schedule, x: &K3Vec) {
        let mut prev = evaluate(sched, x, 0);
        for ranks in 1..=MAX_CLAUSES_PER_RULE as u8 {
            let cur = evaluate(sched, x, ranks);
            for r in 0..NUM_RULES {
                assert!(prev.get(r) == K3::Unknown || prev.get(r) == cur.get(r), "rule {r} retracted at rank {ranks}");
            }
            prev = cur;
        }
        for (r, detection) in ir.iter().enumerate() {
            assert_eq!(prev.get(r), detection.evaluate_ir(x), "rule {r} disagrees with HushSpec IR");
        }
    }
}
```

**Piece 12. Apalache model of the staged controller.** The only decision outside the straight-line kernel is how many ranks to run, taken from the fuel the Tier-0 shadow-price controller grants. The model treats per-prefix verdicts as a constant oracle satisfying the monotonicity theorem and checks that the controller never overspends and never reports a verdict that the full evaluation would contradict.

```tla
---------------------------- MODULE CopleyStagedSchedule ----------------------------
EXTENDS Integers

CONSTANTS
  \* @type: Int;                    number of rules
  NR,
  \* @type: Int -> Int;             exact prefix cost, nondecreasing in the rank
  PrefixCost,
  \* @type: <<Int, Int>> -> Int;    Partial[<<k, r>>] in {0 = unk, 1 = top, 2 = bot}
  Partial,
  \* @type: Int;
  Fuel

Ranks == 0..9
Rules == 1..NR

ASSUME \A k \in 0..8 : PrefixCost[k] <= PrefixCost[k + 1]
ASSUME \A k \in 0..8, r \in Rules :
         Partial[<<k, r>>] = 0 \/ Partial[<<k, r>>] = Partial[<<k + 1, r>>]

VARIABLES
  \* @type: Int;
  stage,
  \* @type: Int;
  spent

Init == stage = 0 /\ spent = 0

Advance ==
  /\ stage < 9
  /\ PrefixCost[stage + 1] <= Fuel
  /\ stage' = stage + 1
  /\ spent' = PrefixCost[stage + 1]

Stop ==
  /\ (stage = 9 \/ PrefixCost[stage + 1] > Fuel)
  /\ UNCHANGED <<stage, spent>>

Next == Advance \/ Stop

BudgetInv == spent <= Fuel
SoundInv  == \A r \in Rules :
               Partial[<<stage, r>>] = 0 \/ Partial[<<stage, r>>] = Partial[<<9, r>>]
Inv == BudgetInv /\ SoundInv
=======================================================================================
```

`SoundInv` is inductive: the assumption on `Partial` is the TLA+ form of `rulePartial_mono`, and transitivity along the rank chain gives agreement with rank 9. `BudgetInv` is inductive because `Advance` guards on the exact prefix cost, which Piece 8 proves is the true op count.

**Piece 13. Additive integration.** Nothing pinned by `formal/proof-manifest.toml` changes shape.

- **Crate placement.** `crates/security/copley-rule-bitset` holds the `#![no_std]`, `#![forbid(unsafe_code)]` compiler and evaluator with the same arithmetic lint as `budget_split.rs`. A build-time `copley-rule-compiler` binary runs `compile` over the lowered Sigma set and emits a generated `schedule.rs` with concrete lengths, so the shipped static has no slack beyond the real op count.
- **Receipts.** The schedule digest, ranks run, ops executed, and `prefix_cost[9]` are recorded under the existing reserved key `"model_metadata"` as a nested `copley_rule_schedule_v1` object. The array `RESERVED_RECEIPT_METADATA_KEYS: [&str; 35]` keeps its length and type, so no consumer that matches on it breaks.
- **Weights binding.** The schedule implements `LoadedWeights` with a provider name of its own and its canonical byte image as the weights, so `evaluate_weights_binding` binds the exact-computation half of Tier-1 to the model card alongside the `UltraBERT` tensors. Threshold vectors travel in the same image, which is what makes the disjointness guarantee of Piece 1 part of the attested artifact.
- **Fuel.** `ranks_for_fuel` consumes a `u32` op budget derived from $\lambda_{\text{latency}}$ by a monotone `FixedQ16_16` map in the Tier-0 controller. Because prefix costs are exact and monotone, the controller's choice is the largest sound prefix, and the full prefix is always feasible when the budget admits the universal bound.
- **Guard mapping.** Any rule at $+$ yields `Verdict::Deny`. No $+$ and any $\bot$ yields `Verdict::PendingApproval`, which the pipeline holds sticky while later guards run. All $-$ yields `Verdict::Allow`. The $\bot$ path is the envelope's conservative fallback, so a truncated stage can only make the system more cautious, never less.

**Piece 14. What remains for Pass 10.** Three items are open and none blocks the above. The Aeneas refinement scripts for `evaluate` and `wcet_ops` need to be generated and checked against the Lean theorems in Piece 9. The HushSpec adapter needs binding to the real IR types in `chio-policy` once their signatures are pinned into the grounded context. The per-field word-span refinement of the WCET bound should be promoted from a compiler diagnostic to a manifest-checked invariant, which would tighten the universal bound for the actual field layout without changing any evaluator code.

---

# Verbatim Treatise - `wave9_angle_3_concurrent_loom_and_dst_crash_recovery_pass_9`

I'll lay out the verification design for Wave 9 Angle 3, then give the additive core module, the two test files, and the Lean, Apalache, and Kani artifacts that discharge the same properties once each.

## Model and theorems

**What is verified where.** Four shared objects and one protocol are under test. Each row is checked at the layer where its failure mode actually lives.

| Target | Failure mode | Loom | DST | Lean / Aeneas | Kani | Apalache |
|---|---|---|---|---|---|---|
| `WeightEpoch` publication | early or torn read of an unpublished epoch | yes | no | no | no | no |
| `ExecutionNonceStore` | nonce dispatched twice, or rolled back after dispatch | yes | yes | yes | yes | yes |
| `BudgetSplit` holders | oversubscribed siblings via check-then-insert, holder underflow | yes | no | no | no | no |
| `SessionOperation` cancel | cancel and dispatch both win across a cutpoint | yes | yes | no | no | yes |
| Crash recovery | lost dispatch, re-dispatch after recovery | no | yes | yes | yes | yes |

**Histories and linearizability.** A history $H$ is a finite sequence of invocation and response events. $H$ is linearizable with respect to a sequential specification $S$ when there exists a total order of its operations that is a legal sequential execution of $S$ and that respects real time: if the response of $a$ precedes the invocation of $b$ in $H$, then $a$ precedes $b$ in the order. Loom enumerates every interleaving up to a preemption bound, so a recorded history that fails the Wing and Gong search is a concrete counterexample, not a sample.

**Cutpoints.** The pre-dispatch cutpoint is the instant the `BeginDispatch` transition is applied to the operation state. The post-dispatch cutpoint is the instant the external side effect becomes irreversible. Before the first cutpoint, `Cancel` and RAII `Drop` compensate by freeing the nonce and releasing the reservation. Between the two cutpoints the system is in an intent window. After the second, only forward recovery is permitted.

**Recovery is $\mathbb{K}_3$-valued.** Recovery reads durable facts only and returns a verdict in $\{+, -, \bot\}$. The verdict is mapped onto the pinned ledger operations with no new ledger semantics:

$$
\rho(\text{nonce}, \text{receipt}) =
\begin{cases}
+ & \text{receipt present, or nonce} = \mathsf{Consumed} \\
\bot & \text{nonce} = \mathsf{Dispatching}, \text{no receipt} \\
- & \text{nonce} \in \{\mathsf{Free}, \mathsf{Reserved}\}, \text{no receipt}
\end{cases}
\qquad
\text{op}(+) = 1,\; \text{op}(-) = 2,\; \text{op}(\bot) = 3
$$

The $\bot$ verdict is the conservative fallback $\bot_x$ of the decision-model law. It retains the escrow and never dispatches. It surfaces through the already reserved `FINDING_RECOVERY_METADATA_KEY`, so the reserved-key array is untouched.

**Theorem 1, lock register linearizability.** Let the epoch cell be a reader-writer lock holding an `Arc<WeightEpoch>`, with `store` taking the write lock and `load` cloning under the read lock. Every history is linearizable with respect to the atomic register specification.

*Proof.* Lock acquisitions are totally ordered by the lock's mutual exclusion between writers and between writers and readers. Assign each operation the instant it acquires its lock as linearization point. That instant lies inside the operation's interval, so the induced order respects real time. In that order each `load` observes exactly the `Arc` installed by the most recent `store` whose critical section preceded its own, which is the register specification. Concurrent readers do not modify state, so any relative order among them is legal. $\square$

This is the protocol-level guarantee that `arc_swap::ArcSwap::load` documents. Loom cannot instrument the `arc-swap` crate, so the test checks the protocol around the cell against this faithful model, and `arc-swap`'s own linearizability is an explicitly stated assumption.

**Proposition 2, the double buffer is not linearizable.** Consider two slots guarded by mutexes and an atomic index. The writer fills the inactive slot and then publishes its index with release ordering. The reader loads the index with acquire ordering and then locks that slot. The following interleaving is a non-linearizable history. The reader loads index `0` while epoch `0` is current. The writer publishes epoch `1` into slot one, then locks slot zero and writes epoch `2`, but has not yet stored the index. The reader now locks slot zero and returns epoch `2`. The reader's second `load` reads index `1` and returns epoch `1`.

*Proof.* The two publishes are in one thread, so any sequential order has `publish(1)` before `publish(2)`. The first read returned `2`, so it follows `publish(2)`. The second read follows the first in real time and must therefore also return `2`. It returned `1`. No legal sequential order exists. $\square$

Loom finds this trace under a preemption bound of two, which is why the double-buffer test is marked `should_panic`. The first read also observed a value before its write was published, so the binding rule in `evaluate_weights_binding` would have been checked against weights the inference never used.

**Theorem 3, cutpoint exclusivity.** With `BeginDispatch` and `Cancel` both applied under one mutex to the transition function `op_step`, exactly one of dispatch and cancel succeeds, the external effect occurs only when dispatch succeeded, and the nonce is rolled back only when cancel succeeded.

*Proof.* `Pending` is the only state in which either event is enabled, and both events leave `Pending`. The mutex serializes the two applications, so the second finds a state in which it is disabled and returns `None`. The effect is executed only on the success path of `BeginDispatch`, and `rollback` is invoked only on the success path of `Cancel`. $\square$

**Theorem 4, no lost dispatch and at-most-once under crashes.** If the durable `Dispatching` intent is written before the external effect and the commit transaction writes nonce, receipt, and ledger atomically, then after any crash and recovery no nonce is dispatched twice and every performed effect ends `Consumed` with a receipt or held under $\bot$. The proof is mechanized below in Lean, and the state space is exhausted by Apalache. The DST file additionally shows the theorem fails without the intent record, so the oracle is sharp.

## Executable harnesses

**Additive core module.** Nothing in `formal_core.rs` or `formal_aeneas.rs` changes. One line is added to the crate root: `pub mod formal_cutpoint;`.

```rust
// crates/kernel/chio-kernel-core/src/formal_cutpoint.rs
//! Wave 9 Angle 3: pure cutpoint and recovery kernel. Strictly additive.
use crate::formal_aeneas::{ledger_apply, ReservationLedger};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum K3 { Pos, Neg, Bot }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum NonceState { Free, Reserved, Dispatching, Consumed }

pub const MAX_NONCE_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceTable { slots: [NonceState; MAX_NONCE_SLOTS] }

impl Default for NonceTable { fn default() -> Self { Self::new() } }

impl NonceTable {
    #[must_use]
    pub const fn new() -> Self { Self { slots: [NonceState::Free; MAX_NONCE_SLOTS] } }
    #[must_use]
    pub fn state(&self, nonce: usize) -> Option<NonceState> { self.slots.get(nonce).copied() }
    fn step(&mut self, nonce: usize, from: NonceState, to: NonceState) -> bool {
        match self.slots.get_mut(nonce) {
            Some(slot) if *slot == from => { *slot = to; true }
            _ => false,
        }
    }
    pub fn reserve(&mut self, n: usize) -> bool { self.step(n, NonceState::Free, NonceState::Reserved) }
    pub fn mark_dispatching(&mut self, n: usize) -> bool { self.step(n, NonceState::Reserved, NonceState::Dispatching) }
    pub fn consume(&mut self, n: usize) -> bool { self.step(n, NonceState::Dispatching, NonceState::Consumed) }
    /// Pre-dispatch cutpoint only. Never succeeds from `Dispatching`.
    pub fn rollback(&mut self, n: usize) -> bool { self.step(n, NonceState::Reserved, NonceState::Free) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryFacts { pub nonce: NonceState, pub receipt_present: bool }

#[must_use]
pub fn resolve_recovery(f: RecoveryFacts) -> K3 {
    match (f.nonce, f.receipt_present) {
        (NonceState::Consumed, _) | (_, true) => K3::Pos,
        (NonceState::Dispatching, false) => K3::Bot,
        (NonceState::Reserved | NonceState::Free, false) => K3::Neg,
    }
}

/// 1 = commit, 2 = release, 3 = retain. Recovery can never emit 0 (reserve).
#[must_use]
pub const fn recovery_ledger_op(v: K3) -> u8 { match v { K3::Pos => 1, K3::Neg => 2, K3::Bot => 3 } }

#[must_use]
pub fn apply_recovery(ledger: ReservationLedger, v: K3, amount: u64) -> (ReservationLedger, bool) {
    ledger_apply(ledger, recovery_ledger_op(v), amount)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpState { Pending, Dispatching, Dispatched, Completed, Cancelled }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpEvent { BeginDispatch, EffectDone, Commit, Cancel }

/// Total transition function. `None` means rejected; the caller leaves state unchanged.
#[must_use]
pub const fn op_step(s: OpState, e: OpEvent) -> Option<OpState> {
    match (s, e) {
        (OpState::Pending, OpEvent::BeginDispatch) => Some(OpState::Dispatching),
        (OpState::Pending, OpEvent::Cancel) => Some(OpState::Cancelled),
        (OpState::Dispatching, OpEvent::EffectDone) => Some(OpState::Dispatched),
        (OpState::Dispatched, OpEvent::Commit) => Some(OpState::Completed),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightEpochDigest { pub epoch: u64, pub weights_hash: u64, pub card_hash: u64 }

#[must_use]
pub const fn mix64(mut x: u64) -> u64 {
    x = (x ^ x.wrapping_shr(30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ x.wrapping_shr(27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ x.wrapping_shr(31)
}

impl WeightEpochDigest {
    #[must_use]
    pub const fn published(epoch: u64) -> Self {
        let w = mix64(epoch);
        Self { epoch, weights_hash: w, card_hash: mix64(w) }
    }
    /// Oracle coupling: hash and card must come from the same publication.
    #[must_use]
    pub const fn well_formed(&self) -> bool {
        self.weights_hash == mix64(self.epoch) && self.card_hash == mix64(self.weights_hash)
    }
}
```

**Cargo wiring.** Loom is a cfg-gated dependency so the kernel crate compiles under the flag, and the cfg is declared to silence `unexpected_cfgs`.

```toml
# crates/kernel/chio-kernel/Cargo.toml (additive)
[target.'cfg(loom)'.dependencies]
loom = "0.7"

[dependencies]
rusqlite = { version = "0.32", features = ["bundled"], optional = true }

[features]
sqlite-dst = ["rusqlite"]

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(loom)'] }

[[test]]
name = "loom_concurrency"
[[test]]
name = "dst_drop_simulation"
```

```sh
RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
  cargo test -p chio-kernel --test loom_concurrency --release -- --test-threads=1
cargo test -p chio-kernel --test dst_drop_simulation
cargo test -p chio-kernel --test dst_drop_simulation --features sqlite-dst
```

**Loom permutation tests.** The trace mutex gives a total order of events that is consistent with real time, which the Wing and Gong search consumes. The trace lock is itself a fence, so the memory-ordering-sensitive double-buffer case asserts directly instead of through the trace.

```rust
// crates/kernel/chio-kernel/tests/loom_concurrency.rs
#![cfg(loom)]
#![forbid(unsafe_code)]

use chio_kernel_core::formal_cutpoint::{op_step, NonceState, NonceTable, OpEvent, OpState, WeightEpochDigest};
use loom::model::Builder;
use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;

fn model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

// ---------- Wing & Gong linearizability search over a recorded history ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call { Publish(u64), Load }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ret { Unit, Epoch(u64) }
#[derive(Clone, Copy, Debug)]
enum Ev { Inv(usize, Call), Res(usize, Ret) }

#[derive(Clone, Copy)]
struct Register(u64);
impl Register {
    fn apply(&mut self, c: Call) -> Ret {
        match c { Call::Publish(e) => { self.0 = e; Ret::Unit } Call::Load => Ret::Epoch(self.0) }
    }
}

struct Trace(Mutex<Vec<Ev>>);
impl Trace {
    fn new() -> Self { Self(Mutex::new(Vec::new())) }
    fn inv(&self, tid: usize, c: Call) { self.0.lock().unwrap().push(Ev::Inv(tid, c)); }
    fn res(&self, tid: usize, r: Ret) { self.0.lock().unwrap().push(Ev::Res(tid, r)); }
    /// (call, ret, invocation position, response position), one tuple per completed op.
    fn history(&self) -> Vec<(Call, Ret, usize, usize)> {
        let evs = self.0.lock().unwrap();
        let mut open: Vec<Option<(Call, usize)>> = vec![None; 4];
        let mut out = Vec::new();
        for (pos, ev) in evs.iter().enumerate() {
            match *ev {
                Ev::Inv(t, c) => open[t] = Some((c, pos)),
                Ev::Res(t, r) => {
                    let (c, inv) = open[t].take().expect("response without invocation");
                    out.push((c, r, inv, pos));
                }
            }
        }
        out
    }
}

fn linearizable(hist: &[(Call, Ret, usize, usize)]) -> bool {
    assert!(hist.len() < 32, "history too long for the bitmask search");
    fn go(hist: &[(Call, Ret, usize, usize)], reg: Register, remaining: u32) -> bool {
        if remaining == 0 { return true; }
        for i in 0..hist.len() {
            if remaining & (1u32 << i) == 0 { continue; }
            let inv_i = hist[i].2;
            let minimal = hist.iter().enumerate()
                .all(|(j, op)| j == i || remaining & (1u32 << j) == 0 || op.3 > inv_i);
            if !minimal { continue; }
            let mut r = reg;
            if r.apply(hist[i].0) == hist[i].1 && go(hist, r, remaining & !(1u32 << i)) { return true; }
        }
        false
    }
    go(hist, Register(0), (1u32 << hist.len()).wrapping_sub(1))
}

// ---------- Target 1: WeightEpoch publication ----------

/// Tempting lock-free optimization. Proposition 2 says it is wrong; loom proves it.
struct DoubleBuffer { slots: [Mutex<WeightEpochDigest>; 2], current: AtomicUsize }
impl DoubleBuffer {
    fn new() -> Self {
        let e0 = WeightEpochDigest::published(0);
        Self { slots: [Mutex::new(e0), Mutex::new(e0)], current: AtomicUsize::new(0) }
    }
    fn publish(&self, e: WeightEpochDigest) {
        let next = self.current.load(Ordering::Relaxed) ^ 1;
        *self.slots[next].lock().unwrap() = e;
        self.current.store(next, Ordering::Release);
    }
    fn load(&self) -> WeightEpochDigest {
        let i = self.current.load(Ordering::Acquire);
        *self.slots[i].lock().unwrap()
    }
}

#[test]
#[should_panic]
fn weight_epoch_double_buffer_admits_early_read() {
    model(|| {
        let cell = Arc::new(DoubleBuffer::new());
        let w = { let c = Arc::clone(&cell); thread::spawn(move || {
            c.publish(WeightEpochDigest::published(1));
            c.publish(WeightEpochDigest::published(2));
        }) };
        let a = cell.load();
        let b = cell.load();
        assert!(a.well_formed() && b.well_formed());
        assert!(a.epoch <= b.epoch, "non-monotonic epoch {} then {}", a.epoch, b.epoch);
        w.join().unwrap();
    });
}

/// Faithful model of `ArcSwap<WeightEpoch>`: one Arc published and loaded atomically.
struct ArcSwapModel(RwLock<Arc<WeightEpochDigest>>);
impl ArcSwapModel {
    fn store(&self, e: WeightEpochDigest) { *self.0.write().unwrap() = Arc::new(e); }
    fn load(&self) -> Arc<WeightEpochDigest> { Arc::clone(&self.0.read().unwrap()) }
}

#[test]
fn weight_epoch_arcswap_model_is_linearizable() {
    model(|| {
        let cell = Arc::new(ArcSwapModel(RwLock::new(Arc::new(WeightEpochDigest::published(0)))));
        let trace = Arc::new(Trace::new());
        let w = { let (c, t) = (Arc::clone(&cell), Arc::clone(&trace)); thread::spawn(move || {
            for e in [1u64, 2] {
                t.inv(0, Call::Publish(e));
                c.store(WeightEpochDigest::published(e));
                t.res(0, Ret::Unit);
            }
        }) };
        for _ in 0..2 {
            trace.inv(1, Call::Load);
            let e = cell.load();          // bind once: hash, card, and weights share this Arc
            trace.res(1, Ret::Epoch(e.epoch));
            assert!(e.well_formed(), "torn epoch");
        }
        w.join().unwrap();
        assert!(linearizable(&trace.history()));
    });
}

// ---------- Targets 2 and 4: nonce store + session cancel across cutpoints ----------

struct Session { op: Mutex<(OpState, NonceTable)>, effects: AtomicUsize }

fn dispatcher(s: &Session) -> bool {
    {   // pre-dispatch cutpoint: BeginDispatch and Cancel linearize on this lock
        let mut g = s.op.lock().unwrap();
        let Some(next) = op_step(g.0, OpEvent::BeginDispatch) else { return false };
        assert!(g.1.mark_dispatching(7));
        assert!(!g.1.rollback(7), "rollback after intent must be rejected");
        g.0 = next;
    }
    s.effects.fetch_add(1, Ordering::SeqCst);   // irreversible effect, outside the lock
    let mut g = s.op.lock().unwrap();            // post-dispatch cutpoint
    g.0 = op_step(g.0, OpEvent::EffectDone).expect("Dispatching -> Dispatched");
    assert!(g.1.consume(7));
    g.0 = op_step(g.0, OpEvent::Commit).expect("Dispatched -> Completed");
    true
}

fn canceller(s: &Session) -> bool {
    let mut g = s.op.lock().unwrap();
    match op_step(g.0, OpEvent::Cancel) {
        Some(next) => { assert!(g.1.rollback(7)); g.0 = next; true }
        None => false,
    }
}

#[test]
fn session_cancel_is_exclusive_with_dispatch_across_cutpoints() {
    model(|| {
        let mut t = NonceTable::new();
        assert!(t.reserve(7));
        assert!(!t.reserve(7), "second reserve of a live nonce must fail");
        let s = Arc::new(Session { op: Mutex::new((OpState::Pending, t)), effects: AtomicUsize::new(0) });
        let d = { let s = Arc::clone(&s); thread::spawn(move || dispatcher(&s)) };
        let c = { let s = Arc::clone(&s); thread::spawn(move || canceller(&s)) };
        let (dispatched, cancelled) = (d.join().unwrap(), c.join().unwrap());
        assert!(dispatched ^ cancelled, "exactly one of dispatch and cancel must win");
        let g = s.op.lock().unwrap();
        let effects = s.effects.load(Ordering::SeqCst);
        assert_eq!(effects, usize::from(dispatched));
        let nonce = g.1.state(7).unwrap();
        assert!(!(effects == 1 && nonce == NonceState::Free), "rolled back a dispatched nonce");
        assert_eq!(g.0, if dispatched { OpState::Completed } else { OpState::Cancelled });
    });
}

// ---------- Target 3: BudgetSplit holder refcounts ----------

#[derive(Clone, Copy)]
struct SplitCell { parent_share_bps: u16, total_child_bps: u32, holders: u32 }

struct Split(Mutex<SplitCell>);
impl Split {
    /// `OversubscribedSiblings` and `HolderCountOverflow` guards under one critical section.
    fn admit(&self, share_bps: u16) -> bool {
        let mut g = self.0.lock().unwrap();
        let Some(total) = g.total_child_bps.checked_add(u32::from(share_bps)) else { return false };
        if total > u32::from(g.parent_share_bps) { return false; }
        let Some(h) = g.holders.checked_add(1) else { return false };
        g.total_child_bps = total;
        g.holders = h;
        true
    }
    fn release(&self, share_bps: u16) -> bool {
        let mut g = self.0.lock().unwrap();
        let (Some(h), Some(t)) = (g.holders.checked_sub(1), g.total_child_bps.checked_sub(u32::from(share_bps)))
            else { return false };
        g.holders = h;
        g.total_child_bps = t;
        true
    }
    /// Anti-pattern: precheck in one critical section, insert in another.
    fn admit_toctou(&self, share_bps: u16) -> bool {
        let fits = {
            let g = self.0.lock().unwrap();
            g.total_child_bps.saturating_add(u32::from(share_bps)) <= u32::from(g.parent_share_bps)
        };
        if !fits { return false; }
        let mut g = self.0.lock().unwrap();
        g.total_child_bps = g.total_child_bps.saturating_add(u32::from(share_bps));
        g.holders = g.holders.saturating_add(1);
        true
    }
}

fn fresh_split() -> Arc<Split> {
    Arc::new(Split(Mutex::new(SplitCell { parent_share_bps: 6_000, total_child_bps: 0, holders: 0 })))
}

#[test]
fn budget_split_holders_never_oversubscribe_or_underflow() {
    model(|| {
        let split = fresh_split();
        let admitters: Vec<_> = (0..2).map(|_| { let s = Arc::clone(&split); thread::spawn(move || s.admit(4_000)) }).collect();
        let releaser = { let s = Arc::clone(&split); thread::spawn(move || s.release(4_000)) };
        let admitted = admitters.into_iter().map(|h| h.join().unwrap()).filter(|w| *w).count();
        let released = releaser.join().unwrap();
        let g = split.0.lock().unwrap();
        assert!(g.total_child_bps <= u32::from(g.parent_share_bps), "OversubscribedSiblings escaped");
        let expected = u64::try_from(admitted).unwrap().checked_sub(u64::from(released)).expect("release before admit");
        assert_eq!(u64::from(g.holders), expected);
    });
}

#[test]
#[should_panic]
fn budget_split_toctou_oversubscribes() {
    model(|| {
        let split = fresh_split();
        let hs: Vec<_> = (0..2).map(|_| { let s = Arc::clone(&split); thread::spawn(move || s.admit_toctou(4_000)) }).collect();
        for h in hs { h.join().unwrap(); }
        let g = split.0.lock().unwrap();
        assert!(g.total_child_bps <= u32::from(g.parent_share_bps));
    });
}
```

**Deterministic crash and Drop simulation.** The episode lattice is enumerated exhaustively rather than sampled, which is stronger than a seeded walk and needs no seed. Each transaction is all-or-nothing, and a crash discards the uncommitted suffix. The same episodes run against SQLite in WAL mode behind the `sqlite-dst` feature, where a crash is modeled as dropping the connection with the transaction open. That exercises SQLite's rollback of an open transaction. It does not model lying fsync or torn pages.

```rust
// crates/kernel/chio-kernel/tests/dst_drop_simulation.rs
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use chio_kernel_core::formal_aeneas::{ledger_apply, ReservationLedger};
use chio_kernel_core::formal_cutpoint::{apply_recovery, recovery_ledger_op, resolve_recovery, NonceState, RecoveryFacts, K3};

const AMOUNT: u64 = 1;

trait Journal {
    fn begin(&mut self);
    fn put(&mut self, key: &str, val: u64);
    fn commit(&mut self);
    /// Process death: uncommitted writes vanish, committed writes survive.
    fn crash(&mut self);
    fn get(&self, key: &str) -> Option<u64>;
}

#[derive(Default)]
struct MemJournal { durable: BTreeMap<String, u64>, pending: Option<BTreeMap<String, u64>> }

impl Journal for MemJournal {
    fn begin(&mut self) { assert!(self.pending.is_none(), "nested txn"); self.pending = Some(BTreeMap::new()); }
    fn put(&mut self, k: &str, v: u64) { self.pending.as_mut().expect("put outside txn").insert(k.to_owned(), v); }
    fn commit(&mut self) { let p = self.pending.take().expect("commit outside txn"); self.durable.extend(p); }
    fn crash(&mut self) { self.pending = None; }
    fn get(&self, k: &str) -> Option<u64> { self.durable.get(k).copied() }
}

#[cfg(feature = "sqlite-dst")]
mod sqlite {
    use super::Journal;
    use rusqlite::{params, Connection};
    pub struct SqliteJournal { path: std::path::PathBuf, conn: Option<Connection> }
    impl SqliteJournal {
        pub fn open(path: std::path::PathBuf) -> Self {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; \
                 CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v INTEGER NOT NULL);",
            ).unwrap();
            Self { path, conn: Some(conn) }
        }
        fn c(&self) -> &Connection { self.conn.as_ref().expect("connection open") }
    }
    impl Journal for SqliteJournal {
        fn begin(&mut self) { self.c().execute_batch("BEGIN IMMEDIATE").unwrap(); }
        fn put(&mut self, k: &str, v: u64) {
            self.c().execute("INSERT INTO kv(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, i64::try_from(v).unwrap()]).unwrap();
        }
        fn commit(&mut self) { self.c().execute_batch("COMMIT").unwrap(); }
        fn crash(&mut self) {
            drop(self.conn.take());                       // open txn dies with the process
            self.conn = Some(Connection::open(&self.path).unwrap());
        }
        fn get(&self, k: &str) -> Option<u64> {
            self.c().query_row("SELECT v FROM kv WHERE k = ?1", params![k], |r| r.get::<_, i64>(0))
                .ok().map(|v| u64::try_from(v).unwrap())
        }
    }
}

fn enc(s: NonceState) -> u64 {
    match s { NonceState::Free => 0, NonceState::Reserved => 1, NonceState::Dispatching => 2, NonceState::Consumed => 3 }
}
fn dec(v: Option<u64>) -> NonceState {
    match v { Some(1) => NonceState::Reserved, Some(2) => NonceState::Dispatching, Some(3) => NonceState::Consumed, _ => NonceState::Free }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step { Reserve, Intent, Effect, Commit }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash { Before(Step), Mid(Step), After(Step) }
#[derive(Clone, Copy, Debug)]
struct Episode { crash: Option<Crash>, cancel_pre_dispatch: bool, with_intent: bool }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome { Completed, Cancelled, Recovered(K3) }

const STEPS: [Step; 4] = [Step::Reserve, Step::Intent, Step::Effect, Step::Commit];

struct World<J: Journal> { j: J, ledger: Option<ReservationLedger>, sink: u32, hold: bool }

impl<J: Journal> World<J> {
    fn new(j: J) -> Self {
        let ledger = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
        Self { j, ledger: Some(ledger), sink: 0, hold: false }
    }
    fn nonce(&self) -> NonceState { dec(self.j.get("nonce")) }
    fn take_ledger(&mut self) -> ReservationLedger { self.ledger.take().expect("ledger present") }
    fn ledger_op(&mut self, op: u8) { let (l, _) = ledger_apply(self.take_ledger(), op, AMOUNT); self.ledger = Some(l); }
    fn put_ledger(&mut self) {
        let l = self.ledger.as_ref().expect("ledger present");
        let fields = [("reserved", l.reserved), ("committed", l.committed), ("released", l.released), ("retained", l.retained)];
        for (k, v) in fields { self.j.put(k, v); }
    }
    fn durable_ledger(&self) -> ReservationLedger {
        ReservationLedger {
            reserved: self.j.get("reserved").unwrap_or(0), committed: self.j.get("committed").unwrap_or(0),
            released: self.j.get("released").unwrap_or(0), retained: self.j.get("retained").unwrap_or(0),
        }
    }

    fn perform(&mut self, step: Step, ep: Episode) {
        let mid = ep.crash == Some(Crash::Mid(step));
        match step {
            Step::Reserve => {
                assert_eq!(self.nonce(), NonceState::Free, "reserve requires a free nonce");
                self.ledger_op(0);
                self.j.begin();
                self.j.put("nonce", enc(NonceState::Reserved));
                if mid { return self.j.crash(); }
                self.put_ledger();
                self.j.commit();
            }
            Step::Intent => if ep.with_intent {
                self.j.begin();
                self.j.put("nonce", enc(NonceState::Dispatching));
                if mid { return self.j.crash(); }
                self.j.commit();
            },
            Step::Effect => self.sink = self.sink.checked_add(1).expect("sink overflow"),
            Step::Commit => {
                self.ledger_op(1);
                self.j.begin();
                self.j.put("nonce", enc(NonceState::Consumed));
                if mid { return self.j.crash(); }
                self.j.put("receipt", 1);
                self.put_ledger();
                self.j.commit();
            }
        }
    }

    fn recover(&mut self) -> Outcome {
        let facts = RecoveryFacts { nonce: self.nonce(), receipt_present: self.j.get("receipt") == Some(1) };
        let v = resolve_recovery(facts);
        assert_ne!(recovery_ledger_op(v), 0, "recovery must never re-reserve");
        let (l, _) = apply_recovery(self.durable_ledger(), v, AMOUNT);
        self.ledger = Some(l);
        self.j.begin();
        match v {
            K3::Pos => { self.j.put("nonce", enc(NonceState::Consumed)); self.j.put("receipt", 1); }
            K3::Neg => self.j.put("nonce", enc(NonceState::Free)),
            K3::Bot => { self.hold = true; self.j.put("hold", 1); }
        }
        self.put_ledger();
        self.j.commit();
        Outcome::Recovered(v)
    }

    fn run(&mut self, ep: Episode) -> Outcome {
        for step in STEPS {
            if ep.crash == Some(Crash::Before(step)) { self.j.crash(); return self.recover(); }
            if step == Step::Intent && ep.cancel_pre_dispatch {
                self.ledger_op(2);
                self.j.begin();
                self.j.put("nonce", enc(NonceState::Free));
                self.put_ledger();
                self.j.commit();
                return Outcome::Cancelled;
            }
            self.perform(step, ep);
            if matches!(ep.crash, Some(Crash::Mid(s) | Crash::After(s)) if s == step) { self.j.crash(); return self.recover(); }
        }
        Outcome::Completed
    }
}

fn check_invariants<J: Journal>(w: &World<J>, ep: Episode) {
    assert!(w.sink <= 1, "NoDoubleDispatch violated: {ep:?}");
    if w.sink == 1 {
        let committed = w.nonce() == NonceState::Consumed && w.j.get("receipt") == Some(1);
        assert!(committed || w.hold, "NoLostDispatch violated: {ep:?}");
    }
}

fn episode<J: Journal>(mut w: World<J>, ep: Episode) -> World<J> {
    let out = w.run(ep);
    if out == Outcome::Recovered(K3::Neg) {
        // A Neg verdict re-arms the nonce. The retry is fault-free and must be the first dispatch.
        let retry = Episode { crash: None, cancel_pre_dispatch: false, with_intent: ep.with_intent };
        assert_eq!(w.run(retry), Outcome::Completed);
    }
    check_invariants(&w, ep);
    w
}

fn all_episodes(with_intent: bool) -> Vec<Episode> {
    let mut crashes = vec![None];
    for s in STEPS {
        crashes.push(Some(Crash::Before(s)));
        crashes.push(Some(Crash::After(s)));
        if s != Step::Effect { crashes.push(Some(Crash::Mid(s))); }
    }
    crashes.into_iter()
        .flat_map(|crash| [false, true].map(|cancel| Episode { crash, cancel_pre_dispatch: cancel, with_intent }))
        .collect()
}

#[test]
fn every_cutpoint_crash_is_recovered_at_most_once_without_loss() {
    for ep in all_episodes(true) { episode(World::new(MemJournal::default()), ep); }
}

#[test]
fn without_durable_intent_a_post_effect_crash_double_dispatches() {
    let ep = Episode { crash: Some(Crash::After(Step::Effect)), cancel_pre_dispatch: false, with_intent: false };
    let r = catch_unwind(AssertUnwindSafe(|| episode(World::new(MemJournal::default()), ep)));
    assert!(r.is_err(), "oracle lost its teeth: the known-bad protocol passed");
}

/// RAII compensation. Drop frees a `Reserved` nonce and leaves `Dispatching` alone.
struct OpGuard<'a, J: Journal>(&'a mut World<J>);
impl<J: Journal> Drop for OpGuard<'_, J> {
    fn drop(&mut self) {
        self.0.j.crash();                                  // abandon any in-flight transaction
        if self.0.nonce() == NonceState::Reserved {        // pre-dispatch cutpoint not yet crossed
            self.0.j.begin();
            self.0.j.put("nonce", enc(NonceState::Free));
            self.0.j.commit();
        }
    }
}

#[test]
fn drop_during_unwind_rolls_back_only_before_the_dispatch_cutpoint() {
    let ep = Episode { crash: None, cancel_pre_dispatch: false, with_intent: true };
    for (steps, expect) in [(1usize, NonceState::Free), (2, NonceState::Dispatching)] {
        let mut w = World::new(MemJournal::default());
        let r = catch_unwind(AssertUnwindSafe(|| {
            let g = OpGuard(&mut w);
            for s in STEPS.iter().take(steps) { g.0.perform(*s, ep); }
            panic!("injected fault after {steps} steps");
        }));
        assert!(r.is_err());
        assert_eq!(w.nonce(), expect);
    }
}

#[cfg(feature = "sqlite-dst")]
#[test]
fn sqlite_wal_episodes_match_the_memory_journal() {
    let dir = std::env::temp_dir().join(format!("chio-dst-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, ep) in all_episodes(true).into_iter().enumerate() {
        let s = episode(World::new(sqlite::SqliteJournal::open(dir.join(format!("ep{i}.sqlite")))), ep);
        let m = episode(World::new(MemJournal::default()), ep);
        assert_eq!((s.nonce(), s.hold, s.sink), (m.nonce(), m.hold, m.sink), "divergence in {ep:?}");
    }
}
```

## Mechanized specifications

**Lean 4 with the Aeneas refinement.** The Rust `resolve_recovery` has no panic paths, so Aeneas emits a total function in the `Result` monad. The theorem `resolve_recovery_refines` pins the generated shape to the abstract `resolveRecovery`, and `no_lost_dispatch` is Theorem 4's safety half under the protocol invariant that the intent record precedes the effect.

```lean
-- formal/lean4/Chio/Cutpoint.lean
import Aeneas
open Aeneas.Std

namespace Chio.Cutpoint

inductive NonceState | free | reserved | dispatching | consumed
  deriving DecidableEq, Repr

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

def resolveRecovery (n : NonceState) (r : Bool) : K3 :=
  match n, r with
  | .consumed, _      => .pos
  | _, true           => .pos
  | .dispatching, false => .bot
  | .reserved, false  => .neg
  | .free, false      => .neg

def ledgerOp : K3 → UInt8
  | .pos => 1 | .neg => 2 | .bot => 3

/-- Ghost-extended facts: `sink` is the external effect, invisible to recovery. -/
structure Facts where
  nonce : NonceState
  receiptPresent : Bool
  sink : Bool

/-- Protocol invariant P1: the effect happens only after the durable intent. -/
def IntentBeforeEffect (f : Facts) : Prop :=
  f.sink = true → f.nonce = .dispatching ∨ f.nonce = .consumed

theorem no_lost_dispatch (f : Facts) (h : IntentBeforeEffect f) (hs : f.sink = true) :
    resolveRecovery f.nonce f.receiptPresent ≠ .neg := by
  rcases h hs with hn | hn <;> rw [hn] <;> cases f.receiptPresent <;> decide

theorem receipt_authoritative (n : NonceState) : resolveRecovery n true = .pos := by
  cases n <;> rfl

theorem reserved_without_receipt_rolls_back : resolveRecovery .reserved false = .neg := rfl

/-- Recovery never emits op 0: it cannot reserve, hence cannot dispatch. -/
theorem ledgerOp_never_reserve (v : K3) : ledgerOp v ≠ 0 := by
  cases v <;> decide

/-- Shape of the Aeneas translation of `formal_cutpoint::resolve_recovery`. -/
namespace Translated
structure RecoveryFacts where
  nonce : NonceState
  receipt_present : Bool
def resolve_recovery (f : RecoveryFacts) : Result K3 :=
  match f.nonce, f.receipt_present with
  | .consumed, _        => ok .pos
  | _, true             => ok .pos
  | .dispatching, false => ok .bot
  | .reserved, false    => ok .neg
  | .free, false        => ok .neg
end Translated

theorem resolve_recovery_refines (f : Translated.RecoveryFacts) :
    Translated.resolve_recovery f = ok (resolveRecovery f.nonce f.receipt_present) := by
  rcases f with ⟨n, r⟩
  cases n <;> cases r <;> rfl

end Chio.Cutpoint
```

**Apalache TLA+.** Each transaction is one atomic action, so a mid-transaction crash coincides with the crash before it. The atomicity assumption is exactly what the SQLite episodes discharge. Recovery with a negative verdict returns to `start`, which lets the model attempt the retry that would expose a double dispatch.

```tla
------------------------------ MODULE ChioCutpoint ------------------------------
EXTENDS Integers

CONSTANT
  \* @type: Bool;
  WithIntent

VARIABLES
  \* @type: Str;
  dNonce,
  \* @type: Bool;
  dReceipt,
  \* @type: Bool;
  dHold,
  \* @type: Str;
  pc,
  \* @type: Int;
  sink

CInit == WithIntent = TRUE
CInitNoIntent == WithIntent = FALSE

Init == dNonce = "Free" /\ dReceipt = FALSE /\ dHold = FALSE /\ pc = "start" /\ sink = 0

Reserve == pc = "start" /\ dNonce = "Free"
  /\ dNonce' = "Reserved" /\ pc' = "reserved"
  /\ UNCHANGED <<dReceipt, dHold, sink>>

Cancel == pc = "reserved"
  /\ dNonce' = "Free" /\ pc' = "done"
  /\ UNCHANGED <<dReceipt, dHold, sink>>

Intent == pc = "reserved"
  /\ dNonce' = IF WithIntent THEN "Dispatching" ELSE dNonce
  /\ pc' = "intent"
  /\ UNCHANGED <<dReceipt, dHold, sink>>

Effect == pc = "intent"
  /\ sink' = sink + 1 /\ pc' = "effected"
  /\ UNCHANGED <<dNonce, dReceipt, dHold>>

Commit == pc = "effected"
  /\ dNonce' = "Consumed" /\ dReceipt' = TRUE /\ pc' = "done"
  /\ UNCHANGED <<dHold, sink>>

Crash == pc \in {"reserved", "intent", "effected"}
  /\ pc' = "crashed"
  /\ UNCHANGED <<dNonce, dReceipt, dHold, sink>>

Resolve == IF dNonce = "Consumed" \/ dReceipt THEN "pos"
           ELSE IF dNonce = "Dispatching" THEN "bot" ELSE "neg"

Recover == pc = "crashed"
  /\ dNonce' = IF Resolve = "neg" THEN "Free"
               ELSE IF Resolve = "pos" THEN "Consumed" ELSE dNonce
  /\ dHold' = (Resolve = "bot")
  /\ pc' = IF Resolve = "neg" THEN "start" ELSE "done"
  /\ UNCHANGED <<dReceipt, sink>>

Next == Reserve \/ Cancel \/ Intent \/ Effect \/ Commit \/ Crash \/ Recover

NoDoubleDispatch == sink <= 1
NoLostDispatch == (sink = 1 /\ pc = "done") => ((dNonce = "Consumed" /\ dReceipt) \/ dHold)
=============================================================================
```

```sh
apalache-mc check --cinit=CInit --inv=NoDoubleDispatch,NoLostDispatch --length=16 ChioCutpoint.tla
# Expected counterexample, documenting why the intent transaction is mandatory:
apalache-mc check --cinit=CInitNoIntent --inv=NoDoubleDispatch --length=16 ChioCutpoint.tla
```

**Kani harnesses.** The learned cancel or dispatch choice is `kani::any()` nondeterminism, exactly as the Envelope Preservation and Verification Transfer Theorem prescribes. The intent-before-effect precondition is assumed here because the loom and DST layers establish it.

```rust
// appended to crates/kernel/chio-kernel-core/src/formal_cutpoint.rs
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn recovery_never_frees_a_dispatched_nonce() {
        let sink: bool = kani::any();
        let nonce: NonceState = kani::any();
        let receipt: bool = kani::any();
        kani::assume(!sink || matches!(nonce, NonceState::Dispatching | NonceState::Consumed));
        let v = resolve_recovery(RecoveryFacts { nonce, receipt_present: receipt });
        if sink { assert!(v != K3::Neg); }
        if receipt { assert!(v == K3::Pos); }
        assert!(recovery_ledger_op(v) != 0);
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn nonce_table_consumed_is_absorbing_and_rollback_is_pre_dispatch_only() {
        let n: usize = kani::any();
        kani::assume(n < MAX_NONCE_SLOTS);
        let mut t = NonceTable::new();
        assert!(t.reserve(n));
        assert!(!t.reserve(n));
        for _ in 0..8 {
            let op: u8 = kani::any();
            kani::assume(op < 4);
            let before = t.state(n).unwrap();
            let ok = match op { 0 => t.reserve(n), 1 => t.mark_dispatching(n), 2 => t.consume(n), _ => t.rollback(n) };
            let after = t.state(n).unwrap();
            if before == NonceState::Consumed { assert!(after == NonceState::Consumed); }
            if op == 3 && ok { assert!(before == NonceState::Reserved && after == NonceState::Free); }
            if !ok { assert!(before == after); }
        }
    }

    #[kani::proof]
    fn op_step_pending_is_the_only_cancel_window() {
        let s: OpState = kani::any_where(|_| true);
        let dispatched = op_step(s, OpEvent::BeginDispatch).is_some();
        let cancelled = op_step(s, OpEvent::Cancel).is_some();
        assert!(dispatched == (s == OpState::Pending));
        assert!(cancelled == (s == OpState::Pending));
    }
}
```

The last harness needs `#[cfg_attr(kani, derive(kani::Arbitrary))]` on `OpState`, added alongside the other derives. The manifest entry ties the five artifacts to one property identifier so a future signature drift fails the pin rather than silently weakening a proof.

```toml
# formal/proof-manifest.toml (additive)
[[proof]]
id = "wave9.cutpoint.recovery"
rust = "crates/kernel/chio-kernel-core/src/formal_cutpoint.rs::resolve_recovery"
lean = "formal/lean4/Chio/Cutpoint.lean::Chio.Cutpoint.no_lost_dispatch"
aeneas = "formal/lean4/Chio/Cutpoint.lean::Chio.Cutpoint.resolve_recovery_refines"
kani = ["recovery_never_frees_a_dispatched_nonce", "nonce_table_consumed_is_absorbing_and_rollback_is_pre_dispatch_only"]
tla = "formal/tla/ChioCutpoint.tla::NoDoubleDispatch,NoLostDispatch"
loom = "crates/kernel/chio-kernel/tests/loom_concurrency.rs::session_cancel_is_exclusive_with_dispatch_across_cutpoints"
dst = "crates/kernel/chio-kernel/tests/dst_drop_simulation.rs::every_cutpoint_crash_is_recovered_at_most_once_without_loss"
```

**Recap.** The pass adds one `no_std` module with the nonce table, the operation transition function, the `K3` recovery resolver, and the epoch digest, and it leaves every pinned signature in `formal_aeneas.rs` and `budget_split.rs` untouched. The loom file proves the double-buffer epoch publication is non-linearizable and the single-`Arc` model is, shows cancel and dispatch are exclusive at the pre-dispatch cutpoint, and shows the oversubscription check must share a critical section with the insert. The DST file enumerates every crash and Drop point, runs the same episodes on SQLite WAL when the feature is enabled, and demonstrates that the durable intent record is what prevents a double dispatch. Lean proves recovery never frees a dispatched nonce, Apalache exhausts the state space in both configurations, and Kani closes the per-slot nonce transitions and the cancel window. Three items remain open for Wave 10: reconciliation of a `Bot` hold against the sink's idempotency key, a loom model of `GuardPipeline`'s sticky `PendingApproval` under concurrent revalidation, and running the SQLite episodes under a fault-injecting VFS to cover fsync and torn-page behavior that the connection-drop model does not.

---

# Verbatim Treatise - `wave9_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_9`

I'll lay out the Pass 9 edge design as one `no_std` core crate plus thin protocol adapters, then the hybrid floor, federated offline verification, attestation binding, and the Lean/Kani/Apalache artifacts that discharge it.

## 1. The protocol edge as a decision-model instance

The three edges share one decision tuple. Call it $\mathcal{D}_{\text{edge}}$, an instance of the Wave 1 law at layer L1.

- **Input $\mathcal{X}$**: a decoded wire view, never raw bytes. Decoding runs in the std adapters. The core crate receives borrowed views and performs only exact work.
- **Exact computation $C(x) \in \mathbb{K}_3^{5}$**: five facts. Time window via the pinned `classify_time_window_code`. Budget via the pinned `budget_precheck`. Receipt floor via hybrid verification. Trust root via offline chain resolution. Attestation via report-data binding. Each fact is `+`, `-`, or `⊥`.
- **Feasible envelope $\mathcal{C}(C(x))$**: a down-closed subset of `{Allow, PendingApproval, Deny}` under the order Deny ⊑ PendingApproval ⊑ Allow. `Deny` is always a member. It is the fallback $\bot_x$.
- **Predictor $P$**: the Tier-0 `FixedQ16_16` micro-model proposes an action from four segment features and the shadow prices. It never touches a fact.
- **Projection $\Pi$**: constant time. If the proposal is in the envelope it passes, otherwise the fallback is returned.
- **Witness $W$**: a receipt whose digest commits to the lifted request, the five facts, the shielded action, and the signer root. The receipt is signed under the hybrid floor.

The Copley segment mapping is the only design choice in the lift. It must be stable, because the Tier-1 `UltraBERT` thresholds were trained per segment role.

| Segment | Predicates | MCP `tools/call` | A2A `message/send` | Envoy `CheckRequest` |
|---|---|---|---|---|
| CommandLine | 345 | canonical `arguments` | message parts | path, query, body digest |
| Image | 97 | tool name | skill id | method and authority |
| OriginalFileName | 57 | server URI | agent card URL | route cluster |
| ParentImage | 38 | session principal | caller agent id | source SPIFFE principal |

The rationale is role fidelity. `Image` is "what executes", `ParentImage` is "who caused it", `OriginalFileName` is "where it claims to come from", and `CommandLine` is "with what". The predicate counts sum to the pinned total and the crate asserts this at compile time.

Receipt metadata does not get a new reserved key. The pinned array has a fixed length, so the edge writes its block under the existing `receipt_context` key as a nested `protocol_edge_v9` object. Zero changes land in the reserved-key array or its tests.

## 2. Lifting, shielding, and the hybrid floor in Rust

The core crate is `crates/edges/chio-protocol-edge-core`. It forbids unsafe code, denies unchecked arithmetic outside tests, and allocates nothing. All buffers are fixed-capacity.

```rust
//! crates/edges/chio-protocol-edge-core/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

// ---------------- Kleene K3 and the Copley segment roles ----------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    #[must_use]
    pub const fn and(self, rhs: K3) -> K3 {
        match (self, rhs) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Pos, K3::Pos) => K3::Pos,
            _ => K3::Bot,
        }
    }
    #[must_use]
    pub const fn from_bool(b: bool) -> K3 { if b { K3::Pos } else { K3::Neg } }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Segment { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

pub const SEGMENT_PREDICATE_COUNTS: [u16; 4] = [345, 97, 57, 38];
pub const TOTAL_ATOMIC_PREDICATES: u16 = 537;
const _: () = assert!(345u16 + 97 + 57 + 38 == TOTAL_ATOMIC_PREDICATES);

pub const MAX_COMMAND_LINE_BYTES: usize = 4_096;
pub const MAX_IDENTITY_BYTES: usize = 512;
pub const MAX_CANONICAL_ARGS: usize = 64;
pub const MAX_A2A_PARTS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiftError {
    SegmentCapacityExceeded(Segment),
    LengthOverflow,
    TooManyArgs,
    TooManyParts,
    ArgsNotCanonical,
    EmptyIdentity(Segment),
    InvalidWindow,
}

// ---------------- Bounded framing writer ----------------

pub struct BoundedBuf<const N: usize> { bytes: [u8; N], len: usize }

impl<const N: usize> Default for BoundedBuf<N> { fn default() -> Self { Self::new() } }

impl<const N: usize> BoundedBuf<N> {
    pub const fn new() -> Self { Self { bytes: [0u8; N], len: 0 } }
    pub fn as_slice(&self) -> &[u8] { &self.bytes[..self.len] }
    pub const fn len(&self) -> usize { self.len }
    pub const fn is_empty(&self) -> bool { self.len == 0 }

    pub fn push(&mut self, src: &[u8], seg: Segment) -> Result<(), LiftError> {
        let end = self.len.checked_add(src.len()).ok_or(LiftError::LengthOverflow)?;
        if end > N { return Err(LiftError::SegmentCapacityExceeded(seg)); }
        self.bytes[self.len..end].copy_from_slice(src);
        self.len = end;
        Ok(())
    }

    /// tag(1) || len(4, big-endian) || bytes. Framing makes the encoding prefix-free.
    pub fn push_framed(&mut self, tag: u8, src: &[u8], seg: Segment) -> Result<(), LiftError> {
        let n = u32::try_from(src.len()).map_err(|_| LiftError::LengthOverflow)?;
        self.push(&[tag], seg)?;
        self.push(&n.to_be_bytes(), seg)?;
        self.push(src, seg)
    }
}

pub struct CopleySegments {
    pub command_line: BoundedBuf<MAX_COMMAND_LINE_BYTES>,
    pub image: BoundedBuf<MAX_IDENTITY_BYTES>,
    pub original_file_name: BoundedBuf<MAX_IDENTITY_BYTES>,
    pub parent_image: BoundedBuf<MAX_IDENTITY_BYTES>,
}

impl CopleySegments {
    pub const fn new() -> Self {
        Self {
            command_line: BoundedBuf::new(),
            image: BoundedBuf::new(),
            original_file_name: BoundedBuf::new(),
            parent_image: BoundedBuf::new(),
        }
    }
}

// ---------------- Canonical argument encoding ----------------

#[derive(Clone, Copy)]
pub enum ArgValue<'w> { Null, Bool(bool), Int(i64), Str(&'w str), Opaque(&'w [u8; 32]) }

#[derive(Clone, Copy)]
pub struct ArgView<'w> { pub key: &'w str, pub value: ArgValue<'w> }

const TAG_KEY: u8 = 0x10;
const TAG_NULL: u8 = 0x20;
const TAG_BOOL: u8 = 0x21;
const TAG_INT: u8 = 0x22;
const TAG_STR: u8 = 0x23;
const TAG_OPAQUE: u8 = 0x24;
const TAG_DATA: u8 = 0x30;
const TAG_FILE: u8 = 0x31;

/// Sorting is the host's job. Verifying strict key order is O(n) exact work here.
pub fn encode_canonical_args<const N: usize>(
    args: &[ArgView<'_>],
    out: &mut BoundedBuf<N>,
) -> Result<(), LiftError> {
    if args.len() > MAX_CANONICAL_ARGS { return Err(LiftError::TooManyArgs); }
    let seg = Segment::CommandLine;
    for pair in args.windows(2) {
        if pair[0].key.as_bytes() >= pair[1].key.as_bytes() {
            return Err(LiftError::ArgsNotCanonical);
        }
    }
    for a in args {
        out.push_framed(TAG_KEY, a.key.as_bytes(), seg)?;
        match a.value {
            ArgValue::Null => out.push_framed(TAG_NULL, &[], seg)?,
            ArgValue::Bool(b) => out.push_framed(TAG_BOOL, &[u8::from(b)], seg)?,
            ArgValue::Int(i) => out.push_framed(TAG_INT, &i.to_be_bytes(), seg)?,
            ArgValue::Str(s) => out.push_framed(TAG_STR, s.as_bytes(), seg)?,
            ArgValue::Opaque(h) => out.push_framed(TAG_OPAQUE, h, seg)?,
        }
    }
    Ok(())
}

// ---------------- PortableToolCallRequest and the lift ----------------

pub trait Digest32 { fn digest32(&self, parts: &[&[u8]]) -> [u8; 32]; }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeProtocol { Mcp = 1, A2a = 2, EnvoyExtAuthz = 3 }

#[derive(Clone, Copy)]
pub struct LiftMeta { pub issued_at: u64, pub expires_at: u64, pub invocation_cost: u64, pub unit_cost: u64 }

pub struct PortableToolCallRequest {
    pub protocol: EdgeProtocol,
    pub segments: CopleySegments,
    pub digest: [u8; 32],
    pub meta: LiftMeta,
}

pub trait ProtocolLift<'w> {
    const PROTOCOL: EdgeProtocol;
    type Wire;
    fn fill(wire: &Self::Wire, out: &mut CopleySegments) -> Result<(), LiftError>;
}

fn len_be(n: usize) -> Result<[u8; 4], LiftError> {
    u32::try_from(n).map(u32::to_be_bytes).map_err(|_| LiftError::LengthOverflow)
}

const DOMAIN_REQUEST: &[u8] = b"chio.portable-tool-call.v9";

pub fn lift<'w, L: ProtocolLift<'w>, D: Digest32>(
    wire: &L::Wire,
    meta: LiftMeta,
    h: &D,
) -> Result<PortableToolCallRequest, LiftError> {
    if meta.expires_at <= meta.issued_at { return Err(LiftError::InvalidWindow); }
    let mut segments = CopleySegments::new();
    L::fill(wire, &mut segments)?;
    if segments.image.is_empty() { return Err(LiftError::EmptyIdentity(Segment::Image)); }
    if segments.parent_image.is_empty() { return Err(LiftError::EmptyIdentity(Segment::ParentImage)); }
    let lens = [
        len_be(segments.command_line.len())?,
        len_be(segments.image.len())?,
        len_be(segments.original_file_name.len())?,
        len_be(segments.parent_image.len())?,
    ];
    let proto = [L::PROTOCOL as u8];
    let parts: [&[u8]; 14] = [
        DOMAIN_REQUEST, &proto,
        &lens[0], segments.command_line.as_slice(),
        &lens[1], segments.image.as_slice(),
        &lens[2], segments.original_file_name.as_slice(),
        &lens[3], segments.parent_image.as_slice(),
        &meta.issued_at.to_be_bytes(), &meta.expires_at.to_be_bytes(),
        &meta.invocation_cost.to_be_bytes(), &meta.unit_cost.to_be_bytes(),
    ];
    let digest = h.digest32(&parts);
    Ok(PortableToolCallRequest { protocol: L::PROTOCOL, segments, digest, meta })
}

// ---------------- The three protocol views ----------------

pub struct McpToolCallView<'w> {
    pub server_uri: &'w str,
    pub tool_name: &'w str,
    pub session_principal: &'w str,
    pub args: &'w [ArgView<'w>],
}
pub struct McpLift;
impl<'w> ProtocolLift<'w> for McpLift {
    const PROTOCOL: EdgeProtocol = EdgeProtocol::Mcp;
    type Wire = McpToolCallView<'w>;
    fn fill(w: &Self::Wire, out: &mut CopleySegments) -> Result<(), LiftError> {
        out.image.push_framed(TAG_STR, w.tool_name.as_bytes(), Segment::Image)?;
        out.original_file_name.push_framed(TAG_STR, w.server_uri.as_bytes(), Segment::OriginalFileName)?;
        out.parent_image.push_framed(TAG_STR, w.session_principal.as_bytes(), Segment::ParentImage)?;
        encode_canonical_args(w.args, &mut out.command_line)
    }
}

pub enum A2aPart<'w> { Text(&'w str), Data(&'w [ArgView<'w>]), File { name: &'w str, sha256: &'w [u8; 32] } }
pub struct A2aMessageView<'w> {
    pub agent_card_url: &'w str,
    pub skill_id: &'w str,
    pub caller_agent_id: &'w str,
    pub parts: &'w [A2aPart<'w>],
}
pub struct A2aLift;
impl<'w> ProtocolLift<'w> for A2aLift {
    const PROTOCOL: EdgeProtocol = EdgeProtocol::A2a;
    type Wire = A2aMessageView<'w>;
    fn fill(w: &Self::Wire, out: &mut CopleySegments) -> Result<(), LiftError> {
        if w.parts.len() > MAX_A2A_PARTS { return Err(LiftError::TooManyParts); }
        out.image.push_framed(TAG_STR, w.skill_id.as_bytes(), Segment::Image)?;
        out.original_file_name.push_framed(TAG_STR, w.agent_card_url.as_bytes(), Segment::OriginalFileName)?;
        out.parent_image.push_framed(TAG_STR, w.caller_agent_id.as_bytes(), Segment::ParentImage)?;
        let seg = Segment::CommandLine;
        for p in w.parts {
            match p {
                A2aPart::Text(t) => out.command_line.push_framed(TAG_STR, t.as_bytes(), seg)?,
                A2aPart::Data(args) => {
                    let count = len_be(args.len())?;
                    out.command_line.push_framed(TAG_DATA, &count, seg)?;
                    encode_canonical_args(args, &mut out.command_line)?;
                }
                A2aPart::File { name, sha256 } => {
                    out.command_line.push_framed(TAG_FILE, name.as_bytes(), seg)?;
                    out.command_line.push_framed(TAG_OPAQUE, *sha256, seg)?;
                }
            }
        }
        Ok(())
    }
}

pub struct ExtAuthzCheckView<'w> {
    pub route_cluster: &'w str,
    pub method: &'w str,
    pub authority: &'w str,
    pub source_principal: &'w str,
    pub path: &'w str,
    pub query: &'w str,
    pub body_sha256: Option<&'w [u8; 32]>,
}
pub struct EnvoyLift;
impl<'w> ProtocolLift<'w> for EnvoyLift {
    const PROTOCOL: EdgeProtocol = EdgeProtocol::EnvoyExtAuthz;
    type Wire = ExtAuthzCheckView<'w>;
    fn fill(w: &Self::Wire, out: &mut CopleySegments) -> Result<(), LiftError> {
        out.image.push_framed(TAG_STR, w.method.as_bytes(), Segment::Image)?;
        out.image.push_framed(TAG_STR, w.authority.as_bytes(), Segment::Image)?;
        out.original_file_name.push_framed(TAG_STR, w.route_cluster.as_bytes(), Segment::OriginalFileName)?;
        out.parent_image.push_framed(TAG_STR, w.source_principal.as_bytes(), Segment::ParentImage)?;
        let seg = Segment::CommandLine;
        out.command_line.push_framed(TAG_STR, w.path.as_bytes(), seg)?;
        out.command_line.push_framed(TAG_STR, w.query.as_bytes(), seg)?;
        match w.body_sha256 {
            Some(d) => out.command_line.push_framed(TAG_OPAQUE, d, seg),
            None => out.command_line.push_framed(TAG_NULL, &[], seg),
        }
    }
}
```

**Facts, envelope, and the shielded action.** The edge does not re-implement kernel arithmetic. It receives the pinned functions as plain function pointers, so the Lean and Aeneas proofs on `formal_core` continue to cover exactly the code that runs.

```rust
#[derive(Clone, Copy)]
pub struct KernelFns {
    pub classify_time_window_code: fn(u64, u64, u64) -> u8,
    pub budget_precheck: fn(u64, u64, u64, u64) -> bool,
    pub receipt_fields_coupled: fn(bool, bool, bool, bool, bool) -> bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EdgeFacts { pub window: K3, pub budget: K3, pub receipt_floor: K3, pub trust_root: K3, pub attestation: K3 }

impl EdgeFacts {
    pub const fn conjunction(&self) -> K3 {
        self.window.and(self.budget).and(self.receipt_floor).and(self.trust_root).and(self.attestation)
    }
}

pub fn exact_window_and_budget(
    k: KernelFns, req: &PortableToolCallRequest, now: u64, remaining_invocations: u64, remaining_units: u64,
) -> (K3, K3) {
    let w = (k.classify_time_window_code)(now, req.meta.issued_at, req.meta.expires_at);
    let b = (k.budget_precheck)(remaining_invocations, remaining_units, req.meta.invocation_cost, req.meta.unit_cost);
    (K3::from_bool(w == 0), K3::from_bool(b))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum EdgeAction { Allow, PendingApproval, Deny }

const BIT_ALLOW: u8 = 0b001;
const BIT_PENDING: u8 = 0b010;
const BIT_DENY: u8 = 0b100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Envelope { mask: u8 }

pub struct ShieldedAction { action: EdgeAction }
impl ShieldedAction { pub const fn action(&self) -> EdgeAction { self.action } }

impl Envelope {
    pub const fn from_facts(f: &EdgeFacts) -> Envelope {
        let mask = match f.conjunction() {
            K3::Pos => BIT_ALLOW | BIT_PENDING | BIT_DENY,
            K3::Bot => BIT_PENDING | BIT_DENY,
            K3::Neg => BIT_DENY,
        };
        Envelope { mask }
    }
    const fn bit(a: EdgeAction) -> u8 {
        match a { EdgeAction::Allow => BIT_ALLOW, EdgeAction::PendingApproval => BIT_PENDING, EdgeAction::Deny => BIT_DENY }
    }
    pub const fn contains(&self, a: EdgeAction) -> bool { self.mask & Self::bit(a) != 0 }
    /// Π: O(1), total, and the only constructor of ShieldedAction.
    pub const fn project(&self, proposed: EdgeAction) -> ShieldedAction {
        if self.contains(proposed) { ShieldedAction { action: proposed } } else { ShieldedAction { action: EdgeAction::Deny } }
    }
}

// ---------------- Tier-1 thresholds and the Tier-0 proposer ----------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Q16_16(pub i32);

impl Q16_16 {
    pub const ZERO: Q16_16 = Q16_16(0);
    pub const ONE: Q16_16 = Q16_16(65_536);
    pub fn add(self, r: Q16_16) -> Option<Q16_16> { self.0.checked_add(r.0).map(Q16_16) }
    pub fn sub(self, r: Q16_16) -> Option<Q16_16> { self.0.checked_sub(r.0).map(Q16_16) }
    pub fn mul(self, r: Q16_16) -> Option<Q16_16> {
        let wide = i64::from(self.0).checked_mul(i64::from(r.0))?;
        let scaled = wide.checked_div(i64::from(Self::ONE.0))?;
        i32::try_from(scaled).ok().map(Q16_16)
    }
}

/// Role-asymmetric thresholds; the constructor enforces tau_neg <= tau_pos.
#[derive(Clone, Copy)]
pub struct RoleThresholds { tau_pos: Q16_16, tau_neg: Q16_16 }
impl RoleThresholds {
    pub const fn new(tau_pos: Q16_16, tau_neg: Q16_16) -> Option<Self> {
        if tau_neg.0 <= tau_pos.0 { Some(Self { tau_pos, tau_neg }) } else { None }
    }
    pub const fn classify(&self, p: Q16_16) -> K3 {
        if p.0 >= self.tau_pos.0 { K3::Pos } else if p.0 <= self.tau_neg.0 { K3::Neg } else { K3::Bot }
    }
}

pub struct Tier0Edge { pub w: [Q16_16; 4], pub bias: Q16_16, pub lambda_latency: Q16_16, pub lambda_budget: Q16_16 }
impl Tier0Edge {
    /// `feat` is the per-segment positive-predicate mass from Tier-1, in [0, 1].
    pub fn propose(&self, feat: &[Q16_16; 4], latency_cost: Q16_16, budget_cost: Q16_16) -> EdgeAction {
        let mut acc = Some(self.bias);
        for (w, f) in self.w.iter().zip(feat.iter()) {
            acc = acc.and_then(|a| w.mul(*f).and_then(|p| a.add(p)));
        }
        acc = acc.and_then(|a| self.lambda_latency.mul(latency_cost).and_then(|p| a.sub(p)));
        acc = acc.and_then(|a| self.lambda_budget.mul(budget_cost).and_then(|p| a.sub(p)));
        match acc { Some(s) if s > Q16_16::ZERO => EdgeAction::Allow, _ => EdgeAction::PendingApproval }
    }
}
```

Overflow in the proposer degrades to `PendingApproval`, never to `Allow`. The proposer is also not allowed to emit `Deny`. Denial is the exact layer's privilege, which keeps the audit question "who denied" answerable from facts alone.

**The hybrid floor.** `KernelCryptoFloor` composes Ed25519 and ML-DSA-65 by concatenation, but both components sign a derived binding that commits to the declared floor and to both public keys. That commitment is what makes the pair non-separable.

| Primitive | Public key bytes | Signature bytes |
|---|---|---|
| Ed25519 | 32 | 64 |
| ML-DSA-65, FIPS 204 | 1952 | 3309 |

```rust
pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA65_PK_LEN: usize = 1_952;
pub const MLDSA65_SIG_LEN: usize = 3_309;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum CryptoFloor { Classical = 1, Hybrid = 2 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackendUnavailable;

pub trait Ed25519Verify {
    fn verify(&self, pk: &[u8; ED25519_PK_LEN], msg: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> Result<bool, BackendUnavailable>;
}
pub trait MlDsa65Verify {
    fn verify(&self, pk: &[u8; MLDSA65_PK_LEN], msg: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> Result<bool, BackendUnavailable>;
}
pub trait Ed25519Sign { fn public_key(&self) -> [u8; ED25519_PK_LEN]; fn sign(&self, msg: &[u8]) -> [u8; ED25519_SIG_LEN]; }
pub trait MlDsa65Sign { fn public_key(&self) -> [u8; MLDSA65_PK_LEN]; fn sign(&self, msg: &[u8]) -> [u8; MLDSA65_SIG_LEN]; }

#[derive(Clone, Copy)]
pub struct HybridPublicKey { pub ed25519: [u8; ED25519_PK_LEN], pub mldsa65: [u8; MLDSA65_PK_LEN] }

#[derive(Clone, Copy)]
pub struct HybridSignature {
    pub floor: CryptoFloor,
    pub ed25519: [u8; ED25519_SIG_LEN],
    pub mldsa65: Option<[u8; MLDSA65_SIG_LEN]>,
}

const ALG_ED25519: u8 = 0x01;
const ALG_MLDSA65: u8 = 0x02;
const DOMAIN_RECEIPT: &[u8] = b"chio.receipt-signature.v9";
const DOMAIN_HYBRID_PK: &[u8] = b"chio.hybrid-pk.v9";

/// Binding = H(domain || alg || floor || H(pk_ed || pk_ml) || receipt_digest).
pub fn binding<D: Digest32>(h: &D, alg: u8, floor: CryptoFloor, pk: &HybridPublicKey, receipt_digest: &[u8; 32]) -> [u8; 32] {
    let pk_commit = h.digest32(&[DOMAIN_HYBRID_PK, &pk.ed25519, &pk.mldsa65]);
    h.digest32(&[DOMAIN_RECEIPT, &[alg, floor as u8], &pk_commit, receipt_digest])
}

pub fn sign_receipt<D: Digest32>(
    h: &D, floor: CryptoFloor, ed: &impl Ed25519Sign, ml: &impl MlDsa65Sign, receipt_digest: &[u8; 32],
) -> (HybridPublicKey, HybridSignature) {
    let pk = HybridPublicKey { ed25519: ed.public_key(), mldsa65: ml.public_key() };
    let ed_sig = ed.sign(&binding(h, ALG_ED25519, floor, &pk, receipt_digest));
    let ml_sig = match floor {
        CryptoFloor::Hybrid => Some(ml.sign(&binding(h, ALG_MLDSA65, floor, &pk, receipt_digest))),
        CryptoFloor::Classical => None,
    };
    (pk, HybridSignature { floor, ed25519: ed_sig, mldsa65: ml_sig })
}

pub struct KernelCryptoFloor<E, M, D> { pub floor: CryptoFloor, pub ed: E, pub ml: M, pub hasher: D }

impl<E: Ed25519Verify, M: MlDsa65Verify, D: Digest32> KernelCryptoFloor<E, M, D> {
    pub fn verify(&self, pk: &HybridPublicKey, receipt_digest: &[u8; 32], sig: &HybridSignature) -> K3 {
        if sig.floor < self.floor { return K3::Neg; }
        let m_ed = binding(&self.hasher, ALG_ED25519, sig.floor, pk, receipt_digest);
        match self.ed.verify(&pk.ed25519, &m_ed, &sig.ed25519) {
            Ok(true) => {}
            Ok(false) => return K3::Neg,
            Err(BackendUnavailable) => return K3::Bot,
        }
        match (sig.floor, sig.mldsa65.as_ref()) {
            (CryptoFloor::Hybrid, None) => K3::Neg,
            (CryptoFloor::Classical, None) => K3::Pos,
            (_, Some(s)) => {
                let m_ml = binding(&self.hasher, ALG_MLDSA65, sig.floor, pk, receipt_digest);
                match self.ml.verify(&pk.mldsa65, &m_ml, s) {
                    Ok(true) => K3::Pos,
                    Ok(false) => K3::Neg,
                    Err(BackendUnavailable) => K3::Bot,
                }
            }
        }
    }
}
```

Three behaviours deserve emphasis. A verifier at the `Hybrid` floor refuses any signature declaring `Classical` before touching a key. A signature declaring `Hybrid` without an ML-DSA component is malformed and fails closed. A verifier whose post-quantum backend is absent returns `⊥`, which removes `Allow` from the envelope while leaving `PendingApproval` reachable. That is the correct outcome for a constrained verifier that can neither confirm nor refute.

**Federated offline verification.** A portable bundle carries the receipt digest, the signer's root id, the hybrid signature, and an endorsement chain. Verification needs only the local root set.

```rust
pub const MAX_TRUST_ROOTS: usize = 64;
pub const MAX_ENDORSEMENT_DEPTH: usize = 4;

#[derive(Clone, Copy)]
pub struct TrustRoot { pub root_id: [u8; 16], pub keys: HybridPublicKey, pub floor: CryptoFloor, pub not_before: u64, pub not_after: u64 }

pub struct Endorsement { pub issuer_root_id: [u8; 16], pub subject: TrustRoot, pub signature: HybridSignature }

pub struct PortableReceiptBundle<'a> {
    pub receipt_digest: [u8; 32],
    pub coupling: [bool; 5],
    pub signer_root_id: [u8; 16],
    pub signature: HybridSignature,
    pub endorsements: &'a [Endorsement],
}

const DOMAIN_ROOT: &[u8] = b"chio.trust-root.v9";

pub fn root_digest<D: Digest32>(h: &D, r: &TrustRoot) -> [u8; 32] {
    h.digest32(&[DOMAIN_ROOT, &r.root_id, &r.keys.ed25519, &r.keys.mldsa65, &[r.floor as u8],
                 &r.not_before.to_be_bytes(), &r.not_after.to_be_bytes()])
}

pub struct OfflineVerifier<'s, E, M, D> {
    pub local_roots: &'s [TrustRoot],
    pub floor: KernelCryptoFloor<E, M, D>,
    pub kernel: KernelFns,
}

impl<'s, E: Ed25519Verify, M: MlDsa65Verify, D: Digest32> OfflineVerifier<'s, E, M, D> {
    fn find_local(&self, id: &[u8; 16]) -> Option<&'s TrustRoot> {
        let roots: &'s [TrustRoot] = self.local_roots;
        roots.iter().find(|r| r.root_id == *id)
    }

    fn verify_under_root(&self, r: &TrustRoot, digest: &[u8; 32], sig: &HybridSignature, now: u64) -> K3 {
        if sig.floor < r.floor { return K3::Neg; }
        let in_window = (self.kernel.classify_time_window_code)(now, r.not_before, r.not_after) == 0;
        K3::from_bool(in_window).and(self.floor.verify(&r.keys, digest, sig))
    }

    pub fn verify(&self, b: &PortableReceiptBundle<'_>, now: u64) -> K3 {
        let c = b.coupling;
        if !(self.kernel.receipt_fields_coupled)(c[0], c[1], c[2], c[3], c[4]) { return K3::Neg; }
        if b.endorsements.len() > MAX_ENDORSEMENT_DEPTH { return K3::Neg; }
        if let Some(r) = self.find_local(&b.signer_root_id) {
            return self.verify_under_root(r, &b.receipt_digest, &b.signature, now);
        }
        let first = match b.endorsements.first() { Some(e) => e, None => return K3::Bot };
        let mut current: &TrustRoot = match self.find_local(&first.issuer_root_id) { Some(r) => r, None => return K3::Bot };
        let mut acc = K3::Pos;
        for e in b.endorsements {
            if e.issuer_root_id != current.root_id { return K3::Neg; }
            if e.subject.floor < current.floor { return K3::Neg; }
            let d = root_digest(&self.floor.hasher, &e.subject);
            acc = acc.and(self.verify_under_root(current, &d, &e.signature, now));
            if acc == K3::Neg { return K3::Neg; }
            current = &e.subject;
        }
        if current.root_id != b.signer_root_id { return K3::Neg; }
        acc.and(self.verify_under_root(current, &b.receipt_digest, &b.signature, now))
    }
}
```

An unknown root that no local root endorses yields `⊥`, not `-`. The receipt may be perfectly valid in another federation. The verifier simply cannot say, and the envelope treats that honestly. Floors are monotone along a chain, so an endorsing root at `Hybrid` can never introduce a `Classical` subject.

**Attestation binding.** Pass 9 ties the executing enclave to the lifted request and to the loaded weights. The host's quote verifier, which is exact parsing of vendor evidence, reports a `K3`. The core crate checks the binding.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TeeKind { SgxDcap, SevSnp, Tdx, ArmCca }

pub struct AttestationEvidence { pub tee: TeeKind, pub measurement: [u8; 48], pub report_data: [u8; 64], pub quote_chain: K3 }
pub struct AttestationPolicy<'p> { pub allowed_measurements: &'p [[u8; 48]], pub required_tee: Option<TeeKind> }

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { acc |= x ^ y; }
    acc == 0
}

const DOMAIN_ATTEST: &[u8] = b"chio.attest-binding.v9";

/// `weights_hash` is the 32-byte decoding of LoadedWeights::loaded_weights_hash,
/// taken after evaluate_weights_binding has already accepted the model card.
pub fn attestation_binding<D: Digest32>(
    h: &D, ev: &AttestationEvidence, pol: &AttestationPolicy<'_>, req_digest: &[u8; 32], weights_hash: &[u8; 32],
) -> K3 {
    let expected = h.digest32(&[DOMAIN_ATTEST, req_digest, weights_hash]);
    let data_ok = ct_eq(&ev.report_data[..32], &expected) && ev.report_data[32..].iter().all(|b| *b == 0);
    let meas_ok = pol.allowed_measurements.iter().any(|m| ct_eq(m, &ev.measurement));
    let tee_ok = pol.required_tee.map_or(true, |t| t == ev.tee);
    ev.quote_chain.and(K3::from_bool(data_ok && meas_ok && tee_ok))
}
```

The std adapters are thin. `chio-mcp-edge` decodes JSON-RPC and sorts `arguments` into `ArgView` slices. `chio-a2a-adapter` flattens message parts. `chio-envoy-ext-authz` reads the `CheckRequest` attributes and hashes the body when present. Each implements `Guard` by calling the lift, computing facts, projecting, and mapping `Allow`, `PendingApproval`, and `Deny` onto the existing `Verdict` variants. On `Allow` the adapter reserves through `ledger_apply` with op 0 and commits with `budget_commit` at dispatch. On `Deny` or expiry it releases with op 2.

## 3. Proof obligations, specifications, and the analytic layer

**Theorem 1, verification transfer at the edge.** For every input $x$ and every proposal $a$ from any predictor whatsoever, $\Pi_{\mathcal{C}(x)}(a) \in \mathcal{C}(x)$, and $\bot_x = \texttt{Deny} \in \mathcal{C}(x)$. Hence any safety property $S$ proved as $\forall x\, \forall a \in \mathcal{C}(x).\ S(x,a)$ holds for the deployed system regardless of the model weights. The Lean proof quantifies over all actions, which is the same move as `kani::any()` in the harnesses.

```lean
-- formal/lean4/Chio/ProtocolEdge.lean  (additive; imports nothing from pinned modules)
namespace Chio.ProtocolEdge

inductive K3 | pos | neg | bot deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _ => .neg
  | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .bot

inductive Action | allow | pending | deny deriving DecidableEq, Repr

structure Facts where
  window : K3
  budget : K3
  floor : K3
  root : K3
  attest : K3

def Facts.conj (f : Facts) : K3 :=
  ((((f.window.and f.budget).and f.floor).and f.root).and f.attest)

def envelope (f : Facts) : Action → Bool
  | .deny => true
  | .pending => f.conj != .neg
  | .allow => f.conj == .pos

def project (f : Facts) (a : Action) : Action :=
  if envelope f a then a else .deny

theorem deny_feasible (f : Facts) : envelope f .deny = true := rfl

theorem project_feasible (f : Facts) (a : Action) : envelope f (project f a) = true := by
  unfold project; split <;> simp_all [envelope]

theorem allow_needs_pos (f : Facts) (h : project f .allow = .allow) : f.conj = .pos := by
  unfold project at h
  by_cases hc : envelope f .allow = true
  · simpa [envelope] using hc
  · simp [hc] at h

-- Hybrid floor, abstracted over the two verification oracles.
inductive Floor | classical | hybrid deriving DecidableEq, Repr
def Floor.rank : Floor → Nat | .classical => 1 | .hybrid => 2
instance : LT Floor := ⟨fun a b => a.rank < b.rank⟩
instance (a b : Floor) : Decidable (a < b) := inferInstanceAs (Decidable (a.rank < b.rank))

structure Sig where
  floor : Floor
  hasMl : Bool
  edOk  : Bool   -- Ed25519 verifies on binding(floor)
  mlOk  : Bool   -- ML-DSA-65 verifies on binding(floor)

def verify (vf : Floor) (s : Sig) : K3 :=
  if s.floor < vf then .neg
  else if !s.edOk then .neg
  else match s.floor, s.hasMl with
    | .hybrid, false => .neg
    | _, false => .pos
    | _, true => if s.mlOk then .pos else .neg

theorem hybrid_accept_has_ml :
    ∀ s : Sig, verify .hybrid s = .pos → s.hasMl = true ∧ s.mlOk = true ∧ s.floor = .hybrid := by
  intro ⟨fl, hm, e, m⟩
  cases fl <;> cases hm <;> cases e <;> cases m <;> decide

end Chio.ProtocolEdge
```

**Lemma 2, envelope shrinking is safe.** If a policy consumes Tier-1 predicates to restrict the envelope to any $\mathcal{C}'(x) \subseteq \mathcal{C}(x)$ with $\bot_x \in \mathcal{C}'(x)$, every safety property proved over $\mathcal{C}(x)$ still holds. Proof: $\Pi_{\mathcal{C}'(x)}(a) \in \mathcal{C}'(x) \subseteq \mathcal{C}(x)$, so the hypothesis of Theorem 1 is met. This is the only sanctioned way for learned predicates to touch admission. They may close doors. They may never open one that the facts closed.

**Lemma 3, pipeline composition preserves feasibility.** `GuardPipeline` returns `Deny` on the first denial, keeps `PendingApproval` sticky, and otherwise returns `Allow`. That is the meet in the order Deny ⊑ PendingApproval ⊑ Allow. Each envelope is down-closed in this order. The meet of elements drawn from down-closed sets lies in every one of those sets. So the pipeline verdict is feasible for every guard that contributed, including the edge guard.

**Theorem 4, hybrid unforgeability and non-separability.** Let $\Sigma_H$ be the composed scheme at floor `Hybrid`. For any forger $\mathcal{F}$ there are reductions $\mathcal{B}_1$ against Ed25519 and $\mathcal{B}_2$ against ML-DSA-65 with
$$\mathrm{Adv}^{\mathrm{euf}}_{\Sigma_H}(\mathcal{F}) \le \min\big(\mathrm{Adv}_{\mathrm{Ed}}(\mathcal{B}_1),\ \mathrm{Adv}_{\mathrm{ML}}(\mathcal{B}_2)\big) + \mathrm{Adv}^{\mathrm{coll}}_H .$$
Proof. $\mathcal{B}_2$ receives an ML-DSA public key, samples an Ed25519 key pair itself, and publishes the hybrid key. Each signing query on digest $r$ is answered by computing the Ed25519 component locally and querying the oracle on the ML binding of $r$. When $\mathcal{F}$ outputs a valid forgery on a fresh $r^\*$, by `hybrid_accept_has_ml` it contains an ML-DSA signature valid on the binding of $r^\*$. That binding was never queried unless $H$ collided, so $\mathcal{B}_2$ outputs it as a forgery. $\mathcal{B}_1$ is symmetric. Non-separability follows from the same binding. Relabelling a `Hybrid` signature as `Classical` changes the floor byte inside both preimages, so the Ed25519 component no longer verifies on the recomputed binding. Stripping therefore costs an Ed25519 forgery, and a verifier at the `Hybrid` floor refuses the relabelled object before any key is touched. The floor is a verifier's declared trust assumption, and the federation only ever raises it.

**Kani harnesses.** These compile under `cfg(kani)` inside the core crate. The learned choice is `kani::any()` throughout.

```rust
#[cfg(kani)]
mod proofs {
    use super::*;

    struct AlwaysOk;
    struct Unavail;
    struct ZeroHash;
    impl Ed25519Verify for AlwaysOk {
        fn verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> Result<bool, BackendUnavailable> { Ok(true) }
    }
    impl MlDsa65Verify for AlwaysOk {
        fn verify(&self, _: &[u8; 1952], _: &[u8], _: &[u8; 3309]) -> Result<bool, BackendUnavailable> { Ok(true) }
    }
    impl MlDsa65Verify for Unavail {
        fn verify(&self, _: &[u8; 1952], _: &[u8], _: &[u8; 3309]) -> Result<bool, BackendUnavailable> { Err(BackendUnavailable) }
    }
    impl Digest32 for ZeroHash { fn digest32(&self, _: &[&[u8]]) -> [u8; 32] { [0u8; 32] } }

    #[kani::proof]
    fn projection_is_feasible_for_any_proposal() {
        let f: EdgeFacts = kani::any();
        let a: EdgeAction = kani::any();
        let env = Envelope::from_facts(&f);
        assert!(env.contains(env.project(a).action()));
        assert!(env.contains(EdgeAction::Deny));
        if env.project(a).action() == EdgeAction::Allow { assert_eq!(f.conjunction(), K3::Pos); }
    }

    #[kani::proof]
    fn hybrid_floor_rejects_stripped_signature() {
        let floor = KernelCryptoFloor { floor: CryptoFloor::Hybrid, ed: AlwaysOk, ml: AlwaysOk, hasher: ZeroHash };
        let pk = HybridPublicKey { ed25519: [0; 32], mldsa65: [0; 1952] };
        let sig = HybridSignature { floor: kani::any(), ed25519: [0; 64], mldsa65: None };
        assert_eq!(floor.verify(&pk, &[0; 32], &sig), K3::Neg);
    }

    #[kani::proof]
    fn unavailable_pq_backend_never_yields_pos() {
        let floor = KernelCryptoFloor { floor: CryptoFloor::Hybrid, ed: AlwaysOk, ml: Unavail, hasher: ZeroHash };
        let pk = HybridPublicKey { ed25519: [0; 32], mldsa65: [0; 1952] };
        let sig = HybridSignature { floor: CryptoFloor::Hybrid, ed25519: [0; 64], mldsa65: Some([0; 3309]) };
        assert_eq!(floor.verify(&pk, &[0; 32], &sig), K3::Bot);
    }

    #[kani::proof]
    #[kani::unwind(100)]
    fn bounded_buf_respects_capacity_and_never_panics() {
        let n: usize = kani::any();
        kani::assume(n <= 96);
        let src = [0xA5u8; 96];
        let mut b = BoundedBuf::<64>::new();
        let r = b.push(&src[..n], Segment::Image);
        assert!(b.len() <= 64);
        assert_eq!(r.is_ok(), n <= 64);
    }

    #[kani::proof]
    fn tier0_overflow_degrades_to_pending_not_allow() {
        let m = Tier0Edge { w: [kani::any(); 4], bias: kani::any(), lambda_latency: kani::any(), lambda_budget: kani::any() };
        let feat: [Q16_16; 4] = kani::any();
        let a = m.propose(&feat, kani::any(), kani::any());
        assert_ne!(a, EdgeAction::Deny);
    }
}
```

`Q16_16` needs a `kani::Arbitrary` derive for the last harness, added with the same `cfg_attr` pattern as the enums.

**Apalache specification of federated floors.** The model abstracts keys away and tracks only what the offline verifier enforces: validity windows, floor monotonicity, and the acceptance rule.

```tla
---------------------------- MODULE FederatedReceiptFloor ----------------------------
EXTENDS Integers

CONSTANTS
  \* @type: Set(Str);
  Roots,
  \* @type: Int;
  Horizon

VARIABLES
  \* @type: Int;
  now,
  \* @type: Str -> Bool;
  valid,
  \* @type: Str -> Str;
  floor,
  \* @type: Set({ root: Str, t: Int, f: Str, ml: Bool });
  accepted

Floors == {"classical", "hybrid"}

Init ==
  /\ now = 0
  /\ valid \in [Roots -> BOOLEAN]
  /\ floor \in [Roots -> Floors]
  /\ accepted = {}

Tick == now < Horizon /\ now' = now + 1 /\ UNCHANGED <<valid, floor, accepted>>

Revoke(r) == valid' = [valid EXCEPT ![r] = FALSE] /\ UNCHANGED <<now, floor, accepted>>

RaiseFloor(r) == floor' = [floor EXCEPT ![r] = "hybrid"] /\ UNCHANGED <<now, valid, accepted>>

\* A receipt arrives declaring floor sf and carrying (ml) or lacking an ML-DSA component.
Accept(r, sf, ml) ==
  /\ valid[r]
  /\ (floor[r] = "hybrid" => sf = "hybrid")
  /\ (sf = "hybrid" => ml)
  /\ accepted' = accepted \cup {[root |-> r, t |-> now, f |-> floor[r], ml |-> ml]}
  /\ UNCHANGED <<now, valid, floor>>

Next ==
  \/ Tick
  \/ \E r \in Roots : Revoke(r) \/ RaiseFloor(r)
  \/ \E r \in Roots, sf \in Floors, ml \in BOOLEAN : Accept(r, sf, ml)

\* State invariant: anything accepted under a hybrid root carried ML-DSA.
FloorRespected == \A a \in accepted : a.f = "hybrid" => a.ml

\* Action invariants (Apalache treats primed references as action invariants).
FloorMonotone == \A r \in Roots : floor[r] = "hybrid" => floor'[r] = "hybrid"
NoPostRevocationAcceptance == \A a \in accepted' \ accepted : valid[a.root]
=====================================================================================
```

Run with `apalache-mc check --inv=FloorRespected,FloorMonotone,NoPostRevocationAcceptance --length=12 FederatedReceiptFloor.tla`. The chain depth bound in Rust is the reason a finite length suffices for the endorsement walk.

**Lemma 5, the shadow price keeps the verification queue bounded.** Hybrid verification is tens of microseconds per receipt. That is two to four orders of magnitude above the Tier-0 window, so it belongs in $C(x)$ and only its cost reaches the proposer as a feature. Let $q_t$ be the backlog of bundles awaiting exact verification and let $\lambda_{t+1} = [\lambda_t + \eta(q_t - q^\*)]_+$ be the latency shadow price. The proposer is a threshold rule, so the arrival rate of `Allow` proposals $a(\lambda)$ is non-increasing in $\lambda$, and admission is capped by $\mu$ verifications per tick. Take $V(q)=\tfrac12 q^2$. Once $\lambda$ exceeds the price at which $a(\lambda) \le \mu - \epsilon$, the drift satisfies $\mathbb{E}[V(q_{t+1}) - V(q_t) \mid q_t] \le B - \epsilon\, q_t$ for a constant $B$ depending on the arrival bound. Summing and telescoping gives $\limsup_T \tfrac1T \sum_t \mathbb{E}[q_t] \le B/\epsilon$, and the projected subgradient step bounds the time $\lambda$ spends below that price by $O(1/\eta)$. The queue is therefore mean-bounded for any weights the Tier-0 model carries, which is the control-theoretic reading of verification transfer. Safety is exact. Only throughput is learned.

**Lemma 6, role-asymmetric thresholds yield a well-defined $\mathbb{K}_3$ lift.** For a predicate with probability $p$ and thresholds $\tau^{\text{neg}} \le \tau^{\text{pos}}$, the regions $\{p \ge \tau^{\text{pos}}\}$ and $\{p \le \tau^{\text{neg}}\}$ are disjoint, so `classify` is a function, and it is monotone in $p$ under the order `-` ⊑ `⊥` ⊑ `+`. The constructor refuses thresholds that violate the inequality, so no deployed threshold pair can produce an ambiguous predicate. Segment features for the proposer are the positive-predicate mass per segment, normalised by the pinned per-segment counts.

What this pass delivers. A single `no_std` core lifts MCP, A2A, and Envoy ext_authz views into one `PortableToolCallRequest` with prefix-free, length-framed Copley segments and a domain-separated digest. Five exact facts drive a down-closed envelope with `Deny` always present, and the Tier-0 proposer can only move within it. `KernelCryptoFloor` signs both components over a binding that commits to the floor and both public keys, so stripping is detectable and downgrade is refused at the verifier. Offline verification resolves federated roots through bounded, floor-monotone endorsement chains and returns `⊥` rather than a guess when a root is unknown. Attestation binds request digest and loaded weights into enclave report data. The Lean theorems, five Kani harnesses, and the Apalache model discharge the envelope, floor, and federation properties without reading a single weight.

Still open for the next pass. The std adapters need their JSON-RPC, A2A, and protobuf decoders wired to the view structs with fuzz targets on the decoders. The `proof-manifest.toml` entry for the new Lean module and the Kani harness list should be added so CI pins them. The hybrid backend traits need concrete bindings to the kernel's Ed25519 and ML-DSA-65 implementations, plus a measurement of ML-DSA-65 verification latency on the target fleet to calibrate the latency shadow price.