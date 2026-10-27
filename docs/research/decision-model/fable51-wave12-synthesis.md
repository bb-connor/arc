# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 12 Synthesis

- **Timestamp**: `20261025-044741 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1618.39s` across 4 parallel passes
- **Total Output**: `154,770` characters (`20,041` words)
- **Claude Max Quota Before Wave 12**: 5-hour `30.0%` | 7-day `94.0%`
- **Claude Max Quota After Wave 12**: 5-hour `42.0%` | 7-day `96.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave12_angle_1_formal_aeneas_and_lean4_deepening_pass_12` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,654` | `39,977` | `693.54` |
| `wave12_angle_2_copley_dag_optimization_and_simd_bitset_pass_12` | `0` | `success` | `['claude-fable-5-1']` | `none` | `3,075` | `20,461` | `939.66` |
| `wave12_angle_3_concurrent_loom_and_dst_crash_recovery_pass_12` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,736` | `49,820` | `1618.38` |
| `wave12_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_12` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,576` | `44,512` | `712.23` |

---

# Verbatim Treatise - `wave12_angle_1_formal_aeneas_and_lean4_deepening_pass_12`

I'll lay out the Wave 12 additive verification surface as one new `#![no_std]` module, its Kani harnesses, the matching Lean 4 development, a Creusot layer, the manifest entries, and the theorems that tie them to the Envelope Preservation and Verification Transfer law.

# Wave 12 · Angle 1 - Mechanization Pass 12

## 0. Additivity contract

Everything below lands in one new file, `crates/kernel/chio-kernel-core/src/formal_wave12.rs`, plus one new Lean directory, `formal/lean4/Chio/Wave12/`. The only edit to an existing file is a single `pub mod formal_wave12;` line in `lib.rs`. No signature from `formal_core.rs`, `formal_aeneas.rs`, or `budget_split.rs` changes. The new module calls `classify_time_window_code` and `MAX_BUDGET_SHARE_BPS` as crate-internal clients, so the pinned proof manifest remains untouched and the new `[[lemma]]` entries are appended.

Every lemma is placed inside the canonical tuple $\mathcal{D}_\ell$:

- Exact computation $C_\ell(x) \in \mathbb{K}_3^{F_\ell}$: Merkle inclusion (`verify_inclusion`), two-sample window classification (`window_k3`), and attenuation chain checking produce $\{+,-,\bot\}$ facts.
- Feasible envelope $\mathcal{C}_\ell$: `Envelope` with a private constructor; `Hold` is $\bot_x$ and is always a member.
- Predictor $P_\ell$: a `FixedQ16_16` score penalized by $\boldsymbol{\lambda}$. It only proposes.
- Projection $\Pi$: `shield`. All proofs quantify over the proposed action, never over the score.

## 1. `FixedQ16_16` saturation lemmas

The Tier-0 micro-models work in Q16.16 on `i32`. The saturation edge cases that matter are: the exact sum leaves the representable interval, the widened product shifts to a value outside `i32`, and the Lagrangian penalty must stay a penalty (never raise the score) even when a product saturates.

```rust
//! crates/kernel/chio-kernel-core/src/formal_wave12.rs  (crate is #![no_std] + alloc)
#![forbid(unsafe_code)]

use core::cmp::Ordering;

use crate::budget_split::MAX_BUDGET_SHARE_BPS;
use crate::formal_aeneas::classify_time_window_code;

/// Kleene three-valued fact produced by every exact computation in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum K3 { Pos, Neg, Bot }

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedQ16_16 { raw: i32 }

const fn clamp_i64_to_i32(v: i64) -> i32 {
    if v > i32::MAX as i64 { i32::MAX } else if v < i32::MIN as i64 { i32::MIN } else { v as i32 }
}

impl FixedQ16_16 {
    pub const SCALE_BITS: u32 = 16;
    pub const ZERO: Self = Self { raw: 0 };
    pub const ONE: Self = Self { raw: 65_536 };
    pub const MAX: Self = Self { raw: i32::MAX };
    pub const MIN: Self = Self { raw: i32::MIN };

    pub const fn from_raw(raw: i32) -> Self { Self { raw } }
    pub const fn raw(self) -> i32 { self.raw }
    pub const fn is_nonneg(self) -> bool { self.raw >= 0 }

    pub const fn sat_add(self, rhs: Self) -> Self { Self { raw: self.raw.saturating_add(rhs.raw) } }
    pub const fn sat_sub(self, rhs: Self) -> Self { Self { raw: self.raw.saturating_sub(rhs.raw) } }

    /// Q16.16 product through an i64 intermediate, floor-shifted, then clamped.
    pub const fn sat_mul(self, rhs: Self) -> Self {
        let wide = match (self.raw as i64).checked_mul(rhs.raw as i64) {
            Some(p) => p,
            // Unreachable: |raw| <= 2^31 so |product| <= 2^62. Kept total;
            // Kani `sat_mul_wide_never_overflows` discharges the unreachability.
            None => return if (self.raw < 0) != (rhs.raw < 0) { Self::MIN } else { Self::MAX },
        };
        let shifted = match wide.checked_shr(Self::SCALE_BITS) { Some(s) => s, None => 0 };
        Self { raw: clamp_i64_to_i32(shifted) }
    }
}

pub const SHADOW_PRICE_DIM: usize = 5;
pub const LAMBDA_BUDGET: usize = 0;
pub const LAMBDA_FUEL: usize = 1;
pub const LAMBDA_LATENCY: usize = 2;
pub const LAMBDA_MEMORY: usize = 3;
pub const LAMBDA_ESCROW: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowPrices { pub lambda: [FixedQ16_16; SHADOW_PRICE_DIM] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViolationVector { pub g: [FixedQ16_16; SHADOW_PRICE_DIM] }

/// s_pen = s ⊖ Σ_i (λ_i ⊗ g_i), every operator saturating.
pub fn penalized_score(base: FixedQ16_16, prices: &ShadowPrices, violation: &ViolationVector) -> FixedQ16_16 {
    let mut acc = base;
    for (lambda, g) in prices.lambda.iter().zip(violation.g.iter()) {
        acc = acc.sat_sub(lambda.sat_mul(*g));
    }
    acc
}
```

**Theorem W12.1 (Saturation lattice).** Let $I = [-2^{31}, 2^{31}-1]$ and $\mathrm{clamp} : \mathbb{Z} \to I$.

1. $\mathrm{clamp}$ is monotone, idempotent, and the identity on $I$.
2. $\mathrm{sat\_add}(a,b) = a+b$ when $a+b \in I$; otherwise it is the bound nearer to $a+b$.
3. For $\lambda, g \ge 0$: $\mathrm{sat\_mul}(\lambda, g) \ge 0$, and $\mathrm{sat\_mul}(\cdot, g)$ is monotone in $\lambda$.
4. For $s \in I$ and $p \ge 0$: $\mathrm{sat\_sub}(s, p) \le s$. Hence `penalized_score` is bounded above by `base` and is antitone in every component of $\boldsymbol{\lambda}$.

*Proof.* (1) Case split on the two comparisons; each branch is linear. (2) By (1) applied to $a+b$. (3) $\lambda g \ge 0$, Euclidean division by $2^{16}>0$ preserves sign and order, and $\mathrm{clamp}$ is monotone by (1). (4) If $s-p \ge -2^{31}$ then $\mathrm{clamp}(s-p) = s-p \le s$; otherwise the result is $-2^{31} \le s$. Antitonicity: $\lambda \le \lambda'$ gives $\mathrm{sat\_mul}(\lambda,g) \le \mathrm{sat\_mul}(\lambda',g)$ by (3), and $x \le y \Rightarrow \mathrm{clamp}(s-y) \le \mathrm{clamp}(s-x)$ by (1). Fold over the five terms. $\square$

The control-theoretic consequence is that the shadow prices remain a valid dual: raising $\lambda_{\text{latency}}$ can only lower every Tier-0 score, so the dual ascent in the Lagrangian loop is never inverted by saturation.

### Lean 4: `formal/lean4/Chio/Wave12/FixedSat.lean`

Lean's `/` on `Int` is Euclidean division, which for the positive divisor $2^{16}$ equals floor division and therefore matches the arithmetic right shift in `sat_mul`.

```lean
namespace Chio.Wave12.FixedSat

def i32Min : Int := -2147483648
def i32Max : Int := 2147483647

def clampI32 (v : Int) : Int :=
  if v > i32Max then i32Max else if v < i32Min then i32Min else v

def satAdd (a b : Int) : Int := clampI32 (a + b)
def satSub (a b : Int) : Int := clampI32 (a - b)
def satMul (a b : Int) : Int := clampI32 (a * b / 65536)

theorem clamp_bounds (v : Int) : i32Min ≤ clampI32 v ∧ clampI32 v ≤ i32Max := by
  unfold clampI32 i32Min i32Max
  repeat' split
  all_goals omega

theorem clamp_id {v : Int} (hlo : i32Min ≤ v) (hhi : v ≤ i32Max) : clampI32 v = v := by
  simp only [clampI32, i32Min, i32Max] at *
  repeat' split
  all_goals omega

theorem clamp_idem (v : Int) : clampI32 (clampI32 v) = clampI32 v :=
  clamp_id (clamp_bounds v).1 (clamp_bounds v).2

theorem clamp_mono {u v : Int} (h : u ≤ v) : clampI32 u ≤ clampI32 v := by
  unfold clampI32 i32Min i32Max
  repeat' split
  all_goals omega

theorem satAdd_exact {a b : Int} (hlo : i32Min ≤ a + b) (hhi : a + b ≤ i32Max) :
    satAdd a b = a + b :=
  clamp_id hlo hhi

theorem satMul_nonneg {a b : Int} (ha : 0 ≤ a) (hb : 0 ≤ b) : 0 ≤ satMul a b := by
  have hprod : 0 ≤ a * b := Int.mul_nonneg ha hb
  have hdiv : 0 ≤ a * b / 65536 := Int.ediv_nonneg hprod (by decide)
  unfold satMul clampI32 i32Min i32Max
  repeat' split
  all_goals omega

theorem satMul_mono_left {l l' g : Int} (hg : 0 ≤ g) (h : l ≤ l') : satMul l g ≤ satMul l' g := by
  have hp : l * g ≤ l' * g := Int.mul_le_mul_of_nonneg_right h hg
  have hd : l * g / 65536 ≤ l' * g / 65536 := Int.ediv_le_ediv (by decide) hp
  exact clamp_mono hd

theorem satSub_le_of_nonneg {a b : Int} (hlo : i32Min ≤ a) (hhi : a ≤ i32Max) (hb : 0 ≤ b) :
    satSub a b ≤ a := by
  simp only [satSub, clampI32, i32Min, i32Max] at *
  repeat' split
  all_goals omega

theorem penalty_never_increases {s l g : Int} (hlo : i32Min ≤ s) (hhi : s ≤ i32Max)
    (hl : 0 ≤ l) (hg : 0 ≤ g) : satSub s (satMul l g) ≤ s :=
  satSub_le_of_nonneg hlo hhi (satMul_nonneg hl hg)

/-- Mirrors `penalized_score`: a left fold of saturating penalties. -/
def penalize (s : Int) (terms : List (Int × Int)) : Int :=
  terms.foldl (fun acc t => satSub acc (satMul t.1 t.2)) s

theorem penalize_le {terms : List (Int × Int)} :
    ∀ (s : Int), i32Min ≤ s → s ≤ i32Max →
      (∀ t ∈ terms, 0 ≤ t.1 ∧ 0 ≤ t.2) → penalize s terms ≤ s := by
  induction terms with
  | nil => intro s _ _ _; exact Int.le_refl s
  | cons t rest ih =>
    intro s hlo hhi hall
    have ht := hall t (by simp)
    have hstep : satSub s (satMul t.1 t.2) ≤ s := penalty_never_increases hlo hhi ht.1 ht.2
    have hb := clamp_bounds (s - satMul t.1 t.2)
    have hrest := ih (satSub s (satMul t.1 t.2)) hb.1 hb.2 (fun u hu => hall u (by simp [hu]))
    exact Int.le_trans hrest hstep

end Chio.Wave12.FixedSat
```

## 2. Epoch boundary transitions

The existing `classify_time_window_code` is a one-sample classifier. The edge cases this pass closes are: a clock sample pair that moves backwards, an empty window where `issued_at == expires_at`, and the saturation edge where an issuer encodes "no expiry" as `u64::MAX`.

```rust
pub const WINDOW_VALID: u8 = 0;
pub const WINDOW_NOT_YET_VALID: u8 = 1;
pub const WINDOW_EXPIRED: u8 = 2;
pub const RANK_EXPIRED: u8 = 2;

/// Lifecycle order NotYetValid < Valid < Expired. Unknown codes rank as Expired (conservative).
pub const fn lifecycle_rank(code: u8) -> u8 {
    match code { WINDOW_NOT_YET_VALID => 0, WINDOW_VALID => 1, _ => RANK_EXPIRED }
}

/// `u64::MAX` is NOT "never expires": under the half-open window the last tick is already Expired.
pub const fn window_is_unbounded_encoding(expires_at: u64) -> bool { expires_at == u64::MAX }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochTransition { Stay, Activate, Expire, Regress }

pub fn epoch_transition(prev_now: u64, now: u64, issued_at: u64, expires_at: u64) -> EpochTransition {
    let before = lifecycle_rank(classify_time_window_code(prev_now, issued_at, expires_at));
    let after = lifecycle_rank(classify_time_window_code(now, issued_at, expires_at));
    match before.cmp(&after) {
        Ordering::Equal => EpochTransition::Stay,
        Ordering::Greater => EpochTransition::Regress,
        Ordering::Less if after == RANK_EXPIRED => EpochTransition::Expire,
        Ordering::Less => EpochTransition::Activate,
    }
}

/// Exact K3 time fact: `Bot` on clock regression, otherwise validity of the later sample.
pub fn window_k3(prev_now: u64, now: u64, issued_at: u64, expires_at: u64) -> K3 {
    if epoch_transition(prev_now, now, issued_at, expires_at) == EpochTransition::Regress {
        return K3::Bot;
    }
    if classify_time_window_code(now, issued_at, expires_at) == WINDOW_VALID { K3::Pos } else { K3::Neg }
}
```

**Theorem W12.2 (Epoch monotonicity).** Fix `issued_at ≤ expires_at` and write $r(n) = \mathrm{rank}(\mathrm{classify}(n))$.

1. $n_1 \le n_2 \Rightarrow r(n_1) \le r(n_2)$. Consequently `epoch_transition` never returns `Regress` for forward clock samples, and $r$ has at most two transition points.
2. If `issued_at == expires_at`, no `now` is `Valid`.
3. For any `issued_at ≤ m`, `classify(m, issued_at, m)` is `Expired`. With $m = $ `u64::MAX` this is the saturation edge: the "unbounded" encoding expires on the last representable tick.
4. (Expiry propagates down a delegation chain.) If the parent window is `Expired` at `now`, every well-formed child window with `expires_child ≤ expires_parent` is `Expired` at `now`.

*Proof.* (1) $\mathrm{classify}$ is a two-threshold step function of `now` with values in lifecycle order; monotone functions into a three-element chain change value at most twice. (2) Under the half-open convention `Valid` needs `issued ≤ now < expires`, impossible when the bounds coincide. (3) `m < issued` is false and `m < m` is false, so the final branch is taken. (4) `Expired` at the parent gives `now ≥ expires_parent ≥ expires_child ≥ issued_child`, so both comparisons fail at the child. $\square$

Item (2) fixes the boundary convention. The Lean model below uses the half-open convention; the Kani harness `empty_window_never_valid_pins_half_open` is what binds that convention to the shipped implementation. If the existing code were closed on the right, that harness fails and the Lean model is flipped, with no other proof affected.

### Lean 4: `formal/lean4/Chio/Wave12/Epoch.lean`

```lean
namespace Chio.Wave12.Epoch

inductive Window | notYetValid | valid | expired
  deriving DecidableEq, Repr

def classify (now issued expires : Nat) : Window :=
  if now < issued then .notYetValid else if now < expires then .valid else .expired

def rank : Window → Nat
  | .notYetValid => 0
  | .valid => 1
  | .expired => 2

theorem rank_mono {n1 n2 i e : Nat} (h : n1 ≤ n2) :
    rank (classify n1 i e) ≤ rank (classify n2 i e) := by
  unfold classify
  repeat' split
  all_goals simp only [rank]
  all_goals omega

theorem empty_window_never_valid {n i : Nat} : classify n i i ≠ .valid := by
  unfold classify
  repeat' split
  all_goals first | omega | (intro h; cases h)

theorem last_tick_is_expired {m i : Nat} (h : i ≤ m) : classify m i m = .expired := by
  unfold classify
  rw [if_neg (Nat.not_lt.mpr h), if_neg (Nat.lt_irrefl m)]

theorem expired_imp_past {now i e : Nat} (h : classify now i e = .expired) : e ≤ now := by
  unfold classify at h
  split at h
  · cases h
  · split at h
    · cases h
    · omega

theorem past_imp_expired {now i e : Nat} (hi : i ≤ now) (he : e ≤ now) :
    classify now i e = .expired := by
  unfold classify
  rw [if_neg (Nat.not_lt.mpr hi), if_neg (Nat.not_lt.mpr he)]

theorem expiry_propagates {now ip ep ic ec : Nat} (hp : classify now ip ep = .expired)
    (hatt : ec ≤ ep) (hw : ic ≤ ec) : classify now ic ec = .expired :=
  have hpast := expired_imp_past hp
  past_imp_expired (Nat.le_trans hw (Nat.le_trans hatt hpast)) (Nat.le_trans hatt hpast)

inductive Transition | stay | activate | expire | regress
  deriving DecidableEq

def transition (prev now i e : Nat) : Transition :=
  if rank (classify prev i e) = rank (classify now i e) then .stay
  else if rank (classify now i e) < rank (classify prev i e) then .regress
  else if rank (classify now i e) = 2 then .expire else .activate

theorem no_regress {prev now i e : Nat} (h : prev ≤ now) : transition prev now i e ≠ .regress := by
  have hm := rank_mono (i := i) (e := e) h
  unfold transition
  repeat' split
  all_goals first | omega | (intro hc; cases hc)

end Chio.Wave12.Epoch
```

## 3. Multi-hop delegation: `AttenuationWitness`

`budget_split.rs` enforces the horizontal constraint, siblings never oversubscribe a parent (`OversubscribedSiblings`), and the parent-child expiry relation (`ParentExpiryConflict`). It uses `String` ids and `BTreeMap`, so it is not a Tier-0 object. The vertical constraint along a delegation chain, which `SwarmDelegationWitnessChain` carries at the swarm layer, gets a `no_std` witness here. Each hop records what it received and what it emitted; the checker recomputes the attenuation exactly.

```rust
pub const BPS_ONE: u32 = MAX_BUDGET_SHARE_BPS as u32;
pub const MAX_DELEGATION_HOPS: usize = 16;

/// floor(parent * share / 10_000). `None` iff an input exceeds the cap.
pub fn attenuate_bps(parent_effective: u16, child_share: u16) -> Option<u16> {
    if parent_effective > MAX_BUDGET_SHARE_BPS || child_share > MAX_BUDGET_SHARE_BPS {
        return None;
    }
    let prod = u32::from(parent_effective).checked_mul(u32::from(child_share))?;
    let q = prod.checked_div(BPS_ONE)?;
    u16::try_from(q).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct AttenuationWitness {
    pub hop: u8,
    pub child_share_bps: u16,
    pub effective_in_bps: u16,
    pub effective_out_bps: u16,
    pub units_cap_in: u64,
    pub units_cap_out: u64,
    pub expires_in: u64,
    pub expires_out: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct RootAuthority { pub units_cap: u64, pub expires_at: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttenuationSummary { pub hops: usize, pub effective_bps: u16, pub units_cap: u64, pub expires_at: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttenuationError {
    BpsOutOfRange, EffectiveMismatch, UnitsCapIncreased, ExpiryExtended,
    HopOrder, ChainTooLong, ChainDisconnected,
}

pub fn check_witness(w: &AttenuationWitness) -> Result<(), AttenuationError> {
    let expected = attenuate_bps(w.effective_in_bps, w.child_share_bps)
        .ok_or(AttenuationError::BpsOutOfRange)?;
    if expected != w.effective_out_bps { return Err(AttenuationError::EffectiveMismatch); }
    if w.units_cap_out > w.units_cap_in { return Err(AttenuationError::UnitsCapIncreased); }
    if w.expires_out > w.expires_in { return Err(AttenuationError::ExpiryExtended); }
    Ok(())
}

pub fn check_chain(root: &RootAuthority, chain: &[AttenuationWitness])
    -> Result<AttenuationSummary, AttenuationError>
{
    if chain.len() > MAX_DELEGATION_HOPS { return Err(AttenuationError::ChainTooLong); }
    let mut eff = MAX_BUDGET_SHARE_BPS;
    let mut units = root.units_cap;
    let mut exp = root.expires_at;
    for (i, w) in chain.iter().enumerate() {
        let hop = u8::try_from(i).map_err(|_| AttenuationError::ChainTooLong)?;
        if w.hop != hop { return Err(AttenuationError::HopOrder); }
        if w.effective_in_bps != eff || w.units_cap_in != units || w.expires_in != exp {
            return Err(AttenuationError::ChainDisconnected);
        }
        check_witness(w)?;
        eff = w.effective_out_bps;
        units = w.units_cap_out;
        exp = w.expires_out;
    }
    Ok(AttenuationSummary { hops: chain.len(), effective_bps: eff, units_cap: units, expires_at: exp })
}
```

**Theorem W12.3 (Attenuation).** For $p, s \le 10^4$: $\mathrm{att}(p,s) = \lfloor ps/10^4 \rfloor \le \min(p, s)$. If `check_chain` returns `Ok(summary)`, then `summary.effective_bps ≤ 10_000`, `summary.units_cap ≤ root.units_cap`, `summary.expires_at ≤ root.expires_at`, and each of the three quantities is non-increasing hop by hop.

*Proof.* $ps \le p \cdot 10^4$, and division by $10^4$ is monotone, so $\mathrm{att}(p,s) \le p$; symmetrically for $s$. The chain checker rejects any hop whose inputs differ from the previous outputs, so the accepted chain is a left fold of per-hop steps, each of which is non-increasing by `check_witness`. A left fold of non-increasing steps is bounded by its seed, by induction on the list. $\square$

Combined with W12.2(4), an expired root cannot be laundered through delegation: every descendant window closes no later than the root's.

### Lean 4: `formal/lean4/Chio/Wave12/Attenuation.lean`

```lean
namespace Chio.Wave12.Attenuation

def attenuate (p s : Nat) : Nat := p * s / 10000

theorem attenuate_le_left {p s : Nat} (hs : s ≤ 10000) : attenuate p s ≤ p := by
  unfold attenuate
  calc p * s / 10000 ≤ p * 10000 / 10000 := Nat.div_le_div_right (Nat.mul_le_mul_left p hs)
    _ = p := Nat.mul_div_cancel p (by decide)

theorem attenuate_le_right {p s : Nat} (hp : p ≤ 10000) : attenuate p s ≤ s := by
  unfold attenuate
  rw [Nat.mul_comm]
  exact attenuate_le_left (p := s) hp

/-- Effective authority after a chain of shares, mirroring `check_chain`'s bps fold. -/
def effective : List Nat → Nat → Nat
  | [], acc => acc
  | s :: rest, acc => effective rest (attenuate acc s)

theorem effective_le_root : ∀ (shares : List Nat) (acc : Nat),
    (∀ s ∈ shares, s ≤ 10000) → effective shares acc ≤ acc
  | [], acc, _ => Nat.le_refl acc
  | s :: rest, acc, h =>
    have hs : s ≤ 10000 := h s (by simp)
    have hrest : ∀ t ∈ rest, t ≤ 10000 := fun t ht => h t (by simp [ht])
    Nat.le_trans (effective_le_root rest (attenuate acc s) hrest) (attenuate_le_left hs)

/-- Generic form used for `units_cap` and `expires_at` with `f := fun acc w => min acc w`. -/
theorem foldl_antitone {α : Type} (f : Nat → α → Nat) (hf : ∀ acc w, f acc w ≤ acc) :
    ∀ (l : List α) (acc : Nat), List.foldl f acc l ≤ acc
  | [], acc => Nat.le_refl acc
  | w :: rest, acc => Nat.le_trans (foldl_antitone f hf rest (f acc w)) (hf acc w)

end Chio.Wave12.Attenuation
```

## 4. Merkle inclusion steps coupled to the decision envelope

The weights-binding path (`LoadedWeights::loaded_weights_hash`, `evaluate_weights_binding`) needs a Tier-0 primitive that proves a weights digest belongs to a pinned registry root. The exact computation returns $\mathbb{K}_3$: `Pos` on a recomputed match, `Neg` on a mismatch, `Bot` when the proof is malformed or too deep for the hot-path latency budget. `Bot` is where $\lambda_{\text{latency}}$ meets verification: a deep proof is not wrong, it is deferred to Tier-1 as `Hold`.

```rust
pub const DIGEST_LEN: usize = 32;
pub type Digest = [u8; DIGEST_LEN];
pub const MAX_MERKLE_DEPTH: usize = 64;
pub const MAX_TIER0_MERKLE_DEPTH: usize = 8;

pub trait NodeHasher { fn hash_pair(&self, left: &Digest, right: &Digest) -> Digest; }

/// One inclusion step. Direction bit decides which side the running digest occupies.
pub fn inclusion_step<H: NodeHasher>(h: &H, acc: &Digest, sibling: &Digest, acc_is_right: bool) -> Digest {
    if acc_is_right { h.hash_pair(sibling, acc) } else { h.hash_pair(acc, sibling) }
}

pub fn verify_inclusion<H: NodeHasher>(
    h: &H, leaf: &Digest, index: u64, path: &[Digest], expected_root: &Digest,
) -> K3 {
    if path.len() > MAX_MERKLE_DEPTH { return K3::Bot; }
    let depth = match u32::try_from(path.len()) { Ok(d) => d, Err(_) => return K3::Bot };
    if depth < 64 {
        let bound = match 1u64.checked_shl(depth) { Some(b) => b, None => return K3::Bot };
        if index >= bound { return K3::Bot; }
    }
    let mut acc = *leaf;
    let mut idx = index;
    for sibling in path {
        let acc_is_right = (idx & 1) == 1;
        acc = inclusion_step(h, &acc, sibling, acc_is_right);
        idx = match idx.checked_shr(1) { Some(v) => v, None => 0 };
    }
    if acc == *expected_root { K3::Pos } else { K3::Neg }
}

/// Hot-path variant: proofs deeper than the Tier-0 budget are `Bot`, never `Pos`.
pub fn verify_inclusion_tier0<H: NodeHasher>(
    h: &H, leaf: &Digest, index: u64, path: &[Digest], expected_root: &Digest,
) -> K3 {
    if path.len() > MAX_TIER0_MERKLE_DEPTH { return K3::Bot; }
    verify_inclusion(h, leaf, index, path, expected_root)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Tier0Action { Allow, Hold, Deny }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Tier0Facts { pub weights_inclusion: K3, pub time: K3, pub budget_ok: bool }

/// Private constructor: only `exact_envelope` can build one. `Hold` is the fallback ⊥_x.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope { allow: bool }

impl Envelope {
    pub const fn contains(&self, a: Tier0Action) -> bool {
        match a { Tier0Action::Allow => self.allow, Tier0Action::Hold | Tier0Action::Deny => true }
    }
    pub const fn fallback(&self) -> Tier0Action { Tier0Action::Hold }
}

pub fn exact_envelope(f: &Tier0Facts) -> Envelope {
    Envelope { allow: f.weights_inclusion == K3::Pos && f.time == K3::Pos && f.budget_ok }
}

/// Π: the learned proposal is kept iff feasible, else the fallback.
pub fn shield(env: &Envelope, proposed: Tier0Action) -> Tier0Action {
    if env.contains(proposed) { proposed } else { env.fallback() }
}

pub fn tier0_decide(f: &Tier0Facts, score: FixedQ16_16, threshold: FixedQ16_16) -> Tier0Action {
    let proposed = if score >= threshold { Tier0Action::Allow } else { Tier0Action::Deny };
    shield(&exact_envelope(f), proposed)
}
```

`budget_ok` is produced by the existing `budget_precheck`; `time` by `window_k3`; `weights_inclusion` by `verify_inclusion_tier0`. Nothing in this module re-derives what those exact computations already decide.

**Theorem W12.4 (Inclusion soundness in $\mathbb{K}_3$).** Let $h$ be any function on digest pairs.

1. `verify_inclusion = Pos` implies the folded digest equals the expected root.
2. A path longer than the depth cap, or an index $\ge 2^{\text{depth}}$, yields `Bot`, never `Pos`.
3. With an empty path, the result is `Pos` iff `leaf == root`, and never `Bot`.
4. The work is exactly `path.len()` calls to `hash_pair`, so the Tier-0 variant costs at most eight.

*Proof.* (1) The final branch compares the fold result with the root and returns `Pos` only on equality. (2) Both guards return before any hashing. (3) The fold over the empty list is the identity. (4) One step per sibling, no other hashing. $\square$

**Theorem W12.5 (Envelope preservation and verification transfer, Wave 12 instance).** For all facts $f$, scores $s$, thresholds $t$:

1. $\mathrm{tier0\_decide}(f, s, t) \in \mathcal{C}(f)$.
2. $\mathrm{Hold} \in \mathcal{C}(f)$.
3. $\mathrm{tier0\_decide}(f, s, t) = \mathrm{Allow}$ implies all three facts are $+$.
4. $\mathrm{tier0\_decide}(f, s, t) = \mathrm{shield}(\mathcal{C}(f), a)$ for some $a$. Therefore any property proved for all $a \in \{\mathrm{Allow}, \mathrm{Hold}, \mathrm{Deny}\}$ holds for all $(s, t)$, and the score never appears in a proof obligation.

*Proof.* `shield` returns its argument only when the envelope contains it, otherwise the fallback, which is always contained. `Allow` is contained only when the conjunction of facts holds. Item (4) is by definition of `tier0_decide`. $\square$

Item (4) is the whole point of the law in Section A: Kani, Lean, Apalache, and Aeneas never see $P_\ell$. They see `kani::any::<Tier0Action>()`, or `∀ a`, or `\E a \in Feasible(s)`.

### Lean 4: `formal/lean4/Chio/Wave12/Merkle.lean` and `Envelope.lean`

```lean
namespace Chio.Wave12.Merkle

variable {D : Type} [DecidableEq D]

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

def step (h : D → D → D) (acc sib : D) (accIsRight : Bool) : D :=
  if accIsRight then h sib acc else h acc sib

def fold (h : D → D → D) (leaf : D) (path : List (D × Bool)) : D :=
  path.foldl (fun acc t => step h acc t.1 t.2) leaf

def verify (h : D → D → D) (maxDepth : Nat) (leaf : D) (path : List (D × Bool)) (root : D) : K3 :=
  if path.length > maxDepth then .bot else if fold h leaf path = root then .pos else .neg

theorem verify_pos_sound {h : D → D → D} {d : Nat} {leaf root : D} {path : List (D × Bool)}
    (hv : verify h d leaf path root = .pos) : fold h leaf path = root := by
  unfold verify at hv
  split at hv
  · cases hv
  · split at hv
    · assumption
    · cases hv

theorem verify_too_deep {h : D → D → D} {d : Nat} {leaf root : D} {path : List (D × Bool)}
    (hd : path.length > d) : verify h d leaf path root = .bot := by
  unfold verify
  simp [hd]

theorem verify_nil {h : D → D → D} {d : Nat} {leaf root : D} :
    verify h d leaf [] root = .pos ↔ leaf = root := by
  unfold verify fold
  have hlen : ¬ (([] : List (D × Bool)).length > d) := by simp
  rw [if_neg hlen]
  simp only [List.foldl_nil]
  constructor
  · intro hv
    split at hv
    · assumption
    · cases hv
  · intro he
    rw [if_pos he]

end Chio.Wave12.Merkle
```

```lean
import Chio.Wave12.Merkle

namespace Chio.Wave12.Envelope
open Chio.Wave12.Merkle

inductive Action | allow | hold | deny
  deriving DecidableEq, Repr

def K3.isPos : K3 → Bool | .pos => true | _ => false

structure Facts where
  weightsInclusion : K3
  time : K3
  budgetOk : Bool

def allowFeasible (f : Facts) : Bool :=
  f.weightsInclusion.isPos && f.time.isPos && f.budgetOk

def feasible (f : Facts) : Action → Bool
  | .allow => allowFeasible f
  | .hold => true
  | .deny => true

def shield (f : Facts) (a : Action) : Action := if feasible f a then a else .hold

def propose (score thr : Int) : Action := if thr ≤ score then .allow else .deny

def tier0Decide (f : Facts) (score thr : Int) : Action := shield f (propose score thr)

theorem hold_always_feasible (f : Facts) : feasible f .hold = true := rfl

theorem shield_feasible (f : Facts) (a : Action) : feasible f (shield f a) = true := by
  unfold shield
  split
  · assumption
  · rfl

theorem allow_sound {f : Facts} {a : Action} (h : shield f a = .allow) : allowFeasible f = true := by
  unfold shield at h
  split at h
  · subst h; assumption
  · cases h

/-- Verification transfer: every property of `tier0Decide` is a property of `shield` at some `a`. -/
theorem decide_is_shield (f : Facts) (score thr : Int) :
    ∃ a, tier0Decide f score thr = shield f a := ⟨propose score thr, rfl⟩

theorem decide_feasible (f : Facts) (score thr : Int) :
    feasible f (tier0Decide f score thr) = true := shield_feasible f _

end Chio.Wave12.Envelope
```

## 5. Kani bit-precise harnesses

All harnesses live in `#[cfg(kani)] mod kani_wave12` inside the same file. The hasher is a deterministic toy; by W12.4 none of the properties depend on hash strength, only on determinism.

```rust
#[cfg(kani)]
mod kani_wave12 {
    use super::*;

    struct XorHasher;
    impl NodeHasher for XorHasher {
        fn hash_pair(&self, left: &Digest, right: &Digest) -> Digest {
            let mut out = [0u8; DIGEST_LEN];
            for ((o, l), r) in out.iter_mut().zip(left.iter()).zip(right.iter()) {
                *o = l.rotate_left(1) ^ *r;
            }
            out
        }
    }

    // §1 saturation
    #[kani::proof]
    fn sat_add_is_exact_or_saturated() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        let r = FixedQ16_16::from_raw(a).sat_add(FixedQ16_16::from_raw(b)).raw();
        match a.checked_add(b) {
            Some(exact) => assert_eq!(r, exact),
            None => assert!(r == i32::MAX || r == i32::MIN),
        }
    }

    #[kani::proof]
    fn sat_mul_wide_never_overflows() {
        let a: i32 = kani::any();
        let b: i32 = kani::any();
        assert!((a as i64).checked_mul(b as i64).is_some());
        let r = FixedQ16_16::from_raw(a).sat_mul(FixedQ16_16::from_raw(b)).raw() as i64;
        let exact = ((a as i64) * (b as i64)) >> 16;
        assert_eq!(r, exact.clamp(i32::MIN as i64, i32::MAX as i64));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn penalty_never_increases_score() {
        let base = FixedQ16_16::from_raw(kani::any());
        let prices = ShadowPrices { lambda: [FixedQ16_16::from_raw(kani::any()); SHADOW_PRICE_DIM] };
        let violation = ViolationVector { g: [FixedQ16_16::from_raw(kani::any()); SHADOW_PRICE_DIM] };
        for l in prices.lambda.iter() { kani::assume(l.is_nonneg()); }
        for g in violation.g.iter() { kani::assume(g.is_nonneg()); }
        assert!(penalized_score(base, &prices, &violation) <= base);
    }

    // §2 epochs (bound to the shipped classify_time_window_code)
    #[kani::proof]
    fn epoch_rank_monotone_in_now() {
        let (issued_at, expires_at): (u64, u64) = (kani::any(), kani::any());
        let (n1, n2): (u64, u64) = (kani::any(), kani::any());
        kani::assume(issued_at <= expires_at);
        kani::assume(n1 <= n2);
        let r1 = lifecycle_rank(classify_time_window_code(n1, issued_at, expires_at));
        let r2 = lifecycle_rank(classify_time_window_code(n2, issued_at, expires_at));
        assert!(r1 <= r2);
        assert_ne!(epoch_transition(n1, n2, issued_at, expires_at), EpochTransition::Regress);
        assert_ne!(window_k3(n1, n2, issued_at, expires_at), K3::Bot);
    }

    #[kani::proof]
    fn empty_window_never_valid_pins_half_open() {
        let (now, t): (u64, u64) = (kani::any(), kani::any());
        assert_ne!(classify_time_window_code(now, t, t), WINDOW_VALID);
    }

    #[kani::proof]
    fn unbounded_encoding_expires_on_last_tick() {
        let issued_at: u64 = kani::any();
        assert!(window_is_unbounded_encoding(u64::MAX));
        assert_eq!(classify_time_window_code(u64::MAX, issued_at, u64::MAX), WINDOW_EXPIRED);
    }

    // §3 attenuation
    #[kani::proof]
    fn attenuate_le_min() {
        let (p, s): (u16, u16) = (kani::any(), kani::any());
        kani::assume(p <= MAX_BUDGET_SHARE_BPS && s <= MAX_BUDGET_SHARE_BPS);
        let a = attenuate_bps(p, s).expect("in-cap inputs always attenuate");
        assert!(a <= p && a <= s);
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn chain_summary_never_exceeds_root() {
        let root: RootAuthority = kani::any();
        let chain: [AttenuationWitness; 4] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 4);
        if let Ok(s) = check_chain(&root, &chain[..len]) {
            assert!(s.effective_bps <= MAX_BUDGET_SHARE_BPS);
            assert!(s.units_cap <= root.units_cap);
            assert!(s.expires_at <= root.expires_at);
            assert_eq!(s.hops, len);
        }
    }

    // §4 inclusion
    #[kani::proof]
    #[kani::unwind(3)]
    fn inclusion_out_of_range_index_is_bot() {
        let (leaf, root): (Digest, Digest) = (kani::any(), kani::any());
        let path: [Digest; 2] = kani::any();
        let index: u64 = kani::any();
        kani::assume(index >= 4);
        assert_eq!(verify_inclusion(&XorHasher, &leaf, index, &path, &root), K3::Bot);
    }

    #[kani::proof]
    fn inclusion_nil_path_iff_leaf_eq_root() {
        let (leaf, root): (Digest, Digest) = (kani::any(), kani::any());
        let k = verify_inclusion(&XorHasher, &leaf, 0, &[], &root);
        assert_eq!(k == K3::Pos, leaf == root);
        assert_ne!(k, K3::Bot);
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn tier0_depth_cap_defers_to_hold() {
        let (leaf, root): (Digest, Digest) = (kani::any(), kani::any());
        let path: [Digest; 9] = kani::any();
        let k = verify_inclusion_tier0(&XorHasher, &leaf, 0, &path, &root);
        assert_eq!(k, K3::Bot);
        let facts = Tier0Facts { weights_inclusion: k, time: kani::any(), budget_ok: kani::any() };
        let out = tier0_decide(&facts, FixedQ16_16::from_raw(kani::any()), FixedQ16_16::from_raw(kani::any()));
        assert_ne!(out, Tier0Action::Allow);
    }

    // §4 envelope: the learned choice is pure nondeterminism
    #[kani::proof]
    fn envelope_preserved_for_any_learned_choice() {
        let facts: Tier0Facts = kani::any();
        let proposed: Tier0Action = kani::any();
        let env = exact_envelope(&facts);
        let out = shield(&env, proposed);
        assert!(env.contains(out));
        assert!(env.contains(Tier0Action::Hold));
        if out == Tier0Action::Allow {
            assert!(facts.weights_inclusion == K3::Pos && facts.time == K3::Pos && facts.budget_ok);
        }
    }
}
```

The score-free harness `envelope_preserved_for_any_learned_choice` subsumes every score-indexed one: by W12.5(4), `tier0_decide` factors through `shield` at some proposal, and the harness ranges over all proposals.

## 6. Creusot layer for the unbounded cases

Kani's chain harness is bounded at four hops. The Lean induction already covers every length, but a Creusot annotation gives a second unbounded discharge at the Rust level with no runtime cost. The attributes are gated so the ordinary build is unaffected.

```rust
#[cfg_attr(creusot, creusot_contracts::requires(parent@ <= 10000 && share@ <= 10000))]
#[cfg_attr(creusot, creusot_contracts::ensures(result@ <= parent@ && result@ <= share@))]
pub fn attenuate_bps_total(parent: u16, share: u16) -> u16 {
    // Both inputs are in cap by precondition, so the product fits in u32 and the quotient in u16.
    attenuate_bps(parent, share).unwrap_or(0)
}

#[cfg_attr(creusot, creusot_contracts::requires(prev_now@ <= now@ && issued_at@ <= expires_at@))]
#[cfg_attr(creusot, creusot_contracts::ensures(result != EpochTransition::Regress))]
pub fn epoch_transition_forward(prev_now: u64, now: u64, issued_at: u64, expires_at: u64) -> EpochTransition {
    epoch_transition(prev_now, now, issued_at, expires_at)
}
```

The `@` operator is Creusot's model view; the postconditions are the Rust-level statements of W12.3 and W12.2(1). The `unwrap_or(0)` default is unreachable under the precondition and keeps the function total for callers outside the proof.

## 7. Proof manifest additions

Appended to `formal/proof-manifest.toml`; every entry is new.

```toml
[[lemma]]
id = "wave12.fixed.penalty_never_increases"
rust = "chio-kernel-core::formal_wave12::penalized_score"
kani = "kani_wave12::penalty_never_increases_score"
lean = "Chio.Wave12.FixedSat.penalize_le"
depends_on_envelope = true

[[lemma]]
id = "wave12.epoch.rank_monotone"
rust = "chio-kernel-core::formal_wave12::epoch_transition"
kani = "kani_wave12::epoch_rank_monotone_in_now"
lean = "Chio.Wave12.Epoch.rank_mono"
creusot = "formal_wave12::epoch_transition_forward"
convention_pin = "kani_wave12::empty_window_never_valid_pins_half_open"

[[lemma]]
id = "wave12.attenuation.chain_le_root"
rust = "chio-kernel-core::formal_wave12::check_chain"
kani = "kani_wave12::chain_summary_never_exceeds_root"
lean = ["Chio.Wave12.Attenuation.effective_le_root", "Chio.Wave12.Attenuation.foldl_antitone"]
creusot = "formal_wave12::attenuate_bps_total"

[[lemma]]
id = "wave12.merkle.k3_soundness"
rust = "chio-kernel-core::formal_wave12::verify_inclusion"
kani = ["kani_wave12::inclusion_out_of_range_index_is_bot", "kani_wave12::inclusion_nil_path_iff_leaf_eq_root"]
lean = ["Chio.Wave12.Merkle.verify_pos_sound", "Chio.Wave12.Merkle.verify_nil"]

[[lemma]]
id = "wave12.envelope.preservation_transfer"
rust = "chio-kernel-core::formal_wave12::tier0_decide"
kani = "kani_wave12::envelope_preserved_for_any_learned_choice"
lean = ["Chio.Wave12.Envelope.decide_feasible", "Chio.Wave12.Envelope.allow_sound"]
transfer = "learned choice modeled as kani::any / ∃ a"
```

## 8. Where each proof sits in the Verification Transfer argument

The transfer theorem says that if a property holds for the shielded projection under unconstrained nondeterministic choice, it holds for every predictor. This pass instantiates it four times:

- **Saturation.** The score is an `i32`. `penalize_le` and the Kani harness bound it for every raw value, so the envelope never needs to know whether the micro-model saturated.
- **Epochs.** `window_k3` turns a clock regression into $\bot$, and $\bot$ excludes `Allow`. The predictor cannot vote a regressed clock into validity.
- **Attenuation.** The chain checker is exact and total. A predictor that proposes `Allow` on a child whose witness claims more authority than its parent is projected to `Hold` because `check_chain` fails and `budget_ok` is false.
- **Inclusion.** A deep or malformed proof is $\bot$, not $-$. The Tier-0 path defers rather than denies, which is what `GuardPipeline`'s sticky `PendingApproval` state consumes downstream.

## Recap

This pass adds one `#![no_std]`, `#![forbid(unsafe_code)]` module with checked arithmetic throughout, eleven Kani harnesses, four Lean 4 files, and two Creusot-annotated wrappers, all strictly additive to the pinned proof manifest. The proven facts are: saturating Q16.16 penalties never raise a score and stay antitone in the shadow prices; the window lifecycle is monotone in the clock, empty windows are never valid, and the `u64::MAX` "unbounded" encoding expires on the last tick; multi-hop attenuation witnesses fold to authority, unit caps, and expiries that never exceed the root, and an expired root cannot be revived by a descendant; Merkle inclusion yields $\bot$ on malformed or over-budget proofs and $+$ only on an exact root match. All of it is closed by one envelope theorem: the Tier-0 decision factors through `shield` at some proposed action, so every proof ranges over three actions and never over a score. Two items need a human decision: the half-open window convention is pinned by a Kani harness that must pass against the shipped classifier, and the `u64::MAX` expiry edge should be either rejected at issuance or mapped to an explicit no-expiry flag.

---

# Verbatim Treatise - `wave12_angle_2_copley_dag_optimization_and_simd_bitset_pass_12`

\&\, nw) \mid (rn \,\&\, pw)$. Then $T = 0$ iff every literal of the clause located in this word has value $+$, and $F \ne 0$ iff some literal in this word has value $-$.

*Proof.* Bit $i$ of $T$ is set iff $(rp_i \wedge \lnot pw_i) \vee (rn_i \wedge \lnot nw_i)$. A positive literal at $i$ has value $+$ iff $pw_i = 1$. A negated literal at $i$ has value $\neg\rho(i) = +$ iff $\rho(i) = -$ iff $nw_i = 1$. So bit $i$ of $T$ is set iff the literal at $i$ exists and is not $+$, which gives the first claim. Bit $i$ of $F$ is set iff a positive literal sees $nw_i = 1$, meaning value $-$, or a negated literal sees $pw_i = 1$, meaning value $\neg(+) = -$. $\square$ Mechanized as `wordStep_true_iff` and `wordStep_false_iff` below.

**Theorem 1, clause.** After the end step of an interned clause $c$, the committed bit $t_c$ equals $[\llbracket c \rrbracket\rho = +]$ and $f_c$ equals $[\llbracket c \rrbracket\rho = -]$.

*Proof.* The accumulators are zero at the start of the clause, because the previous end step cleared them and the schedule begins with zero. Between resets they are only OR-ed, so at the end step $\text{acc}_t = \bigvee_w T_w$ and $\text{acc}_f = \bigvee_w F_w$ over the words emitted for $c$, by the fold lemma `foldl_or_eq_zero`. Hence $\text{acc}_t = 0$ iff all literals of $c$ are $+$, which is the Kleene condition for $\llbracket c \rrbracket = +$, and $\text{acc}_f \ne 0$ iff some literal is $-$, the condition for $\llbracket c \rrbracket = -$. The commit gate multiplies by the end flag, so no intermediate step writes a set bit. $\square$

**Theorem 2, rule.** After the end step of rule $r$, the bits written at index $576 + r$ are $[\llbracket r \rrbracket = +]$ and $[\llbracket r \rrbracket = -]$. The accumulator pair is initialized to $(0, 1)$, OR-folds $t_c$ and AND-folds $f_c$ over the rule's clauses, and is reset to $(0, 1)$ by the end mask. A Kleene disjunction is $+$ iff some disjunct is $+$ and $-$ iff all disjuncts are $-$. $\square$

**Theorem 3, consistency.** $I_{\text{reg}}$ holds after every rule write. By Lemma 1 applied with the induction hypothesis on the atoms read, if $t_c = 1$ then every literal of $c$ is $+$, so none is $-$ and $f_c = 0$; therefore a rule with some $t_c = 1$ has the AND-fold equal to zero. Mechanized as `wordStep_consistent`. $\square$

**Theorem 4, DAG correctness with interning.** For every rank, the final register bits equal $\rho^\ast(576 + r)$. By strong induction on layer: a clause at layer $L$ names only rules of depth below $L$, which were finalized in the rule phase of an earlier layer and are never written again. Interning is sound because the denotation of a clause depends only on its literal set, and canonicalization preserves that set. $\square$

**Theorem 5, rank short-circuit.** The HushSpec interpreter scans rules in rank order and returns at the first Deny rule whose value is $+$. The encoder returns `first_set` of the fired Deny bits. Processing words from high to low and replacing the candidate whenever a word is nonzero leaves the lowest nonzero word's trailing-zero count, which is the minimum set rank. Both sides equal $\min\{r : \text{fired}_r \wedge \text{deny}_r\}$ or the sentinel. Mechanized as `Inv` in the Apalache module and `first_set_is_min_rank` in Kani. $\square$

**Theorem 6, refinement monotonicity.** Order $\mathbb{K}_3$ by information, $\bot \sqsubseteq +$ and $\bot \sqsubseteq -$. Strong Kleene connectives are monotone in this order, so the DAG denotation is monotone, and the fired and refuted vectors can only grow when predicate bits are added. Consequently Deny stays Deny, Allow stays Allow, and only Pending can change. Widening any threshold pair removes predicate bits, so a more conservative threshold policy can move verdicts only toward Pending, never from Deny to Allow. This is the formal content of the fallback $\bot_x$ being refinable but never reversible.

## 3. WCET, mechanized artifacts, and differential tests

**Theorem 7, exact instruction count.** For a well-formed DAG $G$, `evaluate` executes exactly $N_W(G)$ word steps and $N_R(G)$ rule steps, where

$$N_W(G) = \sum_{c \in \text{Canon}(G)} |\text{words}(c)|, \qquad N_R(G) = \sum_{r} |\text{clauses}(r)|,$$

plus exactly $P$ quantization iterations and four encode iterations. None of these counts depends on the register file, because every loop bound is a field of the schedule and every loop body is straight-line. The bounds are

$$N_W(G) \le |\text{Canon}(G)| \cdot \min(K, 13) \le R \cdot D \cdot K, \qquad N_R(G) \le R \cdot D,$$

since a clause with at most $K$ distinct atoms touches at most $K$ register words and interning only merges clauses. Both bounds are attained by any DAG with $R \cdot D$ pairwise distinct clauses, each holding one literal in each of nine distinct predicate words, which exists because each word offers sixty-four atoms.

| Count | Bound | Attained |
|---|---|---|
| Distinct clauses | 2,124 | yes |
| Word steps | 19,116 | yes |
| Rule steps | 2,124 | yes |
| Layers | 236 | yes, by a rank chain |

**Cycle model.** Per-step costs are microarchitectural constants, not theorems. The CI gate runs `llvm-mca` on the two step bodies and fails if the measured reciprocal throughput exceeds the pinned ceilings below. Under those ceilings the worst-shape bound follows by multiplication.

| Phase | Steps | Ceiling cycles/step | Cycles |
|---|---|---|---|
| Quantize | 537 | 6 | 3,222 |
| Word steps | 19,116 | 8 | 152,928 |
| Rule steps | 2,124 | 6 | 12,744 |
| Encode and clear | fixed | fixed | 128 |
| Total | | | 169,022 |

At a 3 GHz clock the worst shape finishes in about 56 microseconds, inside the Tier-1 budget with a wide margin. The Tier-0 slot admits a schedule only when its realized `ScheduleStats`, multiplied by the pinned ceilings, fits the 800 nanosecond deadline; that admission check is a cold comparison in the manifest loader, not a runtime branch. A corollary of input independence is constant time: the evaluation leaks nothing about which predicates fired through its duration.

**Lean 4 kernel lemmas.** File `formal/lean4/Chio/CopleyBitset.lean`, registered additively in `formal/proof-manifest.toml`.

```lean
import Std.Tactic.BVDecide

namespace Chio.Copley

theorem wordStep_true_iff (pw nw rp rn : BitVec 64) :
    ((rp &&& ~~~pw) ||| (rn &&& ~~~nw)) = 0#64 ↔ (rp &&& pw = rp ∧ rn &&& nw = rn) := by
  bv_decide

theorem wordStep_false_iff (pw nw rp rn : BitVec 64) :
    ((rp &&& nw) ||| (rn &&& pw)) ≠ 0#64 ↔ (rp &&& nw ≠ 0#64 ∨ rn &&& pw ≠ 0#64) := by
  bv_decide

theorem wordStep_consistent (pw nw rp rn : BitVec 64) (h : pw &&& nw = 0#64) :
    ((rp &&& ~~~pw) ||| (rn &&& ~~~nw)) = 0#64 → ((rp &&& nw) ||| (rn &&& pw)) = 0#64 := by
  bv_decide

theorem nz_zero : ((0#64 ||| -0#64) >>> 63) = 0#64 := by bv_decide
theorem nz_pos (x : BitVec 64) (h : x ≠ 0#64) : ((x ||| -x) >>> 63) = 1#64 := by bv_decide

theorem ge63_spec (p t : BitVec 64) (hp : p.msb = false) (ht : t.msb = false) :
    (1#64 ^^^ ((p - t) >>> 63)) = 1#64 ↔ t ≤ p := by
  bv_decide

theorem or_eq_zero_iff (a x : BitVec 64) : a ||| x = 0#64 ↔ a = 0#64 ∧ x = 0#64 := by bv_decide

/-- Accumulating with OR: the fold is zero iff the seed and every word are zero. -/
theorem foldl_or_eq_zero (xs : List (BitVec 64)) :
    ∀ acc, xs.foldl (· ||| ·) acc = 0#64 ↔ acc = 0#64 ∧ ∀ x ∈ xs, x = 0#64 := by
  induction xs with
  | nil => intro acc; simp
  | cons x xs ih =>
    intro acc
    simp only [List.foldl, List.mem_cons, forall_eq_or_imp]
    rw [ih, or_eq_zero_iff]
    constructor
    · rintro ⟨⟨ha, hx⟩, hs⟩; exact ⟨ha, hx, hs⟩
    · rintro ⟨ha, hx, hs⟩; exact ⟨⟨ha, hx⟩, hs⟩

end Chio.Copley
```

**Kani harnesses.** These quantify over the full input space, which is the verification-transfer discipline: the predictor is `kani::any()`.

```rust
#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn nz_is_indicator() { let x: u64 = kani::any(); assert_eq!(nz(x), u64::from(x != 0)); }

    #[kani::proof]
    fn ge63_lt63_agree_with_compare() {
        let (p, t): (u64, u64) = (kani::any(), kani::any());
        kani::assume(p < 1 << 63 && t < 1 << 63);
        assert_eq!(ge63(p, t), u64::from(p >= t));
        assert_eq!(lt63(p, t), u64::from(p < t));
    }

    #[kani::proof]
    fn word_step_is_kleene_conjunction() {
        let (pw, nw, rp, rn): (u64, u64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(pw & nw == 0 && rp & rn == 0);
        let t = (rp & !pw) | (rn & !nw);
        let f = (rp & nw) | (rn & pw);
        assert_eq!(t == 0, rp & pw == rp && rn & nw == rn);
        assert_eq!(f != 0, rp & nw != 0 || rn & pw != 0);
        assert!(!(t == 0 && f != 0));
    }

    #[kani::proof]
    #[kani::unwind(257)]
    fn first_set_is_min_rank() {
        let ws: [u64; RULE_WORDS] = kani::any();
        let mut expect = NO_RULE;
        for i in (0..256usize).rev() {
            if (ws[i >> 6] >> (i & 63)) & 1 == 1 { expect = i as u16; }
        }
        assert_eq!(first_set(&ws), expect);
    }

    /// Full-schedule equivalence on a fixed three-rule DAG with symbolic predicate words;
    /// also proves no panic is reachable, which certifies the masked indexing and the dead `unwrap_or` arms.
    #[kani::proof]
    #[kani::unwind(64)]
    fn small_schedule_matches_reference() {
        let dag = fixtures::three_rule_dag();
        let mut sc = compile::CompileScratch::new();
        let mut sched: CompiledSchedule<32, 8> = CompiledSchedule::EMPTY;
        compile::compile(&dag, &mut sc, &mut sched).unwrap();
        let mut regs = K3Regs::EMPTY;
        for w in 0..PRED_WORDS { regs.pos[w] = kani::any(); regs.neg[w] = kani::any(); }
        kani::assume(regs.consistent());
        let expected = reference::verdict(&regs, &dag);
        let got = sched.evaluate(&mut regs);
        assert_eq!((got.code, got.attributed_rank, got.fired, got.refuted), expected);
    }
}
```

**Apalache inductive invariant for Theorem 5.** File `formal/tla/CopleyRankEncode.tla`.

```tla
---------------------------- MODULE CopleyRankEncode ----------------------------
EXTENDS Integers
CONSTANT R
VARIABLES fired, deny, i, result, pc

Ranks == 0..(R-1)
None  == R
Match(r) == fired[r] /\ deny[r]

\* Branch-free side: minimum matching rank, or None.
Encode == IF \E r \in Ranks : Match(r)
          THEN CHOOSE r \in Ranks : Match(r) /\ \A q \in Ranks : Match(q) => r <= q
          ELSE None

ConstInit == R = 236
Init == /\ fired \in [Ranks -> BOOLEAN] /\ deny \in [Ranks -> BOOLEAN]
        /\ i = 0 /\ result = None /\ pc = "scan"

\* HushSpec side: first-match scan with short-circuit return.
Scan == /\ pc = "scan"
        /\ IF i >= R THEN pc' = "done" /\ UNCHANGED <<i, result>>
           ELSE IF Match(i) THEN result' = i /\ pc' = "done" /\ UNCHANGED i
           ELSE i' = i + 1 /\ UNCHANGED <<result, pc>>
        /\ UNCHANGED <<fired, deny>>
Done == pc = "done" /\ UNCHANGED <<fired, deny, i, result, pc>>
Next == Scan \/ Done

Inv == /\ i \in 0..R
       /\ \A q \in 0..(i-1) : ~Match(q)
       /\ pc = "scan" => result = None
       /\ pc = "done" => result = Encode
================================================================================
```

Checked with `apalache-mc check --init=Init --next=Next --inv=Inv` and, for inductiveness, with `--init=Inv --length=1 --inv=Inv`. The scanned prefix has no match, so the first match found is the minimum, and exhausting the scan proves no match exists.

**Differential equivalence tests.** The crate carries a reference interpreter that is the semantic twin of the HushSpec IR: memoized recursive strong-Kleene evaluation over the symbolic DAG, first-match scan in rank order, sticky Pending. The `chio-policy` side implements `HushSpecLowering` and runs the identical harness against its own interpreter, so both the lowering and the compiler are covered. Generated DAGs draw a random topological permutation, reference only earlier rules in that permutation, and randomize rank independently, which exercises the decoupling of evaluation order from bit layout.

```rust
#[cfg(test)]
mod differential {
    extern crate std;
    use super::*;
    use super::compile::*;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)] enum K3 { Pos, Neg, Bot }
    fn not(a: K3) -> K3 { match a { K3::Pos => K3::Neg, K3::Neg => K3::Pos, K3::Bot => K3::Bot } }
    fn and(a: K3, b: K3) -> K3 { match (a, b) { (K3::Neg, _) | (_, K3::Neg) => K3::Neg, (K3::Pos, K3::Pos) => K3::Pos, _ => K3::Bot } }
    fn or(a: K3, b: K3) -> K3 { match (a, b) { (K3::Pos, _) | (_, K3::Pos) => K3::Pos, (K3::Neg, K3::Neg) => K3::Neg, _ => K3::Bot } }

    fn atom(regs: &K3Regs, dag: &CopleyDag, a: u16, memo: &mut [Option<K3>; RULES]) -> K3 {
        if (a as usize) < PREDICATES {
            let (w, b) = ((a as usize) >> 6, a & 63);
            return match ((regs.pos[w] >> b) & 1, (regs.neg[w] >> b) & 1) { (1, _) => K3::Pos, (_, 1) => K3::Neg, _ => K3::Bot };
        }
        rule(regs, dag, (a - RULE_ATOM_BASE) as usize, memo)
    }
    fn rule(regs: &K3Regs, dag: &CopleyDag, r: usize, memo: &mut [Option<K3>; RULES]) -> K3 {
        if let Some(v) = memo[r] { return v; }
        let rl = &dag.rules[r];
        let v = rl.clauses.iter().take(rl.len as usize).fold(K3::Neg, |acc, cl| {
            let c = cl.lits.iter().take(cl.len as usize).fold(K3::Pos, |a, l| {
                let x = atom(regs, dag, l.atom, memo); and(a, if l.negated { not(x) } else { x })
            });
            or(acc, c)
        });
        memo[r] = Some(v); v
    }
    /// HushSpec observable: (code, first firing Deny rank, fired, refuted).
    pub fn verdict(regs: &K3Regs, dag: &CopleyDag) -> (u8, u16, [u64; RULE_WORDS], [u64; RULE_WORDS]) {
        let mut memo = [None; RULES];
        let (mut fired, mut refuted) = ([0u64; RULE_WORDS], [0u64; RULE_WORDS]);
        let (mut first, mut pending) = (NO_RULE, false);
        for r in 0..RULES {
            let v = rule(regs, dag, r, &mut memo);
            let (w, b) = (r >> 6, r & 63);
            if v == K3::Pos { fired[w] |= 1 << b; }
            if v == K3::Neg { refuted[w] |= 1 << b; }
            match (dag.rules[r].band, v) {
                (Band::Deny, K3::Pos) => { if first == NO_RULE { first = r as u16; } }
                (Band::Deny, K3::Bot) | (Band::Pending, K3::Pos) | (Band::Pending, K3::Bot) => pending = true,
                _ => {}
            }
        }
        let code = if first != NO_RULE { Verdict::DENY } else if pending { Verdict::PENDING } else { Verdict::ALLOW };
        (code, first, fired, refuted)
    }

    struct Rng(u64);
    impl Rng { fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 } }

    fn gen_regs(rng: &mut Rng) -> K3Regs {
        let mut regs = K3Regs::EMPTY;
        for j in 0..PREDICATES {
            let (w, b) = (j >> 6, j & 63);
            match rng.next() % 3 { 0 => regs.pos[w] |= 1 << b, 1 => regs.neg[w] |= 1 << b, _ => {} }
        }
        regs
    }

    fn gen_dag(rng: &mut Rng) -> CopleyDag {
        let empty = SymClause { lits: [Lit { atom: 0, negated: false }; MAX_LITERALS], len: 0 };
        let mut rules = [SymRule { band: Band::Deny, clauses: [empty; MAX_CLAUSES_PER_RULE], len: 0 }; RULES];
        let mut topo: [usize; RULES] = core::array::from_fn(|i| i);
        for i in (1..RULES).rev() { topo.swap(i, (rng.next() as usize) % (i + 1)); }
        for pos in 0..RULES {
            let r = topo[pos];
            let rl = &mut rules[r];
            rl.band = if rng.next() % 2 == 0 { Band::Deny } else { Band::Pending };
            rl.len = 1 + (rng.next() % MAX_CLAUSES_PER_RULE as u64) as u8;
            for c in 0..rl.len as usize {
                let n = 1 + (rng.next() % MAX_LITERALS as u64) as usize;
                let mut k = 0;
                while k < n {
                    let a = if pos > 0 && rng.next() % 4 == 0 { RULE_ATOM_BASE + topo[(rng.next() as usize) % pos] as u16 }
                            else { (rng.next() % PREDICATES as u64) as u16 };
                    if rl.clauses[c].lits[..k].iter().any(|l| l.atom == a) { continue; }
                    rl.clauses[c].lits[k] = Lit { atom: a, negated: rng.next() % 2 == 0 }; k += 1;
                }
                rl.clauses[c].len = n as u8;
            }
        }
        SymbolicRuleDag { rules }
    }

    #[test]
    fn compiled_schedule_matches_reference_interpreter() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut sc = std::boxed::Box::new(CompileScratch::new());
        let mut sched = std::boxed::Box::new(CompiledSchedule::<MAX_WORD_STEPS, MAX_RULE_STEPS>::EMPTY);
        for _ in 0..64 {
            let dag = gen_dag(&mut rng);
            compile(&dag, &mut sc, &mut sched).expect("generated DAG is well-formed");
            for _ in 0..256 {
                let base = gen_regs(&mut rng);
                let mut regs = base;
                let got = sched.evaluate(&mut regs);
                assert_eq!((got.code, got.attributed_rank, got.fired, got.refuted), verdict(&base, &dag));
                assert!(regs.consistent());
            }
        }
    }

    #[test]
    fn worst_shape_attains_exact_bound() {
        let dag = fixtures::max_shape_dag();
        let mut sc = std::boxed::Box::new(CompileScratch::new());
        let mut sched = std::boxed::Box::new(CompiledSchedule::<MAX_WORD_STEPS, MAX_RULE_STEPS>::EMPTY);
        let stats = compile(&dag, &mut sc, &mut sched).unwrap();
        assert_eq!((stats.distinct_clauses as usize, stats.word_steps as usize, stats.rule_steps as usize), (MAX_CLAUSES, MAX_WORD_STEPS, MAX_RULE_STEPS));
    }

    #[test]
    fn interning_merges_shared_clauses() {
        let dag = fixtures::shared_clause_dag(); // two rules, one identical clause
        let mut sc = std::boxed::Box::new(CompileScratch::new());
        let mut sched = std::boxed::Box::new(CompiledSchedule::<MAX_WORD_STEPS, MAX_RULE_STEPS>::EMPTY);
        assert_eq!(compile(&dag, &mut sc, &mut sched).unwrap().distinct_clauses, 1);
    }

    #[test]
    fn cycles_and_contradictions_are_rejected() {
        assert!(matches!(compile_fixture(fixtures::two_cycle_dag()), Err(CompileError::Cycle { .. })));
        assert!(matches!(compile_fixture(fixtures::contradictory_dag()), Err(CompileError::ContradictoryClause { .. })));
    }
}
```

**Integration constraints, all additive.**

- **New crate** `crates/kernel/chio-copley-bitset` with the same lint posture as `budget_split.rs`. No existing signature in sections B through E changes.
- **Guard adapter** in `chio-guards` wraps `evaluate` as one `Guard`. Code 2 maps to `Verdict::Deny` with evidence details carrying the attributed rank, code 1 to `Verdict::PendingApproval`, code 0 to `Verdict::Allow`, so the pipeline's sticky-Pending and Deny-return behavior is preserved by construction.
- **Receipt binding** keeps `RESERVED_RECEIPT_METADATA_KEYS` at thirty-five entries. The schedule digest, threshold digest, and realized `ScheduleStats` live as sub-keys under the already reserved `model_metadata` namespace, and the digests are compared next to `loaded_weights_hash` inside the existing `evaluate_weights_binding` flow through a wrapper, not a signature change.
- **Proof manifest** gains the Lean file, the five Kani harnesses, the Apalache module, and the two `llvm-mca` ceilings. A ceiling regression or a count above the Theorem 7 bound fails the build before any artifact is signed.

The recap for a reader arriving here: the compiler turns the 537-predicate, 236-rule DAG into interned clauses scheduled by topological layer with bits laid out by rank; the evaluator is straight-line bit arithmetic whose trip counts are schedule constants; correctness reduces to word-level bit-vector lemmas discharged by `bv_decide` and lifted by the fold and layer inductions; Kani covers the primitives, the priority encoder, panic freedom, and bounded whole-schedule equivalence; Apalache covers first-match equivalence; the differential harness covers random DAGs against the HushSpec-equivalent interpreter; and the exact worst case is nineteen thousand one hundred sixteen word steps plus two thousand one hundred twenty-four rule steps, attained and never exceeded. What remains outside this document is binding the concrete HushSpec IR types to `HushSpecLowering` inside `chio-policy` and recording the measured `llvm-mca` ceilings for the target cores in the manifest.

---

# Verbatim Treatise - `wave12_angle_3_concurrent_loom_and_dst_crash_recovery_pass_12`

## 3. Harness layout: one `sync` shim, four models, one scheduler

The models under test live in `crates/kernel/chio-kernel/src/concurrency/` and are compiled twice: once against `core::sync::atomic` and `std::sync` for production, once against `loom::sync` under `--cfg loom`. Nothing else changes between the two builds, so the loom exploration is over the production control flow, not over a hand-written abstraction of it. The only component that is swapped rather than modeled is the `arc-swap` register, which has its own upstream loom suite; here it is replaced by a mutex-guarded `Arc` that is an atomic register by construction, and the protocol around it is what we verify.

```toml
# crates/kernel/chio-kernel/Cargo.toml  (additive)
[target.'cfg(loom)'.dependencies]
loom = { version = "0.7", features = ["checkpoint"] }

[[test]]
name = "loom_concurrency"

[[test]]
name = "dst_drop_simulation"
```

```rust
// crates/kernel/chio-kernel/src/concurrency/sync.rs
//! Primitives re-exported from `loom` under `--cfg loom`, otherwise from core/std.
#[cfg(loom)]
pub use loom::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex,
};
#[cfg(loom)]
pub use loom::thread;

#[cfg(not(loom))]
pub use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(not(loom))]
pub use std::sync::{Arc, Mutex};
#[cfg(not(loom))]
pub use std::thread;
```

```rust
// crates/kernel/chio-kernel/src/concurrency/mod.rs
#![forbid(unsafe_code)]
pub mod holder_gauge;
pub mod nonce_store;
pub mod session_op;
pub mod sync;
pub mod weight_epoch;
```

**Model 1: `WeightEpoch` register.** The hazard is a torn binding: `evaluate_weights_binding` checks a model-card hash and a weights hash, and the receipt's `model_metadata` records an epoch. If any two of those three come from different loads, a hot-swap in between produces a receipt that attests weights that were never evaluated. The fix is structural: the three fields travel in one immutable snapshot, and `bind` performs exactly one `load`.

```rust
// crates/kernel/chio-kernel/src/concurrency/weight_epoch.rs
use super::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WeightEpoch {
    pub epoch: u64,
    pub model_card_hash: [u8; 32],
    pub weights_hash: [u8; 32],
}

impl WeightEpoch {
    pub const fn genesis() -> Self {
        Self { epoch: 0, model_card_hash: [0; 32], weights_hash: [0; 32] }
    }
    /// The only sanctioned successor constructor: epoch increments are checked.
    pub fn successor(&self, model_card_hash: [u8; 32], weights_hash: [u8; 32]) -> Option<Self> {
        Some(Self { epoch: self.epoch.checked_add(1)?, model_card_hash, weights_hash })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochPublishError {
    NonSuccessive { current: u64, offered: u64 },
    EpochOverflow,
}

pub trait EpochRegister {
    fn load(&self) -> Arc<WeightEpoch>;
    /// Publishes `next` iff `next.epoch == current.epoch + 1`; returns the displaced snapshot.
    fn publish(&self, next: Arc<WeightEpoch>) -> Result<Arc<WeightEpoch>, EpochPublishError>;
}

/// Evidence derived from exactly one snapshot. This is the whole anti-tearing discipline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingEvidence {
    pub epoch: u64,
    pub model_card_hash: [u8; 32],
    pub weights_hash: [u8; 32],
}

pub fn bind(register: &dyn EpochRegister) -> BindingEvidence {
    let s = register.load();
    BindingEvidence { epoch: s.epoch, model_card_hash: s.model_card_hash, weights_hash: s.weights_hash }
}

/// Reference register: trivially an atomic register. Used under `cfg(loom)` and as the
/// differential oracle against `ArcSwapRegister` in the std test suite.
pub struct LockedRegister {
    inner: Mutex<Arc<WeightEpoch>>,
}

impl LockedRegister {
    pub fn new(initial: Arc<WeightEpoch>) -> Self {
        Self { inner: Mutex::new(initial) }
    }
}

impl EpochRegister for LockedRegister {
    fn load(&self) -> Arc<WeightEpoch> {
        Arc::clone(&self.inner.lock().expect("register poisoned"))
    }
    fn publish(&self, next: Arc<WeightEpoch>) -> Result<Arc<WeightEpoch>, EpochPublishError> {
        let mut slot = self.inner.lock().expect("register poisoned");
        let expected = slot.epoch.checked_add(1).ok_or(EpochPublishError::EpochOverflow)?;
        if next.epoch != expected {
            return Err(EpochPublishError::NonSuccessive { current: slot.epoch, offered: next.epoch });
        }
        Ok(core::mem::replace(&mut *slot, next))
    }
}

#[cfg(not(loom))]
pub struct ArcSwapRegister {
    inner: arc_swap::ArcSwap<WeightEpoch>,
}

#[cfg(not(loom))]
impl EpochRegister for ArcSwapRegister {
    fn load(&self) -> Arc<WeightEpoch> {
        self.inner.load_full()
    }
    fn publish(&self, next: Arc<WeightEpoch>) -> Result<Arc<WeightEpoch>, EpochPublishError> {
        let mut current = self.inner.load();
        loop {
            let expected = current.epoch.checked_add(1).ok_or(EpochPublishError::EpochOverflow)?;
            if next.epoch != expected {
                return Err(EpochPublishError::NonSuccessive { current: current.epoch, offered: next.epoch });
            }
            let previous = self.inner.compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                return Ok(Arc::clone(&previous));
            }
            current = previous;
        }
    }
}
```

The successor check matters for the decision-model law. A loader that lost a race and still publishes would silently roll the predictor back to an older $\theta_\ell$ while the receipts claim the newer epoch. Rejecting non-successive publishes makes the epoch sequence a total order that every reader observes monotonically.

**Model 2: `ExecutionNonceStore` slot.** The first design kept owner and state in two atomics. Loom finds its bug with a single preemption: owner A reserves, rolls back, owner B reserves, and a stale second rollback from A compares `state == RESERVED && owner == A` against a stale owner word and frees B's reservation. The repair packs both into one `u64` so that every transition is one compare-exchange and the linearization point is unambiguous.

```rust
// crates/kernel/chio-kernel/src/concurrency/nonce_store.rs
use super::sync::{AtomicU32, AtomicU64, Ordering};

pub const NONCE_FREE: u8 = 0;
pub const NONCE_RESERVED: u8 = 1;
pub const NONCE_COMMITTED: u8 = 2;
pub const NO_OWNER: u32 = u32::MAX;
const OWNER_SHIFT: u32 = 8;
const STATE_MASK: u64 = 0xFF;

#[inline]
pub const fn pack(owner: u32, state: u8) -> u64 {
    // A shift of 8 on a 64-bit word cannot fail; the fallback arm is unreachable.
    match (owner as u64).checked_shl(OWNER_SHIFT) {
        Some(hi) => hi | (state as u64),
        None => state as u64,
    }
}

#[inline]
pub const fn unpack(word: u64) -> (u32, u8) {
    let owner = match word.checked_shr(OWNER_SHIFT) {
        Some(v) => v as u32,
        None => NO_OWNER,
    };
    (owner, (word & STATE_MASK) as u8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceOutcome {
    Reserved,
    AlreadyReserved { owner: u32 },
    AlreadyCommitted,
    Rejected,
}

pub struct NonceSlot {
    word: AtomicU64,
}

impl Default for NonceSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceSlot {
    pub fn new() -> Self {
        Self { word: AtomicU64::new(pack(NO_OWNER, NONCE_FREE)) }
    }

    pub fn reserve(&self, owner: u32) -> NonceOutcome {
        if owner == NO_OWNER {
            return NonceOutcome::Rejected;
        }
        match self.word.compare_exchange(
            pack(NO_OWNER, NONCE_FREE),
            pack(owner, NONCE_RESERVED),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => NonceOutcome::Reserved,
            Err(observed) => match unpack(observed) {
                (o, NONCE_RESERVED) => NonceOutcome::AlreadyReserved { owner: o },
                (_, NONCE_COMMITTED) => NonceOutcome::AlreadyCommitted,
                _ => NonceOutcome::Rejected,
            },
        }
    }

    pub fn commit(&self, owner: u32) -> bool {
        self.word
            .compare_exchange(pack(owner, NONCE_RESERVED), pack(owner, NONCE_COMMITTED), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn rollback(&self, owner: u32) -> bool {
        self.word
            .compare_exchange(pack(owner, NONCE_RESERVED), pack(NO_OWNER, NONCE_FREE), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn state(&self) -> u8 {
        unpack(self.word.load(Ordering::SeqCst)).1
    }
}

/// Monotone owner tickets. Never reused and never equal to `NO_OWNER`; exhaustion refuses sessions.
pub struct OwnerTickets {
    next: AtomicU32,
}

impl OwnerTickets {
    pub fn new() -> Self {
        Self { next: AtomicU32::new(0) }
    }
    pub fn issue(&self) -> Option<u32> {
        let mut cur = self.next.load(Ordering::Relaxed);
        loop {
            if cur == NO_OWNER {
                return None;
            }
            let bumped = cur.checked_add(1)?;
            match self.next.compare_exchange_weak(cur, bumped, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(cur),
                Err(seen) => cur = seen,
            }
        }
    }
}
```

Owner uniqueness is what makes the packed word sufficient. Two distinct sessions never share a ticket, so a stale `(owner, RESERVED)` expectation can never match a fresh reservation by someone else. The Lean lemma in §5 pins the injectivity of `pack` that this argument rests on.

**Model 3: `HolderGauge`.** `ChildAdmission.holders` is authoritative and lives under the `BudgetSplit` mutex, where it increments with checked arithmetic and surfaces `HolderCountOverflow`. The Tier-0 `lambda_escrow` path cannot take that lock in its nanosecond budget, so it reads a lock-free mirror. The mirror must never underflow and must respect the cap. `fetch_add` and `fetch_sub` cannot promise either, hence the compare-exchange loops.

```rust
// crates/kernel/chio-kernel/src/concurrency/holder_gauge.rs
use super::sync::{AtomicU32, Ordering};

/// Lock-free upper bound on `ChildAdmission::holders`, consulted by the Tier-0 escrow shadow price.
/// Volatile by design: rebuilt from the authoritative `BudgetSplit` on recovery (see `dst_drop_simulation`).
pub struct HolderGauge {
    count: AtomicU32,
    cap: u32,
}

impl HolderGauge {
    pub fn new(cap: u32) -> Self {
        Self { count: AtomicU32::new(0), cap }
    }

    pub fn try_acquire(&self) -> bool {
        let mut cur = self.count.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(1).filter(|n| *n <= self.cap) else { return false };
            match self.count.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }

    pub fn release(&self) -> bool {
        let mut cur = self.count.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_sub(1) else { return false };
            match self.count.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }

    pub fn load(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}
```

**Model 4: `SessionOperation` cutpoints.** The states map onto the `GuardPipeline` contract from §D: `Allow` moves C0 to C1, `revalidate_before_dispatch` moves C1 into dispatch, `validate_output_before_release` moves C2 to C3. A `Deny` or sticky `PendingApproval` never calls `guards_allowed`, so those paths stay at C0 and settle as cancellations.

```rust
// crates/kernel/chio-kernel/src/concurrency/session_op.rs
use super::sync::{AtomicBool, AtomicU8, Ordering};
use chio_kernel_core::formal_aeneas::{ledger_apply, ReservationLedger};

pub const OP_PENDING: u8 = 0; //  C0: guard pipeline not yet run
pub const OP_GUARDED: u8 = 1; //  C1: pipeline Allow, awaiting revalidate_before_dispatch
pub const OP_DISPATCHING: u8 = 2; // side effects may be occurring
pub const OP_DISPATCHED: u8 = 3; // C2: awaiting validate_output_before_release
pub const OP_RELEASED: u8 = 4; //  C3: terminal
pub const OP_CANCELLED: u8 = 5; // terminal, never dispatched
pub const OP_WITHHELD: u8 = 6; //  terminal, dispatched, output never released

pub const LEDGER_RESERVE: u8 = 0;
pub const LEDGER_COMMIT: u8 = 1;
pub const LEDGER_RELEASE: u8 = 2;
pub const LEDGER_RETAIN: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled,
    Withheld,
    /// Dispatch was in flight; the dispatcher will withhold. Caller treats this as `Withheld`.
    Deferred,
    TooLate,
    Repeated,
}

pub struct SessionOperation {
    state: AtomicU8,
    cancel_requested: AtomicBool,
}

impl Default for SessionOperation {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionOperation {
    pub fn new() -> Self {
        Self { state: AtomicU8::new(OP_PENDING), cancel_requested: AtomicBool::new(false) }
    }

    // SeqCst throughout: `cancel_requested` and `state` are two locations read in opposite
    // orders by the two threads (store-buffering shape). AcqRel is insufficient here.
    fn cas(&self, from: u8, to: u8) -> bool {
        self.state.compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    pub fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    pub fn guards_allowed(&self) -> bool {
        self.cas(OP_PENDING, OP_GUARDED)
    }

    pub fn begin_dispatch(&self) -> bool {
        self.cas(OP_GUARDED, OP_DISPATCHING)
    }

    /// Returns the state the dispatcher must act on: `OP_DISPATCHED` permits `release`.
    pub fn end_dispatch(&self) -> u8 {
        let _ = self.cas(OP_DISPATCHING, OP_DISPATCHED);
        if self.cancel_requested.load(Ordering::SeqCst) {
            let _ = self.cas(OP_DISPATCHED, OP_WITHHELD);
        }
        self.state()
    }

    pub fn release(&self) -> bool {
        self.cas(OP_DISPATCHED, OP_RELEASED)
    }

    pub fn cancel(&self) -> CancelOutcome {
        if self.cancel_requested.swap(true, Ordering::SeqCst) {
            return CancelOutcome::Repeated;
        }
        if self.cas(OP_PENDING, OP_CANCELLED) || self.cas(OP_GUARDED, OP_CANCELLED) {
            return CancelOutcome::Cancelled;
        }
        if self.cas(OP_DISPATCHED, OP_WITHHELD) {
            return CancelOutcome::Withheld;
        }
        match self.state() {
            OP_DISPATCHING | OP_DISPATCHED => CancelOutcome::Deferred,
            OP_WITHHELD => CancelOutcome::Withheld,
            OP_CANCELLED => CancelOutcome::Cancelled,
            _ => CancelOutcome::TooLate,
        }
    }
}

/// Terminal settlement through the production ledger arithmetic.
pub fn settle(ledger: ReservationLedger, terminal: u8, amount: u64) -> Option<ReservationLedger> {
    let (next, ok) = match terminal {
        OP_CANCELLED => ledger_apply(ledger, LEDGER_RELEASE, amount),
        OP_RELEASED => ledger_apply(ledger, LEDGER_COMMIT, amount),
        OP_WITHHELD => {
            let (committed, ok) = ledger_apply(ledger, LEDGER_COMMIT, amount);
            if !ok {
                return None;
            }
            ledger_apply(committed, LEDGER_RETAIN, amount)
        }
        _ => return None,
    };
    ok.then_some(next)
}
```

The `Deferred` arm encodes the pre-dispatch versus post-dispatch asymmetry exactly. A cancel that lands while `OP_DISPATCHING` cannot undo the side effect, so it does not pretend to; it guarantees instead that the output is withheld, and the ledger commits and retains rather than releasing. The flag is written before any compare-exchange in `cancel` and read after the dispatcher's own compare-exchange in `end_dispatch`. With SeqCst on both locations that ordering is a theorem; with AcqRel it is the classic store-buffering litmus test and the dispatcher may release output after a cancel was acknowledged.

## 4. `crates/kernel/chio-kernel/tests/loom_concurrency.rs`

Each test runs under `loom::model`, which explores every interleaving up to the preemption bound. Three spawned threads plus the main thread is loom's default ceiling, and the tests stay within it.

```rust
#![cfg(loom)]
#![forbid(unsafe_code)]

use chio_kernel::concurrency::holder_gauge::HolderGauge;
use chio_kernel::concurrency::nonce_store::{NonceOutcome, NonceSlot, NONCE_COMMITTED, NONCE_FREE};
use chio_kernel::concurrency::session_op::{
    settle, CancelOutcome, SessionOperation, LEDGER_RESERVE, OP_CANCELLED, OP_DISPATCHED, OP_RELEASED, OP_WITHHELD,
};
use chio_kernel::concurrency::sync::{thread, Arc, AtomicU32, Mutex, Ordering};
use chio_kernel::concurrency::weight_epoch::{bind, EpochRegister, LockedRegister, WeightEpoch};
use chio_kernel_core::formal_aeneas::ReservationLedger;

fn epoch(n: u64) -> WeightEpoch {
    let tag = u8::try_from(n).unwrap_or(u8::MAX);
    WeightEpoch { epoch: n, model_card_hash: [tag; 32], weights_hash: [tag.saturating_mul(7); 32] }
}

/// W1 (atomicity): every observed (epoch, card, weights) triple was published as a unit.
/// W2 (per-reader monotonicity): a reader never sees the epoch go backwards.
#[test]
fn weight_epoch_publish_is_linearizable() {
    loom::model(|| {
        let register = Arc::new(LockedRegister::new(Arc::new(epoch(0))));
        let published: Arc<Mutex<Vec<WeightEpoch>>> = Arc::new(Mutex::new(vec![epoch(0)]));

        let writer = {
            let (register, published) = (Arc::clone(&register), Arc::clone(&published));
            thread::spawn(move || {
                for n in 1..=2u64 {
                    // Log before publishing so that observed ⊆ logged is the right direction.
                    published.lock().unwrap().push(epoch(n));
                    register.publish(Arc::new(epoch(n))).expect("successive epoch accepted");
                }
            })
        };

        let readers: Vec<_> = (0..2)
            .map(|_| {
                let (register, published) = (Arc::clone(&register), Arc::clone(&published));
                thread::spawn(move || {
                    let first = bind(&*register);
                    let second = bind(&*register);
                    assert!(first.epoch <= second.epoch, "W2 violated: {} then {}", first.epoch, second.epoch);
                    let log = published.lock().unwrap();
                    for e in [first, second] {
                        assert!(
                            log.iter().any(|p| p.epoch == e.epoch
                                && p.weights_hash == e.weights_hash
                                && p.model_card_hash == e.model_card_hash),
                            "W1 violated: torn binding evidence at epoch {}",
                            e.epoch
                        );
                    }
                })
            })
            .collect();

        writer.join().unwrap();
        for r in readers {
            r.join().unwrap();
        }
        assert_eq!(register.load().epoch, 2);
        assert!(register.publish(Arc::new(epoch(5))).is_err(), "skipped epoch must be rejected");
    });
}

/// N1 (mutual exclusion): between a successful `reserve` and its `commit`/`rollback`, no other
/// owner holds the nonce. N2: committed is absorbing. N3: a rollback frees exactly one reservation.
fn nonce_race(winner_rolls_back: bool) {
    loom::model(move || {
        let slot = Arc::new(NonceSlot::new());
        let holders = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = [1u32, 2u32]
            .into_iter()
            .map(|owner| {
                let (slot, holders) = (Arc::clone(&slot), Arc::clone(&holders));
                thread::spawn(move || {
                    let out = slot.reserve(owner);
                    if out == NonceOutcome::Reserved {
                        assert_eq!(holders.fetch_add(1, Ordering::SeqCst), 0, "N1 violated by owner {owner}");
                        assert!(!slot.commit(owner.checked_add(10).unwrap()), "foreign owner committed");
                        if winner_rolls_back {
                            holders.fetch_sub(1, Ordering::SeqCst);
                            assert!(slot.rollback(owner), "owner lost its own reservation");
                            assert!(!slot.rollback(owner), "double rollback accepted");
                        } else {
                            assert!(slot.commit(owner), "owner lost its own reservation");
                            assert!(!slot.rollback(owner), "rollback after commit accepted (N2)");
                        }
                    }
                    out
                })
            })
            .collect();

        let outcomes: Vec<NonceOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let wins = outcomes.iter().filter(|o| **o == NonceOutcome::Reserved).count();

        if winner_rolls_back {
            assert!(wins >= 1);
            assert_eq!(slot.state(), NONCE_FREE, "N3 violated");
            assert_eq!(slot.reserve(3), NonceOutcome::Reserved);
        } else {
            assert_eq!(wins, 1, "two owners held one nonce");
            assert_eq!(slot.state(), NONCE_COMMITTED);
            assert_eq!(slot.reserve(3), NonceOutcome::AlreadyCommitted, "N2 violated");
        }
    });
}

#[test]
fn nonce_reservation_commit_is_linearizable() {
    nonce_race(false);
}

#[test]
fn nonce_reservation_rollback_is_linearizable() {
    nonce_race(true);
}

/// B1: the gauge never exceeds `cap` and never underflows. B2: every acquire is matched, so the
/// gauge returns to zero. Three contenders on a cap of two forces at least one refusal path.
#[test]
fn holder_gauge_refcounts_are_exact() {
    loom::model(|| {
        let gauge = Arc::new(HolderGauge::new(2));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let gauge = Arc::clone(&gauge);
                thread::spawn(move || {
                    if gauge.try_acquire() {
                        assert!(gauge.load() <= 2, "B1 violated: cap exceeded");
                        assert!(gauge.release(), "release of a held slot failed");
                    }
                    assert!(!gauge.release() || gauge.load() < 2, "unbalanced release succeeded");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

/// S1: `OP_CANCELLED` implies zero side effects. S2: `OP_WITHHELD` implies exactly one side effect
/// and zero deliveries. S3: `OP_RELEASED` implies the canceller observed `TooLate`.
/// S4: the settled ledger conserves `reserved == committed + released` with `retained <= committed`.
#[test]
fn cancellation_is_linearizable_at_every_cutpoint() {
    loom::model(|| {
        let op = Arc::new(SessionOperation::new());
        let effects = Arc::new(AtomicU32::new(0));
        let delivered = Arc::new(AtomicU32::new(0));

        let dispatcher = {
            let (op, effects, delivered) = (Arc::clone(&op), Arc::clone(&effects), Arc::clone(&delivered));
            thread::spawn(move || {
                if !op.guards_allowed() {
                    return; // cancelled at C0
                }
                if !op.begin_dispatch() {
                    return; // cancelled at C1
                }
                effects.fetch_add(1, Ordering::SeqCst); // the irreversible act
                if op.end_dispatch() == OP_DISPATCHED && op.release() {
                    delivered.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        let canceller = {
            let op = Arc::clone(&op);
            thread::spawn(move || op.cancel())
        };

        dispatcher.join().unwrap();
        let outcome = canceller.join().unwrap();
        let (state, eff, del) = (op.state(), effects.load(Ordering::SeqCst), delivered.load(Ordering::SeqCst));

        match state {
            OP_CANCELLED => {
                assert_eq!((eff, del), (0, 0), "S1 violated");
                assert_eq!(outcome, CancelOutcome::Cancelled);
            }
            OP_WITHHELD => {
                assert_eq!((eff, del), (1, 0), "S2 violated");
                assert!(matches!(outcome, CancelOutcome::Withheld | CancelOutcome::Deferred));
            }
            OP_RELEASED => {
                assert_eq!((eff, del), (1, 1));
                assert_eq!(outcome, CancelOutcome::TooLate, "S3 violated");
            }
            other => panic!("non-terminal state {other} after join"),
        }

        let empty = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
        let (reserved, ok) = chio_kernel_core::formal_aeneas::ledger_apply(empty, LEDGER_RESERVE, 7);
        assert!(ok);
        let settled = settle(reserved, state, 7).expect("terminal state settles");
        assert_eq!(settled.committed.checked_add(settled.released), Some(settled.reserved), "S4 violated");
        assert!(settled.retained <= settled.committed, "S4 violated");
    });
}
```

The assertions inside the spawned closures are where loom earns its keep. `holders.fetch_add` returning nonzero is a direct witness of two owners inside the critical region; the per-reader monotonicity check is a direct witness of a register that is not linearizable. Every assertion failure comes with a loom checkpoint that replays the schedule.

## 5. `dst_drop_simulation.rs`, the SQLite recovery contract, and the formal pins

Loom covers thread interleavings in a live process. It cannot cover the process disappearing. Two facts about a killed process shape the recovery contract. First, `Drop` glue never runs, so every RAII guard (holder gauges, nonce reservations, budget reservations) must be treated as volatile and reconstructed from durable state. Second, SQLite in WAL mode with `synchronous=FULL` guarantees that the set of transactions visible after recovery is a prefix of the committed sequence with each transaction all-or-nothing, but it does not guarantee that a transaction whose `COMMIT` returned to the caller before `fsync` completed survives. The simulation models exactly these two facts and nothing stronger.

The durability contract for a session is therefore a single transaction per cutpoint crossing. The dispatch transaction inserts the receipt row and commits the nonce together. The release transaction updates the row to `Released`. A dangling `Dispatched` row found at recovery is repaired to `Withheld`, because `validate_output_before_release` was never durably recorded, and the envelope law says the fallback at C2 is `Hold`, never `Release`.

```rust
// crates/kernel/chio-kernel/tests/dst_drop_simulation.rs
#![forbid(unsafe_code)]

use chio_kernel::concurrency::nonce_store::{NonceOutcome, NonceSlot, NONCE_COMMITTED};
use std::collections::{BTreeMap, BTreeSet};

/// xorshift64*. The single sanctioned use of wrapping arithmetic in this file.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Row {
    Dispatched,
    Released,
    Withheld,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    InsertReceipt { session: u64 },
    CommitNonce { session: u64 },
    MarkReleased { session: u64 },
    MarkWithheld { session: u64 },
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    txn: u32,
    op: Op,
    commit: bool,
    intact: bool,
}

#[derive(Default)]
struct Wal {
    frames: Vec<Frame>,
    durable: usize,
    next_txn: u32,
}

impl Wal {
    fn begin(&mut self) -> u32 {
        let t = self.next_txn;
        self.next_txn = t.checked_add(1).expect("txn ids exhausted");
        t
    }
    fn append(&mut self, txn: u32, op: Op, commit: bool) {
        self.frames.push(Frame { txn, op, commit, intact: true });
    }
    /// `PRAGMA synchronous=FULL`: the commit frame is fsynced before COMMIT returns.
    fn fsync(&mut self) {
        self.durable = self.frames.len();
    }
    /// Power loss. Frames past the durable prefix are kept, lost, or torn at the simulator's choice.
    fn crash(&mut self, rng: &mut Rng) {
        let tail = self.frames.len().saturating_sub(self.durable);
        let tail_u64 = u64::try_from(tail).unwrap_or(0);
        let kept = usize::try_from(rng.below(tail_u64.saturating_add(1))).unwrap_or(0);
        self.frames.truncate(self.durable.saturating_add(kept));
        if kept > 0 && rng.chance(50) {
            let off = usize::try_from(rng.below(u64::try_from(kept).unwrap_or(1))).unwrap_or(0);
            if let Some(f) = self.frames.get_mut(self.durable.saturating_add(off)) {
                f.intact = false; // torn write: salt/checksum chain breaks here
            }
        }
    }
    /// WAL recovery: longest intact prefix, then truncated to the last commit frame.
    fn recover(&mut self) -> Vec<Frame> {
        let intact = self.frames.iter().position(|f| !f.intact).unwrap_or(self.frames.len());
        let keep = self.frames[..intact]
            .iter()
            .rposition(|f| f.commit)
            .map_or(0, |i| i.saturating_add(1));
        self.frames.truncate(keep);
        self.durable = keep;
        self.frames.clone()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Db {
    receipts: BTreeMap<u64, Row>,
    nonces: BTreeMap<u64, u8>,
}

fn replay(frames: &[Frame]) -> Db {
    let mut db = Db::default();
    for f in frames {
        match f.op {
            Op::InsertReceipt { session } => {
                db.receipts.insert(session, Row::Dispatched);
            }
            Op::CommitNonce { session } => {
                db.nonces.insert(session, NONCE_COMMITTED);
            }
            Op::MarkReleased { session } => {
                db.receipts.insert(session, Row::Released);
            }
            Op::MarkWithheld { session } => {
                db.receipts.insert(session, Row::Withheld);
            }
        }
    }
    db
}

/// Crash, recover, repair dangling dispatches to `Withheld`, and check recovery idempotence (R5).
fn crash_and_recover(wal: &mut Wal, rng: &mut Rng, seed: u64) -> Db {
    wal.crash(rng);
    let frames = wal.recover();
    let again = wal.recover();
    assert_eq!(frames.len(), again.len(), "seed {seed}: recovery is not idempotent");
    let db = replay(&frames);
    for (session, row) in &db.receipts {
        if *row == Row::Dispatched {
            let t = wal.begin();
            wal.append(t, Op::MarkWithheld { session: *session }, true);
            wal.fsync();
        }
    }
    replay(&wal.frames)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Crash {
    None,
    C0,
    C1,
    D1, // dispatch txn: receipt frame written, nonce frame not yet
    D2, // dispatch txn: commit frame written, fsync not returned
    C2,
    D3, // release txn: commit frame written, fsync not returned
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Plan {
    Complete,
    CancelAtC0,
    CancelAtC1,
    CancelAtC2,
}

#[derive(Default)]
struct Oracle {
    dispatch_acked: BTreeSet<u64>,
    release_acked: BTreeSet<u64>,
    cancelled_early: BTreeSet<u64>,
    cancelled_late: BTreeSet<u64>,
}

fn pick_crash(rng: &mut Rng) -> Crash {
    match rng.below(14) {
        0 => Crash::C0,
        1 => Crash::C1,
        2 => Crash::D1,
        3 => Crash::D2,
        4 => Crash::C2,
        5 => Crash::D3,
        _ => Crash::None,
    }
}

fn pick_plan(rng: &mut Rng) -> Plan {
    match rng.below(8) {
        0 => Plan::CancelAtC0,
        1 => Plan::CancelAtC1,
        2 => Plan::CancelAtC2,
        _ => Plan::Complete,
    }
}

fn check(seed: u64, db: &Db, oracle: &Oracle) {
    // R1: receipt row <=> committed nonce (same transaction, both directions).
    for s in db.receipts.keys() {
        assert_eq!(db.nonces.get(s), Some(&NONCE_COMMITTED), "seed {seed}: receipt {s} without nonce");
    }
    for s in db.nonces.keys() {
        assert!(db.receipts.contains_key(s), "seed {seed}: committed nonce {s} without receipt");
    }
    // R2: acknowledged work is durable.
    for s in &oracle.dispatch_acked {
        assert!(db.receipts.contains_key(s), "seed {seed}: acked dispatch {s} lost");
    }
    for s in &oracle.release_acked {
        assert_eq!(db.receipts.get(s), Some(&Row::Released), "seed {seed}: acked release {s} lost");
    }
    // R3: pre-dispatch cancellation leaves no durable trace; the nonce is reservable again.
    for s in &oracle.cancelled_early {
        assert!(!db.receipts.contains_key(s) && !db.nonces.contains_key(s), "seed {seed}: cancelled {s} leaked");
    }
    // R4: post-dispatch cancellation is durably withheld, never released.
    for s in &oracle.cancelled_late {
        assert_eq!(db.receipts.get(s), Some(&Row::Withheld), "seed {seed}: late cancel {s} not withheld");
    }
    // R6: the C2 fallback is Hold. No dangling dispatch survives repair.
    for (s, row) in &db.receipts {
        assert_ne!(*row, Row::Dispatched, "seed {seed}: dangling dispatch {s}");
    }
}

fn run_episode(seed: u64, sessions: u64) {
    let mut rng = Rng::new(seed);
    let mut wal = Wal::default();
    let mut volatile: BTreeMap<u64, NonceSlot> = BTreeMap::new();
    let mut oracle = Oracle::default();
    let mut db = Db::default();

    for s in 0..sessions {
        let (plan, crash) = (pick_plan(&mut rng), pick_crash(&mut rng));
        volatile.insert(s, NonceSlot::new());
        assert_eq!(volatile[&s].reserve(1), NonceOutcome::Reserved);

        // A crash discards the process image. No destructor is observed; the gauge and all
        // in-flight reservations vanish. Recovery must not depend on any of them.
        macro_rules! die {
            () => {{
                volatile = BTreeMap::new();
                db = crash_and_recover(&mut wal, &mut rng, seed);
                check(seed, &db, &oracle);
                continue;
            }};
        }

        if crash == Crash::C0 {
            die!();
        }
        if plan == Plan::CancelAtC0 {
            assert!(volatile[&s].rollback(1));
            oracle.cancelled_early.insert(s);
            continue;
        }
        if crash == Crash::C1 {
            die!();
        }
        if plan == Plan::CancelAtC1 {
            assert!(volatile[&s].rollback(1));
            oracle.cancelled_early.insert(s);
            continue;
        }

        let t = wal.begin();
        wal.append(t, Op::InsertReceipt { session: s }, false);
        if crash == Crash::D1 {
            die!();
        }
        wal.append(t, Op::CommitNonce { session: s }, true);
        if crash == Crash::D2 {
            die!();
        }
        wal.fsync();
        assert!(volatile[&s].commit(1));
        oracle.dispatch_acked.insert(s);
        if crash == Crash::C2 {
            die!();
        }

        if plan == Plan::CancelAtC2 {
            let t = wal.begin();
            wal.append(t, Op::MarkWithheld { session: s }, true);
            wal.fsync();
            oracle.cancelled_late.insert(s);
            continue;
        }

        let t = wal.begin();
        wal.append(t, Op::MarkReleased { session: s }, true);
        if crash == Crash::D3 {
            die!();
        }
        wal.fsync();
        oracle.release_acked.insert(s);
    }

    // Final power loss, then the invariants once more over everything.
    db = crash_and_recover(&mut wal, &mut rng, seed);
    check(seed, &db, &oracle);
}

#[test]
fn drop_simulation_episodes() {
    let base: u64 = std::env::var("CHIO_DST_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5a7d_81ec_5b00_0001);
    let episodes: u64 = std::env::var("CHIO_DST_EPISODES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    for i in 0..episodes {
        let seed = base.checked_add(i).expect("seed space exhausted");
        run_episode(seed, 64);
    }
}
```

Every failure message carries the seed, and `CHIO_DST_SEED=<seed> CHIO_DST_EPISODES=1` replays it exactly. The `die!` macro is the Drop model: it replaces the volatile world wholesale, so a nonce that was `RESERVED` in memory is simply gone, and R3 checks that the durable store agrees it was never committed. The D2 and D3 crash points are where naive implementations fail: the commit frame is on disk but `fsync` has not returned. The simulation lets that frame survive or vanish at random, and the oracle only demands durability for work that was acknowledged after `fsync`, which is precisely SQLite's guarantee under `synchronous=FULL`.

**Why the dispatch transaction must contain both rows.** Suppose the nonce commit were a separate transaction after the receipt insert. A crash between them leaves a receipt whose nonce is `FREE`, and the next request with the same nonce replays the dispatch. The reverse order leaves a committed nonce with no receipt, so the operation can never be audited and the budget can never be settled. R1 in both directions is the test that forbids both orderings, and it fails within the first few hundred seeds for either split.

**Apalache specification of the cancellation race.** The TLA+ model is instruction-level: each compare-exchange and each load of the Rust is one action, so the model has the same interleavings as the code rather than a coarser abstraction that could hide a race.

```tla
-------------------------- MODULE SessionCancel --------------------------
EXTENDS Integers

VARIABLES
  \* @type: Int;   state,
  \* @type: Int;   effects,
  \* @type: Bool;  flag,
  \* @type: Bool;  seen,
  \* @type: Str;   pcD,
  \* @type: Str;   pcC,
  \* @type: Str;   result

Pending == 0  Guarded == 1  Dispatching == 2  Dispatched == 3
Released == 4 Cancelled == 5 Withheld == 6

Init == /\ state = Pending /\ effects = 0 /\ flag = FALSE /\ seen = FALSE
        /\ pcD = "guard" /\ pcC = "flag" /\ result = "none"

\* Dispatcher: each action is one CAS or one load in `session_op.rs`.
Guard == /\ pcD = "guard"
         /\ IF state = Pending THEN state' = Guarded /\ pcD' = "reval"
                               ELSE state' = state   /\ pcD' = "done"
         /\ UNCHANGED <<effects, flag, seen, pcC, result>>
Reval == /\ pcD = "reval"
         /\ IF state = Guarded THEN state' = Dispatching /\ pcD' = "effect"
                               ELSE state' = state       /\ pcD' = "done"
         /\ UNCHANGED <<effects, flag, seen, pcC, result>>
Effect == /\ pcD = "effect" /\ effects' = effects + 1 /\ pcD' = "end1"
          /\ UNCHANGED <<state, flag, seen, pcC, result>>
End1 == /\ pcD = "end1" /\ pcD' = "end2"
        /\ IF state = Dispatching THEN state' = Dispatched ELSE state' = state
        /\ UNCHANGED <<effects, flag, seen, pcC, result>>
End2 == /\ pcD = "end2" /\ seen' = flag /\ pcD' = "end3"
        /\ UNCHANGED <<state, effects, flag, pcC, result>>
End3 == /\ pcD = "end3"
        /\ IF seen THEN (IF state = Dispatched THEN state' = Withheld ELSE state' = state) /\ pcD' = "done"
                   ELSE state' = state /\ pcD' = "release"
        /\ UNCHANGED <<effects, flag, seen, pcC, result>>
Release == /\ pcD = "release" /\ pcD' = "done"
           /\ IF state = Dispatched THEN state' = Released ELSE state' = state
           /\ UNCHANGED <<effects, flag, seen, pcC, result>>

\* Canceller: swap, three CASes, one load.
CFlag == /\ pcC = "flag" /\ flag' = TRUE /\ pcC' = "cas1"
         /\ UNCHANGED <<state, effects, seen, pcD, result>>
Cas1 == /\ pcC = "cas1"
        /\ IF state = Pending THEN state' = Cancelled /\ result' = "cancelled" /\ pcC' = "done"
                              ELSE UNCHANGED <<state, result>> /\ pcC' = "cas2"
        /\ UNCHANGED <<effects, flag, seen, pcD>>
Cas2 == /\ pcC = "cas2"
        /\ IF state = Guarded THEN state' = Cancelled /\ result' = "cancelled" /\ pcC' = "done"
                              ELSE UNCHANGED <<state, result>> /\ pcC' = "cas3"
        /\ UNCHANGED <<effects, flag, seen, pcD>>
Cas3 == /\ pcC = "cas3"
        /\ IF state = Dispatched THEN state' = Withheld /\ result' = "withheld" /\ pcC' = "done"
                                 ELSE UNCHANGED <<state, result>> /\ pcC' = "read"
        /\ UNCHANGED <<effects, flag, seen, pcD>>
Read == /\ pcC = "read" /\ pcC' = "done"
        /\ result' = CASE state \in {Dispatching, Dispatched} -> "deferred"
                       [] state = Withheld  -> "withheld"
                       [] state = Cancelled -> "cancelled"
                       [] OTHER             -> "too_late"
        /\ UNCHANGED <<state, effects, flag, seen, pcD>>

Next == Guard \/ Reval \/ Effect \/ End1 \/ End2 \/ End3 \/ Release
        \/ CFlag \/ Cas1 \/ Cas2 \/ Cas3 \/ Read

Terminal == pcD = "done" /\ pcC = "done"

Inv == /\ effects <= 1
       /\ (state = Cancelled => effects = 0)
       /\ (state \in {Dispatched, Released, Withheld} => effects = 1)
       /\ (Terminal => state \in {Cancelled, Released, Withheld})
       /\ (Terminal /\ state = Released  => result = "too_late")
       /\ (Terminal /\ state = Cancelled => result = "cancelled")
       /\ (Terminal /\ state = Withheld  => result \in {"withheld", "deferred"})
=============================================================================
```

```
apalache-mc check --inv=Inv --length=13 --init=Init --next=Next SessionCancel.tla
```

Thirteen steps covers the longest trace, seven dispatcher actions plus six canceller actions. The specification uses interleaving semantics, which is sound for the Rust only because every shared access is SeqCst; this is the formal counterpart of the ordering comment in `session_op.rs`. Weakening to AcqRel would require a weak-memory model that TLA+ does not provide, and loom's exploration of the AcqRel variant is what justified pinning SeqCst in the first place.

**Lean 4: injectivity of the packed nonce word.** The single-CAS argument for `NonceSlot` needs that no two distinct `(owner, state)` pairs collide in the word. The lemma is small and `omega` discharges it.

```lean
-- formal/lean4/Chio/NoncePack.lean
namespace Chio.NoncePack

def pack (owner state : Nat) : Nat := owner * 256 + state

theorem pack_inj {o o' s s' : Nat} (hs : s < 256) (hs' : s' < 256)
    (h : pack o s = pack o' s') : o = o' ∧ s = s' := by
  unfold pack at h
  have h1 : (o * 256 + s) / 256 = o := by omega
  have h2 : (o' * 256 + s') / 256 = o' := by omega
  have h3 : (o * 256 + s) % 256 = s := by omega
  have h4 : (o' * 256 + s') % 256 = s' := by omega
  exact ⟨by rw [← h1, ← h2, h], by rw [← h3, ← h4, h]⟩

/-- A stale rollback expectation `(a, RESERVED)` never matches a fresh reservation
    `(b, RESERVED)` by a different owner. This is the ABA defence of `NonceSlot::rollback`. -/
theorem stale_rollback_misses {a b : Nat} (hab : a ≠ b) :
    pack a 1 ≠ pack b 1 := by
  intro h
  exact hab (pack_inj (by omega) (by omega) h).1

end Chio.NoncePack
```

**Kani harnesses.** Kani verifies the sequential state machines over all inputs; loom verifies their composition under scheduling. Together they cover the two axes without either tool stretching past what it is good at.

```rust
// crates/kernel/chio-kernel/src/concurrency/kani_harness.rs
#[cfg(kani)]
mod harness {
    use super::super::holder_gauge::HolderGauge;
    use super::super::nonce_store::{NonceOutcome, NonceSlot, NO_OWNER};

    #[kani::proof]
    #[kani::unwind(7)]
    fn holder_gauge_tracks_outstanding_and_respects_cap() {
        let cap: u32 = kani::any();
        kani::assume(cap <= 8);
        let gauge = HolderGauge::new(cap);
        let mut outstanding: u32 = 0;
        for _ in 0..5 {
            if kani::any() {
                if gauge.try_acquire() {
                    outstanding = outstanding.checked_add(1).unwrap();
                }
            } else if gauge.release() {
                outstanding = outstanding.checked_sub(1).unwrap();
            }
            assert_eq!(gauge.load(), outstanding);
            assert!(outstanding <= cap);
        }
    }

    #[kani::proof]
    fn nonce_slot_admits_exactly_one_owner() {
        let slot = NonceSlot::new();
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        kani::assume(a != b && a != NO_OWNER && b != NO_OWNER);
        assert_eq!(slot.reserve(a), NonceOutcome::Reserved);
        assert_eq!(slot.reserve(b), NonceOutcome::AlreadyReserved { owner: a });
        assert!(!slot.rollback(b) && !slot.commit(b));
        if kani::any() {
            assert!(slot.commit(a));
            assert!(!slot.rollback(a));
            assert_eq!(slot.reserve(b), NonceOutcome::AlreadyCommitted);
        } else {
            assert!(slot.rollback(a));
            assert!(!slot.rollback(a));
            assert_eq!(slot.reserve(b), NonceOutcome::Reserved);
        }
    }
}
```

**Proof manifest additions.** All entries are new ids; no existing entry in `formal/proof-manifest.toml` is edited, and no existing signature in `formal_aeneas.rs` or `formal_core.rs` changes. The loom tests call `ledger_apply` as a black box, so the Lean and Aeneas obligations already discharged for it carry over unchanged by the Verification Transfer Theorem.

```toml
[[proof]]
id = "loom.weight_epoch.linearizable"
kind = "loom"
target = "crates/kernel/chio-kernel/tests/loom_concurrency.rs::weight_epoch_publish_is_linearizable"
cmd = "RUSTFLAGS='--cfg loom' LOOM_MAX_PREEMPTIONS=3 cargo test -p chio-kernel --release --test loom_concurrency"
properties = ["W1 atomic binding evidence", "W2 per-reader monotonicity", "successor-only publish"]

[[proof]]
id = "loom.nonce_slot.linearizable"
kind = "loom"
target = "crates/kernel/chio-kernel/tests/loom_concurrency.rs::nonce_reservation_{commit,rollback}_is_linearizable"
cmd = "RUSTFLAGS='--cfg loom' LOOM_MAX_PREEMPTIONS=3 cargo test -p chio-kernel --release --test loom_concurrency"
properties = ["N1 mutual exclusion", "N2 committed absorbing", "N3 rollback frees exactly one"]

[[proof]]
id = "loom.holder_gauge.exact"
kind = "loom"
target = "crates/kernel/chio-kernel/tests/loom_concurrency.rs::holder_gauge_refcounts_are_exact"
properties = ["B1 cap and no underflow", "B2 balanced"]

[[proof]]
id = "loom.session_op.cancel_cutpoints"
kind = "loom"
target = "crates/kernel/chio-kernel/tests/loom_concurrency.rs::cancellation_is_linearizable_at_every_cutpoint"
properties = ["S1", "S2", "S3", "S4 ledger conservation via ledger_apply"]
depends_on = ["aeneas.ledger_apply", "tla.session_cancel"]

[[proof]]
id = "tla.session_cancel"
kind = "apalache"
target = "formal/tla/SessionCancel.tla"
cmd = "apalache-mc check --inv=Inv --length=13 SessionCancel.tla"

[[proof]]
id = "lean.nonce_pack_inj"
kind = "lean4"
target = "formal/lean4/Chio/NoncePack.lean"
theorems = ["Chio.NoncePack.pack_inj", "Chio.NoncePack.stale_rollback_misses"]

[[proof]]
id = "kani.holder_gauge"
kind = "kani"
target = "chio_kernel::concurrency::kani_harness::holder_gauge_tracks_outstanding_and_respects_cap"

[[proof]]
id = "kani.nonce_slot"
kind = "kani"
target = "chio_kernel::concurrency::kani_harness::nonce_slot_admits_exactly_one_owner"

[[proof]]
id = "dst.drop_simulation"
kind = "simulation"
target = "crates/kernel/chio-kernel/tests/dst_drop_simulation.rs::drop_simulation_episodes"
cmd = "CHIO_DST_EPISODES=20000 cargo test -p chio-kernel --release --test dst_drop_simulation"
properties = ["R1 receipt<=>nonce", "R2 acked durable", "R3 early cancel leaves no trace", "R4 late cancel withheld", "R5 idempotent recovery", "R6 no dangling dispatch"]
```

**Obligation coverage.**

| Component | Interleaving (loom) | Sequential (Kani) | Crash/Drop (DST) | Formal pin |
|---|---|---|---|---|
| `WeightEpoch` register | W1, W2 | successor check is total | rebuilt from model card at boot | differential oracle vs `arc-swap` |
| `NonceSlot` | N1, N2, N3 | single owner, foreign ops rejected | R1, R3 | Lean `pack_inj` |
| `HolderGauge` | B1, B2 | exact tracking under cap | volatile, rebuilt | `HolderCountOverflow` on authoritative path |
| `SessionOperation` | S1 to S4 | settled via `ledger_apply` | R2, R4, R6 | Apalache `Inv` |

---

**Recap.** This pass adds a `cfg(loom)` shim and four small concurrency models to `chio-kernel`, then verifies them three ways. The loom suite in `loom_concurrency.rs` proves linearizability of the weight-epoch register protocol, the packed single-word nonce slot, the capped holder gauge, and session cancellation at every cutpoint, with the ledger settled through the production `ledger_apply`. Two design decisions came out of the exploration: the nonce slot packs owner and state into one word to defeat an ABA rollback, and the cancellation protocol uses SeqCst because its flag and state form a store-buffering pattern. The deterministic simulation in `dst_drop_simulation.rs` models SQLite WAL recovery under `synchronous=FULL` and process kill, and fixes the durability contract: receipt insert and nonce commit share one transaction, acknowledged work survives, pre-dispatch cancellations leave no trace, and dangling dispatches are repaired to `Withheld`. The Apalache spec, the Lean injectivity lemma, and the Kani harnesses pin the three arguments the tests rely on. All manifest entries are additive and no existing signature or proof changes. Next is Wave 12 Angle 4, which lifts the same cutpoint model to `SwarmTaskGraph` joins, where several `SessionOperation` instances settle against one `SwarmBudgetPool`.

---

# Verbatim Treatise - `wave12_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_12`

I'll lay out the Wave 12 Angle 4 design as a treatise: the lifting law for the three protocol edges, the Tier-0 four-segment feature path, hybrid Ed25519 + ML-DSA-65 receipt signing behind `KernelCryptoFloor`, portable offline verification across federated trust roots, the attestation binding, and the proofs that carry over by the Envelope Preservation theorem.

## 1. The edge instance of the decision model and the lift into `PortableToolCallRequest`

Every protocol edge instantiates the Wave 1 tuple with $\ell = \text{edge}$. The input space $\mathcal{X}_{\text{edge}}$ is the byte-level request of one of three protocols: the Model Context Protocol tool call, the Agent-to-Agent task send, and the Envoy external authorization check. The exact computation $C_{\text{edge}}(x) \in \mathbb{K}_3^{4}$ is the Kleene conjunction of four facts the kernel already solves exactly: the request time window via `classify_time_window_code`, the budget via `budget_precheck`, the caller's trust-root resolution, and the attestation binding. The envelope $\mathcal{C}_{\text{edge}}(x)$ is a subset of $\{\text{Allow}, \text{Defer}, \text{Deny}\}$ that always contains Deny. The predictor is a Tier-0 integer micro-model over sixteen fixed-point features. The projection is a three-way match and therefore $O(1)$.

The lift is a pure renaming of protocol fields onto the four Copley segments, so the same 537 atomic predicates serve all three edges without retraining. The mapping is fixed by the table below and enforced by the constructors that follow.

| Copley segment | Predicates | MCP field | A2A field | Envoy ext_authz field |
|---|---|---|---|---|
| CommandLine | 345 | canonical arguments JSON | message parts | `:path` plus query |
| Image | 97 | tool name | skill id | `:method`, `:authority`, route |
| OriginalFileName | 57 | resource URI | artifact name | content-disposition |
| ParentImage | 38 | server principal | caller agent id | downstream SPIFFE SAN |

SPIFFE is the Secure Production Identity Framework for Everyone, and SAN is the certificate's subject alternative name. The core lives in one shared `#![no_std]` crate that the three std-side edge crates depend on. The kernel's exact functions are imported through a single line; if they live in `formal_core` rather than `formal_aeneas`, only that line changes.

```rust
//! chio-protocol-edges: shared core for chio-mcp-edge, chio-a2a-adapter, chio-envoy-ext-authz.
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use chio_kernel_core::formal_aeneas::{budget_precheck, classify_time_window_code, receipt_fields_coupled};

/// Kleene 3-valued logic. Strong conjunction: `Neg` absorbs, `Bot` is sticky, `Pos` is the unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum K3 { Pos = 0, Neg = 1, Bot = 2 }

impl K3 {
    #[must_use]
    pub const fn and(self, rhs: K3) -> K3 {
        match (self, rhs) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Bot, _) | (_, K3::Bot) => K3::Bot,
            (K3::Pos, K3::Pos) => K3::Pos,
        }
    }
    #[must_use]
    pub const fn from_bool(b: bool) -> K3 { if b { K3::Pos } else { K3::Neg } }
    #[must_use]
    pub const fn from_code(code: u8) -> Option<K3> {
        match code { 0 => Some(K3::Pos), 1 => Some(K3::Neg), 2 => Some(K3::Bot), _ => None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment { CommandLine, Image, OriginalFileName, ParentImage }

impl Segment {
    #[must_use]
    pub const fn predicate_count(self) -> u16 {
        match self {
            Segment::CommandLine => 345,
            Segment::Image => 97,
            Segment::OriginalFileName => 57,
            Segment::ParentImage => 38,
        }
    }
}
pub const COPLEY_PREDICATES: u16 = 537;
const _: () = assert!(345 + 97 + 57 + 38 == COPLEY_PREDICATES);

pub const MAX_SEGMENT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolEdge { Mcp = 1, A2a = 2, EnvoyExtAuthz = 3 }

impl ProtocolEdge {
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code { 1 => Some(Self::Mcp), 2 => Some(Self::A2a), 3 => Some(Self::EnvoyExtAuthz), _ => None }
    }
    /// `(invocation_cost, unit_cost)` handed to `budget_precheck`.
    #[must_use]
    pub const fn costs(self) -> (u64, u64) {
        match self { Self::Mcp => (1, 4), Self::A2a => (1, 8), Self::EnvoyExtAuthz => (1, 1) }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PortableToolCallRequest<'a> {
    pub edge: ProtocolEdge,
    pub command_line: &'a [u8],
    pub image: &'a [u8],
    pub original_file_name: &'a [u8],
    pub parent_image: &'a [u8],
    pub capability_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiftError {
    SegmentTooLong { segment: Segment, len: usize },
    EmptyPrincipal,
    InvertedWindow { issued_at: u64, expires_at: u64 },
}

fn bounded<'a>(segment: Segment, bytes: &'a [u8]) -> Result<&'a [u8], LiftError> {
    if bytes.len() > MAX_SEGMENT_BYTES {
        Err(LiftError::SegmentTooLong { segment, len: bytes.len() })
    } else {
        Ok(bytes)
    }
}

impl<'a> PortableToolCallRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn lift(
        edge: ProtocolEdge,
        command_line: &'a [u8],
        image: &'a [u8],
        original_file_name: &'a [u8],
        parent_image: &'a [u8],
        capability_id: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, LiftError> {
        if parent_image.is_empty() { return Err(LiftError::EmptyPrincipal); }
        if expires_at < issued_at { return Err(LiftError::InvertedWindow { issued_at, expires_at }); }
        Ok(Self {
            edge,
            command_line: bounded(Segment::CommandLine, command_line)?,
            image: bounded(Segment::Image, image)?,
            original_file_name: bounded(Segment::OriginalFileName, original_file_name)?,
            parent_image: bounded(Segment::ParentImage, parent_image)?,
            capability_id, issued_at, expires_at,
        })
    }
}

pub trait LiftToPortable<'a> {
    fn lift(&self) -> Result<PortableToolCallRequest<'a>, LiftError>;
}

pub struct McpToolCall<'a> {
    pub server_principal: &'a [u8], pub tool_name: &'a [u8],
    pub arguments_canonical_json: &'a [u8], pub resource_uri: &'a [u8],
    pub capability_id: [u8; 32], pub issued_at: u64, pub expires_at: u64,
}
impl<'a> LiftToPortable<'a> for McpToolCall<'a> {
    fn lift(&self) -> Result<PortableToolCallRequest<'a>, LiftError> {
        PortableToolCallRequest::lift(ProtocolEdge::Mcp, self.arguments_canonical_json, self.tool_name,
            self.resource_uri, self.server_principal, self.capability_id, self.issued_at, self.expires_at)
    }
}

pub struct A2aTaskSend<'a> {
    pub caller_agent_id: &'a [u8], pub skill_id: &'a [u8],
    pub message_parts: &'a [u8], pub artifact_name: &'a [u8],
    pub capability_id: [u8; 32], pub issued_at: u64, pub expires_at: u64,
}
impl<'a> LiftToPortable<'a> for A2aTaskSend<'a> {
    fn lift(&self) -> Result<PortableToolCallRequest<'a>, LiftError> {
        PortableToolCallRequest::lift(ProtocolEdge::A2a, self.message_parts, self.skill_id,
            self.artifact_name, self.caller_agent_id, self.capability_id, self.issued_at, self.expires_at)
    }
}

pub struct EnvoyCheckRequest<'a> {
    pub downstream_spiffe_san: &'a [u8], pub method_authority_route: &'a [u8],
    pub path_and_query: &'a [u8], pub content_disposition: &'a [u8],
    pub capability_id: [u8; 32], pub issued_at: u64, pub expires_at: u64,
}
impl<'a> LiftToPortable<'a> for EnvoyCheckRequest<'a> {
    fn lift(&self) -> Result<PortableToolCallRequest<'a>, LiftError> {
        PortableToolCallRequest::lift(ProtocolEdge::EnvoyExtAuthz, self.path_and_query, self.method_authority_route,
            self.content_disposition, self.downstream_spiffe_san, self.capability_id, self.issued_at, self.expires_at)
    }
}
```

**Tier-0 features and the shielded decision.** Each segment yields four `FixedQ16_16` ratios in the unit interval: fill against the segment cap, the non-printable byte share, the shell-separator share, and the digit share. The micro-model scores the sixteen features and subtracts the Lagrangian penalty $\boldsymbol{\lambda}^\top g$, where $g$ is the five-vector of resource pressures. Every operation is checked. An overflow is read as $\bot$ and never as a verdict. Thresholds are constructed only when $\tau^{\text{neg}} \le \tau^{\text{pos}}$, which keeps the three bands disjoint and ordered.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(pub i32);

const Q_SCALE: i64 = 65_536;

impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(65_536);
    pub fn checked_add(self, rhs: Self) -> Option<Self> { self.0.checked_add(rhs.0).map(Self) }
    pub fn checked_sub(self, rhs: Self) -> Option<Self> { self.0.checked_sub(rhs.0).map(Self) }
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(rhs.0))?.checked_div(Q_SCALE)?;
        i32::try_from(wide).ok().map(Self)
    }
    /// `n / d` clamped to `[0, ONE]`. `None` iff `d == 0`.
    pub fn unit_ratio(n: usize, d: usize) -> Option<Self> {
        if d == 0 { return None; }
        let n = u64::try_from(n).ok()?;
        let d = u64::try_from(d).ok()?;
        let scaled = n.checked_mul(65_536)?.checked_div(d)?;
        let clamped = if scaled > 65_536 { 65_536 } else { scaled };
        i32::try_from(clamped).ok().map(Self)
    }
}

pub const FEATURES_PER_SEGMENT: usize = 4;
pub const FEATURE_COUNT: usize = 16;

fn byte_class_counts(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    let (mut nonprint, mut sep, mut digit) = (0usize, 0usize, 0usize);
    for &b in bytes {
        if !(0x20..=0x7e).contains(&b) { nonprint = nonprint.checked_add(1)?; }
        else if matches!(b, b' ' | b';' | b'|' | b'&' | b'/' | b'\\' | b'`' | b'$') { sep = sep.checked_add(1)?; }
        else if b.is_ascii_digit() { digit = digit.checked_add(1)?; }
    }
    Some((nonprint, sep, digit))
}

fn segment_features(bytes: &[u8]) -> Option<[FixedQ16_16; FEATURES_PER_SEGMENT]> {
    let fill = FixedQ16_16::unit_ratio(bytes.len(), MAX_SEGMENT_BYTES)?;
    if bytes.is_empty() {
        return Some([fill, FixedQ16_16::ZERO, FixedQ16_16::ZERO, FixedQ16_16::ZERO]);
    }
    let (nonprint, sep, digit) = byte_class_counts(bytes)?;
    Some([
        fill,
        FixedQ16_16::unit_ratio(nonprint, bytes.len())?,
        FixedQ16_16::unit_ratio(sep, bytes.len())?,
        FixedQ16_16::unit_ratio(digit, bytes.len())?,
    ])
}

pub fn extract_features(req: &PortableToolCallRequest<'_>) -> Option<[FixedQ16_16; FEATURE_COUNT]> {
    let segs = [req.command_line, req.image, req.original_file_name, req.parent_image];
    let mut out = [FixedQ16_16::ZERO; FEATURE_COUNT];
    for (i, seg) in segs.iter().enumerate() {
        let f = segment_features(seg)?;
        let base = i.checked_mul(FEATURES_PER_SEGMENT)?;
        for (j, v) in f.iter().enumerate() {
            *out.get_mut(base.checked_add(j)?)? = *v;
        }
    }
    Some(out)
}

#[derive(Clone, Copy, Debug)]
pub struct ShadowPrices {
    pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16,
    pub memory: FixedQ16_16, pub escrow: FixedQ16_16,
}
pub type ResourcePressure = ShadowPrices;

#[derive(Clone, Copy, Debug)]
pub struct Thresholds { tau_neg: FixedQ16_16, tau_pos: FixedQ16_16 }
impl Thresholds {
    pub fn new(tau_neg: FixedQ16_16, tau_pos: FixedQ16_16) -> Option<Self> {
        if tau_neg <= tau_pos { Some(Self { tau_neg, tau_pos }) } else { None }
    }
}

pub struct EdgeMicroModel {
    pub weights: [FixedQ16_16; FEATURE_COUNT],
    pub bias: FixedQ16_16,
    pub thresholds: Thresholds,
}

impl EdgeMicroModel {
    fn dot(a: &[FixedQ16_16], b: &[FixedQ16_16]) -> Option<FixedQ16_16> {
        let mut acc = FixedQ16_16::ZERO;
        for (x, w) in a.iter().zip(b.iter()) { acc = acc.checked_add(x.checked_mul(*w)?)?; }
        Some(acc)
    }
    pub fn score(&self, f: &[FixedQ16_16; FEATURE_COUNT], lambda: &ShadowPrices, g: &ResourcePressure) -> Option<FixedQ16_16> {
        let raw = Self::dot(f, &self.weights)?.checked_add(self.bias)?;
        let lam = [lambda.budget, lambda.fuel, lambda.latency, lambda.memory, lambda.escrow];
        let use_ = [g.budget, g.fuel, g.latency, g.memory, g.escrow];
        raw.checked_sub(Self::dot(&lam, &use_)?)
    }
    /// Role-asymmetric reading: `+` at or above tau_pos, `-` at or below tau_neg, else `⊥`.
    pub fn predict(&self, f: &[FixedQ16_16; FEATURE_COUNT], lambda: &ShadowPrices, g: &ResourcePressure) -> K3 {
        match self.score(f, lambda, g) {
            None => K3::Bot,
            Some(s) if s >= self.thresholds.tau_pos => K3::Pos,
            Some(s) if s <= self.thresholds.tau_neg => K3::Neg,
            Some(_) => K3::Bot,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeAction { Allow = 0, Defer = 1, Deny = 2 }
impl EdgeAction {
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code { 0 => Some(Self::Allow), 1 => Some(Self::Defer), 2 => Some(Self::Deny), _ => None }
    }
    #[must_use]
    pub const fn from_preference(p: K3) -> Self {
        match p { K3::Pos => Self::Allow, K3::Bot => Self::Defer, K3::Neg => Self::Deny }
    }
}

/// Feasible envelope. `Deny` is always a member; the constructor is crate-private.
#[derive(Clone, Copy, Debug)]
pub struct Envelope { allow: bool, defer: bool }
impl Envelope {
    #[must_use]
    pub const fn from_exact(exact: K3) -> Self {
        match exact {
            K3::Pos => Self { allow: true, defer: true },
            K3::Bot => Self { allow: false, defer: true },
            K3::Neg => Self { allow: false, defer: false },
        }
    }
    #[must_use]
    pub const fn contains(&self, a: EdgeAction) -> bool {
        match a { EdgeAction::Allow => self.allow, EdgeAction::Defer => self.defer, EdgeAction::Deny => true }
    }
}

/// Only `project` constructs this, so every `ShieldedAction` is inside its envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedAction { action: EdgeAction }
impl ShieldedAction { #[must_use] pub const fn action(self) -> EdgeAction { self.action } }

/// Ceiling in the conservativeness order Allow < Defer < Deny. O(1).
#[must_use]
pub const fn project(env: &Envelope, preferred: EdgeAction) -> ShieldedAction {
    if env.contains(preferred) { ShieldedAction { action: preferred } }
    else if env.defer { ShieldedAction { action: EdgeAction::Defer } }
    else { ShieldedAction { action: EdgeAction::Deny } }
}

#[derive(Clone, Copy, Debug)]
pub struct ExactInputs {
    pub now: Option<u64>,
    pub remaining_invocations: u64,
    pub remaining_units: u64,
    pub caller_root: K3,
    pub attestation: K3,
}

pub fn exact_admission(req: &PortableToolCallRequest<'_>, inputs: &ExactInputs) -> K3 {
    let window = match inputs.now {
        Some(now) => K3::from_bool(classify_time_window_code(now, req.issued_at, req.expires_at) == 0),
        None => K3::Bot,
    };
    let (invocation_cost, unit_cost) = req.edge.costs();
    let budget = K3::from_bool(budget_precheck(inputs.remaining_invocations, inputs.remaining_units, invocation_cost, unit_cost));
    window.and(budget).and(inputs.caller_root).and(inputs.attestation)
}

pub fn decide(req: &PortableToolCallRequest<'_>, inputs: &ExactInputs, model: &EdgeMicroModel,
              lambda: &ShadowPrices, g: &ResourcePressure) -> ShieldedAction {
    let env = Envelope::from_exact(exact_admission(req, inputs));
    let preferred = match extract_features(req) {
        Some(f) => EdgeAction::from_preference(model.predict(&f, lambda, g)),
        None => EdgeAction::Deny,
    };
    project(&env, preferred)
}
```

The std-side edge crates map `Allow`, `Defer`, `Deny` onto `Verdict::Allow`, `Verdict::PendingApproval`, `Verdict::Deny` and register themselves as one guard in `GuardPipeline`. Theorem 1 below shows that this composes with every other guard as a Kleene conjunction, so guard order changes only the evidence text and never the verdict. Tier-1 `UltraBERT` runs off the hot path and only when Tier-0 returns $\bot$ and the latency shadow price permits. It refines `preferred` and nothing else, so it inherits the same projection and the same proofs.

## 2. Hybrid signing floor, federated offline verification, attestation binding

**Receipt body and canonical encoding.** The receipt is a fixed-layout record, encoded big-endian in declaration order. Fixed layout removes every canonicalization choice from the verifier, and the encode and decode functions only use checked cursors.

| Object | Bytes |
|---|---|
| Receipt body | 212 |
| Ed25519 signature | 64 |
| ML-DSA-65 signature | 3,309 |
| Signed receipt on the wire | 3,585 |
| ML-DSA-65 public key | 1,952 |

**The floor.** `KernelCryptoFloor` is the only type that can sign a receipt, and it exposes both algorithms. `HybridSignature` has private fields and a single producer, `sign_receipt`, so a receipt carrying fewer than two signatures is unrepresentable. Both signatures cover one binding digest $D = H(\text{tag} \| pk_{\text{ed}} \| pk_{\text{ml}} \| \text{body})$. Including both public keys in $D$ gives message-bound exclusive ownership, which is what defeats key-substitution attacks in a federation where many roots are trusted at once.

```rust
pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA65_PK_LEN: usize = 1_952;
pub const MLDSA65_SIG_LEN: usize = 3_309;
pub const RECEIPT_BODY_LEN: usize = 212;
pub const SIGNED_RECEIPT_LEN: usize = 3_585;
const _: () = assert!(RECEIPT_BODY_LEN + ED25519_SIG_LEN + MLDSA65_SIG_LEN == SIGNED_RECEIPT_LEN);
pub const RECEIPT_DOMAIN_TAG: &[u8] = b"chio-edge-receipt-v1";
pub const ROOT_DOMAIN_TAG: &[u8] = b"chio-trust-root-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptBody {
    pub version: u8,
    pub edge: ProtocolEdge,
    pub request_digest: [u8; 32],
    pub capability_id: [u8; 32],
    pub verdict: K3,
    pub evidence_class: u8,
    pub policy_hash: [u8; 32],
    pub weights_hash: [u8; 32],
    pub attestation_measurement: [u8; 32],
    pub trust_root_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError { Overflow }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError { Truncated, BadEdge, BadVerdict }

struct Cursor<'b> { buf: &'b mut [u8], pos: usize }
impl Cursor<'_> {
    fn put(&mut self, src: &[u8]) -> Result<(), EncodeError> {
        let end = self.pos.checked_add(src.len()).ok_or(EncodeError::Overflow)?;
        self.buf.get_mut(self.pos..end).ok_or(EncodeError::Overflow)?.copy_from_slice(src);
        self.pos = end;
        Ok(())
    }
}
struct Reader<'b> { buf: &'b [u8], pos: usize }
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let end = self.pos.checked_add(N).ok_or(DecodeError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        let arr: [u8; N] = s.try_into().map_err(|_| DecodeError::Truncated)?;
        self.pos = end;
        Ok(arr)
    }
}

impl ReceiptBody {
    pub fn encode(&self) -> Result<[u8; RECEIPT_BODY_LEN], EncodeError> {
        let mut out = [0u8; RECEIPT_BODY_LEN];
        let mut c = Cursor { buf: &mut out, pos: 0 };
        c.put(&[self.version, self.edge as u8])?;
        c.put(&self.request_digest)?;
        c.put(&self.capability_id)?;
        c.put(&[self.verdict as u8, self.evidence_class])?;
        c.put(&self.policy_hash)?;
        c.put(&self.weights_hash)?;
        c.put(&self.attestation_measurement)?;
        c.put(&self.trust_root_id)?;
        c.put(&self.issued_at.to_be_bytes())?;
        c.put(&self.expires_at.to_be_bytes())?;
        if c.pos != RECEIPT_BODY_LEN { return Err(EncodeError::Overflow); }
        Ok(out)
    }
    pub fn decode(bytes: &[u8; RECEIPT_BODY_LEN]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let [version, edge] = r.take::<2>()?;
        let request_digest = r.take::<32>()?;
        let capability_id = r.take::<32>()?;
        let [verdict, evidence_class] = r.take::<2>()?;
        let policy_hash = r.take::<32>()?;
        let weights_hash = r.take::<32>()?;
        let attestation_measurement = r.take::<32>()?;
        let trust_root_id = r.take::<32>()?;
        let issued_at = u64::from_be_bytes(r.take::<8>()?);
        let expires_at = u64::from_be_bytes(r.take::<8>()?);
        Ok(Self {
            version,
            edge: ProtocolEdge::from_code(edge).ok_or(DecodeError::BadEdge)?,
            request_digest, capability_id,
            verdict: K3::from_code(verdict).ok_or(DecodeError::BadVerdict)?,
            evidence_class, policy_hash, weights_hash, attestation_measurement, trust_root_id,
            issued_at, expires_at,
        })
    }
}

pub trait Digest256: Default {
    fn update(&mut self, bytes: &[u8]);
    fn finalize(self) -> [u8; 32];
}

pub fn root_id<H: Digest256>(ed_pk: &[u8; ED25519_PK_LEN], ml_pk: &[u8; MLDSA65_PK_LEN]) -> [u8; 32] {
    let mut h = H::default();
    h.update(ROOT_DOMAIN_TAG); h.update(ed_pk); h.update(ml_pk);
    h.finalize()
}

pub fn binding_digest<H: Digest256>(ed_pk: &[u8; ED25519_PK_LEN], ml_pk: &[u8; MLDSA65_PK_LEN],
                                     body: &[u8; RECEIPT_BODY_LEN]) -> [u8; 32] {
    let mut h = H::default();
    h.update(RECEIPT_DOMAIN_TAG); h.update(ed_pk); h.update(ml_pk); h.update(body);
    h.finalize()
}

pub fn request_digest<H: Digest256>(req: &PortableToolCallRequest<'_>) -> Result<[u8; 32], EncodeError> {
    let mut h = H::default();
    h.update(&[req.edge as u8]);
    for seg in [req.command_line, req.image, req.original_file_name, req.parent_image] {
        let len = u32::try_from(seg.len()).map_err(|_| EncodeError::Overflow)?;
        h.update(&len.to_be_bytes());
        h.update(seg);
    }
    h.update(&req.capability_id);
    h.update(&req.issued_at.to_be_bytes());
    h.update(&req.expires_at.to_be_bytes());
    Ok(h.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError { Backend, BodyEncode(EncodeError), RootMismatch }

/// The floor: a signer that cannot be instantiated without both algorithms.
pub trait KernelCryptoFloor {
    type Hasher: Digest256;
    fn ed25519_public_key(&self) -> &[u8; ED25519_PK_LEN];
    fn mldsa65_public_key(&self) -> &[u8; MLDSA65_PK_LEN];
    fn ed25519_sign(&self, digest: &[u8; 32]) -> Result<[u8; ED25519_SIG_LEN], SignError>;
    fn mldsa65_sign(&self, digest: &[u8; 32], out: &mut [u8; MLDSA65_SIG_LEN]) -> Result<(), SignError>;
}

#[derive(Clone, Copy)]
pub struct HybridSignature { ed25519: [u8; ED25519_SIG_LEN], mldsa65: [u8; MLDSA65_SIG_LEN] }

#[derive(Clone, Copy)]
pub struct SignedReceipt { pub body: ReceiptBody, signature: HybridSignature }

pub fn sign_receipt<F: KernelCryptoFloor>(floor: &F, body: ReceiptBody) -> Result<SignedReceipt, SignError> {
    let (ed_pk, ml_pk) = (floor.ed25519_public_key(), floor.mldsa65_public_key());
    if root_id::<F::Hasher>(ed_pk, ml_pk) != body.trust_root_id { return Err(SignError::RootMismatch); }
    let bytes = body.encode().map_err(SignError::BodyEncode)?;
    let digest = binding_digest::<F::Hasher>(ed_pk, ml_pk, &bytes);
    let ed25519 = floor.ed25519_sign(&digest)?;
    let mut mldsa65 = [0u8; MLDSA65_SIG_LEN];
    floor.mldsa65_sign(&digest, &mut mldsa65)?;
    Ok(SignedReceipt { body, signature: HybridSignature { ed25519, mldsa65 } })
}

impl SignedReceipt {
    pub fn to_bytes(&self) -> Result<[u8; SIGNED_RECEIPT_LEN], EncodeError> {
        let mut out = [0u8; SIGNED_RECEIPT_LEN];
        let mut c = Cursor { buf: &mut out, pos: 0 };
        c.put(&self.body.encode()?)?;
        c.put(&self.signature.ed25519)?;
        c.put(&self.signature.mldsa65)?;
        Ok(out)
    }
    pub fn from_bytes(bytes: &[u8; SIGNED_RECEIPT_LEN]) -> Result<Self, DecodeError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let body = ReceiptBody::decode(&r.take::<RECEIPT_BODY_LEN>()?)?;
        let ed25519 = r.take::<ED25519_SIG_LEN>()?;
        let mldsa65 = r.take::<MLDSA65_SIG_LEN>()?;
        Ok(Self { body, signature: HybridSignature { ed25519, mldsa65 } })
    }
}

pub const MAX_FEDERATED_ROOTS: usize = 4_096;

#[derive(Clone, Copy, Debug)]
pub struct TrustRoot<'a> {
    pub root_id: [u8; 32],
    pub federation_id: [u8; 32],
    pub ed25519_pk: &'a [u8; ED25519_PK_LEN],
    pub mldsa65_pk: &'a [u8; MLDSA65_PK_LEN],
    pub not_before: u64,
    pub not_after: u64,
    /// First instant at which the root is no longer trusted for issuance.
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustStoreError { TooManyRoots(usize), RootIdMismatch(usize), NotStrictlySorted }

/// Roots must be strictly sorted by `root_id`; resolution is a binary search.
pub struct FederatedTrustStore<'a> { roots: &'a [TrustRoot<'a>], pub snapshot_at: u64 }

impl<'a> FederatedTrustStore<'a> {
    pub fn new<H: Digest256>(roots: &'a [TrustRoot<'a>], snapshot_at: u64) -> Result<Self, TrustStoreError> {
        if roots.len() > MAX_FEDERATED_ROOTS { return Err(TrustStoreError::TooManyRoots(roots.len())); }
        for (i, r) in roots.iter().enumerate() {
            if root_id::<H>(r.ed25519_pk, r.mldsa65_pk) != r.root_id { return Err(TrustStoreError::RootIdMismatch(i)); }
        }
        for w in roots.windows(2) {
            if let [a, b] = w { if a.root_id >= b.root_id { return Err(TrustStoreError::NotStrictlySorted); } }
        }
        Ok(Self { roots, snapshot_at })
    }
    pub fn resolve(&self, id: &[u8; 32]) -> Option<&TrustRoot<'a>> {
        self.roots.binary_search_by(|r| r.root_id.cmp(id)).ok().and_then(|i| self.roots.get(i))
    }
}

pub trait HybridVerifier {
    type Hasher: Digest256;
    fn ed25519_verify(&self, pk: &[u8; ED25519_PK_LEN], digest: &[u8; 32], sig: &[u8; ED25519_SIG_LEN]) -> bool;
    fn mldsa65_verify(&self, pk: &[u8; MLDSA65_PK_LEN], digest: &[u8; 32], sig: &[u8; MLDSA65_SIG_LEN]) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct ExpectedReceipt {
    pub capability_id: [u8; 32], pub request_digest: [u8; 32],
    pub verdict: K3, pub policy_hash: [u8; 32], pub evidence_class: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineVerdict { pub root: K3, pub signatures: K3, pub root_window: K3, pub receipt_window: K3, pub coupling: K3 }
impl OfflineVerdict {
    #[must_use]
    pub const fn overall(&self) -> K3 {
        self.root.and(self.signatures).and(self.root_window).and(self.receipt_window).and(self.coupling)
    }
}

pub fn verify_offline<V: HybridVerifier>(v: &V, store: &FederatedTrustStore<'_>, receipt: &SignedReceipt,
                                         expected: &ExpectedReceipt, now: Option<u64>) -> OfflineVerdict {
    let body = &receipt.body;
    let coupling = K3::from_bool(receipt_fields_coupled(
        body.capability_id == expected.capability_id,
        body.request_digest == expected.request_digest,
        body.verdict == expected.verdict,
        body.policy_hash == expected.policy_hash,
        body.evidence_class == expected.evidence_class,
    ));
    let receipt_window = match now {
        Some(t) => K3::from_bool(classify_time_window_code(t, body.issued_at, body.expires_at) == 0),
        None => K3::Bot,
    };
    let Some(root) = store.resolve(&body.trust_root_id) else {
        return OfflineVerdict { root: K3::Neg, signatures: K3::Neg, root_window: K3::Neg, receipt_window, coupling };
    };
    let signatures = match body.encode() {
        Ok(bytes) => {
            let d = binding_digest::<V::Hasher>(root.ed25519_pk, root.mldsa65_pk, &bytes);
            K3::from_bool(v.ed25519_verify(root.ed25519_pk, &d, &receipt.signature.ed25519))
                .and(K3::from_bool(v.mldsa65_verify(root.mldsa65_pk, &d, &receipt.signature.mldsa65)))
        }
        Err(_) => K3::Neg,
    };
    let within_root = classify_time_window_code(body.issued_at, root.not_before, root.not_after) == 0;
    let not_revoked = root.revoked_at.map_or(true, |r| body.issued_at < r);
    let not_future = body.issued_at <= store.snapshot_at;
    OfflineVerdict {
        root: K3::Pos, signatures,
        root_window: K3::from_bool(within_root && not_revoked && not_future),
        receipt_window, coupling,
    }
}

/// Pass 12: a TEE or TPM quote binding the measured firmware, loaded weights, and policy to the signing keys.
#[derive(Clone, Copy, Debug)]
pub struct AttestationQuote { pub measurement: [u8; 32], pub key_commitment: [u8; 32], pub nonce: [u8; 32] }

pub trait QuoteVerifier {
    /// `None` when the vendor certificate chain is unavailable to this verifier.
    fn quote_authentic(&self, quote: &AttestationQuote, quote_signature: &[u8]) -> Option<bool>;
}

pub fn attested_measurement<H: Digest256>(firmware: &[u8; 32], weights: &[u8; 32], policy: &[u8; 32]) -> [u8; 32] {
    let mut h = H::default();
    h.update(b"chio-attest-v1"); h.update(firmware); h.update(weights); h.update(policy);
    h.finalize()
}

pub fn attestation_binds<Q: QuoteVerifier>(q: &Q, quote: &AttestationQuote, sig: &[u8],
                                           root: &[u8; 32], expected_measurement: &[u8; 32]) -> K3 {
    match q.quote_authentic(quote, sig) {
        None => K3::Bot,
        Some(false) => K3::Neg,
        Some(true) => K3::from_bool(quote.key_commitment == *root && quote.measurement == *expected_measurement),
    }
}
```

**Federation semantics.** A trust root is a pair of public keys, and its identifier is the hash of that pair under a domain tag. The store checks this at construction, so a corrupted or mislabeled root entry is rejected before any receipt is examined. Receipts name their root, and any party holding the root's keys verifies the receipt with no network access. Revocation is expressed as an instant, and receipts issued strictly before it remain valid, which is the usual compromise-window rule. Backdating is bounded by requiring the issuance time to lie at or before the store snapshot, and operators are expected to set the revocation instant to the estimated compromise time rather than the discovery time.

**Attestation.** The quote commits to the signing-key pair through the same root identifier and to a measurement that folds in the firmware hash, the loaded weights hash from the `LoadedWeights` provider, and the policy hash. Online, the kernel ran `evaluate_weights_binding` against the model card. Offline, the verifier only checks equality between the receipt's `weights_hash` field and the measured value and reads the quote through `attestation_binds`. A verifier without the vendor chain gets $\bot$, which flows through the Kleene conjunction as Defer rather than a false Allow.

**Metadata discipline.** The core has no metadata map at all. The kernel lifts the receipt body into the reserved `protocol_admission` or `protocol_refusal` keys from `RESERVED_RECEIPT_METADATA_KEYS`, and the edge crates cannot write those keys because they never see the map. This is enforced by the type boundary, not by convention.

## 3. Formal results

**Theorem 1 (GuardPipeline is the Kleene conjunction).** Let $g$ map `Allow` to $+$, `PendingApproval` to $\bot$, and both `Deny` and `Err` to $-$. For guards with results $v_1, \dots, v_n$, the pipeline verdict equals $\bigwedge_{\mathbb{K}_3} g(v_i)$.

*Proof.* Induction on the loop with the invariant that after a prefix without Deny, `final_verdict` equals the conjunction of the prefix and lies in $\{+, \bot\}$. A Deny or an error returns $-$, which is absorbing. A PendingApproval sets the sticky state to $\bot$, and $a \wedge \bot = \bot$ for $a \in \{+, \bot\}$. An Allow leaves the state unchanged, and $a \wedge + = a$. The base case is the empty prefix with state $+$. Because $\wedge$ is commutative and associative, the verdict is order-independent, while the evidence entry is produced by the first denying guard. $\square$

**Theorem 2 (Envelope preservation and verification transfer at the edge).** For all exact $e \in \mathbb{K}_3$ and all preferred actions $p$, the projection of $p$ into the envelope of $e$ lies in that envelope. If $e = -$ the result is Deny, and if the result is Allow then $e = +$. Consequently any safety property $\varphi$ proved for all members of the envelope holds for the deployed system for every $\theta$ and every $\boldsymbol{\lambda}$.

*Proof.* The first claim is a case split on whether $p$ is feasible, then on whether Defer is feasible, with Deny always feasible. The two implications follow from the envelope construction, since Allow is feasible only for $e = +$ and only Deny is feasible for $e = -$. For transfer, the predictor's output ranges over the three actions, so quantifying over an unconstrained nondeterministic choice covers every $\theta$. $\square$

**Theorem 3 (Hybrid AND-composition).** Let $\Sigma_1$ be Ed25519 and $\Sigma_2$ be ML-DSA-65 per FIPS 204. Let $A$ be an adversary against the hybrid scheme producing a forgery on a fresh body with advantage $\varepsilon$. Then there exist adversaries $B_1$ and $B_2$ with
$$\varepsilon \le \min\big(\mathrm{Adv}^{\text{EUF-CMA}}_{\Sigma_1}(B_1),\ \mathrm{Adv}^{\text{EUF-CMA}}_{\Sigma_2}(B_2)\big) + \mathrm{Adv}^{\text{coll}}_H.$$

*Proof.* $B_i$ receives the challenge key for $\Sigma_i$, generates the other key pair itself, and answers $A$'s signing queries by hashing to $D$ and signing with its oracle for component $i$ and its own key for the other. A hybrid forgery on a fresh body yields a fresh digest unless $H$ collides with a queried digest, and then $(D^*, \sigma_i^*)$ is a $\Sigma_i$ forgery. EUF-CMA means existential unforgeability under chosen-message attack. Against a quantum adversary the first bound is vacuous and the second carries the proof. Against a classical adversary exploiting a future lattice flaw the first carries it. $\square$

**Theorem 4 (Offline soundness and cross-root non-transferability).** If `verify_offline` returns $+$ overall, then a root with the claimed identifier exists in the store, both signatures verify under that root's keys on the recomputed binding digest, the root window covered the issuance time, the root was not revoked at or before issuance, issuance is not after the snapshot, the receipt is fresh at the supplied clock, and the five coupled fields match. A receipt honestly signed under root $A$ does not verify under a distinct root $B$ except with the probability of forging under $B$'s keys, because the digest embeds $B$'s keys and the signatures were made over a digest embedding $A$'s.

*Proof.* Each conjunct of `overall` is $+$ only when its Boolean source is true, and the store invariant ties the resolved root's keys to its identifier. For the second claim, verification under $B$ recomputes $D_B \ne D_A$ unless $H$ collides, and a valid signature on $D_B$ under $B$'s keys is a forgery. $\square$

The Lean 4 development states Theorems 1 and 2 over the definitions that Aeneas extracts from the crate. Because `project`, `K3::and`, and `Envelope::from_exact` are total `const fn`s, the extracted terms are in the pure fragment, and the Aeneas-style specification `∃ a, project e p = .ok a ∧ e.mem a = true` reduces to `project_mem` below.

```lean
namespace ChioEdge

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _ => .neg
  | _, .neg => .neg
  | .bot, _ => .bot
  | _, .bot => .bot
  | .pos, .pos => .pos

theorem K3.and_comm (a b : K3) : a.and b = b.and a := by
  cases a <;> cases b <;> rfl
theorem K3.and_assoc (a b c : K3) : (a.and b).and c = a.and (b.and c) := by
  cases a <;> cases b <;> cases c <;> rfl
theorem K3.neg_absorb (a : K3) : a.and .neg = .neg := by cases a <;> rfl

inductive Act | allow | defer | deny
  deriving DecidableEq, Repr

structure Env where
  allow : Bool
  defer : Bool

def Env.ofExact : K3 → Env
  | .pos => ⟨true, true⟩
  | .bot => ⟨false, true⟩
  | .neg => ⟨false, false⟩

def Env.mem (e : Env) : Act → Bool
  | .allow => e.allow
  | .defer => e.defer
  | .deny  => true

def project (e : Env) (p : Act) : Act :=
  if e.mem p then p else if e.defer then .defer else .deny

/-- Theorem 2, envelope preservation. -/
theorem project_mem (e : Env) (p : Act) : e.mem (project e p) = true := by
  unfold project
  split
  · assumption
  · split
    · simpa [Env.mem]
    · rfl

theorem neg_forces_deny (p : Act) : project (Env.ofExact .neg) p = .deny := by
  cases p <;> rfl

theorem allow_needs_pos (x : K3) (p : Act)
    (h : project (Env.ofExact x) p = .allow) : x = .pos := by
  cases x <;> cases p <;> simp [project, Env.ofExact, Env.mem] at h ⊢

inductive Verdict | allow | pending | deny

def Verdict.toK3 : Verdict → K3
  | .allow => .pos | .pending => .bot | .deny => .neg

/-- Mirrors `impl Guard for GuardPipeline`: Deny returns, PendingApproval is sticky, Allow continues. -/
def pipeline : List Verdict → K3 → K3
  | [], acc => acc
  | .deny :: _, _ => .neg
  | .pending :: vs, _ => pipeline vs .bot
  | .allow :: vs, acc => pipeline vs acc

theorem foldl_neg (vs : List Verdict) :
    vs.foldl (fun a v => a.and v.toK3) .neg = .neg := by
  induction vs with
  | nil => rfl
  | cons v vs ih => cases v <;> simpa [List.foldl, K3.and, Verdict.toK3] using ih

/-- Theorem 1. -/
theorem pipeline_is_kleene_and (vs : List Verdict) (acc : K3) (h : acc ≠ .neg) :
    pipeline vs acc = vs.foldl (fun a v => a.and v.toK3) acc := by
  induction vs generalizing acc with
  | nil => rfl
  | cons v vs ih =>
    cases v with
    | deny => simp [pipeline, List.foldl, Verdict.toK3, K3.neg_absorb, foldl_neg]
    | pending =>
      have hb : acc.and .bot = .bot := by
        cases acc <;> first | rfl | exact absurd rfl h
      simp [pipeline, List.foldl, Verdict.toK3, hb]
      exact ih .bot (by decide)
    | allow =>
      have ha : acc.and .pos = acc := by cases acc <;> rfl
      simp [pipeline, List.foldl, Verdict.toK3, ha]
      exact ih acc h

end ChioEdge
```

The Kani harnesses model the learned choice as `kani::any()`, which is the verification-transfer step of Theorem 2, and check that an offline $+$ requires both signature checks to pass under an arbitrary verifier.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn edge_envelope_preserved_for_any_predictor() {
        let exact = K3::from_code(kani::any()).unwrap_or(K3::Neg);
        let preferred = EdgeAction::from_code(kani::any()).unwrap_or(EdgeAction::Deny);
        let env = Envelope::from_exact(exact);
        let out = project(&env, preferred).action();
        assert!(env.contains(out));
        if exact == K3::Neg { assert_eq!(out, EdgeAction::Deny); }
        if out == EdgeAction::Allow { assert_eq!(exact, K3::Pos); }
    }

    #[derive(Default)]
    struct ZeroHash;
    impl Digest256 for ZeroHash {
        fn update(&mut self, _: &[u8]) {}
        fn finalize(self) -> [u8; 32] { [0; 32] }
    }
    struct AnyVerifier { ed: bool, ml: bool }
    impl HybridVerifier for AnyVerifier {
        type Hasher = ZeroHash;
        fn ed25519_verify(&self, _: &[u8; ED25519_PK_LEN], _: &[u8; 32], _: &[u8; ED25519_SIG_LEN]) -> bool { self.ed }
        fn mldsa65_verify(&self, _: &[u8; MLDSA65_PK_LEN], _: &[u8; 32], _: &[u8; MLDSA65_SIG_LEN]) -> bool { self.ml }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn offline_pos_requires_both_signatures() {
        let v = AnyVerifier { ed: kani::any(), ml: kani::any() };
        let (ed_pk, ml_pk) = ([0u8; ED25519_PK_LEN], [0u8; MLDSA65_PK_LEN]);
        let roots = [TrustRoot { root_id: [0; 32], federation_id: [0; 32], ed25519_pk: &ed_pk,
            mldsa65_pk: &ml_pk, not_before: 0, not_after: u64::MAX, revoked_at: None }];
        let store = FederatedTrustStore::new::<ZeroHash>(&roots, u64::MAX).unwrap();
        let body = ReceiptBody {
            version: kani::any(), edge: ProtocolEdge::Mcp, request_digest: kani::any(),
            capability_id: kani::any(), verdict: K3::from_code(kani::any()).unwrap_or(K3::Pos),
            evidence_class: kani::any(), policy_hash: kani::any(), weights_hash: kani::any(),
            attestation_measurement: kani::any(), trust_root_id: [0; 32],
            issued_at: kani::any(), expires_at: kani::any(),
        };
        let receipt = SignedReceipt { body, signature: HybridSignature { ed25519: [0; ED25519_SIG_LEN], mldsa65: [0; MLDSA65_SIG_LEN] } };
        let expected = ExpectedReceipt { capability_id: body.capability_id, request_digest: body.request_digest,
            verdict: body.verdict, policy_hash: body.policy_hash, evidence_class: body.evidence_class };
        let verdict = verify_offline(&v, &store, &receipt, &expected, kani::any());
        if verdict.overall() == K3::Pos { assert!(v.ed && v.ml); }
    }
}
```

The Apalache model checks the revocation rule used by `verify_offline` against honest issuance and against an adversary who holds a revoked key and may claim any past time. Two invariants are checked: honest receipts are never rejected, and forgeries stamped at or after revocation are always rejected. Forgeries stamped before revocation are the documented residual, and that is exactly why the revocation instant must be the compromise estimate.

```tla
------------------------- MODULE FederatedReceipts -------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Set(Str);
  Roots,
  \* @type: Int;
  MaxTime
VARIABLES
  \* @type: Str -> Int;
  revokedAt,
  \* @type: Set({ root: Str, t: Int });
  honest,
  \* @type: Set({ root: Str, t: Int });
  forged,
  \* @type: Int;
  now

Init ==
  /\ revokedAt = [r \in Roots |-> MaxTime + 1]
  /\ honest = {} /\ forged = {} /\ now = 0

Issue(r) ==
  /\ now < revokedAt[r]
  /\ honest' = honest \cup {[root |-> r, t |-> now]}
  /\ UNCHANGED <<revokedAt, forged, now>>

Revoke(r) ==
  /\ now < revokedAt[r]
  /\ revokedAt' = [revokedAt EXCEPT ![r] = now + 1]
  /\ UNCHANGED <<honest, forged, now>>

Forge(r) ==
  /\ revokedAt[r] <= now
  /\ \E t \in 0..now : forged' = forged \cup {[root |-> r, t |-> t]}
  /\ UNCHANGED <<revokedAt, honest, now>>

Tick == now < MaxTime /\ now' = now + 1 /\ UNCHANGED <<revokedAt, honest, forged>>

Next == Tick \/ \E r \in Roots : Issue(r) \/ Revoke(r) \/ Forge(r)

\* The `root_window` rule of verify_offline with snapshot_at = now.
Accept(rc) == rc.t < revokedAt[rc.root] /\ rc.t <= now

HonestAccepted      == \A rc \in honest : Accept(rc)
LateForgeryRejected == \A rc \in forged : rc.t >= revokedAt[rc.root] => ~Accept(rc)
=============================================================================
```

```text
apalache-mc check --inv=HonestAccepted,LateForgeryRejected --length=12 FederatedReceipts.tla
```

**Manifest impact.** Everything here is additive. The crate imports `classify_time_window_code`, `budget_precheck`, and `receipt_fields_coupled` with their pinned signatures and never redefines them, so `formal/proof-manifest.toml` gains new entries for `ChioEdge` and loses none. The Lean file is a new module under `formal/lean4/Chio/`, and existing proofs over `ReservationLedger`, `BudgetCommitResult`, and `budget_split` are untouched.

**Recap.** The three protocol edges lift onto one `PortableToolCallRequest` whose four byte segments are exactly the four Copley segments, so the 537 predicates and the Tier-0 micro-model serve MCP, A2A, and Envoy ext_authz without per-protocol learning. Admission is the Kleene conjunction of exact kernel checks, the learned preference is projected into the resulting envelope in constant time, and Theorem 1 shows the result composes with every other guard as a conjunction. Receipts are signed only through `KernelCryptoFloor`, which makes a single-algorithm receipt unrepresentable, and the digest binds both public keys so receipts cannot migrate between federated roots. Offline verification needs only a sorted root store and a clock, degrades to Defer when the clock or vendor chain is missing, and is covered by the Lean theorems, the two Kani harnesses, and the Apalache revocation model. The residual risk is a forgery backdated before the revocation instant, which is mitigated operationally by setting that instant to the compromise estimate.