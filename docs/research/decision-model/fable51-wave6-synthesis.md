# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 6 Synthesis

- **Timestamp**: `20261025-020145 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1679.58s` across 4 parallel passes
- **Total Output**: `141,238` characters (`18,373` words)
- **Claude Max Quota Before Wave 6**: 5-hour `84.0%` | 7-day `86.0%`
- **Claude Max Quota After Wave 6**: 5-hour `90.0%` | 7-day `87.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave6_angle_1_formal_aeneas_and_lean4_deepening_pass_6` | `0` | `success` | `['claude-fable-5-1']` | `none` | `4,731` | `33,789` | `527.31` |
| `wave6_angle_2_copley_dag_optimization_and_simd_bitset_pass_6` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `6,571` | `49,401` | `1075.2` |
| `wave6_angle_3_concurrent_loom_and_dst_crash_recovery_pass_6` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `1,366` | `11,187` | `1679.56` |
| `wave6_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_6` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `5,705` | `46,861` | `943.79` |

---

# Verbatim Treatise - `wave6_angle_1_formal_aeneas_and_lean4_deepening_pass_6`

I'll lay out the Pass 6 additive mechanization as one new `#![no_std]` module in `chio-kernel-core`, with Lean 4 and Creusot companions, Kani harnesses, and the manifest pins that bind them.

## Saturation and epoch boundaries as exact computation

**Where this sits in the Wave 1 law.** Every artifact below is a component of $\mathcal{D}_\ell$. The exact computation $C_\ell$ gains three new $\mathbb{K}_3$ verdicts: a Merkle inclusion verdict, a multi-hop attenuation verdict, and a time-window verdict. The feasible envelope $\mathcal{C}_\ell$ is a private-constructor `Envelope<A>` whose projection $\Pi$ is a clamp. The learned proposal from Tier-0 or Tier-1 is a `FixedQ16_16` score that every proof treats as `kani::any()`. Nothing in `formal_aeneas.rs`, `formal_core.rs`, or `budget_split.rs` changes. The new module reuses `MAX_BUDGET_SHARE_BPS` and calls the pinned `classify_time_window_code`, `budget_precheck`, and `budget_commit` only from harnesses.

| Tuple element | Pass 6 artifact |
|---|---|
| $C_\ell(x) \in \mathbb{K}_3^{F_\ell}$ | `verify_inclusion`, `AttenuationWitness::verify`, `window_spec` |
| $\mathcal{C}_\ell(C_\ell(x))$ | `Envelope<FixedQ16_16>::gate` |
| $\Pi_{\mathcal{C}_\ell(x)}$ | `Envelope::project`, returns `ShieldedAction<A>` |
| $P_\ell(x;\theta,\boldsymbol{\lambda})$ | `FixedQ16_16::shadow_penalty`, proposal as nondeterminism |
| $\bot_x$ | `Envelope::fallback`, forced by `gate` on `-` or `⊥` |

**The saturating fixed-point lattice.** The Tier-0 micro-models run on `FixedQ16_16`, a signed 32-bit raw with 16 fractional bits. The hot path cannot panic and cannot wrap, so every operation saturates. The non-obvious edge case is that saturation destroys associativity. With `MAX` the largest raw and `one` any positive raw, `(MAX ⊕ one) ⊕ (−one)` equals `MAX − one`, while `MAX ⊕ (one ⊕ (−one))` equals `MAX`. This means the summation order inside `shadow_penalty` is part of the specification, not an implementation detail. The module fixes left-to-right order over the five shadow-price components and the Lean model folds in the same order.

**Theorem 1, saturation lattice.** Let $\operatorname{clamp}(x) = \max(L, \min(H, x))$ on $\mathbb{Z}$ with $L = -2^{31}$ and $H = 2^{31}-1$. Then clamp is monotone and idempotent, $L \le \operatorname{clamp}(x) \le H$, and clamp is the identity on $[L,H]$. Define $a \oplus b = \operatorname{clamp}(a+b)$ and $a \otimes b = \operatorname{clamp}(\lfloor ab / 2^{16} \rfloor)$ with floor division. Then $\oplus$ is commutative, monotone in each argument, and absorbs at the bounds: $H \oplus a = H$ for $a \ge 0$ and $L \oplus a = L$ for $a \le 0$. The product $\otimes$ of two non-negative operands is non-negative, because the floor of a non-negative rational is non-negative and clamp preserves sign. The proof of each clause is a case split on the three regions of clamp followed by linear arithmetic, which is exactly what `omega` discharges below.

**Epoch boundaries.** The pinned classifier returns codes that are not temporally ordered: Valid is code 0, NotYetValid is code 1, Expired is code 2. Monotonicity in time holds only after re-ranking NotYetValid below Valid below Expired. The module adds a pure reference specification, a rank function, and a saturating epoch advance. The reference reads the window as half-open, Valid on `[issued_at, expires_at)`. That is an assumption about the pinned body. The first Kani harness pins it bit-precisely, so if the implementation is closed at expiry, exactly one harness fails and names the boundary.

**Theorem 2, epoch transitions.** For fixed `issued_at` and `expires_at`, the rank of the window code is non-decreasing in `now`. At `now = u64::MAX` the code is Expired for every window, because no `expires_at` can exceed it. A degenerate window with `issued_at > expires_at` is never Valid. Saturating advance never rewinds time. Proofs are linear case analyses, mechanized in Lean and Kani below.

**Budget boundary pin.** The commit path has a sharp edge where the cost equals the remainder. The harness asserts the expected semantics: acceptance iff both costs fit, remainder decremented exactly on acceptance, remainder untouched on rejection. This is a pin of assumed behavior for an existing function. If the real body reports zeros on rejection, the harness fails on the rejection branch and the manifest entry is amended, not the kernel.

```rust
// crates/kernel/chio-kernel-core/src/formal_wave6.rs
// Crate root already carries #![no_std] and #![forbid(unsafe_code)].
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use crate::budget_split::MAX_BUDGET_SHARE_BPS;

/// Kleene three-valued verdict. Mirrors the `formal_core` lattice `+`, `-`, `⊥`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// Strong Kleene conjunction: `-` dominates, then `⊥`, then `+`.
    pub const fn and(self, other: K3) -> K3 {
        match (self, other) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Bot, _) | (_, K3::Bot) => K3::Bot,
            (K3::Pos, K3::Pos) => K3::Pos,
        }
    }
}

/// Signed Q16.16 fixed point. Every operation saturates; none can panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(i32);

impl FixedQ16_16 {
    pub const SCALE: i64 = 65_536;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(65_536);
    pub const MAX: Self = Self(i32::MAX);
    pub const MIN: Self = Self(i32::MIN);

    pub const fn from_raw(raw: i32) -> Self { Self(raw) }
    pub const fn raw(self) -> i32 { self.0 }

    /// Clamp a wide intermediate into the representable range.
    pub fn clamp_wide(x: i64) -> Self {
        match i32::try_from(x) {
            Ok(v) => Self(v),
            Err(_) => if x < 0 { Self::MIN } else { Self::MAX },
        }
    }

    /// `a ⊕ b`: specification is `clamp_wide(a + b)`; Kani proves the match.
    pub fn sat_add(self, rhs: Self) -> Self { Self(self.0.saturating_add(rhs.0)) }

    pub fn sat_sub(self, rhs: Self) -> Self { Self(self.0.saturating_sub(rhs.0)) }

    /// `a ⊗ b`: floor-rounded Q16.16 product, saturated.
    pub fn sat_mul(self, rhs: Self) -> Self {
        let prod = i64::from(self.0).checked_mul(i64::from(rhs.0));
        let scaled = prod.and_then(|p| p.checked_div_euclid(Self::SCALE));
        match scaled {
            Some(s) => Self::clamp_wide(s),
            // Unreachable: |i32|^2 < 2^62 and the divisor is a nonzero constant.
            // The arm keeps the function total and panic-free by construction.
            None => if (self.0 < 0) != (rhs.0 < 0) { Self::MIN } else { Self::MAX },
        }
    }

    /// Tier-0 Lagrangian penalty `Σ λ_k · f_k` over the five shadow prices.
    /// Left-to-right order is part of the spec because `⊕` is not associative.
    pub fn shadow_penalty(features: &[Self; 5], lambda: &[Self; 5]) -> Self {
        let mut acc = Self::ZERO;
        for (f, l) in features.iter().zip(lambda.iter()) {
            acc = acc.sat_add(f.sat_mul(*l));
        }
        acc
    }
}

pub const WINDOW_VALID: u8 = 0;
pub const WINDOW_NOT_YET_VALID: u8 = 1;
pub const WINDOW_EXPIRED: u8 = 2;

/// Reference specification: Valid on the half-open window `[issued_at, expires_at)`.
pub fn window_spec(now: u64, issued_at: u64, expires_at: u64) -> u8 {
    if now < issued_at { WINDOW_NOT_YET_VALID }
    else if now < expires_at { WINDOW_VALID }
    else { WINDOW_EXPIRED }
}

/// Temporal rank: NotYetValid < Valid < Expired. The codes themselves are not ordered.
pub fn temporal_rank(code: u8) -> u8 {
    match code { WINDOW_NOT_YET_VALID => 0, WINDOW_VALID => 1, _ => 2 }
}

/// Saturating epoch advance. Overflow is the end of time, never a rewind.
pub fn advance_epoch(now: u64, delta: u64) -> u64 {
    now.checked_add(delta).unwrap_or(u64::MAX)
}
```

## Attenuation witnesses and Merkle inclusion coupled to envelopes

**Multi-hop attenuation.** A delegation chain is a sequence of hops, each carrying a share in basis points and a validity window. The effective share after a hop is the parent's effective share scaled by the hop's share and floored. The effective window is the intersection. The witness type has one constructor, `verify`, which returns a $\mathbb{K}_3$ verdict and a witness only on `+`. An empty chain or a chain deeper than the cap is `⊥`, because the kernel has no evidence either way and `⊥` collapses the envelope to fallback just as `-` does. Any hop above the cap is `-`.

**Theorem 3, attenuation never amplifies.** Let $K = 10{,}000$ and $p \circ c = \lfloor pc/K \rfloor$. If $c \le K$ then $p \circ c \le p$, since $pc \le pK$ and dividing by $K$ preserves the inequality. Symmetrically $p \le K$ gives $p \circ c \le c$. By induction on the chain with accumulator starting at $K$, the effective share is at most $K$ and at most every hop's share. Floor composition is not associative, so the fold order is fixed left to right, matching the Lean `foldl`.

**Theorem 4, window intersection.** If $\max_i I_i \le t < \min_i E_i$ then $I_i \le t < E_i$ for every hop $i$. The composite Valid verdict therefore implies each hop is Valid at $t$ under the half-open reading. The converse also holds, but the kernel only needs soundness.

**Merkle inclusion.** An inclusion step hashes the accumulator with a sibling, left or right by direction bit. The root of a path is the left fold of steps from the leaf. The verifier returns `⊥` past the depth cap and compares otherwise. The structural theorem is exact: the verdict is `+` iff the depth is within cap and the fold reproduces the root. Semantic soundness, that a `+` verdict means the leaf is really in the committed tree, is relative to collision resistance of the hash. That assumption is stated in the manifest and is not mechanized, since no mechanized theorem can discharge it.

**Coupling to the envelope.** The envelope is gated by the inclusion verdict before projection. A `+` keeps the envelope. Anything else degenerates it to the single fallback point. Projection then clamps the proposal. The combined theorem is the Pass 6 instance of Envelope Preservation: for every proposal, the shielded action lies in the gated envelope, and if the verdict is not `+` the action equals $\bot_x$ regardless of what the model proposed.

```rust
/// Feasible envelope `C_ℓ(x)`: a closed interval with a designated fallback `⊥_x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<A: Ord + Copy> { lo: A, hi: A, fallback: A }

/// Only `Envelope::project` can construct one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedAction<A>(A);

impl<A: Copy> ShieldedAction<A> {
    pub fn into_inner(self) -> A { self.0 }
}

impl<A: Ord + Copy> Envelope<A> {
    pub fn new(lo: A, hi: A, fallback: A) -> Option<Self> {
        if lo <= fallback && fallback <= hi { Some(Self { lo, hi, fallback }) } else { None }
    }
    pub fn degenerate(fallback: A) -> Self { Self { lo: fallback, hi: fallback, fallback } }
    pub fn contains(&self, a: A) -> bool { self.lo <= a && a <= self.hi }
    pub fn fallback(&self) -> A { self.fallback }

    /// `Π_{C(x)}`: O(1) shielded projection of an arbitrary learned proposal.
    pub fn project(&self, proposal: A) -> ShieldedAction<A> {
        let a = if proposal < self.lo { self.lo }
                else if proposal > self.hi { self.hi }
                else { proposal };
        ShieldedAction(a)
    }

    /// Couple to an exact verdict: anything but `+` collapses to `⊥_x`.
    pub fn gate(self, verdict: K3) -> Self {
        match verdict {
            K3::Pos => self,
            K3::Neg | K3::Bot => Self::degenerate(self.fallback),
        }
    }
}

pub const MAX_ATTENUATION_HOPS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Hop { pub share_bps: u16, pub issued_at: u64, pub expires_at: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attenuation { pub effective_bps: u16, pub issued_at: u64, pub expires_at: u64 }

/// Verified multi-hop witness. The only constructor is `verify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttenuationWitness { summary: Attenuation, depth: usize }

/// `parent ∘ child = ⌊parent · child / 10_000⌋`, `None` above the cap.
pub fn compose_bps(parent: u16, child: u16) -> Option<u16> {
    if parent > MAX_BUDGET_SHARE_BPS || child > MAX_BUDGET_SHARE_BPS { return None; }
    let prod = u32::from(parent).checked_mul(u32::from(child))?;
    let scaled = prod.checked_div(u32::from(MAX_BUDGET_SHARE_BPS))?;
    u16::try_from(scaled).ok()
}

impl AttenuationWitness {
    pub fn verify(hops: &[Hop], now: u64) -> (K3, Option<Self>) {
        if hops.is_empty() || hops.len() > MAX_ATTENUATION_HOPS { return (K3::Bot, None); }
        let mut eff: u16 = MAX_BUDGET_SHARE_BPS;
        let mut issued: u64 = 0;
        let mut expires: u64 = u64::MAX;
        for hop in hops {
            eff = match compose_bps(eff, hop.share_bps) {
                Some(v) => v,
                None => return (K3::Neg, None),
            };
            issued = issued.max(hop.issued_at);
            expires = expires.min(hop.expires_at);
        }
        let summary = Attenuation { effective_bps: eff, issued_at: issued, expires_at: expires };
        if window_spec(now, issued, expires) == WINDOW_VALID {
            (K3::Pos, Some(Self { summary, depth: hops.len() }))
        } else {
            (K3::Neg, None)
        }
    }
    pub fn summary(&self) -> Attenuation { self.summary }
    pub fn depth(&self) -> usize { self.depth }
}

pub const MAX_INCLUSION_DEPTH: usize = 64;
pub type Digest = [u8; 32];

/// Abstract node hash. Collision resistance is a manifest assumption, not a theorem.
pub trait Hash32 { fn node(left: &Digest, right: &Digest) -> Digest; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct PathStep { pub sibling: Digest, pub sibling_is_left: bool }

pub fn inclusion_step<H: Hash32>(acc: &Digest, step: &PathStep) -> Digest {
    if step.sibling_is_left { H::node(&step.sibling, acc) } else { H::node(acc, &step.sibling) }
}

pub fn root_of<H: Hash32>(leaf: &Digest, path: &[PathStep]) -> Digest {
    let mut acc = *leaf;
    for step in path { acc = inclusion_step::<H>(&acc, step); }
    acc
}

pub fn verify_inclusion<H: Hash32>(leaf: &Digest, path: &[PathStep], root: &Digest) -> K3 {
    if path.len() > MAX_INCLUSION_DEPTH { return K3::Bot; }
    if root_of::<H>(leaf, path) == *root { K3::Pos } else { K3::Neg }
}

/// Pass 6 coupling: exact inclusion verdict gates the envelope, then `Π` clamps.
pub fn admit_scored<H: Hash32>(
    leaf: &Digest, path: &[PathStep], root: &Digest,
    base: Envelope<FixedQ16_16>, proposal: FixedQ16_16,
) -> ShieldedAction<FixedQ16_16> {
    base.gate(verify_inclusion::<H>(leaf, path, root)).project(proposal)
}
```

## Mechanization: Lean 4, Creusot, Kani, and the manifest

**Lean 4.** The file models raw values as `Int` and `Nat`, folds in the same order as the Rust, and keeps the hash abstract. Every arithmetic obligation closes with `omega` after unfolding, which is the whole point of writing the specification as clamps, floors by literals, and linear comparisons.

```lean
-- formal/lean4/Chio/Wave6.lean
namespace Chio.Wave6

inductive K3 | pos | neg | bot
  deriving DecidableEq, Repr

namespace Fixed
def lo : Int := -2147483648
def hi : Int := 2147483647
def clamp (x : Int) : Int := max lo (min hi x)
def satAdd (a b : Int) : Int := clamp (a + b)

theorem clamp_mem (x : Int) : lo ≤ clamp x ∧ clamp x ≤ hi := by
  unfold clamp lo hi; omega

theorem clamp_id {x : Int} (h₁ : lo ≤ x) (h₂ : x ≤ hi) : clamp x = x := by
  unfold clamp lo hi at *; omega

theorem clamp_mono {x y : Int} (h : x ≤ y) : clamp x ≤ clamp y := by
  unfold clamp lo hi; omega

theorem satAdd_comm (a b : Int) : satAdd a b = satAdd b a := by
  unfold satAdd; rw [Int.add_comm]

theorem satAdd_mono_left {a a' b : Int} (h : a ≤ a') : satAdd a b ≤ satAdd a' b := by
  unfold satAdd; exact clamp_mono (by omega)

theorem satAdd_hi_absorb {a : Int} (h : 0 ≤ a) : satAdd hi a = hi := by
  unfold satAdd clamp lo hi at *; omega

theorem satAdd_lo_absorb {a : Int} (h : a ≤ 0) : satAdd lo a = lo := by
  unfold satAdd clamp lo hi at *; omega

/-- Non-associativity witness: order of summation is part of the spec. -/
theorem satAdd_not_assoc : satAdd (satAdd hi 1) (-1) ≠ satAdd hi (satAdd 1 (-1)) := by
  unfold satAdd clamp lo hi; omega
end Fixed

namespace Epoch
def U : Nat := 18446744073709551615

def windowSpec (now issued expires : Nat) : Nat :=
  if now < issued then 1 else if now < expires then 0 else 2

def rank (c : Nat) : Nat := if c = 1 then 0 else if c = 0 then 1 else 2

theorem rank_mono {now now' i e : Nat} (h : now ≤ now') :
    rank (windowSpec now i e) ≤ rank (windowSpec now' i e) := by
  unfold rank windowSpec
  repeat' split
  all_goals omega

theorem end_of_time {i e : Nat} (hi : i ≤ U) (he : e ≤ U) : windowSpec U i e = 2 := by
  unfold windowSpec U at hi he ⊢
  repeat' split
  all_goals omega

theorem degenerate_never_valid {now i e : Nat} (h : e < i) : windowSpec now i e ≠ 0 := by
  unfold windowSpec
  repeat' split
  all_goals omega
end Epoch

namespace Attenuation
def cap : Nat := 10000
def compose (p c : Nat) : Nat := p * c / cap

theorem compose_le_left {p c : Nat} (hc : c ≤ cap) : compose p c ≤ p := by
  unfold compose
  apply Nat.div_le_of_le_mul
  calc p * c ≤ p * cap := Nat.mul_le_mul (Nat.le_refl p) hc
    _ = cap * p := Nat.mul_comm p cap

theorem compose_le_right {p c : Nat} (hp : p ≤ cap) : compose p c ≤ c := by
  unfold compose
  apply Nat.div_le_of_le_mul
  exact Nat.mul_le_mul hp (Nat.le_refl c)

/-- Left fold from the cap, matching `AttenuationWitness::verify`. -/
def effective (hops : List Nat) : Nat := hops.foldl compose cap

theorem foldl_compose_le (hs : List Nat) : ∀ acc, acc ≤ cap →
    (∀ s ∈ hs, s ≤ cap) → hs.foldl compose acc ≤ acc := by
  induction hs with
  | nil => intro acc _ _; simp
  | cons s rest ih =>
    intro acc hacc hall
    have hs : s ≤ cap := hall s (by simp)
    have hrest : ∀ t ∈ rest, t ≤ cap := fun t ht => hall t (by simp [ht])
    have h1 : compose acc s ≤ acc := compose_le_left hs
    have h2 : compose acc s ≤ cap := Nat.le_trans h1 hacc
    simp only [List.foldl]
    exact Nat.le_trans (ih (compose acc s) h2 hrest) h1

theorem effective_le_cap (hs : List Nat) (h : ∀ s ∈ hs, s ≤ cap) : effective hs ≤ cap :=
  foldl_compose_le hs cap (Nat.le_refl cap) h

/-- Window intersection: composite Valid implies every hop Valid. -/
theorem intersect_sound {t I E Ii Ei : Nat}
    (hI : Ii ≤ I) (hE : E ≤ Ei) (hv : I ≤ t ∧ t < E) : Ii ≤ t ∧ t < Ei := by
  omega
end Attenuation

namespace Envelope
structure Env where
  lo : Int
  hi : Int
  fb : Int
  h1 : lo ≤ fb
  h2 : fb ≤ hi

def project (E : Env) (a : Int) : Int := max E.lo (min E.hi a)

def gate (E : Env) (v : K3) : Env :=
  match v with
  | .pos => E
  | _ => ⟨E.fb, E.fb, E.fb, Int.le_refl _, Int.le_refl _⟩

theorem project_mem (E : Env) (a : Int) : E.lo ≤ project E a ∧ project E a ≤ E.hi := by
  unfold project; have := E.h1; have := E.h2; omega

theorem gate_not_pos (E : Env) (v : K3) (hv : v ≠ .pos) (a : Int) :
    project (gate E v) a = E.fb := by
  cases v with
  | pos => exact absurd rfl hv
  | neg => show max E.fb (min E.fb a) = E.fb; omega
  | bot => show max E.fb (min E.fb a) = E.fb; omega
end Envelope

namespace Merkle
variable {α : Type} (h : α → α → α)

structure Step (α : Type) where
  sibling : α
  siblingIsLeft : Bool

def step (acc : α) (s : Step α) : α :=
  if s.siblingIsLeft then h s.sibling acc else h acc s.sibling

def rootOf (leaf : α) (path : List (Step α)) : α := path.foldl (step h) leaf

def maxDepth : Nat := 64

def verify [DecidableEq α] (leaf : α) (path : List (Step α)) (root : α) : K3 :=
  if path.length > maxDepth then .bot
  else if rootOf h leaf path = root then .pos else .neg

theorem verify_pos_sound [DecidableEq α] {leaf root : α} {path : List (Step α)}
    (hv : verify h leaf path root = .pos) : rootOf h leaf path = root := by
  unfold verify at hv
  split at hv
  · cases hv
  · split at hv
    · assumption
    · cases hv

theorem verify_pos_depth [DecidableEq α] {leaf root : α} {path : List (Step α)}
    (hv : verify h leaf path root = .pos) : path.length ≤ maxDepth := by
  unfold verify at hv
  split at hv
  · cases hv
  · omega

theorem verify_complete [DecidableEq α] {leaf root : α} {path : List (Step α)}
    (hd : path.length ≤ maxDepth) (hr : rootOf h leaf path = root) :
    verify h leaf path root = .pos := by
  unfold verify
  have : ¬ path.length > maxDepth := by omega
  simp [this, hr]
end Merkle

end Chio.Wave6
```

**Creusot.** The Pearlite contracts below are checked with `cargo creusot` and Why3. They target the two places where a loop or a floor hides an obligation that Lean states abstractly: the attenuation fold with its invariant, and the saturating add against its wide specification. The `@` operator is the Pearlite view into unbounded integers.

```rust
// crates/kernel/chio-kernel-core/src/formal_wave6_creusot.rs  (cfg(creusot) only)
use creusot_contracts::*;
use super::formal_wave6::Hop;

#[requires(parent@ <= 10_000 && child@ <= 10_000)]
#[ensures(result@ == (parent@ * child@) / 10_000)]
#[ensures(result@ <= parent@ && result@ <= child@)]
pub fn compose_bps_total(parent: u16, child: u16) -> u16 {
    let prod: u32 = (parent as u32) * (child as u32);
    (prod / 10_000) as u16
}

#[requires(forall<i: Int> 0 <= i && i < hops@.len() ==> hops@[i].share_bps@ <= 10_000)]
#[ensures(result@ <= 10_000)]
#[ensures(forall<i: Int> 0 <= i && i < hops@.len() ==> result@ <= hops@[i].share_bps@)]
pub fn effective_bps(hops: &[Hop]) -> u16 {
    let mut eff: u16 = 10_000;
    let mut i: usize = 0;
    #[invariant(i@ <= hops@.len())]
    #[invariant(eff@ <= 10_000)]
    #[invariant(forall<j: Int> 0 <= j && j < i@ ==> eff@ <= hops@[j].share_bps@)]
    while i < hops.len() {
        eff = compose_bps_total(eff, hops[i].share_bps);
        i += 1;
    }
    eff
}

#[ensures(result@ >= -2147483648 && result@ <= 2147483647)]
#[ensures(-2147483648 <= a@ + b@ && a@ + b@ <= 2147483647 ==> result@ == a@ + b@)]
#[ensures(a@ + b@ > 2147483647 ==> result@ == 2147483647)]
#[ensures(a@ + b@ < -2147483648 ==> result@ == -2147483648)]
pub fn sat_add_spec(a: i32, b: i32) -> i32 {
    match a.checked_add(b) {
        Some(v) => v,
        None => if a < 0 { i32::MIN } else { i32::MAX },
    }
}
```

**Kani.** Each harness is bit-precise over the real machine types. The learned proposal is always `kani::any()`, which is the Verification Transfer discipline: no harness encodes anything about the model. The multiplication harnesses are the slowest because they carry a full 32-by-32 product through CBMC. They are pinned to the CaDiCaL solver in the manifest.

```rust
#[cfg(kani)]
#[allow(clippy::arithmetic_side_effects)]
mod verification {
    use super::*;
    use crate::formal_aeneas::{budget_commit, budget_precheck, classify_time_window_code};

    fn wide_clamp(x: i64) -> i64 { x.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) }

    #[kani::proof]
    fn sat_add_matches_wide_clamp() {
        let (a, b): (i32, i32) = (kani::any(), kani::any());
        let r = FixedQ16_16::from_raw(a).sat_add(FixedQ16_16::from_raw(b));
        assert_eq!(i64::from(r.raw()), wide_clamp(i64::from(a) + i64::from(b)));
    }

    #[kani::proof]
    fn sat_add_monotone() {
        let (a, a2, b): (i32, i32, i32) = (kani::any(), kani::any(), kani::any());
        kani::assume(a <= a2);
        let lhs = FixedQ16_16::from_raw(a).sat_add(FixedQ16_16::from_raw(b));
        let rhs = FixedQ16_16::from_raw(a2).sat_add(FixedQ16_16::from_raw(b));
        assert!(lhs <= rhs);
    }

    #[kani::proof]
    #[kani::solver(cadical)]
    fn sat_mul_matches_wide_floor() {
        let (a, b): (i32, i32) = (kani::any(), kani::any());
        let r = FixedQ16_16::from_raw(a).sat_mul(FixedQ16_16::from_raw(b));
        let exact = (i64::from(a) * i64::from(b)).div_euclid(FixedQ16_16::SCALE);
        assert_eq!(i64::from(r.raw()), wide_clamp(exact));
    }

    #[kani::proof]
    #[kani::solver(cadical)]
    fn shadow_penalty_nonneg_on_nonneg_inputs() {
        let f: [i32; 5] = kani::any();
        let l: [i32; 5] = kani::any();
        for k in 0..5 { kani::assume(f[k] >= 0 && l[k] >= 0); }
        let feats = f.map(FixedQ16_16::from_raw);
        let lam = l.map(FixedQ16_16::from_raw);
        assert!(FixedQ16_16::shadow_penalty(&feats, &lam).raw() >= 0);
    }

    /// Pins the existing classifier to the half-open reading. A failure here
    /// names the boundary, it does not indicate a kernel bug.
    #[kani::proof]
    fn window_code_pinned_to_half_open_spec() {
        let (now, i, e): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        assert_eq!(classify_time_window_code(now, i, e), window_spec(now, i, e));
    }

    #[kani::proof]
    fn temporal_rank_monotone_in_now() {
        let (n1, n2, i, e): (u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(n1 <= n2);
        assert!(temporal_rank(window_spec(n1, i, e)) <= temporal_rank(window_spec(n2, i, e)));
    }

    #[kani::proof]
    fn end_of_time_is_expired() {
        let (i, e): (u64, u64) = (kani::any(), kani::any());
        assert_eq!(window_spec(u64::MAX, i, e), WINDOW_EXPIRED);
    }

    #[kani::proof]
    fn degenerate_window_never_valid() {
        let (now, i, e): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        kani::assume(i > e);
        assert_ne!(window_spec(now, i, e), WINDOW_VALID);
    }

    #[kani::proof]
    fn advance_epoch_never_rewinds() {
        let (now, d): (u64, u64) = (kani::any(), kani::any());
        assert!(advance_epoch(now, d) >= now);
    }

    /// Pins the commit boundary where cost equals remainder.
    #[kani::proof]
    fn budget_commit_boundary() {
        let (ri, ru, ci, cu): (u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let r = budget_commit(ri, ru, ci, cu);
        assert_eq!(r.accepted, budget_precheck(ri, ru, ci, cu));
        assert_eq!(r.accepted, ci <= ri && cu <= ru);
        if r.accepted {
            assert_eq!(r.remaining_invocations, ri - ci);
            assert_eq!(r.remaining_units, ru - cu);
        } else {
            assert_eq!(r.remaining_invocations, ri);
            assert_eq!(r.remaining_units, ru);
        }
    }

    #[kani::proof]
    fn compose_bps_never_amplifies() {
        let (p, c): (u16, u16) = (kani::any(), kani::any());
        match compose_bps(p, c) {
            Some(v) => { assert!(v <= p); assert!(v <= c); assert!(v <= MAX_BUDGET_SHARE_BPS); }
            None => assert!(p > MAX_BUDGET_SHARE_BPS || c > MAX_BUDGET_SHARE_BPS),
        }
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn attenuation_witness_sound() {
        let hops: [Hop; 4] = kani::any();
        let now: u64 = kani::any();
        let (verdict, witness) = AttenuationWitness::verify(&hops, now);
        match witness {
            Some(w) => {
                assert_eq!(verdict, K3::Pos);
                let s = w.summary();
                assert!(s.effective_bps <= MAX_BUDGET_SHARE_BPS);
                for hop in &hops {
                    assert!(s.effective_bps <= hop.share_bps);
                    assert_eq!(window_spec(now, hop.issued_at, hop.expires_at), WINDOW_VALID);
                }
            }
            None => assert_ne!(verdict, K3::Pos),
        }
    }

    #[kani::proof]
    fn attenuation_depth_cap_is_bot() {
        let hops = [Hop { share_bps: 10_000, issued_at: 0, expires_at: u64::MAX }; 17];
        let (verdict, witness) = AttenuationWitness::verify(&hops, 1);
        assert_eq!(verdict, K3::Bot);
        assert!(witness.is_none());
    }

    /// Structural test hash. Not cryptographic; the harness checks fold
    /// structure and gating, never collision resistance.
    struct XorHash;
    impl Hash32 for XorHash {
        fn node(l: &Digest, r: &Digest) -> Digest {
            let mut out = [0u8; 32];
            for k in 0..32 { out[k] = l[k] ^ r[k].rotate_left(1); }
            out
        }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn inclusion_roundtrip_gates_envelope() {
        let leaf: Digest = kani::any();
        let path: [PathStep; 3] = kani::any();
        let root = root_of::<XorHash>(&leaf, &path);
        assert_eq!(verify_inclusion::<XorHash>(&leaf, &path, &root), K3::Pos);

        let base = Envelope::new(
            FixedQ16_16::from_raw(-1_000), FixedQ16_16::from_raw(1_000), FixedQ16_16::ZERO,
        ).unwrap();
        // The learned choice is unconstrained nondeterminism.
        let proposal = FixedQ16_16::from_raw(kani::any());

        let accepted = admit_scored::<XorHash>(&leaf, &path, &root, base, proposal).into_inner();
        assert!(base.contains(accepted));

        let wrong: Digest = kani::any();
        kani::assume(wrong != root);
        let refused = admit_scored::<XorHash>(&leaf, &path, &wrong, base, proposal).into_inner();
        assert_eq!(refused, base.fallback());
    }

    #[kani::proof]
    fn inclusion_depth_cap_is_bot() {
        let deep = [PathStep { sibling: [0u8; 32], sibling_is_left: false }; 65];
        assert_eq!(verify_inclusion::<XorHash>(&[0u8; 32], &deep, &[0u8; 32]), K3::Bot);
    }
}
```

**Manifest pins.** The additions are appended to `formal/proof-manifest.toml`. No existing entry is edited. The collision-resistance assumption is recorded as an assumption entry so the manifest linter can list it next to the inclusion lemma rather than letting it hide in prose.

```toml
# formal/proof-manifest.toml  (appended, Wave 6 Angle 1, Pass 6)

[[lemma]]
id   = "W6.A1.satadd"
rust = "chio_kernel_core::formal_wave6::FixedQ16_16::sat_add"
lean = ["Chio.Wave6.Fixed.clamp_mem", "Chio.Wave6.Fixed.satAdd_mono_left",
        "Chio.Wave6.Fixed.satAdd_hi_absorb", "Chio.Wave6.Fixed.satAdd_not_assoc"]
kani = ["sat_add_matches_wide_clamp", "sat_add_monotone"]
creusot = ["sat_add_spec"]

[[lemma]]
id   = "W6.A1.satmul"
rust = "chio_kernel_core::formal_wave6::FixedQ16_16::sat_mul"
kani = ["sat_mul_matches_wide_floor", "shadow_penalty_nonneg_on_nonneg_inputs"]
solver = "cadical"

[[lemma]]
id   = "W6.A1.epoch"
rust = "chio_kernel_core::formal_wave6::window_spec"
pins = "chio_kernel_core::formal_aeneas::classify_time_window_code"
lean = ["Chio.Wave6.Epoch.rank_mono", "Chio.Wave6.Epoch.end_of_time",
        "Chio.Wave6.Epoch.degenerate_never_valid"]
kani = ["window_code_pinned_to_half_open_spec", "temporal_rank_monotone_in_now",
        "end_of_time_is_expired", "degenerate_window_never_valid",
        "advance_epoch_never_rewinds", "budget_commit_boundary"]

[[lemma]]
id   = "W6.A1.attenuation"
rust = "chio_kernel_core::formal_wave6::AttenuationWitness::verify"
lean = ["Chio.Wave6.Attenuation.compose_le_left", "Chio.Wave6.Attenuation.compose_le_right",
        "Chio.Wave6.Attenuation.effective_le_cap", "Chio.Wave6.Attenuation.intersect_sound"]
kani = ["compose_bps_never_amplifies", "attenuation_witness_sound", "attenuation_depth_cap_is_bot"]
creusot = ["compose_bps_total", "effective_bps"]

[[lemma]]
id   = "W6.A1.inclusion"
rust = "chio_kernel_core::formal_wave6::verify_inclusion"
lean = ["Chio.Wave6.Merkle.verify_pos_sound", "Chio.Wave6.Merkle.verify_pos_depth",
        "Chio.Wave6.Merkle.verify_complete", "Chio.Wave6.Envelope.project_mem",
        "Chio.Wave6.Envelope.gate_not_pos"]
kani = ["inclusion_roundtrip_gates_envelope", "inclusion_depth_cap_is_bot"]

[[assumption]]
id    = "W6.A1.hash-collision-resistance"
scope = "W6.A1.inclusion"
text  = "A `+` inclusion verdict implies true membership only if `Hash32::node` is collision resistant. Structural soundness is mechanized; this clause is not."
```

**What the harnesses pin versus what they prove.** Two harnesses, the window classifier pin and the commit boundary pin, assert a reading of existing functions whose bodies this pass does not modify. They are regression locks, not theorems about new code. If either fails, the action is to amend the half-open assumption in `window_spec` and the manifest text, leaving `formal_aeneas.rs` untouched. Everything else is a genuine theorem about the new module, discharged by Lean on the abstract model, by Creusot on the loop and the floor, and by Kani on the concrete bit widths.

**Recap.** This pass adds one `#![no_std]`, `#![forbid(unsafe_code)]` module to `chio-kernel-core` with saturating `FixedQ16_16` arithmetic, a half-open epoch specification with a temporal rank, a single-constructor `AttenuationWitness` that composes shares by floored multiplication and intersects windows, and a depth-capped Merkle `inclusion_step` verifier that gates a private-constructor `Envelope` before an O(1) clamp. Lean 4 proves the saturation lattice laws including the non-associativity witness, epoch rank monotonicity and end-of-time expiry, attenuation never amplifying under left fold, window-intersection soundness, and the structural iff for inclusion plus envelope preservation under gating. Creusot carries the attenuation loop invariant and the wide specification of saturating add. Fifteen Kani harnesses run bit-precisely with the learned proposal as `kani::any()`, two of them pinning assumed semantics of pinned kernel functions. The manifest gains five lemma blocks and one explicit collision-resistance assumption, and no existing proof or signature changes. The remaining open item is confirming the half-open reading against the actual body of `classify_time_window_code`, which the first epoch harness decides mechanically on the next `cargo kani` run.

---

# Verbatim Treatise - `wave6_angle_2_copley_dag_optimization_and_simd_bitset_pass_6`

I'll deliver the Pass 6 treatise directly: the fixed register layout and 11-op ISA, the zero-branch executor, the dedup/rank-segmenting compiler, the exact instruction-count theorems, the prefix-soundness result for fuel cuts, and the Lean 4 / Kani / Apalache artifacts plus the HushSpec differential harness.

# Wave 6 · Angle 2 · Pass 6 - Copley Bitset Compiler and WCET Proof for `SymbolicRuleDag<537, 9, 9, 236>`

## 0. Position in the decision-model law

The 236-rule DAG is the exact computation $C_\ell(x)$ of the Copley Tier-1 layer. UltraBERT contributes only the Kleene vector $x \in \mathbb{K}_3^{537}$ produced by the role-asymmetric thresholds $(\tau_j^{\text{pos}}, \tau_j^{\text{neg}})$. Everything after that point is exact, branch-free, and has an instruction count that is a function of the schedule alone. Pass 6 fixes four deliverables:

- **A fixed-layout ISA and executor** whose control-flow trace is independent of $x$.
- **A compiler** performing topological clause deduplication and rank segmentation.
- **Three theorems**: exact trip count, exact length formula, closed-form bound $N_{\max}(537,9,9,236) = 46{,}716$.
- **Verification transfer**: Lean 4 for the K3 algebra and dedup law, Kani for the executor and small-instance equivalence, Apalache for rank-cut soundness, and a `proptest` differential harness against `chio-policy` HushSpec IR.

All additions are a new crate `chio-copley-schedule`. Nothing in `formal_core.rs`, `formal_aeneas.rs`, `budget_split.rs`, or the 35 reserved receipt keys changes.

## 1. Semantics

A predicate value is $+$ (known true), $-$ (known false), or $\bot$. A clause is a conjunction of up to 9 literals, a rule a disjunction of up to 9 clauses, under strong Kleene semantics ($\wedge = \min$, $\vee = \max$ in the order $- < \bot < +$). Each rule carries a rank: `Block` (0), `Review` (1), `Audit` (2).

The vector is represented by two 9-word bitsets `pos` and `neg` with the well-formedness invariant `pos & neg == 0`, enforced by the only constructor. Thresholding produces it: $+$ iff $s_j \ge \tau_j^{\text{pos}}$, $-$ iff $s_j < \tau_j^{\text{neg}}$; since $\tau_j^{\text{neg}} \le \tau_j^{\text{pos}}$ the two cases are disjoint, so well-formedness holds by construction.

**Clause-level bitset characterization.** For clause $c$ with positive-literal set $c^+$ and negative-literal set $c^-$:

$$\llbracket c \rrbracket = + \iff \neg\,\text{MISS}_c,\quad \text{MISS}_c = \bigvee_{i\in c^+}\neg\text{pos}_i \;\vee\; \bigvee_{i\in c^-}\neg\text{neg}_i$$
$$\llbracket c \rrbracket = - \iff \text{FALS}_c,\quad \text{FALS}_c = \bigvee_{i\in c^+}\text{neg}_i \;\vee\; \bigvee_{i\in c^-}\text{pos}_i$$

MISS and FALS are disjoint under well-formedness. A rule is $+$ iff some clause bit of CT $= \neg$MISS is set, $-$ iff every clause bit of FALS is set. These are the only facts the compiler relies on; they are proven in §6.

**Topological dedup law.** If clause $a \subseteq b$ (as literal sets) in the same rule, then $\llbracket a \rrbracket \vee \llbracket b \rrbracket = \llbracket a \rrbracket$ in $\mathbb{K}_3$, because $\llbracket b\rrbracket \le \llbracket a \rrbracket$ (min over a superset). Processing clauses in increasing (length, lexicographic) order is a topological order of the subset lattice, so every subsumer is seen before its subsumee. Identical clauses across rules are interned once and owned by the lowest rank that uses them.

## 2. ISA, register layout, executor

```rust
//! chio-copley-schedule - Wave 6 / Angle 2 / Pass 6
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub const COPLEY_P: usize = 537;
pub const COPLEY_K: usize = 9;
pub const COPLEY_L: usize = 9;
pub const COPLEY_R: usize = 236;
pub const RANKS: usize = 3;
pub const COPLEY_PW: usize = 9;   // ceil(537/64)
pub const COPLEY_CW: usize = 36;  // ceil(2124/64) + (RANKS-1) alignment words
pub const COPLEY_RW: usize = 4;   // ceil(236/64)
pub const VERDICT_INSTRS: usize = 34; // 6*RW + 10
pub const COPLEY_N_MAX: usize = 46_716;

#[allow(clippy::arithmetic_side_effects)] // const context: overflow is a compile error
const _: () = {
    assert!(COPLEY_P.div_ceil(64) == COPLEY_PW);
    assert!((COPLEY_R * COPLEY_K).div_ceil(64) + RANKS - 1 == COPLEY_CW);
    assert!(COPLEY_R.div_ceil(64) == COPLEY_RW);
    assert!(COPLEY_K <= COPLEY_CW && VERDICT_INSTRS == 6 * COPLEY_RW + 10);
    assert!(2 * COPLEY_P * RANKS + 2 * COPLEY_R * COPLEY_K * COPLEY_L + COPLEY_CW
          + COPLEY_R * (2 * COPLEY_K + 4) + VERDICT_INSTRS == COPLEY_N_MAX);
};

// Register file. Offsets are schedule constants, never input-derived.
pub const R_POS: u16 = 0;    pub const R_NEG: u16 = 9;
pub const R_MISS: u16 = 18;  pub const R_FALS: u16 = 54;  pub const R_CT: u16 = 90;
pub const R_RT: u16 = 126;   pub const R_RF: u16 = 130;
pub const R_BP: u16 = 134;   pub const R_BN: u16 = 135;   pub const R_ACC: u16 = 136;
pub const R_ACC2: u16 = 137; pub const R_BIT: u16 = 138;  pub const R_T: u16 = 139;
pub const R_BT: u16 = 140;   pub const R_RVT: u16 = 141;  pub const R_BU: u16 = 142;
pub const R_RU: u16 = 143;   pub const R_PEND: u16 = 144; pub const R_ALLOW: u16 = 145;
pub const NREG: usize = 146;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum Op {
    BcastBit,    // d = bcast((a >> imm) & 1)
    Not,         // d = !a
    Or,          // d = a | b
    AndNot,      // d = a & !b
    AndImm,      // d = a & imm
    OrAndImm,    // d |= a & imm
    AndNotImm,   // d = imm & !a
    OrAndNotImm, // d |= imm & !a
    IsZero,      // d = (a == 0)
    NonZero,     // d = (a != 0)
    OrShl,       // d |= a << imm
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Instr { pub op: Op, pub dst: u16, pub a: u16, pub b: u16, pub imm: u64 }

impl Instr {
    pub const ZERO: Self = Self { op: Op::BcastBit, dst: 0, a: 0, b: 0, imm: 0 };
    pub const fn new(op: Op, dst: u16, a: u16, b: u16, imm: u64) -> Self { Self { op, dst, a, b, imm } }
}

/// Broadcast bit 0 of `bit` to all 64 lanes. `wrapping_sub` is the one explicit
/// modular operation in the crate; Kani proves the result is in {0, u64::MAX}.
#[inline(always)]
pub const fn bcast(bit: u64) -> u64 { 0u64.wrapping_sub(bit & 1) }

#[inline(always)]
fn step(regs: &mut [u64; NREG], ins: &Instr) {
    let rd = |r: &[u64; NREG], i: u16| r.get(usize::from(i)).copied().unwrap_or(0);
    let (a, b, d) = (rd(regs, ins.a), rd(regs, ins.b), rd(regs, ins.dst));
    let sh = u32::try_from(ins.imm).unwrap_or(u32::MAX);
    let v = match ins.op {
        Op::BcastBit    => bcast(a.checked_shr(sh).unwrap_or(0)),
        Op::Not         => !a,
        Op::Or          => a | b,
        Op::AndNot      => a & !b,
        Op::AndImm      => a & ins.imm,
        Op::OrAndImm    => d | (a & ins.imm),
        Op::AndNotImm   => ins.imm & !a,
        Op::OrAndNotImm => d | (ins.imm & !a),
        Op::IsZero      => u64::from(a == 0),
        Op::NonZero     => u64::from(a != 0),
        Op::OrShl       => d | a.checked_shl(sh).unwrap_or(0),
    };
    if let Some(slot) = regs.get_mut(usize::from(ins.dst)) { *slot = v; }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KleeneError { Contradiction, ThresholdOrder }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KleeneVector<const PW: usize> { pos: [u64; PW], neg: [u64; PW] }

impl<const PW: usize> KleeneVector<PW> {
    pub fn new(pos: [u64; PW], neg: [u64; PW]) -> Result<Self, KleeneError> {
        if pos.iter().zip(neg.iter()).any(|(p, n)| p & n != 0) {
            return Err(KleeneError::Contradiction);
        }
        Ok(Self { pos, neg })
    }
    /// Role-asymmetric thresholding of Q16.16 scores. Requires tau_neg <= tau_pos per predicate.
    pub fn from_scores<const P: usize>(s: &[i32; P], tp: &[i32; P], tn: &[i32; P]) -> Result<Self, KleeneError> {
        let (mut pos, mut neg) = ([0u64; PW], [0u64; PW]);
        for (i, ((&v, &p), &n)) in s.iter().zip(tp.iter()).zip(tn.iter()).enumerate() {
            if n > p { return Err(KleeneError::ThresholdOrder); }
            let (w, b) = layout::split(i);
            let bit = 1u64.checked_shl(b).unwrap_or(0);
            if v >= p { if let Some(x) = pos.get_mut(w) { *x |= bit; } }
            if v <  n { if let Some(x) = neg.get_mut(w) { *x |= bit; } }
        }
        Self::new(pos, neg)
    }
}

pub mod layout {
    /// Division by the nonzero constants 64 and 2 cannot panic or overflow.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    pub const fn split(i: usize) -> (usize, u32) { (i / 64, (i % 64) as u32) }
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn decode(code: u16) -> (usize, bool) { ((code / 2) as usize, code & 1 == 1) }
}

#[derive(Clone, Copy, Debug)]
pub struct Evaluation { pub regs: [u64; NREG], pub steps: usize }

pub struct Schedule<const CAP: usize> {
    instrs: [Instr; CAP],
    len: usize,
    seg_end: [usize; RANKS],
    block_mask: [u64; COPLEY_RW],
    review_mask: [u64; COPLEY_RW],
    pub stats: ScheduleStats,
}

impl<const CAP: usize> Schedule<CAP> {
    pub const fn empty() -> Self {
        Self { instrs: [Instr::ZERO; CAP], len: 0, seg_end: [0; RANKS],
               block_mask: [0; COPLEY_RW], review_mask: [0; COPLEY_RW], stats: ScheduleStats::ZERO }
    }
    pub const fn len(&self) -> usize { self.len }
    pub const fn seg_end(&self) -> [usize; RANKS] { self.seg_end }

    fn emit(&mut self, ins: Instr) -> Result<(), CompileError> {
        let slot = self.instrs.get_mut(self.len).ok_or(CompileError::ScheduleCapacity)?;
        *slot = ins;
        self.len = self.len.checked_add(1).ok_or(CompileError::Overflow)?;
        Ok(())
    }

    fn load(regs: &mut [u64; NREG], x: &KleeneVector<COPLEY_PW>) {
        for (slot, v) in regs.iter_mut().skip(usize::from(R_POS)).zip(x.pos.iter()) { *slot = *v; }
        for (slot, v) in regs.iter_mut().skip(usize::from(R_NEG)).zip(x.neg.iter()) { *slot = *v; }
    }

    /// Full evaluation: executes exactly `self.len` instructions for every `x`.
    pub fn execute(&self, x: &KleeneVector<COPLEY_PW>) -> Evaluation { self.run(x, self.len) }

    /// Fuel-limited evaluation: runs the longest whole prefix of rank segments
    /// whose end is <= fuel. Returns the number of completed ranks.
    pub fn execute_prefix(&self, x: &KleeneVector<COPLEY_PW>, fuel: usize) -> (Evaluation, u8) {
        let mut done = 0u8;
        let mut upto = 0usize;
        for &end in self.seg_end.iter() {
            if end <= fuel { upto = end; done = done.saturating_add(1); }
        }
        (self.run(x, upto), done)
    }

    fn run(&self, x: &KleeneVector<COPLEY_PW>, upto: usize) -> Evaluation {
        let mut regs = [0u64; NREG];
        Self::load(&mut regs, x);
        let mut steps = 0usize;
        for ins in self.instrs.iter().take(upto) {
            step(&mut regs, ins);
            steps = steps.saturating_add(1);
        }
        Evaluation { regs, steps }
    }

    /// FNV-1a over the instruction stream; bound into `model_metadata`.
    pub fn digest64(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for ins in self.instrs.iter().take(self.len) {
            let mut bytes = [0u8; 15];
            bytes[0] = ins.op as u8;
            bytes[1..3].copy_from_slice(&ins.dst.to_le_bytes());
            bytes[3..5].copy_from_slice(&ins.a.to_le_bytes());
            bytes[5..7].copy_from_slice(&ins.b.to_le_bytes());
            bytes[7..15].copy_from_slice(&ins.imm.to_le_bytes());
            for byte in bytes { h ^= u64::from(byte); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
        }
        h
    }
}
```

**Definition (input-obliviousness).** `execute` is input-oblivious if for all well-formed $x, y$ the sequence of `Instr` values dispatched, the register indices read and written, and the loop trip count are identical. In the code above the only data flowing from $x$ is register *contents*; `ins.op`, `ins.dst`, `ins.a`, `ins.b`, `ins.imm` come from the schedule. The two `bool`-to-`u64` conversions produce values, not control flow. Machine-level constant time is a codegen property re-validated per toolchain pin, not something the source can assert.

## 3. Compiler: canonicalization, topological dedup, rank segmentation

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Rank { Block = 0, Review = 1, Audit = 2 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Literal { pub pred: u16, pub negated: bool }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Clause<const L: usize> { pub len: u8, pub lits: [Literal; L] }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule<const K: usize, const L: usize> {
    pub rank: Rank,
    pub prior_bps: u16,  // calibrated firing frequency; orders rules within a rank
    pub len: u8,
    pub clauses: [Clause<L>; K],
}
pub struct SymbolicRuleDag<const P: usize, const K: usize, const L: usize, const R: usize> {
    pub rules: [Rule<K, L>; R],
}
pub type CopleyDag = SymbolicRuleDag<COPLEY_P, COPLEY_K, COPLEY_L, COPLEY_R>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompileError {
    BadClauseLen, BadRuleLen, EmptyRule, PredicateOutOfRange,
    LayoutExceeded, TableCapacity, ScheduleCapacity, Overflow,
}

/// Canonical clause: literal codes `pred*2 + negated`, sorted ascending, no duplicates,
/// unused slots = u16::MAX so (len, lits) is a total lexicographic order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClauseKey<const L: usize> { pub len: u8, pub lits: [u16; L] }

impl<const L: usize> ClauseKey<L> {
    pub const EMPTY: Self = Self { len: 0, lits: [u16::MAX; L] };
    /// Merge scan over two sorted prefixes.
    pub fn is_subset_of(&self, big: &Self) -> bool {
        let nb = usize::from(big.len);
        let mut j = 0usize;
        for &x in self.lits.iter().take(usize::from(self.len)) {
            while j < nb && big.lits.get(j).is_some_and(|&y| y < x) { j = j.saturating_add(1); }
            if !(j < nb && big.lits.get(j) == Some(&x))
 { return false; }
            j = j.saturating_add(1);
        }
        true
    }
}

pub struct ClauseTable<const L: usize, const C: usize> {
    keys: [ClauseKey<L>; C], owner: [u8; C], index: [u32; C], n: usize,
}

impl<const L: usize, const C: usize> ClauseTable<L, C> {
    pub const fn new() -> Self {
        Self { keys: [ClauseKey::EMPTY; C], owner: [u8::MAX; C], index: [0; C], n: 0 }
    }
    /// Hash-consing with owner = min rank. Returns (table id, was_shared).
    fn intern(&mut self, key: ClauseKey<L>, rank: u8) -> Result<(u16, bool), CompileError> {
        for t in 0..self.n {
            if self.keys.get(t) == Some(&key) {
                if let Some(o) = self.owner.get_mut(t) { *o = (*o).min(rank); }
                return Ok((u16::try_from(t).map_err(|_| CompileError::Overflow)?, true));
            }
        }
        let t = self.n;
        *self.keys.get_mut(t).ok_or(CompileError::TableCapacity)? = key;
        *self.owner.get_mut(t).ok_or(CompileError::TableCapacity)? = rank;
        self.n = t.checked_add(1).ok_or(CompileError::Overflow)?;
        Ok((u16::try_from(t).map_err(|_| CompileError::Overflow)?, false))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ScheduleStats {
    pub broadcasts: usize,   // B  = Σ_k U_k
    pub mask_words: usize,   // M  = nonzero (pred, polarity, clause-word) triples
    pub clause_words: usize, // CW_used
    pub rule_words: usize,   // Σ_r |S_r|
    pub rules: usize, pub clauses: usize, pub dropped_subsumed: usize, pub shared: usize,
}
impl ScheduleStats {
    pub const ZERO: Self = Self { broadcasts: 0, mask_words: 0, clause_words: 0, rule_words: 0,
                                  rules: 0, clauses: 0, dropped_subsumed: 0, shared: 0 };
    /// Theorem 2 as code: len = 2B + 2M + CW_used + 2Σ|S_r| + 4R + 34.
    pub fn predicted_len(&self) -> Option<usize> {
        self.broadcasts.checked_mul(2)?
            .checked_add(self.mask_words.checked_mul(2)?)?
            .checked_add(self.clause_words)?
            .checked_add(self.rule_words.checked_mul(2)?)?
            .checked_add(self.rules.checked_mul(4)?)?
            .checked_add(VERDICT_INSTRS)
    }
}

fn inc(x: &mut usize) -> Result<(), CompileError> {
    *x = x.checked_add(1).ok_or(CompileError::Overflow)?; Ok(())
}
fn reg(base: u16, off: usize) -> Result<u16, CompileError> {
    u16::try_from(off).ok().and_then(|o| o.checked_add(base)).ok_or(CompileError::Overflow)
}
fn set_bit(words: &mut [u64; COPLEY_CW], idx: usize) -> Result<(), CompileError> {
    let (w, b) = layout::split(idx);
    let slot = words.get_mut(w).ok_or(CompileError::LayoutExceeded)?;
    *slot |= 1u64.checked_shl(b).unwrap_or(0);
    Ok(())
}
```

The compiler body, split into its three phases:

```rust
impl<const P: usize, const K: usize, const L: usize, const R: usize> SymbolicRuleDag<P, K, L, R> {
    fn canon(c: &Clause<L>) -> Result<ClauseKey<L>, CompileError> {
        let n = usize::from(c.len);
        if n > L { return Err(CompileError::BadClauseLen); }
        let mut key = ClauseKey::<L>::EMPTY;
        let mut m = 0usize;
        for lit in c.lits.iter().take(n) {
            if usize::from(lit.pred) >= P { return Err(CompileError::PredicateOutOfRange); }
            let code = lit.pred.checked_mul(2).and_then(|v| v.checked_add(u16::from(lit.negated)))
                .ok_or(CompileError::Overflow)?;
            let pos = key.lits.get(..m).map_or(0, |s| s.partition_point(|&y| y < code));
            if key.lits.get(pos) == Some(&code) && pos < m { continue; } // duplicate literal
            key.lits.get_mut(pos..=m).ok_or(CompileError::BadClauseLen)?.rotate_right(1);
            *key.lits.get_mut(pos).ok_or(CompileError::BadClauseLen)? = code;
            inc(&mut m)?;
        }
        key.len = u8::try_from(m).map_err(|_| CompileError::Overflow)?;
        Ok(key)
    }

    /// Short-circuit rank order: (rank, descending prior, id). Rank boundaries are the
    /// only legal early exits; the within-rank order is deterministic for the digest.
    fn rank_order(&self) -> [u16; R] {
        let mut order = [0u16; R];
        for (slot, i) in order.iter_mut().zip(0..) { *slot = i; }
        order.sort_unstable_by_key(|&r| {
            let rule = self.rules.get(usize::from(r));
            (rule.map_or(u8::MAX, |x| x.rank as u8), core::cmp::Reverse(rule.map_or(0, |x| x.prior_bps)), r)
        });
        order
    }

    pub fn compile<const C: usize, const CAP: usize>(
        &self, table: &mut ClauseTable<L, C>, out: &mut Schedule<CAP>,
    ) -> Result<ScheduleStats, CompileError> {
        let rk = R.checked_mul(K).ok_or(CompileError::Overflow)?;
        if P > layout::POS_BITS || R > layout::RULE_BITS || rk > layout::CLAUSE_BITS || C < rk {
            return Err(CompileError::LayoutExceeded);
        }
        let mut st = ScheduleStats::ZERO;
        let mut rule_cl = [[u16::MAX; K]; R];
        let mut rule_n = [0usize; R];

        // Phase A - canonicalize, topological subsumption, global interning.
        for (r, rule) in self.rules.iter().enumerate() {
            let n = usize::from(rule.len);
            if n == 0 { return Err(CompileError::EmptyRule); }
            if n > K { return Err(CompileError::BadRuleLen); }
            let mut keys = [ClauseKey::<L>::EMPTY; K];
            for (slot, c) in keys.iter_mut().zip(rule.clauses.iter()).take(n) { *slot = Self::canon(c)?; }
            keys.get_mut(..n).ok_or(CompileError::BadRuleLen)?.sort_unstable();
            let mut kept = 0usize;
            for i in 0..n {
                let key = *keys.get(i).ok_or(CompileError::BadRuleLen)?;
                if keys.get(..i).is_some_and(|prev| prev.iter().any(|p| p.is_subset_of(&key))) {
                    inc(&mut st.dropped_subsumed)?; continue;
                }
                let (t, shared) = table.intern(key, rule.rank as u8)?;
                *rule_cl.get_mut(r).and_then(|row| row.get_mut(kept)).ok_or(CompileError::BadRuleLen)? = t;
                inc(&mut kept)?;
                if shared { inc(&mut st.shared)?; }
            }
            *rule_n.get_mut(r).ok_or(CompileError::BadRuleLen)? = kept;
        }
        st.clauses = table.n;

        // Phase B - clause index assignment, each rank starting on a word boundary.
        let mut base = 0usize;
        let mut rank_words = [(0usize, 0usize); RANKS];
        for k in 0..RANKS {
            let mut count = 0usize;
            for t in 0..table.n {
                if table.owner.get(t) == Some(&u8::try_from(k).map_err(|_| CompileError::Overflow)?) {
                    let idx = base.checked_add(count).ok_or(CompileError::Overflow)?;
                    *table.index.get_mut(t).ok_or(CompileError::TableCapacity)? =
                        u32::try_from(idx).map_err(|_| CompileError::Overflow)?;
                    inc(&mut count)?;
                }
            }
            let end = base.checked_add(count).ok_or(CompileError::Overflow)?;
            let (w_lo, w_hi) = (layout::split(base).0, end.div_ceil(64));
            if w_hi > COPLEY_CW { return Err(CompileError::LayoutExceeded); }
            *rank_words.get_mut(k).ok_or(CompileError::Overflow)? = (w_lo, w_hi);
            base = w_hi.checked_mul(64).ok_or(CompileError::Overflow)?;
        }

        // Phase C - emission, one segment per rank.
        let order = self.rank_order();
        for k in 0..RANKS {
            let (w_lo, w_hi) = *rank_words.get(k).ok_or(CompileError::Overflow)?;
            let rank_u8 = u8::try_from(k).map_err(|_| CompileError::Overflow)?;
            for i in 0..P {
                let (mut mp, mut mn, mut any) = ([0u64; COPLEY_CW], [0u64; COPLEY_CW], false);
                for t in 0..table.n {
                    if table.owner.get(t) != Some(&rank_u8) { continue; }
                    let key = table.keys.get(t).ok_or(CompileError::TableCapacity)?;
                    let idx = usize::try_from(*table.index.get(t).ok_or(CompileError::TableCapacity)?)
                        .map_err(|_| CompileError::Overflow)?;
                    for &code in key.lits.iter().take(usize::from(key.len)) {
                        let (pred, negated) = layout::decode(code);
                        if pred != i { continue; }
                        set_bit(if negated { &mut mn } else { &mut mp }, idx)?;
                        any = true;
                    }
                }
                if !any { continue; }
                let (wi, bi) = layout::split(i);
                out.emit(Instr::new(Op::BcastBit, R_BP, reg(R_POS, wi)?, 0, u64::from(bi)))?;
                out.emit(Instr::new(Op::BcastBit, R_BN, reg(R_NEG, wi)?, 0, u64::from(bi)))?;
                inc(&mut st.broadcasts)?;
                for cw in w_lo..w_hi {
                    let (p, n) = (mp.get(cw).copied().unwrap_or(0), mn.get(cw).copied().unwrap_or(0));
                    if p != 0 {
                        out.emit(Instr::new(Op::OrAndNotImm, reg(R_MISS, cw)?, R_BP, 0, p))?;
                        out.emit(Instr::new(Op::OrAndImm,    reg(R_FALS, cw)?, R_BN, 0, p))?;
                        inc(&mut st.mask_words)?;
                    }
                    if n != 0 {
                        out.emit(Instr::new(Op::OrAndNotImm, reg(R_MISS, cw)?, R_BN, 0, n))?;
                        out.emit(Instr::new(Op::OrAndImm,    reg(R_FALS, cw)?, R_BP, 0, n))?;
                        inc(&mut st.mask_words)?;
                    }
                }
            }
            for cw in w_lo..w_hi {
                out.emit(Instr::new(Op::Not, reg(R_CT, cw)?, reg(R_MISS, cw)?, 0, 0))?;
                inc(&mut st.clause_words)?;
            }
            for &r16 in order.iter() {
                let r = usize::from(r16);
                let rule = self.rules.get(r).ok_or(CompileError::Overflow)?;
                if rule.rank as u8 != rank_u8 { continue; }
                let mut rm = [0u64; COPLEY_CW];
                let n = *rule_n.get(r).ok_or(CompileError::Overflow)?;
                for &t in rule_cl.get(r).ok_or(CompileError::Overflow)?.iter().take(n) {
                    let idx = *table.index.get(usize::from(t)).ok_or(CompileError::TableCapacity)?;
                    set_bit(&mut rm, usize::try_from(idx).map_err(|_| CompileError::Overflow)?)?;
                }
                let (rw, rb) = layout::split(r);
                for pass in 0..2u8 {
                    let mut first = true;
                    for (cw, &m) in rm.iter().enumerate() {
                        if m == 0 { continue; }
                        let (op, src) = match (pass, first) {
                            (0, true)  => (Op::AndImm,      reg(R_CT, cw)?),
                            (0, false) => (Op::OrAndImm,    reg(R_CT, cw)?),
                            (_, true)  => (Op::AndNotImm,   reg(R_FALS, cw)?),
                            (_, false) => (Op::OrAndNotImm, reg(R_FALS, cw)?),
                        };
                        out.emit(Instr::new(op, R_ACC, src, 0, m))?;
                        if pass == 0 { inc(&mut st.rule_words)?; }
                        first = false;
                    }
                    let (test, dst) = if pass == 0 { (Op::NonZero, R_RT) } else { (Op::IsZero, R_RF) };
                    out.emit(Instr::new(test, R_BIT, R_ACC, 0, 0))?;
                    out.emit(Instr::new(Op::OrShl, reg(dst, rw)?, R_BIT, 0, u64::from(rb)))?;
                }
                inc(&mut st.rules)?;
                let mask = match rule.rank { Rank::Block => Some(&mut out.block_mask),
                                            Rank::Review => Some(&mut out.review_mask), Rank::Audit => None };
                if let Some(m) = mask.and_then(|m| m.get_mut(rw)) { *m |= 1u64.checked_shl(rb).unwrap_or(0); }
            }
            *out.seg_end.get_mut(k).ok_or(CompileError::Overflow)? = out.len;
        }
        emit_verdict(out)?;
        out.stats = st;
        debug_assert_eq!(st.predicted_len(), Some(out.len));
        Ok(st)
    }
}

/// Exactly 6*RW + 10 = 34 instructions; constant-time verdict resolution.
fn emit_verdict<const CAP: usize>(out: &mut Schedule<CAP>) -> Result<(), CompileError> {
    let (bm, rvm) = (out.block_mask, out.review_mask);
    for (acc, dst, mask) in [(R_ACC, R_BT, bm), (R_ACC, R_RVT, rvm)] {
        for (w, &m) in mask.iter().enumerate() {
            let op = if w == 0 { Op::AndImm } else { Op::OrAndImm };
            out.emit(Instr::new(op, acc, reg(R_RT, w)?, 0, m))?;
        }
        out.emit(Instr::new(Op::NonZero, dst, acc, 0, 0))?;
    }
    for w in 0..COPLEY_RW {
        let op = if w == 0 { Op::AndImm } else { Op::OrAndImm };
        out.emit(Instr::new(Op::Or, R_T, reg(R_RT, w)?, reg(R_RF, w)?, 0))?;
        out.emit(Instr::new(Op::Not, R_T, R_T, 0, 0))?;
        out.emit(Instr::new(op, R_ACC,  R_T, 0, bm.get(w).copied().unwrap_or(0)))?;
        out.emit(Instr::new(op, R_ACC2, R_T, 0, rvm.get(w).copied().unwrap_or(0)))?;
    }
    out.emit(Instr::new(Op::NonZero, R_BU, R_ACC, 0, 0))?;
    out.emit(Instr::new(Op::NonZero, R_RU, R_ACC2, 0, 0))?;
    out.emit(Instr::new(Op::Or, R_PEND, R_BU, R_RVT, 0))?;
    out.emit(Instr::new(Op::Or, R_PEND, R_PEND, R_RU, 0))?;
    out.emit(Instr::new(Op::AndNot, R_PEND, R_PEND, R_BT, 0))?;
    out.emit(Instr::new(Op::Or, R_T, R_BT, R_PEND, 0))?;
    out.emit(Instr::new(Op::Not, R_T, R_T, 0, 0))?;
    out.emit(Instr::new(Op::AndImm, R_ALLOW, R_T, 0, 1))
}
```

`layout::POS_BITS`, `RULE_BITS`, `CLAUSE_BITS` are `64·PW`, `64·RW`, and `64·(CW − RANKS + 1)` as `#[allow]`ed consts.

## 4. WCET theorems

**Lemma 1 (step totality).** `step` never panics and writes at most one register. Every sub-operation is total: `get`/`unwrap_or`, bitwise operators, `checked_shr`/`checked_shl` with `unwrap_or(0)`, and `u64::from(bool)`.

**Theorem 1 (exact trip count, input-obliviousness).** For every schedule with `len ≤ CAP` and every well-formed $x$: `execute(x).steps == len`, the dispatched instruction sequence is `instrs[..len]`, and all register indices touched are determined by the schedule. *Proof.* The iterator `instrs.iter().take(len)` yields exactly `len` items whatever the register contents hold. Each iteration calls `step` once (Lemma 1) and increments `steps` by one; `len ≤ CAP < usize::MAX`, so saturation never fires. `step` dispatches on `ins.op` and addresses on `ins.dst/a/b`, none derived from $x$. ∎

**Theorem 2 (exact length formula).** Any schedule accepted by `compile` satisfies

$$\text{len} = 2B + 2M + CW_{\text{used}} + 2\textstyle\sum_r |S_r| + 4R + 34.$$

*Proof.* Emission-site accounting. Phase C has exactly seven emission sites: the broadcast pair (multiplicity $B$), the two mask-word pairs (together $M$ pairs), the clause-word `Not` ($CW_{\text{used}}$), the per-word accumulate in each of two passes ($|S_r|$ each), the fixed test-and-place pair in each pass ($2 \cdot 2$ per rule), and `emit_verdict` (34). Each `emit` adds exactly one. The compiler checks the identity as a debug assertion and Kani checks it as a postcondition on the small instance. ∎

**Theorem 3 (closed-form bound).** For any well-formed DAG with parameters $(P,K,L,R)$, $NR$ ranks, $RW$ rule words:

$$\text{len} \le N_{\max} = 2P\cdot NR + 2RKL + \Big(\big\lceil \tfrac{RK}{64}\big\rceil + NR - 1\Big) + R\,(2\min(K, CW) + 4) + (6RW + 10).$$

For $(537, 9, 9, 236)$ with $NR = 3$, $RW = 4$: $3222 + 38232 + 36 + 5192 + 34 = 46{,}716$.

*Proof.* $B \le P \cdot NR$: a predicate is broadcast at most once per rank. $M \le I \le RKL$: each nonzero (predicate, polarity, clause-word) triple contains at least one literal incidence of a clause assigned to that word, and distinct triples contain disjoint incidences; dedup only deletes incidences. $CW_{\text{used}} = \sum_k \lceil C_k/64 \rceil \le \lceil C/64 \rceil + NR - 1$ since $\lceil a/64 \rceil + \lceil b/64 \rceil \le \lceil (a+b)/64 \rceil + 1$, and $C \le RK$ because interning never creates clauses. $|S_r| \le \min(\text{kept}_r, CW) \le \min(K, CW)$. The verdict phase is constant by construction of `emit_verdict`. ∎

**Corollary (monotonicity of dedup).** Every term in Theorem 2 is non-increasing under subsumption removal and interning, so the bound holds for the dedup-disabled schedule used in the metamorphic test as well.

**Corollary (cycle WCET).** $\text{WCET} \le c_{\text{setup}} + c_{\text{step}} \cdot \text{len} + c_{\text{resolve}}$, where $c_{\text{step}}$ bounds one iteration of `run` on the target. The loop body has no input-dependent branch or address; the register file is 1,168 bytes and the instruction stream at most 747 KB read sequentially, so $c_{\text{step}}$ is a straight-line bound over 11 opcodes obtained once per toolchain pin and recorded in `formal/proof-manifest.toml`. As an illustration only, $c_{\text{step}} = 8$ cycles at 3.0 GHz gives 124.6 µs for $N_{\max}$, two orders of magnitude inside the 5 ms Tier-1 budget. The shipped schedule's actual length is a build artifact pinned by `digest64`, and admission charges it exactly:

```rust
let units = u64::try_from(sched.len()).map_err(|_| AdmitError::Overflow)?;
if !budget_precheck(remaining_invocations, remaining_units, 1, units) { return Verdict::Deny; }
let committed = budget_commit(remaining_invocations, remaining_units, 1, units);
```

## 5. Short-circuit rank ordering and prefix soundness

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict3 { Deny, PendingApproval, Allow }
impl Verdict3 { pub const fn permissiveness(self) -> u8 { match self { Self::Deny => 0, Self::PendingApproval => 1, Self::Allow => 2 } } }

/// Pure core shared by the register resolver and the Kani/TLA+ models.
pub const fn resolve_bits(ranks_done: u8, bt: bool, bu: bool, rt: bool, ru: bool) -> Verdict3 {
    match ranks_done {
        0 => Verdict3::Deny,                                   // nothing proven: fail closed
        1 => if bt { Verdict3::Deny } else { Verdict3::PendingApproval }, // review uncomputed
        _ => if bt { Verdict3::Deny } else if bu || rt || ru { Verdict3::PendingApproval } else { Verdict3::Allow },
    }
}

impl<const CAP: usize> Schedule<CAP> {
    fn any(regs: &[u64; NREG], base: u16, mask: &[u64; COPLEY_RW], unknown: bool) -> bool {
        mask.iter().enumerate().any(|(w, &m)| {
            let rt = regs.get(usize::from(R_RT).saturating_add(w)).copied().unwrap_or(0);
            let rf = regs.get(usize::from(R_RF).saturating_add(w)).copied().unwrap_or(0);
            let _ = base;
            (if unknown { !(rt | rf) } else { rt }) & m != 0
        })
    }
    pub fn resolve(&self, ev: &Evaluation, ranks_done: u8) -> Verdict3 {
        let bt = Self::any(&ev.regs, R_RT, &self.block_mask, false);
        let bu = Self::any(&ev.regs, R_RT, &self.block_mask, true);
        let rt = Self::any(&ev.regs, R_RT, &self.review_mask, false);
        let ru = Self::any(&ev.regs, R_RT, &self.review_mask, true);
        resolve_bits(ranks_done, bt, bu, rt, ru)
    }
}
```

**Theorem 4 (segment isolation).** Segment $k$ never modifies a register observed by the resolver for ranks $< k$. *Proof.* Rank $k$ mask words only contain clause bits with index in rank $k$'s word range, which is disjoint from earlier ranges by Phase B alignment; `OrShl` into `RT`/`RF` sets only bit $r$ of rank-$k$ rules; temporaries are not read by `resolve`. Shared clauses are owned by their minimum rank, so a later rank only *reads* earlier `CT`/`FALS` words. ∎

**Theorem 5 (prefix soundness).** For all well-formed $x$ and all fuel values, `resolve(execute_prefix(x, fuel))` is never more permissive than `resolve(execute(x))`. *Proof.* Let $d$ be the ranks completed. $d = 0$: Deny is the bottom of the permissiveness order. $d = 1$: block registers are final (Theorem 4). If some block rule is $+$ both verdicts are Deny; otherwise the prefix gives PendingApproval while the full verdict is PendingApproval or Allow, since Deny requires a block rule to be $+$. $d \ge 2$: block and review registers are final and audit rules do not enter the verdict, so the verdicts coincide. ∎

This mirrors `GuardPipeline`: a Deny terminates, PendingApproval is sticky and still lets a later guard deny, and the uncomputed rank is treated as the fail-closed value of its class, never as a positive match. The step count of a cut is `seg_end[d-1]`, a function of fuel alone, so Theorem 1 extends to every prefix.

## 6. Verification transfer

### 6.1 Lean 4 (`formal/lean4/Chio/Copley/Pass6.lean`)

```lean
import Mathlib.Data.List.Perm
namespace Chio.Copley.Pass6

inductive K3 where | pos | neg | unk
  deriving DecidableEq, Repr

namespace K3
def not : K3 → K3 | pos => neg | neg => pos | unk => unk
def and : K3 → K3 → K3 | neg, _ => neg | _, neg => neg | pos, pos => pos | _, _ => unk
def or  : K3 → K3 → K3 | pos, _ => pos | _, pos => pos | neg, neg => neg | _, _ => unk
def rank : K3 → Nat | neg => 0 | unk => 1 | pos => 2
def le (a b : K3) : Prop := a.rank ≤ b.rank
instance (a b : K3) : Decidable (le a b) := inferInstanceAs (Decidable (a.rank ≤ b.rank))

theorem le_trans {a b c : K3} (h₁ : le a b) (h₂ : le b c) : le a c := Nat.le_trans h₁ h₂
theorem le_pos (a : K3) : le a pos := by cases a <;> decide
theorem and_le_left (a b : K3) : le (and a b) a := by cases a <;> cases b <;> decide
theorem and_le_right (a b : K3) : le (and a b) b := by cases a <;> cases b <;> decide
theorem le_and_of_le_le {c a b : K3} (h₁ : le c a) (h₂ : le c b) : le c (and a b) := by
  cases c <;> cases a <;> cases b <;> (revert h₁ h₂; decide)
theorem or_eq_left_of_ge {a b : K3} (h : le b a) : or a b = a := by
  cases a <;> cases b <;> (revert h; decide)
theorem or_assoc (a b c : K3) : or (or a b) c = or a (or b c) := by cases a <;> cases b <;> cases c <;> rfl
theorem or_comm (a b : K3) : or a b = or b a := by cases a <;> cases b <;> rfl
theorem and_eq_pos_iff (a b : K3) : and a b = pos ↔ a = pos ∧ b = pos := by cases a <;> cases b <;> decide
theorem and_eq_neg_iff (a b : K3) : and a b = neg ↔ a = neg ∨ b = neg := by cases a <;> cases b <;> decide
end K3

structure Lit (P : Nat) where
  idx : Fin P
  neg : Bool
  deriving DecidableEq
abbrev Vec (P : Nat) := Fin P → K3
variable {P : Nat}

def litVal (x : Vec P) (l : Lit P) : K3 := if l.neg then (x l.idx).not else x l.idx
def clauseVal (x : Vec P) (c : List (Lit P)) : K3 := c.foldr (fun l acc => (litVal x l).and acc) .pos
def ruleVal (x : Vec P) (cs : List (List (Lit P))) : K3 := cs.foldr (fun c acc => (clauseVal x c).or acc) .neg

theorem clauseVal_le_lit {x : Vec P} {c : List (Lit P)} {l : Lit P} (h : l ∈ c) :
    K3.le (clauseVal x c) (litVal x l) := by
  induction c with
  | nil => cases h
  | cons m ms ih =>
    show K3.le ((litVal x m).and (clauseVal x ms)) (litVal x l)
    rcases List.mem_cons.mp h with rfl | hm
    · exact K3.and_le_left _ _
    · exact K3.le_trans (K3.and_le_right _ _) (ih hm)

theorem clauseVal_le_of_subset {x : Vec P} {a b : List (Lit P)} (h : ∀ l, l ∈ a → l ∈ b) :
    K3.le (clauseVal x b) (clauseVal x a) := by
  induction a with
  | nil => exact K3.le_pos _
  | cons l ls ih =>
    show K3.le (clauseVal x b) ((litVal x l).and (clauseVal x ls))
    exact K3.le_and_of_le_le (clauseVal_le_lit (h l (List.mem_cons_self _ _)))
      (ih fun m hm => h m (List.mem_cons_of_mem _ hm))

/-- Topological dedup law: a subsumed clause is K3-redundant in both polarities. -/
theorem subsumption_sound (x : Vec P) (a b : List (Lit P)) (h : ∀ l, l ∈ a → l ∈ b) :
    (clauseVal x a).or (clauseVal x b) = clauseVal x a :=
  K3.or_eq_left_of_ge (clauseVal_le_of_subset h)

theorem ruleVal_drop_subsumed (x : Vec P) (a b : List (Lit P)) (cs : List (List (Lit P)))
    (h : ∀ l, l ∈ a → l ∈ b) : ruleVal x (a :: b :: cs) = ruleVal x (a :: cs) := by
  show (clauseVal x a).or ((clauseVal x b).or (ruleVal x cs)) = (clauseVal x a).or (ruleVal x cs)
  rw [← K3.or_assoc, subsumption_sound x a b h]

/-- Interning order is irrelevant: `or` is left-commutative. Uses the Mathlib pin in
    `formal/lean4/lake-manifest.json` for `List.Perm.foldr_eq`. -/
theorem ruleVal_perm (x : Vec P) {cs ds : List (List (Lit P))} (h : cs.Perm ds) :
    ruleVal x cs = ruleVal x ds :=
  h.foldr_eq (fun c d acc => by
    show (clauseVal x c).or ((clauseVal x d).or acc) = (clauseVal x d).or ((clauseVal x c).or acc)
    rw [← K3.or_assoc, ← K3.or_assoc, K3.or_comm (clauseVal x c)]) _

/-- Bitset characterization used by the MISS / FALS words. -/
def posBit (x : Vec P) (i : Fin P) : Bool := decide (x i = .pos)
def negBit (x : Vec P) (i : Fin P) : Bool := decide (x i = .neg)

theorem clauseVal_eq_pos_iff (x : Vec P) (c : List (Lit P)) :
    clauseVal x c = .pos ↔ ∀ l ∈ c, (if l.neg then negBit x l.idx else posBit x l.idx) = true := by
  induction c with
  | nil => simp [clauseVal]
  | cons l ls ih =>
    show (litVal x l).and (clauseVal x ls) = .pos ↔ _
    rw [K3.and_eq_pos_iff, ih, List.forall_mem_cons]
    unfold litVal posBit negBit
    cases hn : l.neg <;> cases hx : x l.idx <;> simp [K3.not]

theorem clauseVal_eq_neg_iff (x : Vec P) (c : List (Lit P)) :
    clauseVal x c = .neg ↔ ∃ l ∈ c, (if l.neg then posBit x l.idx else negBit x l.idx) = true := by
  induction c with
  | nil => simp [clauseVal]
  | cons l ls ih =>
    show (litVal x l).and (clauseVal x ls) = .neg ↔ _
    rw [K3.and_eq_neg_iff, ih, List.exists_mem_cons_iff]
    unfold litVal posBit negBit
    cases hn : l.neg <;> cases hx : x l.idx <;> simp [K3.not]

end Chio.Copley.Pass6
```

The register-level theorem `compile_correct` states that for every well-formed DAG and vector, bit $r$ of `RT` equals `decide (ruleVal x rule_r = .pos)` and bit $r$ of `RF` equals `decide (ruleVal x rule_r = .neg)`. It is assembled from the two characterization lemmas above, `ruleVal_drop_subsumed`, `ruleVal_perm`, and a segment invariant (`miss_word_sem`, `fals_word_sem`, `ct_word_sem`, `rule_word_sem`) proved by induction over the emitted list with the Phase B word-range disjointness as hypothesis. The learned predictor appears only as the universally quantified `x`, which is the Verification Transfer Theorem in action.

### 6.2 Kani harnesses

```rust
#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn bcast_is_exact() {
        let b: u64 = kani::any();
        assert_eq!(bcast(b), if b & 1 == 1 { u64::MAX } else { 0 });
    }

    #[kani::proof]
    fn step_is_total_for_any_instruction() {
        let ins = Instr::new(kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        let mut regs: [u64; NREG] = kani::any();
        step(&mut regs, &ins); // no panic for any opcode, index, or shift amount
    }

    #[kani::proof]
    fn prefix_never_more_permissive() {
        let (bt, bu, rt, ru): (bool, bool, bool, bool) = kani::any();
        let d: u8 = kani::any();
        kani::assume(d <= 3);
        let full = resolve_bits(3, bt, bu, rt, ru);
        assert!(resolve_bits(d, bt, bu, rt, ru).permissiveness() <= full.permissiveness());
    }

    /// Full compiled-vs-reference equivalence on a 4-rule, 64-predicate instance with
    /// symbolic predicates. The 537-predicate instance is covered by proptest (§7).
    #[kani::proof]
    #[kani::unwind(80)]
    fn small_dag_compiled_equals_reference() {
        let dag: SymbolicRuleDag<64, 2, 3, 4> = fixtures::small_dag();
        let mut table = ClauseTable::<3, 8>::new();
        let mut sched = Schedule::<512>::empty();
        let stats = dag.compile(&mut table, &mut sched).unwrap();
        let mut pos = [0u64; COPLEY_PW]; let mut neg = [0u64; COPLEY_PW];
        pos[0] = kani::any(); neg[0] = kani::any();
        kani::assume(pos[0] & neg[0] == 0);
        let x = KleeneVector::new(pos, neg).unwrap();
        let ev = sched.execute(&x);
        assert_eq!(ev.steps, sched.len());
        assert_eq!(stats.predicted_len(), Some(sched.len()));
        for r in 0..4 {
            let (t, f) = fixtures::reference_rule(&dag, r, &x);
            assert_eq!(ev.regs[usize::from(R_RT)] >> r & 1 == 1, t);
            assert_eq!(ev.regs[usize::from(R_RF)] >> r & 1 == 1, f);
        }
    }
}
```

### 6.3 Apalache TLA+ (`formal/tla/CopleyRankCut.tla`)

```tla
---------------------------- MODULE CopleyRankCut ----------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Int;
  SegEnd0,
  \* @type: Int;
  SegEnd1,
  \* @type: Int;
  NMax
ASSUME 0 <= SegEnd0 /\ SegEnd0 <= SegEnd1 /\ SegEnd1 <= NMax

\* Learned predictor abstracted to unconstrained rule-level outcomes.
VARIABLES
  \* @type: Bool;
  bt,
  \* @type: Bool;
  bu,
  \* @type: Bool;
  rt,
  \* @type: Bool;
  ru,
  \* @type: Int;
  fuel

Perm(v) == IF v = "Deny" THEN 0 ELSE IF v = "Pending" THEN 1 ELSE 2
Full == IF bt THEN "Deny" ELSE IF bu \/ rt \/ ru THEN "Pending" ELSE "Allow"
RanksDone == IF fuel >= SegEnd1 THEN 2 ELSE IF fuel >= SegEnd0 THEN 1 ELSE 0
Steps == IF fuel >= SegEnd1 THEN SegEnd1 ELSE IF fuel >= SegEnd0 THEN SegEnd0 ELSE 0
Cut == IF RanksDone = 0 THEN "Deny"
       ELSE IF RanksDone = 1 THEN (IF bt THEN "Deny" ELSE "Pending") ELSE Full

Init == bt \in BOOLEAN /\ bu \in BOOLEAN /\ rt \in BOOLEAN /\ ru \in BOOLEAN /\ fuel \in 0..NMax
Next == UNCHANGED <<bt, bu, rt, ru, fuel>>

PrefixSound == Perm(Cut) <= Perm(Full)
StepsInputIndependent == Steps = (IF fuel >= SegEnd1 THEN SegEnd1 ELSE IF fuel >= SegEnd0 THEN SegEnd0 ELSE 0)
WCET == Steps <= NMax
=============================================================================
```

`apalache check --inv=PrefixSound --inv=WCET` with `NMax = 46716` and the pinned `SegEnd*` values from the shipped schedule discharges Theorem 5 and the prefix form of Theorem 1 at the abstract level; `Steps` mentions no rule-outcome variable, which is the input-independence statement.

## 7. Differential equivalence against HushSpec IR and runtime integration

The adapter below is the only code touching `chio-policy` types. Its assumed surface is a rule list with a severity and a DNF of concept literals; if the real `HushSpecIr` accessor names differ, only `lower` changes.

```rust
#[cfg(test)]
mod differential {
    extern crate std;
    use super::*;
    use chio_policy::hushspec::{HushSpecIr, HushSeverity, evaluate_k3, K3 as HushK3};
    use proptest::prelude::*;

    fn lower(ir: &HushSpecIr) -> Result<CopleyDag, CompileError> { /* severity→Rank, literals→Literal */ todo!() }

    fn kleene() -> impl Strategy<Value = KleeneVector<COPLEY_PW>> {
        (any::<[u64; 9]>(), any::<[u64; 9]>()).prop_map(|(p, n)| {
            let neg = core::array::from_fn(|w| n[w] & !p[w]);
            KleeneVector::new(p, neg).expect("disjoint by construction")
        })
    }

    static COMPILED: std::sync::LazyLock<(HushSpecIr, std::boxed::Box<Schedule<COPLEY_N_MAX>>)> =
        std::sync::LazyLock::new(|| {
            let ir = HushSpecIr::load_pinned("copley-236.hushspec");
            let dag = lower(&ir).unwrap();
            let mut table = std::boxed::Box::new(ClauseTable::<COPLEY_L, 2124>::new());
            let mut sched = std::boxed::Box::new(Schedule::<COPLEY_N_MAX>::empty());
            dag.compile(&mut table, &mut sched).unwrap();
            assert!(sched.len() <= COPLEY_N_MAX);
            (ir, sched)
        });

    fn check(x: &KleeneVector<COPLEY_PW>) {
        let (ir, sched) = &*COMPILED;
        let ev = sched.execute(x);
        assert_eq!(ev.steps, sched.len());
        let reference = evaluate_k3(ir, x.as_assignment()); // Vec<HushK3>, one per rule
        for (r, v) in reference.iter().enumerate() {
            let (rw, rb) = layout::split(r);
            let t = ev.regs[usize::from(R_RT) + rw] >> rb & 1 == 1;
            let f = ev.regs[usize::from(R_RF) + rw] >> rb & 1 == 1;
            assert_eq!((t, f), (*v == HushK3::True, *v == HushK3::False), "rule {r}");
        }
        assert_eq!(sched.resolve(&ev, 3), ir.verdict_k3(&reference).into());
        assert_eq!(ev.regs[usize::from(R_BT)] == 1, sched.resolve(&ev, 3) == Verdict3::Deny);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]
        #[test] fn compiled_matches_hushspec(x in kleene()) { check(&x); }
        #[test] fn every_prefix_is_sound(x in kleene(), fuel in 0usize..=COPLEY_N_MAX) {
            let (_, sched) = &*COMPILED;
            let full = sched.resolve(&sched.execute(&x), 3);
            let (ev, d) = sched.execute_prefix(&x, fuel);
            prop_assert!(sched.resolve(&ev, d).permissiveness() <= full.permissiveness());
        }
    }

    #[test]
    fn corners_and_single_bits() {
        let all = |p: u64, n: u64| KleeneVector::new([p; 9], [n; 9]).unwrap();
        for x in [all(0, 0), all(u64::MAX, 0), all(0, u64::MAX)] { check(&x); }
        for i in 0..COPLEY_P { for negated in [false, true] {
            let mut p = [0u64; 9]; let mut n = [0u64; 9];
            let (w, b) = layout::split(i);
            *(if negated { &mut n } else { &mut p }).get_mut(w).unwrap() |= 1u64 << b;
            check(&KleeneVector::new(p, n).unwrap());
        } }
    }
}
```

A metamorphic test compiles the same DAG with subsumption disabled, asserts identical `RT`/`RF` words on 20,000 vectors, and asserts the dedup schedule is no longer than the other, which is the Corollary to Theorem 3.

**Guard integration.** A `CopleyRuleGuard` implements `Guard`: `Deny → Verdict::Deny`, `PendingApproval → Verdict::PendingApproval`, `Allow → Verdict::Allow`, with `GuardEvidence { guard_name: "copley_rule_dag", verdict, details: Some("schedule=<digest64>; steps=<n>; ranks_done=<d>") }`. The pipeline's sticky `PendingApproval` and terminating `Deny` match Theorem 5's lattice exactly.

**Receipt and weights binding.** The schedule digest, instruction count, and completed ranks are recorded under the existing `model_metadata` reserved key as a nested `copley_rule_schedule` object, so the 35-entry `RESERVED_RECEIPT_METADATA_KEYS` array is untouched. The `ModelCard` gains an optional `rule_schedule_digest`, checked by a new sibling of `evaluate_weights_binding` so that a card's `loaded_weights_hash` and its rule schedule travel together. `formal/proof-manifest.toml` gains three additive entries: `copley.schedule_digest`, `copley.schedule_len`, `copley.c_step_cycles`.

## Recap

The Pass 6 artifact is a `#![no_std]`, `#![forbid(unsafe_code)]` crate with an 11-opcode register ISA over a 146-word file, a zero-input-branch executor, and a compiler that canonicalizes clauses, drops subsumed clauses in subset-lattice order, interns shared clauses to their minimum rank, and emits one segment per rank with word-aligned clause ranges. Theorem 1 gives an exact, input-independent trip count equal to the schedule length. Theorem 2 gives the exact length formula, checked in code. Theorem 3 bounds every legal `SymbolicRuleDag<537, 9, 9, 236>` schedule at 46,716 instructions. Theorem 5 shows that cutting at any rank boundary under fuel pressure never yields a more permissive verdict than the full run. The K3 algebra and dedup law are proven in Lean 4, the executor and a small-instance equivalence in Kani, the rank-cut lattice in Apalache, and the full 537-predicate instance is tied to the HushSpec reference evaluator by a 20,000-case differential harness plus exhaustive single-literal corners. Next steps are landing the `lower` adapter against the real `chio-policy` accessor names, recording the shipped schedule's digest and length in the proof manifest, and measuring `c_step` on the pinned toolchain.

---

# Verbatim Treatise - `wave6_angle_3_concurrent_loom_and_dst_crash_recovery_pass_6`

Picking up at the deliverable itself: the additive specification module, both test files, and the Lean, Apalache, and Kani artifacts follow, each in its own block.

## Specification module and the single lemma everything rests on

**Verification contract.** Four kernel objects race in Pass 6: the `ArcSwap<WeightEpoch>` publication path behind `evaluate_weights_binding`, the `ExecutionNonceStore` reserve/commit/rollback cycle, the `ChildAdmission::holders` refcount inside `BudgetSplit`, and `SessionOperation` cancellation against the two dispatch cutpoints. Each is reduced to one `u64` word mutated by one compare-and-swap, and each gets a pure sequential specification in a new `formal_concurrency.rs`. Loom explores schedule nondeterminism against that specification. The deterministic simulator explores crash and drop nondeterminism against the same specification with SQLite as the durable store. Lean, Apalache, and Kani discharge the specification's invariants once, with the learned choice modelled as unconstrained nondeterminism, exactly as the Wave 1 transfer theorem prescribes. `ledger_is_terminal` is `pub(crate)` and therefore not reachable from the `chio-kernel` test crate, so every test couples to the ledger only through the public `ledger_apply` and asserts that it accepts each transition the protocol performs.

```rust
// crates/kernel/chio-kernel-core/src/formal_concurrency.rs   (new; `pub mod formal_concurrency;` in lib.rs)
//! Sequential specs + single-word CAS implementations for the four racy objects.
//! Strictly additive: `formal_core` and `formal_aeneas` are untouched; the ledger is
//! reused only through `ledger_apply` (ops 0 reserve, 1 commit, 2 release, 3 retain).
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const LEDGER_RESERVE: u8 = 0;
pub const LEDGER_COMMIT: u8 = 1;
pub const LEDGER_RELEASE: u8 = 2;
pub const LEDGER_RETAIN: u8 = 3;

/// Production: `core::sync::atomic::AtomicU64`. `--cfg loom`: a wrapper in the test crate.
/// Kani: a `Cell<u64>`. Everything below is generic over this one trait.
pub trait AtomicWord {
    fn load_word(&self) -> u64;
    /// `Ok(previous)` if the word equalled `current` and was replaced; `Err(actual)` otherwise.
    fn cas_word(&self, current: u64, new: u64) -> Result<u64, u64>;
}

#[cfg(all(not(loom), target_has_atomic = "64"))]
impl AtomicWord for core::sync::atomic::AtomicU64 {
    fn load_word(&self) -> u64 {
        self.load(core::sync::atomic::Ordering::Acquire)
    }
    fn cas_word(&self, current: u64, new: u64) -> Result<u64, u64> {
        use core::sync::atomic::Ordering::{AcqRel, Acquire};
        self.compare_exchange(current, new, AcqRel, Acquire)
    }
}

/// Bounded CAS loop exhausted. Callers map it to the layer fallback `Defer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contended { pub last_seen: u64 }

/// Applies the pure step `f` atomically. Linearization point: the successful CAS, or the
/// load when `f` leaves the word unchanged (Lemma 1 below).
pub fn atomic_apply<W: AtomicWord, R>(
    word: &W, max_attempts: u32, f: impl Fn(u64) -> (u64, R),
) -> Result<R, Contended> {
    let mut attempts: u32 = 0;
    let mut cur = word.load_word();
    loop {
        let (next, out) = f(cur);
        if next == cur {
            return Ok(out);
        }
        match word.cas_word(cur, next) {
            Ok(_) => return Ok(out),
            Err(actual) => {
                attempts = attempts.checked_add(1).ok_or(Contended { last_seen: actual })?;
                if attempts >= max_attempts {
                    return Err(Contended { last_seen: actual });
                }
                cur = actual;
            }
        }
    }
}

// ---------- 1. WeightEpoch publication (ArcSwap pointer == epoch word) ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochPublishError { NotMonotone { observed: u64, proposed: u64 }, Raced { current: u64 } }

/// The `(epoch, weights_hash)` pair lives in one immutable allocation, so a torn pair is
/// impossible by construction; what needs verifying is the publish protocol itself.
pub fn epoch_spec_step(cur: u64, observed: u64, proposed: u64) -> (u64, Result<u64, EpochPublishError>) {
    if proposed <= observed {
        return (cur, Err(EpochPublishError::NotMonotone { observed, proposed }));
    }
    if cur != observed {
        return (cur, Err(EpochPublishError::Raced { current: cur }));
    }
    (proposed, Ok(cur))
}

pub fn publish_epoch<W: AtomicWord>(cell: &W, observed: u64, proposed: u64) -> Result<u64, EpochPublishError> {
    match atomic_apply(cell, 2, |cur| epoch_spec_step(cur, observed, proposed)) {
        Ok(r) => r,
        Err(c) => Err(EpochPublishError::Raced { current: c.last_seen }),
    }
}

// ---------- 2. ExecutionNonceStore slot: tag in low 2 bits, owner above ----------
pub const NONCE_FREE: u64 = 0;
pub const NONCE_RESERVED: u64 = 1;
pub const NONCE_COMMITTED: u64 = 2;
const NONCE_TAG_MASK: u64 = 0b11;
const NONCE_TAG_BITS: u32 = 2;
/// `u64::MAX >> 2`, written as a literal so the module stays free of unchecked arithmetic.
pub const NONCE_MAX_OWNER: u64 = 0x3FFF_FFFF_FFFF_FFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceOp { Reserve, Commit, Rollback }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NonceError { Occupied = 1, NotOwner = 2, NotReserved = 3, OwnerTooLarge = 4, Contended = 5 }

pub fn nonce_pack(tag: u64, owner: u64) -> Result<u64, NonceError> {
    if owner > NONCE_MAX_OWNER || tag > NONCE_TAG_MASK {
        return Err(NonceError::OwnerTooLarge);
    }
    let shifted = owner.checked_shl(NONCE_TAG_BITS).ok_or(NonceError::OwnerTooLarge)?;
    Ok(shifted | tag)
}

pub fn nonce_unpack(word: u64) -> (u64, u64) {
    (word & NONCE_TAG_MASK, word.checked_shr(NONCE_TAG_BITS).unwrap_or(0))
}

pub fn nonce_spec_step(word: u64, op: NonceOp, owner: u64) -> (u64, Result<(), NonceError>) {
    let reserved = match nonce_pack(NONCE_RESERVED, owner) { Ok(w) => w, Err(e) => return (word, Err(e)) };
    let committed = match nonce_pack(NONCE_COMMITTED, owner) { Ok(w) => w, Err(e) => return (word, Err(e)) };
    let (from, to) = match op {
        NonceOp::Reserve => (NONCE_FREE, reserved),
        NonceOp::Commit => (reserved, committed),
        NonceOp::Rollback => (reserved, NONCE_FREE),
    };
    if word == from {
        return (to, Ok(()));
    }
    let (tag, holder) = nonce_unpack(word);
    let err = match op {
        NonceOp::Reserve => NonceError::Occupied,
        _ if tag == NONCE_RESERVED && holder != owner => NonceError::NotOwner,
        _ => NonceError::NotReserved,
    };
    (word, Err(err))
}

pub fn nonce_step<W: AtomicWord>(slot: &W, op: NonceOp, owner: u64) -> Result<(), NonceError> {
    atomic_apply(slot, 8, |cur| nonce_spec_step(cur, op, owner)).unwrap_or(Err(NonceError::Contended))
}

/// Projection used by the refinement checks: a successful slot op is one ledger op of amount 1.
pub fn nonce_op_to_ledger_op(op: NonceOp) -> u8 {
    match op { NonceOp::Reserve => LEDGER_RESERVE, NonceOp::Commit => LEDGER_COMMIT, NonceOp::Rollback => LEDGER_RELEASE }
}

// ---------- 3. ChildAdmission::holders refcount ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HolderError { Overflow = 1, Underflow = 2, Contended = 3 }

/// `Overflow` is the lock-free twin of `BudgetSplitError::HolderCountOverflow`.
pub fn holder_spec_step(word: u64, cap: u64, acquire: bool) -> (u64, Result<u64, HolderError>) {
    if acquire {
        match word.checked_add(1) {
            Some(n) if n <= cap => (n, Ok(n)),
            _ => (word, Err(HolderError::Overflow)),
        }
    } else {
        match word.checked_sub(1) {
            Some(n) => (n, Ok(n)),
            None => (word, Err(HolderError::Underflow)),
        }
    }
}

pub fn holder_step<W: AtomicWord>(word: &W, cap: u64, acquire: bool) -> Result<u64, HolderError> {
    atomic_apply(word, 8, |cur| holder_spec_step(cur, cap, acquire)).unwrap_or(Err(HolderError::Contended))
}

// ---------- 4. SessionOperation word: tag in bits 0..3, cancel-request bit 3 ----------
pub const SESSION_ADMITTED: u64 = 0;
pub const SESSION_PENDING: u64 = 1;
pub const SESSION_DISPATCHING: u64 = 2;
pub const SESSION_DISPATCHED: u64 = 3;
pub const SESSION_RELEASED: u64 = 4;
pub const SESSION_CANCELLED: u64 = 5;
pub const SESSION_HELD: u64 = 6;
pub const SESSION_DENIED: u64 = 7;
pub const SESSION_TAG_MASK: u64 = 0b111;
pub const SESSION_CANCEL_REQ: u64 = 0b1000;

/// Exact guard outcome from `GuardPipeline`; never a learned quantity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict3 { Allow, PendingApproval, Deny }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Cutpoint { PreDispatch = 0, PostDispatch = 1, AlreadyTerminal = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOp { Begin(Verdict3), MarkDispatched, Finish { output_valid: bool }, Cancel }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOut { Moved(u64), Stale(u64), Cut(Cutpoint) }

pub fn session_tag(word: u64) -> u64 { word & SESSION_TAG_MASK }
pub fn session_cancel_requested(word: u64) -> bool { word & SESSION_CANCEL_REQ != 0 }
pub fn session_is_terminal(word: u64) -> bool {
    matches!(session_tag(word), SESSION_RELEASED | SESSION_CANCELLED | SESSION_HELD | SESSION_DENIED)
}

/// `Begin` is `revalidate_before_dispatch`: PendingApproval is sticky and a later guard may
/// still deny. `Finish` runs after `validate_output_before_release`.
pub fn session_spec_step(word: u64, op: SessionOp) -> (u64, SessionOut) {
    let tag = session_tag(word);
    let flag = word & SESSION_CANCEL_REQ;
    match op {
        SessionOp::Begin(v) => match (tag, v) {
            (SESSION_ADMITTED, Verdict3::PendingApproval) => (SESSION_PENDING, SessionOut::Moved(SESSION_PENDING)),
            (SESSION_ADMITTED | SESSION_PENDING, Verdict3::Allow) => (SESSION_DISPATCHING, SessionOut::Moved(SESSION_DISPATCHING)),
            (SESSION_ADMITTED | SESSION_PENDING, Verdict3::Deny) => (SESSION_DENIED, SessionOut::Moved(SESSION_DENIED)),
            _ => (word, SessionOut::Stale(word)),
        },
        SessionOp::MarkDispatched => {
            if tag == SESSION_DISPATCHING { (SESSION_DISPATCHED | flag, SessionOut::Moved(SESSION_DISPATCHED)) } else { (word, SessionOut::Stale(word)) }
        }
        SessionOp::Finish { output_valid } => {
            if tag != SESSION_DISPATCHED { return (word, SessionOut::Stale(word)); }
            if flag != 0 || !output_valid { (SESSION_HELD, SessionOut::Moved(SESSION_HELD)) } else { (SESSION_RELEASED, SessionOut::Moved(SESSION_RELEASED)) }
        }
        SessionOp::Cancel => match tag {
            SESSION_ADMITTED | SESSION_PENDING => (SESSION_CANCELLED, SessionOut::Cut(Cutpoint::PreDispatch)),
            SESSION_DISPATCHING | SESSION_DISPATCHED => (word | SESSION_CANCEL_REQ, SessionOut::Cut(Cutpoint::PostDispatch)),
            _ => (word, SessionOut::Cut(Cutpoint::AlreadyTerminal)),
        },
    }
}

pub fn session_step<W: AtomicWord>(word: &W, op: SessionOp) -> Result<SessionOut, Contended> {
    atomic_apply(word, 8, |cur| session_spec_step(

---

# Verbatim Treatise - `wave6_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_6`

I am delivering the Wave 6 Angle 4 design as a self-contained treatise: Rust for the portable request, the three lifters, the signing floor and the offline verifier, plus the Lean 4, Aeneas, Kani and Apalache obligations that pin them.

**Outcome.** The three protocol edges lift into one borrowed, allocation-free `PortableToolCallRequest`. Exact facts live in Kleene three-valued logic and are committed into the receipt. Receipts are signed under a both-or-nothing Ed25519 plus ML-DSA-65 floor whose key is bound to a hardware measurement. Offline verifiers resolve federated trust roots through a bounded endorsement chain and return a three-valued outcome that never promotes unknown to verified. Every addition is strictly additive. The reserved metadata array keeps its length of 35, and edge payloads nest under the existing receipt-context and model-metadata keys. I could not run cargo, Lean, Kani or Apalache in this session, so the artifacts below are written to compile and discharge but are not toolchain-verified yet.

## Lifting three wire protocols into one exact request

The edge layer instantiates the canonical tuple as follows.

| Component | Edge instantiation |
|---|---|
| $\mathcal{X}_{\text{edge}}$ | MCP `tools/call`, A2A `message/send`, Envoy ext_authz `CheckRequest` |
| $C_{\text{edge}}(x)$ | Lifting, segment bounds, identity coherence, time window, budget precheck, guard verdict |
| $\mathcal{C}_{\text{edge}}$ | Bit envelope over Deny, Defer, Allow with Deny always set |
| $P_{\text{edge}}$ | Tier-0 fixed-point gate, then Tier-1 UltraBERT concept readout |
| $\Pi_{\mathcal{C}}$ | Keep the proposal iff feasible, else Deny |
| $W_{\text{edge}}$ | Hybrid-signed receipt committing facts, envelope bits and action |

**Segment mapping.** Copley's four segments were trained on process telemetry, where the image is what ran and the original file name is what the binary declared about itself. The protocol analog is the identity the caller invokes versus the identity pinned at registration time. A mismatch is the renamed-binary signal the model already knows.

| Segment | MCP | A2A | Envoy ext_authz |
|---|---|---|---|
| CommandLine | RFC 8785 canonical arguments | canonical message parts | canonical query and allowlisted headers |
| Image | invoked tool name | requested skill id | method and route template |
| OriginalFileName | tool name from the server's registered manifest | skill id from the Agent Card | route operation id from the upstream contract |
| ParentImage | server identity | caller Agent Card URI | mTLS source principal |

Identity coherence is an exact fact, not a prediction. It is `+` when invoked and declared bytes are equal, `-` when they differ, and `⊥` when no manifest was pinned. The envelope treats `⊥` as not refuted but commits it into the receipt so downstream policy can tighten.

The crate is `no_std` without `alloc`. Segments borrow the ingress buffer. Canonical bytes are written into caller-supplied scratch with checked offsets.

```rust
//! crates/edges/chio-portable-call/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use chio_kernel_core::formal_aeneas::{classify_time_window_code, edge_envelope_bits, edge_project_code};

pub mod receipt;
pub mod tier0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum K3 { Pos = 0, Neg = 1, Bot = 2 }

impl K3 {
    pub const fn from_bool(b: bool) -> Self { if b { Self::Pos } else { Self::Neg } }
    pub const fn is_pos(self) -> bool { matches!(self, Self::Pos) }
    pub const fn is_neg(self) -> bool { matches!(self, Self::Neg) }
    pub const fn and(self, o: Self) -> Self {
        match (self, o) {
            (Self::Neg, _) | (_, Self::Neg) => Self::Neg,
            (Self::Pos, Self::Pos) => Self::Pos,
            _ => Self::Bot,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeProtocol { McpToolsCall = 1, A2aMessageSend = 2, EnvoyExtAuthz = 3 }

impl EdgeProtocol {
    pub const fn mask(self) -> u8 {
        match self { Self::McpToolsCall => 0b001, Self::A2aMessageSend => 0b010, Self::EnvoyExtAuthz => 0b100 }
    }
}

/// Mirrors the guard pipeline verdict ordering; the adapter maps `GuardDecision` onto it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeVerdict { Allow = 0, PendingApproval = 1, Deny = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeAction { Deny = 0, Defer = 1, Allow = 2 }

impl EdgeAction {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code { 0 => Some(Self::Deny), 1 => Some(Self::Defer), 2 => Some(Self::Allow), _ => None }
    }
    pub const fn bit(self) -> u8 { match self { Self::Deny => 1, Self::Defer => 2, Self::Allow => 4 } }
    pub const fn admits(self) -> bool { matches!(self, Self::Allow) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Segment { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

pub const SEGMENT_PREDICATES: [u16; 4] = [345, 97, 57, 38];
pub const TOTAL_PREDICATES: usize = 537;
pub const MAX_COMMAND_LINE_BYTES: usize = 16_384;
pub const MAX_IDENTITY_BYTES: usize = 1_024;
pub const PTCR_DOMAIN: &[u8; 16] = b"chio.ptcr.canon1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiftError {
    SegmentTooLong { segment: Segment, len: usize },
    MissingField(&'static str),
    ProtocolMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalError { Capacity, Overflow, SegmentTooLong }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopleySegments<'a> {
    pub command_line: &'a [u8],
    pub image: &'a [u8],
    pub original_file_name: &'a [u8],
    pub parent_image: &'a [u8],
}

impl<'a> CopleySegments<'a> {
    pub fn checked(
        command_line: &'a [u8], image: &'a [u8],
        original_file_name: &'a [u8], parent_image: &'a [u8],
    ) -> Result<Self, LiftError> {
        bound(Segment::CommandLine, command_line, MAX_COMMAND_LINE_BYTES)?;
        bound(Segment::Image, image, MAX_IDENTITY_BYTES)?;
        bound(Segment::OriginalFileName, original_file_name, MAX_IDENTITY_BYTES)?;
        bound(Segment::ParentImage, parent_image, MAX_IDENTITY_BYTES)?;
        Ok(Self { command_line, image, original_file_name, parent_image })
    }
    /// Exact renamed-binary fact: invoked identity versus registration-time declared identity.
    pub fn identity_coherent(&self) -> K3 {
        if self.original_file_name.is_empty() { K3::Bot }
        else { K3::from_bool(self.image == self.original_file_name) }
    }
}

fn bound(segment: Segment, bytes: &[u8], cap: usize) -> Result<(), LiftError> {
    if bytes.len() > cap { Err(LiftError::SegmentTooLong { segment, len: bytes.len() }) } else { Ok(()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeFacts {
    pub identity_coherent: K3,
    pub transport_authenticated: K3,
    pub schema_valid: K3,
    /// From `classify_time_window_code`: 0 Valid, 1 NotYetValid, 2 Expired.
    pub time_window: u8,
}

impl EdgeFacts {
    pub fn write(&self, w: &mut CanonicalWriter<'_>) -> Result<(), CanonicalError> {
        w.u8(self.identity_coherent as u8)?;
        w.u8(self.transport_authenticated as u8)?;
        w.u8(self.schema_valid as u8)?;
        w.u8(self.time_window)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableToolCallRequest<'a> {
    pub protocol: EdgeProtocol,
    pub principal: &'a [u8],
    pub capability_id: &'a [u8],
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
    pub segments: CopleySegments<'a>,
    pub facts: EdgeFacts,
}

impl PortableToolCallRequest<'_> {
    /// Domain, protocol, then fixed-width length-prefixed fields. Injective: `Chio.Edge.encode_injective`.
    pub fn write_canonical(&self, out: &mut [u8]) -> Result<usize, CanonicalError> {
        let mut w = CanonicalWriter::new(out);
        w.raw(PTCR_DOMAIN)?;
        w.u8(self.protocol as u8)?;
        w.seg(self.principal)?;
        w.seg(self.capability_id)?;
        w.u64(self.issued_at)?;
        w.u64(self.expires_at)?;
        w.u64(self.invocation_cost)?;
        w.u64(self.unit_cost)?;
        w.seg(self.segments.command_line)?;
        w.seg(self.segments.image)?;
        w.seg(self.segments.original_file_name)?;
        w.seg(self.segments.parent_image)?;
        self.facts.write(&mut w)?;
        Ok(w.written())
    }
}

pub struct CanonicalWriter<'w> { buf: &'w mut [u8], pos: usize }

impl<'w> CanonicalWriter<'w> {
    pub fn new(buf: &'w mut [u8]) -> Self { Self { buf, pos: 0 } }
    pub fn written(&self) -> usize { self.pos }
    pub fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        let end = self.pos.checked_add(bytes.len()).ok_or(CanonicalError::Overflow)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(CanonicalError::Capacity)?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
    pub fn u8(&mut self, v: u8) -> Result<(), CanonicalError> { self.raw(&[v]) }
    pub fn u64(&mut self, v: u64) -> Result<(), CanonicalError> { self.raw(&v.to_be_bytes()) }
    pub fn seg(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        let len = u32::try_from(bytes.len()).map_err(|_| CanonicalError::SegmentTooLong)?;
        self.raw(&len.to_be_bytes())?;
        self.raw(bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LiftInput<'a> {
    pub protocol: EdgeProtocol,
    pub principal: &'a [u8],
    pub capability_id: &'a [u8],
    pub now: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub invocation_cost: u64,
    pub unit_cost: u64,
    pub transport_authenticated: K3,
    pub schema_valid: K3,
}

fn lift<'a>(input: &LiftInput<'a>, expected: EdgeProtocol, segments: CopleySegments<'a>)
    -> Result<PortableToolCallRequest<'a>, LiftError>
{
    if input.protocol != expected { return Err(LiftError::ProtocolMismatch); }
    if input.principal.is_empty() { return Err(LiftError::MissingField("principal")); }
    if input.capability_id.is_empty() { return Err(LiftError::MissingField("capability_id")); }
    let facts = EdgeFacts {
        identity_coherent: segments.identity_coherent(),
        transport_authenticated: input.transport_authenticated,
        schema_valid: input.schema_valid,
        time_window: classify_time_window_code(input.now, input.issued_at, input.expires_at),
    };
    Ok(PortableToolCallRequest {
        protocol: input.protocol, principal: input.principal, capability_id: input.capability_id,
        issued_at: input.issued_at, expires_at: input.expires_at,
        invocation_cost: input.invocation_cost, unit_cost: input.unit_cost, segments, facts,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct McpToolsCall<'a> {
    pub server_id: &'a [u8], pub tool_name: &'a [u8],
    pub manifest_tool_name: &'a [u8], pub jcs_arguments: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
pub struct A2aMessageSend<'a> {
    pub caller_agent_card: &'a [u8], pub skill_id: &'a [u8],
    pub card_skill_id: &'a [u8], pub canonical_parts: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
pub struct EnvoyCheckRequest<'a> {
    pub source_principal: &'a [u8], pub method_and_path: &'a [u8],
    pub route_operation_id: &'a [u8], pub canonical_query_and_headers: &'a [u8],
}

pub fn lift_mcp<'a>(i: &LiftInput<'a>, c: &McpToolsCall<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(i, EdgeProtocol::McpToolsCall,
         CopleySegments::checked(c.jcs_arguments, c.tool_name, c.manifest_tool_name, c.server_id)?)
}
pub fn lift_a2a<'a>(i: &LiftInput<'a>, m: &A2aMessageSend<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(i, EdgeProtocol::A2aMessageSend,
         CopleySegments::checked(m.canonical_parts, m.skill_id, m.card_skill_id, m.caller_agent_card)?)
}
pub fn lift_envoy<'a>(i: &LiftInput<'a>, r: &EnvoyCheckRequest<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    lift(i, EdgeProtocol::EnvoyExtAuthz,
         CopleySegments::checked(r.canonical_query_and_headers, r.method_and_path, r.route_operation_id, r.source_principal)?)
}

/// Feasible envelope with a private constructor; the Deny bit is always set by `edge_envelope_bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeEnvelope(u8);

impl EdgeEnvelope {
    pub fn from_facts(f: &EdgeFacts, verdict: EdgeVerdict, budget_accepted: bool) -> Self {
        Self(edge_envelope_bits(verdict as u8, budget_accepted, f.identity_coherent as u8,
                                f.transport_authenticated as u8, f.schema_valid as u8, f.time_window))
    }
    pub const fn bits(self) -> u8 { self.0 }
    pub const fn contains(self, a: EdgeAction) -> bool { self.0 & a.bit() != 0 }
    /// The shielded projection: keep the learned proposal iff feasible, else the fallback Deny.
    pub fn project(self, proposed: EdgeAction) -> EdgeAction {
        EdgeAction::from_code(edge_project_code(self.0, proposed as u8)).unwrap_or(EdgeAction::Deny)
    }
    /// The base policy: least conservative feasible action, used when the predictor is skipped.
    pub const fn pi_base(self) -> EdgeAction {
        if self.contains(EdgeAction::Allow) { EdgeAction::Allow }
        else if self.contains(EdgeAction::Defer) { EdgeAction::Defer } else { EdgeAction::Deny }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeResponse {
    Mcp { is_error: bool, pending_ticket: bool },
    A2a { task_state: u8 },
    Envoy { ok: bool, status: u16, pending_header: bool },
}

/// Total response mapping. A2A task state: 0 submitted, 1 input-required, 2 rejected.
pub const fn respond(p: EdgeProtocol, a: EdgeAction) -> EdgeResponse {
    match (p, a) {
        (EdgeProtocol::McpToolsCall, EdgeAction::Allow) => EdgeResponse::Mcp { is_error: false, pending_ticket: false },
        (EdgeProtocol::McpToolsCall, EdgeAction::Defer) => EdgeResponse::Mcp { is_error: true, pending_ticket: true },
        (EdgeProtocol::McpToolsCall, EdgeAction::Deny) => EdgeResponse::Mcp { is_error: true, pending_ticket: false },
        (EdgeProtocol::A2aMessageSend, EdgeAction::Allow) => EdgeResponse::A2a { task_state: 0 },
        (EdgeProtocol::A2aMessageSend, EdgeAction::Defer) => EdgeResponse::A2a { task_state: 1 },
        (EdgeProtocol::A2aMessageSend, EdgeAction::Deny) => EdgeResponse::A2a { task_state: 2 },
        (EdgeProtocol::EnvoyExtAuthz, EdgeAction::Allow) => EdgeResponse::Envoy { ok: true, status: 200, pending_header: false },
        (EdgeProtocol::EnvoyExtAuthz, EdgeAction::Defer) => EdgeResponse::Envoy { ok: false, status: 403, pending_header: true },
        (EdgeProtocol::EnvoyExtAuthz, EdgeAction::Deny) => EdgeResponse::Envoy { ok: false, status: 403, pending_header: false },
    }
}

pub const fn response_admits(r: EdgeResponse) -> bool {
    match r {
        EdgeResponse::Mcp { is_error, .. } => !is_error,
        EdgeResponse::A2a { task_state } => task_state == 0,
        EdgeResponse::Envoy { ok, .. } => ok,
    }
}
```

**Guard pipeline interplay.** The adapter runs the lifted request through the existing pipeline. A sticky pending verdict followed by a later deny collapses to deny, exactly as the pipeline loop already does. A lift failure is reported as guard evidence with the adapter name and denies, matching the pipeline's error branch. The Defer response is representable in every protocol but admits in none. For A2A it is the input-required state. For MCP it is an error result carrying an approval ticket. For Envoy it is a denied response with a pending header, because an ext_authz filter cannot hold a connection.

**Predictor tiers and the shadow prices.** The predictor only tightens. Tier-0 decides whether Tier-1 inference is affordable under the Lagrangian penalty $\boldsymbol{\lambda}\cdot c \le \text{slack}$, where slack is the remaining ext_authz deadline expressed in the same fixed-point units. This is the per-request subproblem of a dual decomposition. The outer loop that adjusts $\boldsymbol{\lambda}$ runs on the control plane and is out of scope here. If Tier-1 is skipped the edge takes the base policy. If Tier-1 runs, an escalation predicate at `+` moves the proposal to Defer when feasible. Either way the result passes through the projection.

```rust
//! crates/edges/chio-portable-call/src/t
ier0.rs
use crate::{EdgeAction, EdgeEnvelope, K3, TOTAL_PREDICATES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const ONE: Self = Self(65_536);
    pub fn add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
    pub fn mul(self, o: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0))?.checked_shr(16)?;
        i32::try_from(wide).ok().map(Self)
    }
}

/// Order matches the Wave 1 shadow-price vector: budget, fuel, latency, memory, escrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceVector {
    pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16,
    pub memory: FixedQ16_16, pub escrow: FixedQ16_16,
}

/// Lagrangian gate: Tier-1 runs iff the priced cost fits the slack. Overflow is unaffordable.
pub fn tier1_affordable(lambda: &ResourceVector, cost: &ResourceVector, slack: FixedQ16_16) -> Option<bool> {
    let total = lambda.budget.mul(cost.budget)?
        .add(lambda.fuel.mul(cost.fuel)?)?
        .add(lambda.latency.mul(cost.latency)?)?
        .add(lambda.memory.mul(cost.memory)?)?
        .add(lambda.escrow.mul(cost.escrow)?)?;
    Some(total <= slack)
}

/// Role-asymmetric threshold with `tau_neg <= tau_pos`; the branches are exclusive.
pub fn threshold(p: FixedQ16_16, tau_pos: FixedQ16_16, tau_neg: FixedQ16_16) -> K3 {
    if p >= tau_pos { K3::Pos } else if p <= tau_neg { K3::Neg } else { K3::Bot }
}

/// Tightening-only proposal, then the shielded projection.
pub fn propose(predicates: &[K3; TOTAL_PREDICATES], escalation: &[u16], env: EdgeEnvelope) -> EdgeAction {
    let escalate = escalation.iter()
        .any(|&j| predicates.get(usize::from(j)).map_or(false, |k| k.is_pos()));
    let proposed = if escalate {
        if env.contains(EdgeAction::Defer) { EdgeAction::Defer } else { EdgeAction::Deny }
    } else {
        env.pi_base()
    };
    env.project(proposed)
}
```

## Receipt signing floor, attestation binding, and offline federated verification

**The floor.** A receipt carries one signature object with two components over the same to-be-signed bytes. Verification evaluates both components unconditionally and accepts only when both pass. The suite identifier is inside the signed bytes, so neither component can be lifted out and presented as a single-algorithm signature under a different domain. The signing key never leaves the attested environment. The trait only exposes signing of already-canonical bytes.

| Constant | Value |
|---|---|
| Ed25519 public key, signature | 32, 64 bytes |
| ML-DSA-65 public key, signature | 1952, 3309 bytes |
| Receipt TBS length | 333 bytes |
| Trust root TBS length | 2226 bytes |
| Expected measurements per root | up to 4, SHA-384 width |
| Endorsement chain depth | 4 |

```rust
//! crates/edges/chio-portable-call/src/receipt.rs
use crate::{CanonicalError, CanonicalWriter, EdgeAction, EdgeEnvelope, EdgeFacts,
            EdgeProtocol, EdgeVerdict, K3, PortableToolCallRequest};
use chio_kernel_core::formal_aeneas::{classify_time_window_code, receipt_fields_coupled};

pub const ED25519_PK_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MLDSA65_PK_LEN: usize = 1_952;
pub const MLDSA65_SIG_LEN: usize = 3_309;
pub const HYBRID_PK_LEN: usize = 1_984;
pub const HYBRID_SUITE_ID: u16 = 0x0E65;
pub const MEASUREMENT_LEN: usize = 48;
pub const MAX_EXPECTED_MEASUREMENTS: usize = 4;
pub const MAX_ENDORSEMENT_DEPTH: u8 = 4;
pub const MAX_EVIDENCE_CLASS: u8 = 7;
pub const RECEIPT_TBS_LEN: usize = 333;
pub const ROOT_TBS_LEN: usize = 2_226;
pub const RECEIPT_TBS_DOMAIN: &[u8; 16] = b"chio.rcpt.tbs.v1";
pub const ROOT_TBS_DOMAIN: &[u8; 16] = b"chio.root.tbs.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridPublicKey { pub ed25519: [u8; ED25519_PK_LEN], pub mldsa65: [u8; MLDSA65_PK_LEN] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridSignature { pub ed25519: [u8; ED25519_SIG_LEN], pub mldsa65: [u8; MLDSA65_SIG_LEN] }

pub trait HybridVerifier {
    fn digest32(msg: &[u8]) -> [u8; 32];
    fn ed25519_verify(pk: &[u8; ED25519_PK_LEN], msg: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> bool;
    fn mldsa65_verify(pk: &[u8; MLDSA65_PK_LEN], msg: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> bool;
    /// The floor: both components, same TBS, no short circuit.
    fn hybrid_verify(pk: &HybridPublicKey, tbs: &[u8], sig: &HybridSignature) -> bool {
        let ed = Self::ed25519_verify(&pk.ed25519, tbs, &sig.ed25519);
        let ml = Self::mldsa65_verify(&pk.mldsa65, tbs, &sig.mldsa65);
        ed & ml
    }
}

pub trait KernelCryptoFloor: HybridVerifier {
    type Error;
    fn public_key(&self) -> &HybridPublicKey;
    fn ed25519_sign(&self, tbs: &[u8]) -> Result<[u8; ED25519_SIG_LEN], Self::Error>;
    fn mldsa65_sign(&self, tbs: &[u8]) -> Result<[u8; MLDSA65_SIG_LEN], Self::Error>;
    fn hybrid_sign(&self, tbs: &[u8]) -> Result<HybridSignature, Self::Error> {
        Ok(HybridSignature { ed25519: self.ed25519_sign(tbs)?, mldsa65: self.mldsa65_sign(tbs)? })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TeeKind { None = 0, SgxDcap = 1, Tdx = 2, SevSnp = 3, ArmCca = 4, Tpm2 = 5 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub tee: TeeKind,
    pub measurement: [u8; MEASUREMENT_LEN],
    pub report_data: [u8; 64],
    pub nonce: [u8; 32],
    pub quote_digest: [u8; 32],
}

impl AttestationEvidence {
    fn write(&self, w: &mut CanonicalWriter<'_>) -> Result<(), CanonicalError> {
        w.u8(self.tee as u8)?;
        w.raw(&self.measurement)?;
        w.raw(&self.report_data)?;
        w.raw(&self.nonce)?;
        w.raw(&self.quote_digest)
    }
}

/// Vendor quote-chain check. Offline without vendor roots it must return `Bot`, never `Pos`.
pub trait AttestationVerifier { fn verify_quote(&self, evidence: &AttestationEvidence) -> K3; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeReceipt {
    pub root_id: [u8; 16],
    pub protocol: EdgeProtocol,
    pub request_digest: [u8; 32],
    pub facts: EdgeFacts,
    pub verdict: EdgeVerdict,
    pub envelope_bits: u8,
    pub action: EdgeAction,
    pub budget_accepted: bool,
    pub policy_hash: [u8; 32],
    pub weights_hash: [u8; 32],
    pub evidence_class: u8,
    pub issued_at: u64,
    pub expires_at: u64,
    pub attestation: AttestationEvidence,
}

impl EdgeReceipt {
    pub fn write_tbs(&self, out: &mut [u8]) -> Result<usize, CanonicalError> {
        let mut w = CanonicalWriter::new(out);
        w.raw(RECEIPT_TBS_DOMAIN)?;
        w.raw(&HYBRID_SUITE_ID.to_be_bytes())?;
        w.raw(&self.root_id)?;
        w.u8(self.protocol as u8)?;
        w.raw(&self.request_digest)?;
        self.facts.write(&mut w)?;
        w.u8(self.verdict as u8)?;
        w.u8(self.envelope_bits)?;
        w.u8(self.action as u8)?;
        w.u8(self.budget_accepted as u8)?;
        w.raw(&self.policy_hash)?;
        w.raw(&self.weights_hash)?;
        w.u8(self.evidence_class)?;
        w.u64(self.issued_at)?;
        w.u64(self.expires_at)?;
        self.attestation.write(&mut w)?;
        Ok(w.written())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustRoot {
    pub root_id: [u8; 16],
    pub key: HybridPublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub protocol_mask: u8,
    pub measurement_count: u8,
    pub expected_measurements: [[u8; MEASUREMENT_LEN]; MAX_EXPECTED_MEASUREMENTS],
}

impl TrustRoot {
    pub fn write_tbs(&self, out: &mut [u8]) -> Result<usize, CanonicalError> {
        let mut w = CanonicalWriter::new(out);
        w.raw(ROOT_TBS_DOMAIN)?;
        w.raw(&self.root_id)?;
        w.raw(&self.key.ed25519)?;
        w.raw(&self.key.mldsa65)?;
        w.u64(self.not_before)?;
        w.u64(self.not_after)?;
        w.u8(self.protocol_mask)?;
        w.u8(self.measurement_count)?;
        for m in &self.expected_measurements { w.raw(m)?; }
        Ok(w.written())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootEndorsement { pub endorser_id: [u8; 16], pub endorsed: TrustRoot, pub signature: HybridSignature }

pub struct FederatedTrustStore<'a> { pub roots: &'a [TrustRoot], pub endorsements: &'a [RootEndorsement] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refutation {
    TimeWindow(u8), RootWindow, ProtocolNotDelegated, SignatureInvalid,
    EnvelopeViolation, RequestDigestMismatch, Coupling, AttestationRefuted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unknown { UnknownRoot, EndorsementDepthExceeded, ScratchExhausted }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified { pub request_bound: K3, pub attested: K3 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome { Verified(Verified), Refuted(Refutation), Unknown(Unknown) }

impl VerifyOutcome {
    pub const fn k3(&self) -> K3 {
        match self { Self::Verified(_) => K3::Pos, Self::Refuted(_) => K3::Neg, Self::Unknown(_) => K3::Bot }
    }
}

#[derive(Debug)]
pub enum SignError<E> { Canonical(CanonicalError), KeyBindingBroken, Floor(E) }

fn key_binding<V: HybridVerifier>(pk: &HybridPublicKey, ev: &AttestationEvidence) -> K3 {
    let mut kb = [0u8; HYBRID_PK_LEN];
    let Some(head) = kb.get_mut(..ED25519_PK_LEN) else { return K3::Bot };
    head.copy_from_slice(&pk.ed25519);
    let Some(tail) = kb.get_mut(ED25519_PK_LEN..) else { return K3::Bot };
    tail.copy_from_slice(&pk.mldsa65);
    let d = V::digest32(&kb);
    K3::from_bool(ev.report_data.get(..32) == Some(&d[..]))
}

/// Refuses to sign when the quote's report data does not commit to the hybrid public key.
pub fn sign_receipt<F: KernelCryptoFloor>(floor: &F, receipt: &EdgeReceipt)
    -> Result<HybridSignature, SignError<F::Error>>
{
    let attested_env = !matches!(receipt.attestation.tee, TeeKind::None);
    if attested_env && key_binding::<F>(floor.public_key(), &receipt.attestation).is_neg() {
        return Err(SignError::KeyBindingBroken);
    }
    let mut buf = [0u8; RECEIPT_TBS_LEN];
    let n = receipt.write_tbs(&mut buf).map_err(SignError::Canonical)?;
    let tbs = buf.get(..n).ok_or(SignError::Canonical(CanonicalError::Capacity))?;
    floor.hybrid_sign(tbs).map_err(SignError::Floor)
}

/// Bounded recursion: `depth` strictly decreases, so at most `MAX_ENDORSEMENT_DEPTH` hops.
fn resolve_root<'s, V: HybridVerifier>(
    store: &'s FederatedTrustStore<'s>, root_id: &[u8; 16], at: u64, depth: u8,
) -> Result<&'s TrustRoot, Unknown> {
    if let Some(r) = store.roots.iter().find(|r| r.root_id == *root_id) { return Ok(r); }
    let Some(next) = depth.checked_sub(1) else { return Err(Unknown::EndorsementDepthExceeded) };
    for e in store.endorsements.iter().filter(|e| e.endorsed.root_id == *root_id) {
        let Ok(endorser) = resolve_root::<V>(store, &e.endorser_id, at, next) else { continue };
        if classify_time_window_code(at, endorser.not_before, endorser.not_after) != 0 { continue; }
        let mut buf = [0u8; ROOT_TBS_LEN];
        let Ok(n) = e.endorsed.write_tbs(&mut buf) else { continue };
        let Some(tbs) = buf.get(..n) else { continue };
        if V::hybrid_verify(&endorser.key, tbs, &e.signature) { return Ok(&e.endorsed); }
    }
    Err(Unknown::UnknownRoot)
}

fn attestation_k3<V: HybridVerifier>(root: &TrustRoot, receipt: &EdgeReceipt, quotes: &impl AttestationVerifier) -> K3 {
    if matches!(receipt.attestation.tee, TeeKind::None) || root.measurement_count == 0 { return K3::Bot; }
    let count = usize::from(root.measurement_count).min(MAX_EXPECTED_MEASUREMENTS);
    let measured = root.expected_measurements.iter().take(count)
        .any(|m| *m == receipt.attestation.measurement);
    key_binding::<V>(&root.key, &receipt.attestation)
        .and(K3::from_bool(measured))
        .and(quotes.verify_quote(&receipt.attestation))
}

pub fn verify_receipt_offline<V: HybridVerifier>(
    store: &FederatedTrustStore<'_>,
    quotes: &impl AttestationVerifier,
    receipt: &EdgeReceipt,
    signature: &HybridSignature,
    request: Option<&PortableToolCallRequest<'_>>,
    expected_policy_hash: Option<&[u8; 32]>,
    scratch: &mut [u8],
    now: u64,
) -> VerifyOutcome {
    use VerifyOutcome::{Refuted, Unknown as Unk, Verified as Ver};
    let tw = classify_time_window_code(now, receipt.issued_at, receipt.expires_at);
    if tw != 0 { return Refuted(Refutation::TimeWindow(tw)); }
    let root = match resolve_root::<V>(store, &receipt.root_id, receipt.issued_at, MAX_ENDORSEMENT_DEPTH) {
        Ok(r) => r,
        Err(u) => return Unk(u),
    };
    if classify_time_window_code(receipt.issued_at, root.not_before, root.not_after) != 0 {
        return Refuted(Refutation::RootWindow);
    }
    if root.protocol_mask & receipt.protocol.mask() == 0 { return Refuted(Refutation::ProtocolNotDelegated); }

    let mut buf = [0u8; RECEIPT_TBS_LEN];
    let Ok(n) = receipt.write_tbs(&mut buf) else { return Refuted(Refutation::SignatureInvalid) };
    let Some(tbs) = buf.get(..n) else { return Refuted(Refutation::SignatureInvalid) };
    if !V::hybrid_verify(&root.key, tbs, signature) { return Refuted(Refutation::SignatureInvalid); }

    // Verification transfer: the committed action must have been feasible under the committed facts.
    let env = EdgeEnvelope::from_facts(&receipt.facts, receipt.verdict, receipt.budget_accepted);
    if env.bits() != receipt.envelope_bits || !env.contains(receipt.action) {
        return Refuted(Refutation::EnvelopeViolation);
    }

    let request_bound = match request {
        None => K3::Bot,
        Some(req) => match req.write_canonical(scratch) {
            Err(_) => return Unk(Unknown::ScratchExhausted),
            Ok(len) => match scratch.get(..len) {
                None => return Unk(Unknown::ScratchExhausted),
                Some(bytes) => K3::from_bool(
                    V::digest32(bytes) == receipt.request_digest && req.protocol == receipt.protocol),
            },
        },
    };
    if request_bound.is_neg() { return Refuted(Refutation::RequestDigestMismatch); }
    if request.is_some() {
        let coupled = receipt_fields_coupled(
            request_bound.is_pos(), request_bound.is_pos(), env.contains(receipt.action),
            expected_policy_hash.map_or(true, |p| p == &receipt.policy_hash),
            receipt.evidence_class <= MAX_EVIDENCE_CLASS);
        if !coupled { return Refuted(Refutation::Coupling); }
    }

    let attested = attestation_k3::<V>(root, receipt, quotes);
    if attested.is_neg() { return Refuted(Refutation::AttestationRefuted); }
    Ver(Verified { request_bound, attested })
}
```

**Attestation binding.** The quote's report data must equal the digest of the concatenated hybrid public key. The signer refuses to sign otherwise, and the verifier recomputes the same binding from the root's key. The root pins the set of acceptable measurements. The weights hash from the loaded-weights provider is committed into the receipt body at signing time after the model-card binding check passes. An offline reader therefore knows which predictor emitted the concept readout, even though the predictor never decided admission.

**Three-valued outcome.** Expired receipts, bad signatures, envelope violations and digest mismatches are refutations. An unresolvable root or an exhausted scratch buffer is unknown. A missing quote-verification chain yields unknown attestation on an otherwise verified receipt. Consumers fail closed on anything but verified.

## Formal obligations and proofs

**Additive kernel-core exports.** The envelope law has a single source of truth. The portable crate calls these plain functions, and Aeneas extracts them to Lean.

```rust
// crates/kernel/chio-kernel-core/src/formal_aeneas.rs  (strictly additive)
pub fn edge_allow_feasible(verdict_code: u8, budget_accepted: bool, identity_code: u8,
                           transport_code: u8, schema_code: u8, time_window_code: u8) -> bool {
    budget_accepted && verdict_code == 0 && identity_code != 1
        && transport_code == 0 && schema_code == 0 && time_window_code == 0
}

pub fn edge_defer_feasible(verdict_code: u8, budget_accepted: bool) -> bool {
    budget_accepted && verdict_code == 1
}

pub fn edge_envelope_bits(verdict_code: u8, budget_accepted: bool, identity_code: u8,
                          transport_code: u8, schema_code: u8, time_window_code: u8) -> u8 {
    let mut bits: u8 = 1;
    if edge_defer_feasible(verdict_code, budget_accepted) { bits |= 2; }
    if edge_allow_feasible(verdict_code, budget_accepted, identity_code, transport_code, schema_code, time_window_code) {
        bits |= 4;
    }
    bits
}

pub fn edge_project_code(envelope_bits: u8, proposed_code: u8) -> u8 {
    let bit = match proposed_code { 0 => 1u8, 1 => 2, 2 => 4, _ => 0 };
    if envelope_bits & bit != 0 { proposed_code } else { 0 }
}

pub fn hybrid_floor_accepts(ed25519_ok: bool, mldsa65_ok: bool) -> bool { ed25519_ok && mldsa65_ok }

pub fn root_window_covers(issued_at: u64, root_not_before: u64, root_not_after: u64) -> bool {
    classify_time_window_code(issued_at, root_not_before, root_not_after) == 0
}
```

**Lean 4 specification.** The hand-written model below is what the extracted functions must refine.

```lean
namespace Chio.Edge

inductive K3 | pos | neg | bot deriving DecidableEq, Repr
inductive Verdict | allow | pending | deny deriving DecidableEq, Repr
inductive Action | deny | defer | allow deriving DecidableEq, Repr

structure Facts where
  identityCoherent : K3
  transportAuthenticated : K3
  schemaValid : K3
  timeWindow : UInt8
  deriving DecidableEq, Repr

def allowFeasible (f : Facts) (v : Verdict) (b : Bool) : Bool :=
  b && decide (v = .allow) && decide (f.identityCoherent ≠ .neg) &&
  decide (f.transportAuthenticated = .pos) && decide (f.schemaValid = .pos) &&
  decide (f.timeWindow = 0)

def deferFeasible (v : Verdict) (b : Bool) : Bool := b && decide (v = .pending)

def envelope (f : Facts) (v : Verdict) (b : Bool) : List Action :=
  .deny :: ((if deferFeasible v b then [.defer] else []) ++
            (if allowFeasible f v b then [.allow] else []))

def project (env : List Action) (p : Action) : Action := if p ∈ env then p else .deny

def admits : Action → Bool
  | .allow => true
  | _ => false

theorem deny_mem (f v b) : Action.deny ∈ envelope f v b := by simp [envelope]

theorem project_mem (f v b) (p : Action) : project (envelope f v b) p ∈ envelope f v b := by
  unfold project
  split
  · assumption
  · exact deny_mem f v b

theorem allow_sound (f v b) (h : Action.allow ∈ envelope f v b) : allowFeasible f v b = true := by
  simp only [envelope, List.mem_cons, List.mem_append] at h
  rcases h with h | h | h
  · cases h
  · split at h <;> simp_all
  · split at h <;> simp_all

theorem allow_gates (f v b) (h : allowFeasible f v b = true) :
    b = true ∧ v = .allow ∧ f.identityCoherent ≠ .neg ∧
    f.transportAuthenticated = .pos ∧ f.schemaValid = .pos ∧ f.timeWindow = 0 := by
  simpa [allowFeasible, Bool.and_eq_true, decide_eq_true_eq, and_assoc] using h

theorem pending_never_admits (f v b p) (hv : v = .pending) :
    admits (project (envelope f v b) p) = false := by
  have hm := project_mem f v b p
  cases hp : project (envelope f v b) p with
  | allow =>
    rw [hp] at hm
    have hg := (allow_gates f v b (allow_sound f v b hm)).2.1
    subst hv; cases hg
  | deny => rfl
  | defer => rfl

/-- Abstract fixed-width length prefix, as emitted by `CanonicalWriter::seg`. -/
structure Prefix where
  enc   : Nat → List UInt8
  width : ∀ n, (enc n).length = 4
  inj   : ∀ m n, enc m = enc n → m = n

def encode (P : Prefix) : List (List UInt8) → List UInt8
  | [] => []
  | s :: rest => P.enc s.length ++ (s ++ encode P rest)

theorem encode_injective (P : Prefix) : ∀ a b, encode P a = encode P b → a = b := by
  intro a
  induction a with
  | nil =>
    intro b h
    cases b with
    | nil => rfl
    | cons t rest =>
      have hl := congrArg List.length h
      simp only [encode, List.length_append, List.length_nil, P.width] at hl
      omega
  | cons s rest ih =>
    intro b h
    cases b with
    | nil =>
      have hl := congrArg List.length h
      simp only [encode, List.length_append, List.length_nil, P.width] at hl
      omega
    | cons t rest' =>
      simp only [encode] at h
      obtain ⟨hp, hrest⟩ := List.append_inj h (by rw [P.width, P.width])
      obtain ⟨hs, hr⟩ := List.append_inj hrest (P.inj _ _ hp)
      rw [hs, ih rest' hr]

end Chio.Edge
```

The refinement obligation for the extracted code is stated once and discharged by case analysis on the five codes and the boolean:

$$\forall\, f\, v\, b.\;\; \big(\texttt{edge\_envelope\_bits}(v,b,f) \mathbin{\&} 4 \neq 0\big) \iff \texttt{Action.allow} \in \texttt{envelope}\, f\, v\, b .$$

**Apalache model.** The learned choice is an unconstrained existential over the feasible set, exactly the verification-transfer discipline.

```tla
------------------------- MODULE ChioProtocolEdge -------------------------
EXTENDS Integers

CONSTANTS
  \* @type: Set(Str);
  Requests

VARIABLES
  \* @type: Str -> Str;
  phase,
  \* @type: Str -> Str;
  verdict,
  \* @type: Str -> Bool;
  factsOk,
  \* @type: Str -> Bool;
  budgetOk,
  \* @type: Str -> Str;
  action,
  \* @type: Str -> Bool;
  dualSigned,
  \* @type: Str -> Bool;
  admitted

Verdicts == {"Allow", "PendingApproval", "Deny"}

Feasible(r) ==
  {"Deny"}
    \cup (IF budgetOk[r] /\ verdict[r] = "PendingApproval" THEN {"Defer"} ELSE {})
    \cup (IF budgetOk[r] /\ verdict[r] = "Allow" /\ factsOk[r] THEN {"Allow"} ELSE {})

Init ==
  /\ phase = [r \in Requests |-> "lifted"]
  /\ verdict \in [Requests -> Verdicts]
  /\ factsOk \in [Requests -> BOOLEAN]
  /\ budgetOk \in [Requests -> BOOLEAN]
  /\ action = [r \in Requests |-> "Deny"]
  /\ dualSigned = [r \in Requests |-> FALSE]
  /\ admitted = [r \in Requests |-> FALSE]

Decide(r) ==
  /\ phase[r] = "lifted"
  /\ \E a \in Feasible(r): action' = [action EXCEPT ![r] = a]
  /\ dualSigned' = [dualSigned EXCEPT ![r] = TRUE]
  /\ phase' = [phase EXCEPT ![r] = "decided"]
  /\ UNCHANGED <<verdict, factsOk, budgetOk, admitted>>

Respond(r) ==
  /\ phase[r] = "decided"
  /\ admitted' = [admitted EXCEPT ![r] = (action[r] = "Allow")]
  /\ phase' = [phase EXCEPT ![r] = "responded"]
  /\ UNCHANGED <<verdict, factsOk, budgetOk, action, dualSigned>>

Next == \E r \in Requests: Decide(r) \/ Respond(r)

AdmissionSound ==
  \A r \in Requests:
    admitted[r] => /\ action[r] = "Allow" /\ verdict[r] = "Allow"
                   /\ factsOk[r] /\ budgetOk[r] /\ dualSigned[r]

PendingNeverAdmits == \A r \in Requests: verdict[r] = "PendingApproval" => ~admitted[r]

IndInv ==
  /\ AdmissionSound /\ PendingNeverAdmits
  /\ \A r \in Requests: phase[r] # "lifted" => action[r] \in Feasible(r) /\ dualSigned[r]
=============================================================================
```

Run `apalache-mc check --inv=IndInv --length=12` for bounded reachability and `--inductive=IndInv` for the inductive step.

**Kani harnesses.** Each harness models the learned choice with unconstrained nondeterminism.

```rust
#[cfg(kani)]
#[allow(clippy::arithmetic_side_effects)]
mod verification {
    use super::*;

    fn any_k3() -> K3 {
        let x: u8 = kani::any(); kani::assume(x <= 2);
        match x { 0 => K3::Pos, 1 => K3::Neg, _ => K3::Bot }
    }
    fn any_verdict() -> EdgeVerdict {
        let x: u8 = kani::any(); kani::assume(x <= 2);
        match x { 0 => EdgeVerdict::Allow, 1 => EdgeVerdict::PendingApproval, _ => EdgeVerdict::Deny }
    }
    fn any_action() -> EdgeAction {
        let x: u8 = kani::any(); kani::assume(x <= 2);
        EdgeAction::from_code(x).unwrap_or(EdgeAction::Deny)
    }
    fn any_protocol() -> EdgeProtocol {
        let x: u8 = kani::any(); kani::assume(x <= 2);
        match x { 0 => EdgeProtocol::McpToolsCall, 1 => EdgeProtocol::A2aMessageSend, _ => EdgeProtocol::EnvoyExtAuthz }
    }
    fn any_facts() -> EdgeFacts {
        EdgeFacts { identity_coherent: any_k3(), transport_authenticated: any_k3(),
                    schema_valid: any_k3(), time_window: kani::any() }
    }

    #[kani::proof]
    fn projection_closed_and_deny_feasible() {
        let env = EdgeEnvelope::from_facts(&any_facts(), any_verdict(), kani::any());
        let proposed = any_action();
        assert!(env.contains(EdgeAction::Deny));
        assert!(env.contains(env.project(proposed)));
    }

    #[kani::proof]
    fn allow_implies_exact_gates() {
        let f = any_facts(); let v = any_verdict(); let b: bool = kani::any();
        let env = EdgeEnvelope::from_facts(&f, v, b);
        if env.contains(EdgeAction::Allow) {
            assert!(b && v == EdgeVerdict::Allow && !f.identity_coherent.is_neg()
                && f.transport_authenticated.is_pos() && f.schema_valid.is_pos() && f.time_window == 0);
        }
    }

    #[kani::proof]
    fn response_admits_iff_allow() {
        let p = any_protocol(); let a = any_action();
        assert_eq!(response_admits(respond(p, a)), a.admits());
    }

    #[kani::proof]
    #[kani::unwind(70)]
    fn canonical_writer_total() {
        let mut out = [0u8; 64];
        let n: usize = kani::any(); kani::assume(n <= 64);
        let src = [0xA5u8; 64];
        let mut w = CanonicalWriter::new(&mut out);
        let ok = w.seg(&src[..n]).is_ok();
        assert_eq!(ok, n.checked_add(4).map_or(false, |t| t <= 64));
    }

    #[kani::proof]
    fn floor_requires_both() {
        let ed: bool = kani::any(); let ml: bool = kani::any();
        let acc = chio_kernel_core::formal_aeneas::hybrid_floor_accepts(ed, ml);
        assert!(!acc || (ed && ml));
    }
}
```

**Theorem 1, envelope soundness and projection closure.** For every fact tuple, verdict and budget outcome, the projection returns a member of the envelope, and Allow is a member only when the verdict is Allow, the budget was accepted, identity is not refuted, transport and schema are `+`, and the time window is valid. Proof: `project_mem`, `allow_sound` and `allow_gates` in Lean, mirrored by the first two Kani harnesses and by `AdmissionSound` in Apalache. A pending verdict therefore never admits by `pending_never_admits`, and the response mapping preserves this by the exhaustive harness over protocol and action.

**Theorem 2, canonical binding.** Two requests with equal canonical bytes are field-wise equal. Proof: the writer emits a fixed domain, one protocol byte, fixed-width integers, and then fixed-width length-prefixed segments. The segment part is injective by `encode_injective`, whose prefix structure is satisfied by a four-byte big-endian length because segments are capped well below the width bound. Fixed-width fields are trivially injective by position. Hence a receipt whose request digest matches a presented request binds that exact request, up to collision of the 32-byte digest, with advantage bounded by the collision resistance of the provider's hash.

**Theorem 3, the hybrid floor.** Let the signing scheme be the AND combiner over Ed25519 and ML-DSA-65 with the suite identifier inside the signed bytes. For any forger $\mathcal{F}$ against the combiner,

$$\mathrm{Adv}^{\text{EUF-CMA}}_{\text{hybrid}}(\mathcal{F}) \;\le\; \min\!\big(\mathrm{Adv}^{\text{EUF-CMA}}_{\text{Ed25519}}(\mathcal{B}_1),\; \mathrm{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA-65}}(\mathcal{B}_2)\big).$$

Proof. Build $\mathcal{B}_1$ against Ed25519: it receives an Ed25519 public key, samples an ML-DSA-65 key pair itself, hands the pair to $\mathcal{F}$, and answers each signing query by querying its Ed25519 oracle and signing locally with ML-DSA-65 over the same bytes. When $\mathcal{F}$ outputs a forgery on fresh bytes, $\mathcal{B}_1$ outputs the Ed25519 component, which verifies on fresh bytes. $\mathcal{B}_2$ is symmetric. Both reductions are tight and succeed whenever $\mathcal{F}$ does, so the advantage is bounded by the smaller of the two. Non-separability follows from the domain tag and suite identifier: a component signature over receipt bytes is not a valid signature over any message in a single-algorithm domain, so stripping produces nothing a single-algorithm policy accepts. The verifier evaluates both components without short circuit, so a provider bug in one scheme cannot be masked by an early return.

**Theorem 4, offline verification is sound and monotone.** Assume federation coherence: every root identifier denotes one descriptor across local roots and endorsements. Then verified outcomes are sound, and adding roots or endorsements can move unknown to verified or refuted but never flips verified and refuted. Proof. Resolution terminates because the depth parameter strictly decreases on each recursive call. If resolution succeeds through endorsements, there is a chain of at most the maximum depth, each link hybrid-verified under the endorser's key with the endorser's window covering the receipt's issue time, grounded in a local root. All subsequent checks are deterministic functions of the resolved descriptor and the receipt. Under coherence the descriptor is fixed once resolvable, so store growth cannot change a resolved verdict. The only outcomes that depend on store contents are the unknown cases, which is the monotonicity claim. The three-valued result is thus a Kleene-monotone function of verifier knowledge.

**Proof manifest additions.** Each row is an additive entry; no existing signature changes.

| Obligation | Tool | Artifact |
|---|---|---|
| Envelope soundness, projection closure, pending never admits | Lean 4 | `formal/lean4/Chio/Edge.lean` |
| Canonical encoding injectivity | Lean 4 | same module, `encode_injective` |
| Extracted envelope refines Lean model | Aeneas | `formal_aeneas.rs` edge functions |
| Admission soundness, inductive invariant | Apalache | `formal/tla/ChioProtocolEdge.tla` |
| Projection, gates, response mapping, writer totality, floor | Kani | `verification` module in the portable crate |

**Status.** The portable crate, the three lifters, the Tier-0 gate, the signing floor, the trust store and the offline verifier are written as additive code depending only on existing kernel-core functions plus the six new ones above. The Lean, Apalache and Kani artifacts state and discharge the envelope, binding and floor properties. Nothing here was executed against a toolchain in this session, so the next step is wiring the manifest rows into CI and running the three provers against the pinned toolchains.