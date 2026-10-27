# Chio / Arc Grounded Fable-5.1 (`--effort max`) Kernel-as-Decision-Model Experiment

- **Timestamp**: `20261025-003139`
- **Repo Base**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`)
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Max OAuth, zero API spend)
- **Wall-Clock Elapsed**: `943.36s` (4-way parallel execution)

## Verification Summary

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Elapsed (s) |
|---|---:|---|---|---|---|---:|
| `w2_angle_1_slices_p1_p2_p3_crate_plan` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6571` | `747.21` |
| `w2_angle_2_lean_aeneas_kani_apalache_proofs` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6125` | `699.61` |
| `w2_angle_3_linux_macos_os_enforcement` | `0` | `success` | `['claude-fable-5-1']` | `none` | `1799` | `943.35` |
| `w2_angle_4_agentic_economy_relying_party_and_positioning` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5255` | `791.07` |

---

## w2_angle_1_slices_p1_p2_p3_crate_plan

I'll lay out the three slices as a dependency-ordered crate plan, with module layouts, `#![no_std]` signatures, the theorems each slice must discharge, and the Kani/Loom/property/DST gates that make each one mergeable.

## 1. Cross-slice ordering, crate topology, and the shared invariant

The Wave 1 result being implemented is the enveloped decision process. An exact fact processor $C$ maps a state $s$ to a feasibility set $F(s) \subseteq \mathcal{A}$ that always contains the conservative action $\bot_s$. A learned policy $\pi_\theta$ proposes, and a shield projects the proposal into $F(s)$ in $O(1)$. Every decision emits a witness that a receipt binds. Slices P1, P2, P3 realise the three layers of that process, and nothing in P2 or P3 may widen $F(s)$.

**Delivery order and parallelism.** Four work packages, three of which run in parallel after the first two land.

| Order | Package | Crate / path | Depends on | Target gate |
|---|---|---|---|---|
| 0 | P1 | `chio-kernel-core::envelope` (new module) | nothing new | `no_std`, no `alloc` |
| 1 | P2.0 | `crates/core/chio-fixed` (new crate) | nothing | `no_std`, no `alloc` |
| 2a | P2.1 | `crates/economy/chio-micro-model` (new) | P1, P2.0 | `no_std`, no `alloc` |
| 2b | P3 | `crates/security/chio-predicate-dag` (new) | P1, P2.0 | `no_std`, no `alloc` |
| 3 | P2.2 + P3.2 | `chio-kernel::{envelope_runtime, shadow_price_plane, predicate_ingress}` | 2a, 2b | `std`, Loom, DST |

P3 does not depend on P2.1. The 19.3M-parameter Copley encoder never runs in-kernel. A sidecar quantises it and exports 537 Q16.16 logits plus an attestation. The kernel consumes logits and sealed thresholds only, so P3 needs the fixed-point type but not the micro-model runtime.

**Workspace lint posture for all new code.** Every new crate and module carries the workspace denies on `unsafe_code`, `unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `as_conversions`, and `arithmetic_side_effects`. The signatures below are written to those lints: slice access goes through `get`, arithmetic through `checked_*`, `saturating_*`, or `wrapping_shr` on a const amount, and integer conversion through `From`/`TryFrom`. P2.0 additionally denies `clippy::float_arithmetic` so cross-target determinism cannot regress by accident.

**A true no-std gate.** Each `no_std` crate is built in CI for `thumbv7em-none-eabi` in addition to `wasm32-unknown-unknown`, `wasm32-wasip1`, and the mobile targets. A target with no `std` and no default allocator is the only build that catches an accidental `alloc` or `std` leak at compile time.

## 2. Slice P1: `Envelope<A>`, `FeasibilityMap`, conservative default, receipt witness

**Module layout** inside `crates/kernel/chio-kernel-core/src/`:

```
envelope/
  mod.rs          re-exports; crate feature `envelope` (default on)
  action.rs       ActionIndex, EnvelopeAction, MAX_ENVELOPE_ACTIONS
  mask.rs         FeasibilityMask (fixed 4×u64 bitset)
  map.rs          FeasibilityMap, EnvelopeError, restrict, from_mask_with_bot
  project.rs      Projected, ProjectionOutcome, FeasibilityMap::project
  witness.rs      EnvelopeWitness, WitnessHasher, fixed-width codec
  decide.rs       Envelope<A> trait, Decision<A>, decide()
  verdict.rs      impl EnvelopeAction for Verdict, KernelVerdictEnvelope (bot = Deny)
  kani_harnesses.rs   #[cfg(kani)]
formal_aeneas.rs      + project_index(), mask_contains_word()
```

**Signatures.** The action alphabet is capped at 256 so the mask is a fixed array and the projection is a bit test with no loop.

```rust
// action.rs
pub const MAX_ENVELOPE_ACTIONS: usize = 256;
pub const MASK_WORDS: usize = MAX_ENVELOPE_ACTIONS / 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ActionIndex(u8);

impl ActionIndex {
    #[must_use] pub const fn new(raw: u8) -> Self { Self(raw) }
    #[must_use] pub const fn raw(self) -> u8 { self.0 }
    #[must_use] #[inline] pub fn word(self) -> usize { usize::from(self.0.wrapping_shr(6)) }
    #[must_use] #[inline] pub fn bit(self) -> u32 { u32::from(self.0 & 0x3F) }
}

pub trait EnvelopeAction: Copy + Eq {
    fn to_index(self) -> ActionIndex;
    fn from_index(index: ActionIndex) -> Option<Self>;
}

// mask.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeasibilityMask { words: [u64; MASK_WORDS] }

impl FeasibilityMask {
    pub const EMPTY: Self = Self { words: [0; MASK_WORDS] };
    pub const FULL: Self = Self { words: [u64::MAX; MASK_WORDS] };

    #[inline] #[must_use]
    pub fn contains(&self, a: ActionIndex) -> bool {
        self.words.get(a.word()).is_some_and(|w| (w.wrapping_shr(a.bit()) & 1) == 1)
    }
    #[inline] #[must_use]
    pub fn with(mut self, a: ActionIndex) -> Self {
        if let Some(w) = self.words.get_mut(a.word()) { *w |= 1u64.wrapping_shl(a.bit()); }
        self
    }
    #[inline] #[must_use]
    pub fn without(mut self, a: ActionIndex) -> Self {
        if let Some(w) = self.words.get_mut(a.word()) { *w &= !(1u64.wrapping_shl(a.bit())); }
        self
    }
    #[must_use]
    pub fn intersect(self, o: Self) -> Self {
        let mut words = [0u64; MASK_WORDS];
        for (d, (a, b)) in words.iter_mut().zip(self.words.iter().zip(o.words.iter())) { *d = a & b; }
        Self { words }
    }
    #[must_use] pub const fn words(&self) -> &[u64; MASK_WORDS] { &self.words }
    #[must_use] pub const fn from_words(words: [u64; MASK_WORDS]) -> Self { Self { words } }
}
```

```rust
// map.rs + project.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    ConservativeNotFeasible { bot: ActionIndex },
    ActionCodec { index: ActionIndex },
    WitnessOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeasibilityMap { mask: FeasibilityMask, bot: ActionIndex }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionOutcome { Accepted, Shielded, PolicyUnavailable }

impl ProjectionOutcome {
    #[must_use] pub const fn code(self) -> u8 {
        match self { Self::Accepted => 0, Self::Shielded => 1, Self::PolicyUnavailable => 2 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projected {
    pub chosen: ActionIndex,
    pub proposed: Option<ActionIndex>,
    pub outcome: ProjectionOutcome,
}

impl FeasibilityMap {
    pub fn new(mask: FeasibilityMask, bot: ActionIndex) -> Result<Self, EnvelopeError> {
        if mask.contains(bot) { Ok(Self { mask, bot }) }
        else { Err(EnvelopeError::ConservativeNotFeasible { bot }) }
    }
    /// Infallible constructor: `{bot}` is adjoined to whatever `mask` says.
    #[must_use] pub fn from_mask_with_bot(mask: FeasibilityMask, bot: ActionIndex) -> Self {
        Self { mask: mask.with(bot), bot }
    }
    #[must_use] pub fn conservative_only(bot: ActionIndex) -> Self {
        Self::from_mask_with_bot(FeasibilityMask::EMPTY, bot)
    }
    /// `(mask ∩ other) ∪ {bot}`: no guard can remove the conservative action.
    #[must_use] pub fn restrict(self, other: FeasibilityMask) -> Self {
        Self::from_mask_with_bot(self.mask.intersect(other), self.bot)
    }
    #[must_use] pub const fn mask(&self) -> FeasibilityMask { self.mask }
    #[must_use] pub const fn bot(&self) -> ActionIndex { self.bot }

    /// O(1): one bit test, no loop, no allocation.
    #[inline] #[must_use]
    pub fn project(&self, proposed: Option<ActionIndex>) -> Projected {
        match proposed {
            Some(a) if self.mask.contains(a) =>
                Projected { chosen: a, proposed, outcome: ProjectionOutcome::Accepted },
            Some(_) =>
                Projected { chosen: self.bot, proposed, outcome: ProjectionOutcome::Shielded },
            None =>
                Projected { chosen: self.bot, proposed: None, outcome: ProjectionOutcome::PolicyUnavailable },
        }
    }
}
```

```rust
// decide.rs
pub trait Envelope<A: EnvelopeAction> {
    type State: ?Sized;
    fn envelope_id(&self) -> [u8; 32];
    fn policy_version(&self) -> u32;
    /// The exact fact processor C(s) ↦ F(s). Total, pure, bounded work.
    fn feasibility(&self, state: &Self::State) -> FeasibilityMap;
    fn state_digest(&self, state: &Self::State) -> [u8; 32];
}

pub struct Decision<A> {
    pub chosen: A,
    pub projected: Projected,
    pub map: FeasibilityMap,
    pub witness: EnvelopeWitness,
}

pub fn decide<A: EnvelopeAction, E: Envelope<A> + ?Sized>(
    env: &E, state: &E::State, proposed: Option<A>,
) -> Result<Decision<A>, EnvelopeError> {
    let map = env.feasibility(state);
    let projected = map.project(proposed.map(EnvelopeAction::to_index));
    let chosen = A::from_index(projected.chosen)
        .ok_or(EnvelopeError::ActionCodec { index: projected.chosen })?;
    let witness = EnvelopeWitness {
        version: ENVELOPE_WITNESS_VERSION,
        envelope_id: env.envelope_id(),
        state_digest: env.state_digest(state),
        mask: map.mask(),
        bot: map.bot(),
        projected,
        policy_version: env.policy_version(),
    };
    Ok(Decision { chosen, projected, map, witness })
}
```

```rust
// witness.rs
pub const ENVELOPE_WITNESS_VERSION: u16 = 1;
pub const ENVELOPE_WITNESS_WIRE_LEN: usize = 107; // 2+32+32+32+1+4+4
pub const ENVELOPE_WITNESS_DOMAIN: &[u8] = b"chio.kernel.envelope-witness.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeWitness {
    pub version: u16,
    pub envelope_id: [u8; 32],
    pub state_digest: [u8; 32],
    pub mask: FeasibilityMask,
    pub bot: ActionIndex,
    pub projected: Projected,
    pub policy_version: u32,
}

pub trait WitnessHasher { fn digest32(&self, domain: &[u8], payload: &[u8]) -> [u8; 32]; }

struct Cursor<'a> { buf: &'a mut [u8], at: usize }
impl Cursor<'_> {
    fn put(&mut self, src: &[u8]) -> Result<(), EnvelopeError> {
        let end = self.at.checked_add(src.len()).ok_or(EnvelopeError::WitnessOverflow)?;
        let dst = self.buf.get_mut(self.at..end).ok_or(EnvelopeError::WitnessOverflow)?;
        dst.copy_from_slice(src);
        self.at = end;
        Ok(())
    }
}

impl EnvelopeWitness {
    pub fn encode(&self, out: &mut [u8; ENVELOPE_WITNESS_WIRE_LEN]) -> Result<(), EnvelopeError> {
        let mut c = Cursor { buf: out, at: 0 };
        c.put(&self.version.to_le_bytes())?;
        c.put(&self.envelope_id)?;
        c.put(&self.state_digest)?;
        for w in self.mask.words() { c.put(&w.to_le_bytes())?; }
        c.put(&[self.bot.raw()])?;
        let (present, proposed) = match self.projected.proposed {
            Some(a) => (1u8, a.raw()),
            None => (0u8, 0u8),
        };
        c.put(&[present, proposed, self.projected.chosen.raw(), self.projected.outcome.code()])?;
        c.put(&self.policy_version.to_le_bytes())?;
        if c.at == ENVELOPE_WITNESS_WIRE_LEN { Ok(()) } else { Err(EnvelopeError::WitnessOverflow) }
    }
    pub fn decode(bytes: &[u8; ENVELOPE_WITNESS_WIRE_LEN]) -> Result<Self, EnvelopeError> { /* mirror of encode */ unimplemented_decode(bytes) }
    pub fn digest(&self, h: &dyn WitnessHasher) -> Result<[u8; 32], EnvelopeError> {
        let mut buf = [0u8; ENVELOPE_WITNESS_WIRE_LEN];
        self.encode(&mut buf)?;
        Ok(h.digest32(ENVELOPE_WITNESS_DOMAIN, &buf))
    }
}
```

The witness digest is what `chio-kernel` places into a new `envelope_witness_digest` field of `ChioReceiptIdInput`, which grows from 20 to 21 canonical fields. The kernel-core module never serialises JSON, so the hashing backend is injected through `WitnessHasher` and implemented once in `chio-core::crypto`.

**Theorems for P1.** Let $M$ be a `FeasibilityMap` with mask $\mu$ and conservative action $\bot$, and let $P(a) = $ `M.project(a)`.

*Theorem P1.1 (Non-vacuity).* For every constructible $M$, $\bot \in \mu$. Proof. The three constructors are `new`, `from_mask_with_bot`, and `restrict`. `new` returns `Ok` only after `mask.contains(bot)`. The other two end with `mask.with(bot)`, and `contains(bot)` after `with(bot)` is true because `word(bot) ≤ 3 < MASK_WORDS` so the `get_mut` succeeds and sets bit `bit(bot)`. The field is private, so no other construction path exists. $\square$

*Theorem P1.2 (Shield soundness).* For all $a \in \mathcal{A} \cup \{\varnothing\}$, `P(a).chosen` $\in \mu$. Proof. Case `Some(a)` with `contains(a)`: chosen is $a \in \mu$. Case `Some(a)` otherwise, or `None`: chosen is $\bot \in \mu$ by P1.1. $\square$

*Theorem P1.3 (Idempotence and transparency).* `P(Some(P(a).chosen)).chosen = P(a).chosen`, and if $a \in \mu$ then `P(Some(a)).chosen = a`. Proof. By P1.2 the chosen action is feasible, so the second projection takes the `Accepted` arm. The second claim is the `Accepted` arm directly. $\square$ Consequence: on the feasible region the enveloped process and the unshielded policy coincide, so shielding never distorts a lawful $\pi_\theta$.

*Theorem P1.4 (Witness injectivity).* `encode` is injective on `EnvelopeWitness`. Proof. Every field occupies a fixed offset and width with no delimiters, and the `(present, proposed)` pair encodes `None` as `(0,0)` and `Some(a)` as `(1,a)`, which are disjoint. Hence `decode ∘ encode = id`, and two witnesses with equal encodings are equal. With `canonical_inj` already mechanised, a receipt-id collision between distinct decisions therefore requires a hash collision. $\square$

*Proposition P1.5 (WCET).* `project` executes one shift, one mask, one compare, one branch, and no loop. `encode` writes exactly 107 bytes through 10 `put` calls. Both are data-independent in control flow except the single feasibility branch.

**Feature flags.** `envelope` (default), `kani` via `--cfg kani`, `std` only in dev-dependencies for proptest.

**Test matrix.**

| Kind | Name | Checks |
|---|---|---|
| Unit | `mask_contains_roundtrip_all_256` | every index set then read |
| Unit | `restrict_cannot_remove_bot` | P1.1 on `restrict` |
| Unit | `verdict_envelope_bot_is_deny` | kernel envelope conservative default is `Deny` |
| Property | `prop_project_in_mask` (10k cases) | P1.2 for random masks and proposals |
| Property | `prop_witness_encode_decode_roundtrip` | P1.4 |
| Kani | `verify_feasibility_map_always_contains_bot` | symbolic mask and bot, all constructors |
| Kani | `verify_project_chosen_in_mask` | P1.2, fully symbolic `u8` |
| Kani | `verify_project_idempotent` | P1.3 |
| Kani | `verify_mask_contains_no_panic` | symbolic `u8`, no unwinding failure |
| Kani | `verify_witness_roundtrip_injective` | symbolic witness, `decode(encode(w)) == w` |
| Aeneas/Lean | `project_index`, `mask_contains_word` extracted to `Envelope/Projection.lean` | `project_mem_feasible`, `project_idem`, `bot_mem_feasible` |
| Apalache | `EnvelopeDecisionReceipt.tla` | `ChosenInFeasible`, `WitnessBeforeAllow`; negative mutant `EnvelopeNoBot.tla` must yield an `.itf` trace |

**Acceptance criteria.** All harnesses above green. `thumbv7em-none-eabi` build passes for `chio-kernel-core` with `envelope` on. `formal/MAPPING.md` gains rows for P1.1 to P1.4 and `scripts/check-mapping.sh` passes. `chio-kernel-core::evaluate` routes `Allow` through `decide` so that no `Verdict::Allow` is produced without an `EnvelopeWitness`. Receipt id test vectors are regenerated and the 21-field layout is versioned.

**Risk register P1.**

| ID | Risk | L/I | Mitigation |
|---|---|---|---|
| P1-R1 | A future action alphabet exceeds 256 | L/M | `const _: () = assert!` on every `EnvelopeAction` impl's cardinality; the cap is a documented v1 bound |
| P1-R2 | An envelope configures `bot = Allow`, inverting conservatism | L/H | `verdict.rs` fixes `bot = Deny` for kernel verdicts; Kani harness `verify_kernel_envelope_bot_is_deny`; any other envelope needs a signed policy attestation |
| P1-R3 | `state_digest` omits a field, under-binding the witness | M/H | state digest is computed from `NormalizedEvaluationVerdict` inputs through the existing canonical path; property test that two differing normalized states give different digests |
| P1-R4 | Two decision paths diverge, one bypassing `decide` | M/H | `project` is `pub` but `Verdict::Allow` construction in `evaluate` is gated behind `Decision<Verdict>`; grep-based xtask check `formal-mirrors` |
| P1-R5 | Accidental `alloc` leak | M/L | `thumbv7em-none-eabi` CI build |

## 3. Slice P2: `chio-fixed`, `chio-micro-model`, shadow-price control plane

**Module layout.**

```
crates/core/chio-fixed/src/
  lib.rs       FixedQ16_16, WideAcc, FRAC_BITS           (no_std, no alloc)
crates/economy/chio-micro-model/src/
  lib.rs
  tensor.rs    Vec16<N>, Mat16<R,C>
  cost.rs      CostMeter, InferenceError, MAX_TIER0_COST_UNITS
  model.rs     MicroModel trait, Affine<IN,OUT>, Mlp<IN,HID,OUT>
  shadow.rs    ShadowPrices<R>, DualAscentParams, lagrangian_scores, ActionCosts
  policy.rs    argmax_feasible, Tier0Policy, PolicyWitness
  kani_harnesses.rs
crates/kernel/chio-kernel/src/
  shadow_price_plane.rs   Tier 1: single-writer dual ascent, ArcSwap publication
  envelope_runtime.rs     Tier 0 call site in evaluate path; staleness fence
```

**Fixed-point layout.** Q16.16 in `i32`: 1 sign bit, 15 integer bits, 16 fraction bits. Range $[-32768, 32768)$, resolution $2^{-16}$. Products are exact in Q32.32 inside `i64`, and accumulation saturates. Rounding on narrowing is floor via arithmetic shift, which is deterministic and monotone.

```rust
// chio-fixed/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic, clippy::as_conversions, clippy::arithmetic_side_effects)]

pub const FRAC_BITS: u32 = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct FixedQ16_16(i32);

impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(0x0001_0000);
    pub const EPSILON: Self = Self(1);
    pub const MAX: Self = Self(i32::MAX);
    pub const MIN: Self = Self(i32::MIN);

    #[must_use] pub const fn from_raw(raw: i32) -> Self { Self(raw) }
    #[must_use] pub const fn raw(self) -> i32 { self.0 }
    #[must_use] pub fn from_int(i: i16) -> Self { Self(i32::from(i).wrapping_shl(FRAC_BITS)) }
    #[must_use] pub fn saturating_add(self, o: Self) -> Self { Self(self.0.saturating_add(o.0)) }
    #[must_use] pub fn saturating_sub(self, o: Self) -> Self { Self(self.0.saturating_sub(o.0)) }
    #[must_use] pub fn saturating_mul(self, o: Self) -> Self { WideAcc::ZERO.mac(self, o).to_q16().0 }
    #[must_use] pub fn relu(self) -> Self { if self.0 < 0 { Self::ZERO } else { self } }
    #[must_use] pub fn clamp_fixed(self, lo: Self, hi: Self) -> Self {
        if self < lo { lo } else if self > hi { hi } else { self }
    }
}

/// Q32.32 saturating accumulator for dot products.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WideAcc { raw: i64, saturated: bool }

impl WideAcc {
    pub const ZERO: Self = Self { raw: 0, saturated: false };
    #[must_use] pub fn from_q16(x: FixedQ16_16) -> Self {
        Self { raw: i64::from(x.0).wrapping_shl(FRAC_BITS), saturated: false }
    }
    /// Exact wide product (|a·b| ≤ 2^62) added with saturation.
    #[must_use] pub fn mac(self, a: FixedQ16_16, b: FixedQ16_16) -> Self {
        let p = i64::from(a.0).saturating_mul(i64::from(b.0));
        match self.raw.overflowing_add(p) {
            (raw, false) => Self { raw, saturated: self.saturated },
            (_, true) => Self { raw: if p < 0 { i64::MIN } else { i64::MAX }, saturated: true },
        }
    }
    /// floor(raw / 2^16) narrowed to i32 with saturation; returns the saturation flag.
    #[must_use] pub fn to_q16(self) -> (FixedQ16_16, bool) {
        let shifted = self.raw.wrapping_shr(FRAC_BITS);
        match i32::try_from(shifted) {
            Ok(v) => (FixedQ16_16(v), self.saturated),
            Err(_) => (if shifted < 0 { FixedQ16_16::MIN } else { FixedQ16_16::MAX }, true),
        }
    }
}
```

```rust
// chio-micro-model: tensor.rs, cost.rs, model.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vec16<const N: usize>(pub [FixedQ16_16; N]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mat16<const R: usize, const C: usize>(pub [[FixedQ16_16; C]; R]);

pub const MAX_TIER0_COST_UNITS: usize = 16_384;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CostMeter { spent: usize, saturated: bool }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferenceError { CostBudgetExceeded { spent: usize, budget: usize }, CostOverflow }

impl CostMeter {
    pub fn charge(&mut self, units: usize, budget: usize) -> Result<(), InferenceError> {
        let next = self.spent.checked_add(units).ok_or(InferenceError::CostOverflow)?;
        if next > budget { return Err(InferenceError::CostBudgetExceeded { spent: next, budget }); }
        self.spent = next;
        Ok(())
    }
    pub fn note_saturation(&mut self, s: bool) { self.saturated |= s; }
    #[must_use] pub const fn spent(&self) -> usize { self.spent }
    #[must_use] pub const fn saturated(&self) -> bool { self.saturated }
}

pub trait MicroModel<const IN: usize, const OUT: usize> {
    const COST_UNITS: usize;
    fn model_digest(&self) -> [u8; 32];
    fn infer(&self, x: &Vec16<IN>, meter: &mut CostMeter, budget: usize)
        -> Result<Vec16<OUT>, InferenceError>;
}

pub struct Affine<const IN: usize, const OUT: usize> { pub w: Mat16<OUT, IN>, pub b: Vec16<OUT> }

impl<const IN: usize, const OUT: usize> Affine<IN, OUT> {
    pub const COST_UNITS: usize = OUT.saturating_mul(IN.saturating_add(1));
    pub fn forward(&self, x: &Vec16<IN>, meter: &mut CostMeter, budget: usize)
        -> Result<Vec16<OUT>, InferenceError> {
        meter.charge(Self::COST_UNITS, budget)?; // charged before work, so WCET is admitted up front
        let mut out = [FixedQ16_16::ZERO; OUT];
        for (o, (row, bias)) in out.iter_mut().zip(self.w.0.iter().zip(self.b.0.iter())) {
            let acc = row.iter().zip(x.0.iter())
                .fold(WideAcc::from_q16(*bias), |acc, (wi, xi)| acc.mac(*wi, *xi));
            let (v, sat) = acc.to_q16();
            meter.note_saturation(sat);
            *o = v;
        }
        Ok(Vec16(out))
    }
}

pub struct Mlp<const IN: usize, const HID: usize, const OUT: usize> {
    pub l1: Affine<IN, HID>, pub l2: Affine<HID, OUT>, pub digest: [u8; 32],
}

impl<const IN: usize, const HID: usize, const OUT: usize> MicroModel<IN, OUT> for Mlp<IN, HID, OUT> {
    const COST_UNITS: usize = Affine::<IN, HID>::COST_UNITS
        .saturating_add(HID)
        .saturating_add(Affine::<HID, OUT>::COST_UNITS);
    fn model_digest(&self) -> [u8; 32] { self.digest }
    fn infer(&self, x: &Vec16<IN>, meter: &mut CostMeter, budget: usize)
        -> Result<Vec16<OUT>, InferenceError> {
        let mut h = self.l1.forward(x, meter, budget)?;
        meter.charge(HID, budget)?;
        for v in h.0.iter_mut() { *v = v.relu(); }
        self.l2.forward(&h, meter, budget)
    }
}

// The shipped Tier-0 shape is gated at compile time against the WCET budget.
const _: () = assert!(<Mlp<64, 96, 8> as MicroModel<64, 8>>::COST_UNITS <= MAX_TIER0_COST_UNITS);
```

```rust
// shadow.rs + policy.rs
pub struct DualAscentParams { pub eta: FixedQ16_16, pub lambda_max: FixedQ16_16 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowPrices<const R: usize> { pub lambda: [FixedQ16_16; R], pub epoch: u64 }

impl<const R: usize> ShadowPrices<R> {
    #[must_use] pub const fn zero() -> Self { Self { lambda: [FixedQ16_16::ZERO; R], epoch: 0 } }
    /// λ_r ← clamp(λ_r + η·(u_r − c_r), 0, λ_max); epoch strictly advances or the step is refused.
    #[must_use]
    pub fn step(&self, usage: &[FixedQ16_16; R], capacity: &[FixedQ16_16; R], p: &DualAscentParams) -> Option<Self> {
        let epoch = self.epoch.checked_add(1)?;
        let mut lambda = self.lambda;
        for (l, (u, c)) in lambda.iter_mut().zip(usage.iter().zip(capacity.iter())) {
            let delta = p.eta.saturating_mul(u.saturating_sub(*c));
            *l = l.saturating_add(delta).clamp_fixed(FixedQ16_16::ZERO, p.lambda_max);
        }
        Some(Self { lambda, epoch })
    }
}

pub struct ActionCosts<const R: usize, const K: usize>(pub [[FixedQ16_16; R]; K]);

/// score_a = u_θ(s,a) − Σ_r λ_r · c_r(a)
#[must_use]
pub fn lagrangian_scores<const R: usize, const K: usize>(
    utility: &Vec16<K>, costs: &ActionCosts<R, K>, prices: &ShadowPrices<R>,
) -> Vec16<K> {
    let mut out = [FixedQ16_16::ZERO; K];
    for (s, (u, row)) in out.iter_mut().zip(utility.0.iter().zip(costs.0.iter())) {
        let penalty = row.iter().zip(prices.lambda.iter())
            .fold(WideAcc::ZERO, |acc, (c, l)| acc.mac(*c, *l)).to_q16().0;
        *s = u.saturating_sub(penalty);
    }
    Vec16(out)
}

/// argmax restricted to F(s); ties resolve to the lowest index.
#[must_use]
pub fn argmax_feasible<const K: usize>(scores: &Vec16<K>, map: &FeasibilityMap) -> Option<ActionIndex> {
    let mut best: Option<(ActionIndex, FixedQ16_16)> = None;
    for (i, s) in scores.0.iter().enumerate() {
        let Ok(raw) = u8::try_from(i) else { break };
        let idx = ActionIndex::new(raw);
        if !map.mask().contains(idx) { continue; }
        best = match best {
            Some((_, b)) if b >= *s => best,
            _ => Some((idx, *s)),
        };
    }
    best.map(|(i, _)| i)
}

pub struct PolicyWitness {
    pub model_digest: [u8; 32],
    pub features_digest: [u8; 32],
    pub shadow_epoch: u64,
    pub cost_units_spent: usize,
    pub saturated: bool,
    pub proposed: Option<ActionIndex>,
}
```

Tier 0 lives on the evaluation path. It calls `infer`, `lagrangian_scores`, `argmax_feasible`, then P1's `project`. Because the argmax is already restricted to $F(s)$, projection takes the `Accepted` arm whenever a proposal exists, and the shield remains as defence in depth for externally supplied proposals. Tier 1 lives in `chio-kernel::shadow_price_plane`. A single writer runs `step` at millisecond cadence from `chio-metering` usage and `chio-fiscal` capacities, and publishes through an `ArcSwap<ShadowPrices<R>>`. Readers load one snapshot per decision and record its `epoch` in the witness. A clock fence rejects snapshots older than `MAX_SHADOW_EPOCH_AGE_MS` and substitutes a configured `lambda_safe` vector, so a stalled control plane degrades to a known pricing rather than a stale one.

**Theorems for P2.**

*Theorem P2.1 (Bit-exact portability).* For identical inputs, `infer`, `lagrangian_scores`, `argmax_feasible`, and `step` produce identical bytes on every supported target. Proof. Every operation is a fixed-width two's complement integer operation with target-independent semantics in Rust, every function is total, there is no floating point by lint, and iteration order over fixed arrays is defined. $\square$

*Theorem P2.2 (Quantisation error).* Let $q(x) = \lfloor 2^{16}x \rfloor / 2^{16}$, so $|x - q(x)| < 2^{-16}$. For an affine layer with real weights $W \in \mathbb{R}^{O \times N}$, $|W_{ij}| \le B_w$, inputs $|x_j| \le B_x$, if no saturation occurs then the fixed-point output $\hat y_i$ satisfies
$$|\hat y_i - y_i| \le 2^{-16}\big(N(B_x + B_w) + 2\big).$$
Proof. Products of quantised operands are exact in Q32.32 and the sum is exact absent saturation, so the only errors are weight quantisation $\sum_j |W_{ij} - q(W_{ij})|\,|x_j| \le N B_x 2^{-16}$, input quantisation $\sum_j |q(W_{ij})|\,|x_j - q(x_j)| \le N B_w 2^{-16}$, bias quantisation $< 2^{-16}$, and the final floor $< 2^{-16}$. Triangle inequality. $\square$ ReLU is 1-Lipschitz, so the bound composes through the two-layer MLP with the hidden-layer bound substituted for $B_x$.

*Theorem P2.3 (WCET).* `Mlp::infer` performs exactly `COST_UNITS` multiply-accumulate or activation steps and the meter admits them before the first one executes. Proof. Loop bounds are const generics. The only data-dependent branch is the saturation test inside `to_q16`, which has constant cost on both arms. The meter is charged with the compile-time constant before each layer body runs, so a run that would exceed the budget returns `CostBudgetExceeded` having done no work for that layer. $\square$ The acceptance benchmark measures wall time per unit on each target and asserts the ratio against the constant.

*Theorem P2.4 (Shadow-price range and authority separation).* For all inputs, `step` yields $\lambda_r \in [0, \lambda_{\max}]$ and a strictly larger epoch or `None`. For every price vector $\lambda$, the Tier 0 chosen action lies in $F(s)$. Proof. Each component ends with `clamp_fixed(ZERO, lambda_max)` and the epoch uses `checked_add`. The second claim is immediate because `argmax_feasible` skips every index not in the mask and `project` is sound by P1.2. Prices can reorder actions inside $F(s)$, and nothing else. $\square$

*Proposition P2.5 (Dual ascent).* `step` is projected subgradient ascent on the Lagrangian dual $g(\lambda) = \min_a \big[-u(a) + \sum_r \lambda_r (c_r(a) - \mathrm{cap}_r)\big]$ over the box $[0,\lambda_{\max}]^R$. With bounded per-step usage $|u_r - \mathrm{cap}_r| \le G$ and step $\eta$, the standard analysis gives average constraint violation over $T$ steps of order $\frac{\lambda_{\max}}{\eta T} + \eta G$, so $\eta$ is chosen in the control plane as a tuning constant, and `const _: () = assert!` pins $\eta \le \eta_{\max}$ so fixed-point saturation can never be the binding behaviour for admissible usage ranges.

**Feature flags.** `chio-fixed`: none. `chio-micro-model`: `envelope` (pulls `chio-kernel-core` for `FeasibilityMap`, default on), `shadow` (default on). `chio-kernel`: `shadow-price-plane` enabling Tier 1 and `arc-swap`.

**Test matrix.**

| Kind | Name | Checks |
|---|---|---|
| Unit | `fixed_mul_floor_semantics`, `wide_acc_saturates_both_signs` | rounding and saturation edge cases |
| Unit | `mlp_cost_units_matches_counted_macs` | P2.3 against an instrumented reference |
| Property | `prop_fixed_mul_within_one_ulp_of_rational` | P2.2 base case against `i128` rational arithmetic |
| Property | `prop_argmax_feasible_lowest_index_tie_break` | determinism of tie-break |
| Golden | `mlp_cross_target_vectors` | identical output bytes on native, wasm32, aarch64 (P2.1) |
| Kani | `verify_fixed_mul_sat_no_panic`, `verify_fixed_mul_sat_bounds` | totality and range |
| Kani | `verify_fixed_mul_monotone_nonneg` | $a \le a' \Rightarrow a b \le a' b$ for $b \ge 0$ |
| Kani | `verify_wide_acc_saturating_total` | symbolic `mac` sequence of length 3 |
| Kani | `verify_dual_step_in_range`, `verify_dual_step_monotone_in_usage`, `verify_dual_step_epoch_strict` | P2.4 |
| Kani | `verify_argmax_feasible_in_mask`, `verify_argmax_feasible_some_when_bot_lt_k` | P2.4 second claim |
| Kani | `verify_cost_meter_monotone_and_bounded` | meter never exceeds budget |
| Loom | `loom_shadow_price_publish_single_writer_epoch_monotone` | readers observe non-decreasing epochs |
| Loom | `loom_shadow_price_reader_never_tears` | one snapshot per decision, consistent across `lambda` and `epoch` |
| Loom | `loom_tier1_step_while_tier0_scores` | no blocking on the evaluation path |
| DST | `dst_drop_simulation` extension | a dropped future after `infer` but before witness commit leaves no `Allow` without a `PolicyWitness` |
| Aeneas/Lean | `fixed_mul_sat`, `dual_step` into `Fixed/Q16.lean`, `Shadow/Dual.lean` | `mul_sat_bounds`, `dual_step_in_range` |
| Apalache | `ShadowPriceEpochPublish.tla` | `EpochMonotone`, `ReaderSeesConsistentSnapshot`; negative mutant with two writers must trace |

**Acceptance criteria.** Golden vectors identical across three targets. WCET benchmark ratio within the budgeted constant on every target, recorded in `docs/perf/tier0-wcet.md`. Kani and Loom green. `MAPPING.md` rows for P2.1 to P2.4. Saturation flag appears in the receipt and triggers `AutonomousDriftKind::ModelVersionMismatch`-style drift accounting through a new `SaturationRate` drift kind in `chio-autonomy`.

**Risk register P2.**

| ID | Risk | L/I | Mitigation |
|---|---|---|---|
| P2-R1 | Silent saturation changes the argmax | M/M | `saturated` in witness, drift counter, model export rescales weights to $B_w \le 1$ |
| P2-R2 | Floating point leaks in via a dependency | L/H | `deny(clippy::float_arithmetic)`, no deps in `chio-fixed`, `thumbv7em` build |
| P2-R3 | Measured WCET exceeds budgeted constant on wasm32 | M/M | per-target ratio benchmark gate; budget has 2x headroom at `MAX_TIER0_COST_UNITS` |
| P2-R4 | Shadow prices oscillate with large $\eta$ | M/M | `const` upper bound on $\eta$, damping in control plane, Proposition P2.5 bound documented |
| P2-R5 | Stale epoch used under control-plane stall | M/M | staleness fence with `lambda_safe` fallback; epoch recorded in witness |
| P2-R6 | Prices treated as authority to allow | L/H | P2.4; prices enter only `lagrangian_scores`, never `FeasibilityMap` |

## 4. Slice P3: `chio-predicate-dag`, the Copley composer as a `no_std` boolean DAG

**Module layout.**

```
crates/security/chio-predicate-dag/src/
  lib.rs
  tri.rs        Tri, TriSet<W> (strong Kleene three-valued logic in paired bitsets)
  dag.rs        AtomRef, Clause, ClauseKind, Rule, RulePolarity, PredicateDag, ThresholdPair
  validate.rs   ValidatedDag, DagError, taint analysis, work bound
  eval.rs       EvaluationMode, LearnedScores, DagOutcome, evaluate
  margin.rs     RuleMargin, rule_margin (explainability witness)
  receipt.rs    DagReceipt, codec, verify_receipt (replay)
  envelope.rs   RuleEffectTable, feasibility_from_outcome      (feature `envelope`)
  copley_v1.rs  &'static tables generated by `tools/copley-export` (feature `copley-v1`)
  kani_harnesses.rs
```

**Epistemic partition in types.** Copley separates observed facts, exact computation $C(X)$, and learned predictions $P(X)$. In the evaluator, exact facts arrive as a `TriSet` carrying `known_positive`, `known_negative`, and `unknown_effect`, with `unsupported_syntax` mapped to unknown. Learned predictions arrive as 537 Q16.16 logits and become three-valued through the sealed asymmetric thresholds: $z_j \ge \tau_j^{\text{pos}}$ asserts, $z_j < \tau_j^{\text{neg}}$ negates, and the band between abstains. Rules compose atoms in strong Kleene logic.

```rust
#![no_std]
pub const MAX_PREDICATES: usize = 1024;
pub const PRED_WORDS: usize = MAX_PREDICATES / 64;
pub const MAX_RULES: usize = 512;
pub const RULE_WORDS: usize = MAX_RULES / 64;
pub const MAX_TOTAL_ATOMS: usize = 16_384;
pub const COPLEY_V1_PREDICATES: u16 = 537;
pub const COPLEY_V1_RULES: u16 = 236;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tri { False, True, Unknown }

impl Tri {
    #[must_use] pub const fn and(self, o: Self) -> Self {
        match (self, o) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::True, Tri::True) => Tri::True,
            _ => Tri::Unknown,
        }
    }
    #[must_use] pub const fn or(self, o: Self) -> Self {
        match (self, o) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::False, Tri::False) => Tri::False,
            _ => Tri::Unknown,
        }
    }
    #[must_use] pub const fn not(self) -> Self {
        match self { Tri::True => Tri::False, Tri::False => Tri::True, Tri::Unknown => Tri::Unknown }
    }
    #[must_use] pub const fn from_bool(b: bool) -> Self { if b { Tri::True } else { Tri::False } }
}

/// Paired bitsets: known & value = True, known & !value = False, !known = Unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TriSet<const W: usize> { known: [u64; W], value: [u64; W] }

impl<const W: usize> TriSet<W> {
    pub const UNKNOWN: Self = Self { known: [0; W], value: [0; W] };
    #[must_use] pub fn get(&self, i: u16) -> Tri {
        let (w, b) = (usize::from(i.wrapping_shr(6)), u32::from(i & 0x3F));
        match (self.known.get(w), self.value.get(w)) {
            (Some(k), Some(v)) if (k.wrapping_shr(b) & 1) == 1 =>
                Tri::from_bool((v.wrapping_shr(b) & 1) == 1),
            _ => Tri::Unknown,
        }
    }
    pub fn set(&mut self, i: u16, t: Tri) {
        let (w, b) = (usize::from(i.wrapping_shr(6)), u32::from(i & 0x3F));
        let bit = 1u64.wrapping_shl(b);
        if let (Some(k), Some(v)) = (self.known.get_mut(w), self.value.get_mut(w)) {
            match t {
                Tri::True => { *k |= bit; *v |= bit; }
                Tri::False => { *k |= bit; *v &= !bit; }
                Tri::Unknown => { *k &= !bit; *v &= !bit; }
            }
        }
    }
}
```

```rust
// dag.rs + validate.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomRef { Learned(u16), Exact(u16), Rule(u16) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClauseKind { AllPositive, AnyPositive, AllNegated }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RulePolarity { Deny, Enable, Advisory }

pub struct Clause<'a> { pub kind: ClauseKind, pub atoms: &'a [AtomRef] }
pub struct Rule<'a> { pub clauses: &'a [Clause<'a>], pub polarity: RulePolarity }

/// Sealed on the validation split; invariant neg ≤ pos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThresholdPair { pub pos: FixedQ16_16, pub neg: FixedQ16_16 }

pub struct PredicateDag<'a> {
    pub thresholds: &'a [ThresholdPair],   // one per learned predicate
    pub exact_facts: u16,                  // size of the C(X) fact space
    pub rules: &'a [Rule<'a>],             // topological: Rule(r) atoms satisfy r < current index
    pub dag_digest: [u8; 32],
    pub threshold_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DagError {
    TooManyPredicates, TooManyRules, WorkBoundExceeded, ScoreLengthMismatch,
    ThresholdOrder { predicate: usize },
    ForwardRuleReference { rule: usize, target: u16 },
    PredicateOutOfRange { rule: usize, atom: u16 },
    LearnedTaintInEnableRule { rule: usize },
}

pub struct ValidatedDag<'a> { dag: &'a PredicateDag<'a>, work_bound: usize, learned_tainted: [u64; RULE_WORDS] }

impl<'a> PredicateDag<'a> {
    /// Single topological pass: bounds, threshold order, acyclicity by index, taint propagation.
    pub fn validate(&'a self) -> Result<ValidatedDag<'a>, DagError> {
        if self.thresholds.len() > MAX_PREDICATES || usize::from(self.exact_facts) > MAX_PREDICATES {
            return Err(DagError::TooManyPredicates);
        }
        if self.rules.len() > MAX_RULES { return Err(DagError::TooManyRules); }
        for (j, t) in self.thresholds.iter().enumerate() {
            if t.neg > t.pos { return Err(DagError::ThresholdOrder { predicate: j }); }
        }
        let mut work: usize = 0;
        let mut tainted = [0u64; RULE_WORDS];
        for (k, rule) in self.rules.iter().enumerate() {
            let mut rule_tainted = false;
            for clause in rule.clauses {
                work = work.checked_add(clause.atoms.len()).ok_or(DagError::WorkBoundExceeded)?;
                for atom in clause.atoms {
                    match *atom {
                        AtomRef::Learned(j) => {
                            if usize::from(j) >= self.thresholds.len() { return Err(DagError::PredicateOutOfRange { rule: k, atom: j }); }
                            rule_tainted = true;
                        }
                        AtomRef::Exact(j) => {
                            if j >= self.exact_facts { return Err(DagError::PredicateOutOfRange { rule: k, atom: j }); }
                        }
                        AtomRef::Rule(r) => {
                            if usize::from(r) >= k { return Err(DagError::ForwardRuleReference { rule: k, target: r }); }
                            rule_tainted |= bit_get(&tainted, r);
                        }
                    }
                }
            }
            if rule_tainted {
                if rule.polarity == RulePolarity::Enable { return Err(DagError::LearnedTaintInEnableRule { rule: k }); }
                bit_set(&mut tainted, k);
            }
        }
        if work > MAX_TOTAL_ATOMS { return Err(DagError::WorkBoundExceeded); }
        Ok(ValidatedDag { dag: self, work_bound: work, learned_tainted: tainted })
    }
}
```

```rust
// eval.rs + margin.rs + receipt.rs (signatures)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationMode {
    /// Copley parity: each rule's Unknown collapses to False in topological order.
    Boolean,
    /// Kernel mode: Unknown propagates; the envelope treats it conservatively.
    Kleene,
}

pub struct LearnedScores<'a> { pub z: &'a [FixedQ16_16] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DagOutcome { pub fired: [u64; RULE_WORDS], pub unknown: [u64; RULE_WORDS], pub work: usize }

#[must_use]
pub fn learned_atom(z: FixedQ16_16, t: ThresholdPair) -> Tri {
    if z >= t.pos { Tri::True } else if z < t.neg { Tri::False } else { Tri::Unknown }
}

pub fn evaluate(dag: &ValidatedDag<'_>, scores: &LearnedScores<'_>, exact: &TriSet<PRED_WORDS>, mode: EvaluationMode)
    -> Result<DagOutcome, DagError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleMargin { pub rule: u16, pub margin_raw: i32 }
pub const MAX_RECEIPT_MARGINS: usize = 8;

pub const DAG_RECEIPT_VERSION: u16 = 1;
pub const DAG_RECEIPT_WIRE_LEN: usize = 311;
pub struct DagReceipt {
    pub version: u16, pub mode: EvaluationMode,
    pub dag_digest: [u8; 32], pub threshold_digest: [u8; 32],
    pub scores_digest: [u8; 32], pub exact_digest: [u8; 32],
    pub fired: [u64; RULE_WORDS], pub unknown: [u64; RULE_WORDS],
    pub work: u32, pub top_margins: [RuleMargin; MAX_RECEIPT_MARGINS],
}
pub fn verify_receipt(dag: &ValidatedDag<'_>, scores: &LearnedScores<'_>, exact: &TriSet<PRED_WORDS>, receipt: &DagReceipt, h: &dyn WitnessHasher) -> bool;

// envelope.rs (feature `envelope`)
pub struct RuleEffectTable<'a> { pub deny_masks: &'a [FeasibilityMask], pub enable_masks: &'a [FeasibilityMask] }
pub fn feasibility_from_outcome(dag: &ValidatedDag<'_>, outcome: &DagOutcome, effects: &RuleEffectTable<'_>, base: FeasibilityMask, bot: ActionIndex) -> FeasibilityMap;
```

`evaluate` visits rules in index order. For each clause it folds atoms with `Tri::and` or `Tri::or`, applying `Tri::not` for `AllNegated`, then folds clauses with `Tri::and`. In `Boolean` mode a rule result of `Unknown` is stored as `False` before later rules read it. `feasibility_from_outcome` starts from `base`, intersects away `deny_masks[k]` for every `Deny` rule that is `True` or `Unknown`, unions `enable_masks[k]` for every `Enable` rule that is `True`, and finishes with `FeasibilityMap::from_mask_with_bot`. The `scores_digest` covers the sidecar's attestation header, so the receipt also binds the encoder model digest that produced the logits.

**Theorems for P3.**

*Theorem P3.1 (Termination and bounded work).* For a `ValidatedDag`, `evaluate` performs exactly `work_bound` atom evaluations plus at most `rules.len()` rule stores, with `work_bound ≤ MAX_TOTAL_ATOMS`. Proof. Validation rejects any `Rule(r)` atom with $r \ge k$, so every reference points to an already-stored result and the single forward pass needs no fixpoint. The atom count was summed with `checked_add` during validation and compared against the bound. $\square$

*Theorem P3.2 (Kleene information monotonicity).* Order $\mathrm{Unknown} \sqsubseteq \mathrm{True}$ and $\mathrm{Unknown} \sqsubseteq \mathrm{False}$, extended pointwise to inputs. In `Kleene` mode, if $(z, e) \sqsubseteq (z', e')$ componentwise on atom values, then every rule output under $(z,e)$ is $\sqsubseteq$ its output under $(z',e')$. Proof. `and`, `or`, `not` are monotone in $\sqsubseteq$ by inspection of the match tables: a decided output is produced only from inputs whose decided values force it, and refining an `Unknown` input never removes those forcing values. Compositions of monotone functions are monotone, and the rule DAG is a finite composition by P3.1. $\square$ Consequence: a `Deny` rule that fires under partial information still fires under any refinement, so a restriction imposed because a rule fired is never lifted by learning more. Refinement can only lift restrictions that were imposed because of `Unknown`, which is exactly the conservative half.

*Theorem P3.3 (Boolean-mode margin characterisation).* Define for a learned atom in positive role $m = z - \tau^{\text{pos}}$, in negated role $m = \tau^{\text{neg}} - z - 1$, computed in `i64` raw units, and for exact or rule atoms $m = 0$ if the atom is `True` and $m = -1$ otherwise. Let the clause margin be the min over `All*` atoms and the max over `Any` atoms, and the rule margin the min over clauses. Then in `Boolean` mode a rule fires iff its margin is $\ge 0$. Proof. For integers, $z \ge \tau \iff z - \tau \ge 0$ and $z < \tau \iff \tau - z \ge 1 \iff \tau - z - 1 \ge 0$. Conjunction holds iff every conjunct's margin is $\ge 0$ iff the min is, disjunction iff some margin is $\ge 0$ iff the max is. Rule-level collapse of `Unknown` to `False` is matched by assigning $-1$ to non-`True` referenced atoms. $\square$ `top_margins` therefore makes a receipt locally verifiable without recomputing the whole DAG, and `verify_receipt` performs the full replay.

*Theorem P3.4 (Learned predictions cannot widen feasibility).* Fix exact facts $e$ and base mask $\beta$. For all score vectors $z, z'$,
$$F(e, z) \subseteq \beta \cup \bigcup_{k \in \mathrm{Enable},\, R_k(e) = \mathrm{True}} \mathrm{enable}_k \cup \{\bot\} = F(e, z').$$
Proof. By induction on rule index, the `learned_tainted` bit of rule $k$ is set iff $R_k$ depends on some `Learned` atom directly or through a referenced rule. Validation rejects any `Enable` rule with that bit set, so every `Enable` rule's value is a function of $e$ alone. `Deny` rules only intersect, so changing $z$ can only remove actions from the right-hand set, never add to it. $\square$ This is the mechanised form of the Copley principle that exact computation decides what is possible and learned prediction only restricts within it.

*Lemma P3.5 (Mode agreement).* If no atom evaluates to `Unknown`, `Boolean` and `Kleene` modes produce identical `fired` sets. Proof. The only difference between modes is the collapse of `Unknown`, which never occurs. $\square$

**Feature flags.** `envelope` (default on), `copley-v1` (links the generated 537 by 236 static tables, off for the generic kernel build), `kani` via cfg.

**Test matrix.**

| Kind | Name | Checks |
|---|---|---|
| Unit | `tri_truth_tables`, `triset_set_get_all_1024` | connective tables, bitset codec |
| Unit | `validate_rejects_forward_ref_and_threshold_order` | validation errors |
| Unit | `validate_rejects_tainted_enable_rule_transitively` | P3.4 precondition |
| Golden | `copley_v1_parity_frozen_corpus` | `Boolean` mode reproduces Copley's evaluator rule-by-rule on the frozen validation split, so the published 93.96% F1 and 1.12% false-alarm figures are reproduced bit-exactly from exported logits |
| Property | `prop_kleene_monotone_random_dags` | P3.2 on random small DAGs with random refinements |
| Property | `prop_margin_iff_fires` | P3.3 |
| Property | `prop_learned_cannot_widen` | P3.4 with random $z, z'$ |
| Kani | `verify_kleene_and_monotone_info`, `verify_kleene_or_monotone_info`, `verify_kleene_not_monotone_info` | P3.2 base cases, fully symbolic |
| Kani | `verify_learned_atom_consistent_with_thresholds` | atom is `True` iff $z \ge \tau^{\text{pos}}$, `False` iff $z < \tau^{\text{neg}}$ |
| Kani | `verify_rule_margin_iff_fires_small_rule` | P3.3 on a two-clause symbolic rule |
| Kani | `verify_validate_rejects_forward_rule_ref` | P3.1 precondition |
| Kani | `verify_eval_work_le_validated_bound` | P3.1 |
| Kani | `verify_feasibility_from_outcome_contains_bot` | composes with P1.1 |
| Kani | `verify_receipt_roundtrip_injective` | fixed-width codec |
| Loom | `loom_threshold_set_hot_reload_atomic` | thresholds and `dag_digest` swap together; a decision never mixes old thresholds with a new digest |
| DST | `dst_drop_simulation` extension | a dropped future between `evaluate` and receipt commit leaves no receipt claiming a fired rule |
| Aeneas/Lean | `kleene_and_bits`, `rule_margin_fires` into `Predicate/Kleene.lean`, `Predicate/Margin.lean` | `kleene_and_monotone`, `eval_monotone_info`, `fires_iff_margin_nonneg`, `learned_no_widen` |
| Apalache | `PredicateReceiptBinding.tla` | `ReceiptBindsThresholdDigest`; negative mutant `ThresholdSwapWithoutDigest.tla` must trace |

**Acceptance criteria.** Parity golden test green with the exported Copley corpus checked in under a digest. All Kani and Loom harnesses green. Static tables for `copley-v1` fit the bound table below and live in read-only data with no stack copies. `MAPPING.md` rows for P3.1 to P3.4. The kernel envelope for tool-call evaluation uses `Kleene` mode, and the documented semantic delta from Copley's boolean evaluator is exactly Lemma P3.5's complement: the abstention band and unknown exact facts produce conservative restriction instead of silent non-firing.

| Quantity | Copley v1 | Bound |
|---|---|---|
| learned predicates | 537 | 1,024 |
| rules | 236 | 512 |
| total atoms | measured at export | 16,384 |
| receipt wire bytes | 311 | 311 |

**Risk register P3.**

| ID | Risk | L/I | Mitigation |
|---|---|---|---|
| P3-R1 | Kleene semantics diverge from the F1-validated boolean evaluator | H/M | `Boolean` mode parity gate; Lemma P3.5; kernel uses `Kleene` only through the envelope adapter |
| P3-R2 | Threshold tampering changes firing | L/H | `threshold_digest` in receipt; thresholds shipped in a signed bundle verified by `chio-kernel` before `validate` |
| P3-R3 | Poisoned sidecar logits deny legitimate actions | M/M | P3.4 limits damage to availability; `chio-autonomy` drift on fired-rate spike; `OverrideRate` drift kind reused |
| P3-R4 | An exported rule set references a rule out of order | M/L | `validate` rejects with `ForwardRuleReference`; export tool sorts topologically and asserts |
| P3-R5 | Static tables grow past `MAX_TOTAL_ATOMS` | L/M | export tool fails the build; bound is validated again at load |
| P3-R6 | Exact fact space index collides with learned index space | M/M | separate `AtomRef::Exact` and `exact_facts` bound; no shared index space |

The three slices together give the kernel a decision path whose safety rests on `FeasibilityMap` alone. P1 proves every chosen action is feasible and every feasibility set contains the conservative default. P2 adds a learned, priced policy that reorders only within that set, with bit-exact portability and a compile-time WCET gate. P3 turns Copley's predicate composer into a bounded three-valued evaluator whose learned inputs can only restrict, and whose receipts replay to a bit. The recommended start is P1 and `chio-fixed` in the same sprint, then `chio-micro-model` and `chio-predicate-dag` in parallel, with the kernel integration and Loom/DST work last.

---

## w2_angle_2_lean_aeneas_kani_apalache_proofs

I'll lay out the Wave 2 proof program as four artifact families over one shared scalar seam, with the actual Lean, Kani, Loom, and TLA+ text, then the effort table and the honest out-of-reach list.

**The shared seam under proof.** Every artifact below talks about the same five pure functions, placed in `chio_kernel_core::formal_aeneas::envelope` and mirrored byte for byte into `formal/aeneas/verified_core.rs`. The mirror is what `cargo xtask check formal-mirrors` already polices. The state is the scalar projection of kernel-core state that Φ constrains. The action is the shielded decision alphabet. The policy π_θ never appears in the seam, because the seam receives the policy's output as a plain value. That is the whole trick: Φ is proved for every value the policy can emit, so the network is irrelevant to safety.

```rust
//! chio-kernel-core/src/formal_aeneas/envelope.rs
//! Pure scalar envelope seam. No traits, no closures, no slices, no `?`.
//! Mirrored verbatim into formal/aeneas/verified_core.rs for Aeneas extraction.
#![no_std]
#![forbid(unsafe_code)]

pub const KIND_HOLD: u8 = 0; // ⊥_s: emits a Deny receipt, mutates nothing
pub const KIND_RESERVE: u8 = 1; // remaining  -> reserved
pub const KIND_COMMIT: u8 = 2; // reserved   -> committed, invocation_count + 1
pub const KIND_RELEASE: u8 = 3; // reserved   -> remaining (always conservative)
pub const KIND_EGRESS: u8 = 4; // flow-fenced egress, no ledger effect
pub const WINDOW_VALID: u8 = 0; // classify_time_window_code output

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EnvelopeState {
    pub cap_units: u64,
    pub remaining_units: u64,
    pub reserved_units: u64,
    pub committed_units: u64,
    pub invocation_count: u32,
    pub max_invocations: u32,
    pub flow_level: u8,
    pub sink_ceiling: u8,
    pub window_code: u8,
    pub revoked: bool,
    pub stopped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct EnvelopeAction {
    pub kind: u8,
    pub units: u64,
}

/// Φ(s): ledger conservation and the invocation ceiling.
pub fn envelope_phi(s: &EnvelopeState) -> bool {
    let conserved = match s.remaining_units.checked_add(s.reserved_units) {
        Some(partial) => match partial.checked_add(s.committed_units) {
            Some(total) => total == s.cap_units,
            None => false,
        },
        None => false,
    };
    conserved && s.invocation_count <= s.max_invocations
}

/// ⊥_s. Independent of s by construction; the parameter is kept so the
/// Lean statement `bot_feasible` quantifies over s uniformly.
pub fn envelope_bot(_s: &EnvelopeState) -> EnvelopeAction {
    EnvelopeAction { kind: KIND_HOLD, units: 0 }
}

/// F(s) as a decidable membership test.
pub fn envelope_feasible(s: &EnvelopeState, a: &EnvelopeAction) -> bool {
    let live = !s.revoked && !s.stopped && s.window_code == WINDOW_VALID;
    match a.kind {
        KIND_HOLD => true,
        KIND_RESERVE => live && a.units > 0 && a.units <= s.remaining_units,
        KIND_COMMIT => {
            live && a.units <= s.reserved_units && s.invocation_count < s.max_invocations
        }
        KIND_RELEASE => a.units <= s.reserved_units,
        KIND_EGRESS => live && s.flow_level <= s.sink_ceiling,
        _ => false,
    }
}

/// Π_s: the O(1) shielded projection. Loop-free; one feasibility test.
pub fn envelope_project(s: &EnvelopeState, raw: &EnvelopeAction) -> EnvelopeAction {
    if envelope_feasible(s, raw) {
        *raw
    } else {
        envelope_bot(s)
    }
}

fn move_units(from: u64, to: u64, units: u64) -> Option<(u64, u64)> {
    match (from.checked_sub(units), to.checked_add(units)) {
        (Some(f), Some(t)) => Some((f, t)),
        _ => None,
    }
}

/// Transition. `None` means an arithmetic guard fired; the theorems show
/// this branch is unreachable from Φ(s) ∧ a ∈ F(s).
pub fn envelope_step(s: &EnvelopeState, a: &EnvelopeAction) -> Option<EnvelopeState> {
    let mut n = *s;
    match a.kind {
        KIND_HOLD | KIND_EGRESS => Some(n),
        KIND_RESERVE => match move_units(s.remaining_units, s.reserved_units, a.units) {
            Some((r, v)) => {
                n.remaining_units = r;
                n.reserved_units = v;
                Some(n)
            }
            None => None,
        },
        KIND_COMMIT => match move_units(s.reserved_units, s.committed_units, a.units) {
            Some((v, c)) => match s.invocation_count.checked_add(1) {
                Some(i) => {
                    n.reserved_units = v;
                    n.committed_units = c;
                    n.invocation_count = i;
                    Some(n)
                }
                None => None,
            },
            None => None,
        },
        KIND_RELEASE => match move_units(s.reserved_units, s.remaining_units, a.units) {
            Some((v, r)) => {
                n.reserved_units = v;
                n.remaining_units = r;
                Some(n)
            }
            None => None,
        },
        _ => None,
    }
}

/// One closed-loop tick: s' = step(s, Π_s(raw)), raw = π_θ(s, λ) computed elsewhere.
pub fn envelope_closed_loop_step(s: &EnvelopeState, raw: &EnvelopeAction) -> Option<EnvelopeState> {
    let a = envelope_project(s, raw);
    envelope_step(s, &a)
}
```

The hot-path micro-model lives beside the seam but outside it. Aeneas does not translate const generics, iterators, or closures, so the micro-model is covered by Kani for panic freedom and by the shield theorem for everything else.

```rust
//! chio-kernel-core/src/micro_model.rs  (no_std, forbid unsafe, no indexing)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Q16_16(i32);

pub const Q_FRAC_BITS: u32 = 16;

impl Q16_16 {
    pub const ZERO: Q16_16 = Q16_16(0);
    pub const ONE: Q16_16 = Q16_16(1 << Q_FRAC_BITS);
    pub const fn from_raw(raw: i32) -> Self { Q16_16(raw) }
    pub const fn raw(self) -> i32 { self.0 }

    /// Saturating Q16.16 multiply. The i64 product of two i32 values never
    /// overflows, so both `unwrap_or` arms below are dead code; Lean proves it.
    pub fn sat_mul(self, o: Q16_16) -> Q16_16 {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0)).unwrap_or(i64::MAX);
        let shifted = wide.checked_shr(Q_FRAC_BITS).unwrap_or(0);
        let clamp = if shifted < 0 { i32::MIN } else { i32::MAX };
        Q16_16(i32::try_from(shifted).unwrap_or(clamp))
    }
    pub fn sat_add(self, o: Q16_16) -> Q16_16 { Q16_16(self.0.saturating_add(o.0)) }
    pub fn sat_sub(self, o: Q16_16) -> Q16_16 { Q16_16(self.0.saturating_sub(o.0)) }
}

/// Tier-2 hot-path scorer: score_a = b_a + Σ_f w_{a,f} x_f − Σ_r λ_r u_{a,r}.
pub struct MicroModel<const F: usize, const A: usize, const R: usize> {
    pub w: [[Q16_16; F]; A],
    pub b: [Q16_16; A],
    pub resource_use: [[Q16_16; R]; A],
}

impl<const F: usize, const A: usize, const R: usize> MicroModel<F, A, R> {
    pub fn score(&self, x: &[Q16_16; F], lambda: &[Q16_16; R]) -> [Q16_16; A] {
        let mut out = [Q16_16::ZERO; A];
        let rows = self.w.iter().zip(self.resource_use.iter()).zip(self.b.iter());
        for (o, ((wrow, urow), bias)) in out.iter_mut().zip(rows) {
            let mut acc = *bias;
            for (w, xv) in wrow.iter().zip(x.iter()) {
                acc = acc.sat_add(w.sat_mul(*xv));
            }
            for (u, l) in urow.iter().zip(lambda.iter()) {
                acc = acc.sat_sub(l.sat_mul(*u));
            }
            *o = acc;
        }
        out
    }

    pub fn argmax(scores: &[Q16_16; A]) -> usize {
        let (best, _) = scores.iter().enumerate().fold((0usize, Q16_16(i32::MIN)), |(bi, bv), (i, v)| {
            if *v > bv { (i, *v) } else { (bi, bv) }
        });
        best
    }
}

/// Type-level separation: only `shield` can mint an `AdmittedAction`, and
/// dispatch accepts nothing else. A compile-fail doctest pins this, exactly
/// as `CandidatePlanV1` is kept away from `SignedRecoveryGrant` in chio-recovery.
pub struct AdmittedAction(EnvelopeAction);
impl AdmittedAction {
    pub fn shield(s: &EnvelopeState, raw: EnvelopeAction) -> AdmittedAction {
        AdmittedAction(envelope_project(s, &raw))
    }
    pub fn action(&self) -> &EnvelopeAction { &self.0 }
}
```

## 1. Lean 4 obligations via Aeneas extraction

Aeneas emits `Chio/Aeneas/VerifiedCore/Funs.lean` in namespace `verified_core`, with every function returning `Result`. The hand-written proofs go in `Chio/Proofs/EnvelopeShield.lean`. Lemma names for scalar primitives follow the Aeneas `Std` library at the commit pinned in `formal/aeneas/AENEAS_COMMIT`, and `scalar_tac` discharges the bounded-arithmetic side conditions.

```lean
import Chio.Aeneas.VerifiedCore.Funs
open Aeneas Aeneas.Std Result verified_core

namespace Chio.Envelope

/-- Φ as a mathematical predicate on the scalar values, independent of the
    checked-arithmetic encoding used in Rust. -/
def PhiSpec (s : EnvelopeState) : Prop :=
  s.remaining_units.val + s.reserved_units.val + s.committed_units.val = s.cap_units.val ∧
  s.invocation_count.val ≤ s.max_invocations.val

/-- F(s) as a mathematical predicate. -/
def FeasibleSpec (s : EnvelopeState) (a : EnvelopeAction) : Prop :=
  let live := s.revoked = false ∧ s.stopped = false ∧ s.window_code.val = 0
  (a.kind.val = 0) ∨
  (a.kind.val = 1 ∧ live ∧ 0 < a.units.val ∧ a.units.val ≤ s.remaining_units.val) ∨
  (a.kind.val = 2 ∧ live ∧ a.units.val ≤ s.reserved_units.val ∧
      s.invocation_count.val < s.max_invocations.val) ∨
  (a.kind.val = 3 ∧ a.units.val ≤ s.reserved_units.val) ∨
  (a.kind.val = 4 ∧ live ∧ s.flow_level.val ≤ s.sink_ceiling.val)

/-- O1. The Rust Φ test is total and decides PhiSpec. The overflow arm of
    `checked_add` cannot lie: an overflowing sum exceeds U64.max ≥ cap. -/
theorem envelope_phi_spec (s : EnvelopeState) :
    envelope_phi s = ok (decide (PhiSpec s)) := by
  unfold envelope_phi PhiSpec
  rcases h₁ : core.num.U64.checked_add s.remaining_units s.reserved_units with _ | p
  · simp [U64.checked_add_eq_none_iff] at h₁; simp; scalar_tac
  · rcases h₂ : core.num.U64.checked_add p s.committed_units with _ | t
    · simp [U64.checked_add_eq_none_iff, U64.checked_add_eq_some_iff] at *; simp; scalar_tac
    · simp [U64.checked_add_eq_some_iff] at *; simp; scalar_tac

/-- O2. The feasibility test is total and decides FeasibleSpec. -/
theorem envelope_feasible_spec (s : EnvelopeState) (a : EnvelopeAction) :
    envelope_feasible s a = ok (decide (FeasibleSpec s a)) := by
  unfold envelope_feasible FeasibleSpec
  split <;> simp_all <;> scalar_tac

/-- O3. ⊥_s ∈ F(s) for every s, including revoked, stopped and expired states. -/
theorem bot_feasible (s : EnvelopeState) :
    ∃ b, envelope_bot s = ok b ∧ envelope_feasible s b = ok true := by
  refine ⟨⟨0#u8, 0#u64⟩, rfl, ?_⟩
  rw [envelope_feasible_spec]; simp [FeasibleSpec]

/-- O4. Π_s always lands in F(s). This is the shield soundness theorem. -/
theorem project_feasible (s : EnvelopeState) (raw : EnvelopeAction) :
    ∃ a, envelope_project s raw = ok a ∧ envelope_feasible s a = ok true := by
  unfold envelope_project
  rw [envelope_feasible_spec]
  by_cases h : FeasibleSpec s raw
  · exact ⟨raw, by simp [h], by rw [envelope_feasible_spec]; simp [h]⟩
  · obtain ⟨b, hb, hfb⟩ := bot_feasible s
    exact ⟨b, by simp [h, hb], hfb⟩

/-- O5. Π_s is the identity on F(s): the shield is never over-conservative. -/
theorem project_id_on_feasible (s : EnvelopeState) (a : EnvelopeAction)
    (h : FeasibleSpec s a) : envelope_project s a = ok a := by
  unfold envelope_project; rw [envelope_feasible_spec]; simp [h]

/-- O6. Idempotence: shielding twice equals shielding once. -/
theorem project_idempotent (s : EnvelopeState) (raw : EnvelopeAction) :
    ∃ a, envelope_project s raw = ok a ∧ envelope_project s a = ok a := by
  obtain ⟨a, ha, hf⟩ := project_feasible s raw
  rw [envelope_feasible_spec] at hf
  exact ⟨a, ha, project_id_on_feasible s a (by simpa using hf)⟩

/-- O7. Every feasible action preserves Φ and never trips a checked-arithmetic
    guard. The `None` arms of `envelope_step` are provably dead. -/
theorem step_preserves_phi (s : EnvelopeState) (a : EnvelopeAction)
    (hΦ : PhiSpec s) (hF : FeasibleSpec s a) :
    ∃ s', envelope_step s a = ok (some s') ∧ PhiSpec s' := by
  unfold envelope_step move_units
  rcases hF with h | h | h | h | h
  · -- KIND_HOLD
    refine ⟨s, ?_, hΦ⟩; simp [h]
  · -- KIND_RESERVE: units ≤ remaining, reserved + units ≤ cap ≤ U64.max
    obtain ⟨hk, hlive, hpos, hle⟩ := h
    progress as ⟨r, hr⟩; progress as ⟨v, hv⟩
    refine ⟨_, by simp [hk], ?_⟩
    unfold PhiSpec at *; simp; scalar_tac
  · -- KIND_COMMIT: reserved - units, committed + units, invocation_count + 1
    obtain ⟨hk, hlive, hle, hinv⟩ := h
    progress as ⟨v, hv⟩; progress as ⟨c, hc⟩; progress as ⟨i, hi⟩
    refine ⟨_, by simp [hk], ?_⟩
    unfold PhiSpec at *; simp; scalar_tac
  · -- KIND_RELEASE
    obtain ⟨hk, hle⟩ := h
    progress as ⟨v, hv⟩; progress as ⟨r, hr⟩
    refine ⟨_, by simp [hk], ?_⟩
    unfold PhiSpec at *; simp; scalar_tac
  · -- KIND_EGRESS
    obtain ⟨hk, -⟩ := h
    refine ⟨s, ?_, hΦ⟩; simp [hk]

/-- O8. Main theorem. For an arbitrary policy π, including non-computable ones,
    one shielded tick preserves Φ and is total. -/
theorem closed_loop_preserves_phi (π : EnvelopeState → EnvelopeAction)
    (s : EnvelopeState) (hΦ : PhiSpec s) :
    ∃ s', envelope_closed_loop_step s (π s) = ok (some s') ∧ PhiSpec s' := by
  unfold envelope_closed_loop_step
  obtain ⟨a, ha, hf⟩ := project_feasible s (π s)
  rw [envelope_feasible_spec] at hf
  obtain ⟨s', hs, hΦ'⟩ := step_preserves_phi s a hΦ (by simpa using hf)
  exact ⟨s', by simp [ha, hs], hΦ'⟩

/-- Trace semantics. The policy may read the whole history; the shield reads
    only the current state, so the theorem is unchanged. -/
def run (π : List EnvelopeState → EnvelopeAction) :
    Nat → List EnvelopeState → EnvelopeState → Result (Option EnvelopeState)
  | 0, _, s => ok (some s)
  | n + 1, hist, s => do
      let r ← envelope_closed_loop_step s (π (s :: hist))
      match r with
      | some s' => run π n (s :: hist) s'
      | none => ok none

/-- O9. Φ is an inductive invariant of every shielded trace, of any length,
    under any history-dependent policy. -/
theorem run_preserves_phi (π : List EnvelopeState → EnvelopeAction) :
    ∀ (n : Nat) (hist : List EnvelopeState) (s : EnvelopeState), PhiSpec s →
      ∃ s', run π n hist s = ok (some s') ∧ PhiSpec s' := by
  intro n
  induction n with
  | zero => intro hist s h; exact ⟨s, rfl, h⟩
  | succ n ih =>
    intro hist s h
    obtain ⟨s₁, h₁, hΦ₁⟩ := closed_loop_preserves_phi (fun t => π (t :: hist)) s h
    obtain ⟨s', h', hΦ'⟩ := ih (s :: hist) s₁ hΦ₁
    exact ⟨s', by simp [run, h₁, h'], hΦ'⟩

/-- O10. Shadow-price independence. λ is not an argument of Π_s or step, so
    any λ-indexed family of policies is covered by O8. Stated explicitly
    because the Loom models in §3 depend on it. -/
theorem closed_loop_preserves_phi_any_lambda {Λ : Type}
    (π : Λ → EnvelopeState → EnvelopeAction) (λ : Λ) (s : EnvelopeState) (hΦ : PhiSpec s) :
    ∃ s', envelope_closed_loop_step s (π λ s) = ok (some s') ∧ PhiSpec s' :=
  closed_loop_preserves_phi (π λ) s hΦ

/-- O11. Q16.16 multiply: the saturation fallbacks in `sat_mul` are dead,
    and the result is the floor-shifted exact product clamped to i32. -/
def clampI32 (z : Int) : Int := max (-(2 ^ 31)) (min (2 ^ 31 - 1) z)

theorem q16_sat_mul_spec (a b : Q16_16) :
    ∃ r, Q16_16.sat_mul a b = ok r ∧
      r._0.val = clampI32 (Int.fdiv (a._0.val * b._0.val) (2 ^ 16)) := by
  unfold Q16_16.sat_mul
  -- |a·b| ≤ 2^62 < 2^63, so checked_mul is `some`; 16 < 64, so checked_shr is `some`.
  have hmul : a._0.val * b._0.val ≤ 2 ^ 62 := by scalar_tac
  have hmul' : -(2 ^ 62) ≤ a._0.val * b._0.val := by scalar_tac
  progress as ⟨wide, hwide⟩ <;> try scalar_tac
  progress as ⟨shifted, hsh⟩
  split <;> simp_all [clampI32, Int.fdiv] <;> scalar_tac

end Chio.Envelope
```

Two things the Lean layer deliberately does not claim. First, it says nothing about which action the policy picks, so optimality, regret and the Lagrangian pricing are outside Lean. Second, O(1) is proved only structurally: `envelope_project` contains no recursion and the Aeneas translation has no `div` outcome, which Lean records as totality. Timing is not a Lean statement.

`formal/MAPPING.md` gains one row per obligation O1 through O11, each pointing at the Rust symbol, the Lean theorem, and the Kani harness that bounds-checks the same statement, so `scripts/check-mapping.sh` fails if any of the three drifts.

## 2. Kani harnesses with `kani::any()` as the universally quantified policy

The harnesses live in `kani_public_harnesses.rs` under `#[cfg(kani)]`. The policy output is `kani::any()`, which is exactly the bounded-model-checking reading of "for all π_θ": the solver chooses the worst action of every reachable shape, including ones no trained network would produce. These harnesses do not call the network, so a compromised weight file changes nothing about the verdict.

```rust
#[cfg(kani)]
mod envelope_harnesses {
    use crate::formal_aeneas::envelope::*;
    use crate::formal_core::budget_precheck;
    use crate::micro_model::{MicroModel, Q16_16};

    const F: usize = 8; // features
    const A: usize = 5; // one score per action kind
    const R: usize = 3; // priced resources

    fn any_phi_state() -> EnvelopeState {
        let s: EnvelopeState = kani::any();
        kani::assume(envelope_phi(&s));
        s
    }

    /// Φ(s) ∧ raw arbitrary ⟹ step(s, Π_s(raw)) defined ∧ Φ(s').  Mirrors Lean O4 + O7 + O8.
    #[kani::proof]
    #[kani::unwind(1)]
    fn verify_shield_closes_envelope_for_any_policy_output() {
        let s = any_phi_state();
        let raw: EnvelopeAction = kani::any(); // π_θ(s, λ), fully unconstrained
        let a = envelope_project(&s, &raw);
        kani::assert(envelope_feasible(&s, &a), "projected action is in F(s)");
        match envelope_step(&s, &a) {
            Some(next) => kani::assert(envelope_phi(&next), "Phi preserved"),
            None => kani::assert(false, "step is total on F(s)"),
        }
    }

    /// ⊥_s ∈ F(s) for every s, including revoked / stopped / expired.  Lean O3.
    #[kani::proof]
    fn verify_bot_always_feasible() {
        let s: EnvelopeState = kani::any();
        kani::assert(envelope_feasible(&s, &envelope_bot(&s)), "bottom always feasible");
    }

    /// Shield is identity on F(s) and idempotent.  Lean O5 + O6.
    #[kani::proof]
    fn verify_project_identity_and_idempotent() {
        let s: EnvelopeState = kani::any();
        let raw: EnvelopeAction = kani::any();
        let once = envelope_project(&s, &raw);
        if envelope_feasible(&s, &raw) {
            kani::assert(once == raw, "feasible actions pass through unchanged");
        }
        kani::assert(envelope_project(&s, &once) == once, "idempotent");
    }

    /// Four shielded ticks with four independent arbitrary actions.  Lean O9 at n = 4.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_four_step_trace_preserves_phi() {
        let mut s = any_phi_state();
        for _ in 0..4 {
            let raw: EnvelopeAction = kani::any();
            match envelope_closed_loop_step(&s, &raw) {
                Some(next) => {
                    kani::assert(envelope_phi(&next), "Phi holds along trace");
                    s = next;
                }
                None => kani::assert(false, "closed loop total"),
            }
        }
    }

    /// Tier-2 scorer never panics and never indexes out of range, for arbitrary
    /// weights, inputs and shadow prices.  Loop bounds: F inner, R inner, A outer.
    #[kani::proof]
    #[kani::unwind(9)]
    fn verify_micro_model_forward_panic_free() {
        let model = MicroModel::<F, A, R> {
            w: kani::any(),
            b: kani::any(),
            resource_use: kani::any(),
        };
        let x: [Q16_16; F] = kani::any();
        let lambda: [Q16_16; R] = kani::any();
        let scores = model.score(&x, &lambda);
        let idx = MicroModel::<F, A, R>::argmax(&scores);
        kani::assert(idx < A, "argmax index in range");
    }

    /// The real decoder feeding the shield, under arbitrary λ: the control plane
    /// cannot widen F(s) by pricing.  Lean O10.
    #[kani::proof]
    #[kani::unwind(9)]
    fn verify_shadow_prices_cannot_breach_envelope() {
        let s = any_phi_state();
        let model = MicroModel::<F, A, R> { w: kani::any(), b: kani::any(), resource_use: kani::any() };
        let x: [Q16_16; F] = kani::any();
        let lambda: [Q16_16; R] = kani::any();
        let idx = MicroModel::<F, A, R>::argmax(&model.score(&x, &lambda));
        let kind = u8::try_from(idx).unwrap_or(KIND_HOLD);
        let raw = EnvelopeAction { kind, units: kani::any() };
        let a = envelope_project(&s, &raw);
        kani::assert(envelope_feasible(&s, &a), "shielded regardless of lambda");
    }

    /// Dead-saturation and exactness for Q16.16 multiply.  Lean O11.
    #[kani::proof]
    fn verify_q16_sat_mul_matches_i64_reference() {
        let a: Q16_16 = kani::any();
        let b: Q16_16 = kani::any();
        let wide = i64::from(a.raw()).checked_mul(i64::from(b.raw()));
        kani::assert(wide.is_some(), "i32 x i32 fits in i64");
        let reference = wide.unwrap_or(0) >> 16;
        let r = i64::from(a.sat_mul(b).raw());
        let clamped = reference.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
        kani::assert(r == clamped, "sat_mul equals clamped floor-shifted product");
    }

    /// Receipt witness: `check` accepts iff the recorded projection is what Π_s computes.
    #[kani::proof]
    fn verify_shield_witness_check_sound_and_complete() {
        let s: EnvelopeState = kani::any();
        let raw: EnvelopeAction = kani::any();
        let claimed: EnvelopeAction = kani::any();
        let w = ShieldWitness { raw, projected: claimed, was_projected: raw != claimed, lambda_epoch: kani::any() };
        let ok = w.check(&s);
        kani::assert(ok == (claimed == envelope_project(&s, &raw)), "witness check is exact");
    }

    /// Cross-seam agreement with the already-verified budget_precheck.
    #[kani::proof]
    fn verify_reserve_feasibility_agrees_with_formal_core_budget_precheck() {
        let s = any_phi_state();
        kani::assume(!s.revoked && !s.stopped && s.window_code == WINDOW_VALID);
        let units: u64 = kani::any();
        kani::assume(units > 0);
        let a = EnvelopeAction { kind: KIND_RESERVE, units };
        // budget_precheck(remaining_invocations, remaining_units, invocation_cost, unit_cost)
        let legacy = budget_precheck(1, s.remaining_units, 0, units);
        kani::assert(envelope_feasible(&s, &a) == legacy, "envelope and formal_core agree");
    }
}
```

The witness type referenced above is the receipt-side artifact. It records the raw action, the projected action, whether projection fired, and the λ epoch the hot path read. `check` recomputes `envelope_project` and compares. Because the witness is deterministic and the state is already in the receipt body, an auditor can re-derive every shield decision from the receipt alone.

Registry entries in `.kani/harnesses.toml` follow the existing shape:

```toml
[[harness]]
name = "verify_shield_closes_envelope_for_any_policy_output"
crate = "chio-kernel-core"
unwind = 1
solver = "cadical"
timeout_secs = 120
properties = ["Envelope.Phi.Preservation", "Envelope.Shield.Soundness"]
lean = "Chio.Envelope.closed_loop_preserves_phi"
mapping = "formal/MAPPING.md#envelope-o8"

[[harness]]
name = "verify_micro_model_forward_panic_free"
crate = "chio-kernel-core"
unwind = 9
solver = "cadical"
timeout_secs = 600
properties = ["MicroModel.PanicFree", "MicroModel.ArgmaxInRange"]
mapping = "formal/MAPPING.md#micro-model-bmc"
```

The `#[kani::unwind(1)]` on the main harness doubles as a structural O(1) certificate. If anyone introduces a loop into the projection path, the unwinding assertion fails. That is a loop-freedom check, not a WCET bound.

## 3. Loom models for the control-plane / hot-path shared state

Two cells are shared across the tier boundary. The control plane publishes the shadow-price vector λ every few milliseconds. It also owns the emergency-stop flag, which must act as a cut on Allow receipts, in the same sense as `KernelTransitionCancelSafe`. The hot path reads both without blocking. The model weights are large and infrequently updated, so they stay behind the existing `arc_swap` path already covered by `loom_emergency_stop_arcswap`. The λ vector is small and updated at millisecond cadence, so it gets a lock-free seqlock with no allocation on publish.

```rust
//! chio-kernel/src/envelope/lambda_cell.rs
#[cfg(loom)]
use loom::sync::atomic::{fence, AtomicBool, AtomicI32, AtomicU64, Ordering};
#[cfg(not(loom))]
use core::sync::atomic::{fence, AtomicBool, AtomicI32, AtomicU64, Ordering};
use chio_kernel_core::micro_model::Q16_16;

/// Single-writer seqlock. Even `seq` = stable snapshot; odd = write in progress.
pub struct LambdaCell<const R: usize> {
    seq: AtomicU64,
    epoch: AtomicU64,
    slots: [AtomicI32; R],
}

impl<const R: usize> LambdaCell<R> {
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            epoch: AtomicU64::new(0),
            slots: core::array::from_fn(|_| AtomicI32::new(0)),
        }
    }

    /// Control plane only. Callers hold the single-writer token by construction.
    pub fn publish(&self, lambda: &[Q16_16; R], epoch: u64) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        for (slot, l) in self.slots.iter().zip(lambda.iter()) {
            slot.store(l.raw(), Ordering::Relaxed);
        }
        self.epoch.store(epoch, Ordering::Relaxed);
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    /// Hot path. Returns a consistent (λ, epoch) pair from one publish.
    pub fn read(&self) -> ([Q16_16; R], u64) {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                core::hint::spin_loop();
                continue;
            }
            let mut out = [Q16_16::ZERO; R];
            for (o, slot) in out.iter_mut().zip(self.slots.iter()) {
                *o = Q16_16::from_raw(slot.load(Ordering::Relaxed));
            }
            let epoch = self.epoch.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return (out, epoch);
            }
        }
    }
}

/// Emergency stop as a linearizable cut over receipt tickets (Dekker pattern, SeqCst).
pub struct StopCut {
    stop: AtomicBool,
    next_ticket: AtomicU64,
}

impl StopCut {
    pub fn take_ticket_unless_stopped(&self) -> Result<u64, u64> {
        let t = self.next_ticket.fetch_add(1, Ordering::SeqCst);
        if self.stop.load(Ordering::SeqCst) { Err(t) } else { Ok(t) }
    }
    /// Returns the cut: every Allow ticket issued is strictly below it.
    pub fn stop(&self) -> u64 {
        self.stop.store(true, Ordering::SeqCst);
        self.next_ticket.load(Ordering::SeqCst)
    }
}
```

Loom harnesses in `tests/loom_concurrency.rs`, registered in `.loom/harnesses.toml` with `preemption_bound = 3`:

```rust
#![cfg(loom)]
#![allow(clippy::unwrap_used, reason = "loom harness; panics are the oracle")]
use loom::{sync::Arc, thread};

/// H1. No torn read: both components and the epoch come from the same publish.
#[test]
fn loom_lambda_cell_no_torn_read() {
    loom::model(|| {
        let cell = Arc::new(LambdaCell::<2>::new());
        let w = { let c = cell.clone(); thread::spawn(move || {
            c.publish(&[Q16_16::from_raw(1), Q16_16::from_raw(1)], 1);
            c.publish(&[Q16_16::from_raw(2), Q16_16::from_raw(2)], 2);
        }) };
        let r = { let c = cell.clone(); thread::spawn(move || {
            let (l, epoch) = c.read();
            assert_eq!(l[0], l[1], "payload torn across publishes");
            assert_eq!(i64::from(l[0].raw()), i64::from(epoch).min(2), "epoch disagrees with payload");
        }) };
        w.join().unwrap(); r.join().unwrap();
    });
}

/// H2. Reader epochs are monotone across two reads on the hot path.
#[test]
fn loom_lambda_cell_reader_epoch_monotone() {
    loom::model(|| {
        let cell = Arc::new(LambdaCell::<1>::new());
        let w = { let c = cell.clone(); thread::spawn(move || {
            c.publish(&[Q16_16::ONE], 1); c.publish(&[Q16_16::ONE], 2);
        }) };
        let r = { let c = cell.clone(); thread::spawn(move || {
            let (_, e1) = c.read(); let (_, e2) = c.read();
            assert!(e1 <= e2);
        }) };
        w.join().unwrap(); r.join().unwrap();
    });
}

/// H3. Shield independence under interleaving: whichever λ the hot path sees,
/// stale or fresh, the admitted action is feasible and Φ holds. Catches any
/// future regression where feasibility starts reading the shared cell.
#[test]
fn loom_shield_ignores_lambda_staleness() {
    loom::model(|| {
        let cell = Arc::new(LambdaCell::<3>::new());
        let w = { let c = cell.clone(); thread::spawn(move || c.publish(&[Q16_16::ONE; 3], 7)) };
        let h = { let c = cell.clone(); thread::spawn(move || {
            let s = fixture_state_with_phi();
            let (lambda, epoch) = c.read();
            let raw = fixture_micro_model().decide(&s, &lambda);
            let admitted = AdmittedAction::shield(&s, raw);
            assert!(envelope_feasible(&s, admitted.action()));
            let next = envelope_step(&s, admitted.action()).unwrap();
            assert!(envelope_phi(&next));
            assert!(epoch == 0 || epoch == 7, "witness records the epoch actually read");
        }) };
        w.join().unwrap(); h.join().unwrap();
    });
}

/// H4. Stop is a cut: every Allow ticket is strictly below the cut returned by stop().
#[test]
fn loom_stop_cut_linearizes_before_allow() {
    loom::model(|| {
        let cut = Arc::new(StopCut::default());
        let allowed = Arc::new(loom::sync::Mutex::new(Vec::new()));
        let hot = { let c = cut.clone(); let a = allowed.clone(); thread::spawn(move || {
            if let Ok(t) = c.take_ticket_unless_stopped() { a.lock().unwrap().push(t); }
        }) };
        let cp = { let c = cut.clone(); thread::spawn(move || c.stop()) };
        hot.join().unwrap();
        let cut_at = cp.join().unwrap();
        for t in allowed.lock().unwrap().iter() {
            assert!(*t < cut_at, "Allow ticket {t} issued at or after the stop cut {cut_at}");
        }
    });
}
```

Loom exhaustively explores interleavings up to the preemption bound under its C11-style memory model, including the fences. H1 is the property that the `lambda_epoch` field in the receipt witness is trustworthy. H4 is the concurrency half of the TLA+ invariant `StopIsCut` in the next section; the TLA+ side assumes the ticket is linearizable and H4 shows the Rust primitive provides that.

## 4. Apalache / TLA+ for receipt ordering, liveness and starvation-freedom

The spec models N agents with disjoint ledgers, an arbitrary policy as nondeterministic `Propose`, the shield inside `Attest`, a two-phase attest-then-effect commit so that receipt ordering is observable, a round-robin arbiter, revocation, and stop. Starvation-freedom is encoded twice: as the temporal formula that TLC checks on a small instance, and as a bounded-waiting safety invariant that Apalache checks by induction.

```tla
---------------------------- MODULE EnvelopedDecision ----------------------------
EXTENDS Integers, Sequences, Apalache

CONSTANTS
  \* @type: Int;
  N,
  \* @type: Int;
  Cap,
  \* @type: Int;
  MaxInv

Agents == 0..(N - 1)
Kinds  == 0..4

VARIABLES
  \* @type: Int -> Int;
  remaining,
  \* @type: Int -> Int;
  reserved,
  \* @type: Int -> Int;
  committed,
  \* @type: Int -> Int;
  invCount,
  \* @type: Int -> Bool;
  revoked,
  \* @type: Bool;
  stopped,
  \* @type: Int;
  stopSeq,
  \* @type: Int -> Int;
  phase,        \* 0 idle, 1 proposed, 2 attested (receipt appended, effect pending)
  \* @type: Int -> Int;
  pKind,
  \* @type: Int -> Int;
  pUnits,
  \* @type: Int -> Int;
  epoch,
  \* @type: Int -> Int;
  waiting,      \* turn advances observed while in phase 1
  \* @type: Int -> Int;
  effects,      \* history: effects applied per agent
  \* @type: Int -> Int;
  allowReceipts,\* history: Allow receipts appended per agent
  \* @type: Int;
  turn,
  \* @type: Seq({ seq: Int, agent: Int, allow: Bool, kind: Int, units: Int, epoch: Int });
  log

vars == <<remaining, reserved, committed, invCount, revoked, stopped, stopSeq,
          phase, pKind, pUnits, epoch, waiting, effects, allowReceipts, turn, log>>

Live(a) == ~revoked[a] /\ ~stopped

\* F(s): mirrors envelope_feasible exactly.
Feasible(a, k, u) ==
  \/ k = 0
  \/ k = 1 /\ Live(a) /\ u > 0 /\ u <= remaining[a]
  \/ k = 2 /\ Live(a) /\ u <= reserved[a] /\ invCount[a] < MaxInv
  \/ k = 3 /\ u <= reserved[a]
  \/ k = 4 /\ Live(a)

\* The arithmetic core of F(s), unaffected by Revoke and Stop.
ArithFeasible(a, k, u) ==
  /\ (k = 1 => u <= remaining[a])
  /\ (k \in {2, 3} => u <= reserved[a])
  /\ (k = 2 => invCount[a] < MaxInv)

\* Π_s(a) = a if a ∈ F(s) else ⊥.
Project(a, k, u) == IF Feasible(a, k, u) THEN <<k, u>> ELSE <<0, 0>>

Advance(w) == [b \in Agents |-> IF phase[b] = 1 /\ b # turn THEN w[b] + 1 ELSE w[b]]

Init ==
  /\ remaining = [a \in Agents |-> Cap] /\ reserved = [a \in Agents |-> 0]
  /\ committed = [a \in Agents |-> 0]   /\ invCount = [a \in Agents |-> 0]
  /\ revoked = [a \in Agents |-> FALSE] /\ stopped = FALSE /\ stopSeq = 0
  /\ phase = [a \in Agents |-> 0] /\ pKind = [a \in Agents |-> 0] /\ pUnits = [a \in Agents |-> 0]
  /\ epoch = [a \in Agents |-> 0] /\ waiting = [a \in Agents |-> 0]
  /\ effects = [a \in Agents |-> 0] /\ allowReceipts = [a \in Agents |-> 0]
  /\ turn = 0 /\ log = <<>>

\* The learned policy: any action whatsoever.
Propose(a) ==
  /\ phase[a] = 0
  /\ \E k \in Kinds, u \in 0..Cap :
       /\ pKind' = [pKind EXCEPT ![a] = k]
       /\ pUnits' = [pUnits EXCEPT ![a] = u]
  /\ phase' = [phase EXCEPT ![a] = 1]
  /\ waiting' = [waiting EXCEPT ![a] = 0]
  /\ UNCHANGED <<remaining, reserved, committed, invCount, revoked, stopped, stopSeq,
                 epoch, effects, allowReceipts, turn, log>>

\* Shield, then append the terminal receipt BEFORE any effect.
Attest(a) ==
  /\ turn = a /\ phase[a] = 1
  /\ LET pr == Project(a, pKind[a], pUnits[a])
         allow == pr[1] # 0
     IN /\ pKind' = [pKind EXCEPT ![a] = pr[1]]
        /\ pUnits' = [pUnits EXCEPT ![a] = pr[2]]
        /\ log' = Append(log, [seq |-> Len(log) + 1, agent |-> a, allow |-> allow,
                               kind |-> pr[1], units |-> pr[2], epoch |-> epoch[a]])
        /\ allowReceipts' = [allowReceipts EXCEPT ![a] = IF allow THEN @ + 1 ELSE @]
  /\ phase' = [phase EXCEPT ![a] = 2]
  /\ UNCHANGED <<remaining, reserved, committed, invCount, revoked, stopped, stopSeq,
                 epoch, waiting, effects, turn>>

Effect(a) ==
  /\ phase[a] = 2
  /\ LET k == pKind[a] u == pUnits[a] IN
     /\ remaining' = [remaining EXCEPT ![a] = IF k = 1 THEN @ - u ELSE IF k = 3 THEN @ + u ELSE @]
     /\ reserved'  = [reserved  EXCEPT ![a] = IF k = 1 THEN @ + u ELSE IF k \in {2, 3} THEN @ - u ELSE @]
     /\ committed' = [committed EXCEPT ![a] = IF k = 2 THEN @ + u ELSE @]
     /\ invCount'  = [invCount  EXCEPT ![a] = IF k = 2 THEN @ + 1 ELSE @]
     /\ effects'   = [effects   EXCEPT ![a] = IF k # 0 THEN @ + 1 ELSE @]
  /\ epoch' = [epoch EXCEPT ![a] = @ + 1]
  /\ phase' = [phase EXCEPT ![a] = 0]
  /\ turn' = (turn + 1) % N
  /\ waiting' = Advance(waiting)
  /\ UNCHANGED <<revoked, stopped, stopSeq, pKind, pUnits, allowReceipts, log>>

Skip ==
  /\ phase[turn] = 0
  /\ turn' = (turn + 1) % N
  /\ waiting' = Advance(waiting)
  /\ UNCHANGED <<remaining, reserved, committed, invCount, revoked, stopped, stopSeq,
                 phase, pKind, pUnits, epoch, effects, allowReceipts, log>>

Revoke(a) ==
  /\ ~revoked[a] /\ revoked' = [revoked EXCEPT ![a] = TRUE]
  /\ UNCHANGED <<remaining, reserved, committed, invCount, stopped, stopSeq, phase,
                 pKind, pUnits, epoch, waiting, effects, allowReceipts, turn, log>>

Stop ==
  /\ ~stopped /\ stopped' = TRUE /\ stopSeq' = Len(log)
  /\ UNCHANGED <<remaining, reserved, committed, invCount, revoked, phase, pKind, pUnits,
                 epoch, waiting, effects, allowReceipts, turn, log>>

Next ==
  \/ \E a \in Agents : Propose(a) \/ Attest(a) \/ Effect(a) \/ Revoke(a)
  \/ Skip \/ Stop

Fairness == /\ \A a \in Agents : WF_vars(Attest(a)) /\ WF_vars(Effect(a))
            /\ WF_vars(Skip)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------------
\* Safety

TypeOK ==
  /\ \A a \in Agents : phase[a] \in 0..2 /\ pKind[a] \in Kinds /\ pUnits[a] \in 0..Cap
  /\ turn \in Agents /\ Len(log) >= stopSeq

Phi == \A a \in Agents :
  /\ remaining[a] + reserved[a] + committed[a] = Cap
  /\ remaining[a] >= 0 /\ reserved[a] >= 0 /\ committed[a] >= 0
  /\ invCount[a] <= MaxInv

\* The action whose effect is pending was feasible at attest time and remains
\* arithmetically feasible: nothing but Effect(a) touches a's ledger.
AttestedIsFeasible == \A a \in Agents : phase[a] = 2 => ArithFeasible(a, pKind[a], pUnits[a])

\* ReceiptBeforeAllow, lifted to the enveloped process.
ReceiptBeforeEffect == \A a \in Agents : effects[a] <= allowReceipts[a]

LogSeqIsIndex == \A i \in DOMAIN log : log[i].seq = i

TerminalReceiptExactlyOne ==
  \A i, j \in DOMAIN log :
    (log[i].agent = log[j].agent /\ log[i].epoch = log[j].epoch) => i = j

\* Revocation / stop is a cut: after stopSeq only Hold and Release receipts appear.
StopIsCut == stopped => \A i \in DOMAIN log : i > stopSeq => log[i].kind \in {0, 3}

\* Starvation-freedom as safety: a proposal sees at most N-1 turn advances.
BoundedWaiting == \A a \in Agents : waiting[a] <= N - 1

IndInv == TypeOK /\ Phi /\ AttestedIsFeasible /\ ReceiptBeforeEffect
          /\ LogSeqIsIndex /\ TerminalReceiptExactlyOne /\ StopIsCut /\ BoundedWaiting

----------------------------------------------------------------------------------
\* Liveness (TLC on finite instances; Apalache bounded-lasso only)

EveryProposalTerminates == \A a \in Agents : (phase[a] = 1) ~> (phase[a] = 0)
NoStarvation == \A a \in Agents : []<>(phase[a] = 1 => turn = a)
==================================================================================
```

Checking commands, recorded in `formal/apalache/README.md` alongside the existing specs:

```sh
# Inductive invariant: base case, then one-step consecution from IndInv.
apalache-mc check --init=Init   --inv=IndInv --length=0 EnvelopedDecision.tla
apalache-mc check --init=IndInv --inv=IndInv --length=1 EnvelopedDecision.tla
# Bounded liveness (lasso search up to depth 14).
apalache-mc check --temporal=EveryProposalTerminates --length=14 EnvelopedDecision.tla
# Full liveness on the finite instance N=3, Cap=2, MaxInv=2 via TLC.
tlc -config EnvelopedDecision_N3.cfg EnvelopedDecision.tla
```

The negative registry gets four mutants, each of which must produce an exact `itf` counterexample or the gate fails:

```toml
[[mutant]]
name = "EnvelopedDecision_NoShield"
mutation = "Attest writes <<pKind[a], pUnits[a]>> instead of Project(a, pKind[a], pUnits[a])"
violated = "Phi"
expected_trace_max_len = 3

[[mutant]]
name = "EnvelopedDecision_EffectBeforeReceipt"
mutation = "Effect enabled at phase 1; Attest moves phase 2 -> 0 and appends the receipt"
violated = "ReceiptBeforeEffect"
expected_trace_max_len = 3

[[mutant]]
name = "EnvelopedDecision_StopNotChecked"
mutation = "Live(a) drops the ~stopped conjunct"
violated = "StopIsCut"
expected_trace_max_len = 4

[[mutant]]
name = "EnvelopedDecision_NoRoundRobin"
mutation = "turn' \\in Agents in Effect and Skip"
violated = "BoundedWaiting"
expected_trace_max_len = 6
```

The mapping between these TLA+ actions and the Rust lifecycle is one row each in `formal/MAPPING.md`: `Attest` is `PostEffectObligation::commit_terminal_receipt`, `Effect` is `Discharged::deliver`, `Stop` is `StopCut::stop` with Loom H4 as its concurrency witness, and `Project` is `AdmittedAction::shield`.

**Effort estimates.** One engineer who already knows the Chio formal stack. Elapsed weeks assume the Aeneas toolchain pin and `check-mapping.sh` extensions are done first.

| Artifact | New lines | Effort | Main risk |
|---|---|---|---|
| Rust envelope seam + mirror + `AdmittedAction` doctest | 260 Rust | 2 days | None |
| Lean O1 to O10 (shield and trace theorems) | 350 Lean | 2 weeks | `progress` lemma names at the pinned Aeneas commit |
| Lean O11 (Q16.16 multiply, dead saturation) | 80 Lean | 3 days | `i64::from` trait instance in extraction |
| Kani: nine harnesses + registry | 320 Rust | 1 week | Micro-model harness solver time at F=8, A=5 |
| Loom: `LambdaCell`, `StopCut`, four harnesses | 300 Rust | 1.5 weeks | Fence modeling edge cases, preemption bound tuning |
| Apalache spec, four mutants, TLC config | 260 TLA+ | 2 weeks | Apalache performance on `Seq` log beyond length 14 |
| MAPPING.md rows, xtask mirror wiring, CI gates | 60 lines | 2 days | None |
| Total | about 1,600 | 8 to 9 weeks | |

**What stays out of reach, and why.**

- **Real WCET.** Lean proves totality and Kani proves loop-freedom with `unwind(1)`. Neither says anything about cache misses, branch prediction or interrupts. A cycle bound needs a hardware timing model and a tool such as aiT or measured worst-case runs on the deployment SoC with interrupts masked. Record measured bounds in receipts as evidence, not as theorems.
- **Any statement about π_θ itself.** Optimality, regret, calibration, the 93.96% atomic concept F1 figure, and robustness of the 19.3M-parameter UltraBERT heads are empirical claims. The shield makes them irrelevant to Φ, which is the point of the design, but they are not machine-checked and current neural verifiers do not scale to this model.
- **Fixed-point faithfulness to the FP32 training-time model.** O11 bounds one multiply exactly. A whole-network quantization error bound is a floating-point reasoning problem that Lean can state but not discharge at these dimensions without weeks of bespoke numerics. Kani covers F=8, A=5 for panic freedom only.
- **Unbounded liveness under the real scheduler.** `EveryProposalTerminates` holds relative to weak fairness of the kernel's own actions. That fairness is an assumption about tokio and the host OS, not something any of these tools can check. Apalache checks liveness only up to a lasso length. TLC checks it fully only on a finite instance. The safety encoding `BoundedWaiting` is the strongest machine-checked form.
- **Refinement between the three models.** The Lean model, the Kani harnesses, and the TLA+ spec are tied by `formal/MAPPING.md` and by the Kani cross-seam harness, not by a mechanized refinement proof. Trace-conformance tests that replay Apalache `itf` traces through the Rust seam are the practical substitute and should be added in Wave 3.
- **Pooled budgets across agents.** The TLA+ spec uses disjoint ledgers so `AttestedIsFeasible` is inductive. The `SwarmBudgetPool` case, where a concurrent `Attest` by one child can invalidate another child's arithmetic feasibility between attest and effect, needs the reservation-ledger composition from `ReservationLedger.lean` and is not covered here.
- **Full information-flow non-interference.** The seam abstracts the flow lattice to a total order on `flow_level`. The product lattice in `chio-flow` and the two-run hyperproperty are outside both Aeneas and Kani at useful sizes.
- **Weak memory beyond Loom's model and bound.** Loom explores C11-style orderings up to the preemption bound. It is not a hardware memory model and it is not exhaustive beyond the bound.
- **The trusted base.** Lean's kernel, the Aeneas translator, CBMC under Kani, Z3 under Apalache, rustc, and the Ed25519 and ML-DSA signature assumptions behind receipt attestation are all trusted, not verified.

The deliverable is a single scalar seam with eleven Lean obligations proving Φ-preservation for arbitrary policies, nine Kani harnesses that quantify the policy output with `kani::any()`, four Loom models for the λ seqlock and the stop cut, and one Apalache module with four falsifiability mutants covering receipt ordering, Φ, stop-as-cut and starvation-freedom. The honest boundary is that timing, policy quality, whole-network quantization error, scheduler fairness and cross-model refinement remain assumptions or empirical measurements rather than theorems.

---

## w2_angle_3_linux_macos_os_enforcement

```swift
// ChioESClient.swift (system extension)
let result = es_new_client(&client) { client, msg in
    let hardNs = chio_mach_to_ns(msg.pointee.deadline)
    let nowNs  = chio_mach_to_ns(mach_absolute_time())
    let slot   = ChioAuthSlots.acquire(msg)                     // retains msg, wraps core::AuthSlot
    watchdog.schedule(atNs: hardNs - MARGIN_NS) {               // time-constraint thread
        if slot.claim(.watchdog) { respondBottom(client, msg); chio_record_miss(msg) }
    }
    decisionQueue.async {
        let d = chio_es_decide(msg, nowNs, hardNs)              // -> core::enforce, deferral_budget = 0
        if slot.claim(.worker) { respond(client, msg, d) } else { chio_record_late_decision(msg, d) }
    }
}

func respondBottom(_ c: OpaquePointer, _ m: UnsafePointer<es_message_t>) {
    if m.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN { es_respond_flags_result(c, m, 0, false) }
    else { es_respond_auth_result(c, m, ES_AUTH_RESULT_DENY, false) }
}
```

Two policies follow from the subject-dependence of verdicts. First, `cache` is always `false`: the ES result cache is keyed by file, not by responsible process, so a cached `Allow` for one session would leak to another. Second, `Pending` cells get `deferral_budget_ns = 0` on ES, because ES has no pause primitive. They are denied immediately with cause `BottomPendingNoDeferral`, the daemon raises the approval, and the agent retries after resolution. A late worker decision never responds twice; it is recorded with the would-have-been verdict, which gives Copley a clean deadline-miss predicate for segment $s_3$.

### 3.4 NetworkExtension content filter

The data provider sees every new socket flow with its `sourceAppAuditToken`. Ungoverned tokens return `.allow()` in microseconds. Governed flows resolve `NetConnect` (outbound) or `NetBind` (inbound) against the CIDR-and-port slot table. Unlike ES, NE can pause, so `Pending` cells receive a deferral budget of 30 s for human approval.

```swift
override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
    guard let sock = flow as? NEFilterSocketFlow, let token = flow.sourceAppAuditToken else { return .allow() }
    let d = chio_ne_decide(token, sock.remoteEndpoint, sock.direction, 30_000_000_000)  // deferral budget ns
    switch d.kind {
    case .allow: return .allow()
    case .deny:  return .drop()
    case .defer:
        pending.arm(flow, afterNs: d.deferralNs) { [weak self] in self?.resumeFlow(flow, with: .drop()) } // bot_s
        return .pause()
    }
}
```

An approval that lands before the timer fires recompiles the table; the shim re-runs `enforce` against the new epoch and resumes with `.allow()` only if the cell now reads `Allow`. `NEFilterSettings` rules cannot select by process, so scoping happens in the handler, not in the rule set.

### 3.5 Packaging

The host app bundles the extension under `Contents/Library/SystemExtensions/` and activates it with `OSSystemExtensionRequest`. Entitlements: `com.apple.developer.endpoint-security.client`, `com.apple.developer.networking.networkextension` (`content-filter-provider-systemextension`), `com.apple.developer.system-extension.install`. ES additionally requires Full Disk Access, granted interactively or through an MDM PPPC payload. The daemon is a `LaunchDaemon` plist with a Mach service name the extension connects to over XPC. Receipt batches use the `encode` wire form from the core crate and land in the same SQLite schema as Linux.

## 4. Latency Budgets, Deadline-Miss Semantics, and Formal Guarantees

### 4.1 Budgets

| Path | Mechanism | p50 target | p99 target | Bound type |
|---|---|---|---|---|
| Linux file open / exec / connect | BPF-LSM, in-kernel | 0.8 µs | 3 µs | WCET $W \le 10$ µs (Proposition 1) |
| Linux receipt reserve + submit | ring buffer | 0.2 µs | 0.5 µs | included in $W$ |
| macOS ES AUTH decision | extension worker | 150 µs | 2 ms | hard: kernel deadline $D$, margin $\mu = 20$ ms |
| macOS NE new flow | data provider | 200 µs | 2 ms | pause cap 30 s then drop |
| Revocation visibility | 8-byte map write / XPC push | 50 µs | 1 ms | $\Delta_\rho$ |
| Table recompile + swap | tier-1 control plane | 400 µs | 2 ms | $\Delta_c = T_{\text{ctrl}} + T_{\text{compile}} + G$ |
| Pending approval | human via prompt | | 30 s | deny on expiry |

### 4.2 Deadline-miss and degraded-mode semantics

| Condition | Linux BPF-LSM | macOS ES | macOS NE | Receipt cause |
|---|---|---|---|---|
| Under governed root, no session slot | `-EPERM` | `DENY` | drop | `BottomUnknownSubject` |
| Table absent or malformed | `-EPERM` | `DENY` | drop | `BottomNoTable` / `BottomBadTable` |
| Live revocation floor above compiled | `-EPERM` | `DENY` | drop | `BottomRevoked` |
| Cell `Pending` | `-EPERM` | `DENY` | pause 30 s, then drop | `BottomPendingNoDeferral` / `PendingDeferred` |
| No decision by $D - \mu$ | not possible (synchronous) | watchdog `DENY` or flags `0` | not applicable | `BottomDeadlineMiss` |
| Ring full or XPC backpressure | `Allow` becomes `-EPERM` | `Allow` becomes `DENY` | `Allow` becomes drop | `BottomReceiptUnavailable` |
| Enforcement detached or crashed | Landlock envelope, `cgroup.freeze` within $\tau_w$ | daemon watchdog `SIGSTOP`s governed processes | same | out-of-band `HostEnforcementLost` |

### 4.3 Theorems

**Definition 1 (Compile invariant).** For session $s$ at epoch $e$, $T^{(e)}_s[h,o] = \mathsf{Allow} \iff a_{h,o} \in F(s_e)$, and `revocation_floor` equals the revocation epoch $\rho_s$ observed by the compiler.

**Theorem 1 (Shield soundness).** For a governed subject, if `enforce` returns `Allow` then the table was well formed, the live floor satisfied $\rho^{\text{live}}_s \le \rho^{\text{compiled}}_s$, the cell was `Allow`, and a receipt was reserved. Hence the realized action lies in $F(s_e)$.

*Proof.* `project` yields `HostVerdict::Allow` only in the `Some(Cell::Allow)` arm, reached after the deadline, table presence, well-formedness, revocation, and range guards. `shield` is the only function applied afterward, and it maps `Allow` to `Deny` unless `receipt_reserved`. `Ungoverned` subjects return before any table read and are outside the claim. By Definition 1 the `Allow` bit implies $a_{h,o} \in F(s_e)$. $\blacksquare$

**Theorem 2 (Deadline-miss safety, macOS).** Let message $m$ have hard deadline $D_m$, margin $\mu$, and watchdog scheduling latency $\varepsilon < \mu$. Exactly one response is sent, it is sent before $D_m$, and if no worker decision exists by $D_m - \mu$ the response is $\bot_s$.

*Proof.* Both responders call `AuthSlot::claim`, a compare-and-exchange from `PENDING`. CAS is linearizable, so exactly one claim succeeds and exactly one response is issued, which also rules out `ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE`. The watchdog fires no later than $D_m - \mu + \varepsilon < D_m$. If the worker has not claimed by then, the watchdog claims and sends `DENY` or flags `0`, which is the $\bot_s$ image of hook $h$. $\blacksquare$

*Corollary.* The system never terminates the client for a missed deadline, so the kernel's allow-on-client-death path is unreachable while the extension runs.

**Theorem 3 (Epoch isolation under generation flip).** If every hook invocation completes within $W$ and the writer waits $G \ge W$ after flipping `ACTIVE_GEN[slot]` before rewriting the retired buffer, then no hook invocation reads a buffer while it is being written.

*Proof.* A reader observes generation $g$ at time $t_0$ and reads only buffer $2\cdot\mathrm{slot} + g$, finishing by $t_0 + W$. The writer writes only the inactive buffer. Buffer $b$ becomes inactive at a flip time $t_f$ and is next written no earlier than $t_f + G$. Any reader of $b$ started before $t_f$ and finished by $t_f + W \le t_f + G$. Readers starting after $t_f$ read the other buffer. $\blacksquare$

**Theorem 4 (Receipt-before-allow and loss detectability).** Every realized `Allow` on a governed subject has a submitted record in the ring. Record loss is detectable by the consumer.

*Proof.* By Theorem 1 an `Allow` requires a successful reservation, and `enforce` submits the record after the decision in the same invocation. `bpf_ringbuf_reserve` fails rather than overwriting unconsumed data, so submitted records persist until drained. Per-CPU `SEQ` increments on every reserved record and `DROPS` on every failed reservation; a gap in the sequence or a non-zero drop delta is observable. $\blacksquare$

**Theorem 5 (Static envelope).** With Landlock ruleset $L = \overline{F}$ applied at spawn and LSM stacking intersecting decisions, the effective permission is $L \cap E_{\text{BPF}} \subseteq F(s_t)$ while BPF is attached, and $\subseteq \overline{F}$ for at most $\tau_w$ after detachment, after which the governed cgroup is frozen.

*Proof.* Landlock is enforced in `security_*` hooks ahead of BPF and is irrevocable for the process tree. Intersection gives the first claim via Theorem 1. On detachment the watchdog observes link loss within its 100 ms poll period and writes `cgroup.freeze` within $\tau_w$, after which no process in the cgroup is scheduled. $\blacksquare$

**Theorem 6 (Staleness bound).** A revocation is enforced within $\Delta_\rho$ independently of recompilation. Any budget-induced shrinkage of $F(s)$ is enforced within $\Delta_c$, and over-admission in that window is bounded by $\sum_h c^{\max}_h\, n_h(\Delta_c)$, where $n_h$ counts hook invocations and $c^{\max}_h$ the per-invocation cost.

*Proof.* The floor write is a single store or XPC message; `project` compares it on every invocation, so denial follows within $\Delta_\rho$. Budget shrinkage reaches the host only through a new epoch, whose latency is $\Delta_c$. Each invocation in the window costs at most $c^{\max}_h$, and `budget_precheck` in `chio-kernel-core` remains the authoritative ledger, so the host bound is a second shield rather than the accounting of record. $\blacksquare$

**Proposition 1 (WCET of the AUTH hot path).** The program is loop-free, so $W = c_0 + c_{\text{dpath}}(\ell) + c_{\text{lpm}}(\ell) + c_{\text{rb}}$, with $\ell \le 256$ path bytes, $c_{\text{lpm}}$ bounded by 2,048 bit comparisons, and $c_{\text{rb}}$ constant. The verifier bounds the straight-line instruction count, and helper costs are bounded by their fixed-size arguments. $\blacksquare$

**Lemma 1 (Epoch rate under hysteresis).** If each $\lambda_r$ moves at most $\delta_{\max}$ per control tick $T_{\text{ctrl}}$ and `recompile_required` uses band $\eta_r$, consecutive recompiles are at least $\lceil \eta_r / \delta_{\max} \rceil$ ticks apart for resource $r$, so the epoch rate is at most $\min(1, \delta_{\max}/\eta_r)\,/\,T_{\text{ctrl}}$. This bounds `es_clear_cache`-free table pushes on macOS and grace-period pressure on Linux.

### 4.4 Verification mapping (additions to `formal/MAPPING.md`)

| Artifact | Property | Tool |
|---|---|---|
| `verify_host_projection_sound` | Theorem 1 over symbolic tables and inputs | Kani |
| `verify_shield_receipt_before_allow` | `shield` never returns `Allow` without reservation | Kani |
| `verify_record_encode_exact_len` | `encode` writes exactly `RECORD_BYTES` | Kani |
| `verify_mach_ticks_no_overflow` | `mach_ticks_to_ns` total on all inputs | Kani |
| `loom_auth_slot_exactly_one_response` | Theorem 2 claim race | Loom |
| `loom_generation_flip_grace` | Theorem 3 reader-writer model | Loom |
| `HostEpochSwap.tla` | `NoMixedEpochRead`, `RevocationDominatesTable` | Apalache |
| `HostReceiptBeforeAllow.tla` | host image of `ReceiptBeforeAllow` | Apalache |
| `_negative_tests`: shield-without-reservation, watchdog-without-CAS, flip-without-grace | each must yield a counterexample trace | Apalache |

The design keeps the kernel-core contract unchanged: `evaluate` computes $F(s)$ and emits bits, the host projects bits into hook verdicts in constant time, and every path that cannot decide collapses to $\bot_s$. Linux gets a synchronous in-kernel shield under a Landlock envelope with frozen-cgroup fail-closed behaviour and Omarchy packaging through `uwsm` scopes and systemd units. macOS gets an ES client whose watchdog makes the kernel's allow-on-timeout path unreachable, plus an NE filter that can pause for approvals. Receipt records double as Copley telemetry, so learning improves the next table without ever touching the hot path. Next steps are landing the three crates (`chio-host-enforce-core`, `-bpf`, `-darwin`) with the listed Kani and Loom harnesses, then measuring the p99 targets in the table above on an Omarchy host and an Apple silicon machine.

---

## w2_angle_4_agentic_economy_relying_party_and_positioning

I'll write the treatise directly, building on the Wave 1 envelope and emitting the receipt schema and relying-party verifiers as `#![no_std]` Rust.

**Assumptions carried from Wave 1.** The state is $s = C(x)$, produced by the exact fact processor from the evidence window $x$. The feasibility map $F(s) \subseteq \mathcal{A}$ is computed deterministically in `chio-kernel-core`, and $\bot_s \in F(s)$ for every $s$. The learned policy proposes $a_\theta = \pi_\theta(s)$, and the shielded projection $\Pi_s(a) = a$ if $a \in F(s)$, else $\bot_s$, runs in $O(1)$. The Tier-1 control plane publishes shadow prices $\lambda \in \mathbb{R}^R_{\ge 0}$ at millisecond cadence, and the Tier-0 micro-model scores $L_\lambda(s,a) = c(s,a) + \lambda^\top g(s,a)$ in Q16.16 under a WCET bound. Copley supplies $P(x)$, the calibrated predicate activations, and the boolean DAG verdict with exact witnesses.

## 1. Deterministic Decision Receipts for Relying Parties

**What a relying party needs.** A payment rail, an API provider, an insurer, or an enterprise change-control system never sees the agent's prompt, weights, or sandbox. It sees one action and must decide whether to honor it. Today that decision rests on the API key or account that issued the action, which says nothing about the process behind it. A decision receipt replaces identity-based trust with process-based evidence. It is a signed, canonical, log-committed statement that a specific action was admitted by a specific governed process under a specific policy, with the conservative alternative present and rejected for stated reasons. The receipt must be cheap to verify, bound to the exact bytes of the action, fresh against revocation, and attributable for liability.

**Schema.** The body is a fixed-size struct partitioned along Copley's epistemic lines, so the verification mode of every field is known before the relying party reads it.

| Partition | Fields | How the relying party checks it |
| --- | --- | --- |
| Observed facts | request hash, capability root, attenuation witness, containment attestation, revocation snapshot and epoch, decision time, authority deadline | Equality against signed sources: canonical request bytes, trust-root set, revocation oracle, sandbox measurement |
| Governing artifacts | policy IR hash, model version hash, predicate DAG hash | Membership in the relying party's accepted set |
| Deterministic computation $C(x)$ | facts hash, computed hash, feasibility witness, projection kind, ledger triple, Lagrangian witness | Recomputable from disclosed scalars with the same pure functions |
| Learned prediction $P(x)$ | predicate activation hash | Attributable to the sealed model; DAG output recomputable from disclosed activations |
| Treaty | treaty id, treaty truth vector | Equality with the relying party's own predicate set and required truth bits |

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::as_conversions,
    clippy::arithmetic_side_effects
)]
//! chio-rp-receipt: relying-party decision receipt (schema v1) and its O(1) structural verifier.
//! Canonical encoding and cryptography are injected through traits so the crate stays
//! dependency-free; the kernel supplies RFC 8785 encoding and the hybrid signature floor.

pub type Hash32 = [u8; 32];

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const MAX_ACTIONS: u8 = 64;
pub const MAX_SHADOW_PRICES: usize = 8;
pub const MAX_INCLUSION_PATH: usize = 64;

/// Two's-complement Q16.16 scalar shared with the Tier-0 micro-model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(65_536);

    #[must_use]
    pub fn from_int(v: i32) -> Option<Self> {
        v.checked_mul(65_536).map(Self)
    }
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }
    /// Product truncating toward negative infinity; bit-identical on every target.
    #[must_use]
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(rhs.0))?;
        let scaled = wide.checked_shr(16)?;
        i32::try_from(scaled).ok().map(Self)
    }
    #[must_use]
    pub fn is_non_negative(self) -> bool {
        self.0 >= 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Cancelled,
    Incomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionKind {
    Identity,
    FallbackToConservative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionIndex(pub u8);

/// Bit i set <=> action i in F(s). `conservative` is bot_s and must always be set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeasibilityWitness {
    pub mask: u64,
    pub conservative: ActionIndex,
}

impl FeasibilityWitness {
    #[must_use]
    pub fn contains(&self, action: ActionIndex) -> bool {
        if action.0 >= MAX_ACTIONS {
            return false;
        }
        match 1_u64.checked_shl(u32::from(action.0)) {
            Some(bit) => (self.mask & bit) != 0,
            None => false,
        }
    }
}

/// Committed shadow prices and the two Lagrangian operands the verifier replays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LagrangianWitness {
    pub price_count: u8,
    pub lambda: [FixedQ16_16; MAX_SHADOW_PRICES],
    pub cost_chosen: FixedQ16_16,
    pub usage_chosen: [FixedQ16_16; MAX_SHADOW_PRICES],
    pub cost_conservative: FixedQ16_16,
    pub usage_conservative: [FixedQ16_16; MAX_SHADOW_PRICES],
}

impl LagrangianWitness {
    fn score(
        &self,
        cost: FixedQ16_16,
        usage: &[FixedQ16_16; MAX_SHADOW_PRICES],
    ) -> Option<FixedQ16_16> {
        let n = usize::from(self.price_count);
        if n > MAX_SHADOW_PRICES {
            return None;
        }
        self.lambda
            .iter()
            .zip(usage.iter())
            .take(n)
            .try_fold(cost, |acc, (lam, g)| acc.checked_add(lam.checked_mul(*g)?))
    }

    #[must_use]
    pub fn prices_dual_feasible(&self) -> bool {
        let n = usize::from(self.price_count);
        n <= MAX_SHADOW_PRICES && self.lambda.iter().take(n).all(|l| l.is_non_negative())
    }

    /// L(a*) <= L(bot_s) under the committed prices. None signals overflow.
    #[must_use]
    pub fn chosen_no_worse_than_conservative(&self) -> Option<bool> {
        let l_star = self.score(self.cost_chosen, &self.usage_chosen)?;
        let l_bot = self.score(self.cost_conservative, &self.usage_conservative)?;
        Some(l_star <= l_bot)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelyingPartyReceiptBodyV1 {
    pub schema_version: u16,
    // Observed facts and authority.
    pub request_hash: Hash32,
    pub capability_root: Hash32,
    pub attenuation_witness: Hash32,
    pub containment_attestation: Hash32,
    // Governing artifacts.
    pub policy_ir_hash: Hash32,
    pub model_version_hash: Hash32,
    pub predicate_dag_hash: Hash32,
    // Epistemic partition commitments.
    pub facts_hash: Hash32,
    pub computed_hash: Hash32,
    pub predicate_activation_hash: Hash32,
    // Freshness.
    pub revocation_snapshot_hash: Hash32,
    pub revocation_epoch: u64,
    pub decided_at_unix_ms: u64,
    pub authority_deadline_unix_ms: u64,
    // Enveloped decision.
    pub feasibility: FeasibilityWitness,
    pub proposed: ActionIndex,
    pub chosen: ActionIndex,
    pub projection: ProjectionKind,
    pub lagrangian: LagrangianWitness,
    // Ledger.
    pub units_before: u64,
    pub units_after: u64,
    pub cost_units: u64,
    pub decision: Decision,
    // Treaty.
    pub treaty_id: Hash32,
    pub treaty_truth_vector: u64,
}

pub struct RelyingPartyReceiptV1<'a> {
    pub body: RelyingPartyReceiptBodyV1,
    pub receipt_id: Hash32,
    pub signature: &'a [u8],
    pub leaf_index: u64,
    pub tree_size: u64,
    pub inclusion_path: &'a [Hash32],
    pub checkpoint_root: Hash32,
    pub checkpoint_signature: &'a [u8],
}

pub struct RelyingPartyPolicy<'a> {
    pub accepted_policy_ir: &'a [Hash32],
    pub accepted_models: &'a [Hash32],
    pub accepted_predicate_dags: &'a [Hash32],
    pub min_revocation_epoch: u64,
    pub treaty_id: Hash32,
    pub required_treaty_bits: u64,
    pub max_cost_units: u64,
    pub require_containment_attestation: bool,
}

pub trait ReceiptIdDeriver {
    /// H(RFC 8785 canonical bytes of the body).
    fn receipt_id(&self, body: &RelyingPartyReceiptBodyV1) -> Hash32;
}

pub trait Digest32 {
    /// RFC 6962 leaf hash H(0x00 || id).
    fn hash_leaf(&self, receipt_id: &Hash32) -> Hash32;
    /// RFC 6962 node hash H(0x01 || left || right).
    fn hash_node(&self, left: &Hash32, right: &Hash32) -> Hash32;
}

pub trait SignatureVerifier {
    fn verify_receipt(&self, receipt_id: &Hash32, signature: &[u8]) -> bool;
    fn verify_checkpoint(&self, root: &Hash32, tree_size: u64, signature: &[u8]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRejection {
    SchemaVersion,
    ReceiptIdMismatch,
    BadReceiptSignature,
    BadCheckpointSignature,
    LeafOutsideTree,
    InclusionPathTooLong,
    InclusionRootMismatch,
    PolicyNotAccepted,
    ModelNotAccepted,
    PredicateDagNotAccepted,
    ContainmentMissing,
    RevocationEpochStale,
    DeadlineBeforeDecision,
    ActionOutOfRange,
    ConservativeNotFeasible,
    ChosenNotFeasible,
    ProjectionInconsistent,
    NonDenyOnConservative,
    BudgetArithmetic,
    CostAboveRelyingPartyCap,
    DualInfeasiblePrices,
    LagrangianOverflow,
    ChosenWorseThanConservative,
    TreatyMismatch,
    TreatyPredicateFailed,
}

fn accepted(set: &[Hash32], h: &Hash32) -> bool {
    set.iter().any(|x| x == h)
}

/// RFC 9162 section 2.1.3.2 inclusion walk. One compression per path element.
fn compute_inclusion_root<D: Digest32>(
    d: &D,
    leaf: &Hash32,
    leaf_index: u64,
    tree_size: u64,
    path: &[Hash32],
) -> Result<Hash32, ReceiptRejection> {
    type R = ReceiptRejection;
    if leaf_index >= tree_size {
        return Err(R::LeafOutsideTree);
    }
    if path.len() > MAX_INCLUSION_PATH {
        return Err(R::InclusionPathTooLong);
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size.checked_sub(1).ok_or(R::LeafOutsideTree)?;
    let mut acc = *leaf;
    for sibling in path {
        if snode == 0 {
            return Err(R::InclusionPathTooLong);
        }
        if (fnode & 1) == 1 || fnode == snode {
            acc = d.hash_node(sibling, &acc);
            if (fnode & 1) == 0 {
                while (fnode & 1) == 0 && fnode != 0 {
                    fnode = fnode.wrapping_shr(1);
                    snode = snode.wrapping_shr(1);
                }
            }
        } else {
            acc = d.hash_node(&acc, sibling);
        }
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    if snode == 0 {
        Ok(acc)
    } else {
        Err(R::InclusionRootMismatch)
    }
}

/// Tier V1 acceptance predicate Acc_RP. Total, panic-free, O(1) in agents, models, and swarm size.
pub fn verify_structural<I, D, S>(
    receipt: &RelyingPartyReceiptV1<'_>,
    rp: &RelyingPartyPolicy<'_>,
    ids: &I,
    digest: &D,
    sigs: &S,
) -> Result<(), ReceiptRejection>
where
    I: ReceiptIdDeriver,
    D: Digest32,
    S: SignatureVerifier,
{
    type R = ReceiptRejection;
    let b = &receipt.body;
    if b.schema_version != SCHEMA_VERSION_V1 {
        return Err(R::SchemaVersion);
    }
    // Binding: id = H(canon(body)), two signatures, log inclusion.
    if ids.receipt_id(b) != receipt.receipt_id {
        return Err(R::ReceiptIdMismatch);
    }
    if !sigs.verify_receipt(&receipt.receipt_id, receipt.signature) {
        return Err(R::BadReceiptSignature);
    }
    if !sigs.verify_checkpoint(&receipt.checkpoint_root, receipt.tree_size, receipt.checkpoint_signature) {
        return Err(R::BadCheckpointSignature);
    }
    let leaf = digest.hash_leaf(&receipt.receipt_id);
    let root = compute_inclusion_root(digest, &leaf, receipt.leaf_index, receipt.tree_size, receipt.inclusion_path)?;
    if root != receipt.checkpoint_root {
        return Err(R::InclusionRootMismatch);
    }
    // Governing artifacts the relying party accepts.
    if !accepted(rp.accepted_policy_ir, &b.policy_ir_hash) {
        return Err(R::PolicyNotAccepted);
    }
    if !accepted(rp.accepted_models, &b.model_version_hash) {
        return Err(R::ModelNotAccepted);
    }
    if !accepted(rp.accepted_predicate_dags, &b.predicate_dag_hash) {
        return Err(R::PredicateDagNotAccepted);
    }
    if rp.require_containment_attestation && b.containment_attestation == [0_u8; 32] {
        return Err(R::ContainmentMissing);
    }
    // Freshness.
    if b.revocation_epoch < rp.min_revocation_epoch {
        return Err(R::RevocationEpochStale);
    }
    if b.authority_deadline_unix_ms < b.decided_at_unix_ms {
        return Err(R::DeadlineBeforeDecision);
    }
    // Enveloped decision: bot_s in F(s), a* in F(s), a* = Proj(a_theta).
    if b.chosen.0 >= MAX_ACTIONS || b.proposed.0 >= MAX_ACTIONS || b.feasibility.conservative.0 >= MAX_ACTIONS {
        return Err(R::ActionOutOfRange);
    }
    if !b.feasibility.contains(b.feasibility.conservative) {
        return Err(R::ConservativeNotFeasible);
    }
    if !b.feasibility.contains(b.chosen) {
        return Err(R::ChosenNotFeasible);
    }
    let projection_ok = match b.projection {
        ProjectionKind::Identity => b.chosen == b.proposed,
        ProjectionKind::FallbackToConservative => {
            !b.feasibility.contains(b.proposed) && b.chosen == b.feasibility.conservative
        }
    };
    if !projection_ok {
        return Err(R::ProjectionInconsistent);
    }
    if b.chosen == b.feasibility.conservative && b.decision != Decision::Deny {
        return Err(R::NonDenyOnConservative);
    }
    // Ledger: before = after + cost, under the relying party's exposure cap.
    let expected_before = b.units_after.checked_add(b.cost_units).ok_or(R::BudgetArithmetic)?;
    if expected_before != b.units_before {
        return Err(R::BudgetArithmetic);
    }
    if b.cost_units > rp.max_cost_units {
        return Err(R::CostAboveRelyingPartyCap);
    }
    // Prices: dual feasibility and rationality witness.
    if !b.lagrangian.prices_dual_feasible() {
        return Err(R::DualInfeasiblePrices);
    }
    match b.lagrangian.chosen_no_worse_than_conservative() {
        None => return Err(R::LagrangianOverflow),
        Some(false) => return Err(R::ChosenWorseThanConservative),
        Some(true) => {}
    }
    // Treaty: the relying party's own predicates, evaluated in-kernel.
    if b.treaty_id != rp.treaty_id {
        return Err(R::TreatyMismatch);
    }
    if (b.treaty_truth_vector & rp.required_treaty_bits) != rp.required_treaty_bits {
        return Err(R::TreatyPredicateFailed);
    }
    Ok(())
}
```

**Verification tiers.** Relying parties choose how much of the receipt to re-derive.

| Tier | What is checked | Cost class |
| --- | --- | --- |
| V0 | Receipt and checkpoint signatures, Merkle inclusion | Two signature verifications plus $\lceil \log_2 n \rceil + 1$ hashes |
| V1 | V0 plus every structural check in `verify_structural` | V0 plus under two hundred word operations |
| V2 | V1 plus replay of the Aeneas-mirrored scalar functions on disclosed inputs | V1 plus a few hundred integer operations |
| V3 | V2 plus full replay of $C(x)$ and the boolean DAG from escrowed evidence | Proportional to evidence size; no model weights needed for the DAG |

The target envelope for V1 on one commodity core, to be measured in the first quarter, is:

| Step | Work | Target |
| --- | --- | --- |
| Receipt id recompute | One canonical encode plus one SHA-256 over under 4 KB | under 10 µs |
| Receipt signature | Ed25519 alone, or hybrid with ML-DSA-65 | under 60 µs, or under 250 µs hybrid |
| Checkpoint signature | Same | Same |
| Inclusion walk at tree size $2^{24}$ | 25 compressions | under 25 µs |
| Structural checks | Under 200 word operations | under 1 µs |
| Whole V1 | | p99 under 1 ms; artifact under 4 KB |

**Definition (acceptance predicate).** $\mathsf{Acc}_{RP}(R) = 1$ iff `verify_structural` returns Ok under the relying party's policy.

**Trust assumption T1.** The signing key is held by an instance of the audited kernel build. The binding is either remote attestation of the build measurement to the key, or an operator liability contract attached to the key. Everything below is relative to T1.

**Theorem 1 (Relying-party soundness).** Assume $H$ is collision resistant, the canonical encoding is injective, the signature scheme is EUF-CMA secure, and T1 holds. If $\mathsf{Acc}_{RP}(R) = 1$ and the decision is Allow, then except with negligible probability: (a) the kernel evaluated a state $s$ under a policy in the relying party's accepted set with $a^* \in F(s)$ and $\bot_s \in F(s)$; (b) $a^* \ne \bot_s$ and $a^* = \Pi_s(a_\theta)$; (c) any request whose canonical hash equals the receipt's request hash is byte-identical to the admitted request; (d) no external effect preceded fixation of the receipt body.

*Proof.* (c) Injectivity of the canonical encoding, mechanized as `canonical_inj`, and collision resistance of $H$ give that two distinct requests collide only with negligible probability; `receipt_id_collision_resistant` lifts this to the receipt id. (a), (b) The feasibility, projection, and conservative-action checks are evaluated on the signed body. By EUF-CMA, a verifying signature on the receipt id was produced by the key holder, which under T1 is the audited kernel. The kernel's receipt path fills the feasibility witness from $F(s)$ and the chosen action from $\Pi_s$, so the field relations the relying party verifies are the relations the kernel computed. Wave 1 gives $\bot_s \in F(s)$ for all $s$, so the fallback field is always well defined, and the structural check rejects any body in which it is absent. (d) `ReceiptBeforeAllow` is an invariant of the kernel transition system, checked symbolically in Apalache, and the body is fixed when ownership passes to the post-effect obligation. T1 transfers this property of the build to the signed artifact. $\blacksquare$

**Theorem 2 (Verification cost is independent of agents, models, and swarm size).** For a log of size $n$, `verify_structural` performs exactly two signature verifications, at most $\lceil \log_2 n \rceil + 1$ hash compressions, and at most $c_0 + |\mathcal{A}| + 4R$ word operations for a constant $c_0$, with $|\mathcal{A}| \le 64$ and $R \le 8$. No term depends on $|x|$, on the parameter count of $\pi_\theta$ or the Copley encoder, or on the number of agents in the swarm.

*Proof.* The body is fixed-size, so the identity recomputation hashes a bounded buffer. The inclusion walk performs one compression per path element, and the `snode` exhaustion check rejects paths longer than $\lceil \log_2 n \rceil$. The Lagrangian check iterates at most $R$ products and sums for each of two scores. Every other check is a constant number of comparisons. $\blacksquare$

**Proposition 3 (Epistemic partition yields non-repudiation of the symbolic layer).** Let $E$ be the pure boolean DAG evaluator, $\mathbf{p}$ the committed activation vector, and $\tau$ the sealed thresholds under the predicate DAG hash. If an auditor obtains $\mathbf{p}$ matching the activation hash and finds $E(\mathbf{p}, \tau)$ inconsistent with the receipt's committed computation, the signed receipt is a transferable proof of kernel misbehavior. The only non-recomputable surface is the map $x \mapsto \mathbf{p}$, attributable to the model version hash and bounded by its sealed validation false-alarm rate.

*Proof.* $E$ is deterministic with no hidden inputs, so two honest evaluations agree. A disagreement witnessed under a valid signature is therefore attributable to the signer. $\blacksquare$

**Trust bootstrapping.** A receipt is only as useful as the relying party's confidence in T1 and in the policy behind it. Four roots compose, from weakest to strongest.

- **Operator liability.** The key is registered under a contract. Verification is V0 and the remedy is legal. This is where most relying parties start.
- **Attested build.** A hardware quote binds the kernel's reproducible build measurement to the signing key. The relying party pins the measurement, not the operator.
- **Federation and revocation.** Operator keys are cross-signed through `chio-federation`, and the revocation oracle publishes strictly advancing epochs with equivocation rejected, which `epoch_advance_is_strict` and `same_epoch_equivocation_rejected` mechanize. The relying party's minimum epoch floor makes stale receipts fail closed.
- **Treaty predicates.** The relying party writes its own predicates in the Lean-specified predicate language. The kernel evaluates them and commits the truth vector. The relying party then needs no trust in the operator's policy at all, only in the kernel's evaluation of the relying party's predicates, which is attributable and, for predicates over committed facts, recomputable.

Acceptance graduates through the same three modes the autonomy layer uses for its own models. In Shadow the relying party computes its own verdict and merely records agreement. In Advisory a verifying receipt unlocks a small exposure cap and disagreements escalate to a human. In Active a verifying receipt is sufficient up to the cap. The graduation rule is a confidence bound, not a vibe.

**Theorem 4 (Safe graduation).** In Shadow the relying party records $D_i = 1$ when it would have denied the $i$-th Allow receipt. Suppose the $D_i$ are independent Bernoulli($p$) over a stationarity window. If the relying party graduates only when $\hat p_n + \sqrt{\ln(1/\alpha)/(2n)} \le \delta$, then $\Pr[p > \delta] \le \alpha$.

*Proof.* Hoeffding's one-sided inequality gives $\Pr[p - \hat p_n > \epsilon] \le \exp(-2n\epsilon^2)$. Substituting $\epsilon = \sqrt{\ln(1/\alpha)/(2n)}$ bounds the probability that the true rate exceeds the confidence bound by $\alpha$, and the graduation condition places that bound at or below $\delta$. $\blacksquare$

Stationarity is enforced rather than assumed. Any drift alarm of a kind the autonomy layer already tracks, such as a loss-ratio spike or a model version mismatch, resets the ledger to Shadow. That is `SwitchToSafeState` applied on the relying party's side.

```rust
// Same crate, continued: relying-party trust ledger and premium quote.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AcceptanceMode {
    Shadow,
    Advisory,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraduationThresholds {
    pub min_samples: u32,
    /// ln(1/alpha) in Q16.16; alpha = 0.01 gives ln(100) = 4.60517, encoded as 301_804.
    pub ln_inverse_alpha: FixedQ16_16,
    pub max_disagreement_advisory: FixedQ16_16,
    pub max_disagreement_active: FixedQ16_16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowLedger {
    pub allow_observed: u32,
    pub allow_disagreed: u32,
    pub mode: AcceptanceMode,
}

/// Floor of sqrt(n) by binary search; at most 33 iterations, no overflow.
fn isqrt_u64(n: u64) -> u64 {
    let mut lo: u64 = 0;
    let mut hi: u64 = 4_294_967_296;
    while lo < hi {
        let mid = lo.wrapping_add(hi.wrapping_sub(lo).wrapping_shr(1)).wrapping_add(1);
        match mid.checked_mul(mid) {
            Some(sq) if sq <= n => lo = mid,
            _ => hi = mid.wrapping_sub(1),
        }
    }
    lo
}

impl ShadowLedger {
    #[must_use]
    pub const fn new() -> Self {
        Self { allow_observed: 0, allow_disagreed: 0, mode: AcceptanceMode::Shadow }
    }

    pub fn record(&mut self, relying_party_would_deny: bool) -> Option<()> {
        self.allow_observed = self.allow_observed.checked_add(1)?;
        if relying_party_would_deny {
            self.allow_disagreed = self.allow_disagreed.checked_add(1)?;
        }
        Some(())
    }

    /// Hoeffding upper confidence bound p_hat + sqrt(ln(1/alpha) / (2n)), in Q16.16.
    #[must_use]
    pub fn upper_confidence_bound(&self, t: &GraduationThresholds) -> Option<FixedQ16_16> {
        let n = i64::from(self.allow_observed);
        if n <= 0 {
            return None;
        }
        let p_hat = i64::from(self.allow_disagreed).checked_shl(16)?.checked_div(n)?;
        let variance_term = i64::from(t.ln_inverse_alpha.0).checked_div(n.checked_mul(2)?)?;
        let radicand = u64::try_from(variance_term).ok()?.checked_shl(16)?;
        let root = i64::try_from(isqrt_u64(radicand)).ok()?;
        i32::try_from(p_hat.checked_add(root)?).ok().map(FixedQ16_16)
    }

    /// Evidence may lower the mode immediately; it may raise it by one step per call.
    pub fn graduate(&mut self, t: &GraduationThresholds) -> Option<AcceptanceMode> {
        if self.allow_observed < t.min_samples {
            return Some(self.mode);
        }
        let ub = self.upper_confidence_bound(t)?;
        let evidence = if ub <= t.max_disagreement_active {
            AcceptanceMode::Active
        } else if ub <= t.max_disagreement_advisory {
            AcceptanceMode::Advisory
        } else {
            AcceptanceMode::Shadow
        };
        let one_step_up = match self.mode {
            AcceptanceMode::Shadow => AcceptanceMode::Advisory,
            AcceptanceMode::Advisory | AcceptanceMode::Active => AcceptanceMode::Active,
        };
        self.mode = if evidence <= one_step_up { evidence } else { one_step_up };
        Some(self.mode)
    }

    /// Any AutonomousDriftKind alarm applies SwitchToSafeState on the relying-party side.
    pub fn on_drift_alarm(&mut self) {
        *self = Self::new();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PremiumSchedule {
    /// Currency per cost unit.
    pub unit_value: FixedQ16_16,
    /// Base rate beta.
    pub base_rate: FixedQ16_16,
    /// Scarcity load gamma applied to the maximum committed shadow price.
    pub scarcity_load: FixedQ16_16,
}

/// premium = beta * V + gamma * lambda_max * V, with V = unit_value * cost_units.
/// Requires cost_units <= 32_767, which the relying-party cap enforces upstream.
#[must_use]
pub fn quote_premium(s: &PremiumSchedule, body: &RelyingPartyReceiptBodyV1) -> Option<FixedQ16_16> {
    let units = FixedQ16_16::from_int(i32::try_from(body.cost_units).ok()?)?;
    let exposure = units.checked_mul(s.unit_value)?;
    let n = usize::from(body.lagrangian.price_count);
    let lambda_max = body
        .lagrangian
        .lambda
        .iter()
        .take(n)
        .copied()
        .max()
        .unwrap_or(FixedQ16_16::ZERO);
    let base = s.base_rate.checked_mul(exposure)?;
    let load = s.scarcity_load.checked_mul(lambda_max)?.checked_mul(exposure)?;
    base.checked_add(load)
}
```

**Pricing models.** The receipt is priced differently by each relying-party class because each class replaces a different cost center.

| Relying party | What the receipt replaces | Pricing model | Fields that price it |
| --- | --- | --- | --- |
| Payment rail | Per-transfer fraud or compliance review | Basis points on receipted settlement volume; settlement admitted only on Allow with verified evidence, as `settlement_admission_requires_verified_evidence` already mechanizes | cost units, ledger triple, decision, treaty vector |
| API provider | Blanket per-key rate limits | Receipted calls earn elevated quota; the operator pays a per-receipt attestation fee; the provider pays nothing and gains attribution | capability root, policy IR hash, revocation epoch |
| Insurer | Underwriting an opaque agent | Premium from `quote_premium`; bond sized by Theorem 5; claims adjudicated against the rationality witness | Lagrangian witness, cost units, model version hash |
| Enterprise IT | Change advisory tickets | Per-kernel license plus Copley predicate packs; verifying receipts auto-close change records | containment attestation, activation hash, treaty vector |
| Verifier service | Nothing today | V0 and V1 open and free; V2 metered per receipt; V3 priced on evidence escrow storage | all |

The operator pays for receipts as the cost of market access. The relying party's gain is review cost avoided times acceptance rate, minus residual loss, and Theorem 5 is what caps the residual loss.

**Theorem 5 (Bounded aggregate exposure under pooled swarm budgets).** Let a swarm draw on a pool of capacity $B$ through `reserve_swarm_budget_fanout` and `release_swarm_budget_fanin`, and let the relying party's exposure on an accepted Allow receipt be at most its cost units. Then total exposure over all accepted Allow receipts of the swarm is at most $B$.

*Proof.* `ReservationConservation` holds at every reachable state of the post-admission model: $\sum_i r_i + \mathrm{free} = B$ with nonnegative terms, so $\sum_i r_i \le B$. A child's Allow receipt carries a cost committed by `budget_commit`, which succeeds only if `budget_precheck` passed against that child's remaining units, so $\mathrm{cost}_i \le r_i$; `verify_reservation_ledger_conservation` discharges the bounded instance in Kani. `TerminalReceiptExactlyOne` gives at most one terminal receipt per reservation. Summing, $\sum_i \mathrm{cost}_i \le \sum_i r_i \le B$. $\blacksquare$

**Proposition 6 (Rationality witness and premium coherence).** If `chosen_no_worse_than_conservative` returns true, then $L_\lambda(s, a^*) \le L_\lambda(s, \bot_s)$ under the committed $\lambda \ge 0$. Both sides are evaluated in Q16.16 with truncation toward negative infinity by the same function on kernel and verifier, so the inequality is bit-exact reproducible on every target. The premium $\beta V + \gamma \lambda_{\max} V$ is nonnegative and monotone in exposure $V$ and in scarcity $\lambda_{\max}$.

*Proof.* The inequality is the checked evaluation itself, and determinism follows from fixed-point arithmetic having no platform-dependent rounding. Nonnegativity and monotonicity follow from $\beta, \gamma, V, \lambda_{\max} \ge 0$, where $\lambda \ge 0$ is dual feasibility checked field-wise. $\blacksquare$

The practical consequence for insurers is that a claim can be adjudicated against the kernel's own scarcity judgment at decision time. An insurer that covers only receipts satisfying the rationality witness is never worse off than if the kernel had taken the conservative action, under the prices the kernel itself committed.

## 2. Architectural Comparison with OpenShell-Style Sandboxed Runtimes

I treat OpenShell-style runtimes as the class publicly described around NVIDIA's agent stack: an isolation boundary per agent, declarative policy over filesystem, network, and tool reach, an egress or privacy router for model traffic, and an audit log, with inference running adjacent to the GPU. Product capabilities in this space change quarterly, so the comparison is at the pattern level and specific feature claims should be checked against current documentation.

| Dimension | Sandboxed runtime | Governed kernel plus Copley |
| --- | --- | --- |
| Primary guarantee | Containment: the process cannot reach beyond its declared surface | Admission: each action is authorized, budgeted, feasible, and receipted before effect |
| Policy form | Declarative allow and deny over hosts, paths, tools | Capability tokens with attenuation proofs, HushSpec IR with refinement checking, feasibility map $F(s)$ |
| Semantic coverage | Syntactic matching | Calibrated atomic predicates composed by a boolean DAG with exact witnesses |
| Learned components | None in the enforcement path, or opaque | $\pi_\theta$ proposes only inside $F(s)$; conservative fallback proven present |
| Evidence | Operator-held audit log, written after the fact | Pre-effect signed receipt, Merkle-committed, verifiable by third parties |
| Multi-agent | Per-sandbox | Task DAG verified before any child runs; pooled budgets with conservation proof |
| Economics | None | Shadow prices, metering, settlement, underwriting |
| Determinism | Not a design goal | `no_std` core, fixed-point, WCET-bounded Tier-0 |
| Formal verification | None public | Lean 4, Aeneas, Apalache, Kani, Loom, deterministic simulation |
| Isolation strength | Strong and mature | `chio-cage` is adequate but is not the differentiator |
| Inference adjacency | Native | Through provider adapters |

**Three differences matter to a relying party.** First, containment is invisible from outside. A payment rail cannot inspect the sandbox the agent ran in, so containment adds nothing to the rail's decision unless its measurement is carried in a verifiable artifact. The receipt's containment attestation field does exactly that, which makes the two systems complementary rather than substitutes. Second, an audit log is controlled by the party whose behavior it describes, and it is written after the effect. The receipt is fixed before the effect by `ReceiptBeforeAllow`, signed, and committed to an append-only log whose checkpoints the relying party can pin. Third, allow lists cannot express the predicates relying parties care about, such as whether a transfer memo semantically matches an approved invoice or whether a file operation targets a path equivalent under normalization to a protected root. Copley's predicate heads capture these patterns, and the DAG keeps the final word symbolic and witnessed, so the neural layer never has unshielded authority.

**Where the sandbox wins.** Isolation engineering, GPU locality, language runtime breadth, and operator familiarity. Chio should not compete on any of these. The kernel's job is to decide and attest, and the sandbox's job is to contain, and both are needed.

## 3. Integration versus Competition

| Option | Where Chio runs | Receipt point | Strengths | Weaknesses |
| --- | --- | --- | --- | --- |
| I1 Sidecar inside the sandbox | As the tool-call fabric within the agent's sandbox | At each tool call | Easy adoption; no network change | Sandbox operator controls both layers, so relying parties need attestation to trust it |
| I2 Egress gateway | Outside the sandbox, in the network path relying parties already see | At the trust boundary | Boundary matches the relying party's view; sandbox is treated as untrusted | Needs network placement and a latency budget |
| I3 Verifier only | At the relying party | None; verifies receipts from any conforming emitter | Sets the standard; zero footprint on the agent stack | Depends on emitters existing |
| C1 Full runtime | Replaces the sandbox | Everywhere | Full control | Fights on isolation and ecosystem, where sandboxes lead |

**Recommendation.** Pursue I2 and I3 together and ship I1 as an emitter plugin for OpenShell-style runtimes. Never pursue C1. The egress gateway is where receipts are generated at the boundary relying parties see, which is the wedge. The verifier SDK makes the receipt schema the thing relying parties ask for, which converts every sandbox vendor into a potential emitter rather than a competitor. The emitter plugin has three natural hooks. The sandbox's egress router is the interception point, through `chio-envoy-ext-authz` or the Tower middleware. The sandbox's policy file compiles into HushSpec through `chio-policy`, so there is one policy source rather than two drifting ones. The sandbox's image and policy measurement becomes the containment attestation field, so relying parties see both containment and admission in one artifact.

If a sandbox vendor adds signed decision logs, that overlaps V0 only. The defensible layers are the feasibility envelope with its proven fallback, the Copley predicate packs with their calibrated false-alarm rates, the economic layer that makes receipts priceable, and the verifier network effect. Open the schema and conformance suite, and keep the kernel, the packs, and the verifier service as the product.

## 4. Twelve-Month Product Wedge

| Quarter | Deliverables | Measurable exit criteria |
| --- | --- | --- |
| Months 1 to 3: verifiable receipt | Schema v1 frozen; `no_std` verifier crate with a `wasm32` build and TypeScript and Python bindings; malformed-receipt negative registry mirroring the Apalache mutant discipline; one payment-rail design partner in Shadow | V1 verification p99 under 1 ms on the partner's verifier host; artifact under 4 KB at tree size $2^{24}$; every registry mutant rejected with its expected `ReceiptRejection` variant; at least 100,000 Shadow receipts captured |
| Months 4 to 6: trust roots | Attestation binding of kernel measurement to signing key; federation cross-signing; revocation oracle epoch feed; insurer pilot pricing from the Lagrangian witness; API-provider receipted-quota pilot | One relying party reaches Advisory under Theorem 4 with $\delta$ at 0.5% and $\alpha$ at 0.01; revocation epoch propagation p99 under 2 s; 100% of partner receipts carry a non-zero containment attestation |
| Months 7 to 9: treaties and predicates | Treaty predicate language live with relying-party-authored predicates evaluated in-kernel; Copley predicate pack for finance operations; OpenShell-style emitter plugin; swarm terminal receipts accepted by the verifier | At least 20 relying-party-authored predicates in production; pack F1 at least 93% with false-alarm rate at most 1.2% on the partner's sealed validation split; emitter passes the published conformance suite |
| Months 10 to 12: market | Active acceptance at the payment rail; receipt-gated settlement through `chio-settle`; operator bonding sized by Theorem 5; priced V2 and V3 tiers | At least three relying parties Active; zero Allow effects without a verifying receipt in audit; loss ratio under the insurer's underwriting threshold; agreed receipted settlement volume reached |

**Risks and their controls.**

- **Attestation dependency.** If hardware attestation slips, Months 4 to 6 fall back to operator liability as the root, and Theorem 4 still governs graduation. Exposure caps stay low until attestation lands.
- **Schema churn.** Freeze v1 in Month 3 and version by field addition only. The verifier rejects unknown schema versions rather than guessing.
- **Relying parties want their own kernel.** This is a win, not a loss. The co-kernel pattern lets the relying party re-evaluate under its own policy with the agent-side receipt as an observed fact, and the treaty field already encodes that relationship.
- **Vendor adds signed logs.** This validates the category and overlaps V0 only. Respond by publishing the conformance suite early so the vendor becomes an emitter.

**Recap.** Deterministic receipts let a relying party accept an autonomous action on the basis of the process that produced it rather than the key that sent it. The receipt binds the canonical action, the governing artifacts, the feasibility envelope with its proven conservative fallback, the ledger delta, the committed shadow prices, and the relying party's own treaty predicates, and it is fixed before any effect and committed to a verifiable log. Verification is constant in agents, models, and swarm size, so it fits inside a payment rail's or API gateway's latency budget. Trust bootstraps through liability, attestation, federation, and treaties, with graduation governed by a Hoeffding bound and reset by drift alarms. Exposure is capped by pooled-budget conservation, and insurers can price and adjudicate against the kernel's own rationality witness. Against OpenShell-style runtimes the right posture is complementary: let the sandbox contain, let the kernel decide and attest, carry the sandbox's measurement in the receipt, and make the open receipt schema the thing relying parties demand. The next step is the Month 1 to 3 benchmark that turns the target envelope in the cost table into measured numbers.