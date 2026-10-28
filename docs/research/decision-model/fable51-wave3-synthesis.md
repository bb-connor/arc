# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 3 Synthesis

- **Timestamp**: `20261025-010322 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `1668.76s` across 4 parallel passes
- **Total Output**: `108,894` characters (`14,037` words)
- **Claude Max Quota Before Wave 3**: 5-hour `39.0%` | 7-day `78.0%`
- **Claude Max Quota After Wave 3**: 5-hour `58.0%` | 7-day `82.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave3_angle_1_lean4_and_apalache_mechanized_proofs` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `0` | `0` | `1668.75` |
| `wave3_angle_2_tier0_micro_models_and_dual_controller` | `0` | `success` | `['claude-fable-5-1']` | `none` | `616` | `5,144` | `831.61` |
| `wave3_angle_3_copley_ultrabert_4segment_encoder_bridge` | `1` | `error_max_budget_usd` | `['claude-fable-5-1']` | `none` | `6,941` | `54,553` | `1104.08` |
| `wave3_angle_4_linux_ebpf_lsm_omarchy_macos_enforcement` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6,480` | `49,197` | `619.09` |

---

# Verbatim Treatise - `wave3_angle_1_lean4_and_apalache_mechanized_proofs`



---

# Verbatim Treatise - `wave3_angle_2_tier0_micro_models_and_dual_controller`

| RecoveryGraphRanker | open set, one work unit per call | yes | `Exhausted` |
| PheromoneRouteSelector | routes, one shift plus one multiply each | one `from_ratio_u64` per route | base route or `Hold` |
| KvContextTierEvictor | blocks, one division per unknown block | partial | `Hold` |

All `checked_*` paths that return `None` collapse to the fallback rather than to a panic, so none of the seven entry points can unwind. Kani checks arithmetic overflow and slice bounds on every harness by default, so the harnesses above also serve as panic-freedom proofs for the covered input shapes.

**Manifest additions.** The additions below are new tables only. No existing `[[harness]]` or `[[lean]]` entry is edited, so every pinned signature in `formal_core.rs` and `formal_aeneas.rs` keeps its existing proof.

```toml
# formal/proof-manifest.toml (appended)
[[kani]]
crate = "chio-kernel-core"
harnesses = [
  "tier0::shadow_price::verification::projection_keeps_box_for_any_residual",
  "tier0::admission_quota::verification::proposal_never_oversubscribes",
  "tier0::guard_order::verification::output_is_sorted_permutation",
  "tier0::swarm_branch::verification::select_respects_envelope",
  "tier0::swarm_branch::verification::sprt_verdict_matches_thresholds",
  "tier0::recovery_rank::verification::pick_is_admissible_and_metered",
  "tier0::pheromone_route::verification::selected_route_is_feasible",
  "tier0::pheromone_route::verification::decay_is_contractive_on_unit_interval",
  "tier0::kv_evict::verification::never_evicts_pinned_and_never_holds_when_unpinned_exists",
  "tier0::kv_evict::verification::quota_never_exceeds_unpinned",
]

[[lean]]
module = "Chio.Tier0.Clamp"
theorems = ["Chio.Tier0.clampZ_mem", "Chio.Tier0.clampZ_idem"]
aeneas_source = "crates/kernel/chio-kernel-core/src/tier0/fixed.rs::FixedQ16_16::clamp_to"

[[apalache]]
module = "formal/tla/Tier0SprtGate.tla"
invariant = "GateSafe"
length = 64
```

**Cross-crate pin for the task cap.** `chio-swarm-authority` depends on `chio-kernel-core`, not the reverse, so the branch controller carries its own copy of the task cap. One line in `chio-swarm-authority/src/types.rs` keeps the two from drifting:

```rust
const _: () = assert!(MAX_SWARM_GRAPH_TASKS == chio_kernel_core::tier0::swarm_branch::TIER0_MAX_BRANCH_TASKS as usize);
```

**Wiring points.** Each caller passes its own slice and reads back a `Shielded` value or a plain enum whose feasibility the harness already covers.

- `BudgetSplit::admit_child` in `budget_split.rs` calls `AdmissionQuotaScorer::propose` to size the share before the existing checks run. Those checks stay in place as a second, independent line of defense.
- `TwoPhaseGuardPipeline` calls `GuardScheduleOrderer::order` once per phase and iterates `guards` through the returned permutation. The fold in `GuardPipeline::check` is unchanged.
- The swarm scheduler calls `select` before appending a task and `SprtGate::observe` after each join receipt. `Hold` maps to `SwarmContinuationToken` retention rather than a new task.
- `chio-recovery` constructs `WorkBudget::from_planner_limit` from its `PlannerLimitsV1::Work` and threads it through the open-set loop.
- `chio-pheromone` stores `RouteState` per route and calls `select` on each dispatch tick. The base route is the deterministic policy already shipped.
- The context tier calls `eviction_quota` once per pressure event and then `choose_victim` that many times, removing each victim from the slice between calls.

**Shadow-price feed.** The five `usage` and `capacity` inputs to `ShadowPriceVector::update` come from exact counters. Budget and escrow come from `ReservationLedger` fields and `budget_commit` results. Fuel comes from `SwarmBudgetPool`. Latency and memory come from the kernel's own tick and residency counters. Both inputs are normalized to fractions of capacity in Q16.16 so that the residual $g_t$ is dimensionless and the regret constant $G$ in Theorem 1 is bounded by $\sqrt5$ times the largest admissible overshoot ratio.

**What this delivers and what remains.** The module gives `chio-kernel-core` a complete `no_std`, panic-free Tier-0 layer. The seven units are the fixed-point type, the dual controller, and the six micro-models. Each has an exact envelope function, a learned scorer projected into that envelope, unit tests, and Kani harnesses that quantify over every learned input. Each also has a stated theorem with proof: bounded dual regret, envelope safety for admission, ratio-rule optimality with pipeline order invariance, Weitzman and Wald correctness, bounded work with bounded suboptimality, Whittle index closed form with indexability, and Belady optimality on the known subset.

Two things are not done in this treatise. The Lean lemma covers only the projection step. Aeneas extraction of the full `FixedQ16_16` arithmetic, so that `checked_mul` flooring and `saturating_mul` are also mirrored in Lean, is the natural Wave 3 Angle 3 follow-on. The Apalache module uses unbounded integers. A bounded-width refinement that matches the `i32` raw type would let the TLA+ invariant and the Kani harness be cross-checked bit-for-bit.

---

# Verbatim Treatise - `wave3_angle_3_copley_ultrabert_4segment_encoder_bridge`

I'm writing Wave 3 Angle 3 as a new `#![no_std]` crate, `chio-copley-bridge`, plus the additive kernel and guard hooks, with Lean 4, Apalache and Kani artifacts that discharge each claim.

**Outcome up front.** The bridge sits entirely inside the predictor $P_\ell$ of the Wave 1 tuple. Everything around the 537 learned scores is an exact computation $C_\ell$: canonical serialization, SHA-256 commitment, seqlock-consistent cache reads, threshold classification, and DAG rule evaluation. Six results are proved below.

- **Theorem 1.** The canonical frame encoding is injective and bounded, so `segment_input_digest` commits to exactly one projection.
- **Theorem 2.** A cache hit returns the vector a fresh evaluation would return, given SHA-256 collision resistance and the Apalache-checked seqlock invariant.
- **Theorem 3.** Verdicts are upward-closed in the Kleene information order, so a timeout fallback of all $\bot$ can never allow what the full evaluation would deny or hold.
- **Theorem 4.** Every hot-path function has a constant operation bound and the wait loop overshoots the deadline by at most one poll.
- **Theorem 5.** Role-asymmetric thresholds with $\tau^{\text{neg}}_j \le \tau^{\text{pos}}_j$ partition the score line into a strict three-valued classifier with a conformal error bound per role.
- **Theorem 6.** No existing Lean, Aeneas, Apalache or Kani proof needs to change, because they already quantify over every element of $\mathbb{K}_3^{537}$.

The crate boundary is fixed by this table.

| Component | Kind | Where |
|---|---|---|
| Canonical projection, frame, digest | exact $C_\ell$ | `segments.rs` |
| Epoch cache, seqlock, breaker, ring protocol | exact $C_\ell$ | `cache.rs`, `sidecar.rs` |
| Threshold table, 236-rule DAG, verdict map | exact $C_\ell$, data signed | `calibration.rs` |
| 537 scores from 4-segment UltraBERT | learned $P_\ell$ | Copley sidecar process |
| `Deny` / `PendingApproval` floor | envelope $\Pi_{\mathcal{C}_\ell}$ | `GuardPipeline` as it exists |

Shared crate root:

```rust
//! crates/security/chio-copley-bridge/src/lib.rs
#![
no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub mod segments;
pub mod cache;
pub mod sidecar;
pub mod calibration;

pub const PREDICATE_COUNT: usize = 537;
pub const RULE_COUNT: usize = 236;
pub const SEGMENT_PREDICATES: [u16; 4] = [345, 97, 57, 38];

/// SHA-256 output. The bridge never hashes itself; the host injects a hasher.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Digest32(pub [u8; 32]);

/// Implemented in `chio-weights` for `sha2::Sha256`; keeps this crate dependency-free.
pub trait Sha256Hasher {
    fn update(&mut self, bytes: &[u8]);
    fn finalize(self) -> [u8; 32];
}

/// Strong Kleene logic. `Unknown` is the information-order bottom ⊥.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u8)]
pub enum Kleene3 { Unknown = 0, False = 1, True = 2 }

impl Kleene3 {
    pub const fn code(self) -> u8 { self as u8 }
    pub const fn from_code(c: u8) -> Option<Self> {
        match c { 0 => Some(Self::Unknown), 1 => Some(Self::False), 2 => Some(Self::True), _ => None }
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
    pub const fn not(self) -> Self {
        match self { Self::True => Self::False, Self::False => Self::True, Self::Unknown => Self::Unknown }
    }
    /// Information order ⊑: `Unknown ⊑ x` for every `x`, otherwise reflexive.
    pub const fn refines(self, upper: Self) -> bool {
        matches!(self, Self::Unknown) || self.code() == upper.code()
    }
}
```

## 1. Canonical 4-Segment Serializer

**Design.** A projection borrows four byte slices from the kernel's existing canonical forms and never copies them. Each slice is clamped to a per-segment cap, and the clamp is recorded in a header flag so a truncated frame can never collide with a short untruncated one. The frame is `magic || version || flags || reserved || 4 × (u32 LE length || bytes)`. The digest is SHA-256 over a domain tag followed by exactly those frame bytes. Hashing and frame writing share one visitor, so the committed bytes and the transmitted bytes are identical by construction rather than by convention.

| Segment | Cap | Chio source |
|---|---|---|
| `CommandLine` | 4096 B | canonical action bytes of `EvaluateInput` |
| `Image` | 512 B | capability subject and tool identity from `GuardContext` |
| `OriginalFileName` | 256 B | `chio-flow::InformationLabel` canonical encoding |
| `ParentImage` | 512 B | parent-chain digest, `parent_token_id`, quantized `chio-pheromone` trail |

```rust
//! crates/security/chio-copley-bridge/src/segments.rs
use crate::{Digest32, Sha256Hasher};

pub const SEGMENT_COUNT: usize = 4;
pub const MAX_SEGMENT_BYTES: [usize; SEGMENT_COUNT] = [4096, 512, 256, 512];
pub const FRAME_MAGIC: [u8; 4] = *b"CPL1";
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_BYTES: usize = 8;
pub const FRAME_LEN_PREFIX_BYTES: usize = 4;
/// 8 + 4·4 + 4096 + 512 + 256 + 512
pub const MAX_FRAME_BYTES: usize = 5_400;
const DOMAIN_TAG: &[u8] = b"chio-copley-segments-v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SegmentKind { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

impl SegmentKind {
    pub const fn cap(self) -> usize { MAX_SEGMENT_BYTES[self as usize] }
}

/// Borrowed, bounded view. No bytes are copied; truncation is recorded.
#[derive(Clone, Copy, Debug)]
pub struct SegmentView<'a> { bytes: &'a [u8], truncated: bool }

impl<'a> SegmentView<'a> {
    pub fn bounded(kind: SegmentKind, raw: &'a [u8]) -> Self {
        let cap = kind.cap();
        if raw.len() <= cap { return Self { bytes: raw, truncated: false }; }
        match raw.get(..cap) {
            Some(prefix) => Self { bytes: prefix, truncated: true },
            None => Self { bytes: &[], truncated: true },
        }
    }
    pub const fn truncated(&self) -> bool { self.truncated }
}

/// Implemented in `chio-guards` over `(EvaluateInput, GuardContext, InformationLabel, PheromoneSnapshot)`.
pub trait SegmentSource {
    fn command_line(&self) -> &[u8];
    fn image(&self) -> &[u8];
    fn original_file_name(&self) -> &[u8];
    fn parent_image(&self) -> &[u8];
}

#[derive(Clone, Copy, Debug)]
pub struct CanonicalProjection<'a> { segments: [SegmentView<'a>; SEGMENT_COUNT] }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError { OutputTooSmall }

impl<'a> CanonicalProjection<'a> {
    pub fn project<S: SegmentSource + ?Sized>(src: &'a S) -> Self {
        Self { segments: [
            SegmentView::bounded(SegmentKind::CommandLine, src.command_line()),
            SegmentView::bounded(SegmentKind::Image, src.image()),
            SegmentView::bounded(SegmentKind::OriginalFileName, src.original_file_name()),
            SegmentView::bounded(SegmentKind::ParentImage, src.parent_image()),
        ] }
    }

    /// Bit i set iff segment i was truncated. Committed by the digest.
    pub fn flags(&self) -> u8 {
        let mut f = 0u8;
        for (i, s) in self.segments.iter().enumerate() {
            if s.truncated {
                f |= u32::try_from(i).ok().and_then(|sh| 1u8.checked_shl(sh)).unwrap_or(0);
            }
        }
        f
    }

    /// The single source of canonical bytes for both hashing and framing.
    pub fn visit_canonical<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&FRAME_MAGIC);
        f(&[FRAME_VERSION, self.flags(), 0, 0]);
        for s in &self.segments {
            let len = u32::try_from(s.bytes.len()).unwrap_or(u32::MAX);
            f(&len.to_le_bytes());
            f(s.bytes);
        }
    }

    pub fn canonical_len(&self) -> usize {
        self.segments.iter().fold(FRAME_HEADER_BYTES, |acc, s| {
            acc.saturating_add(FRAME_LEN_PREFIX_BYTES).saturating_add(s.bytes.len())
        })
    }

    /// `SHA-256(DOMAIN_TAG || frame)`; no intermediate buffer.
    pub fn segment_input_digest<H: Sha256Hasher>(&self, mut h: H) -> Digest32 {
        h.update(DOMAIN_TAG);
        self.visit_canonical(|chunk| h.update(chunk));
        Digest32(h.finalize())
    }

    /// Writes the frame into a caller-provided buffer, typically a shared ring slot.
    pub fn write_frame(&self, out: &mut [u8]) -> Result<usize, FrameError> {
        let mut cursor = 0usize;
        let mut err = None;
        self.visit_canonical(|chunk| {
            if err.is_some() { return; }
            let end = cursor.checked_add(chunk.len());
            match end.and_then(|e| out.get_mut(cursor..e).map(|dst| (dst, e))) {
                Some((dst, e)) => { dst.copy_from_slice(chunk); cursor = e; }
                None => err = Some(FrameError::OutputTooSmall),
            }
        });
        match err { Some(e) => Err(e), None => Ok(cursor) }
    }
}
```

**Theorem 1, canonical encoding.** Let $E(p)$ be the byte string produced by `visit_canonical`. Then $|E(p)| \le$ `MAX_FRAME_BYTES`, and $E(p) = E(p')$ implies equal flags and pairwise equal segment bytes.

*Proof.* The header is fixed at 8 bytes and each segment contributes a 4-byte prefix plus at most its cap, which sums to the constant. Injectivity follows from the Lean lemma below applied four times after stripping the equal-length header with `List.append_inj`. $\square$

```lean
-- formal/lean4/Chio/Copley/Segments.lean
namespace Chio.Copley

structure LenCodec where
  enc    : Nat → List UInt8
  len_eq : ∀ n, (enc n).length = 4
  inj    : ∀ {m n}, m < 2^32 → n < 2^32 → enc m = enc n → m = n

def encodeSeg (c : LenCodec) (s : List UInt8) : List UInt8 := c.enc s.length ++ s

theorem encodeSeg_append_inj (c : LenCodec) {s₁ s₂ t₁ t₂ : List UInt8}
    (h₁ : s₁.length < 2^32) (h₂ : s₂.length < 2^32)
    (h : encodeSeg c s₁ ++ t₁ = encodeSeg c s₂ ++ t₂) : s₁ = s₂ ∧ t₁ = t₂ := by
  unfold encodeSeg at h
  rw [List.append_assoc, List.append_assoc] at h
  have hl : (c.enc s₁.length).length = (c.enc s₂.length).length := by
    rw [c.len_eq, c.len_eq]
  obtain ⟨hpre, hrest⟩ := List.append_inj h hl
  exact List.append_inj hrest (c.inj h₁ h₂ hpre)

end Chio.Copley
```

Truncation deserves one exact rule. An adversary can push payload past the 4096-byte `CommandLine` cap, so truncation of that segment is treated as an exact deny-class predicate in the guard adapter, never as something the model is asked to notice.

## 2. Lock-Free Epoch Cache & Timeout-Bounded Sidecar Protocol

**Cache design.** The key is the 96-byte concatenation of the three digests, split into 12 words. Values are 537 two-bit Kleene codes packed into 17 words. Each slot is a seqlock built only from `core::sync::atomic` types, which is what lets the crate keep `#![forbid(unsafe_code)]`. The fence pattern is the Boehm seqlock encoding. A global epoch counter gives O(1) invalidation of every entry at rebind, as defense in depth over the key already containing both digests.

```rust
//! crates/security/chio-copley-bridge/src/cache.rs
use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use crate::{Digest32, Kleene3, PREDICATE_COUNT};

pub const KEY_WORDS: usize = 12;
pub const VALUE_WORDS: usize = 17;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CacheKey { pub words: [u64; KEY_WORDS] }

impl CacheKey {
    pub fn new(segment: &Digest32, model_card: &Digest32, calibration: &Digest32) -> Self {
        let mut words = [0u64; KEY_WORDS];
        let mut it = words.iter_mut();
        for part in [segment, model_card, calibration] {
            for chunk in part.0.chunks_exact(8) {
                if let (Some(w), Ok(arr)) = (it.next(), <[u8; 8]>::try_from(chunk)) {
                    *w = u64::from_le_bytes(arr);
                }
            }
        }
        Self { words }
    }
    /// Word 0 is 64 uniform bits of SHA-256 output.
    pub fn slot(&self, mask: usize) -> usize {
        let w = self.words.first().copied().unwrap_or(0);
        (w as usize) & mask
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PredicateVector { words: [u64; VALUE_WORDS] }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexOutOfRange;

impl PredicateVector {
    pub const UNKNOWN: Self = Self { words: [0u64; VALUE_WORDS] };
    pub const fn from_words(words: [u64; VALUE_WORDS]) -> Self { Self { words } }
    pub const fn words(&self) -> [u64; VALUE_WORDS] { self.words }

    fn locate(j: usize) -> Option<(usize, u32)> {
        if j >= PREDICATE_COUNT { return None; }
        let word = j.checked_shr(5)?;
        let shift = u32::try_from(j & 31).ok()?.checked_mul(2)?;
        Some((word, shift))
    }
    pub fn get(&self, j: usize) -> Option<Kleene3> {
        let (w, s) = Self::locate(j)?;
        let bits = self.words.get(w)?.checked_shr(s)? & 0b11;
        Kleene3::from_code(u8::try_from(bits).ok()?)
    }
    pub fn set(&mut self, j: usize, v: Kleene3) -> Result<(), IndexOutOfRange> {
        let (w, s) = Self::locate(j).ok_or(IndexOutOfRange)?;
        let word = self.words.get_mut(w).ok_or(IndexOutOfRange)?;
        let mask = 0b11u64.checked_shl(s).ok_or(IndexOutOfRange)?;
        let val = u64::from(v.code()).checked_shl(s).ok_or(IndexOutOfRange)?;
        *word = (*word & !mask) | val;
        Ok(())
    }
}

pub struct EpochSlot {
    seq: AtomicU64,   // even = stable, odd = write in progress
    epoch: AtomicU32,
    key: [AtomicU64; KEY_WORDS],
    value: [AtomicU64; VALUE_WORDS],
}

impl EpochSlot {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            epoch: AtomicU32::new(0),
            key: [const { AtomicU64::new(0) }; KEY_WORDS],
            value: [const { AtomicU64::new(0) }; VALUE_WORDS],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InsertOutcome { Stored, Contended }
impl InsertOutcome { pub const fn is_stored(self) -> bool { matches!(self, Self::Stored) } }

pub struct EpochCache<const SLOTS: usize> { epoch: AtomicU32, slots: [EpochSlot; SLOTS] }

impl<const SLOTS: usize> EpochCache<SLOTS> {
    pub const MASK: usize = { assert!(SLOTS.is_power_of_two()); SLOTS.saturating_sub(1) };

    /// Epoch starts at 1 and slots at 0, so every slot begins invalid.
    pub const fn new() -> Self {
        Self { epoch: AtomicU32::new(1), slots: [const { EpochSlot::new() }; SLOTS] }
    }

    /// O(1) bulk invalidation at provider rebind.
    pub fn rebind(&self) -> u32 { self.epoch.fetch_add(1, Ordering::AcqRel).wrapping_add(1) }

    /// Seqlock read: 34 atomic loads at most, no loops with data-dependent bounds.
    pub fn lookup(&self, key: &CacheKey) -> Option<PredicateVector> {
        let slot = self.slots.get(key.slot(Self::MASK))?;
        let s1 = slot.seq.load(Ordering::Acquire);
        if (s1 & 1) == 1 { return None; }
        if slot.epoch.load(Ordering::Relaxed) != self.epoch.load(Ordering::Acquire) { return None; }
        for (cell, want) in slot.key.iter().zip(key.words.iter()) {
            if cell.load(Ordering::Relaxed) != *want { return None; }
        }
        let mut words = [0u64; VALUE_WORDS];
        for (w, cell) in words.iter_mut().zip(slot.value.iter()) { *w = cell.load(Ordering::Relaxed); }
        fence(Ordering::Acquire);
        let s2 = slot.seq.load(Ordering::Relaxed);
        if s1 == s2 { Some(PredicateVector { words }) } else { None }
    }

    /// Seqlock write. Writers never spin: a contended slot is simply skipped.
    pub fn insert(&self, key: &CacheKey, value: &PredicateVector) -> InsertOutcome {
        let Some(slot) = self.slots.get(key.slot(Self::MASK)) else { return InsertOutcome::Contended };
        let s = slot.seq.load(Ordering::Relaxed);
        if (s & 1) == 1 { return InsertOutcome::Contended; }
        if slot.seq.compare_exchange(s, s.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed).is_err() {
            return InsertOutcome::Contended;
        }
        slot.epoch.store(self.epoch.load(Ordering::Acquire), Ordering::Relaxed);
        for (cell, w) in slot.key.iter().zip(key.words.iter()) { cell.store(*w, Ordering::Relaxed); }
        for (cell, w) in slot.value.iter().zip(value.words.iter()) { cell.store(*w, Ordering::Relaxed); }
        slot.seq.store(s.wrapping_add(2), Ordering::Release);
        InsertOutcome::Stored
    }
}
```

**Sidecar protocol.** On a miss the Tier-1 path writes the frame straight into a `#[repr(C)]` ring slot of atomics, which the host maps into the Copley process. The sidecar mirrors the state machine: it CASes `SUBMITTED` to `CLAIMED`, recomputes the digest over the payload and rejects a mismatch, runs the encoder on the four segments, thresholds with the bound calibration table, writes the 17 result words, and stores `DONE`. Time enters only as caller-supplied monotonic ticks, so every path is deterministic and testable.

```rust
//! crates/security/chio-copley-bridge/src/sidecar.rs
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use crate::cache::{CacheKey, EpochCache, PredicateVector, VALUE_WORDS};
use crate::segments::{CanonicalProjection, MAX_FRAME_BYTES};
use crate::{Digest32, Sha256Hasher};

pub type Ticks = u64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BreakerState { Closed, Open { until: Ticks }, HalfOpen { probe_in_flight: bool } }

pub struct CircuitBreaker {
    state: BreakerState,
    consecutive_failures: u32,
    failure_threshold: u32,
    cooldown: Ticks,
}

impl CircuitBreaker {
    pub const fn new(failure_threshold: u32, cooldown: Ticks) -> Self {
        Self { state: BreakerState::Closed, consecutive_failures: 0, failure_threshold, cooldown }
    }
    pub fn permits(&mut self, now: Ticks) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open { until } if now >= until => {
                self.state = BreakerState::HalfOpen { probe_in_flight: true };
                true
            }
            BreakerState::Open { .. } => false,
            BreakerState::HalfOpen { probe_in_flight: false } => {
                self.state = BreakerState::HalfOpen { probe_in_flight: true };
                true
            }
            BreakerState::HalfOpen { .. } => false,
        }
    }
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = BreakerState::Closed;
    }
    pub fn record_failure(&mut self, now: Ticks) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let trip = matches!(self.state, BreakerState::HalfOpen { .. })
            || self.consecutive_failures >= self.failure_threshold;
        if trip { self.state = BreakerState::Open { until: now.saturating_add(self.cooldown) }; }
    }
}

const FREE: u32 = 0;
const WRITING: u32 = 1;
const SUBMITTED: u32 = 2;
const CLAIMED: u32 = 3;
const DONE: u32 = 4;
const FAILED: u32 = 5;
const ABANDONED: u32 = 6;

#[repr(C)]
pub struct SharedFrameSlot {
    state: AtomicU32,
    generation: AtomicU32,
    len: AtomicU32,
    _pad: AtomicU32,
    digest: [AtomicU64; 4],
    result: [AtomicU64; VALUE_WORDS],
    payload: [AtomicU8; MAX_FRAME_BYTES],
}

impl SharedFrameSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(FREE), generation: AtomicU32::new(0),
            len: AtomicU32::new(0), _pad: AtomicU32::new(0),
            digest: [const { AtomicU64::new(0) }; 4],
            result: [const { AtomicU64::new(0) }; VALUE_WORDS],
            payload: [const { AtomicU8::new(0) }; MAX_FRAME_BYTES],
        }
    }
}

#[repr(C)]
pub struct SharedRing<const N: usize> { slots: [SharedFrameSlot; N], next: AtomicUsize }

impl<const N: usize> SharedRing<N> {
    pub const MASK: usize = { assert!(N.is_power_of_two()); N.saturating_sub(1) };
    pub const fn new() -> Self {
        Self { slots: [const { SharedFrameSlot::new() }; N], next: AtomicUsize::new(0) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ticket { slot: u32, generation: u32 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubmitError { RingFull, FrameTooLarge }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SidecarFault { Reported, BadTicket }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PollOutcome { Pending, Ready(PredicateVector), Failed(SidecarFault) }

pub trait SidecarChannel {
    fn submit(&mut self, digest: &Digest32, proj: &CanonicalProjection<'_>) -> Result<Ticket, SubmitError>;
    fn poll(&mut self, ticket: Ticket) -> PollOutcome;
    fn cancel(&mut self, ticket: Ticket);
}

pub struct RingProducer<'r, const N: usize> { ring: &'r SharedRing<N> }

impl<'r, const N: usize> RingProducer<'r, N> {
    pub const fn new(ring: &'r SharedRing<N>) -> Self { Self { ring } }
}

impl<const N: usize> SidecarChannel for RingProducer<'_, N> {
    fn submit(&mut self, digest: &Digest32, proj: &CanonicalProjection<'_>) -> Result<Ticket, SubmitError> {
        let idx = self.ring.next.fetch_add(1, Ordering::Relaxed) & SharedRing::<N>::MASK;
        let slot = self.ring.slots.get(idx).ok_or(SubmitError::RingFull)?;
        slot.state
            .compare_exchange(FREE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| SubmitError::RingFull)?;
        let mut cursor = 0usize;
        let mut overflow = false;
        proj.visit_canonical(|chunk| {
            for &b in chunk {
                match slot.payload.get(cursor) {
                    Some(cell) => { cell.store(b, Ordering::Relaxed); cursor = cursor.saturating_add(1); }
                    None => overflow = true,
                }
            }
        });
        if overflow {
            slot.state.store(FREE, Ordering::Release);
            return Err(SubmitError::FrameTooLarge);
        }
        for (cell, chunk) in slot.digest.iter().zip(digest.0.chunks_exact(8)) {
            if let Ok(arr) = <[u8; 8]>::try_from(chunk) { cell.store(u64::from_le_bytes(arr), Ordering::Relaxed); }
        }
        slot.len.store(u32::try_from(cursor).unwrap_or(u32::MAX), Ordering::Relaxed);
        let generation = slot.generation.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        slot.state.store(SUBMITTED, Ordering::Release);
        Ok(Ticket { slot: u32::try_from(idx).unwrap_or(u32::MAX), generation })
    }

    fn poll(&mut self, t: Ticket) -> PollOutcome {
        let Some(slot) = self.ring.slots.get(usize::try_from(t.slot).unwrap_or(usize::MAX)) else {
            return PollOutcome::Failed(SidecarFault::BadTicket);
        };
        if slot.generation.load(Ordering::Acquire) != t.generation {
            return PollOutcome::Failed(SidecarFault::BadTicket);
        }
        match slot.state.load(Ordering::Acquire) {
            DONE => {
                let mut words = [0u64; VALUE_WORDS];
                for (w, cell) in words.iter_mut().zip(slot.result.iter()) { *w = cell.load(Ordering::Relaxed); }
                slot.state.store(FREE, Ordering::Release);
                PollOutcome::Ready(PredicateVector::from_words(words))
            }
            FAILED => { slot.state.store(FREE, Ordering::Release); PollOutcome::Failed(SidecarFault::Reported) }
            _ => PollOutcome::Pending,
        }
    }

    fn cancel(&mut self, t: Ticket) {
        let Some(slot) = self.ring.slots.get(usize::try_from(t.slot).unwrap_or(usize::MAX)) else { return };
        if slot.state.compare_exchange(SUBMITTED, FREE, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            let _ = slot.state.compare_exchange(CLAIMED, ABANDONED, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FallbackReason { BreakerOpen, Submit(SubmitError), Timeout, Fault(SidecarFault) }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier1Source { CacheHit, Fresh, Fallback(FallbackReason) }
#[derive(Clone, Copy, Debug)]
pub struct Tier1Result { pub digest: Digest32, pub vector: PredicateVector, pub source: Tier1Source }

pub struct CopleyBridge<'c, const SLOTS: usize, Ch: SidecarChannel> {
    cache: &'c EpochCache<SLOTS>,
    channel: Ch,
    breaker: CircuitBreaker,
    model_card: Digest32,
    calibration: Digest32,
}

impl<'c, const SLOTS: usize, Ch: SidecarChannel> CopleyBridge<'c, SLOTS, Ch> {
    pub const fn new(cache: &'c EpochCache<SLOTS>, channel: Ch, breaker: CircuitBreaker,
                     model_card: Digest32, calibration: Digest32) -> Self {
        Self { cache, channel, breaker, model_card, calibration }
    }

    /// Tier-1 entry point. Returns no later than `deadline` plus one `poll`.
    /// Fallbacks are never cached, so a transient timeout cannot poison the cache with ⊥.
    pub fn evaluate<H: Sha256Hasher, Clk: FnMut() -> Ticks>(
        &mut self, proj: &CanonicalProjection<'_>, hasher: H, mut clock: Clk, deadline: Ticks,
    ) -> Tier1Result {
        let digest = proj.segment_input_digest(hasher);
        let key = CacheKey::new(&digest, &self.model_card, &self.calibration);
        if let Some(vector) = self.cache.lookup(&key) {
            return Tier1Result { digest, vector, source: Tier1Source::CacheHit };
        }
        let fallback = |reason| Tier1Result {
            digest, vector: PredicateVector::UNKNOWN, source: Tier1Source::Fallback(reason),
        };
        let now = clock();
        if !self.breaker.permits(now) { return fallback(FallbackReason::BreakerOpen); }
        let ticket = match self.channel.submit(&digest, proj) {
            Ok(t) => t,
            Err(e) => { self.breaker.record_failure(now); return fallback(FallbackReason::Submit(e)); }
        };
        loop {
            match self.channel.poll(ticket) {
                PollOutcome::Ready(vector) => {
                    self.breaker.record_success();
                    let _ = self.cache.insert(&key, &vector);
                    return Tier1Result { digest, vector, source: Tier1Source::Fresh };
                }
                PollOutcome::Failed(f) => {
                    self.breaker.record_failure(clock());
                    return fallback(FallbackReason::Fault(f));
                }
                PollOutcome::Pending => {
                    let t = clock();
                    if t >= deadline {
                        self.channel.cancel(ticket);
                        self.breaker.record_failure(t);
                        return fallback(FallbackReason::Timeout);
                    }
                    core::hint::spin_loop();
                }
            }
        }
    }
}
```

**Theorem 2, cache-hit soundness.** Assume A1, SHA-256 is collision resistant; A2, the seqlock never returns a torn pair; A3, the sidecar is a deterministic function of frame bytes given fixed `model_card_sha256` and `calibration_table_sha256`. Then `lookup` returning `Some(v)` for frame $f$ under digests $(m, c)$ implies $v$ equals the fresh sidecar output for $f$ under $(m, c)$.

*Proof.* Entries are written only on the `Ready` path, so every committed pair is $(\text{key}(H(f'), m', c'), \text{sidecar}(f', m', c'))$ for some frame $f'$. A hit compares all 12 key words, so $H(f') = H(f)$, $m' = m$, $c' = c$. By A2 the returned value belongs to that same committed pair. By A1, $H(f') = H(f)$ with $f' \ne f$ is excluded, so $f' = f$, and A3 gives the equality. $\square$

A2 is checked by Apalache on a sequentially consistent abstraction with two separately written fields, which is the only way a torn read can appear. The Rust code realizes the abstraction with the acquire and release fences shown above.

```tla
---------------------------- MODULE EpochSeqlock ----------------------------
EXTENDS Integers
CONSTANTS
    \* @type: Set(Int);
    Readers,
    \* @type: Int;
    MaxWrites
VARIABLES
    \* @type: Int;
    seq,
    \* @type: Int;
    k,
    \* @type: Int;
    v,
    \* @type: Int;
    nWrites,
    \* @type: Set(<<Int, Int>>);
    committed,
    \* @type: Int -> Str;
    pc,
    \* @type: Int -> Int;
    s1,
    \* @type: Int -> Int;
    rk,
    \* @type: Int -> Int;
    rv,
    \* @type: Int -> Set(<<Int, Int>>);
    ret

CInit == Readers = {1, 2} /\ MaxWrites = 3

Init ==
    /\ seq = 0 /\ k = 0 /\ v = 0 /\ nWrites = 0 /\ committed = {<<0, 0>>}
    /\ pc = [r \in Readers |-> "idle"] /\ s1 = [r \in Readers |-> 0]
    /\ rk = [r \in Readers |-> 0] /\ rv = [r \in Readers |-> 0]
    /\ ret = [r \in Readers |-> {}]

RVars == <<pc, s1, rk, rv, ret>>
WVars == <<seq, k, v, nWrites, committed>>

WBegin == /\ seq % 2 = 0 /\ nWrites < MaxWrites
          /\ seq' = seq + 1 /\ UNCHANGED <<k, v, nWrites, committed>> /\ UNCHANGED RVars
WKey   == /\ seq % 2 = 1 /\ k # nWrites + 1
          /\ k' = nWrites + 1 /\ UNCHANGED <<seq, v, nWrites, committed>> /\ UNCHANGED RVars
WVal   == /\ seq % 2 = 1 /\ k = nWrites + 1 /\ v # 10 * (nWrites + 1)
          /\ v' = 10 * (nWrites + 1) /\ UNCHANGED <<seq, k, nWrites, committed>> /\ UNCHANGED RVars
WEnd   == /\ seq % 2 = 1 /\ k = nWrites + 1 /\ v = 10 * (nWrites + 1)
          /\ seq' = seq + 1 /\ nWrites' = nWrites + 1
          /\ committed' = committed \cup {<<k, v>>}
          /\ UNCHANGED <<k, v>> /\ UNCHANGED RVars

RStart(r) == /\ pc[r] = "idle"
             /\ s1' = [s1 EXCEPT ![r] = seq]
             /\ pc' = [pc EXCEPT ![r] = IF seq % 2 = 0 THEN "k" ELSE "idle"]
             /\ ret' = [ret EXCEPT ![r] = {}]
             /\ UNCHANGED <<rk, rv>> /\ UNCHANGED WVars
RKey(r)   == /\ pc[r] = "k" /\ rk' = [rk EXCEPT ![r] = k] /\ pc' = [pc EXCEPT ![r] = "v"]
             /\ UNCHANGED <<s1, rv, ret>> /\ UNCHANGED WVars
RVal(r)   == /\ pc[r] = "v" /\ rv' = [rv EXCEPT ![r] = v] /\ pc' = [pc EXCEPT ![r] = "chk"]
             /\ UNCHANGED <<s1, rk, ret>> /\ UNCHANGED WVars
RCheck(r) == /\ pc[r] = "chk" /\ pc' = [pc EXCEPT ![r] = "idle"]
             /\ ret' = [ret EXCEPT ![r] = IF seq = s1[r] THEN {<<rk[r], rv[r]>>} ELSE {}]
             /\ UNCHANGED <<s1, rk, rv>> /\ UNCHANGED WVars

Next == WBegin \/ WKey \/ WVal \/ WEnd
        \/ \E r \in Readers : RStart(r) \/ RKey(r) \/ RVal(r) \/ RCheck(r)

\* A returned pair is never torn: it is always a committed <<key, value>>.
NoTornRead == \A r \in Readers : ret[r] \subseteq committed
=============================================================================
```

Run with `apalache-mc check --cinit=CInit --inv=NoTornRead --length=24 EpochSeqlock.tla`. The invariant holds because any write overlapping a reader's window changes `seq`, and a reader only publishes when `seq` is unchanged and even.

**Theorem 4, WCET.** Every function on the request path has a constant operation bound, and `evaluate` returns within one `poll` of `deadline` whenever the clock is monotonic.

| Path | Operations | Tier |
|---|---|---|
| `lookup` | at most 34 atomic loads, 29 compares | Tier-0, tens of ns |
| `segment_input_digest` | at most 85 SHA-256 blocks for 5,423 bytes | Tier-1 |
| `submit` | at most 5,400 byte stores plus 6 word stores | Tier-1 |
| wait loop | one `poll` per iteration until `deadline` | Tier-1 |

*Proof.* `lookup` and `insert` iterate only over constant-length arrays. `visit_canonical` emits a bounded byte count by Theorem 1, so hashing and `submit` are bounded. The loop body is constant-time, and each `Pending` iteration reads the clock and returns once it reaches `deadline`; by monotonicity the number of iterations is finite and the exit happens on the first iteration whose clock reading is at or past the deadline. $\square$

The Tier-0 hot path is `lookup` alone. Digest computation is required anyway for the receipt, so its cost is paid once per request, not per guard.

## 3. Signed Model & Calibration Bundle Loader

**Bundle format.** The bundle is a fixed 6,304-byte blob delivered through the existing signed `LoadedWeights` provider path, so authenticity is inherited from the provider signature. The loader verifies structure, then that the embedded bundle digest, the recomputed digest, and the card's pin agree. The result type has no public constructor, following the `ShieldedAction<A>` pattern.

| Offset | Content |
|---|---|
| 0 | magic, version, counts 537 and 236, segment counts 345, 97, 57, 38 |
| 24 | 537 threshold pairs, Q16.16 `tau_pos` then `tau_neg` |
| 4320 | 236 rule instructions, 8 bytes each |
| 6208 | deny-class bitmap, 4 words |
| 6240 | bound `model_card_sha256` |
| 6272 | SHA-256 of bytes 0 to 6272 |

```rust
//! crates/security/chio-copley-bridge/src/calibration.rs
use crate::cache::PredicateVector;
use crate::{Digest32, Kleene3, Sha256Hasher, PREDICATE_COUNT, RULE_COUNT, SEGMENT_PREDICATES};

pub const BUNDLE_MAGIC: [u8; 8] = *b"CPLYCAL1";
pub const BUNDLE_VERSION: u16 = 1;
const OFF_THRESHOLDS: usize = 24;
const OFF_RULES: usize = OFF_THRESHOLDS + 8 * PREDICATE_COUNT;
const OFF_DENY_MASK: usize = OFF_RULES + 8 * RULE_COUNT;
const OFF_MODEL_CARD: usize = OFF_DENY_MASK + 32;
const OFF_BUNDLE_DIGEST: usize = OFF_MODEL_CARD + 32;
pub const BUNDLE_BYTES: usize = OFF_BUNDLE_DIGEST + 32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedQ16_16(pub i32);
impl FixedQ16_16 { pub const ZERO: Self = Self(0); pub const ONE: Self = Self(1 << 16); }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ThresholdPair { pub tau_pos: FixedQ16_16, pub tau_neg: FixedQ16_16 }

impl ThresholdPair {
    /// 0 ≤ τneg ≤ τpos ≤ 1.
    pub const fn well_formed(self) -> bool {
        FixedQ16_16::ZERO.0 <= self.tau_neg.0
            && self.tau_neg.0 <= self.tau_pos.0
            && self.tau_pos.0 <= FixedQ16_16::ONE.0
    }
    /// Role-asymmetric classification; the gap [τneg, τpos) is ⊥.
    pub const fn classify(self, score: FixedQ16_16) -> Kleene3 {
        if score.0 >= self.tau_pos.0 { Kleene3::True }
        else if score.0 < self.tau_neg.0 { Kleene3::False }
        else { Kleene3::Unknown }
    }
}

pub struct CalibrationTable { pairs: [ThresholdPair; PREDICATE_COUNT] }
impl CalibrationTable {
    pub fn pair(&self, j: usize) -> Option<ThresholdPair> { self.pairs.get(j).copied() }
}

/// Operands below 537 name predicates; 537 + r names rule r, which must be earlier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Instr { Pred(u16), And(u16, u16), Or(u16, u16), Not(u16) }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleVector(pub [Kleene3; RULE_COUNT]);

pub struct RuleDag { instrs: [Instr; RULE_COUNT], deny_mask: [u64; 4] }

impl RuleDag {
    fn operand(&self, preds: &PredicateVector, rules: &[Kleene3; RULE_COUNT], i: usize, o: u16) -> Kleene3 {
        let o = usize::from(o);
        if o < PREDICATE_COUNT { return preds.get(o).unwrap_or(Kleene3::Unknown); }
        o.checked_sub(PREDICATE_COUNT).filter(|r| *r < i)
            .and_then(|r| rules.get(r).copied()).unwrap_or(Kleene3::Unknown)
    }
    /// One forward pass, 236 steps, total, no fuel.
    pub fn evaluate(&self, preds: &PredicateVector) -> RuleVector {
        let mut rules = [Kleene3::Unknown; RULE_COUNT];
        for i in 0..RULE_COUNT {
            let Some(ins) = self.instrs.get(i).copied() else { break };
            let v = match ins {
                Instr::Pred(a) => self.operand(preds, &rules, i, a),
                Instr::And(a, b) => self.operand(preds, &rules, i, a).and(self.operand(preds, &rules, i, b)),
                Instr::Or(a, b) => self.operand(preds, &rules, i, a).or(self.operand(preds, &rules, i, b)),
                Instr::Not(a) => self.operand(preds, &rules, i, a).not(),
            };
            if let Some(slot) = rules.get_mut(i) { *slot = v; }
        }
        RuleVector(rules)
    }
    pub fn is_deny_class(&self, i: usize) -> bool {
        let word = self.deny_mask.get(i.checked_shr(6).unwrap_or(usize::MAX)).copied().unwrap_or(0);
        u32::try_from(i & 63).ok().and_then(|s| word.checked_shr(s)).map_or(false, |w| (w & 1) == 1)
    }
    #[cfg(kani)]
    pub fn for_verification(deny_mask: [u64; 4]) -> Self { Self { instrs: [Instr::Pred(0); RULE_COUNT], deny_mask } }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuleVerdict { Allow, PendingApproval, Deny }

/// Maps 1:1 onto `Verdict::{Allow, PendingApproval, Deny}` in `chio-guards`.
pub fn verdict_from_rules(dag: &RuleDag, rules: &RuleVector) -> RuleVerdict {
    let mut pending = false;
    for (i, r) in rules.0.iter().enumerate() {
        if !dag.is_deny_class(i) { continue; }
        match r {
            Kleene3::True => return RuleVerdict::Deny,
            Kleene3::Unknown => pending = true,
            Kleene3::False => {}
        }
    }
    if pending { RuleVerdict::PendingApproval } else { RuleVerdict::Allow }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CalibrationBindingError {
    Length { expected: usize, actual: usize }, Magic, Version(u16),
    PredicateCount(u16), RuleCount(u16), SegmentCounts,
    ThresholdOrder { predicate: u16 }, ThresholdRange { predicate: u16 },
    UnknownOpcode { rule: u16, op: u8 }, ForwardReference { rule: u16, operand: u16 },
    ModelCardMismatch, BundleDigestMismatch, CardPinMismatch,
}

/// Private constructor: only `evaluate_calibration_binding` produces one.
pub struct VerifiedCalibration { table: CalibrationTable, dag: RuleDag, bundle_digest: Digest32 }
impl VerifiedCalibration {
    pub fn table(&self) -> &CalibrationTable { &self.table }
    pub fn dag(&self) -> &RuleDag { &self.dag }
    pub const fn bundle_digest(&self) -> Digest32 { self.bundle_digest }
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(s).ok()?))
}
fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(i32::from_le_bytes(<[u8; 4]>::try_from(s).ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(s).ok()?))
}
fn digest_at(b: &[u8], off: usize) -> Option<Digest32> {
    let s = b.get(off..off.checked_add(32)?)?;
    Some(Digest32(<[u8; 32]>::try_from(s).ok()?))
}

pub fn evaluate_calibration_binding<H: Sha256Hasher>(
    pinned_bundle_sha256: &Digest32,
    bound_model_card_sha256: &Digest32,
    bundle: &[u8],
    mut hasher: H,
) -> Result<VerifiedCalibration, CalibrationBindingError> {
    use CalibrationBindingError as E;
    if bundle.len() != BUNDLE_BYTES { return Err(E::Length { expected: BUNDLE_BYTES, actual: bundle.len() }); }
    if bundle.get(..8) != Some(&BUNDLE_MAGIC[..]) { return Err(E::Magic); }
    let version = u16_at(bundle, 8).ok_or(E::Magic)?;
    if version != BUNDLE_VERSION { return Err(E::Version(version)); }
    let n_pred = u16_at(bundle, 10).ok_or(E::Magic)?;
    if usize::from(n_pred) != PREDICATE_COUNT { return Err(E::PredicateCount(n_pred)); }
    let n_rule = u16_at(bundle, 12).ok_or(E::Magic)?;
    if usize::from(n_rule) != RULE_COUNT { return Err(E::RuleCount(n_rule)); }
    for (s, expected) in SEGMENT_PREDICATES.iter().enumerate() {
        let off = 14usize.checked_add(s.checked_mul(2).ok_or(E::SegmentCounts)?).ok_or(E::SegmentCounts)?;
        if u16_at(bundle, off) != Some(*expected) { return Err(E::SegmentCounts); }
    }

    // 1. Thresholds: 0 ≤ τneg ≤ τpos ≤ 1 for every predicate.
    let mut pairs = [ThresholdPair { tau_pos: FixedQ16_16::ZERO, tau_neg: FixedQ16_16::ZERO }; PREDICATE_COUNT];
    for (j, pair) in pairs.iter_mut().enumerate() {
        let predicate = u16::try_from(j).map_err(|_| E::PredicateCount(u16::MAX))?;
        let range = E::ThresholdRange { predicate };
        let off = OFF_THRESHOLDS.checked_add(j.checked_mul(8).ok_or(range)?).ok_or(range)?;
        let tau_pos = FixedQ16_16(i32_at(bundle, off).ok_or(range)?);
        let tau_neg = FixedQ16_16(i32_at(bundle, off.checked_add(4).ok_or(range)?).ok_or(range)?);
        let p = ThresholdPair { tau_pos, tau_neg };
        if tau_neg > tau_pos { return Err(E::ThresholdOrder { predicate }); }
        if !p.well_formed() { return Err(range); }
        *pair = p;
    }

    // 2. Rule DAG: valid opcode; operands name predicates or strictly earlier rules.
    let mut instrs = [Instr::Pred(0); RULE_COUNT];
    for (i, slot) in instrs.iter_mut().enumerate() {
        let rule = u16::try_from(i).map_err(|_| E::RuleCount(u16::MAX))?;
        let bad = E::RuleCount(rule);
        let off = OFF_RULES.checked_add(i.checked_mul(8).ok_or(bad)?).ok_or(bad)?;
        let op = bundle.get(off).copied().ok_or(bad)?;
        let a = u16_at(bundle, off.checked_add(1).ok_or(bad)?).ok_or(bad)?;
        let b = u16_at(bundle, off.checked_add(3).ok_or(bad)?).ok_or(bad)?;
        let limit = PREDICATE_COUNT.checked_add(i).ok_or(bad)?;
        let check = |o: u16| if usize::from(o) < limit { Ok(o) } else { Err(E::ForwardReference { rule, operand: o }) };
        *slot = match op {
            0 => Instr::Pred(check(a)?),
            1 => Instr::And(check(a)?, check(b)?),
            2 => Instr::Or(check(a)?, check(b)?),
            3 => Instr::Not(check(a)?),
            other => return Err(E::UnknownOpcode { rule, op: other }),
        };
    }
    let mut deny_mask = [0u64; 4];
    for (w, word) in deny_mask.iter_mut().enumerate() {
        let off = OFF_DENY_MASK.checked_add(w.checked_mul(8).ok_or(E::Magic)?).ok_or(E::Magic)?;
        *word = u64_at(bundle, off).ok_or(E::Magic)?;
    }

    // 3. Bindings: embedded card digest, embedded bundle digest, recomputed digest, and card pin agree.
    if digest_at(bundle, OFF_MODEL_CARD) != Some(*bound_model_card_sha256) { return Err(E::ModelCardMismatch); }
    let embedded = digest_at(bundle, OFF_BUNDLE_DIGEST).ok_or(E::BundleDigestMismatch)?;
    hasher.update(bundle.get(..OFF_BUNDLE_DIGEST).ok_or(E::BundleDigestMismatch)?);
    let computed = Digest32(hasher.finalize());
    if computed != embedded { return Err(E::BundleDigestMismatch); }
    if computed != *pinned_bundle_sha256 { return Err(E::CardPinMismatch); }
    Ok(VerifiedCalibration { table: CalibrationTable { pairs }, dag: RuleDag { instrs, deny_mask }, bundle_digest: computed })
}
```

**Kernel and guard hooks, strictly additive.** The existing `evaluate_weights_binding` and the three-method `LoadedWeights` trait are untouched. The pin lives in the card's signed metadata under a new sub-key, so `ModelCard` gains no field. Receipts record the calibration digest, the segment digest, and the Tier-1 source inside the value of the existing `"model_metadata"` key, so the 35-entry `RESERVED_RECEIPT_METADATA_KEYS` array keeps its type.

```rust
// crates/kernel/chio-kernel/src/weights_binding.rs (additive)
pub const CALIBRATION_PIN_METADATA_KEY: &str = "copley.calibration_table_sha256";

pub struct CalibrationBindingRequest<'a> { pub bundle_bytes: &'a [u8], pub bound_model_card_sha256: [u8; 32] }

#[derive(Debug)]
pub enum BindingError { Weights(WeightsBindingError), Calibration(CalibrationBindingError), MissingCalibrationPin }

/// Composes the existing weights check with the calibration check.
pub fn evaluate_weights_and_calibration_binding(
    card: &ModelCard, weights: &WeightsBindingRequest<'_>, calibration: &CalibrationBindingRequest<'_>,
) -> Result<VerifiedCalibration, BindingError> {
    evaluate_weights_binding(card, weights).map_err(BindingError::Weights)?;
    let pin = card_calibration_pin(card).ok_or(BindingError::MissingCalibrationPin)?;
    evaluate_calibration_binding(
        &Digest32(pin), &Digest32(calibration.bound_model_card_sha256),
        calibration.bundle_bytes, Sha256Adapter::default(),
    ).map_err(BindingError::Calibration)
}

/// New provider trait; existing `LoadedWeights` implementors are unaffected.
pub trait LoadedCalibration: LoadedWeights {
    fn loaded_calibration_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable>;
}
```

```rust
// crates/guards/chio-guards/src/copley.rs (sketch against the existing Guard trait)
fn evaluate(&self, input: &EvaluateInput, ctx: &GuardContext) -> Result<Verdict, GuardError> {
    let src = CopleySegmentSource::new(input, ctx);
    let proj = CanonicalProjection::project(&src);
    let deadline = now_ticks().saturating_add(self.tier1_budget_ns);
    let r = self.bridge.lock().evaluate(&proj, Sha256Adapter::default(), now_ticks, deadline);
    let rules = self.calibration.dag().evaluate(&r.vector);
    let mut v = map_verdict(verdict_from_rules(self.calibration.dag(), &rules));
    // Exact predicate: a truncated CommandLine is never allowed on model evidence alone.
    if (proj.flags() & 1) == 1 && v == Verdict::Allow { v = Verdict::PendingApproval; }
    self.record_model_metadata(ctx, r.digest, self.calibration.bundle_digest(), r.source);
    Ok(v)
}
```

This composes with `GuardPipeline` exactly as it stands: `Deny` short-circuits, `PendingApproval` is sticky, and `Allow` continues.

**Theorem 3, fallback soundness.** Let $v \sqsubseteq v'$ pointwise in $\mathbb{K}_3^{537}$. Then `verdict_from_rules` at $v$ equal to `Allow` implies `Allow` at $v'$. In particular the fallback $\bot^{537}$ never yields `Allow` when full evaluation yields `Deny` or `PendingApproval`.

*Proof.* Strong Kleene `and`, `or`, `not` are monotone in $\sqsubseteq$, so by induction over the 236 instructions every rule satisfies $r_i(v) \sqsubseteq r_i(v')$. If the verdict at $v$ is `Allow`, every deny-class rule is $-$ at $v$. Since $-$ is maximal in $\sqsubseteq$, each such rule is $-$ at $v'$, hence `Allow` at $v'$. The contrapositive gives the second sentence, because $\bot^{537} \sqsubseteq v'$ for every $v'$. $\square$

```lean
-- formal/lean4/Chio/Copley/K3.lean
namespace Chio.Copley

inductive K3 where
  | unk | neg | pos
  deriving DecidableEq, Repr

namespace K3
def le : K3 → K3 → Bool
  | unk, _ => true
  | neg, neg => true
  | pos, pos => true
  | _, _ => false
def and : K3 → K3 → K3
  | neg, _ => neg
  | _, neg => neg
  | pos, pos => pos
  | _, _ => unk
def or : K3 → K3 → K3
  | pos, _ => pos
  | _, pos => pos
  | neg, neg => neg
  | _, _ => unk
def not : K3 → K3
  | pos => neg
  | neg => pos
  | unk => unk

theorem and_mono {a a' b b' : K3} (ha : le a a' = true) (hb : le b b' = true) :
    le (and a b) (and a' b') = true := by
  revert ha hb; cases a <;> cases a' <;> cases b <;> cases b' <;> decide
theorem or_mono {a a' b b' : K3} (ha : le a a' = true) (hb : le b b' = true) :
    le (or a b) (or a' b') = true := by
  revert ha hb; cases a <;> cases a' <;> cases b <;> cases b' <;> decide
theorem not_mono {a a' : K3} (ha : le a a' = true) : le (not a) (not a') = true := by
  revert ha; cases a <;> cases a' <;> decide
end K3

abbrev PredVec := Fin 537 → K3
def PredVec.le (v v' : PredVec) : Prop := ∀ j, K3.le (v j) (v' j) = true

theorem fallback_le (v : PredVec) : PredVec.le (fun _ => .unk) v := fun j => by
  cases v j <;> rfl

inductive ListLe : List K3 → List K3 → Prop
  | nil : ListLe [] []
  | cons {a b as bs} : K3.le a b = true → ListLe as bs → ListLe (a :: as) (b :: bs)

/-- Rule lookup; out-of-range reads are ⊥, matching `RuleDag::operand`. -/
def at? : List K3 → Nat → K3
  | [], _ => .unk
  | x :: _, 0 => x
  | _ :: xs, i + 1 => at? xs i

theorem at?_mono {xs ys : List K3} (h : ListLe xs ys) :
    ∀ i, K3.le (at? xs i) (at? ys i) = true := by
  induction h with
  | nil => intro i; cases i <;> rfl
  | cons hab _ ih =>
    intro i
    cases i with
    | zero => exact hab
    | succ i => exact ih i

theorem ListLe.snoc {xs ys : List K3} (h : ListLe xs ys) {x y : K3}
    (hxy : K3.le x y = true) : ListLe (xs ++ [x]) (ys ++ [y]) := by
  induction h with
  | nil => exact .cons hxy .nil
  | cons hab _ ih => exact .cons hab ih

inductive Instr where
  | pred (j : Fin 537)
  | and (a b : Nat)
  | or (a b : Nat)
  | not (a : Nat)

def step (v : PredVec) (acc : List K3) : Instr → K3
  | .pred j => v j
  | .and a b => K3.and (at? acc a) (at? acc b)
  | .or a b => K3.or (at? acc a) (at? acc b)
  | .not a => K3.not (at? acc a)

/-- Structural recursion on the program: total, no fuel. -/
def eval (v : PredVec) : List Instr → List K3 → List K3
  | [], acc => acc
  | i :: is, acc => eval v is (acc ++ [step v acc i])

theorem step_mono {v v' : PredVec} (hv : PredVec.le v v') {acc acc' : List K3}
    (ha : ListLe acc acc') (i : Instr) : K3.le (step v acc i) (step v' acc' i) = true := by
  cases i with
  | pred j => exact hv j
  | and a b => exact K3.and_mono (at?_mono ha a) (at?_mono ha b)
  | or a b => exact K3.or_mono (at?_mono ha a) (at?_mono ha b)
  | not a => exact K3.not_mono (at?_mono ha a)

theorem eval_mono {v v' : PredVec} (hv : PredVec.le v v') :
    ∀ (is : List Instr) {acc acc' : List K3}, ListLe acc acc' →
      ListLe (eval v is acc) (eval v' is acc')
  | [], _, _, ha => ha
  | i :: is, _, _, ha => eval_mono hv is (ha.snoc (step_mono hv ha i))

end Chio.Copley
```

The verdict step of Theorem 3 is discharged exhaustively by Kani over symbolic rule vectors, which is cheaper than a second Lean development for the Boolean scan.

```rust
#[cfg(kani)]
mod harness {
    use super::*;
    use crate::cache::{CacheKey, EpochCache, PredicateVector};
    use crate::calibration::{verdict_from_rules, RuleDag, RuleVector, RuleVerdict};
    use crate::sidecar::CircuitBreaker;

    #[kani::proof]
    fn predicate_vector_set_get_isolated() {
        let j: usize = kani::any(); kani::assume(j < PREDICATE_COUNT);
        let i: usize = kani::any(); kani::assume(i < PREDICATE_COUNT && i != j);
        let v: Kleene3 = kani::any();
        let mut pv = PredicateVector::UNKNOWN;
        assert!(pv.set(j, v).is_ok());
        assert_eq!(pv.get(j), Some(v));
        assert_eq!(pv.get(i), Some(Kleene3::Unknown));
    }

    #[kani::proof]
    fn cache_roundtrip_and_epoch_invalidation() {
        static CACHE: EpochCache<16> = EpochCache::new();
        let key = CacheKey { words: kani::any() };
        let value = PredicateVector::from_words(kani::any());
        assert!(CACHE.insert(&key, &value).is_stored());
        assert_eq!(CACHE.lookup(&key), Some(value));
        CACHE.rebind();
        assert_eq!(CACHE.lookup(&key), None);
    }

    #[kani::proof]
    fn breaker_blocks_until_cooldown() {
        let cooldown: u64 = kani::any();
        let now: u64 = kani::any();
        let t: u64 = kani::any();
        kani::assume(t >= now && t < now.saturating_add(cooldown));
        let mut b = CircuitBreaker::new(1, cooldown);
        b.record_failure(now);
        assert!(!b.permits(t));
    }

    #[kani::proof]
    #[kani::unwind(240)]
    fn allow_is_upward_closed() {
        let lower: [Kleene3; RULE_COUNT] = kani::any();
        let upper: [Kleene3; RULE_COUNT] = kani::any();
        for i in 0..RULE_COUNT { kani::assume(lower[i].refines(upper[i])); }
        let dag = RuleDag::for_verification(kani::any());
        if verdict_from_rules(&dag, &RuleVector(lower)) == RuleVerdict::Allow {
            assert_eq!(verdict_from_rules(&dag, &RuleVector(upper)), RuleVerdict::Allow);
        }
    }
}
```

**Theorem 5, role-asymmetric calibration.** For a well-formed pair, `classify` is a total function whose preimages of $+$, $\bot$, $-$ are the disjoint intervals $[\tau^{\text{pos}}, \infty)$, $[\tau^{\text{neg}}, \tau^{\text{pos}})$, $(-\infty, \tau^{\text{neg}})$, and it is monotone from scores to the truth order $- < \bot < +$. If $\tau^{\text{pos}}_j$ is the $\lceil (1-\alpha)(n+1) \rceil$-th order statistic of $n$ held-out negative scores, exchangeability gives $\Pr[\text{score} \ge \tau^{\text{pos}}_j \mid \text{negative}] \le \alpha$. The mirror statement bounds false $-$ at $\beta$ using positives and $\tau^{\text{neg}}_j$.

*Proof.* Disjointness and totality follow from $\tau^{\text{neg}} \le \tau^{\text{pos}}$, which the loader enforces before constructing the table. The coverage bound is the standard split-conformal quantile argument: the rank of an exchangeable fresh score among $n+1$ values is uniform. $\square$

The loader checks the structural invariants. The statistical claim is attested by the signed bundle's provenance, not re-derived at bind time, which is the correct division of labor under the Wave 1 law.

**Theorem 6, verification transfer.** Every existing proof models the learned choice as unconstrained nondeterminism over $\mathcal{A}_\ell$ or over $\mathbb{K}_3^{F_\ell}$. The bridge produces an element of $\mathbb{K}_3^{537}$ on every path, including cache hit, fresh evaluation, breaker open, ring full, fault, and timeout. The guard maps it into `{Allow, PendingApproval, Deny}`, and `GuardPipeline` keeps `Deny` and `PendingApproval` reachable regardless. Hence no existing obligation changes, and Theorems 1 through 5 are refinements layered on top.

```toml
# formal/proof-manifest.toml (additive entries)
[[proof]]
id = "copley-bridge.segments.prefix-free"
kind = "lean4"
module = "Chio.Copley.Segments"
theorem = "encodeSeg_append_inj"
rust_symbol = "chio_copley_bridge::segments::CanonicalProjection::visit_canonical"

[[proof]]
id = "copley-bridge.k3.eval-mono"
kind = "lean4"
module = "Chio.Copley.K3"
theorem = "eval_mono"
rust_symbol = "chio_copley_bridge::calibration::RuleDag::evaluate"

[[proof]]
id = "copley-bridge.seqlock.no-torn-read"
kind = "apalache"
spec = "formal/tla/EpochSeqlock.tla"
invariant = "NoTornRead"
length = 24

[[proof]]
id = "copley-bridge.kani.allow-upward-closed"
kind = "kani"
harness = "chio_copley_bridge::harness::allow_is_upward_closed"
```

Recap. The new crate `chio-copley-bridge` serializes four borrowed segments into a bounded, injective frame committed by `segment_input_digest`, serves a seqlock epoch cache keyed on the three digests with no unsafe code, and runs a deadline-bounded ring protocol with a circuit breaker whose only failure mode is the conservative vector $\bot^{537}$. The calibration loader authenticates 537 threshold pairs and the 236-rule DAG against the card pin and the bound model digest at provider bind time, through additive hooks that leave `evaluate_weights_binding`, `LoadedWeights`, and the reserved metadata key array unchanged. Lean 4 proves encoding injectivity and DAG monotonicity, Apalache checks the seqlock, and Kani checks packing, invalidation, the breaker, and verdict upward-closure. Next steps are the `chio-guards` `SegmentSource` implementation over the concrete context types, the `Sha256Adapter` in `chio-weights`, and wiring the manifest entries into CI.

---

# Verbatim Treatise - `wave3_angle_4_linux_ebpf_lsm_omarchy_macos_enforcement`

I'll lay out the three enforcement surfaces as pure, allocation-free Rust cores that emit kernel artifacts, with the syscall boundary isolated in audited shim crates, then give the Lean 4, Kani, and Apalache specifications and the proofs that transfer Wave 1's envelope law to each platform.

## Architecture and shared Tier-0 core

**Where unsafe lives.** Landlock, seccomp, eBPF ring buffers, cgroup files, Wayland sockets, and EndpointSecurity all end in a syscall or a C ABI call. Those calls cannot be `forbid(unsafe_code)`. The design therefore splits each platform into two crates. The core crate is `#![no_std]`, `#![forbid(unsafe_code)]`, and compiles a `ShieldedAction<CagePlan>` into plain data: a Landlock ruleset descriptor, a seccomp instruction array, a cgroup write set, a security-context descriptor, or an EndpointSecurity response. The shim crate applies that data byte for byte and contains the only `unsafe` blocks, each under a feature flag and listed in the proof manifest as trusted. Every theorem below is about the core, and the shim's obligation is a single sentence: it applies the artifact it was given and nothing else.

**The three safety predicates.** Each platform has one predicate that the kernel or the ES subsystem would otherwise reject or that would create an unsound state.

| Platform | Safety predicate on the artifact |
|---|---|
| Linux Landlock | every rule's allowed access is a subset of the ruleset's handled access, and no rule is empty |
| Linux seccomp | every jump target is inside the program, every path ends in a return, length is at most `BPF_MAXINSNS` |
| Omarchy cgroup | `cpu.weight` and `io.weight` lie in the kernel's accepted range, `memory.high` is at or above the cage floor |
| macOS ES | a response reaches ES before the message deadline, and a cached response never came from the fallback |

**Shared Tier-0 core.** Both Linux and macOS evaluate the same exact symbolic layer over Copley's predicate bitmap. The bitmap is Kleene 3-valued: a predicate is `+`, `-`, or `⊥`. The rule DAG is exact computation in the sense of Wave 1's first law, so the learned model is never asked to approximate it. Tier-1 only refines `⊥` atoms, and the DAG is re-evaluated.

```rust
//! crates/security/chio-cage/src/copley_tier0.rs
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const N_PREDICATES: usize = 537;
pub const BITMAP_WORDS: usize = 9;
pub const MAX_RULE_DEPTH: u8 = 9;
pub const N_RULES: usize = 236;
pub const RULE_WORDS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Segment { CommandLine = 0, Image = 1, OriginalFileName = 2, ParentImage = 3 }

impl Segment {
    pub const fn range(self) -> (usize, usize) {
        match self {
            Segment::CommandLine => (0, 345),
            Segment::Image => (345, 442),
            Segment::OriginalFileName => (442, 499),
            Segment::ParentImage => (499, 537),
        }
    }
    pub const fn bit(self) -> u8 { 1 << (self as u8) }
}
/// Segments whose value is a function of the executable vnode alone.
pub const VNODE_STABLE_SEGMENTS: u8 = Segment::Image.bit() | Segment::OriginalFileName.bit();

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum K3 { Pos, Neg, Unknown }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier0Error { Index, RuleOrder, RuleDepth, RuleCount }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Kleene3Bitmap<const W: usize> { known: [u64; W], value: [u64; W] }

impl<const W: usize> Kleene3Bitmap<W> {
    pub const fn all_unknown() -> Self { Self { known: [0; W], value: [0; W] } }

    pub fn get(&self, idx: usize) -> Result<K3, Tier0Error> {
        let (word, mask) = Self::locate(idx)?;
        let k = *self.known.get(word).ok_or(Tier0Error::Index)?;
        let v = *self.value.get(word).ok_or(Tier0Error::Index)?;
        Ok(if k & mask == 0 { K3::Unknown } else if v & mask != 0 { K3::Pos } else { K3::Neg })
    }

    /// Information-order extension only: a known atom is never rewritten.
    pub fn refine(&mut self, idx: usize, v: K3) -> Result<bool, Tier0Error> {
        if self.get(idx)? != K3::Unknown || v == K3::Unknown { return Ok(false); }
        let (word, mask) = Self::locate(idx)?;
        let k = self.known.get_mut(word).ok_or(Tier0Error::Index)?;
        *k |= mask;
        let val = self.value.get_mut(word).ok_or(Tier0Error::Index)?;
        if v == K3::Pos { *val |= mask; }
        Ok(true)
    }

    /// Exact-layer writes (canonicalizer output) may assert any value.
    pub fn assert(&mut self, idx: usize, v: K3) -> Result<(), Tier0Error> {
        let (word, mask) = Self::locate(idx)?;
        let k = self.known.get_mut(word).ok_or(Tier0Error::Index)?;
        let val = self.value.get_mut(word).ok_or(Tier0Error::Index)?;
        match v {
            K3::Unknown => { *k &= !mask; *val &= !mask; }
            K3::Pos => { *k |= mask; *val |= mask; }
            K3::Neg => { *k |= mask; *val &= !mask; }
        }
        Ok(())
    }

    fn locate(idx: usize) -> Result<(usize, u64), Tier0Error> {
        let word = idx >> 6;
        let bit = u32::try_from(idx & 63).map_err(|_| Tier0Error::Index)?;
        let mask = 1u64.checked_shl(bit).ok_or(Tier0Error::Index)?;
        if word >= W { return Err(Tier0Error::Index); }
        Ok((word, mask))
    }
}

/// Kleene strong conjunction over positive and negative literal masks.
pub fn eval_conj<const W: usize>(pos: &[u64; W], neg: &[u64; W], bm: &Kleene3Bitmap<W>) -> K3 {
    let mut any_false = false;
    let mut all_known = true;
    for w in 0..W {
        let (k, v) = (bm.known[w], bm.value[w]);
        if (pos[w] & k & !v) | (neg[w] & k & v) != 0 { any_false = true; }
        if (pos[w] | neg[w]) & !k != 0 { all_known = false; }
    }
    if any_false { K3::Neg } else if all_known { K3::Pos } else { K3::Unknown }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Consequent { Deny, Derived, GrantFs(u64), GrantNet(u64) }

#[derive(Clone, Copy)]
pub struct Rule<const W: usize> {
    pub pos_atoms: [u64; W],
    pub neg_atoms: [u64; W],
    pub pos_rules: [u64; RULE_WORDS],
    pub neg_rules: [u64; RULE_WORDS],
    pub segments: u8,
    pub depth: u8,
    pub consequent: Consequent,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier0Verdict { Deny, Defer, Allow { fs: u64, net: u64 } }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tier0Outcome { pub verdict: Tier0Verdict, pub used_segments: u8 }

pub struct SymbolicRuleDag<const N: usize, const W: usize, const D: usize, const R: usize> {
    rules: [Rule<W>; R],
    len: usize,
}

impl<const N: usize, const W: usize, const D: usize, const R: usize> SymbolicRuleDag<N, W, D, R> {
    /// Validates topological order and depth before any evaluation is possible.
    pub fn new(rules: [Rule<W>; R], len: usize) -> Result<Self, Tier0Error> {
        if len > R || R > RULE_WORDS.checked_mul(64).ok_or(Tier0Error::RuleCount)? {
            return Err(Tier0Error::RuleCount);
        }
        for r in 0..len {
            let rule = &rules[r];
            if usize::from(rule.depth) > D { return Err(Tier0Error::RuleDepth); }
            for j in 0..R {
                let word = j >> 6;
                let bit = u32::try_from(j & 63).map_err(|_| Tier0Error::Index)?;
                let mask = 1u64.checked_shl(bit).ok_or(Tier0Error::Index)?;
                let referenced = (rule.pos_rules[word] | rule.neg_rules[word]) & mask != 0;
                if referenced && (j >= r || rules[j].depth >= rule.depth) {
                    return Err(Tier0Error::RuleOrder);
                }
            }
        }
        Ok(Self { rules, len })
    }

    /// Cost is bounded by len * (W + RULE_WORDS) word operations.
    pub fn evaluate(&self, atoms: &Kleene3Bitmap<W>) -> Result<Tier0Outcome, Tier0Error> {
        let mut fired: Kleene3Bitmap<RULE_WORDS> = Kleene3Bitmap::all_unknown();
        let (mut deny_pos, mut deny_unknown) = (false, false);
        let (mut fs, mut net, mut used) = (0u64, 0u64, 0u8);
        for r in 0..self.len {
            let rule = &self.rules[r];
            let a = eval_conj(&rule.pos_atoms, &rule.neg_atoms, atoms);
            let b = eval_conj(&rule.pos_rules, &rule.neg_rules, &fired);
            let res = match (a, b) {
                (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
                (K3::Pos, K3::Pos) => K3::Pos,
                _ => K3::Unknown,
            };
            fired.assert(r, res)?;
            if res != K3::Neg { used |= rule.segments; }
            match (rule.consequent, res) {
                (Consequent::Deny, K3::Pos) => deny_pos = true,
                (Consequent::Deny, K3::Unknown) => deny_unknown = true,
                (Consequent::GrantFs(m), K3::Pos) => fs |= m,
                (Consequent::GrantNet(m), K3::Pos) => net |= m,
                _ => {}
            }
        }
        let verdict = if deny_pos { Tier0Verdict::Deny }
            else if deny_unknown { Tier0Verdict::Defer }
            else { Tier0Verdict::Allow { fs, net } };
        Ok(Tier0Outcome { verdict, used_segments: used })
    }
}

pub type CopleyDag = SymbolicRuleDag<N_PREDICATES, BITMAP_WORDS, 9, N_RULES>;
```

The conservative direction is built into `evaluate`. A deny rule that is `⊥` yields `Defer`, never silence. A grant rule that is `⊥` grants nothing. Tier-1 refinement enters only through `refine`, which cannot rewrite a known atom. That one restriction is what makes the exact layer dominate the learned layer, proven below.

## Platform enforcers

**Linux: Landlock and seccomp compilation.** The cage plan is fixed-capacity so the module has no allocator. Syscall permissions are a bitset over the first 512 syscall numbers, which covers every number currently assigned on x86_64 and aarch64 and gives the seccomp length bound for free.

```rust
//! crates/security/chio-cage/src/linux_decision_enforcer.rs
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use chio_kernel_core::shield::ShieldedAction;
use chio_kernel_core::formal_aeneas::classify_time_window_code;
use crate::copley_tier0::{Kleene3Bitmap, Segment, BITMAP_WORDS};

pub const MAX_PATH_RULES: usize = 256;
pub const MAX_NET_RULES: usize = 64;
pub const MAX_SYSCALL_NR: usize = 512;
pub const SYSCALL_WORDS: usize = 8;
pub const BPF_MAXINSNS: usize = 4096;

pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFF: u32 = 0;
const SECCOMP_DATA_ARCH_OFF: u32 = 4;

/// Handled filesystem bits the probed ABI understands; unknown bits would return EINVAL.
pub const fn fs_mask_for_abi(abi: u8) -> u64 {
    match abi { 0 => 0, 1 => 0x1FFF, 2 => 0x3FFF, 3 | 4 => 0x7FFF, _ => 0xFFFF }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum CageMode { Enforce, Defer, Deny }

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PathRule { pub path_slot: u16, pub allowed_fs: u64 }
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NetRule { pub port: u16, pub allowed_net: u64 }

#[derive(Clone, Copy)]
pub struct CagePlan {
    pub mode: CageMode,
    pub issued_at: u64,
    pub expires_at: u64,
    pub handled_fs: u64,
    pub handled_net: u64,
    pub path_rules: [PathRule; MAX_PATH_RULES],
    pub path_rule_count: usize,
    pub net_rules: [NetRule; MAX_NET_RULES],
    pub net_rule_count: usize,
    pub syscall_allow: [u64; SYSCALL_WORDS],
}

impl CagePlan {
    /// The envelope's bottom element: nothing handled-and-allowed, only clean exit.
    pub const fn fallback() -> Self {
        let mut allow = [0u64; SYSCALL_WORDS];
        // x86_64: exit_group 231, exit 60, rt_sigreturn 15
        allow[3] = 1 << (231 - 192);
        allow[0] = (1 << 60) | (1 << 15);
        Self {
            mode: CageMode::Deny, issued_at: 0, expires_at: u64::MAX,
            handled_fs: 0xFFFF, handled_net: 0b11,
            path_rules: [PathRule { path_slot: 0, allowed_fs: 0 }; MAX_PATH_RULES], path_rule_count: 0,
            net_rules: [NetRule { port: 0, allowed_net: 0 }; MAX_NET_RULES], net_rule_count: 0,
            syscall_allow: allow,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LandlockRulesetAttrV4 { pub handled_access_fs: u64, pub handled_access_net: u64 }

#[derive(Clone, Copy)]
pub struct LandlockArtifact {
    pub attr: LandlockRulesetAttrV4,
    pub path_rules: [PathRule; MAX_PATH_RULES],
    pub path_rule_count: usize,
    pub net_rules: [NetRule; MAX_NET_RULES],
    pub net_rule_count: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompileError { AbiTooOld(u8), PlanExpired, PlanNotYetValid, Capacity, Overflow }

pub fn compile_landlock(plan: &ShieldedAction<CagePlan>, abi: u8, now: u64)
    -> Result<LandlockArtifact, CompileError>
{
    if abi < 4 { return Err(CompileError::AbiTooOld(abi)); }
    let p = plan.action();
    match classify_time_window_code(now, p.issued_at, p.expires_at) {
        0 => {}
        1 => return Err(CompileError::PlanNotYetValid),
        _ => return Err(CompileError::PlanExpired),
    }
    let handled_fs = p.handled_fs & fs_mask_for_abi(abi);
    let handled_net = p.handled_net & (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);
    let mut out = LandlockArtifact {
        attr: LandlockRulesetAttrV4 { handled_access_fs: handled_fs, handled_access_net: handled_net },
        path_rules: [PathRule::default(); MAX_PATH_RULES], path_rule_count: 0,
        net_rules: [NetRule::default(); MAX_NET_RULES], net_rule_count: 0,
    };
    if p.mode == CageMode::Deny { return Ok(out); }
    for r in p.path_rules.iter().take(p.path_rule_count.min(MAX_PATH_RULES)) {
        let allowed = r.allowed_fs & handled_fs;
        if allowed == 0 { continue; }
        let slot = out.path_rules.get_mut(out.path_rule_count).ok_or(CompileError::Capacity)?;
        *slot = PathRule { path_slot: r.path_slot, allowed_fs: allowed };
        out.path_rule_count = out.path_rule_count.checked_add(1).ok_or(CompileError::Overflow)?;
    }
    for r in p.net_rules.iter().take(p.net_rule_count.min(MAX_NET_RULES)) {
        let allowed = r.allowed_net & handled_net;
        if allowed == 0 { continue; }
        let slot = out.net_rules.get_mut(out.net_rule_count).ok_or(CompileError::Capacity)?;
        *slot = NetRule { port: r.port, allowed_net: allowed };
        out.net_rule_count = out.net_rule_count.checked_add(1).ok_or(CompileError::Overflow)?;
    }
    Ok(out)
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SockFilter { pub code: u16, pub jt: u8, pub jf: u8, pub k: u32 }

impl SockFilter {
    pub const RET_KILL: Self = Self { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS };
    const fn ld(off: u32) -> Self { Self { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: off } }
    const fn jeq(k: u32, jt: u8, jf: u8) -> Self { Self { code: BPF_JMP_JEQ_K, jt, jf, k } }
    const fn ret(k: u32) -> Self { Self { code: BPF_RET_K, jt: 0, jf: 0, k } }
}

/// Emits: arch check, nr load, one (JEQ, RET ALLOW) pair per allowed syscall, default action.
/// Every jump offset is 0 or 1, so the u8 jt/jf fields can never truncate.
pub fn compile_seccomp(plan: &ShieldedAction<CagePlan>, arch: u32, out: &mut [SockFilter])
    -> Result<usize, CompileError>
{
    let p = plan.action();
    let default = match p.mode {
        CageMode::Enforce => SECCOMP_RET_ERRNO_EPERM,
        CageMode::Defer => SECCOMP_RET_USER_NOTIF,
        CageMode::Deny => SECCOMP_RET_KILL_PROCESS,
    };
    let mut n = 0usize;
    let mut push = |insn: SockFilter, n: &mut usize| -> Result<(), CompileError> {
        let slot = out.get_mut(*n).ok_or(CompileError::Capacity)?;
        *slot = insn;
        *n = n.checked_add(1).ok_or(CompileError::Overflow)?;
        Ok(())
    };
    push(SockFilter::ld(SECCOMP_DATA_ARCH_OFF), &mut n)?;
    push(SockFilter::jeq(arch, 1, 0), &mut n)?;
    push(SockFilter::RET_KILL, &mut n)?;
    push(SockFilter::ld(SECCOMP_DATA_NR_OFF), &mut n)?;
    for nr in 0..MAX_SYSCALL_NR {
        let word = nr >> 6;
        let bit = u32::try_from(nr & 63).map_err(|_| CompileError::Overflow)?;
        let mask = 1u64.checked_shl(bit).ok_or(CompileError::Overflow)?;
        if p.syscall_allow[word] & mask == 0 { continue; }
        let k = u32::try_from(nr).map_err(|_| CompileError::Overflow)?;
        push(SockFilter::jeq(k, 0, 1), &mut n)?;
        push(SockFilter::ret(SECCOMP_RET_ALLOW), &mut n)?;
    }
    push(SockFilter::ret(default), &mut n)?;
    if n > BPF_MAXINSNS { return Err(CompileError::Capacity); }
    Ok(n)
}

/// Independent checker used by Kani and by the shim before `prctl`.
pub fn verify_program(prog: &[SockFilter]) -> bool {
    let Some(last) = prog.last() else { return false; };
    if last.code != BPF_RET_K { return false; }
    for (i, insn) in prog.iter().enumerate() {
        if insn.code == BPF_JMP_JEQ_K {
            let base = match i.checked_add(1) { Some(b) => b, None => return false };
            let t = base.checked_add(usize::from(insn.jt));
            let f = base.checked_add(usize::from(insn.jf));
            match (t, f) {
                (Some(t), Some(f)) if t < prog.len() && f < prog.len() => {}
                _ => return false,
            }
        }
    }
    true
}
```

`CageMode::Defer` maps the pipeline's sticky `PendingApproval` onto `SECCOMP_RET_USER_NOTIF`, so the supervisor adjudicates each unlisted syscall with a timeout that falls back to EPERM. If no notifier is attached, the kernel fails the syscall, which is the fail-closed direction.

**Linux: eBPF LSM ingestion.** The BPF program attaches to `bprm_committed_creds`, `file_open`, and `socket_connect`, and reserves one ring-buffer record per event with a fixed little-endian header followed by four length-prefixed segments. The core parses it without `unsafe` and canonicalizes into the four Copley segments. On Linux the `OriginalFileName` slot carries the exec'd file's `d_path`, and `ParentImage` carries the parent task's `exe_file` path resolved in BPF.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LsmHook { BprmCommittedCreds = 1, FileOpen = 2, SocketConnect = 3 }

pub struct LsmRecordView<'a> {
    pub hook: LsmHook, pub pid: u32, pub ppid: u32, pub cgroup_id: u64, pub ts_ns: u64,
    pub segments: [&'a [u8]; 4],
}

const LSM_HEADER_LEN: usize = 34;

pub fn parse_lsm_record(buf: &[u8]) -> Result<LsmRecordView<'_>, CompileError> {
    let hdr = buf.get(..LSM_HEADER_LEN).ok_or(CompileError::Capacity)?;
    let hook = match hdr[0] { 1 => LsmHook::BprmCommittedCreds, 2 => LsmHook::FileOpen,
        3 => LsmHook::SocketConnect, _ => return Err(CompileError::Capacity) };
    let seg_len = |i: usize| -> Result<usize, CompileError> {
        let off = 2usize.checked_add(i.checked_mul(2).ok_or(CompileError::Overflow)?).ok_or(CompileError::Overflow)?;
        let b = hdr.get(off..off.checked_add(2).ok_or(CompileError::Overflow)?).ok_or(CompileError::Capacity)?;
        Ok(usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let u32_at = |off: usize| -> u32 { u32::from_le_bytes([hdr[off], hdr[off + 1], hdr[off + 2], hdr[off + 3]]) };
    let u64_at = |off: usize| -> u64 {
        let mut b = [0u8; 8]; b.copy_from_slice(&hdr[off..off + 8]); u64::from_le_bytes(b)
    };
    let mut cursor = LSM_HEADER_LEN;
    let mut segments: [&[u8]; 4] = [&[]; 4];
    for i in 0..4 {
        let len = seg_len(i)?;
        let end = cursor.checked_add(len).ok_or(CompileError::Overflow)?;
        segments[i] = buf.get(cursor..end).ok_or(CompileError::Capacity)?;
        cursor = end;
    }
    Ok(LsmRecordView { hook, pid: u32_at(10), ppid: u32_at(14), cgroup_id: u64_at(18), ts_ns: u64_at(26), segments })
}

pub const SEGMENT_MAX_BYTES: usize = 4096;

/// ASCII lowercase, whitespace runs collapsed, control bytes dropped, truncated.
pub fn canonicalize_segment(raw: &[u8], out: &mut [u8; SEGMENT_MAX_BYTES]) -> usize {
    let mut n = 0usize;
    let mut pending_space = false;
    for &b in raw {
        let c = match b {
            b'A'..=b'Z' => b | 0x20,
            b' ' | b'\t' | b'\n' | b'\r' => { pending_space = n != 0; continue; }
            0..=0x1F | 0x7F => continue,
            other => other,
        };
        if pending_space {
            if n >= SEGMENT_MAX_BYTES { break; }
            out[n] = b' '; n = n.saturating_add(1); pending_space = false;
        }
        if n >= SEGMENT_MAX_BYTES { break; }
        out[n] = c; n = n.saturating_add(1);
    }
    n
}

/// Generated predicate tables implement this; `copley_predicates_gen.rs` holds 537 byte-pattern tests.
pub trait AtomicPredicateSource {
    fn evaluate(&self, segment: Segment, canonical: &[u8], atoms: &mut Kleene3Bitmap<BITMAP_WORDS>)
        -> Result<(), crate::copley_tier0::Tier0Error>;
}
```

The `saturating_add` calls in the canonicalizer are bounded by the preceding `>= SEGMENT_MAX_BYTES` check and can never saturate; the lint accepts saturating operations, and the explicit bound makes the Aeneas extraction trivial.

**Omarchy OS supervisor.** Omarchy runs Hyprland, which implements the `wp_security_context_v1` protocol. The supervisor opens one listening socket per cage through that protocol, so every Wayland client that connects via the cage's socket is labelled by the compositor with the cage's sandbox engine, app id, and instance id. The core only produces the descriptor.

```rust
//! crates/platform/chio-omarchy-supervisor/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

pub const SANDBOX_ENGINE: &str = "org.chio.cage";
pub const CPU_WEIGHT_MIN: u16 = 1;
pub const CPU_WEIGHT_MAX: u16 = 10_000;
pub const IO_WEIGHT_MIN: u16 = 1;
pub const IO_WEIGHT_MAX: u16 = 10_000;
pub const ONE_Q16: u64 = 1 << 16;
pub const OS_ENFORCEMENT_METADATA_KEY: &str = "os_enforcement";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FixedQ16_16(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ShadowPriceVector {
    pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16,
    pub memory: FixedQ16_16, pub escrow: FixedQ16_16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CageResourceBase {
    pub cpu_weight_base: u16, pub io_weight_base: u16,
    pub memory_quota_bytes: u64, pub memory_floor_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CgroupLimits { pub cpu_weight: u16, pub memory_high_bytes: u64, pub io_weight: u16 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceMapError { Overflow, FloorAboveQuota }

fn clamp_weight(v: u64, lo: u16, hi: u16) -> u16 {
    let v = v.min(u64::from(hi)).max(u64::from(lo));
    u16::try_from(v).unwrap_or(hi)
}

/// cpu.weight rises with the latency price and falls with the fuel price.
/// memory.high falls with the memory price toward the floor. io.weight falls with the budget price.
pub fn derive_limits(base: &CageResourceBase, l: &ShadowPriceVector) -> Result<CgroupLimits, ResourceMapError> {
    if base.memory_floor_bytes > base.memory_quota_bytes { return Err(ResourceMapError::FloorAboveQuota); }
    let lat = ONE_Q16.checked_add(u64::from(l.latency.0)).ok_or(ResourceMapError::Overflow)?;
    let fuel = ONE_Q16.checked_add(u64::from(l.fuel.0)).ok_or(ResourceMapError::Overflow)?;
    let cpu_num = u64::from(base.cpu_weight_base).checked_mul(lat).ok_or(ResourceMapError::Overflow)?;
    let cpu = cpu_num.checked_div(fuel).ok_or(ResourceMapError::Overflow)?;
    let mem_den = u128::from(ONE_Q16).checked_add(u128::from(l.memory.0)).ok_or(ResourceMapError::Overflow)?;
    let mem_num = u128::from(base.memory_quota_bytes).checked_mul(u128::from(ONE_Q16)).ok_or(ResourceMapError::Overflow)?;
    let mem = mem_num.checked_div(mem_den).ok_or(ResourceMapError::Overflow)?;
    let mem = u64::try_from(mem).map_err(|_| ResourceMapError::Overflow)?.max(base.memory_floor_bytes);
    let bud = ONE_Q16.checked_add(u64::from(l.budget.0)).ok_or(ResourceMapError::Overflow)?;
    let io_num = u64::from(base.io_weight_base).checked_mul(ONE_Q16).ok_or(ResourceMapError::Overflow)?;
    let io = io_num.checked_div(bud).ok_or(ResourceMapError::Overflow)?;
    Ok(CgroupLimits {
        cpu_weight: clamp_weight(cpu, CPU_WEIGHT_MIN, CPU_WEIGHT_MAX),
        memory_high_bytes: mem,
        io_weight: clamp_weight(io, IO_WEIGHT_MIN, IO_WEIGHT_MAX),
    })
}

/// Projected dual ascent on one shadow price: lambda' = clamp(0, lambda_max, lambda + eta*(usage - cap)).
pub fn dual_step(lambda: FixedQ16_16, usage: u64, cap: u64, eta_q16: u32, lambda_max: u32) -> FixedQ16_16 {
    let eta = i128::from(eta_q16);
    let err = i128::from(usage).saturating_sub(i128::from(cap));
    let delta = eta.saturating_mul(err) >> 16;
    let next = i128::from(lambda.0).saturating_add(delta).clamp(0, i128::from(lambda_max));
    FixedQ16_16(u32::try_from(next).unwrap_or(lambda_max))
}

#[derive(Clone, Copy)]
pub struct CgroupWrite { pub file: &'static str, pub value: [u8; 32], pub len: usize }

fn fmt_u64(mut v: u64, out: &mut [u8; 32], prefix: &[u8]) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    loop {
        tmp[i] = b'0'.wrapping_add((v % 10) as u8);
        i = i.saturating_add(1);
        v /= 10;
        if v == 0 { break; }
    }
    let mut n = 0usize;
    for &b in prefix { out[n] = b; n = n.saturating_add(1); }
    while i > 0 { i = i.saturating_sub(1); out[n] = tmp[i]; n = n.saturating_add(1); }
    n
}

pub fn cgroup_write_set(limits: &CgroupLimits) -> [CgroupWrite; 3] {
    let mut cpu = [0u8; 32]; let cpu_len = fmt_u64(u64::from(limits.cpu_weight), &mut cpu, b"");
    let mut mem = [0u8; 32]; let mem_len = fmt_u64(limits.memory_high_bytes, &mut mem, b"");
    let mut io = [0u8; 32]; let io_len = fmt_u64(u64::from(limits.io_weight), &mut io, b"default ");
    [
        CgroupWrite { file: "cpu.weight", value: cpu, len: cpu_len },
        CgroupWrite { file: "memory.high", value: mem, len: mem_len },
        CgroupWrite { file: "io.weight", value: io, len: io_len },
    ]
}

/// Descriptor applied by the shim through wp_security_context_manager_v1.
pub struct SecurityContextDescriptor { pub app_id: [u8; 128], pub app_id_len: usize, pub instance_id: [u8; 64], pub instance_id_len: usize }

pub fn provenance_descriptor(cage_id: &[u8; 16], epoch: u64, receipt_hash: &[u8; 32]) -> SecurityContextDescriptor {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut inst = [0u8; 64];
    let mut n = 0usize;
    for &b in cage_id.iter().chain(receipt_hash[..8].iter()) {
        inst[n] = HEX[usize::from(b >> 4)]; inst[n.saturating_add(1)] = HEX[usize::from(b & 15)];
        n = n.saturating_add(2);
    }
    for &b in epoch.to_be_bytes().iter() {
        inst[n] = HEX[usize::from(b >> 4)]; inst[n.saturating_add(1)] = HEX[usize::from(b & 15)];
        n = n.saturating_add(2);
    }
    let mut app = [0u8; 128];
    let tag = b"org.chio.cage.";
    app[..tag.len()].copy_from_slice(tag);
    SecurityContextDescriptor { app_id: app, app_id_len: tag.len(), instance_id: inst, instance_id_len: n }
}

pub struct ReceiptDigest(pub [u8; 32]);
pub struct Signature { pub bytes: [u8; 96], pub len: usize, pub key_handle: u32 }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignError { Uncoupled, Hardware(u32) }

/// TPM2 on Omarchy, Secure Enclave on macOS; both shims implement this trait.
pub trait HardwareSigner {
    fn sign(&mut self, digest: &ReceiptDigest, policy_hash: &[u8; 32]) -> Result<Signature, SignError>;
}

pub fn sign_enforcement_receipt<S: HardwareSigner>(
    signer: &mut S, digest: &ReceiptDigest, policy_hash: &[u8; 32],
    capability: bool, request: bool, verdict: bool, policy: bool, evidence: bool,
) -> Result<Signature, SignError> {
    if !chio_kernel_core::formal_aeneas::receipt_fields_coupled(capability, request, verdict, policy, evidence) {
        return Err(SignError::Uncoupled);
    }
    signer.sign(digest, policy_hash)
}
```

The `instance_id` encodes the full cage identifier, so two cages can never collide in the compositor's labelling, and the receipt-hash prefix binds the surface to the plan epoch that admitted it. The `fmt_u64` helper uses `%` and `/` with literal divisors, which the arithmetic lint accepts, and its loop runs at most twenty times for a `u64`. The new metadata key is a separate constant rather than an edit to the 35-element reserved array, so the existing array type and the proofs pinned to it are untouched; a reserved-key check must test both.

**macOS EndpointSecurity deadline scheduler.** An AUTH message carries a deadline in Mach absolute time. Missing it is a client fault that ES eventually punishes by terminating the client, so the scheduler must respond with something safe before the deadline no matter what Tier-1 does. Tier-1 is dispatched only when Tier-0 returned `Defer` and the slack covers Tier-1's worst case, Tier-0's re-evaluation, and the respond call; a watchdog otherwise sends the Tier-0 fallback. Tier-1 invocations also pass the kernel's exact budget check first.

```rust
//! crates/platform/chio-macos-es-enforcer/src/deadline_scheduler.rs
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use chio_cage::copley_tier0::{CopleyDag, K3, Kleene3Bitmap, Tier0Outcome, Tier0Verdict, BITMAP_WORDS, N_PREDICATES, VNODE_STABLE_SEGMENTS};
use chio_kernel_core::formal_aeneas::budget_precheck;

pub const TIER0_WCET_NS: u64 = 250_000;
pub const TIER1_WCET_NS: u64 = 5_000_000;
pub const RESPOND_OVERHEAD_NS: u64 = 50_000;
pub const SAFETY_MARGIN_NS: u64 = 2_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MachTimebase { pub numer: u32, pub denom: u32 }

pub fn mach_to_ns(ticks: u64, tb: &MachTimebase) -> Option<u64> {
    let n = u128::from(ticks).checked_mul(u128::from(tb.numer))?;
    let d = u128::from(tb.denom);
    if d == 0 { return None; }
    u64::try_from(n.checked_div(d)?).ok()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EsAuthKind { Exec, Open { requested_fflags: u32 } }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EsResponse { AuthResult { allow: bool, cache: bool }, FlagsResult { authorized_flags: u32, cache: bool } }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Schedule {
    RespondNow(EsResponse),
    DispatchTier1 { tier1_deadline_ns: u64, watchdog_response: EsResponse },
}

pub struct Tier1Budget { pub remaining_invocations: u64, pub remaining_units: u64, pub invocation_cost: u64, pub unit_cost: u64 }

fn fallback(kind: EsAuthKind) -> EsResponse {
    match kind {
        EsAuthKind::Exec => EsResponse::AuthResult { allow: false, cache: false },
        EsAuthKind::Open { .. } => EsResponse::FlagsResult { authorized_flags: 0, cache: false },
    }
}

pub fn response_for(kind: EsAuthKind, out: &Tier0Outcome, from_fallback: bool) -> EsResponse {
    let vnode_only = out.used_segments & !VNODE_STABLE_SEGMENTS == 0;
    match (kind, out.verdict) {
        (_, Tier0Verdict::Defer) => fallback(kind),
        (EsAuthKind::Exec, Tier0Verdict::Deny) => EsResponse::AuthResult { allow: false, cache: !from_fallback },
        (EsAuthKind::Exec, Tier0Verdict::Allow { .. }) => EsResponse::AuthResult { allow: true, cache: vnode_only && !from_fallback },
        (EsAuthKind::Open { .. }, Tier0Verdict::Deny) => EsResponse::FlagsResult { authorized_flags: 0, cache: !from_fallback },
        (EsAuthKind::Open { requested_fflags }, Tier0Verdict::Allow { fs, .. }) => {
            // FREAD = 1, FWRITE = 2 in the fflags word; write authority requires a Landlock-class write grant.
            let mut flags = requested_fflags & 1;
            if fs & chio_cage::linux_decision_enforcer::LANDLOCK_ACCESS_FS_WRITE_FILE != 0 { flags |= requested_fflags & 2; }
            EsResponse::FlagsResult { authorized_flags: flags, cache: vnode_only && !from_fallback }
        }
    }
}

pub fn schedule(now_ns: u64, deadline_ns: u64, kind: EsAuthKind, tier0: &Tier0Outcome, budget: &Tier1Budget) -> Schedule {
    let immediate = response_for(kind, tier0, false);
    if tier0.verdict != Tier0Verdict::Defer { return Schedule::RespondNow(immediate); }
    let Some(slack) = deadline_ns.checked_sub(now_ns).and_then(|d| d.checked_sub(SAFETY_MARGIN_NS)) else {
        return Schedule::RespondNow(fallback(kind));
    };
    let need = TIER1_WCET_NS.checked_add(TIER0_WCET_NS).and_then(|v| v.checked_add(RESPOND_OVERHEAD_NS));
    let affordable = budget_precheck(budget.remaining_invocations, budget.remaining_units, budget.invocation_cost, budget.unit_cost);
    match need {
        Some(need) if slack >= need && affordable => Schedule::DispatchTier1 {
            tier1_deadline_ns: now_ns.saturating_add(TIER1_WCET_NS),
            watchdog_response: fallback(kind),
        },
        _ => Schedule::RespondNow(fallback(kind)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Thresholds { pub tau_pos: [u16; N_PREDICATES], pub tau_neg: [u16; N_PREDICATES] }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefineError { ThresholdOrder(usize), Tier0(chio_cage::copley_tier0::Tier0Error) }

/// Tier-1 probabilities in Q0.16 fill unknown atoms only; the exact DAG then re-decides.
pub fn refine_and_reevaluate(dag: &CopleyDag, atoms: &mut Kleene3Bitmap<BITMAP_WORDS>, probs: &[u16; N_PREDICATES], th: &Thresholds)
    -> Result<Tier0Outcome, RefineError>
{
    for j in 0..N_PREDICATES {
        if th.tau_neg[j] > th.tau_pos[j] { return Err(RefineError::ThresholdOrder(j)); }
        let v = if probs[j] >= th.tau_pos[j] { K3::Pos } else if probs[j] <= th.tau_neg[j] { K3::Neg } else { K3::Unknown };
        atoms.refine(j, v).map_err(RefineError::Tier0)?;
    }
    dag.evaluate(atoms).map_err(RefineError::Tier0)
}
```

Segment sourcing on macOS: `CommandLine` from the exec argument vector, `Image` from the target executable path, `OriginalFileName` from the target's signing identifier since Mach-O has no PE original filename, and `ParentImage` from the path of the process issuing the exec, which is the pre-exec image and an approximation of Sysmon's parent image. The shim records that approximation in the receipt.

## Formal specifications and proofs

**Lean 4 core.** The Kleene order and monotonicity are decided by exhaustive case analysis; the seccomp layout lemma is by induction on the allowed list.

```lean
namespace Chio.Enforce

inductive K3 | pos | neg | unk deriving DecidableEq, Repr

/-- Information order as a Bool: unk below everything, else equality. -/
def K3.le (a b : K3) : Bool := match a, b with | .unk, _ => true | a, b => a == b

def K3.and : K3 → K3 → K3
  | .neg, _ | _, .neg => .neg
  | .pos, .pos => .pos
  | _, _ => .unk

theorem K3.and_mono : ∀ a a' b b', K3.le a a' = true → K3.le b b' = true →
    K3.le (K3.and a b) (K3.and a' b') = true := by decide

theorem K3.neg_stable : ∀ a a', K3.le a a' = true → a = .neg → a' = .neg := by decide
theorem K3.pos_stable : ∀ a a', K3.le a a' = true → a = .pos → a' = .pos := by decide

structure Insn where code : UInt16; jt : UInt8; jf : UInt8; k : UInt32

def allowBlock (nr : UInt32) : List Insn := [⟨0x15, 0, 1, nr⟩, ⟨0x06, 0, 0, 0x7fff0000⟩]
def body : List UInt32 → List Insn
  | [] => []
  | nr :: rest => allowBlock nr ++ body rest
def prologue (arch : UInt32) : List Insn :=
  [⟨0x20, 0, 0, 4⟩, ⟨0x15, 1, 0, arch⟩, ⟨0x06, 0, 0, 0x80000000⟩, ⟨0x20, 0, 0, 0⟩]
def compile (arch dflt : UInt32) (nrs : List UInt32) : List Insn :=
  prologue arch ++ body nrs ++ [⟨0x06, 0, 0, dflt⟩]

theorem body_length : ∀ nrs, (body nrs).length = 2 * nrs.length := by
  intro nrs; induction nrs with
  | nil => rfl
  | cons h t ih => simp [body, allowBlock, ih]; omega

theorem compile_length (arch dflt : UInt32) (nrs : List UInt32) :
    (compile arch dflt nrs).length = 2 * nrs.length + 5 := by
  simp [compile, prologue, body_length]; omega

theorem compile_bounded (arch dflt : UInt32) (nrs : List UInt32) (h : nrs.length ≤ 512) :
    (compile arch dflt nrs).length ≤ 4096 := by
  rw [compile_length]; omega

/-- Envelope Preservation and Verification Transfer, instantiated per platform. -/
theorem transfer {X A : Type} (Feasible : X → A → Prop) (Safe : A → Prop)
    (h : ∀ x a, Feasible x a → Safe a) (P : X → A)
    (Π : (x : X) → A → {a : A // Feasible x a}) : ∀ x, Safe (Π x (P x)).1 :=
  fun x => h x _ (Π x (P x)).2

end Chio.Enforce
```

**Kani harnesses.** The learned choice is `kani::any()`, consistent with Wave 1. The `cfg(kani)` constructor on `ShieldedAction` exists only under that configuration and asserts the candidate lies in the envelope, which is the projection's postcondition and not a new trust assumption.

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    #[kani::unwind(520)]
    fn seccomp_program_well_formed_for_any_feasible_plan() {
        let mut plan = CagePlan::fallback();
        plan.syscall_allow = kani::any();
        plan.mode = kani::any();
        let shielded = ShieldedAction::from_any_feasible(plan);
        let mut buf = [SockFilter::RET_KILL; BPF_MAXINSNS];
        let n = compile_seccomp(&shielded, AUDIT_ARCH_X86_64, &mut buf).unwrap();
        assert!(n <= BPF_MAXINSNS);
        assert!(verify_program(&buf[..n]));
    }

    #[kani::proof]
    #[kani::unwind(260)]
    fn landlock_rules_are_subsets_of_handled() {
        let mut plan = CagePlan::fallback();
        plan.mode = CageMode::Enforce;
        plan.handled_fs = kani::any();
        plan.path_rule_count = kani::any();
        kani::assume(plan.path_rule_count <= MAX_PATH_RULES);
        for i in 0..plan.path_rule_count { plan.path_rules[i] = PathRule { path_slot: kani::any(), allowed_fs: kani::any() }; }
        let abi: u8 = kani::any();
        kani::assume(abi >= 4);
        let art = compile_landlock(&ShieldedAction::from_any_feasible(plan), abi, 1).unwrap();
        for r in &art.path_rules[..art.path_rule_count] {
            assert!(r.allowed_fs != 0 && r.allowed_fs & !art.attr.handled_access_fs == 0);
        }
    }

    #[kani::proof]
    fn cgroup_limits_in_kernel_range() {
        let base = CageResourceBase { cpu_weight_base: kani::any(), io_weight_base: kani::any(),
            memory_quota_bytes: kani::any(), memory_floor_bytes: kani::any() };
        let l: ShadowPriceVector = kani::any();
        if let Ok(lim) = derive_limits(&base, &l) {
            assert!(lim.cpu_weight >= CPU_WEIGHT_MIN && lim.cpu_weight <= CPU_WEIGHT_MAX);
            assert!(lim.io_weight >= IO_WEIGHT_MIN && lim.io_weight <= IO_WEIGHT_MAX);
            assert!(lim.memory_high_bytes >= base.memory_floor_bytes);
            assert!(lim.memory_high_bytes <= base.memory_quota_bytes.max(base.memory_floor_bytes));
        }
    }
}
```

**Apalache TLA+ for the ES scheduler.** Tier-1 latency and verdict are unconstrained nondeterminism. The three invariants are the macOS safety predicate plus the cache soundness rule.

```tla
---------------------------- MODULE EsDeadlineScheduler ----------------------------
EXTENDS Integers
CONSTANTS
  \* @type: Int;
  T0, T1, OVH, MARGIN, DEADLINE
VARIABLES
  \* @type: Int;
  now,
  \* @type: Str;
  state, verdict, source,
  \* @type: Bool;
  cache
ASSUME T0 > 0 /\ T1 > 0 /\ OVH > 0 /\ MARGIN > OVH /\ DEADLINE > T0 + MARGIN

Init == now = 0 /\ state = "Pending" /\ verdict = "Deny" /\ source = "None" /\ cache = FALSE

Tier0 == state = "Pending" /\ now' = now + T0 /\ state' = "Tier0Done"
  /\ \E v \in {"Allow", "Deny", "Defer"} : verdict' = v /\ source' = "Tier0" /\ cache' = FALSE

RespondDefinite == state = "Tier0Done" /\ verdict # "Defer"
  /\ now' = now + OVH /\ state' = "Responded" /\ UNCHANGED <<verdict, source>>
  /\ \E c \in BOOLEAN : cache' = c

RespondFallback == state = "Tier0Done" /\ verdict = "Defer"
  /\ DEADLINE - now - MARGIN < T1 + T0 + OVH
  /\ now' = now + OVH /\ state' = "Responded" /\ verdict' = "Deny" /\ source' = "Fallback" /\ cache' = FALSE

Dispatch == state = "Tier0Done" /\ verdict = "Defer"
  /\ DEADLINE - now - MARGIN >= T1 + T0 + OVH
  /\ state' = "Tier1Running" /\ UNCHANGED <<now, verdict, source, cache>>

Tier1Returns == state = "Tier1Running"
  /\ \E d \in 0..T1 : now' = now + d + T0 + OVH
  /\ \E v \in {"Allow", "Deny", "Defer"} :
       IF v = "Defer" THEN verdict' = "Deny" /\ source' = "Fallback" /\ cache' = FALSE
       ELSE verdict' = v /\ source' = "Tier1" /\ cache' = FALSE
  /\ state' = "Responded"

Watchdog == state = "Tier1Running" /\ now' = now + T1 + T0 + OVH
  /\ state' = "Responded" /\ verdict' = "Deny" /\ source' = "Fallback" /\ cache' = FALSE

Next == Tier0 \/ RespondDefinite \/ RespondFallback \/ Dispatch \/ Tier1Returns \/ Watchdog

RespondBeforeDeadline == state = "Responded" => now < DEADLINE
NoFallbackCache == source = "Fallback" => cache = FALSE
FallbackIsDeny == source = "Fallback" => verdict = "Deny"
Inv == RespondBeforeDeadline /\ NoFallbackCache /\ FallbackIsDeny
===================================================================================
```

Run with `apalache-mc check --inv=Inv --length=6 EsDeadlineScheduler.tla` and concrete constants such as `T0=1, T1=20, OVH=1, MARGIN=8, DEADLINE=200`. The Rust `response_for` sets `cache` from the vnode-stability mask, which the TLA model abstracts as a free Boolean in `RespondDefinite`; that is a strengthening the model does not need.

**Proof manifest additions.** All entries are new and no existing entry changes.

```toml
[[module]]
crate = "chio-cage"
path = "crates/security/chio-cage/src/copley_tier0.rs"
backend = "aeneas"
lean_target = "formal/lean4/Chio/Cage/Tier0.lean"
status = "additive"

[[module]]
crate = "chio-cage"
path = "crates/security/chio-cage/src/linux_decision_enforcer.rs"
backend = "kani"
harnesses = ["seccomp_program_well_formed_for_any_feasible_plan", "landlock_rules_are_subsets_of_handled"]
status = "additive"

[[trusted]]
crate = "chio-cage-sys"
reason = "applies LandlockArtifact and SockFilter arrays byte-for-byte; the only unsafe in the cage"
```

**Theorem 1, exact dominates learned.** Let `b ≤_k b'` denote that `b'` agrees with `b` on every atom `b` knows. `refine` only writes atoms that are `⊥` in `b`, so after any sequence of refinements the result `b'` satisfies `b ≤_k b'`. Each rule's antecedent is a Kleene conjunction, and by `K3.and_mono` lifted to the fold over literals, the rule result in `b'` is above its result in `b` in the information order. By induction over the topologically ordered rule array, the same holds for the derived-rule bitmap, since `fired` at step `r` depends only on results of rules below `r`. By `K3.neg_stable` and `K3.pos_stable`, a rule that was `Pos` or `Neg` under `b` keeps that value under `b'`. Hence if Tier-0 produced `Deny`, some deny rule was `Pos` and remains `Pos`, so the re-evaluated verdict is `Deny`. If Tier-0 produced `Allow`, every deny rule was `Neg` and remains `Neg`, so the verdict stays `Allow` with a grant mask that can only grow. Tier-1 can therefore only resolve `Defer`; it can never flip a definite verdict in either direction. The threshold invariant `τ_neg ≤ τ_pos` guarantees that a single probability never produces both `Pos` and `Neg`, so `refine` receives a function of the probability.

**Theorem 2, Landlock artifact validity.** For every emitted path rule, `allowed_fs = r.allowed_fs & handled_fs` with `handled_fs = p.handled_fs & fs_mask_for_abi(abi)`, so `allowed_fs ⊆ handled_fs` and contains no bit the probed ABI rejects. Rules with empty allowed access are skipped, excluding the kernel's `ENOMSG` case. In `Deny` mode no rules are emitted and all accesses are handled, which is the most restrictive ruleset the ABI expresses. The same holds for network rules against the two-bit network mask. The Kani harness checks this for symbolic rule tables.

**Theorem 3, seccomp well-formedness and bound.** Every `JEQ` in the body has `jt = 0`, `jf = 1`, and is followed by a `RET` and then either another block or the terminal `RET`, so both targets exist. The prologue's `JEQ` has `jt = 1` targeting the `LD` at index 3 and `jf = 0` targeting the `RET KILL`. Every path ends at a `RET` because the body consists of alternating `JEQ` and `RET` and the program ends in `RET`. Length is `2n + 5` by `compile_length`, and `n ≤ 512` since the allow set is a 512-bit bitset, so length is at most 1029, well under `BPF_MAXINSNS`; `compile_bounded` discharges this and the Kani harness confirms it on the Rust artifact. Because offsets are 0 or 1, the `u8` jump fields cannot truncate, which is the usual bug in linear seccomp filters past 255 entries.

**Theorem 4, cgroup monotonicity and closed-loop stability.** Write `c(λ) = base · (2^16 + λ_lat) / (2^16 + λ_fuel)`. Integer division by a positive denominator is monotone in the numerator, and for fixed numerator nonincreasing in the denominator, so `c` is nondecreasing in `λ_lat` and nonincreasing in `λ_fuel`; clamping is monotone, so `cpu.weight` inherits both properties. The same argument gives `memory.high` nonincreasing in `λ_mem` and bounded below by the floor by the final `max`, and `io.weight` nonincreasing in `λ_budget`. Range membership is immediate from the clamp bounds, which match the kernel's accepted interval for `cpu.weight` and `io.weight`. For the controller, `dual_step` is projected subgradient ascent on the Lagrangian dual of the allocation problem with utilities `u_i(r) = w_i log r`, whose optimal primal response is `r_i = w_i / λ`, which the mapping approximates with a reciprocal in the shifted price. With a fixed step `η`, projected subgradient ascent on a concave dual with bounded subgradients converges to a neighborhood of the optimum whose radius is proportional to `η` times the squared usage bound, by the standard telescoping bound on `‖λ_t − λ*‖²`. Saturating arithmetic in `dual_step` and the clamp to `λ_max` keep every price in a compact set, which is what the bounded-subgradient hypothesis needs.

**Theorem 5, ES deadline schedulability.** Let `D` be the deadline and `t` the arrival time. The scheduler responds immediately unless Tier-0 returned `Defer` and `D − t − MARGIN ≥ T1 + T0 + OVH`. In the immediate case the response time is `T0 + OVH`, which is below `MARGIN` under the module's constants, so the response lands before `D`. In the dispatch case the watchdog fires at `t + T1 + T0 + OVH` at the latest, and the response completes by `t + T1 + T0 + OVH ≤ D − MARGIN < D`. Every response is either a Tier-0 or Tier-1 definite verdict, or the fallback `Deny` with `cache = false`. Apalache checks all three invariants over the nondeterministic Tier-1 outcome and latency. The cache rule follows from Theorem 1: a cached `Allow` must be a function of vnode-stable segments alone, which `response_for` enforces through `used_segments`, and a fallback is never cached because it encodes deadline pressure rather than a verdict.

**Theorem 6, verification transfer.** For each platform define `Safe` as the row of the table above and `Feasible(x)` as the Wave 1 envelope for the cage layer. Theorems 2 through 5 establish `∀ a ∈ Feasible(x), Safe(Compile(a))`, with the learned plan appearing only as an arbitrary element of `Feasible(x)`. By the Lean `transfer` theorem, `Safe(Compile(Π(P(x))))` holds for whatever `UltraBERT` or the Tier-0 micro-models propose. No proof above mentions a model weight, which is exactly why a weights change under `evaluate_weights_binding` does not invalidate them.

**Recap.** The deliverable is a `no_std`, `forbid(unsafe_code)` Tier-0 core shared by Linux and macOS, a Linux module that compiles shielded cage plans into Landlock v4+ descriptors and a bounded seccomp program and ingests eBPF LSM ring-buffer records into the four Copley segments, an Omarchy supervisor core that derives cgroup v2 limits from shadow prices by a monotone law, labels Wayland clients through the security-context protocol, and gates hardware signing on `receipt_fields_coupled`, and a macOS ES scheduler that answers every AUTH message before its deadline using Tier-1 only to refine Kleene unknowns. The Lean, Kani, and Apalache artifacts are additive entries in the proof manifest. Two items need measurement on target hardware rather than proof: the wall-clock cost of a full DAG evaluation, bounded here only in word operations, and the `TIER1_WCET_NS` figure, which must be calibrated per machine before the scheduler constants are frozen.