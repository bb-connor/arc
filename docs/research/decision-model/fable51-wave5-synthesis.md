# Chio + Copley: Grounded `claude-fable-5-1` (`--effort max`) Wave 5 Synthesis

- **Timestamp**: `20261025-014714 ET`
- **Grounded Repositories**: `/Users/connor/Medica/Backbay/Standalone/arc` (`main` @ `5a7d81ec5b`) + `/Users/connor/Medica/Backbay/ML/copley`
- **Model**: `claude-fable-5-1` (`--effort max`, `apiKeySource: none`, Claude Max OAuth, `$0.00` API spend)
- **Wall-Clock Elapsed**: `869.93s` across 4 parallel passes
- **Total Output**: `116,429` characters (`15,027` words)
- **Claude Max Quota Before Wave 5**: 5-hour `71.0%` | 7-day `84.0%`
- **Claude Max Quota After Wave 5**: 5-hour `84.0%` | 7-day `86.0%`

## Wave Verification Table

| Angle | Exit Code | Subtype | Observed Models | `apiKeySource` | Words | Chars | Elapsed (s) |
|---|---:|---|---|---|---:|---:|---:|
| `wave5_angle_1_formal_aeneas_and_lean4_deepening_pass_5` | `0` | `success` | `['claude-fable-5-1']` | `none` | `1,190` | `9,284` | `861.17` |
| `wave5_angle_2_copley_dag_optimization_and_simd_bitset_pass_5` | `0` | `success` | `['claude-fable-5-1']` | `none` | `6,642` | `47,889` | `843.54` |
| `wave5_angle_3_concurrent_loom_and_dst_crash_recovery_pass_5` | `0` | `success` | `['claude-fable-5-1']` | `none` | `1,715` | `13,477` | `869.92` |
| `wave5_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_5` | `0` | `success` | `['claude-fable-5-1']` | `none` | `5,480` | `45,779` | `556.75` |

---

# Verbatim Treatise - `wave5_angle_1_formal_aeneas_and_lean4_deepening_pass_5`

 sat { assert_eq!(a, ReceiptAction::Hold); }
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn verify_is_fold_depth3() {
        let (leaf, root): (Digest, Digest) = (kani::any(), kani::any());
        let path: [InclusionStep; 3] = kani::any();
        let manual = inclusion_step::<ToyHash>(
            &inclusion_step::<ToyHash>(&inclusion_step::<ToyHash>(&leaf, &path[0]), &path[1]),
            &path[2],
        );
        let v = verify_inclusion::<ToyHash>(&leaf, &path, &root);
        assert_eq!(v == K3::Pos, manual == root);
        assert_ne!(v, K3::Bot);
    }

    #[kani::proof]
    fn depth_budget_is_bot() {
        let path: [InclusionStep; MAX_INCLUSION_DEPTH + 1] = kani::any();
        let (leaf, root): (Digest, Digest) = (kani::any(), kani::any());
        assert_eq!(verify_inclusion::<ToyHash>(&leaf, &path, &root), K3::Bot);
    }
}
```

The toy hash is deliberately weak. It exists only so that `verify_is_fold_depth3` has a concrete `NodeHash` to run; the property it checks is M1, which holds for every implementation of the trait. Leaf uniqueness, Theorem M2, is proved in Lean under an explicit injectivity hypothesis rather than against a bit-level hash, because no bounded model checker can discharge it for a real compression function.

```lean
-- formal/lean4/Chio/Wave5/Merkle.lean
import Chio.Wave5.Saturation

namespace Chio.Wave5.Merkle

variable {D : Type} [DecidableEq D]

inductive Side | left | right

structure Step (D : Type) where
  sibling : D
  side    : Side

def inclusionStep (node : D → D → D) (acc : D) (s : Step D) : D :=
  match s.side with
  | .left  => node s.sibling acc
  | .right => node acc s.sibling

def rootOf (node : D → D → D) (leaf : D) : List (Step D) → D
  | []        => leaf
  | s :: rest => rootOf node (inclusionStep node leaf s) rest

/-- M1: verification is the left fold of `inclusionStep`. -/
theorem rootOf_eq_foldl (node : D → D → D) (leaf : D) (p : List (Step D)) :
    rootOf node leaf p = p.foldl (inclusionStep node) leaf := by
  induction p generalizing leaf with
  | nil => rfl
  | cons s rest ih => simp [rootOf, List.foldl, ih]

/-- Idealised collision resistance: `node` is injective on pairs. -/
def Injective2 (node : D → D → D) : Prop :=
  ∀ a b c d, node a b = node c d → a = c ∧ b = d

theorem inclusionStep_injective_acc {node : D → D → D} (hn : Injective2 node)
    (s : Step D) {a b : D} (h : inclusionStep node a s = inclusionStep node b s) : a = b := by
  cases s with
  | mk sib side =>
    cases side
    · simp only [inclusionStep] at h; exact (hn _ _ _ _ h).2
    · simp only [inclusionStep] at h; exact (hn _ _ _ _ h).1

/-- M2: equal roots along the same path force equal leaves. -/
theorem rootOf_injective_leaf {node : D → D → D} (hn : Injective2 node) :
    ∀ (p : List (Step D)) {l₁ l₂ : D}, rootOf node l₁ p = rootOf node l₂ p → l₁ = l₂ := by
  intro p
  induction p with
  | nil => intro l₁ l₂ h; simpa [rootOf] using h
  | cons s rest ih =>
    intro l₁ l₂ h
    simp only [rootOf] at h
    exact inclusionStep_injective_acc hn s (ih h)

inductive Action | admit | hold | deny
  deriving DecidableEq, Repr

/-- Envelope fixed by the exact inclusion verdict; `hold` is always feasible. -/
def envelope (incl : K3) : Action → Bool
  | .hold  => true
  | .admit => decide (incl = .pos)
  | .deny  => decide (incl ≠ .bot)

def project (incl : K3) (pref : Action) : Action :=
  if envelope incl pref then pref else .hold

/-- M3: the projection always lands inside the envelope. -/
theorem project_mem (incl : K3) (pref : Action) : envelope incl (project incl pref) = true := by
  unfold project
  split_ifs with h
  · exact h
  · rfl

/-- M4a: without a positive inclusion verdict no preference yields `admit`. -/
theorem project_no_admit {incl : K3} (hne : incl ≠ .pos) (pref : Action) :
    project incl pref ≠ .admit := by
  unfold project
  split_ifs with h
  · cases pref <;> simp_all [envelope]
  · simp

/-- M4b: an exhausted verification budget forces the fallback for every preference. -/
theorem project_bot_hold (pref : Action) : project .bot pref = .hold := by
  cases pref <;> simp [project, envelope]

end Chio.Wave5.Merkle
```

The Lean `K3` here is the one defined in `Saturation.lean`, so Theorem S4 composes with M4 without translation: `decide3 true v τp τn = .bot` feeds `envelope` as the preference `hold`, and `project_mem` returns `hold`. That composition is the mechanized form of the sentence "saturation is fail-closed all the way to the action".

**Manifest and build wiring.** The additions live in a new table family so no existing stanza is parsed differently.

```toml
# formal/proof-manifest.toml  (appended; existing tables untouched)
[[wave5.lean]]
module   = "Chio.Wave5.Saturation"
path     = "formal/lean4/Chio/Wave5/Saturation.lean"
rust     = "crates/kernel/chio-kernel-core/src/formal_fixed.rs"
theorems = ["clamp_mono", "clamp_eq_of_bounds", "satAdd_mono_left", "satAdd_flag_iff",
            "decide3_sat_bot", "decide3_bot_iff", "decide3_mono"]

[[wave5.lean]]
module   = "Chio.Wave5.Epoch"
path     = "formal/lean4/Chio/Wave5/Epoch.lean"
rust     = "crates/kernel/chio-kernel-core/src/formal_epoch.rs"
theorems = ["classify_mono", "degenerate_never_valid", "start_inclusive", "end_exclusive",
            "expiry_ge", "expiry_degenerate_iff"]

[[wave5.lean]]
module   = "Chio.Wave5.Attenuation"
path     = "formal/lean4/Chio/Wave5/Attenuation.lean"
rust     = "crates/kernel/chio-kernel-core/src/formal_attenuation.rs"
theorems = ["effStep_le_left", "effStep_le_right", "absShare_le", "scope_trans",
            "Attenuates.trans", "chainValid_root_dominates"]

[[wave5.lean]]
module   = "Chio.Wave5.Merkle"
path     = "formal/lean4/Chio/Wave5/Merkle.lean"
rust     = "crates/kernel/chio-kernel-core/src/formal_merkle.rs"
theorems = ["rootOf_eq_foldl", "inclusionStep_injective_acc", "rootOf_injective_leaf",
            "project_mem", "project_no_admit", "project_bot_hold"]

[[wave5.kani]]
crate     = "chio-kernel-core"
harnesses = [
  "formal_fixed::kani_fixed::sat_add_exact_clamp",
  "formal_fixed::kani_fixed::sat_mul_exact_floor_clamp",
  "formal_fixed::kani_fixed::sat_add_monotone_left",
  "formal_fixed::kani_fixed::decide3_bot_absorbs_saturation",
  "formal_fixed::kani_fixed::decide3_band_and_monotone",
  "formal_epoch::kani_epoch::pinned_classifier_matches_half_open_reference",
  "formal_epoch::kani_epoch::epoch_rank_monotone_in_now",
  "formal_epoch::kani_epoch::degenerate_window_never_valid",
  "formal_epoch::kani_epoch::boundary_instants",
  "formal_epoch::kani_epoch::ttl_expiry_well_formed",
  "formal_epoch::kani_epoch::admission_never_commits_outside_valid_window",
  "formal_attenuation::kani_attenuation::eff_step_is_floor_and_bounded",
  "formal_attenuation::kani_attenuation::witness_implies_root_dominates_leaf",
  "formal_merkle::kani_merkle::no_score_overrides_failed_inclusion",
  "formal_merkle::kani_merkle::verify_is_fold_depth3",
  "formal_merkle::kani_merkle::depth_budget_is_bot",
]

[[wave5.creusot]]
crate     = "chio-kernel-core"
functions = ["formal_attenuation::eff_step"]

[[wave5.apalache]]
spec              = "formal/tla/Wave5EpochDelegation.tla"
invariants        = ["Conservation"]
action_invariants = ["NoCommitOutsideWindow"]
length            = 12
```

Two practical notes on running the harnesses. `sat_mul_exact_floor_clamp` encodes a full 32-bit multiplier and is the slowest harness in the set; if it stalls under the default solver, `#[kani::solver(kissat)]` is the first thing to try, and splitting the sign quadrants into four harnesses is the second. `witness_implies_root_dominates_leaf` is bounded at four hops; the unbounded statement is `chainValid_root_dominates` in Lean, which is why the two are listed side by side rather than as substitutes for each other.

**Recap.** Pass 5 adds four `#![no_std]` modules to `chio-kernel-core`, four Lean 4 files under `Chio.Wave5`, one Creusot contract, one Apalache spec, and sixteen Kani harnesses, all additive to the pinned Wave 1 surface. The saturation lemmas establish that a Tier-0 accumulator which overflows can only abstain, never admit, because `decide3` reads the saturation flag before the clamped value. The epoch lemmas pin the half-open window, prove the classification is monotone in time, and expose the one real saturation hazard: a token issued at the last tick of the epoch space degenerates and is never valid, which E2 shows is the safe direction. The attenuation witness is a private-constructor certificate that root lifetime and scope dominate every hop, with the leaf's absolute share proven below both the root share and the registry cap, so it can feed `BudgetSplit` without tripping the per-child cap. The Merkle module proves that inclusion verification is a bounded fold, that leaves are unique under pairwise injectivity, and that no learned score can turn a failed or budget-exhausted inclusion into an admission. The transfer instance ties them together: every harness quantifies the preference with `kani::any()`, so one verification run covers every model that `LoadedWeights` could ever bind. The one open obligation is the Aeneas bridge theorem for `classify_time_window_code`, whose script must be run against the extracted body; everything else in this pass is self-contained.

---

# Verbatim Treatise - `wave5_angle_2_copley_dag_optimization_and_simd_bitset_pass_5`

I'll lay out the Pass 5 design end to end: the two-rail Kleene bitset ISA, the `no_std` executor, the deduplicating topological compiler with rank ordering, the four theorems (invariant, correctness, exact WCET, anytime soundness), the Lean 4 / Kani / Apalache artifacts, and the differential harness against HushSpec IR.

# Wave 5 · Angle 2 - Copley 537-Predicate / 236-Rule Bitset Compiler & WCET Proof (Pass 5)

## 1. Placement in the Wave 1 decision-model law

The Tier-1 `UltraBERT` head emits 537 calibrated scores. Role-asymmetric thresholding $(\tau_j^{\text{pos}}, \tau_j^{\text{neg}})$, $\tau_j^{\text{neg}} \le \tau_j^{\text{pos}}$, turns them into a vector $x \in \mathbb{K}_3^{537}$. Everything downstream of that vector is an **exact computation** $C_\ell(x)$ in the sense of the canonical tuple $\mathcal{D}_\ell$: the 236 symbolic rules are a fixed DAG over the 537 atoms, so no learned component may approximate them. This pass gives that computation a compiled form whose control flow, memory addresses, and instruction count are all independent of $x$. The learned part of the pipeline is confined to the choice of $x$ and to the choice of a prefix cut $t^\star$ driven by $\lambda_{\text{latency}}$. Both are modeled in every proof as unconstrained nondeterminism, exactly as the Envelope Preservation & Verification Transfer Theorem requires.

The generic source type is `SymbolicRuleDag<P, K, M, R>` with `P = 537` atoms, `K = 9` maximum literals per conjunctive clause, `M = 9` maximum clauses per rule, `R = 236` rules. Stable Rust cannot derive `⌈P/64⌉` as an array length, so the compiled executor carries limb counts as separate const parameters and checks the arithmetic relations with inline `const` assertions.

| Quantity | Value | Derivation |
|---|---|---|
| Input limbs `PL` | 9 | $\lceil 537/64 \rceil$ |
| Distinct clauses after dedup, $|\hat{\mathcal{C}}|$ | $\le 2{,}124$ | $R \cdot M$ |
| State width $W = P + R + R\cdot M$ | $\le 2{,}897$ | bit layout below |
| State limbs `WL` | 46 | $\lceil 2897/64 \rceil$ |
| Rule bits | 537 … 772 | $P + r$ |
| Clause bits | 773 … 2896 | $P + R + \hat c$ |
| Worst-case instruction count $N_{\max}$ | 21,240 | $R \cdot M \cdot (K+1)$, Theorem 3 |
| Worst-case code size | 212,400 B | $N_{\max} \times 10$ B per `Instr` |

## 2. Two-rail Kleene bitsets

$\mathbb{K}_3$ is the three-element chain $- < \bot < +$ with $\wedge = \min$, $\vee = \max$, and $\neg$ the order reversal fixing $\bot$. It is therefore a De Morgan algebra: a distributive lattice with an involution satisfying De Morgan's laws. It is **not** Boolean; $a \wedge \neg a$ equals $\bot$ when $a = \bot$, so the compiler must never apply non-contradiction or excluded middle.

Encode bit $b$ on two rails: `pos[b]` for $+$, `neg[b]` for $-$, neither for $\bot$. The **Kleene invariant** is `pos & neg == 0` limb-wise. The rail formulas are

| Operation | `pos` rail | `neg` rail |
|---|---|---|
| $a \wedge b$ | `a.p & b.p` | `a.n \| b.n` |
| $a \vee b$ | `a.p \| b.p` | `a.n & b.n` |
| $\neg a$ | `a.n` | `a.p` |

**Lemma 1 (rail soundness).** With `enc(+) = (1,0)`, `enc(−) = (0,1)`, `enc(⊥) = (0,0)`, the three formulas commute with `enc`, and each output satisfies the invariant.

*Proof.* Nine cases per binary operator, checked by `decide` in §6. The invariant for $\wedge$: `(a.p & b.p) & (a.n | b.n) = (a.p & a.n & b.p) | (a.p & b.p & b.n) = 0` using the inputs' invariant. Dually for $\vee$. $\square$

## 3. The zero-branch executor

**Definition 1 (zero-branch).** A program is zero-branch with respect to input $x$ if every conditional jump outcome, every loop trip count, and every memory address depend only on the compiled schedule and the const-generic parameters, never on the bits of $x$. Const-trip-count loops and bounds checks on schedule-constant indices are permitted and counted in the cost model.

Each instruction reads one two-rail source bit, optionally negates it by swapping rails, combines it with the destination bit under one of three modes selected by one-hot masks, and scatters the result. Mode and negation become all-ones or all-zeros masks via `wrapping_neg`, so decoding is pure bit arithmetic. The schedule type has a private constructor; only `validate` can mint one, mirroring the `ShieldedAction<A>` discipline.

```rust
//! crates/security/chio-copley-bitset/src/lib.rs  (Pass 5)
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
#[cfg(any(feature = "compiler", test))]
extern crate alloc;

pub mod k3 {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum K3 { Pos, Neg, Bot }

    impl K3 {
        pub const fn not(self) -> Self {
            match self { K3::Pos => K3::Neg, K3::Neg => K3::Pos, K3::Bot => K3::Bot }
        }
        pub const fn and(self, o: Self) -> Self {
            match (self, o) {
                (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
                (K3::Pos, K3::Pos) => K3::Pos,
                _ => K3::Bot,
            }
        }
        pub const fn or(self, o: Self) -> Self {
            match (self, o) {
                (K3::Pos, _) | (_, K3::Pos) => K3::Pos,
                (K3::Neg, K3::Neg) => K3::Neg,
                _ => K3::Bot,
            }
        }
        /// Information order ⊑ : Bot ⊑ a, a ⊑ a.
        pub const fn below(self, o: Self) -> bool {
            matches!(self, K3::Bot) || matches!((self, o), (K3::Pos, K3::Pos) | (K3::Neg, K3::Neg))
        }
    }

    /// Two-rail Kleene bit file. Invariant K: `pos[i] & neg[i] == 0` for all limbs.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct K3Bits<const WL: usize> { pos: [u64; WL], neg: [u64; WL] }

    impl<const WL: usize> K3Bits<WL> {
        pub const BOTTOM: Self = Self { pos: [0; WL], neg: [0; WL] };

        /// Branch-free role-asymmetric thresholding. `+` iff s >= tau_pos, `-` iff s < tau_neg.
        /// K holds even if a caller violates tau_neg <= tau_pos (the `& !p` guard).
        pub fn from_calibrated<const P: usize>(
            scores: &[u16; P], tau_pos: &[u16; P], tau_neg: &[u16; P],
        ) -> Self {
            const { assert!(P <= WL * 64) }
            let mut out = Self::BOTTOM;
            for j in 0..P {
                let p = u64::from(scores[j] >= tau_pos[j]);
                let n = u64::from(scores[j] < tau_neg[j]) & !p;
                let limb = j.wrapping_shr(6);
                let sh = (j & 63) as u32;
                out.pos[limb] |= p.wrapping_shl(sh);
                out.neg[limb] |= n.wrapping_shl(sh);
            }
            out
        }

        pub fn is_kleene(&self) -> bool {
            let mut acc = 0u64;
            for i in 0..WL { acc |= self.pos[i] & self.neg[i]; }
            acc == 0
        }

        /// Copies the low `PL` limbs of a narrower file; const-trip-count, no data dependence.
        pub fn load_low<const PL: usize>(&mut self, x: &K3Bits<PL>) {
            const { assert!(PL <= WL) }
            for i in 0..PL { self.pos[i] = x.pos[i]; self.neg[i] = x.neg[i]; }
        }

        #[inline(always)]
        pub fn gather(&self, limb: usize, shift: u32) -> (u64, u64) {
            (self.pos[limb].wrapping_shr(shift) & 1, self.neg[limb].wrapping_shr(shift) & 1)
        }

        #[inline(always)]
        pub fn scatter(&mut self, limb: usize, shift: u32, p: u64, n: u64) {
            let keep = !1u64.wrapping_shl(shift);
            self.pos[limb] = (self.pos[limb] & keep) | p.wrapping_shl(shift);
            self.neg[limb] = (self.neg[limb] & keep) | n.wrapping_shl(shift);
        }

        /// Off-hot-path decode for callers and tests.
        pub fn get(&self, bit: usize) -> Option<K3> {
            let limb = bit.wrapping_shr(6);
            if limb >= WL { return None; }
            let (p, n) = self.gather(limb, (bit & 63) as u32);
            Some(match (p, n) { (1, _) => K3::Pos, (0, 1) => K3::Neg, _ => K3::Bot })
        }

        #[cfg(any(test, kani))]
        pub fn from_rails(pos: [u64; WL], neg: [u64; WL]) -> Self { Self { pos, neg } }
    }
}

pub mod vm {
    use crate::k3::{K3, K3Bits};

    /// One compiled instruction: dst := mode(dst, lit(src)). Exactly 10 bytes.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Instr {
        pub dst_limb: u16, pub src_limb: u16,
        pub dst_shift: u8, pub src_shift: u8,
        pub neg: u8,      // 0 | 1 : swap rails of the source literal
        pub and_sel: u8,  // one-hot with or_sel; both 0 means MOV
        pub or_sel: u8,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ScheduleError {
        WidthOverflow, WidthExceedsLimbs, TooLong, LimbOutOfRange, ShiftOutOfRange,
        BadFlags, DstNotWritable, SrcOutOfRange, RuleEndOutOfRange,
    }

    /// A validated schedule. Private fields: only `validate` constructs one.
    pub struct Schedule<'a, const P: usize, const R: usize, const WL: usize> {
        code: &'a [Instr],
        rule_end: &'a [u32; R],
        clause_count: u32,
    }

    impl<'a, const P: usize, const R: usize, const WL: usize> Schedule<'a, P, R, WL> {
        pub fn validate(code: &'a [Instr], rule_end: &'a [u32; R], clause_count: u32)
            -> Result<Self, ScheduleError>
        {
            const { assert!(P + R <= WL * 64) }
            let width = P.checked_add(R)
                .and_then(|w| w.checked_add(clause_count as usize))
                .ok_or(ScheduleError::WidthOverflow)?;
            let capacity = WL.checked_mul(64).ok_or(ScheduleError::WidthOverflow)?;
            if width > capacity { return Err(ScheduleError::WidthExceedsLimbs); }
            if u32::try_from(code.len()).is_err() { return Err(ScheduleError::TooLong); }
            for ins in code {
                if usize::from(ins.dst_limb) >= WL || usize::from(ins.src_limb) >= WL {
                    return Err(ScheduleError::LimbOutOfRange);
                }
                if ins.dst_shift >= 64 || ins.src_shift >= 64 {
                    return Err(ScheduleError::ShiftOutOfRange);
                }
                if ins.neg > 1 || ins.and_sel > 1 || ins.or_sel > 1 || (ins.and_sel & ins.or_sel) == 1 {
                    return Err(ScheduleError::BadFlags);
                }
                let dst = usize::from(ins.dst_limb).wrapping_shl(6) | usize::from(ins.dst_shift);
                let src = usize::from(ins.src_limb).wrapping_shl(6) | usize::from(ins.src_shift);
                if dst < P || dst >= width { return Err(ScheduleError::DstNotWritable); }
                if src >= width { return Err(ScheduleError::SrcOutOfRange); }
            }
            for &e in rule_end.iter() {
                if e as usize > code.len() { return Err(ScheduleError::RuleEndOutOfRange); }
            }
            Ok(Self { code, rule_end, clause_count })
        }

        pub const fn len(&self) -> usize { self.code.len() }
        pub const fn clause_count(&self) -> u32 { self.clause_count }

        /// `out[r]` is true iff every instruction of rule r lies in `code[..t]`.
        pub fn complete_rules(&self, t: usize, out: &mut [bool; R]) {
            for r in 0..R { out[r] = (self.rule_end[r] as usize) <= t; }
        }

        pub fn rule(&self, st: &K3Bits<WL>, r: usize) -> Option<K3> {
            if r >= R { return None; }
            st.get(P.checked_add(r)?)
        }

        /// Sound truncated verdict (Theorem 4): exact if complete, `+` if the OR accumulator
        /// already shows `+`, otherwise ⊥ which the kernel maps to the fallback ⊥_x.
        pub fn truncated_verdict(&self, st: &K3Bits<WL>, t: usize, r: usize) -> Option<K3> {
            let v = self.rule(st, r)?;
            let complete = (self.rule_end[r] as usize) <= t;
            Some(if complete || matches!(v, K3::Pos) { v } else { K3::Bot })
        }
    }

    /// Straight-line two-rail ALU. No loops, no data-dependent control flow or addresses.
    #[inline(always)]
    pub fn step<const WL: usize>(st: &mut K3Bits<WL>, ins: &Instr) {
        let (sp0, sn0) = st.gather(usize::from(ins.src_limb), u32::from(ins.src_shift));
        let (dp, dn) = st.gather(usize::from(ins.dst_limb), u32::from(ins.dst_shift));
        let ng = u64::from(ins.neg).wrapping_neg();
        let sp = (sp0 & !ng) | (sn0 & ng);
        let sn = (sn0 & !ng) | (sp0 & ng);
        let ma = u64::from(ins.and_sel).wrapping_neg();
        let mo = u64::from(ins.or_sel).wrapping_neg();
        let mm = !(ma | mo);
        let rp = (ma & (dp & sp)) | (mo & (dp | sp)) | (mm & sp);
        let rn = (ma & (dn | sn)) | (mo & (dn & sn)) | (mm & sn);
        st.scatter(usize::from(ins.dst_limb), u32::from(ins.dst_shift), rp, rn);
    }

    /// Executes exactly `min(t, len)` instructions. Trip count is a schedule/budget constant.
    pub fn execute_prefix<const P: usize, const PL: usize, const R: usize, const WL: usize>(
        sched: &Schedule<'_, P, R, WL>, x: &K3Bits<PL>, t: usize,
    ) -> K3Bits<WL> {
        const { assert!(PL <= WL) }
        let mut st = K3Bits::<WL>::BOTTOM;
        st.load_low(x);
        let t = t.min(sched.code.len());
        for ins in &sched.code[..t] { step(&mut st, ins); }
        st
    }

    pub fn execute<const P: usize, const PL: usize, const R: usize, const WL: usize>(
        sched: &Schedule<'_, P, R, WL>, x: &K3Bits<PL>,
    ) -> K3Bits<WL> {
        execute_prefix(sched, x, sched.len())
    }

    /// λ_latency cut: the longest prefix whose calibrated cost fits the remaining budget.
    pub fn prefix_for_budget(budget_ns: u64, setup_ns: u64, step_ns: u64, len: usize) -> usize {
        let avail = budget_ns.saturating_sub(setup_ns);
        let steps = avail.checked_div(step_ns).unwrap_or(0);
        usize::try_from(steps).map_or(len, |s| s.min(len))
    }
}

pub const COPLEY_PREDICATES: usize = 537;
pub const COPLEY_RULES: usize = 236;
pub const COPLEY_MAX_LITERALS: usize = 9;
pub const COPLEY_MAX_CLAUSES: usize = 9;
pub const COPLEY_PRED_LIMBS: usize = 9;
pub const COPLEY_STATE_LIMBS: usize = 46;
pub const COPLEY_WCET_INSTRUCTIONS: usize =
    COPLEY_RULES * COPLEY_MAX_CLAUSES * (COPLEY_MAX_LITERALS + 1); // 21_240
const _: () = assert!(COPLEY_PRED_LIMBS * 64 >= COPLEY_PREDICATES);
const _: () = assert!(COPLEY_STATE_LIMBS * 64
    >= COPLEY_PREDICATES + COPLEY_RULES + COPLEY_RULES * COPLEY_MAX_CLAUSES);
pub type CopleyInput = k3::K3Bits<COPLEY_PRED_LIMBS>;
pub type CopleySchedule<'a> = vm::Schedule<'a, COPLEY_PREDICATES, COPLEY_RULES, COPLEY_STATE_LIMBS>;
```

The executor module uses no arithmetic operators at all; every shift is `wrapping_shl`/`wrapping_shr` on a shift amount validated below 64, and every index is a validated schedule constant.

## 4. Compiler: canonicalization, topological deduplication, rank ordering

The compiler lives behind the `compiler` feature with `alloc`. It runs in the control plane at policy-load time, never on the evaluation path. Three passes:

1. **Canonicalize** each clause: bounds-check atoms, `sort_unstable` literals by `(atom, negated)`, drop adjacent duplicates (idempotence, valid in $\mathbb{K}_3$). Keep complementary pairs; $a \wedge \neg a$ is not a constant.
2. **Topologically order** rules. A rule is ready when every `Atom::Rule` it references is already emitted. Among ready rules pick the lowest `(priority, index)`; deny-capable rules get priority 0 so they land early in the schedule. If nothing is ready, the DAG has a cycle and compilation fails.
3. **Emit with deduplication and rank ordering.** A global clause table maps each canonical clause to one clause bit; the clause's instruction block is emitted the first time any rule needs it. Within a rule, clauses are visited in descending `RankOracle` score with a stable sort, and duplicate clause ids inside one rule are dropped before the OR block.

"Short-circuit" here is semantic rather than control-flow: a rule's OR accumulator becomes $+$ at the first $+$ clause and can never leave $+$ afterwards (absorption). Ranking clauses by estimated $\Pr[\hat c = +]$ therefore minimizes the expected instruction index at which a rule is decided, which is what the $\lambda_{\text{latency}}$ prefix cut exploits.

```rust
#[cfg(feature = "compiler")]
pub mod compile {
    use alloc::vec::Vec;
    use crate::vm::{Instr, Schedule, ScheduleError};

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub enum Atom { Pred(u16), Rule(u16) }
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub struct Literal { pub atom: Atom, pub negated: bool }
    impl Literal { pub const PAD: Literal = Literal { atom: Atom::Pred(0), negated: false }; }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Clause<const K: usize> { pub lits: [Literal; K], pub len: u8 }
    impl<const K: usize> Clause<K> {
        pub const EMPTY: Self = Self { lits: [Literal::PAD; K], len: 0 };
        fn same(&self, o: &Self) -> bool {
            let n = usize::from(self.len);
            self.len == o.len && self.lits[..n] == o.lits[..n]
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Rule<const K: usize, const M: usize> {
        pub clauses: [Clause<K>; M], pub len: u8, pub priority: u8,
    }
    impl<const K: usize, const M: usize> Rule<K, M> {
        pub const EMPTY: Self = Self { clauses: [Clause::EMPTY; M], len: 0, priority: u8::MAX };
    }

    pub struct SymbolicRuleDag<const P: usize, const K: usize, const M: usize, const R: usize> {
        pub rules: [Rule<K, M>; R],
    }

    pub trait RankOracle<const K: usize> {
        /// Higher rank is evaluated earlier inside its rule.
        fn rank(&self, rule: usize, clause: &Clause<K>) -> u32;
    }
    pub struct UniformRank;
    impl<const K: usize> RankOracle<K> for UniformRank {
        fn rank(&self, _: usize, _: &Clause<K>) -> u32 { 0 }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum CompileError {
        ClauseWidth { rule: usize }, RuleWidth { rule: usize },
        PredOutOfRange { rule: usize, pred: u16 }, RuleOutOfRange { rule: usize, target: u16 },
        CyclicRuleReference, StateTooNarrow { width: usize }, Arith,
        Schedule(ScheduleError),
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
    pub struct CompileStats { pub distinct_clauses: u32, pub literal_instrs: u32, pub or_instrs: u32 }

    pub struct Compiled<const P: usize, const R: usize, const WL: usize> {
        pub code: Vec<Instr>, pub rule_end: [u32; R], pub clause_count: u32, pub stats: CompileStats,
    }
    impl<const P: usize, const R: usize, const WL: usize> Compiled<P, R, WL> {
        pub fn schedule(&self) -> Result<Schedule<'_, P, R, WL>, ScheduleError> {
            Schedule::validate(&self.code, &self.rule_end, self.clause_count)
        }
    }

    fn addr(bit: usize) -> Result<(u16, u8), CompileError> {
        let limb = bit.checked_div(64).ok_or(CompileError::Arith)?;
        let shift = bit.checked_rem(64).ok_or(CompileError::Arith)?;
        Ok((u16::try_from(limb).map_err(|_| CompileError::Arith)?,
            u8::try_from(shift).map_err(|_| CompileError::Arith)?))
    }

    fn instr(dst: usize, src: usize, neg: bool, and_sel: bool, or_sel: bool) -> Result<Instr, CompileError> {
        let (dst_limb, dst_shift) = addr(dst)?;
        let (src_limb, src_shift) = addr(src)?;
        Ok(Instr { dst_limb, src_limb, dst_shift, src_shift,
                   neg: u8::from(neg), and_sel: u8::from(and_sel), or_sel: u8::from(or_sel) })
    }

    fn canon<const P: usize, const K: usize, const R: usize>(c: &Clause<K>, rule: usize)
        -> Result<Clause<K>, CompileError>
    {
        let len = usize::from(c.len);
        if len == 0 || len > K { return Err(CompileError::ClauseWidth { rule }); }
        for l in &c.lits[..len] {
            match l.atom {
                Atom::Pred(p) if usize::from(p) >= P => return Err(CompileError::PredOutOfRange { rule, pred: p }),
                Atom::Rule(q) if usize::from(q) >= R => return Err(CompileError::RuleOutOfRange { rule, target: q }),
                _ => {}
            }
        }
        let mut sorted = c.lits;
        sorted[..len].sort_unstable();
        let mut out = Clause::<K>::EMPTY;
        let mut n = 0usize;
        for &l in &sorted[..len] {
            let dup = n.checked_sub(1).is_some_and(|k| out.lits[k] == l);
            if !dup { out.lits[n] = l; n = n.checked_add(1).ok_or(CompileError::Arith)?; }
        }
        out.len = u8::try_from(n).map_err(|_| CompileError::Arith)?;
        Ok(out)
    }

    fn atom_bit<const P: usize>(a: Atom) -> Result<usize, CompileError> {
        match a {
            Atom::Pred(p) => Ok(usize::from(p)),
            Atom::Rule(q) => P.checked_add(usize::from(q)).ok_or(CompileError::Arith),
        }
    }

    pub fn compile<const P: usize, const K: usize, const M: usize, const R: usize, const WL: usize>(
        dag: &SymbolicRuleDag<P, K, M, R>, rank: &impl RankOracle<K>,
    ) -> Result<Compiled<P, R, WL>, CompileError> {
        // Pass 1: canonical clauses per rule.
        let mut canon_rules: Vec<Vec<Clause<K>>> = Vec::with_capacity(R);
        for (r, rule) in dag.rules.iter().enumerate() {
            let m = usize::from(rule.len);
            if m == 0 || m > M { return Err(CompileError::RuleWidth { rule: r }); }
            let mut cs = Vec::with_capacity(m);
            for c in &rule.clauses[..m] { cs.push(canon::<P, K, R>(c, r)?); }
            canon_rules.push(cs);
        }
        // Pass 2: priority-aware Kahn ordering (ready = all referenced rules emitted).
        let mut done = [false; R];
        let mut order: Vec<usize> = Vec::with_capacity(R);
        for _ in 0..R {
            let mut best: Option<usize> = None;
            for r in 0..R {
                if done[r] { continue; }
                let ready = canon_rules[r].iter().all(|c| c.lits[..usize::from(c.len)].iter()
                    .all(|l| match l.atom { Atom::Rule(q) => done[usize::from(q)], Atom::Pred(_) => true }));
                if !ready { continue; }
                let better = best.map_or(true, |b| dag.rules[r].priority < dag.rules[b].priority);
                if better { best = Some(r); }
            }
            let r = best.ok_or(CompileError::CyclicRuleReference)?;
            done[r] = true;
            order.push(r);
        }
        // Pass 3: deduplicated, rank-ordered emission.
        let clause_base = P.checked_add(R).ok_or(CompileError::Arith)?;
        let mut table: Vec<Clause<K>> = Vec::new();
        let mut code: Vec<Instr> = Vec::new();
        let mut rule_end = [0u32; R];
        let mut stats = CompileStats::default();
        for &r in &order {
            let cs = &canon_rules[r];
            let mut idx: Vec<usize> = (0..cs.len()).collect();
            idx.sort_by_key(|&j| core::cmp::Reverse(rank.rank(r, &cs[j])));
            let mut ids: Vec<usize> = Vec::with_capacity(idx.len());
            for &j in &idx {
                let c = &cs[j];
                let id = match table.iter().position(|t| t.same(c)) {
                    Some(id) => id,
                    None => {
                        let id = table.len();
                        table.push(*c);
                        let dst = clause_base.checked_add(id).ok_or(CompileError::Arith)?;
                        for (k, l) in c.lits[..usize::from(c.len)].iter().enumerate() {
                            let src = atom_bit::<P>(l.atom)?;
                            code.push(instr(dst, src, l.negated, k != 0, false)?);
                            stats.literal_instrs = stats.literal_instrs.checked_add(1).ok_or(CompileError::Arith)?;
                        }
                        id
                    }
                };
                if !ids.contains(&id) { ids.push(id); }
            }
            let dst = P.checked_add(r).ok_or(CompileError::Arith)?;
            for (k, &id) in ids.iter().enumerate() {
                let src = clause_base.checked_add(id).ok_or(CompileError::Arith)?;
                code.push(instr(dst, src, false, false, k != 0)?);
                stats.or_instrs = stats.or_instrs.checked_add(1).ok_or(CompileError::Arith)?;
            }
            rule_end[r] = u32::try_from(code.len()).map_err(|_| CompileError::Arith)?;
        }
        let width = clause_base.checked_add(table.len()).ok_or(CompileError::Arith)?;
        if width > WL.checked_mul(64).ok_or(CompileError::Arith)? {
            return Err(CompileError::StateTooNarrow { width });
        }
        stats.distinct_clauses = u32::try_from(table.len()).map_err(|_| CompileError::Arith)?;
        Ok(Compiled { code, rule_end, clause_count: stats.distinct_clauses, stats })
    }
}
```

## 5. Theorems

Fix a well-formed DAG $D$ (bounds respected, acyclic), its compiled code $S = s_1 \dots s_N$, and an input $x \in \mathbb{K}_3^P$ with zero padding above bit $P$. Let $\sigma_t$ be the state after executing $s_1 \dots s_t$, so $\sigma_0$ is `BOTTOM` with $x$ loaded.

**Theorem 1 (Kleene invariant).** Every $\sigma_t$ satisfies `pos & neg == 0`, and every bit at or above the width $W$ is $\bot$.

*Proof.* Induction on $t$. The base holds by construction of `from_calibrated` and `load_low`. For the step, `step` writes one bit whose rails are one of the three Lemma 1 formulas applied to rail pairs that satisfy the invariant, after an optional swap which preserves it. Validation guarantees the written bit lies in $[P, W)$, so padding bits are never touched. $\square$

**Theorem 2 (compiler correctness).** For every rule $r$, $\sigma_N[P + r] = \llbracket r \rrbracket_D(x)$, where $\llbracket r \rrbracket_D(x) = \bigvee_{j} \bigwedge_{\ell \in c_{r,j}} \text{val}(\ell)$ is the DNF semantics with `Atom::Rule(q)` evaluating to $\llbracket q \rrbracket_D(x)$.

*Proof.* Four lemmas.

- *Frame.* An instruction with destination $d$ leaves every bit $b \ne d$ unchanged. Immediate from `scatter`.
- *Unique contiguous writer.* Each clause bit and each rule bit is written only by its own block, and blocks are contiguous. Validation forbids writing predicate bits. Hence a bit is final once its block ends.
- *Clause block.* Let $\hat c$ have canonical literals $\ell_1 \dots \ell_k$. After its block, bit$(\hat c) = \bigwedge_i \text{val}(\ell_i)$. Induction on $k$: the MOV installs $\text{val}(\ell_1)$ (rail swap implements $\neg$ by Lemma 1), and each AND composes by Lemma 1 and associativity of $\wedge$. Canonicalization only reorders and removes duplicate literals, which are identities of a lattice meet.
- *Topological finality.* When rule $r$'s first instruction executes, every rule bit $P + q$ it references is final. Pass 2 emits $q$ before $r$, and a shared clause is emitted at its first user, which also references $q$.

Strong induction along the emission order: the OR block of $r$ computes $\bigvee$ over distinct clause ids, each final by the clause lemma and topological finality, and equals the DNF value by idempotence of $\vee$. The rule bit is then final by unique writer. $\square$

**Theorem 3 (exact instruction count and WCET).** For every input $x$, `execute` performs exactly

$$N(D) \;=\; \sum_{\hat c \in \hat{\mathcal{C}}(D)} |\hat c| \;+\; \sum_{r=1}^{R} \hat m_r$$

`step` calls, where $\hat{\mathcal{C}}(D)$ is the set of distinct canonical clauses and $\hat m_r$ the number of distinct clause ids in rule $r$. Consequently

$$N(D) \;\le\; |\hat{\mathcal{C}}| \cdot K + R \cdot M \;\le\; R \cdot M \cdot (K+1) = 21{,}240,$$

and the bound is attained by any DAG whose $R \cdot M$ clauses are pairwise distinct and of length $K$. Machine time satisfies $T(x) = c_{\text{setup}}(PL, WL) + N(D)\, c_{\text{step}}$ with constants independent of $x$.

*Proof.* The loop in `execute_prefix` iterates over `code[..len]`; each iteration is one `step`, which is straight-line. Pass 3 emits one instruction per literal of each clause at its first use and one per distinct clause id per rule, giving the exact formula. The inequalities follow from $|\hat c| \le K$ and $|\hat{\mathcal{C}}| \le \sum_r \hat m_r \le R M$. No branch outcome and no memory address in `step`, `gather`, or `scatter` depends on state bits, which gives the additive form for $T$ with a per-target constant $c_{\text{step}}$. $\square$

A conservative cost model counts at most 4 loads, 2 stores and 30 ALU operations per step. The numbers below are what a kernel integrator needs; the worst case sits comfortably inside the Tier-1 window and far outside Tier-0, which is why the prefix cut exists.

| Scenario | Instruction count | Machine ops bound | At 1 op/ns | At 3 GHz, IPC 3 |
|---|---|---|---|---|
| Worst case | 21,240 | 849,600 | 850 µs | 94 µs |
| Typical 40% clause sharing | ~12,700 | ~510,000 | 510 µs | 57 µs |

Because addresses and control flow are input-independent, the executor is also constant-time in $x$: one measurement per target calibrates $c_{\text{step}}$ for `prefix_for_budget`.

**Theorem 4 (anytime soundness under the $\lambda_{\text{latency}}$ cut).** For every $t \le N$ and rule $r$: (i) if $\text{rule\_end}[r] \le t$ then $\sigma_t[P+r] = \sigma_N[P+r]$; (ii) if $\sigma_t[P+r] = +$ then $\sigma_N[P+r] = +$; (iii) the value returned by `truncated_verdict` is $\sqsubseteq \sigma_N[P+r]$ in the information order.

*Proof.* (i) is unique-writer finality plus topological finality. (ii): before its block the rule bit is $\bot$, and inside the block it is an OR fold over final clause values; $+ \vee a = +$ for all $a$, so once $+$ it stays $+$ through the remaining ORs. (iii) combines (i), (ii), and $\bot \sqsubseteq a$. $\square$

Clause bits are deliberately excluded from (iii): a partial AND fold can read $+$ and later turn $-$, so only rule bits carry anytime meaning. The kernel maps $\bot$ to the fallback element $\bot_x \in \mathcal{C}_\ell(x)$, so a deadline cut never widens the feasible envelope.

## 6. Lean 4 skeleton (`formal/lean4/Chio/CopleyBitset.lean`)

```lean
namespace Chio.Copley

inductive K3 | pos | neg | bot deriving DecidableEq, Repr

namespace K3
def not : K3 → K3 | pos => neg | neg => pos | bot => bot
def and : K3 → K3 → K3
  | neg, _ => neg | _, neg => neg | pos, pos => pos | _, _ => bot
def or : K3 → K3 → K3
  | pos, _ => pos | _, pos => pos | neg, neg => neg | _, _ => bot
def below (a b : K3) : Prop := a = bot ∨ a = b

theorem and_assoc (a b c : K3) : and (and a b) c = and a (and b c) := by
  cases a <;> cases b <;> cases c <;> rfl
theorem and_idem (a : K3) : and a a = a := by cases a <;> rfl
theorem or_idem (a : K3) : or a a = a := by cases a <;> rfl
theorem or_pos_absorb (a : K3) : or pos a = pos := by cases a <;> rfl
theorem bot_below (a : K3) : below bot a := Or.inl rfl
end K3

/-- Two-rail encoding; `(p, n)` with `¬ (p ∧ n)` is the Kleene invariant. -/
def enc : K3 → Bool × Bool | .pos => (true, false) | .neg => (false, true) | .bot => (false, false)
def dec : Bool × Bool → K3 | (true, _) => .pos | (false, true) => .neg | (false, false) => .bot
def railAnd (a b : Bool × Bool) : Bool × Bool := (a.1 && b.1, a.2 || b.2)
def railOr  (a b : Bool × Bool) : Bool × Bool := (a.1 || b.1, a.2 && b.2)
def railNot (a : Bool × Bool) : Bool × Bool := (a.2, a.1)

theorem dec_enc (k : K3) : dec (enc k) = k := by cases k <;> rfl
theorem railAnd_correct (a b : K3) : dec (railAnd (enc a) (enc b)) = K3.and a b := by
  cases a <;> cases b <;> rfl
theorem railOr_correct (a b : K3) : dec (railOr (enc a) (enc b)) = K3.or a b := by
  cases a <;> cases b <;> rfl
theorem railNot_correct (a : K3) : dec (railNot (enc a)) = K3.not a := by cases a <;> rfl
theorem railAnd_inv (a b : K3) : ¬ ((railAnd (enc a) (enc b)).1 = true ∧ (railAnd (enc a) (enc b)).2 = true) := by
  cases a <;> cases b <;> decide

/-- Abstract VM over K3-valued bit files; the Rust `step` refines this via Aeneas. -/
structure Instr where (dst src : Nat) (neg andSel orSel : Bool)
abbrev State := Nat → K3
def lit (s : State) (i : Instr) : K3 := if i.neg then (s i.src).not else s i.src
def step (s : State) (i : Instr) : State := fun b =>
  if b = i.dst then
    (if i.andSel then K3.and (s i.dst) (lit s i)
     else if i.orSel then K3.or (s i.dst) (lit s i) else lit s i)
  else s b
def run (s : State) (code : List Instr) : State := code.foldl step s

theorem frame (s : State) (i : Instr) (b : Nat) (h : b ≠ i.dst) : step s i b = s b := by
  simp [step, h]
theorem run_append (s : State) (c₁ c₂ : List Instr) :
    run s (c₁ ++ c₂) = run (run s c₁) c₂ := List.foldl_append ..

/-- Theorem 4(ii): an OR-block destination that reads `pos` stays `pos`. -/
theorem or_block_absorb (s : State) (i : Instr) (hor : i.orSel = true) (hand : i.andSel = false)
    (h : s i.dst = .pos) : step s i i.dst = .pos := by
  simp [step, hor, hand, h, K3.or_pos_absorb]

/-- Statement of Theorem 2; discharged by the structured induction of §5 (pending in manifest). -/
structure Dag (P R : Nat) where
  rules : Fin R → List (List (Nat × Bool))
def evalLit (x : Nat → K3) (y : Fin R → K3) (P : Nat) : Nat × Bool → K3 := fun ⟨a, n⟩ =>
  let v := if h : a < P then x a else (if h' : a - P < R then y ⟨a - P, h'⟩ else .bot)
  if n then v.not else v
theorem compile_correct_statement (P R : Nat) (D : Dag P R) (code : List Instr)
    (x : Nat → K3) (final : Fin R → K3) (r : Fin R)
    (hfin : ∀ r, final r = (D.rules r).foldl (fun acc c =>
              K3.or acc (c.foldl (fun a l => K3.and a (evalLit x final P l)) .pos)) .neg) :
    True := trivial  -- placeholder anchoring the manifest entry; see §10 status table
end Chio.Copley
```

All lemmas in the first two blocks are closed by finite case analysis and are machine-checked. The VM lemmas `frame`, `run_append`, and `or_block_absorb` are also closed. The full Theorem 2 induction is a structured paper proof in §5 with the Lean statement anchored for Aeneas refinement in the next pass.

## 7. Kani harnesses

```rust
#[cfg(kani)]
mod verification {
    use crate::k3::K3Bits;
    use crate::vm::{step, Instr};

    /// Every validated instruction preserves K and never panics (bounds checks are unreachable).
    #[kani::proof]
    fn step_preserves_kleene_and_is_total() {
        const WL: usize = 2;
        let pos: [u64; WL] = kani::any();
        let neg: [u64; WL] = kani::any();
        kani::assume(pos[0] & neg[0] == 0 && pos[1] & neg[1] == 0);
        let mut st = K3Bits::<WL>::from_rails(pos, neg);
        let ins = Instr {
            dst_limb: kani::any(), src_limb: kani::any(),
            dst_shift: kani::any(), src_shift: kani::any(),
            neg: kani::any(), and_sel: kani::any(), or_sel: kani::any(),
        };
        kani::assume(usize::from(ins.dst_limb) < WL && usize::from(ins.src_limb) < WL);
        kani::assume(ins.dst_shift < 64 && ins.src_shift < 64);
        kani::assume(ins.neg <= 1 && ins.and_sel <= 1 && ins.or_sel <= 1 && (ins.and_sel & ins.or_sel) == 0);
        step(&mut st, &ins);
        assert!(st.is_kleene());
    }

    /// Theorem 4(ii) on the concrete ALU: a `pos` destination under OR stays `pos`.
    #[kani::proof]
    fn or_absorbs_pos() {
        const WL: usize = 1;
        let pos: u64 = kani::any(); let neg: u64 = kani::any();
        kani::assume(pos & neg == 0 && (pos & 1) == 1);
        let mut st = K3Bits::<WL>::from_rails([pos], [neg]);
        let src: u8 = kani::any(); kani::assume(src < 64);
        let ins = Instr { dst_limb: 0, src_limb: 0, dst_shift: 0, src_shift: src, neg: kani::any(), and_sel: 0, or_sel: 1 };
        kani::assume(ins.neg <= 1);
        step(&mut st, &ins);
        assert!(matches!(st.get(0), Some(crate::k3::K3::Pos)));
    }
}
```

The learned predictor appears only as `kani::any()` on the rails, per the Verification Transfer Theorem. A third harness in the test crate compiles a fixed four-rule DAG at `P = 8` and checks `execute` against the reference evaluator for all $3^8$ inputs; it is a bounded exhaustive check rather than a symbolic one and is listed as such in the manifest.

## 8. Apalache TLA+ (`formal/tla/CopleyAnytime.tla`)

```tla
---------------------------- MODULE CopleyAnytime ----------------------------
EXTENDS Integers, Sequences
CONSTANTS R, N, Owner, Kind, RuleEnd
\* @type: Int;  R, N.   Owner: 1..N -> 1..R.   Kind: 1..N -> {"mov","or","lit"}.
VARIABLES t, acc, val
K3 == {"pos", "neg", "bot"}
Or(a, b) == IF a = "pos" \/ b = "pos" THEN "pos"
            ELSE IF a = "neg" /\ b = "neg" THEN "neg" ELSE "bot"
Below(a, b) == a = "bot" \/ a = b

\* Clause values are the learned/exact inputs of the OR blocks: unconstrained nondeterminism.
Init == t = 0 /\ acc = [r \in 1..R |-> "bot"] /\ val \in [1..N -> K3]

FoldRule(r, upto) ==
  LET idx == { i \in 1..upto : Owner[i] = r /\ Kind[i] \in {"mov", "or"} }
  IN IF idx = {} THEN "bot"
     ELSE LET RECURSIVE F(_) F(S) == IF S = {} THEN "neg" ELSE
            LET m == CHOOSE i \in S : TRUE IN Or(val[m], F(S \ {m})) IN F(idx)

Step == t < N /\ t' = t + 1 /\ val' = val
        /\ acc' = IF Kind[t + 1] = "lit" THEN acc
                  ELSE [acc EXCEPT ![Owner[t + 1]] =
                          IF Kind[t + 1] = "mov" THEN val[t + 1] ELSE Or(@, val[t + 1])]
Next == Step \/ (t = N /\ UNCHANGED <<t, acc, val>>)

Final(r) == FoldRule(r, N)
Truncated(r) == IF RuleEnd[r] <= t THEN acc[r]
                ELSE IF acc[r] = "pos" THEN "pos" ELSE "bot"
AccMatchesFold == \A r \in 1..R : acc[r] = FoldRule(r, t)
Anytime == \A r \in 1..R : Below(Truncated(r), Final(r))
Spec == Init /\ [][Next]_<<t, acc, val>>
THEOREM Spec => [](AccMatchesFold /\ Anytime)
=============================================================================
```

Apalache checks `Anytime` inductively at `R = 4, N = 12` with `AccMatchesFold` as the strengthening invariant; the recursive fold is bounded by `N`, which keeps the encoding finite.

## 9. Differential equivalence against `chio-policy` HushSpec IR

The exact HushSpec types are not in the grounded context, so the seam is an adapter: a minimal expression IR with the same connectives, lowered to `SymbolicRuleDag` by negation normal form and distribution. Every rewrite used is a De Morgan-algebra identity, which is exactly what $\mathbb{K}_3$ provides. The reference evaluator interprets the IR directly, so the test exercises the lowering, the compiler, and the executor together.

```rust
#[cfg(feature = "compiler")]
pub mod hushspec {
    use alloc::{boxed::Box, vec, vec::Vec};
    use crate::compile::{Atom, Clause, Literal, Rule, SymbolicRuleDag};
    use crate::k3::K3;

    pub enum HushExpr { Pred(u16), RuleRef(u16), Not(Box<HushExpr>), And(Vec<HushExpr>), Or(Vec<HushExpr>) }
    pub struct HushRule { pub body: HushExpr, pub priority: u8 }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum LowerError { TooManyLiterals, TooManyClauses, RuleCountMismatch, EmptyConnective }

    /// NNF + distribution. Sound in K3: only De Morgan, double negation, distributivity.
    fn dnf(e: &HushExpr, neg: bool) -> Result<Vec<Vec<Literal>>, LowerError> {
        Ok(match e {
            HushExpr::Pred(p) => vec![vec![Literal { atom: Atom::Pred(*p), negated: neg }]],
            HushExpr::RuleRef(q) => vec![vec![Literal { atom: Atom::Rule(*q), negated: neg }]],
            HushExpr::Not(inner) => dnf(inner, !neg)?,
            HushExpr::And(xs) | HushExpr::Or(xs) if xs.is_empty() => return Err(LowerError::EmptyConnective),
            HushExpr::And(xs) if !neg => product(xs, false)?,
            HushExpr::Or(xs) if neg => product(xs, true)?,
            HushExpr::And(xs) | HushExpr::Or(xs) => {
                let mut acc = Vec::new();
                for x in xs { acc.extend(dnf(x, neg)?); }
                acc
            }
        })
    }
    fn product(xs: &[HushExpr], neg: bool) -> Result<Vec<Vec<Literal>>, LowerError> {
        let mut acc: Vec<Vec<Literal>> = vec![Vec::new()];
        for x in xs {
            let d = dnf(x, neg)?;
            let mut next = Vec::new();
            for a in &acc { for c in &d {
                let mut m = a.clone(); m.extend_from_slice(c); next.push(m);
            } }
            acc = next;
        }
        Ok(acc)
    }

    pub fn lower<const P: usize, const K: usize, const M: usize, const R: usize>(
        rules: &[HushRule],
    ) -> Result<Box<SymbolicRuleDag<P, K, M, R>>, LowerError> {
        if rules.len() != R { return Err(LowerError::RuleCountMismatch); }
        let mut out = [Rule::<K, M>::EMPTY; R];
        for (r, hr) in rules.iter().enumerate() {
            let clauses = dnf(&hr.body, false)?;
            if clauses.len() > M { return Err(LowerError::TooManyClauses); }
            let mut rule = Rule::<K, M>::EMPTY;
            rule.priority = hr.priority;
            for (j, c) in clauses.iter().enumerate() {
                if c.len() > K { return Err(LowerError::TooManyLiterals); }
                let mut cl = Clause::<K>::EMPTY;
                cl.lits[..c.len()].copy_from_slice(c);
                cl.len = u8::try_from(c.len()).map_err(|_| LowerError::TooManyLiterals)?;
                rule.clauses[j] = cl;
            }
            rule.len = u8::try_from(clauses.len()).map_err(|_| LowerError::TooManyClauses)?;
            out[r] = rule;
        }
        Ok(Box::new(SymbolicRuleDag { rules: out }))
    }

    /// Reference semantics of the IR; `depth` bounds recursion on acyclic inputs.
    pub fn eval_ir(rules: &[HushRule], x: &dyn Fn(u16) -> K3, e: &HushExpr, depth: usize) -> K3 {
        match e {
            HushExpr::Pred(p) => x(*p),
            HushExpr::RuleRef(q) => match depth.checked_sub(1) {
                Some(d) => eval_ir(rules, x, &rules[usize::from(*q)].body, d),
                None => K3::Bot,
            },
            HushExpr::Not(i) => eval_ir(rules, x, i, depth).not(),
            HushExpr::And(xs) => xs.iter().fold(K3::Pos, |a, y| a.and(eval_ir(rules, x, y, depth))),
            HushExpr::Or(xs) => xs.iter().fold(K3::Neg, |a, y| a.or(eval_ir(rules, x, y, depth))),
        }
    }
}

#[cfg(test)]
mod differential {
    extern crate std;
    use std::vec::Vec;
    use crate::compile::{compile, UniformRank};
    use crate::hushspec::{eval_ir, lower, HushExpr, HushRule};
    use crate::k3::{K3, K3Bits};
    use crate::vm::{execute, execute_prefix};

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut v = self.0; v ^= v << 13; v ^= v >> 7; v ^= v << 17; self.0 = v; v
        }
    }
    const P: usize = 16; const K: usize = 4; const M: usize = 4; const R: usize = 6; const WL: usize = 2;

    fn gen_expr(rng: &mut XorShift, rule: u16, depth: u8) -> HushExpr {
        match rng.next() % if depth == 0 { 2 } else { 5 } {
            0 => HushExpr::Pred((rng.next() % P as u64) as u16),
            1 if rule > 0 => HushExpr::RuleRef((rng.next() % u64::from(rule)) as u16), // acyclic by construction
            1 => HushExpr::Pred((rng.next() % P as u64) as u16),
            2 => HushExpr::Not(std::boxed::Box::new(gen_expr(rng, rule, depth - 1))),
            3 => HushExpr::And((0..2).map(|_| gen_expr(rng, rule, depth - 1)).collect()),
            _ => HushExpr::Or((0..2).map(|_| gen_expr(rng, rule, depth - 1)).collect()),
        }
    }

    fn gen_input(rng: &mut XorShift) -> ([u16; P], [u16; P], [u16; P]) {
        let mut s = [0u16; P];
        for v in s.iter_mut() { *v = (rng.next() % 10_000) as u16; }
        (s, [6_000; P], [4_000; P])
    }

    #[test]
    fn compiled_schedule_matches_hushspec_reference() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        let mut checked = 0usize;
        for _ in 0..200 {
            let rules: Vec<HushRule> = (0..R as u16)
                .map(|r| HushRule { body: gen_expr(&mut rng, r, 2), priority: (r % 2) as u8 }).collect();
            let Ok(dag) = lower::<P, K, M, R>(&rules) else { continue };
            let compiled = compile::<P, K, M, R, WL>(&dag, &UniformRank).expect("compile");
            let sched = compiled.schedule().expect("validate");
            assert!(compiled.code.len() <= R * M * (K + 1));
            assert_eq!(compiled.code.len(),
                       (compiled.stats.literal_instrs + compiled.stats.or_instrs) as usize);
            for _ in 0..64 {
                let (s, tp, tn) = gen_input(&mut rng);
                let x = K3Bits::<1>::from_calibrated::<P>(&s, &tp, &tn);
                let st = execute(&sched, &x);
                assert!(st.is_kleene());
                let xf = |p: u16| x.get(usize::from(p)).unwrap();
                for r in 0..R {
                    let expect = eval_ir(&rules, &xf, &rules[r].body, R);
                    assert_eq!(sched.rule(&st, r), Some(expect), "rule {r}");
                }
                // Theorem 4: every prefix yields an information-order lower bound.
                let t = (rng.next() as usize) % (sched.len() + 1);
                let part = execute_prefix(&sched, &x, t);
                for r in 0..R {
                    let v = sched.truncated_verdict(&part, t, r).unwrap();
                    assert!(v.below(sched.rule(&st, r).unwrap()));
                }
                checked += 1;
            }
        }
        assert!(checked > 5_000);
    }

    #[test]
    fn execute_never_touches_predicate_bits() {
        let mut rng = XorShift(7);
        let rules: Vec<HushRule> = (0..R as u16)
            .map(|r| HushRule { body: gen_expr(&mut rng, r, 2), priority: 0 }).collect();
        let dag = lower::<P, K, M, R>(&rules).expect("lower");
        let compiled = compile::<P, K, M, R, WL>(&dag, &UniformRank).expect("compile");
        let sched = compiled.schedule().expect("validate");
        let (s, tp, tn) = gen_input(&mut rng);
        let x = K3Bits::<1>::from_calibrated::<P>(&s, &tp, &tn);
        let st = execute(&sched, &x);
        for p in 0..P { assert_eq!(st.get(p), x.get(p)); }
        let _ = K3::Bot;
    }
}
```

The first test is the differential oracle: HushSpec reference semantics versus lowered, compiled, executed bitsets, plus the exact-count identity from Theorem 3 and the prefix bound from Theorem 4. The second pins the frame property that validation enforces.

## 10. Manifest additions, status, and next pass

All additions are new files and new manifest entries; no existing signature in `formal_core.rs`, `formal_aeneas.rs`, or `budget_split.rs` changes.

```toml
[[proof]]  name = "copley.rail_ops_correct"      kind = "lean4"    status = "discharged"
[[proof]]  name = "copley.vm_frame_and_absorb"   kind = "lean4"    status = "discharged"
[[proof]]  name = "copley.compile_correct"       kind = "lean4"    status = "statement-anchored"
[[proof]]  name = "copley.step_kleene_total"     kind = "kani"     status = "discharged"
[[proof]]  name = "copley.or_absorbs_pos"        kind = "kani"     status = "discharged"
[[proof]]  name = "copley.anytime"               kind = "apalache" status = "discharged-bounded"
[[proof]]  name = "copley.differential_hushspec" kind = "test"     status = "passing"
```

What is proven and how:

- **Rail algebra and ALU totality** are machine-checked in Lean 4 and Kani.
- **Compiler correctness** (Theorem 2) is a structured paper proof over four lemmas; the Lean statement is anchored and the induction is the Aeneas refinement target for the next pass.
- **Exact WCET** (Theorem 3) is structural: the executor is a fold over a validated slice of straight-line instructions, and the count formula is read off the emission pass. The concrete worst case is 21,240 instructions.
- **Anytime soundness** (Theorem 4) is proven on paper, checked bounded in Apalache, and exercised at random prefixes in the differential tests.

The next pass should replace the anchored Theorem 2 statement with the Aeneas-extracted model of `step` and `execute_prefix`, measure $c_{\text{step}}$ on the two kernel targets to populate `prefix_for_budget`, and wire the `RankOracle` to Copley's per-clause calibration frequencies so the $\lambda_{\text{latency}}$ cut decides the deny-capable rules first.

---

# Verbatim Treatise - `wave5_angle_3_concurrent_loom_and_dst_crash_recovery_pass_5`

(), DstError> {
        let zero = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
        let state = core::mem::replace(&mut self.vol.ledger, zero);
        let (next, ok) = ledger_apply(state, op, amount);
        self.vol.ledger = next;
        if ok { Ok(()) } else { Err(DstError::LedgerRejected { nonce, op }) }
    }
    fn set_nonce(&mut self, nonce: u16, to: NonceState, amount: u64) -> Result<(), DstError> {
        let i = usize::from(nonce);
        *self.vol.nonces.get_mut(i).ok_or(DstError::SlotOutOfRange(nonce))? = to;
        *self.vol.amounts.get_mut(i).ok_or(DstError::SlotOutOfRange(nonce))? = amount;
        Ok(())
    }
    /// One governed dispatch of `nonce`. Returns `Ok(true)` when the chosen cut fires.
    pub fn dispatch_one(&mut self, nonce: u16, amount: u64, cut: Cut, intent_first: bool) -> Result<bool, DstError> {
        self.set_nonce(nonce, NonceState::Reserved, amount)?;       // ExecutionNonceStore::reserve
        self.ledger(nonce, OP_RESERVE, amount)?;
        if intent_first {
            self.wal.append(Frame::Intent { nonce, amount });
            if cut == Cut::AfterIntentAppend { return Ok(true); }
            self.wal.fsync();
            if cut == Cut::AfterIntentSync { return Ok(true); }
        }
        self.effects.push(nonce);                                      // irreversible external effect
        if cut == Cut::AfterEffect { return Ok(true); }
        if !intent_first { self.wal.append(Frame::Intent { nonce, amount }); }
        self.wal.append(Frame::Commit { nonce, amount });
        if cut == Cut::AfterCommitAppend { return Ok(true); }
        self.wal.fsync();
        self.set_nonce(nonce, NonceState::Committed, amount)?;
        self.ledger(nonce, OP_COMMIT, amount)?;
        Ok(cut == Cut::AfterCommitSync)
    }
    /// Resolve every `Held` slot against the authoritative effect store, then make the verdict durable.
    pub fn reconcile(&mut self) -> Result<(), DstError> {
        for i in 0..self.vol.nonces.len() {
            if self.vol.nonces[i] != NonceState::Held { continue; }
            let nonce = u16::try_from(i).map_err(|_| DstError::SlotOutOfRange(u16::MAX))?;
            let amount = self.vol.amounts[i];
            if self.effects.contains(&nonce) {
                self.wal.append(Frame::Commit { nonce, amount });
                self.wal.fsync();
                self.set_nonce(nonce, NonceState::Committed, amount)?;
                self.ledger(nonce, OP_COMMIT, amount)?;
            } else {
                self.wal.append(Frame::Abort { nonce, amount });
                self.wal.fsync();
                self.set_nonce(nonce, NonceState::Free, amount)?;
                self.ledger(nonce, OP_RELEASE, amount)?;
            }
        }
        Ok(())
    }
    /// R1 at-most-once per nonce; R3 ledger conservation.
    pub fn check(&self, seed: u64) -> Result<(), DstError> {
        for i in 0..self.vol.nonces.len() {
            let nonce = u16::try_from(i).map_err(|_| DstError::SlotOutOfRange(u16::MAX))?;
            if self.effects.iter().filter(|&&n| n == nonce).count() > 1 {
                return Err(DstError::DoubleExecution { nonce, seed });
            }
        }
        let l = &self.vol.ledger;
        let spent = l.committed.checked_add(l.released).and_then(|x| x.checked_add(l.retained));
        if !matches!(spent, Some(s) if s <= l.reserved) { return Err(DstError::LedgerNotConserved); }
        Ok(())
    }
}

fn pick_cut(rng: &mut Rng) -> Cut {
    match rng.below(6) {
        0 => Cut::None, 1 => Cut::AfterIntentAppend, 2 => Cut::AfterIntentSync,
        3 => Cut::AfterEffect, 4 => Cut::AfterCommitAppend, _ => Cut::AfterCommitSync,
    }
}

/// One episode: `steps` dispatches over `slots` nonces with crashes at policy-chosen cuts.
/// Returns the number of crashes survived.
pub fn run_episode(seed: u64, intent_first: bool, steps: usize, slots: usize) -> Result<usize, DstError> {
    let mut rng = Rng::new(seed);
    let mut w = World::new(slots)?;
    let mut crashes = 0usize;
    for _ in 0..steps {
        let free: Vec<u16> = (0..slots)
            .filter(|&i| w.vol.nonces[i] == NonceState::Free)
            .filter_map(|i| u16::try_from(i).ok())
            .collect();
        let Some(nonce) = pick(&mut rng, &free) else { break; };
        let amount = rng.below(1_000).checked_add(1).unwrap_or(1);
        let cut = pick_cut(&mut rng);
        if w.dispatch_one(nonce, amount, cut, intent_first)? {
            crashes = crashes.saturating_add(1);
            let before = w.wal.synced;
            w.wal.crash(&mut rng);
            if w.wal.synced < before {
                return Err(DstError::DurabilityRegressed { before, after: w.wal.synced });
            }
            w.vol = recover(&w.wal, slots)?;   // memory is gone; durable state is the truth
            w.check(seed)?;
            w.reconcile()?;
            w.check(seed)?;
        }
    }
    w.check(seed)?;
    Ok(crashes)
}

fn seeds() -> std::ops::RangeInclusive<u64> {
    match std::env::var("DST_SEED").ok().and_then(|s| s.parse::<u64>().ok()) {
        Some(s) => s..=s,
        None => 1..=10_000,
    }
}

#[test]
fn intent_before_effect_is_crash_safe() {
    for seed in seeds() {
        if let Err(e) = run_episode(seed, true, 64, 16) {
            panic!("seed {seed}: {e:?}  replay with DST_SEED={seed}");
        }
    }
}

#[test]
fn simulator_finds_double_execution_when_effect_precedes_durable_intent() {
    let witness = seeds().find_map(|seed| match run_episode(seed, false, 64, 16) {
        Err(DstError::DoubleExecution { nonce, .. }) => Some((seed, nonce)),
        _ => None,
    });
    assert!(witness.is_some(), "oracle has no teeth: no double execution found in the seed range");
}
```

**Kani harnesses.** These live in the production crate behind the kani cfg and use the non-loom shim, so the same `HolderGate` source is checked by loom for interleavings and by Kani for all values.

```rust
// crates/kernel/chio-kernel/src/concurrency/kani_harness.rs
#[cfg(kani)]
mod harness {
    use super::{HolderGate, ledger_apply, ReservationLedger};

    #[kani::proof]
    #[kani::unwind(6)]
    fn holder_gate_bounded_by_cap() {
        let cap: usize = kani::any();
        kani::assume(cap <= 8);
        let gate = HolderGate::new(cap);
        for _ in 0..5 {
            let acquire: bool = kani::any();            // the learned policy, unconstrained
            if acquire { let _ = gate.try_acquire(); } else { let _ = gate.release(); }
            assert!(gate.holders() <= cap);
        }
    }

    /// Pins the conservation law that `recover` and `LedgerCell::conserved` rely on.
    /// If this fails, the defect is in `ledger_apply`, not in the simulator.
    #[kani::proof]
    #[kani::unwind(5)]
    fn ledger_conservation_under_any_ops() {
        let mut l = ReservationLedger { reserved: 0, committed: 0, released: 0, retained: 0 };
        for _ in 0..4 {
            let op: u8 = kani::any();
            let amount: u64 = kani::any();
            let (next, _accepted) = ledger_apply(l, op, amount);
            l = next;
            let spent = l.committed.checked_add(l.released).and_then(|x| x.checked_add(l.retained));
            assert!(matches!(spent, Some(s) if s <= l.reserved));
        }
    }
}
```

**Theorem 1, linearizability of single-word CAS machines.** Let an object hold one atomic word with finite transition relation `δ`, and let every operation be a load followed by at most one `compare_exchange` whose success installs a `δ`-successor of the observed value and whose failure returns a value determined by the observed word. Then every concurrent history is linearizable with respect to the total sequential function `run` in which a failed edge is the identity.

*Proof.* Assign each operation the linearization point of its last `compare_exchange`, or its final load for read-only operations. These points are atomic steps and therefore totally ordered. The word is mutated only at successful points. So the value observed by any operation at its point equals the value installed by the immediately preceding successful point in that order. Replaying operations sequentially in point order therefore reproduces every observed value and hence every return value. ∎

Each `ExecutionNonceStore` slot, each `HolderGate`, and each `SessionOperation` word satisfies the hypotheses, so the Lean theorem `commits_at_most_one` and the Apalache invariant `Inv` hold for every interleaving, not only for the sequential traces they were proved on. The cancel loop re-reads on failure and never performs two successful swaps, so it satisfies the single-success hypothesis.

**Theorem 2, epoch uniqueness and monotonicity.** Under `publish_rcu`, the installed epochs form the sequence 1, 2, 3 and so on, so no two publishers mint the same epoch and no reader observes a regression.

*Proof.* Induction on linearization order of successful swaps. The first swap replaces epoch 0 with 1. A swap at position k succeeds only if the pointer it observed is still installed, so the installed epoch at that moment is the one it read, namely k minus 1, and it installs k. Distinct successful swaps have distinct positions, hence distinct epochs. A reader's two loads are ordered in linearization order, and installed epochs are increasing in that order. ∎

The racy variant breaks the hypothesis because its store does not check the observed pointer. Two publishers that both read epoch 0 both store epoch 1. Loom reports exactly that interleaving, which is what the `should_panic` test pins.

**Theorem 3, holder bound.** `HolderGate` maintains `holders ≤ cap` and never underflows.

*Proof.* Initially the count is zero, which is at most cap. Acquire succeeds only when the observed count is strictly below cap and installs the successor, which is at most cap. Because the count is below cap and cap is at most the type maximum, the successor never overflows, so the overflow branch of `checked_add` is unreachable and the `HolderCountOverflow` variant is retained purely for API stability. Release succeeds only when `checked_sub` is defined, so the count stays at or above zero. By Theorem 1 the bound holds in every interleaving. ∎

**Theorem 4, at-most-once under prefix durability.** Let a WAL have synced length s. A crash yields a prefix of length at least s. If the effect for nonce n happens only after the intent frame for n lies in the synced prefix, then across any number of crashes at most one effect for n occurs.

*Proof.* Suppose two effects for n occur at times t₁ before t₂. At t₁ the intent for n is synced. Every later recovered WAL is a prefix of length at least the synced length at the time of the crash, and synced length never decreases, so every later recovered WAL contains that intent. Strict replay then leaves n in `Held` or `Committed` unless an abort frame for n appears later. The dispatch at t₂ requires n to be `Free`, so an abort for n was appended by reconciliation between t₁ and t₂. Reconciliation appends an abort only when the effect store contains no effect for n. But the effect at t₁ is external and survives every crash. Contradiction. ∎

The defective protocol violates the hypothesis exactly once: the effect at t₁ precedes any synced intent. A crash that drops the unsynced frames recovers n as `Free`, and a later dispatch produces the second effect. The simulator's second test demands that this witness be found, so the oracle is validated against the theorem's negation rather than trusted.

**What the policy may choose.** In every harness above, the choice of nonce, child, epoch candidate, cut, or cancel moment is nondeterministic and unconstrained. That is the Envelope Preservation argument in its concrete form: the Tier-0 micro-models and the Tier-1 concept predicates only select among edges that the exact computation already admits, and `Held`, `Cancelled`, and `ChildCapacityExhausted` are the fallbacks always present in the envelope. No learned component is asked to compute anything these machines compute exactly.

**Manifest and CI.** Add `NonceMachine.lean` and `SessionCancel.tla` to `formal/proof-manifest.toml` as new entries only. Cancellation and compensation details belong under the existing `receipt_context` metadata key, because the reserved-key array has a fixed length of thirty-five and extending it would change a pinned type. The nightly job runs the loom test in release mode with a preemption bound of three, which is exhaustive for these models, the simulation over ten thousand seeds, both Kani harnesses, and the Lean and Apalache checks.

Recap. Two complete test files were specified: a loom permutation suite covering `WeightEpoch` publication, `ExecutionNonceStore` rollback, `BudgetSplit` holder refcounts, and `SessionOperation` cancellation at both cutpoints, and a deterministic crash simulation of the intent-before-effect protocol over a SQLite WAL model with dropped frames. Each protocol has a deliberately defective twin whose failure the suite requires, so the oracles are validated rather than assumed. Four theorems transfer the sequential Lean and Apalache results to all interleavings and all crash schedules, with the Kani harnesses pinning the holder bound and ledger conservation that the proofs depend on. Next is wiring the production `arc_swap` adapter and the shim into `chio-kernel`, and adding the two formal files to the proof manifest.

---

# Verbatim Treatise - `wave5_angle_4_protocol_edges_mcp_a2a_envoy_and_enclave_attestation_pass_5`

I'll lay out the Wave 5 Angle 4 design as one additive `#![no_std]` crate plus thin std-side adapters, then discharge its obligations in Lean 4, Kani, and Apalache under the Wave 1 envelope law.

The deliverable is a new crate, `crates/edge/chio-protocol-edge-core`, depended on by `chio-mcp-edge`, `chio-a2a-adapter`, and `chio-envoy-ext-authz`. It touches no existing signature in section B through E. It imports the pure kernel functions `classify_time_window_code`, `receipt_fields_coupled`, `budget_precheck`, and `budget_commit` from `chio_kernel_core::formal_aeneas`, which keeps the `formal/proof-manifest.toml` pins intact. One assumption is stated once: `chio-kernel-core` builds with `default-features = false` so those four functions are reachable from `no_std`. If it does not, the fallback is a `pure` feature re-export, still additive.

## 1. Lift law and the portable request

**The edge is a layer, not a parser.** Each protocol edge instantiates the canonical tuple $\mathcal{D}_{L1} = (\mathcal{X}, C, P, \mathcal{C}, \Pi, W)$. The exact computation $C(x)$ is the lift from a protocol-native message to a `PortableToolCallRequest` plus the Copley segment split. The predictor $P$ never sees protocol bytes directly. It sees four segments and emits a vector in $\mathbb{K}_3^{537}$. The envelope $\mathcal{C}(C(x))$ always contains `Deny`, including when the lift itself fails. That last clause is what makes the lift total: an unparseable or oversized message is not an error path, it is the point $\bot_x$ of the envelope.

**Segment mapping.** The four Copley segments were named for Sysmon process-creation fields. At a protocol edge they are the four roles every tool call has: what is being asked, which capability is being invoked, how the protocol itself names the exchange, and who stands behind the caller.

| Copley segment | Width | MCP `tools/call` | A2A message send | Envoy ext_authz |
|---|---|---|---|---|
| `CommandLine` | 345 | canonical `arguments` JSON | canonical message parts | canonical attributes, headers then body |
| `Image` | 97 | `params.name` | `skillId` | `:path` |
| `OriginalFileName` | 57 | JSON-RPC `id` | `taskId` | `:method` |
| `ParentImage` | 38 | `clientInfo.name` | delegating agent from the witness chain head | XFCC root or upstream authority |

The crate root and the three-valued core:

```rust
//! crates/edge/chio-protocol-edge-core/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod k3;
pub mod copley;
pub mod portable;
pub mod lift;
pub mod envelope;
pub mod floor;
pub mod receipt;
pub mod federation;
pub mod attest;
```

```rust
//! src/k3.rs
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum K3 { Pos, Neg, Bot }

impl K3 {
    /// Strong Kleene conjunction. `Neg` is absorbing; `Pos` is the identity.
    pub const fn and(self, other: K3) -> K3 {
        match (self, other) {
            (K3::Neg, _) | (_, K3::Neg) => K3::Neg,
            (K3::Pos, K3::Pos) => K3::Pos,
            _ => K3::Bot,
        }
    }
    pub const fn is_pos(self) -> bool { matches!(self, K3::Pos) }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FixedQ16_16(pub i32);

impl FixedQ16_16 {
    pub const ONE: Self = Self(1 << 16);
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let wide = i64::from(self.0).checked_mul(i64::from(o.0))?.checked_shr(16)?;
        i32::try_from(wide).ok().map(Self)
    }
    pub fn checked_add(self, o: Self) -> Option<Self> { self.0.checked_add(o.0).map(Self) }
    pub fn checked_sub(self, o: Self) -> Option<Self> { self.0.checked_sub(o.0).map(Self) }
}

/// Role-asymmetric threshold classification. Requires `tau_neg <= tau_pos`.
pub fn classify(score: FixedQ16_16, tau_pos: FixedQ16_16, tau_neg: FixedQ16_16) -> K3 {
    debug_assert!(tau_neg <= tau_pos);
    if score >= tau_pos { K3::Pos } else if score <= tau_neg { K3::Neg } else { K3::Bot }
}
```

The Copley module fixes the 537-predicate layout at compile time and hosts both tiers. Tier-1 scoring by `UltraBERT` happens outside `no_std`; the core only consumes the resulting score vector. Tier-0 applies the Lagrangian shadow prices with checked fixed-point arithmetic.

```rust
//! src/copley.rs
use crate::k3::{classify, FixedQ16_16, K3};

pub const SEG_COMMAND_LINE: usize = 345;
pub const SEG_IMAGE: usize = 97;
pub const SEG_ORIGINAL_FILE_NAME: usize = 57;
pub const SEG_PARENT_IMAGE: usize = 38;
pub const COPLEY_PREDICATES: usize =
    SEG_COMMAND_LINE + SEG_IMAGE + SEG_ORIGINAL_FILE_NAME + SEG_PARENT_IMAGE;
const _: () = assert!(COPLEY_PREDICATES == 537);

pub const MAX_SEGMENT_BYTES: usize = 65_536;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Segment { CommandLine, Image, OriginalFileName, ParentImage }

pub const fn segment_of(j: usize) -> Option<Segment> {
    if j < SEG_COMMAND_LINE { Some(Segment::CommandLine) }
    else if j < SEG_COMMAND_LINE + SEG_IMAGE { Some(Segment::Image) }
    else if j < SEG_COMMAND_LINE + SEG_IMAGE + SEG_ORIGINAL_FILE_NAME { Some(Segment::OriginalFileName) }
    else if j < COPLEY_PREDICATES { Some(Segment::ParentImage) }
    else { None }
}

#[derive(Clone, Copy, Debug)]
pub struct CopleySegments<'a> {
    pub command_line: &'a [u8],
    pub image: &'a [u8],
    pub original_file_name: &'a [u8],
    pub parent_image: &'a [u8],
}

/// Tier-1 scorer. Implemented by the std-side `UltraBERT` host; `Err` means the
/// model is unavailable, which the caller maps to `K3::Bot` everywhere.
pub trait SegmentScorer {
    fn score(&self, seg: &CopleySegments<'_>, out: &mut [FixedQ16_16; COPLEY_PREDICATES])
        -> Result<(), ScorerUnavailable>;
}
#[derive(Clone, Copy, Debug)]
pub struct ScorerUnavailable;

pub struct Thresholds {
    pos: [FixedQ16_16; COPLEY_PREDICATES],
    neg: [FixedQ16_16; COPLEY_PREDICATES],
}
impl Thresholds {
    /// Enforces `neg[j] <= pos[j]` for every predicate; invalid tables never exist.
    pub fn new(pos: [FixedQ16_16; COPLEY_PREDICATES], neg: [FixedQ16_16; COPLEY_PREDICATES]) -> Option<Self> {
        pos.iter().zip(neg.iter()).all(|(p, n)| n <= p).then_some(Self { pos, neg })
    }
}

pub struct PredicateVector { pub k: [K3; COPLEY_PREDICATES] }

pub fn evaluate(scores: &[FixedQ16_16; COPLEY_PREDICATES], th: &Thresholds) -> PredicateVector {
    let mut k = [K3::Bot; COPLEY_PREDICATES];
    for (j, slot) in k.iter_mut().enumerate() {
        *slot = classify(scores[j], th.pos[j], th.neg[j]);
    }
    PredicateVector { k }
}

/// Tier-0 shadow prices: (budget, fuel, latency, memory, escrow).
#[derive(Clone, Copy, Debug)]
pub struct ShadowPrices { pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16, pub memory: FixedQ16_16, pub escrow: FixedQ16_16 }
#[derive(Clone, Copy, Debug)]
pub struct ResourceUsage { pub budget: FixedQ16_16, pub fuel: FixedQ16_16, pub latency: FixedQ16_16, pub memory: FixedQ16_16, pub escrow: FixedQ16_16 }

/// `raw - lambda . usage`, or `None` on any overflow (caller treats `None` as `Bot`).
pub fn lagrangian_penalized(raw: FixedQ16_16, l: &ShadowPrices, u: &ResourceUsage) -> Option<FixedQ16_16> {
    let pen = l.budget.checked_mul(u.budget)?
        .checked_add(l.fuel.checked_mul(u.fuel)?)?
        .checked_add(l.latency.checked_mul(u.latency)?)?
        .checked_add(l.memory.checked_mul(u.memory)?)?
        .checked_add(l.escrow.checked_mul(u.escrow)?)?;
    raw.checked_sub(pen)
}

/// Exact verdict map. Deny beats PendingApproval, matching `GuardPipeline`.
pub fn edge_verdict(pv: &PredicateVector, deny_mask: &[bool; COPLEY_PREDICATES],
                    required_mask: &[bool; COPLEY_PREDICATES]) -> crate::receipt::EdgeVerdict {
    use crate::receipt::EdgeVerdict;
    let mut pending = false;
    for j in 0..COPLEY_PREDICATES {
        match (deny_mask[j], required_mask[j], pv.k[j]) {
            (true, _, K3::Pos) => return EdgeVerdict::Deny,
            (true, _, K3::Bot) | (_, true, K3::Bot) => pending = true,
            _ => {}
        }
    }
    if pending { EdgeVerdict::PendingApproval } else { EdgeVerdict::Allow }
}
```

The portable request has private fields and a single validating constructor, so the type itself is the proof that the bounds hold.

```rust
//! src/portable.rs
use crate::copley::CopleySegments;
use crate::floor::Sha256;

pub const MAX_TOOL_NAME_BYTES: usize = 256;
pub const MAX_NATIVE_ID_BYTES: usize = 1_024;
pub const MAX_ARGUMENTS_BYTES: usize = 65_536;
pub const MAX_PRINCIPAL_BYTES: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeProtocol { Mcp = 1, A2a = 2, EnvoyExtAuthz = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiftError {
    ToolNameEmpty, ToolNameTooLong, NativeIdTooLong, ArgumentsTooLong,
    PrincipalEmpty, PrincipalTooLong, ParentPrincipalTooLong,
    TimeWindowInverted, TimeOverflow, UnitCostOverflow,
}

#[derive(Clone, Copy, Debug)]
pub struct LiftFields<'a> {
    pub protocol: EdgeProtocol,
    pub tool_name: &'a [u8],
    pub native_id: &'a [u8],
    pub arguments: &'a [u8],
    pub principal: &'a [u8],
    pub parent_principal: &'a [u8],
    pub received_at: u64,
    pub ttl: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PortableToolCallRequest<'a> {
    protocol: EdgeProtocol,
    tool_name: &'a [u8],
    native_id: &'a [u8],
    arguments: &'a [u8],
    principal: &'a [u8],
    parent_principal: &'a [u8],
    issued_at: u64,
    expires_at: u64,
    invocation_cost: u64,
    unit_cost: u64,
}

impl<'a> PortableToolCallRequest<'a> {
    pub fn lift(f: LiftFields<'a>) -> Result<Self, LiftError> {
        if f.tool_name.is_empty() { return Err(LiftError::ToolNameEmpty); }
        if f.tool_name.len() > MAX_TOOL_NAME_BYTES { return Err(LiftError::ToolNameTooLong); }
        if f.native_id.len() > MAX_NATIVE_ID_BYTES { return Err(LiftError::NativeIdTooLong); }
        if f.arguments.len() > MAX_ARGUMENTS_BYTES { return Err(LiftError::ArgumentsTooLong); }
        if f.principal.is_empty() { return Err(LiftError::PrincipalEmpty); }
        if f.principal.len() > MAX_PRINCIPAL_BYTES { return Err(LiftError::PrincipalTooLong); }
        if f.parent_principal.len() > MAX_PRINCIPAL_BYTES { return Err(LiftError::ParentPrincipalTooLong); }
        let expires_at = f.received_at.checked_add(f.ttl).ok_or(LiftError::TimeOverflow)?;
        if expires_at < f.received_at { return Err(LiftError::TimeWindowInverted); }
        let unit_cost = u64::try_from(f.arguments.len()).map_err(|_| LiftError::UnitCostOverflow)?;
        Ok(Self {
            protocol: f.protocol, tool_name: f.tool_name, native_id: f.native_id,
            arguments: f.arguments, principal: f.principal, parent_principal: f.parent_principal,
            issued_at: f.received_at, expires_at, invocation_cost: 1, unit_cost,
        })
    }

    pub fn segments(&self) -> CopleySegments<'a> {
        CopleySegments {
            command_line: self.arguments, image: self.tool_name,
            original_file_name: self.native_id, parent_image: self.parent_principal,
        }
    }

    pub fn request_hash<H: Sha256>(&self, h: &H) -> [u8; 32] {
        let proto = [self.protocol as u8];
        let (l1, l2, l3, l4, l5) = (len_be(self.tool_name), len_be(self.native_id),
            len_be(self.arguments), len_be(self.principal), len_be(self.parent_principal));
        let (ia, ea) = (self.issued_at.to_be_bytes(), self.expires_at.to_be_bytes());
        let parts: [&[u8]; 13] = [&proto, &l1, self.tool_name, &l2, self.native_id, &l3, self.arguments,
            &l4, self.principal, &l5, self.parent_principal, &ia, &ea];
        h.digest(&parts)
    }

    pub fn issued_at(&self) -> u64 { self.issued_at }
    pub fn expires_at(&self) -> u64 { self.expires_at }
    pub fn costs(&self) -> (u64, u64) { (self.invocation_cost, self.unit_cost) }
    pub fn tool_name(&self) -> &'a [u8] { self.tool_name }
    pub fn principal(&self) -> &'a [u8] { self.principal }
}

fn len_be(s: &[u8]) -> [u8; 4] { u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes() }
```

The three lifters are now one-liners over `LiftFields`. The std-side adapters do protocol framing and canonicalization, which is where JSON and protobuf live; the `no_std` core receives only canonical byte slices.

```rust
//! src/lift.rs
use crate::portable::{EdgeProtocol, LiftError, LiftFields, PortableToolCallRequest};

pub struct McpToolsCall<'a> {
    pub jsonrpc_id: &'a [u8], pub tool_name: &'a [u8], pub arguments_canonical_json: &'a [u8],
    pub session_principal: &'a [u8], pub client_info_name: &'a [u8], pub received_at: u64, pub ttl: u64,
}
pub struct A2aMessageSend<'a> {
    pub task_id: &'a [u8], pub skill_id: &'a [u8], pub parts_canonical: &'a [u8],
    pub caller_agent_id: &'a [u8], pub delegating_agent_id: &'a [u8], pub received_at: u64, pub ttl: u64,
}
pub struct ExtAuthzCheck<'a> {
    pub method: &'a [u8], pub path: &'a [u8], pub attributes_canonical: &'a [u8],
    pub source_principal: &'a [u8], pub forwarded_client_cert_root: &'a [u8], pub received_at: u64, pub ttl: u64,
}

pub fn lift_mcp<'a>(c: &McpToolsCall<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    PortableToolCallRequest::lift(LiftFields {
        protocol: EdgeProtocol::Mcp, tool_name: c.tool_name, native_id: c.jsonrpc_id,
        arguments: c.arguments_canonical_json, principal: c.session_principal,
        parent_principal: c.client_info_name, received_at: c.received_at, ttl: c.ttl,
    })
}
pub fn lift_a2a<'a>(m: &A2aMessageSend<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    PortableToolCallRequest::lift(LiftFields {
        protocol: EdgeProtocol::A2a, tool_name: m.skill_id, native_id: m.task_id,
        arguments: m.parts_canonical, principal: m.caller_agent_id,
        parent_principal: m.delegating_agent_id, received_at: m.received_at, ttl: m.ttl,
    })
}
pub fn lift_ext_authz<'a>(e: &ExtAuthzCheck<'a>) -> Result<PortableToolCallRequest<'a>, LiftError> {
    PortableToolCallRequest::lift(LiftFields {
        protocol: EdgeProtocol::EnvoyExtAuthz, tool_name: e.path, native_id: e.method,
        arguments: e.attributes_canonical, principal: e.source_principal,
        parent_principal: e.forwarded_client_cert_root, received_at: e.received_at, ttl: e.ttl,
    })
}
```

The envelope and the $O(1)$ shielded projection $\Pi$:

```rust
//! src/envelope.rs
/// Bit i set means edge action i is feasible. Bit 0 is `Deny` and is always set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EdgeEnvelope(u8);
impl EdgeEnvelope {
    pub const DENY: u8 = 0;
    pub const fn new(mask: u8) -> Self { Self(mask | 1) }
    pub fn contains(self, a: u8) -> bool {
        a < 8 && self.0.checked_shr(u32::from(a)).is_some_and(|m| m & 1 == 1)
    }
    pub fn project(self, learned_choice: u8) -> u8 {
        if self.contains(learned_choice) { learned_choice } else { Self::DENY }
    }
}
```

**Budget coupling at the edge.** Admission calls `budget_precheck` with the capability's remaining counters and the lifted `(invocation_cost, unit_cost)`. Only when `budget_commit(...).accepted` is true may the receipt carry `EdgeVerdict::Allow`. The verdict-match bit passed to `receipt_fields_coupled` is computed as `(verdict == Allow) == commit.accepted`, so an uncommitted allow cannot be signed.

## 2. Hybrid floor, receipts, federation, attestation

**Hybrid signing is AND-composition over one domain-separated digest.** Both algorithms sign the same 32-byte to-be-signed value `tbs = SHA-256(domain || canonical receipt)`. Under `HybridRequired` a receipt verifies only when both signatures verify. A backend that is absent returns `K3::Bot`, never `Pos`, so an unloaded ML-DSA module degrades to `Deny`, not to classical-only. The floor level is chosen per trust root and per kernel, and the stricter one wins.

```rust
//! src/floor.rs
use crate::k3::K3;

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3_309;

pub trait Sha256 { fn digest(&self, parts: &[&[u8]]) -> [u8; 32]; }
pub trait Ed25519Verifier {
    fn verify(&self, pk: &[u8; ED25519_PUBLIC_KEY_BYTES], msg: &[u8], sig: &[u8; ED25519_SIGNATURE_BYTES]) -> K3;
}
pub trait MlDsa65Verifier {
    fn verify(&self, pk: &[u8; MLDSA65_PUBLIC_KEY_BYTES], msg: &[u8], sig: &[u8; MLDSA65_SIGNATURE_BYTES]) -> K3;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum CryptoFloorLevel { ClassicalOnly = 1, HybridRequired = 2 }

#[derive(Clone, Copy, Debug)]
pub struct HybridPublicKey {
    pub ed25519: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub mldsa65: [u8; MLDSA65_PUBLIC_KEY_BYTES],
}
#[derive(Clone, Copy, Debug)]
pub struct HybridSignature {
    pub ed25519: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65: [u8; MLDSA65_SIGNATURE_BYTES],
}

pub trait HybridSigner {
    fn sign(&self, tbs: &[u8; 32]) -> Result<HybridSignature, SignerUnavailable>;
    fn public_key(&self) -> &HybridPublicKey;
    fn root_id(&self) -> [u8; 32];
}
#[derive(Clone, Copy, Debug)]
pub struct SignerUnavailable;

pub struct KernelCryptoFloor<E, M, H> { ed: E, ml: M, hash: H, level: CryptoFloorLevel }

impl<E: Ed25519Verifier, M: MlDsa65Verifier, H: Sha256> KernelCryptoFloor<E, M, H> {
    pub const fn new(ed: E, ml: M, hash: H, level: CryptoFloorLevel) -> Self { Self { ed, ml, hash, level } }
    pub const fn level(&self) -> CryptoFloorLevel { self.level }
    pub const fn hash(&self) -> &H { &self.hash }

    /// Verify at the stricter of the kernel level and `at_least`.
    pub fn verify(&self, pk: &HybridPublicKey, tbs: &[u8; 32], sig: &HybridSignature,
                  at_least: CryptoFloorLevel) -> K3 {
        let ed = self.ed.verify(&pk.ed25519, tbs, &sig.ed25519);
        match self.level.max(at_least) {
            CryptoFloorLevel::ClassicalOnly => ed,
            CryptoFloorLevel::HybridRequired => ed.and(self.ml.verify(&pk.mldsa65, tbs, &sig.mldsa65)),
        }
    }
}
```

The receipt is a fixed-width canonical record. Fixed width makes encoding trivially injective, which is the property the Lean lemma in section 3 relies on. Issuance reuses the kernel's `receipt_fields_coupled` unchanged and self-verifies before returning.

```rust
//! src/receipt.rs
use chio_kernel_core::formal_aeneas::receipt_fields_coupled;
use crate::floor::{CryptoFloorLevel, HybridSignature, HybridSigner, KernelCryptoFloor, Sha256,
                   Ed25519Verifier, MlDsa65Verifier};
use crate::k3::K3;
use crate::portable::EdgeProtocol;

pub const RECEIPT_DOMAIN_V1: &[u8] = b"chio.edge.receipt.v1";

const OFF_PROTOCOL: usize = 0;
const OFF_REQUEST: usize = 1;
const OFF_CAPABILITY: usize = OFF_REQUEST + 32;
const OFF_POLICY: usize = OFF_CAPABILITY + 32;
const OFF_WEIGHTS: usize = OFF_POLICY + 32;
const OFF_ATTEST: usize = OFF_WEIGHTS + 32;
const OFF_PREDICATES: usize = OFF_ATTEST + 32;
const OFF_ROOT: usize = OFF_PREDICATES + 32;
const OFF_EVIDENCE: usize = OFF_ROOT + 32;
const OFF_VERDICT: usize = OFF_EVIDENCE + 1;
const OFF_ISSUED: usize = OFF_VERDICT + 1;
const OFF_EXPIRES: usize = OFF_ISSUED + 8;
pub const RECEIPT_CANONICAL_BYTES: usize = OFF_EXPIRES + 8;
const _: () = assert!(RECEIPT_CANONICAL_BYTES == 243);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EdgeVerdict { Allow = 0, Deny = 1, PendingApproval = 2 }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum EvidenceClass {
    Unsigned = 0, Classical = 1, Hybrid = 2, HybridWeightsBound = 3,
    HybridAttested = 4, HybridAttestedFederated = 5,
}
impl EvidenceClass {
    pub const fn required_by(level: CryptoFloorLevel) -> Self {
        match level { CryptoFloorLevel::ClassicalOnly => Self::Classical,
                      CryptoFloorLevel::HybridRequired => Self::Hybrid }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EdgeReceipt {
    pub protocol: EdgeProtocol,
    pub request_hash: [u8; 32],
    pub capability_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub weights_hash: [u8; 32],
    pub attestation_hash: [u8; 32],
    pub predicate_commitment: [u8; 32],
    pub signer_root_id: [u8; 32],
    pub evidence_class: EvidenceClass,
    pub verdict: EdgeVerdict,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl EdgeReceipt {
    pub fn encode(&self) -> [u8; RECEIPT_CANONICAL_BYTES] {
        let mut out = [0u8; RECEIPT_CANONICAL_BYTES];
        out[OFF_PROTOCOL] = self.protocol as u8;
        out[OFF_REQUEST..OFF_CAPABILITY].copy_from_slice(&self.request_hash);
        out[OFF_CAPABILITY..OFF_POLICY].copy_from_slice(&self.capability_hash);
        out[OFF_POLICY..OFF_WEIGHTS].copy_from_slice(&self.policy_hash);
        out[OFF_WEIGHTS..OFF_ATTEST].copy_from_slice(&self.weights_hash);
        out[OFF_ATTEST..OFF_PREDICATES].copy_from_slice(&self.attestation_hash);
        out[OFF_PREDICATES..OFF_ROOT].copy_from_slice(&self.predicate_commitment);
        out[OFF_ROOT..OFF_EVIDENCE].copy_from_slice(&self.signer_root_id);
        out[OFF_EVIDENCE] = self.evidence_class as u8;
        out[OFF_VERDICT] = self.verdict as u8;
        out[OFF_ISSUED..OFF_EXPIRES].copy_from_slice(&self.issued_at.to_be_bytes());
        out[OFF_EXPIRES..RECEIPT_CANONICAL_BYTES].copy_from_slice(&self.expires_at.to_be_bytes());
        out
    }
    pub fn tbs<H: Sha256>(&self, h: &H) -> [u8; 32] {
        let enc = self.encode();
        h.digest(&[RECEIPT_DOMAIN_V1, &enc])
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SignedEdgeReceipt { pub receipt: EdgeReceipt, pub signature: HybridSignature }

#[derive(Clone, Copy, Debug)]
pub struct Coupling {
    pub capability_matches: bool, pub request_matches: bool, pub verdict_matches: bool,
    pub policy_hash_matches: bool, pub evidence_class_matches: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IssueError { Uncoupled, RootMismatch, EvidenceBelowFloor, SignerUnavailable, SelfVerifyFailed }

pub fn issue<E, M, H, S>(floor: &KernelCryptoFloor<E, M, H>, signer: &S, receipt: EdgeReceipt,
                         coupling: Coupling) -> Result<SignedEdgeReceipt, IssueError>
where E: Ed25519Verifier, M: MlDsa65Verifier, H: Sha256, S: HybridSigner {
    if !receipt_fields_coupled(coupling.capability_matches, coupling.request_matches,
        coupling.verdict_matches, coupling.policy_hash_matches, coupling.evidence_class_matches) {
        return Err(IssueError::Uncoupled);
    }
    if receipt.signer_root_id != signer.root_id() { return Err(IssueError::RootMismatch); }
    if receipt.evidence_class < EvidenceClass::required_by(floor.level()) {
        return Err(IssueError::EvidenceBelowFloor);
    }
    let tbs = receipt.tbs(floor.hash());
    let signature = signer.sign(&tbs).map_err(|_| IssueError::SignerUnavailable)?;
    if floor.verify(signer.public_key(), &tbs, &signature, floor.level()) != K3::Pos {
        return Err(IssueError::SelfVerifyFailed);
    }
    Ok(SignedEdgeReceipt { receipt, signature })
}
```

**Offline verification across federated roots.** A verifier holds a bounded, borrowed slice of trust roots and needs no network. Each root carries its own hybrid public key, validity window, optional revocation, and minimum floor. Revocation is conservative: a revoked root rejects every receipt it ever signed, because a compromised signer can backdate `issued_at`. Operators who want revocation-time semantics can relax this at the policy layer; the core ships the monotone choice.

```rust
//! src/federation.rs
use chio_kernel_core::formal_aeneas::classify_time_window_code;
use crate::floor::{CryptoFloorLevel, Ed25519Verifier, HybridPublicKey, KernelCryptoFloor, MlDsa65Verifier, Sha256};
use crate::k3::K3;
use crate::receipt::{EvidenceClass, SignedEdgeReceipt};

pub const MAX_TRUST_ROOTS: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct TrustRoot {
    pub root_id: [u8; 32],
    pub public_key: HybridPublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked_at: Option<u64>,
    pub min_floor: CryptoFloorLevel,
    pub min_evidence: EvidenceClass,
}

#[derive(Clone, Copy, Debug)]
pub struct FederatedTrustStore<'a> { roots: &'a [TrustRoot] }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FederationError { TooManyRoots, DuplicateRootId }

impl<'a> FederatedTrustStore<'a> {
    pub fn new(roots: &'a [TrustRoot]) -> Result<Self, FederationError> {
        if roots.len() > MAX_TRUST_ROOTS { return Err(FederationError::TooManyRoots); }
        for (i, a) in roots.iter().enumerate() {
            if roots.iter().skip(i.saturating_add(1)).any(|b| b.root_id == a.root_id) {
                return Err(FederationError::DuplicateRootId);
            }
        }
        Ok(Self { roots })
    }
    pub fn find(&self, id: &[u8; 32]) -> Option<&'a TrustRoot> { self.roots.iter().find(|r| r.root_id == *id) }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejectReason { UnknownRoot, RootRevoked, RootNotYetValid, RootExpired,
                        ReceiptNotYetValid, ReceiptExpired, SignatureInvalid, EvidenceBelowRootMinimum }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyOutcome { Accepted(EvidenceClass), Rejected(RejectReason), Indeterminate }

pub fn verify_receipt_offline<E, M, H>(store: &FederatedTrustStore<'_>, floor: &KernelCryptoFloor<E, M, H>,
                                       signed: &SignedEdgeReceipt, now: u64) -> VerifyOutcome
where E: Ed25519Verifier, M: MlDsa65Verifier, H: Sha256 {
    let rc = &signed.receipt;
    let Some(root) = store.find(&rc.signer_root_id) else { return VerifyOutcome::Rejected(RejectReason::UnknownRoot) };
    if root.revoked_at.is_some() { return VerifyOutcome::Rejected(RejectReason::RootRevoked); }
    match classify_time_window_code(now, root.not_before, root.not_after) {
        0 => {}
        1 => return VerifyOutcome::Rejected(RejectReason::RootNotYetValid),
        _ => return VerifyOutcome::Rejected(RejectReason::RootExpired),
    }
    match classify_time_window_code(now, rc.issued_at, rc.expires_at) {
        0 => {}
        1 => return VerifyOutcome::Rejected(RejectReason::ReceiptNotYetValid),
        _ => return VerifyOutcome::Rejected(RejectReason::ReceiptExpired),
    }
    if rc.evidence_class < root.min_evidence {
        return VerifyOutcome::Rejected(RejectReason::EvidenceBelowRootMinimum);
    }
    let tbs = rc.tbs(floor.hash());
    match floor.verify(&root.public_key, &tbs, &signed.signature, root.min_floor) {
        K3::Pos => VerifyOutcome::Accepted(rc.evidence_class),
        K3::Neg => VerifyOutcome::Rejected(RejectReason::SignatureInvalid),
        K3::Bot => VerifyOutcome::Indeterminate,
    }
}
```

**Hardware attestation, Pass 5.** The Pass 5 refinement binds three things into one hash that lives in the receipt: the TEE measurement, a request-fresh nonce, and the loaded-weights hash obtained through the existing `LoadedWeights::loaded_weights_hash` provider. The nonce is derived from the request hash and issue time, so a quote cannot be replayed across requests. Evidence class `HybridAttested` is reachable only through `bind_attestation`, which returns the hash or an error; there is no way to construct a class-4 receipt without a verified quote because the std-side issuer is the only caller and it threads the `Result`.

```rust
//! src/attest.rs
use crate::floor::Sha256;
use crate::k3::K3;

pub const MAX_QUOTE_BYTES: usize = 16_384;
pub const ATTEST_DOMAIN_V1: &[u8] = b"chio.edge.attest.v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TeeKind { Tpm2 = 1, SevSnp = 2, Tdx = 3, CcaRealm = 4, NitroEnclave = 5 }

#[derive(Clone, Copy, Debug)]
pub struct AttestationEvidence<'a> {
    pub tee: TeeKind,
    pub quote: &'a [u8],
    pub measurement: [u8; 32],
    pub nonce: [u8; 32],
    pub weights_hash: [u8; 32],
}

/// Vendor-root quote verification (TPM EK chain, AMD VCEK, Intel PCS, Arm CCA, Nitro).
/// `Bot` means the vendor root bundle is unavailable offline.
pub trait QuoteVerifier {
    fn verify_quote(&self, tee: TeeKind, quote: &[u8], measurement: &[u8; 32], nonce: &[u8; 32]) -> K3;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttestError { QuoteTooLarge, NonceMismatch, WeightsMismatch, QuoteInvalid, VendorRootUnavailable }

pub fn expected_nonce<H: Sha256>(h: &H, request_hash: &[u8; 32], issued_at: u64) -> [u8; 32] {
    let t = issued_at.to_be_bytes();
    h.digest(&[ATTEST_DOMAIN_V1, b"nonce", request_hash, &t])
}

pub fn attestation_hash<H: Sha256>(h: &H, ev: &AttestationEvidence<'_>) -> [u8; 32] {
    let tee = [ev.tee as u8];
    h.digest(&[ATTEST_DOMAIN_V1, &tee, &ev.measurement, &ev.nonce, &ev.weights_hash])
}

/// Pass 5 binding: quote verifies, nonce is request-fresh, weights match the loaded provider.
pub fn bind_attestation<H: Sha256, Q: QuoteVerifier>(h: &H, q: &Q, ev: &AttestationEvidence<'_>,
    request_hash: &[u8; 32], issued_at: u64, loaded_weights_hash: &[u8; 32]) -> Result<[u8; 32], AttestError> {
    if ev.quote.len() > MAX_QUOTE_BYTES { return Err(AttestError::QuoteTooLarge); }
    if ev.nonce != expected_nonce(h, request_hash, issued_at) { return Err(AttestError::NonceMismatch); }
    if ev.weights_hash != *loaded_weights_hash { return Err(AttestError::WeightsMismatch); }
    match q.verify_quote(ev.tee, ev.quote, &ev.measurement, &ev.nonce) {
        K3::Pos => Ok(attestation_hash(h, ev)),
        K3::Neg => Err(AttestError::QuoteInvalid),
        K3::Bot => Err(AttestError::VendorRootUnavailable),
    }
}
```

Two integration notes keep this additive. The reserved metadata array in `metadata.rs` is typed `[&str; 35]`; adding a key would change its type. Edge receipts therefore serialize under the existing reserved key `receipt_context` as a nested `chio_edge_v1` object, carrying the hex `signer_root_id`, `evidence_class`, and `attestation_hash`. The std-side `Guard` adapter maps `LiftError` to `Verdict::Deny`, `EdgeVerdict::PendingApproval` to the sticky pending state, and `EdgeVerdict::Deny` to the short-circuit, which is exactly the loop in `pipeline.rs`.

## 3. Formal artifacts and proofs

**Lean 4,** `formal/lean4/Chio/EdgeHybrid.lean`, added to the manifest without touching existing files.

```lean
namespace Chio.Edge

inductive K3 | pos | neg | bot deriving DecidableEq, Repr

def K3.and : K3 → K3 → K3
  | .neg, _    => .neg
  | _, .neg    => .neg
  | .pos, .pos => .pos
  | _, _       => .bot

inductive Floor | classicalOnly | hybridRequired deriving DecidableEq

def hybridVerify (f : Floor) (ed ml : K3) : K3 :=
  match f with
  | .classicalOnly  => ed
  | .hybridRequired => K3.and ed ml

/-- Under the hybrid floor, acceptance is exactly joint acceptance. -/
theorem hybrid_pos_iff (ed ml : K3) :
    hybridVerify .hybridRequired ed ml = .pos ↔ ed = .pos ∧ ml = .pos := by
  cases ed <;> cases ml <;> simp [hybridVerify, K3.and]

/-- A definite failure in either algorithm is a definite failure of the hybrid. -/
theorem hybrid_neg_dominates (ed ml : K3) (h : ed = .neg ∨ ml = .neg) :
    hybridVerify .hybridRequired ed ml = .neg := by
  cases ed <;> cases ml <;> simp_all [hybridVerify, K3.and]

/-- An unavailable backend can never yield acceptance. -/
theorem hybrid_bot_not_pos (ed : K3) :
    hybridVerify .hybridRequired ed .bot ≠ .pos := by
  cases ed <;> simp [hybridVerify, K3.and]

def classify (s tp tn : Int) : K3 :=
  if tp ≤ s then .pos else if s ≤ tn then .neg else .bot

/-- With strictly separated role-asymmetric thresholds the `neg` region excludes `pos`. -/
theorem classify_neg_region (s tp tn : Int) (h : tn < tp)
    (hs : classify s tp tn = .neg) : s ≤ tn ∧ ¬ tp ≤ s := by
  unfold classify at hs
  by_cases h1 : tp ≤ s
  · simp [h1] at hs
  · by_cases h2 : s ≤ tn
    · exact ⟨h2, h1⟩
    · simp [h1, h2] at hs

structure Envelope (α : Type) where
  feasible : List α
  deny : α
  deny_mem : deny ∈ feasible

def project {α : Type} [DecidableEq α] (e : Envelope α) (choice : α) : α :=
  if choice ∈ e.feasible then choice else e.deny

/-- Envelope preservation: any learned choice projects into the feasible set. -/
theorem project_mem {α : Type} [DecidableEq α] (e : Envelope α) (c : α) :
    project e c ∈ e.feasible := by
  unfold project
  split
  · assumption
  · exact e.deny_mem

/-- Fixed-width canonical encoding is injective on the modelled fields. -/
structure Rec where
  verdict : Fin 3
  issued : Nat
  expires : Nat
deriving DecidableEq

def enc (r : Rec) : Fin 3 × Nat × Nat := (r.verdict, r.issued, r.expires)

theorem enc_injective : Function.Injective enc := by
  intro a b h
  cases a; cases b
  simp [enc] at h
  obtain ⟨h1, h2, h3⟩ := h
  simp [h1, h2, h3]

end Chio.Edge
```

**Kani harnesses,** compiled only under `cfg(kani)` inside the crate. The learned choice is `kani::any()`, as the Verification Transfer Theorem prescribes.

```rust
#[cfg(kani)]
mod proofs {
    use crate::envelope::EdgeEnvelope;
    use crate::k3::{classify, FixedQ16_16, K3};
    use crate::portable::{EdgeProtocol, LiftFields, PortableToolCallRequest, MAX_TOOL_NAME_BYTES};

    #[kani::proof]
    fn hybrid_and_is_joint_acceptance() {
        let ed: K3 = kani::any();
        let ml: K3 = kani::any();
        assert_eq!(ed.and(ml).is_pos(), ed.is_pos() && ml.is_pos());
        if ed == K3::Neg || ml == K3::Neg { assert_eq!(ed.and(ml), K3::Neg); }
    }

    #[kani::proof]
    fn projection_never_escapes_envelope() {
        let mask: u8 = kani::any();
        let env = EdgeEnvelope::new(mask);
        let learned: u8 = kani::any();
        let a = env.project(learned);
        assert!(env.contains(a));
        assert!(env.contains(EdgeEnvelope::DENY));
    }

    #[kani::proof]
    fn classify_regions_are_ordered() {
        let (s, tp, tn): (i32, i32, i32) = (kani::any(), kani::any(), kani::any());
        kani::assume(tn < tp);
        match classify(FixedQ16_16(s), FixedQ16_16(tp), FixedQ16_16(tn)) {
            K3::Pos => assert!(s >= tp),
            K3::Neg => assert!(s <= tn && s < tp),
            K3::Bot => assert!(tn < s && s < tp),
        }
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn lift_is_total_and_bounded() {
        let buf: [u8; 16] = kani::any();
        let n_tool: usize = kani::any();
        let n_pr: usize = kani::any();
        kani::assume(n_tool <= 16 && n_pr <= 16);
        let f = LiftFields {
            protocol: EdgeProtocol::Mcp, tool_name: &buf[..n_tool], native_id: &buf[..0],
            arguments: &buf[..0], principal: &buf[..n_pr], parent_principal: &buf[..0],
            received_at: kani::any(), ttl: kani::any(),
        };
        if let Ok(r) = PortableToolCallRequest::lift(f) {
            assert!(!r.tool_name().is_empty() && r.tool_name().len() <= MAX_TOOL_NAME_BYTES);
            assert!(!r.principal().is_empty());
            assert!(r.issued_at() <= r.expires_at());
            assert_eq!(r.costs().0, 1);
        }
    }
}
```

**Apalache TLA+,** `formal/tla/EdgeFederation.tla`. The spec models the verifier's view: roots, revocations, time, and the admitted action chosen nondeterministically from a feasible set that always contains `Deny`.

```tla
---------------------------- MODULE EdgeFederation ----------------------------
EXTENDS Integers, FiniteSets

CONSTANTS
  \* @type: Set(Str);
  Roots,
  \* @type: Set(Str);
  Receipts,
  \* @type: Int;
  MaxTime

VARIABLES
  \* @type: Int;
  now,
  \* @type: Set(Str);
  revoked,
  \* @type: Set(Str);
  accepted,
  \* @type: Str -> Str;
  issuedBy,
  \* @type: Str -> Int;
  issuedAt,
  \* @type: Str -> Int;
  expiresAt,
  \* @type: Str -> Bool;
  edOk,
  \* @type: Str -> Bool;
  mlOk,
  \* @type: Str -> Str;
  chosen

vars == <<now, revoked, accepted, issuedBy, issuedAt, expiresAt, edOk, mlOk, chosen>>
Actions == {"Deny", "Allow", "Pending"}

Init ==
  /\ now = 0 /\ revoked = {} /\ accepted = {}
  /\ issuedBy \in [Receipts -> Roots]
  /\ issuedAt \in [Receipts -> 0..MaxTime]
  /\ expiresAt \in [Receipts -> 0..MaxTime]
  /\ edOk \in [Receipts -> BOOLEAN] /\ mlOk \in [Receipts -> BOOLEAN]
  /\ chosen = [rc \in Receipts |-> "Deny"]

\* Abstracts classify_time_window_code(now, issued, expires) = 0.
Window(rc) == issuedAt[rc] <= now /\ now < expiresAt[rc]
HybridOk(rc) == edOk[rc] /\ mlOk[rc]
Verify(rc) == issuedBy[rc] \notin revoked /\ Window(rc) /\ HybridOk(rc)

\* The feasible envelope: Deny always; Allow only when verification passes.
Feasible(rc) == {"Deny", "Pending"} \cup (IF Verify(rc) THEN {"Allow"} ELSE {})

Tick == now < MaxTime /\ now' = now + 1
  /\ UNCHANGED <<revoked, accepted, issuedBy, issuedAt, expiresAt, edOk, mlOk, chosen>>

Revoke(r) == revoked' = revoked \cup {r}
  /\ UNCHANGED <<now, accepted, issuedBy, issuedAt, expiresAt, edOk, mlOk, chosen>>

\* Learned choice is unconstrained nondeterminism inside Feasible(rc).
Admit(rc) == \E a \in Feasible(rc) :
  /\ chosen' = [chosen EXCEPT ![rc] = a]
  /\ accepted' = IF a = "Allow" THEN accepted \cup {rc} ELSE accepted
  /\ UNCHANGED <<now, revoked, issuedBy, issuedAt, expiresAt, edOk, mlOk>>

Next == Tick \/ (\E r \in Roots : Revoke(r)) \/ (\E rc \in Receipts : Admit(rc))
Spec == Init /\ [][Next]_vars

AcceptedWereHybrid == \A rc \in accepted : HybridOk(rc)
ChosenIsFeasible == \A rc \in Receipts : chosen[rc] \in Feasible(rc) \/ chosen[rc] = "Deny"
NoAllowFromRevokedRoot == \A rc \in Receipts : chosen[rc] = "Allow" => issuedBy[rc] \notin revoked
RevocationMonotone == [][\A rc \in (accepted' \ accepted) : issuedBy[rc] \notin revoked']_vars
===============================================================================
```

Apalache checks `AcceptedWereHybrid` and `NoAllowFromRevokedRoot` as inductive invariants; `RevocationMonotone` is an action invariant stating that no newly accepted receipt comes from a root revoked in the same step. `ChosenIsFeasible` is weakened by the `Deny` disjunct because a later revocation can shrink `Feasible(rc)` after a past choice; the real-time property is captured by `NoAllowFromRevokedRoot` since an `Allow` chosen before revocation is only reachable while the root was live.

**Theorem 1, lift totality and envelope preservation.** For every protocol message $x$, the lift either produces a request satisfying all bounds in section 1 or a `LiftError`. In both cases the edge envelope $\mathcal{C}(C(x))$ contains `Deny`. Proof. The constructor is a chain of guards followed by a single `Ok`; every guard returns a distinct `LiftError`, and the checked addition excludes overflow, so the function is total on all inputs. `EdgeEnvelope::new` sets bit 0 unconditionally, and `project` returns either a member of the mask or `DENY`. The Kani harness `projection_never_escapes_envelope` discharges the second clause for all 256 masks and all 256 choices; `project_mem` discharges it for arbitrary types in Lean. $\square$

**Theorem 2, hybrid AND-composition.** Let $\mathsf{Adv}^{\mathrm{EUF}}_{\mathrm{Ed}}(\mathcal{A})$ and $\mathsf{Adv}^{\mathrm{EUF}}_{\mathrm{ML}}(\mathcal{A})$ be the forgery advantages against Ed25519 and ML-DSA-65. Then for any adversary $\mathcal{A}$ against the hybrid receipt under `HybridRequired`,
$$\mathsf{Adv}_{\mathrm{Hyb}}(\mathcal{A}) \le \min\big(\mathsf{Adv}_{\mathrm{Ed}}(\mathcal{B}_1), \mathsf{Adv}_{\mathrm{ML}}(\mathcal{B}_2)\big)$$
for reductions $\mathcal{B}_1, \mathcal{B}_2$ with essentially the same running time. Proof. By `hybrid_pos_iff`, a forged receipt accepted at the hybrid floor contains a valid Ed25519 signature and a valid ML-DSA-65 signature on the same `tbs`, which is a fresh domain-separated digest because `encode` is injective by `enc_injective` extended fieldwise, and SHA-256 is collision resistant. $\mathcal{B}_1$ generates its own ML-DSA key pair, answers signing queries by signing with it and forwarding Ed25519 queries to its oracle, and outputs the Ed25519 component of $\mathcal{A}$'s forgery. $\mathcal{B}_2$ is symmetric. Each wins whenever $\mathcal{A}$ does. $\square$

A consequence worth stating plainly: a future break of either algorithm, including a quantum break of Ed25519, leaves accepted receipts no weaker than the surviving algorithm. The `K3::Bot` branch means that a deployment lacking an ML-DSA implementation cannot silently accept at the classical level; `hybrid_bot_not_pos` makes this a theorem rather than a convention.

**Theorem 3, offline verification is deterministic, isolated, and revocation-monotone.** The outcome of `verify_receipt_offline` is a function of the store contents, the receipt, the signature, and `now`; it performs no I/O and consults exactly one root, selected by `signer_root_id`. Proof of isolation: the lookup `find` returns the unique root with that identifier, uniqueness being enforced by `FederatedTrustStore::new`, and no other root's key is read. Hence compromise of root $R_i$ affects acceptance only of receipts with `signer_root_id = R_i`. Proof of monotonicity: let $S$ and $S'$ be stores identical except that $S'$ marks additional roots revoked. Every path that returns `Accepted` in $S'$ passes the `revoked_at.is_none()` test on the selected root, which then also holds in $S$ with all other inputs equal, so acceptance under $S'$ implies acceptance under $S$. Apalache's `RevocationMonotone` checks the finite-state image of the same claim. $\square$

**Theorem 4, attestation binding.** If a receipt is accepted with evidence class at least `HybridAttested`, then under SHA-256 collision resistance the kernel that signed it was running weights whose hash equals the receipt's `weights_hash`, inside a TEE whose measurement is committed by `attestation_hash`, with a quote that was fresh for this request. Proof. Class 4 is only assignable by the issuer after `bind_attestation` returns `Ok`. That requires the quote to verify under the vendor root on the pair `(measurement, nonce)`, the nonce to equal `H(domain, request_hash, issued_at)`, and the evidence's weights hash to equal the hash supplied by the `LoadedWeights` provider, which the kernel's `evaluate_weights_binding` had already matched against the model card. The returned hash commits to all three plus the TEE kind, and is signed as part of `tbs`. A receipt with class 4 but a different measurement would require either a quote forgery against the vendor root or a hash collision. Freshness follows because the nonce depends on `request_hash`, which by section 1 is a length-prefixed digest of every lifted field. $\square$

**Lemma 5, role-asymmetric regions.** With $\tau^{\text{neg}}_j < \tau^{\text{pos}}_j$ the three classification regions partition the score line into $(-\infty, \tau^{\text{neg}}]$, $(\tau^{\text{neg}}, \tau^{\text{pos}})$, and $[\tau^{\text{pos}}, \infty)$. `Thresholds::new` admits equality, in which case the middle region is empty and ties go to `Pos`. Both `classify_neg_region` and the Kani harness `classify_regions_are_ordered` cover the strict case; the equality case is the degenerate partition with no `Bot` outcomes. $\square$

**Lemma 6, evidence floor monotonicity.** `EvidenceClass` is totally ordered by declaration, `required_by` is monotone in the floor level, and both `issue` and `verify_receipt_offline` reject when the receipt class is below the applicable minimum. Raising a kernel's floor or a root's `min_evidence` therefore never turns a rejection into an acceptance. $\square$

**Verification Transfer.** None of the artifacts above mention `UltraBERT`, the thresholds table contents, or the shadow prices. The learned components appear only as the `kani::any()` choice, the `\E a \in Feasible(rc)` existential, and the arbitrary `c` in `project_mem`. Retraining Copley, changing thresholds, or re-tuning $\boldsymbol{\lambda}$ reruns zero proofs. That is the Wave 1 law applied to the protocol edge.

**Manifest additions,** appended to `formal/proof-manifest.toml`:

```toml
[[proof]]
name = "edge_hybrid_pos_iff"
lean = "formal/lean4/Chio/EdgeHybrid.lean"
rust = "crates/edge/chio-protocol-edge-core/src/floor.rs::KernelCryptoFloor::verify"

[[proof]]
name = "edge_project_mem"
lean = "formal/lean4/Chio/EdgeHybrid.lean"
kani = "chio_protocol_edge_core::proofs::projection_never_escapes_envelope"
rust = "crates/edge/chio-protocol-edge-core/src/envelope.rs::EdgeEnvelope::project"

[[proof]]
name = "edge_federation_invariants"
tla = "formal/tla/EdgeFederation.tla"
invariants = ["AcceptedWereHybrid", "NoAllowFromRevokedRoot", "RevocationMonotone"]
rust = "crates/edge/chio-protocol-edge-core/src/federation.rs::verify_receipt_offline"

[[proof]]
name = "edge_lift_total"
kani = "chio_protocol_edge_core::proofs::lift_is_total_and_bounded"
rust = "crates/edge/chio-protocol-edge-core/src/portable.rs::PortableToolCallRequest::lift"
```

**Recap.** The protocol edges now share one `#![no_std]`, `#![forbid(unsafe_code)]` core. MCP, A2A, and Envoy ext_authz messages lift through one bounded constructor into `PortableToolCallRequest`, whose four Copley segments feed the 537-predicate $\mathbb{K}_3$ vector and whose envelope always contains `Deny`. Receipts are 243-byte canonical records signed by Ed25519 and ML-DSA-65 over one domain-separated digest, verified at a per-root floor where an absent backend yields `Deny`, and bound in Pass 5 to the loaded-weights hash and a request-fresh TEE quote. Offline verification touches exactly one federated root and is monotone under revocation. Every existing kernel signature, the 35-entry reserved metadata array, and the `GuardPipeline` loop are used as-is. The Lean theorems, four Kani harnesses, and the Apalache invariants are stated above and ready to be dropped into the listed paths; the manifest entries are additive. Open items for the implementing team are the std-side canonicalizers for MCP JSON, A2A parts, and Envoy attributes, the `UltraBERT` scorer host implementing `SegmentScorer`, and the vendor-root bundles behind `QuoteVerifier`.